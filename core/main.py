"""Uvicorn entry point for the Lil Tweak trusted core."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from lil_tweak.api import create_app
from lil_tweak.archive import ingest_r2_sources
from lil_tweak.config import Config
from lil_tweak.evidence import R2EvidenceStore
from lil_tweak.git_source import ingest_git_source
from lil_tweak.limits import TRUSTED_WORK_ROOT_BYTES, TRUSTED_WORK_ROOT_INODES
from lil_tweak.openai_agent import (
    CodeEngineer,
    PromotionRecoveryRequired,
    ResponsesClient,
    WorkspaceTools,
    cleanup_patch_remnants,
    load_reviewed_instructions,
    reconcile_promotion_markers,
)
from lil_tweak.orchestrator import (
    BackgroundJobRunner,
    DurableJobScheduler,
    EngineeringOrchestrator,
)
from lil_tweak.runtime_lock import RuntimeExecutionBusy, runtime_execution_lock
from lil_tweak.sandbox import PodmanSandbox, SandboxLimits
from lil_tweak.store import PostgresJobStore
from lil_tweak.test_world_api import TestWorldApi
from lil_tweak.test_world_postgres import PostgresTestWorldStore
from lil_tweak.test_world_runner import TestWorldAttemptRunner
from lil_tweak.test_world_runtime import TestWorldRuntime
from lil_tweak.test_world_scheduler import TestWorldScheduler


def _mount_field(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def is_bounded_work_root(
    path: Path,
    *,
    mountinfo_text: str | None = None,
    statvfs: Any = os.statvfs,
) -> bool:
    """Require a distinct tmpfs whose total capacity matches deploy bounds."""

    try:
        resolved = path.resolve(strict=mountinfo_text is None)
        text = (
            Path("/proc/self/mountinfo").read_text(encoding="utf-8")
            if mountinfo_text is None
            else mountinfo_text
        )
        filesystem = None
        for line in text.splitlines():
            fields = line.split()
            separator = fields.index("-")
            if len(fields) <= separator + 1:
                continue
            mount_point = Path(_mount_field(fields[4]))
            if mount_point == resolved:
                filesystem = fields[separator + 1]
                break
        if filesystem != "tmpfs":
            return False
        stats = statvfs(resolved)
        capacity = stats.f_frsize * stats.f_blocks
        return (
            capacity == TRUSTED_WORK_ROOT_BYTES
            and stats.f_files == TRUSTED_WORK_ROOT_INODES
        )
    except (OSError, ValueError, IndexError):
        return False


def _build_test_world_app(
    *,
    config: Any,
    job_store: Any,
    responses: Any,
    reviewed_instructions: str,
    work_root: Path,
    connect: Any,
    fallback: Any,
) -> Any:
    """Compose Test World beside the existing trusted-core application."""

    world_store = PostgresTestWorldStore(connect)
    execution_lock = runtime_execution_lock
    world_worker_id = f"test-world-{uuid.uuid4()}"
    world_lease_seconds = min(60, max(15, config.job_timeout_seconds // 4))
    runtime = TestWorldRuntime(
        work_root=work_root,
        runner_image=config.runner_image,
        git_allowed_hosts=config.git_allowed_hosts,
        responses_client=responses,
        model=config.openai_model,
        instructions=reviewed_instructions,
        job_timeout_seconds=config.job_timeout_seconds,
    )
    runner = TestWorldAttemptRunner(
        store=world_store,
        worker_id=world_worker_id,
        lease_seconds=world_lease_seconds,
        prepare_workspace=runtime.prepare_workspace,
        apply_previous_patch=runtime.apply_previous_patch,
        run_agent=runtime.run_agent,
        capture_cumulative_patch=runtime.capture_cumulative_patch,
        run_check=runtime.run_check,
        cleanup_workspace=runtime.cleanup_workspace,
    )
    scheduler = TestWorldScheduler(
        world_store,
        runner,
        worker_id=world_worker_id,
        lease_seconds=world_lease_seconds,
        execution_guard=lambda: execution_lock(work_root),
    )
    scheduler.start()
    return TestWorldApi(
        fallback=fallback,
        nonce_store=job_store,
        world_store=world_store,
        signing_keys=config.signing_keys,
        canonical_owner_id=config.canonical_owner_id,
        on_attempt_queued=scheduler.notify,
    )


def build_app(environ: dict[str, str] | None = None) -> Any:
    config = Config.from_env(environ)
    import psycopg
    import boto3
    from botocore.config import Config as BotoConfig

    store = PostgresJobStore(lambda: psycopg.connect(config.database_url))
    r2_client = boto3.client(
        "s3",
        endpoint_url=config.evidence_endpoint,
        region_name="auto",
        aws_access_key_id=config.aws_access_key_id,
        aws_secret_access_key=config.aws_secret_access_key,
        config=BotoConfig(
            connect_timeout=2,
            read_timeout=2,
            retries={"max_attempts": 0, "mode": "standard"},
        ),
    )
    evidence_store = R2EvidenceStore(
        r2_client,
        config.evidence_bucket,
    )
    responses = ResponsesClient(api_key=config.openai_api_key)
    reviewed_instructions = load_reviewed_instructions(
        Path(__file__).resolve().parent / "prompts" / "code_engineer.md"
    )
    work_root = config.work_root.resolve()
    if not is_bounded_work_root(work_root):
        raise RuntimeError("work root must be a dedicated bounded tmpfs")
    snapshot_root = work_root / ".snapshots"
    # Serialize startup reconciliation with every production job and live
    # probe. A held or unprovable lock must fail before cleanup can mutate the
    # active process's containers or recovery trees.
    with runtime_execution_lock(work_root):
        # Eliminate live writers, then reconcile every durable promotion marker
        # before deleting any proposal or snapshot recovery context.
        PodmanSandbox.cleanup_stale()
        reconcile_promotion_markers(work_root)
        cleanup_patch_remnants(work_root)
        try:
            if snapshot_root.exists():
                shutil.rmtree(snapshot_root)
            snapshot_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        except Exception:
            raise PromotionRecoveryRequired("patch_cleanup_failed") from None
    recovery_latched = {"value": False}
    worker_id = f"core-{uuid.uuid4()}"
    lease_seconds = min(60, max(15, config.job_timeout_seconds // 4))

    def workspace_for(job_id: str) -> Any:
        workspace = (work_root / job_id).resolve()
        if workspace.parent != work_root:
            raise ValueError("invalid workspace")
        return workspace

    def remove_runtime_tree(path: Path) -> None:
        try:
            shutil.rmtree(path)
        except FileNotFoundError:
            return
        except Exception:
            recovery_latched["value"] = True
            raise PromotionRecoveryRequired("patch_cleanup_failed") from None

    def prepare_sources(job_id: str, owner_id: str, lease: Any = None) -> list[str]:
        if recovery_latched["value"]:
            raise PromotionRecoveryRequired("patch_reconciliation_required")
        job = store.get_job(job_id, owner_id)
        if job is None:
            raise ValueError("job not found")
        try:
            reconcile_promotion_markers(work_root)
            cleanup_patch_remnants(work_root)
        except PromotionRecoveryRequired:
            recovery_latched["value"] = True
            raise
        if job.state.value == "queued":
            job = store.transition_job(
                job.id,
                owner_id=owner_id,
                expected_revision=job.revision,
                state="ingesting",
                lease=lease,
                event_kind="ingesting",
                event_data={},
            )
        elif job.state.value != "ingesting":
            raise ValueError("job is not ready for source intake")
        workspace = workspace_for(job_id)
        job_snapshots = snapshot_root / job_id
        remove_runtime_tree(job_snapshots)
        remove_runtime_tree(workspace)
        try:
            workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
            if job.git_source is not None:
                return ingest_git_source(
                    job.git_source,
                    workspace,
                    allowed_hosts=config.git_allowed_hosts,
                )
            return ingest_r2_sources(
                r2_client, config.evidence_bucket, job.sources, workspace
            )
        except Exception as intake_error:
            recording_error: Exception | None = None
            try:
                latest = store.get_job(job_id, owner_id)
                if latest is not None and latest.state.value == "ingesting":
                    store.transition_job(
                        job_id,
                        owner_id=owner_id,
                        expected_revision=latest.revision,
                        state="failed",
                        lease=lease,
                        event_kind="source_intake_failed",
                        event_data={"code": "source_intake_failed"},
                    )
            except Exception as error:
                recording_error = error
            remove_runtime_tree(workspace)
            if recording_error is not None:
                raise recording_error from intake_error
            raise

    def execute_job(
        job_id: str,
        owner_id: str,
        source_inventory: list[str],
        lease: Any = None,
    ) -> Any:
        workspace = workspace_for(job_id)
        sandbox = PodmanSandbox(
            image=config.runner_image,
            workspace=workspace,
            name=f"lt-{job_id.replace('-', '')[:32]}",
            limits=SandboxLimits(
                wall_timeout_seconds=config.job_timeout_seconds,
                command_timeout_seconds=min(10 * 60, config.job_timeout_seconds),
            ),
        )
        tools: WorkspaceTools | None = None
        preserve_recovery_context = False
        try:
            tools = WorkspaceTools(workspace, sandbox)
            agent = CodeEngineer(
                responses,
                tools,
                model=config.openai_model,
                instructions=reviewed_instructions,
            )
            return EngineeringOrchestrator(
                store=store,
                agent=agent,
                evidence_store=evidence_store,
                job_timeout_seconds=config.job_timeout_seconds,
                lease=lease,
                lease_seconds=lease_seconds,
            ).run_job(
                job_id,
                owner_id,
                source_inventory=source_inventory,
                workspace=workspace,
            )
        except PromotionRecoveryRequired:
            preserve_recovery_context = True
            recovery_latched["value"] = True
            raise
        except BaseException:
            preserve_recovery_context = bool(
                tools is not None and tools.recovery_context_exists()
            )
            if preserve_recovery_context:
                recovery_latched["value"] = True
            raise
        finally:
            active_failure = sys.exc_info()[0] is not None
            teardown_failed = False
            try:
                sandbox.teardown()
            except Exception:
                teardown_failed = True
                preserve_recovery_context = True
                recovery_latched["value"] = True
            if sandbox.lifecycle_failed or bool(
                tools is not None and tools.recovery_context_exists()
            ):
                preserve_recovery_context = True
                recovery_latched["value"] = True
            if not preserve_recovery_context:
                remove_runtime_tree(workspace)
            if teardown_failed and not active_failure:
                raise RuntimeError("sandbox lifecycle failed")

    def runtime_admission_available() -> bool:
        if recovery_latched["value"]:
            return False
        try:
            with runtime_execution_lock(work_root):
                return True
        except RuntimeExecutionBusy:
            return False

    job_runner = BackgroundJobRunner(
        execute_job,
        source_intake=prepare_sources,
        max_admitted=config.max_admitted_jobs,
        admission_guard=runtime_admission_available,
        execution_guard=lambda: runtime_execution_lock(work_root),
    )
    scheduler = DurableJobScheduler(
        store,
        job_runner,
        worker_id=worker_id,
        lease_seconds=lease_seconds,
    )
    scheduler.start()

    def readiness() -> dict[str, bool]:
        database = False
        try:
            with psycopg.connect(config.database_url) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT EXISTS (SELECT 1 FROM lil_tweak_schema_version WHERE version=3)"
                    )
                    database = bool(cursor.fetchone()[0])
        except Exception:
            database = False
        runner = False
        if shutil.which("podman") is not None:
            try:
                probe = subprocess.run(
                    ["podman", "image", "exists", config.runner_image],
                    shell=False,
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
                runner = probe.returncode == 0
            except (OSError, subprocess.SubprocessError):
                runner = False
        git = shutil.which("git") is not None and shutil.which("prlimit") is not None
        workspace = work_root.is_dir() and os.access(
            work_root, os.R_OK | os.W_OK | os.X_OK
        )
        evidence = False
        try:
            r2_client.head_bucket(Bucket=config.evidence_bucket)
            evidence = True
        except Exception:
            evidence = False
        return {
            "database": database,
            "runner": runner,
            "git": git,
            "workspace": workspace,
            "evidence": evidence,
            "signing": bool(config.signing_keys),
            "admission": job_runner.has_capacity,
        }

    base_app = create_app(
        store=store,
        signing_keys=config.signing_keys,
        canonical_owner_id=config.canonical_owner_id,
        readiness=readiness,
        evidence_store=evidence_store,
        on_job_queued=scheduler.notify,
    )
    return _build_test_world_app(
        config=config,
        job_store=store,
        responses=responses,
        reviewed_instructions=reviewed_instructions,
        work_root=work_root,
        connect=lambda: psycopg.connect(config.database_url),
        fallback=base_app,
    )


class _LazyApp:
    def __init__(self) -> None:
        self._app: Any = None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if self._app is None:
            self._app = build_app()
        await self._app(scope, receive, send)


app = _LazyApp()
