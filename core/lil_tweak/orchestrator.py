"""Authoritative engineering workflow orchestration."""

from __future__ import annotations

import hashlib
import shutil
import threading
import time
from collections.abc import Sequence
from contextlib import nullcontext
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .contracts import JobMode, JobState, TERMINAL_STATES
from .evidence import (
    EvidenceStore,
    WorkspaceSnapshot,
    build_command_evidence,
    build_edit_journal_evidence,
    build_evidence_bundle,
    build_workspace_patch,
    capture_workspace,
)
from .openai_agent import (
    AgentDeadlineError,
    AgentResult,
    PromotionRecoveryRequired,
)
from .store import Job, JobLease, JobNotFound, JobStore, StaleLease


_EXPORT_ACTION = "export_patch"
_EXPORT_TARGET = "owner_download"
_POLICY_VERSION = "v1"
_RESOURCE_PROFILE = {
    "cpus": 1,
    "memory": "1g",
    "pids": 256,
    "wallSeconds": 1200,
}


def _remove_snapshot_tree(path: Path) -> None:
    """Remove one known snapshot tree or fail closed without error details."""

    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        return
    except Exception:
        raise PromotionRecoveryRequired("patch_cleanup_failed") from None


class AdmissionUnavailable(RuntimeError):
    code = "admission_unavailable"

    def __init__(self) -> None:
        super().__init__("admission unavailable")


class BackgroundJobRunner:
    """Single-admission background executor for DigitalOcean engineering jobs."""

    def __init__(
        self,
        run_job: Any,
        *,
        source_intake: Any = None,
        max_admitted: int = 2,
        admission_guard: Any = None,
        execution_guard: Any = None,
    ) -> None:
        if max_admitted < 1:
            raise ValueError("max_admitted must be positive")
        self._run_job = run_job
        self._source_intake = source_intake
        self._max_admitted = max_admitted
        self._admission_guard = admission_guard
        self._execution_guard = execution_guard
        self._admitted = 0
        self._admission_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="lil-tweak-engineering"
        )

    def submit(
        self, job_id: str, owner_id: str, lease: JobLease | None = None
    ) -> Future[Any]:
        with self._admission_lock:
            if (
                self._admission_guard is not None
                and not bool(self._admission_guard())
            ) or self._admitted >= self._max_admitted:
                raise AdmissionUnavailable()
            self._admitted += 1
        try:
            future = self._executor.submit(self._execute, job_id, owner_id, lease)
        except Exception:
            self._release_admission()
            raise
        future.add_done_callback(lambda _: self._release_admission())
        return future

    @property
    def has_capacity(self) -> bool:
        with self._admission_lock:
            return (
                self._admission_guard is None
                or bool(self._admission_guard())
            ) and self._admitted < self._max_admitted

    def _release_admission(self) -> None:
        with self._admission_lock:
            self._admitted -= 1

    def _execute(
        self, job_id: str, owner_id: str, lease: JobLease | None
    ) -> Any:
        guard = (
            self._execution_guard()
            if self._execution_guard is not None
            else nullcontext()
        )
        with guard:
            if self._source_intake is None:
                if lease is None:
                    return self._run_job(job_id, owner_id)
                return self._run_job(job_id, owner_id, lease)
            if lease is None:
                inventory = self._source_intake(job_id, owner_id)
                return self._run_job(job_id, owner_id, inventory)
            inventory = self._source_intake(job_id, owner_id, lease)
            return self._run_job(job_id, owner_id, inventory, lease)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=False)


class DurableJobScheduler:
    """Continuously claims durable queued work and renews generation leases."""

    def __init__(
        self,
        store: JobStore,
        runner: BackgroundJobRunner,
        *,
        worker_id: str,
        lease_seconds: int,
        poll_interval: float = 1.0,
        clock: Any = time.time,
    ) -> None:
        if not worker_id or lease_seconds <= 0 or poll_interval <= 0:
            raise ValueError("invalid scheduler configuration")
        self.store = store
        self.runner = runner
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds
        self.poll_interval = poll_interval
        self.clock = clock
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._loop,
            name="lil-tweak-durable-scheduler",
            daemon=True,
        )
        self._thread.start()

    def notify(self, *_: Any) -> None:
        self._wake.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:
                # A transient database/runner failure must not terminate durable
                # admission. Readiness reports the underlying dependency state.
                pass
            self._wake.wait(self.poll_interval)
            self._wake.clear()

    def poll_once(self) -> int:
        now = self.clock()
        self.store.reconcile_active_jobs(now=now, limit=100)
        admitted = 0
        while self.runner.has_capacity:
            jobs = self.store.list_schedulable_jobs(now=now, limit=1)
            if not jobs:
                break
            job = jobs[0]
            lease = self.store.claim_job(
                job.id,
                job.owner_id,
                self.worker_id,
                lease_seconds=self.lease_seconds,
                now=now,
            )
            if lease is None:
                break
            try:
                future = self.runner.submit(job.id, job.owner_id, lease)
            except Exception:
                self.store.release_claim(lease)
                raise
            admitted += 1
            heartbeat_stop = threading.Event()
            future.add_done_callback(
                lambda _future, bound_lease=lease, stop=heartbeat_stop: self._finished(
                    bound_lease, stop
                )
            )
            threading.Thread(
                target=self._heartbeat,
                args=(lease, future, heartbeat_stop),
                name=f"lil-tweak-lease-{job.id[:8]}",
                daemon=True,
            ).start()
        return admitted

    def _heartbeat(
        self,
        lease: JobLease,
        future: Future[Any],
        stopped: threading.Event,
    ) -> None:
        interval = max(0.05, self.lease_seconds / 3)
        while not future.done() and not stopped.wait(interval):
            try:
                self.store.renew_claim(
                    lease,
                    lease_seconds=self.lease_seconds,
                    now=self.clock(),
                )
            except StaleLease:
                return
            except Exception:
                # Retry on the next heartbeat while the current lease remains
                # valid; generation fencing prevents a stale finalization.
                continue

    def _finished(self, lease: JobLease, stopped: threading.Event) -> None:
        stopped.set()
        self.store.release_claim(lease)
        self.notify()

    def shutdown(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.poll_interval * 2))


class EngineeringOrchestrator:
    def __init__(
        self,
        *,
        store: JobStore,
        agent: Any,
        evidence_store: EvidenceStore,
        clock: Any = time.time,
        monotonic: Any = time.monotonic,
        job_timeout_seconds: int = 20 * 60,
        galor: Any = None,
        runner_verifier: Any = None,
        lease: JobLease | None = None,
        lease_seconds: int = 60,
    ) -> None:
        self.store = store
        self.agent = agent
        self.evidence_store = evidence_store
        self.clock = clock
        self.monotonic = monotonic
        self.job_timeout_seconds = job_timeout_seconds
        self.galor = galor
        self.runner_verifier = runner_verifier
        self.lease = lease
        self.lease_seconds = lease_seconds
        self.resource_profile = {
            **_RESOURCE_PROFILE,
            "wallSeconds": job_timeout_seconds,
        }

    def _move(
        self,
        job: Job,
        state: JobState,
        *,
        proposal_digest: str | None = None,
        evidence_manifest: dict[str, Any] | None = None,
        summary: str | None = None,
        source_digest: str | None = None,
        approval_proposal: dict[str, Any] | None = None,
    ) -> Job:
        self._renew_lease()
        return self.store.transition_job(
            job.id,
            owner_id=job.owner_id,
            expected_revision=job.revision,
            state=state,
            proposal_digest=proposal_digest,
            evidence_manifest=evidence_manifest,
            summary=summary,
            source_digest=source_digest,
            approval_proposal=approval_proposal,
            lease=self.lease,
            event_kind=state.value,
            event_data={},
        )

    def _renew_lease(self) -> None:
        if self.lease is not None:
            self.lease = self.store.renew_claim(
                self.lease,
                lease_seconds=self.lease_seconds,
            )

    def run_job(
        self,
        job_id: str,
        owner_id: str,
        *,
        source_inventory: Sequence[str] = (),
        workspace: str | Path | None = None,
    ) -> Job:
        job = self.store.get_job(job_id, owner_id)
        if job is None:
            raise JobNotFound("job not found")
        if job.state in TERMINAL_STATES:
            return job
        if job.cancel_requested:
            return self._move(job, JobState.CANCELLED)
        started_at = self.clock()
        deadline = self.monotonic() + self.job_timeout_seconds
        snapshot_roots: list[Path] = []
        preserve_recovery_context = False
        workspace_tools = getattr(self.agent, "tools", None)
        try:
            if job.state is JobState.DRAFT:
                job = self._move(job, JobState.QUEUED)
            if job.state is JobState.QUEUED:
                job = self._move(job, JobState.INGESTING)
            if workspace is not None:
                workspace_path = Path(workspace).resolve()
                if workspace_tools is None or not callable(
                    getattr(workspace_tools, "capture_final_snapshot", None)
                ):
                    raise PromotionRecoveryRequired("patch_reconciliation_required")
                if bool(
                    getattr(workspace_tools, "recovery_context_exists", lambda: True)()
                ):
                    raise PromotionRecoveryRequired("patch_reconciliation_required")
                snapshot_job_root = (
                    workspace_path.parent / ".snapshots" / job.id
                )
                _remove_snapshot_tree(snapshot_job_root)
                attempt = self.lease.generation if self.lease is not None else job.revision
                attempt_root = snapshot_job_root / f"attempt-{attempt}"
                baseline_stage = attempt_root / "baseline"
                snapshot_roots.append(snapshot_job_root)
                baseline = capture_workspace(
                    workspace_path, staging_root=baseline_stage
                )
            else:
                baseline = WorkspaceSnapshot(
                    {}, hashlib.sha256(b"lil-tweak-source-v1\0").hexdigest()
                )
            for state in (JobState.PLANNING, JobState.EXECUTING):
                job = self._move(
                    job,
                    state,
                    source_digest=baseline.source_digest
                    if state is JobState.PLANNING
                    else None,
                )
                latest = self.store.get_job(job.id, owner_id)
                if latest is not None and latest.cancel_requested:
                    return self._move(latest, JobState.CANCELLED)
            galor_context = None
            if self.galor is not None:
                galor_result = self.galor.fetch(dict(job.project_context or {}))
                galor_context = galor_result.context
                if galor_result.error:
                    self.store.append_event(
                        job.id,
                        owner_id,
                        "galor_unavailable",
                        {"code": "galor_unavailable"},
                    )
            result: AgentResult = self.agent.run(
                mode=job.mode,
                prompt=job.prompt,
                source_inventory=source_inventory,
                project_context=job.project_context,
                galor_context=galor_context,
                deadline=deadline,
                monotonic=self.monotonic,
            )
            latest = self.store.get_job(job.id, owner_id)
            if latest is None:
                raise JobNotFound("job not found")
            if latest.cancel_requested:
                return self._move(latest, JobState.CANCELLED)
            job = latest
            job = self._move(job, JobState.TESTING)
            job = self._move(job, JobState.COLLECTING)
            if workspace is not None:
                final_stage = attempt_root / "final"
                final = workspace_tools.capture_final_snapshot(
                    baseline, final_stage
                )
            else:
                final = baseline
            patch = build_workspace_patch(baseline, final)
            runner_receipt = None
            if self.runner_verifier is not None and job.mode is not JobMode.CHAT:
                if job.git_source is None or workspace is None:
                    raise ValueError("GitHub runner requires an exact Git source")
                runner_receipt = self.runner_verifier.verify(
                    job=job,
                    workspace=Path(workspace).resolve(),
                    patch=patch,
                    baseline_digest=baseline.source_digest,
                    final_digest=final.source_digest,
                )
            observations = tuple(
                getattr(getattr(self.agent, "tools", None), "command_observations", ())
            )
            tests_log, command_metadata = build_command_evidence(observations)
            journal = tuple(
                getattr(getattr(self.agent, "tools", None), "edit_journal", ())
            )
            journal_metadata = build_edit_journal_evidence(journal)
            timed_out = any(command_metadata["timeouts"])
            external_action = result.external_action
            if job.mode is JobMode.CHAT and external_action is not None:
                raise ValueError("chat cannot propose external actions")
            if external_action is not None and external_action != {
                "effect": _EXPORT_ACTION,
                "target": _EXPORT_TARGET,
            }:
                raise ValueError("unsupported external action")
            approval_needed = not timed_out and (
                bool(patch) or external_action is not None
            )
            approval_binding: dict[str, Any] | None = None
            if approval_needed:
                approval_binding = {
                    "action": _EXPORT_ACTION,
                    "target": _EXPORT_TARGET,
                    "policyVersion": _POLICY_VERSION,
                    "resourceProfile": dict(self.resource_profile),
                    "sourceDigest": baseline.source_digest,
                    "expiresAt": _iso_timestamp(self.clock() + 300),
                }
            bundle = build_evidence_bundle(
                plan=result.plan,
                patch=patch,
                tests=tests_log,
                summary=result.summary,
                metadata={
                    **command_metadata,
                    **journal_metadata,
                    "source_digest": baseline.source_digest,
                    "proposal_source_digest": final.source_digest,
                    "approval": approval_binding,
                    "limits": {"network": "none", "max_tool_rounds": 40},
                    "started_at_epoch": started_at,
                    "finished_at_epoch": self.clock(),
                    "model_usage": {
                        "calls": result.model_calls,
                        "input_tokens": result.input_tokens,
                        "output_tokens": result.output_tokens,
                        "total_tokens": result.total_tokens,
                    },
                    "github_runner": runner_receipt,
                },
            )
            owner_prefix = hashlib.sha256(owner_id.encode("utf-8")).hexdigest()
            evidence_manifest: dict[str, dict[str, int | str]] = {}
            for name, data in bundle.files.items():
                self._renew_lease()
                key = f"{owner_prefix}/{job.id}/{bundle.proposal_digest}/{name}"
                stored = self.evidence_store.put(
                    key, data, bundle.artifact_hashes[name]
                )
                evidence_manifest[name] = {
                    "sha256": stored.sha256,
                    "bytes": stored.size,
                    "objectKey": key,
                }
            if approval_binding is not None:
                approval_proposal = {
                    **approval_binding,
                    "proposalDigest": bundle.proposal_digest,
                }
                job = self._move(
                    job,
                    JobState.AWAITING_APPROVAL,
                    proposal_digest=bundle.proposal_digest,
                    evidence_manifest=evidence_manifest,
                    summary=result.summary,
                    source_digest=baseline.source_digest,
                    approval_proposal=approval_proposal,
                )
                self.store.append_event(
                    job.id,
                    owner_id,
                    "approval_required",
                    {
                        "action": _EXPORT_ACTION,
                        "proposal_digest": bundle.proposal_digest,
                        "source_digest": baseline.source_digest,
                        "revision": job.revision,
                    },
                )
                return job
            return self._move(
                job,
                JobState.TIMED_OUT if timed_out else JobState.COMPLETED,
                proposal_digest=bundle.proposal_digest,
                evidence_manifest=evidence_manifest,
                summary=result.summary,
                source_digest=baseline.source_digest,
            )
        except PromotionRecoveryRequired:
            preserve_recovery_context = True
            raise
        except Exception as error:
            latest = self.store.get_job(job_id, owner_id)
            if latest is None or latest.state in TERMINAL_STATES:
                raise
            if latest.cancel_requested:
                return self._move(latest, JobState.CANCELLED)
            if isinstance(error, AgentDeadlineError):
                return self._move(latest, JobState.TIMED_OUT)
            failed = self._move(latest, JobState.FAILED)
            self.store.append_event(
                job_id, owner_id, "engineering_failed", {"code": "engineering_failed"}
            )
            return failed
        finally:
            if bool(
                getattr(workspace_tools, "recovery_context_exists", lambda: False)()
            ):
                preserve_recovery_context = True
            if not preserve_recovery_context:
                for snapshot_root in snapshot_roots:
                    _remove_snapshot_tree(snapshot_root)


def _iso_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat().replace("+00:00", "Z")
