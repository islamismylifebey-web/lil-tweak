from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path

import uvicorn

from liltweak.agent import DeterministicPlanner, OpenAIPlanner, PlanningProviderError
from liltweak.api import create_app
from liltweak.artifacts import EncryptedArtifactStore
from liltweak.config import Settings
from liltweak.costs import CostGuard
from liltweak.creator import CreatorService
from liltweak.creator_contract import CreatorCompileRequest
from liltweak.models import (
    ApprovalDecisionRequest,
    RecoveryCreateRequest,
    RepositoryRef,
    TaskCreate,
)
from liltweak.reasoning_policy import (
    REASONING_POLICY,
    require_primary_engineering_model,
)
from liltweak.recovery import RecoveryCapture
from liltweak.repository import RepositoryInspector
from liltweak.service import LilTweakService
from liltweak.store import SQLiteStore


def _service(
    planner: DeterministicPlanner | OpenAIPlanner,
    db_path: Path,
    workspace_root: Path,
) -> LilTweakService:
    store = SQLiteStore(db_path)
    inspector = RepositoryInspector(
        workspace_root,
        repository_mappings={"local:smoke-repository": "repository"},
    )
    return LilTweakService(
        store=store,
        planner=planner,
        cost_guard=CostGuard(monthly_limit_usd=250, job_default_limit_usd=5),
        repository_inspector=inspector,
        recovery_capture=RecoveryCapture(
            inspector=inspector,
            artifact_store=EncryptedArtifactStore(
                root=workspace_root.parent / "artifacts",
                workspace_root=workspace_root,
                master_key=b"LilTweakPhase3SmokeKeyMaterial!!",
                store=store,
            ),
        ),
        owner_id="maurice-pennington-bey",
        evidence_signing_key=b"LilTweakPhase3EvidenceKeyMateria",
    )


def _sample_task(task_id: str) -> TaskCreate:
    return TaskCreate(
        task_id=task_id,
        requested_by="maurice-pennington-bey",
        organization_id="owner",
        project_id="lil-tweak",
        repository=RepositoryRef(
            provider="local",
            repository_id="smoke-repository",
            revision="WORKTREE",
        ),
        objective=(
            "Inspect a bounded project and prepare the smallest safe plan to repair a "
            "connector whose token disappears after verification."
        ),
        constraints=["Do not expose credentials.", "Do not claim execution."],
        required_evidence=["root-cause evidence", "test plan", "rollback plan"],
        execution_permission=False,
    )


def _create_smoke_repository(workspace_root: Path) -> None:
    repository = workspace_root / "repository"
    repository.mkdir()
    (repository / "src").mkdir()
    (repository / "src" / "app.py").write_text(
        "from fastapi import FastAPI\n\napp = FastAPI()\n",
        encoding="utf-8",
    )
    (repository / "pyproject.toml").write_text(
        (
            "[project]\n"
            'name = "smoke-repository"\n'
            'version = "0.1.0"\n'
            'dependencies = ["fastapi>=0.100"]\n\n'
            "[tool.pytest.ini_options]\n"
            'testpaths = ["tests"]\n'
        ),
        encoding="utf-8",
    )
    (repository / ".gitignore").write_text(".env.local\n", encoding="utf-8")
    fake_secret = "sk-" + "proj-" + ("A" * 32)
    (repository / "src" / "credential-fixture.txt").write_text(
        fake_secret,
        encoding="utf-8",
    )
    commands = [
        ["git", "init", "-q", str(repository)],
        ["git", "-C", str(repository), "config", "user.name", "Lil Tweak Smoke"],
        ["git", "-C", str(repository), "config", "user.email", "smoke@example.invalid"],
        ["git", "-C", str(repository), "add", "."],
        ["git", "-C", str(repository), "commit", "-q", "-m", "Initial fixture"],
    ]
    for command in commands:
        subprocess.run(command, check=True, capture_output=True)
    (repository / "src" / "app.py").write_text(
        "from fastapi import FastAPI\n\napp = FastAPI(title='changed')\n",
        encoding="utf-8",
    )
    (repository / "src" / "recovery-note.txt").write_text(
        "safe untracked recovery fixture\n",
        encoding="utf-8",
    )


def _live_smoke_model_id() -> str:
    return require_primary_engineering_model(
        os.getenv("LILTWEAK_MODEL", REASONING_POLICY.primary_model.value)
    ).value


async def run_smoke(live: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="liltweak-smoke-") as directory:
        workspace_root = Path(directory) / "workspace"
        workspace_root.mkdir()
        _create_smoke_repository(workspace_root)
        planner = OpenAIPlanner(_live_smoke_model_id())
        if not live:
            planner = DeterministicPlanner()
        service = _service(planner, Path(directory) / "smoke.db", workspace_root)
        task = _sample_task("live-smoke" if live else "offline-smoke")
        job = service.create_job(task, "smoke-idempotency-key-0001")
        try:
            job = await service.analyze_job(job.id)
        except PlanningProviderError:
            job = service.get_job(job.id)
            print(
                json.dumps(
                    {
                        "status": job.status.value,
                        "phase": service.health().phase,
                        "execution_connected": service.health().execution_connected,
                        "plan_created": False,
                        "inspection_created": job.inspection is not None,
                        "evidence_valid": service.evidence.verify(job.id),
                        "blockers": ["Planning provider is currently unavailable."],
                    },
                    indent=2,
                )
            )
            raise SystemExit(2) from None
        recovery = service.create_recovery_request(
            job.id,
            RecoveryCreateRequest(
                expected_repository_fingerprint=(
                    job.inspection.repository_fingerprint if job.inspection else ""
                )
            ),
            "smoke-recovery-idempotency-0001",
            "maurice-pennington-bey",
        )
        service.decide_approval(
            recovery.approval_id,
            ApprovalDecisionRequest(
                decision="approve",
                action_digest=recovery.action_digest,
            ),
            "maurice-pennington-bey",
        )
        recovery = service.prepare_recovery(job.id, "maurice-pennington-bey")
        change = service.prepare_change(job.id, "maurice-pennington-bey")
        evidence_valid = service.evidence.verify(job.id)
        print(
            json.dumps(
                {
                    "status": job.status.value,
                    "phase": service.health().phase,
                    "execution_connected": service.health().execution_connected,
                    "repository_inspection_enabled": (
                        service.health().repository_inspection_enabled
                    ),
                    "durable_evidence_integrity": (service.health().durable_evidence_integrity),
                    "inspection_created": job.inspection is not None,
                    "inspection_read_only": (
                        job.inspection.read_only_verified if job.inspection else False
                    ),
                    "secret_findings_redacted": (
                        len(job.inspection.secret_findings) if job.inspection else 0
                    ),
                    "plan_created": job.plan is not None,
                    "planning_budget_reserved_usd": job.budget_reserved_usd,
                    "recovery_status": recovery.status.value,
                    "encrypted_artifact_count": len(recovery.artifacts),
                    "recovery_source_unchanged": (
                        recovery.source_fingerprint == recovery.after_fingerprint
                    ),
                    "change_preparation_status": change.status.value,
                    "change_source_writes_performed": change.source_writes_performed,
                    "evidence_valid": evidence_valid,
                    "blockers": job.plan.blockers if job.plan else [],
                },
                indent=2,
            )
        )


def run_creator_smoke() -> None:
    store = SQLiteStore(":memory:")
    creator = CreatorService(
        store=store,
        signing_key=b"LilTweakCreatorSmokeKeyMaterial!",
        durable_signatures=True,
    )
    preview = creator.prepare(
        CreatorCompileRequest(
            direction=(
                "Build a typed Creator Model API with adaptive routing and regression tests. "
                "Keep execution disconnected."
            )
        ),
        actor_id="maurice-pennington-bey",
    )
    print(
        json.dumps(
            {
                "status": preview.route.status.value,
                "version": creator.health().version,
                "work_kind": preview.envelope.brief.work_kind.value,
                "brief_digest": preview.envelope.brief_digest,
                "selected_tier": (
                    preview.route.selected_tier.value
                    if preview.route.selected_tier is not None
                    else None
                ),
                "reasoning_effort": (
                    preview.route.reasoning_effort.value
                    if preview.route.reasoning_effort is not None
                    else None
                ),
                "model_call_authorized": preview.route.model_call_authorized,
                "tool_use_authorized": preview.route.tool_use_authorized,
                "spend_authorized": preview.route.spend_authorized,
                "execution_authorized": preview.route.execution_authorized,
                "execution_connected": preview.execution_connected,
            },
            indent=2,
        )
    )


def main() -> None:
    port = os.getenv("PORT")
    if port:
        settings = Settings.from_env()
        uvicorn.run(
            create_app(settings=settings),
            host=settings.server_host,
            port=int(port),
            log_level="info",
        )
        return

    parser = argparse.ArgumentParser(description="Lil Tweak Phase 3 runtime")
    parser.add_argument(
        "command",
        choices=[
            "smoke",
            "creator-smoke",
            "live-smoke",
            "phase2-live-smoke",
            "phase3-live-smoke",
        ],
    )
    args = parser.parse_args()
    if args.command == "creator-smoke":
        run_creator_smoke()
        return
    asyncio.run(
        run_smoke(live=args.command in {"live-smoke", "phase2-live-smoke", "phase3-live-smoke"})
    )


if __name__ == "__main__":
    main()
