from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from liltweak.agent import DeterministicPlanner
from liltweak.approvals import ApprovalError
from liltweak.artifacts import EncryptedArtifactStore
from liltweak.costs import CostGuard
from liltweak.models import (
    ApprovalDecisionRequest,
    ApprovalStatus,
    Environment,
    JobStatus,
    RecoveryCreateRequest,
    RepositoryRef,
    TaskCreate,
)
from liltweak.recovery import RecoveryBlockedError, RecoveryCapture
from liltweak.repository import RepositoryInspector
from liltweak.service import EmergencyStopError, LilTweakService
from liltweak.store import SQLiteStore, canonical_json
from tests.repository_helpers import initialize_repository


def _service(tmp_path: Path) -> tuple[LilTweakService, Path, str]:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    repository, head = initialize_repository(workspace)
    store = SQLiteStore(":memory:")
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )
    artifact_store = EncryptedArtifactStore(
        root=tmp_path / "artifacts",
        workspace_root=workspace,
        master_key=b"T" * 32,
        store=store,
    )
    service = LilTweakService(
        store=store,
        planner=DeterministicPlanner(),
        cost_guard=CostGuard(monthly_limit_usd=250, job_default_limit_usd=5),
        repository_inspector=inspector,
        recovery_capture=RecoveryCapture(
            inspector=inspector,
            artifact_store=artifact_store,
        ),
        owner_id="owner",
    )
    return service, repository, head


def _task(
    head: str,
    *,
    task_id: str,
    environment: Environment = Environment.DEVELOPMENT,
    prohibited_actions: list[str] | None = None,
) -> TaskCreate:
    return TaskCreate(
        task_id=task_id,
        requested_by="owner",
        organization_id="owner",
        project_id="lil-tweak",
        repository=RepositoryRef(
            provider="local",
            repository_id="fixture",
            revision=head,
        ),
        environment=environment,
        objective="Prepare a review-only technical change.",
        prohibited_actions=prohibited_actions or [],
    )


@pytest.mark.asyncio
async def test_technical_approval_binds_plan_and_source_snapshot(tmp_path: Path) -> None:
    service, _repository, head = _service(tmp_path)
    job = service.create_job(
        _task(
            head,
            task_id="bound-approval",
            environment=Environment.PRODUCTION,
        ),
        "bound-approval-key-0001",
    )
    job = await service.analyze_job(job.id)
    approval = service.approvals.get(job.approval_id or "")
    assert (
        approval.proposal.plan_digest
        == hashlib.sha256(
            canonical_json(job.plan.model_dump(mode="json")).encode()  # type: ignore[union-attr]
        ).hexdigest()
    )
    assert approval.proposal.source_snapshot_digest == (
        job.inspection.git.recovery_snapshot_digest  # type: ignore[union-attr]
    )

    persisted = service.get_job(job.id)
    assert persisted.plan is not None
    persisted.plan.objective = "A different, unapproved plan."
    service.store.save_job(persisted)
    with pytest.raises(ApprovalError, match="stale"):
        service.decide_approval(
            approval.id,
            ApprovalDecisionRequest(
                decision="approve",
                action_digest=approval.action_digest,
            ),
            "owner",
        )
    assert service.approvals.get(approval.id).status == ApprovalStatus.PENDING


@pytest.mark.asyncio
async def test_prohibited_recovery_operation_is_enforced(tmp_path: Path) -> None:
    service, repository, head = _service(tmp_path)
    (repository / "notes.txt").write_text("recover me\n", encoding="utf-8")
    job = service.create_job(
        _task(
            head,
            task_id="prohibited-recovery",
            prohibited_actions=["prepare_recovery_package"],
        ),
        "prohibited-recovery-job-0001",
    )
    job = await service.analyze_job(job.id)
    assert job.inspection is not None
    with pytest.raises(RecoveryBlockedError) as blocked:
        service.create_recovery_request(
            job.id,
            RecoveryCreateRequest(
                expected_repository_fingerprint=job.inspection.repository_fingerprint,
            ),
            "prohibited-recovery-request-0001",
            "owner",
        )
    assert blocked.value.code == "operation_prohibited"


@pytest.mark.asyncio
async def test_change_preparation_requires_complete_inspection_and_uses_clean_rollback(
    tmp_path: Path,
) -> None:
    service, _repository, head = _service(tmp_path)
    first = service.create_job(
        _task(head, task_id="clean-change"),
        "clean-change-job-key-0001",
    )
    first = await service.analyze_job(first.id)
    preparation = service.prepare_change(first.id, "owner")
    assert preparation.plan_digest == service._plan_digest(first)
    assert preparation.source_snapshot_digest == first.inspection.git.recovery_snapshot_digest  # type: ignore[union-attr]
    assert preparation.recovery_package_id is None
    assert "exact base revision" in preparation.rollback_plan[0]

    second = service.create_job(
        _task(head, task_id="incomplete-change"),
        "incomplete-change-job-key-0001",
    )
    second = await service.analyze_job(second.id)
    assert second.inspection is not None
    second.inspection.complete = False
    service.store.save_job(second)
    with pytest.raises(RecoveryBlockedError) as blocked:
        service.prepare_change(second.id, "owner")
    assert blocked.value.code == "inspection_incomplete"


@pytest.mark.asyncio
async def test_canceled_and_emergency_stopped_approvals_are_invalidated(tmp_path: Path) -> None:
    service, _repository, head = _service(tmp_path)
    canceled = service.create_job(
        _task(
            head,
            task_id="canceled-approval",
            environment=Environment.PRODUCTION,
        ),
        "canceled-approval-key-0001",
    )
    canceled = await service.analyze_job(canceled.id)
    approval = service.approvals.get(canceled.approval_id or "")
    service.cancel_job(canceled.id, "owner")
    with pytest.raises(ApprovalError, match="canceled"):
        service.decide_approval(
            approval.id,
            ApprovalDecisionRequest(
                decision="approve",
                action_digest=approval.action_digest,
            ),
            "owner",
        )
    assert service.approvals.get(approval.id).status == ApprovalStatus.INVALIDATED
    assert service.get_job(canceled.id).status == JobStatus.CANCELED

    stopped_service, _repository, stopped_head = _service(tmp_path / "stopped")
    waiting = stopped_service.create_job(
        _task(
            stopped_head,
            task_id="stopped-approval",
            environment=Environment.PRODUCTION,
        ),
        "stopped-approval-key-0001",
    )
    waiting = await stopped_service.analyze_job(waiting.id)
    stopped_approval = stopped_service.approvals.get(waiting.approval_id or "")
    stopped_service.emergency_stop("owner")
    with pytest.raises(EmergencyStopError):
        stopped_service.decide_approval(
            stopped_approval.id,
            ApprovalDecisionRequest(
                decision="approve",
                action_digest=stopped_approval.action_digest,
            ),
            "owner",
        )
    assert stopped_service.approvals.get(stopped_approval.id).status == ApprovalStatus.INVALIDATED
