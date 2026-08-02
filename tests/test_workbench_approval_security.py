from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from liltweak.workbench_contract import (
    ApprovalPurpose,
    CommandRequest,
    GcpExamConfig,
    NetworkMode,
    StepPhase,
    TaskImport,
    ToolKind,
    ToolRequest,
    WorkbenchApproval,
    WorkbenchMode,
    WorkbenchPlan,
    WorkbenchState,
    WorkbenchTask,
    content_digest,
    utc_now,
)
from liltweak.workbench_store import WorkbenchConflict, WorkbenchStore

DIGEST = "a" * 64
POLICY_DIGEST = "b" * 64


def task() -> WorkbenchTask:
    imported = TaskImport(title="task", direction="task", source_snapshot_digest=DIGEST)
    return WorkbenchTask(
        id="task:approval",
        imported=imported,
        task_digest=imported.task_digest,
        state=WorkbenchState.RECEIVED,
    )


def plan() -> WorkbenchPlan:
    command = ToolRequest(
        tool_id="test-1",
        kind=ToolKind.COMMAND,
        phase=StepPhase.TEST,
        purpose="test",
        command=CommandRequest(executable="pytest", args=("-q",)),
    )
    verify = command.model_copy(update={"tool_id": "verify-1", "phase": StepPhase.VERIFICATION})
    return WorkbenchPlan(
        summary="bounded checks",
        reasoning="Run required checks.",
        source_snapshot_digest=DIGEST,
        steps=(command, verify),
        rollback_steps=("restore",),
    )


def awaiting(store: WorkbenchStore, imported: TaskImport | None = None) -> WorkbenchTask:
    received = (
        task()
        if imported is None
        else WorkbenchTask(
            id="task:gcp-approval",
            imported=imported,
            task_digest=imported.task_digest,
            state=WorkbenchState.RECEIVED,
        )
    )
    store.create_task(received)
    store.transition(received.id, WorkbenchState.INSPECTING)
    store.transition(received.id, WorkbenchState.ANALYZED)
    store.transition(received.id, WorkbenchState.PLAN_READY, plan=plan())
    return store.transition(received.id, WorkbenchState.AWAITING_APPROVAL)


def approval(
    current: WorkbenchTask,
    *,
    created_offset: int = 0,
    expires_offset: int = 10,
    project: str | None = None,
    candidate_identity: str | None = None,
) -> WorkbenchApproval:
    created = utc_now() + timedelta(minutes=created_offset)
    exam = current.imported.examination
    assert current.plan is not None
    bindings = {
        "task_id": current.id,
        "task_digest": current.task_digest,
        "purpose": ApprovalPurpose.EXECUTE.value,
        "plan_digest": current.plan.plan_digest,
        "source_snapshot_digest": DIGEST,
        "repository_id": current.imported.repository_id,
        "examination_digest": exam.config_digest if exam else None,
        "project": project,
        "candidate_identity": candidate_identity,
        "execution_attempt": 1,
        "approved_tool_digests": tuple(step.request_digest for step in current.plan.steps),
        "policy_digest": POLICY_DIGEST,
        "runner_grant_digest": None,
        "network_mode": NetworkMode.DENIED.value,
        "nonce": "nonce:test",
    }
    return WorkbenchApproval(
        id="approval:one",
        **bindings,
        approval_digest=content_digest(bindings),
        status="pending",
        created_at=created,
        expires_at=utc_now() + timedelta(minutes=expires_offset),
    )


def test_expired_approval_is_never_approved(tmp_path: Path) -> None:
    store = WorkbenchStore(tmp_path / "workbench.db")
    current = awaiting(store)
    store.publish_approval(approval(current, created_offset=-2, expires_offset=-1))
    assert store.get_approval("approval:one").status == "expired"
    with pytest.raises(WorkbenchConflict):
        store.decide_approval(
            "approval:one",
            task_id="task:approval",
            decision="approve",
            approval_digest=store.get_approval("approval:one").approval_digest,
            actor_id="owner",
        )


def test_changed_digest_and_reuse_are_rejected(tmp_path: Path) -> None:
    store = WorkbenchStore(tmp_path / "workbench.db")
    original = awaiting(store)
    pending = approval(original)
    store.publish_approval(pending)
    with pytest.raises(WorkbenchConflict, match="digest"):
        store.decide_approval(
            pending.id,
            task_id=original.id,
            decision="approve",
            approval_digest="b" * 64,
            actor_id="owner",
        )
    approved = store.decide_approval(
        pending.id,
        task_id=original.id,
        decision="approve",
        approval_digest=pending.approval_digest,
        actor_id="owner",
    )
    assert approved.status == "approved"
    with pytest.raises(WorkbenchConflict, match="pending"):
        store.decide_approval(
            pending.id,
            task_id=original.id,
            decision="approve",
            approval_digest=pending.approval_digest,
            actor_id="owner",
        )


def test_consumption_rejects_changed_project_or_candidate_identity(tmp_path: Path) -> None:
    store = WorkbenchStore(tmp_path / "workbench.db")
    imported = TaskImport(
        mode=WorkbenchMode.GCP_QUALIFICATION,
        title="GCP task",
        direction="bounded verification",
        source_snapshot_digest=DIGEST,
        examination=GcpExamConfig(
            examination_id="exam-1",
            authorized_project="valid-project-1",
            candidate_service_account=("candidate@valid-project-1.iam.gserviceaccount.com"),
            region="us-central1",
            zone="us-central1-a",
            spending_ceiling_usd=1,
            current_task_number=1,
        ),
    )
    current = awaiting(store, imported)
    pending = approval(
        current,
        project="other-project-1",
        candidate_identity="candidate@other-project-1.iam.gserviceaccount.com",
    )
    changed = pending.model_copy(update={"id": "approval:gcp-wrong-binding"})
    store.publish_approval(changed)
    changed = store.decide_approval(
        changed.id,
        task_id=current.id,
        decision="approve",
        approval_digest=changed.approval_digest,
        actor_id="owner",
    )
    current = store.transition(current.id, WorkbenchState.APPROVED)

    with pytest.raises(WorkbenchConflict, match="binding changed"):
        store.consume_approval(
            changed.id,
            task=current,
            expected_attempt=1,
            tool_digests=changed.approved_tool_digests,
            expected_purpose=ApprovalPurpose.EXECUTE,
            expected_owner_id="owner",
            policy_digest=POLICY_DIGEST,
            runner_grant_digest=None,
        )
