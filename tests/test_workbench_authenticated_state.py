from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from liltweak.workbench_contract import (
    ApprovalPurpose,
    CandidateSubmission,
    CommandRequest,
    EvidenceKind,
    NetworkMode,
    StepPhase,
    SubmissionStatus,
    TaskImport,
    ToolKind,
    ToolRequest,
    ToolRunRecord,
    WorkbenchApproval,
    WorkbenchPlan,
    WorkbenchState,
    WorkbenchTask,
    content_digest,
    utc_now,
)
from liltweak.workbench_store import WorkbenchConflict, WorkbenchStore

SOURCE_DIGEST = "a" * 64
POLICY_DIGEST = "b" * 64


def _store(tmp_path: Path, name: str) -> WorkbenchStore:
    return WorkbenchStore(tmp_path / name, signing_key=b"s" * 32)


def _received_task() -> WorkbenchTask:
    imported = TaskImport(
        title="task",
        direction="bounded task",
        source_snapshot_digest=SOURCE_DIGEST,
    )
    return WorkbenchTask(
        id="task:authenticated",
        imported=imported,
        task_digest=imported.task_digest,
        state=WorkbenchState.RECEIVED,
    )


def _plan() -> WorkbenchPlan:
    test_step = ToolRequest(
        tool_id="test-1",
        kind=ToolKind.COMMAND,
        phase=StepPhase.TEST,
        purpose="test",
        command=CommandRequest(executable="pytest", args=("-q",)),
    )
    verification_step = test_step.model_copy(
        update={"tool_id": "verify-1", "phase": StepPhase.VERIFICATION}
    )
    return WorkbenchPlan(
        summary="Run bounded checks.",
        reasoning="Run the required test and verification commands.",
        source_snapshot_digest=SOURCE_DIGEST,
        steps=(test_step, verification_step),
        rollback_steps=("Restore the snapshot.",),
    )


def _awaiting_approval(store: WorkbenchStore) -> WorkbenchTask:
    item = store.create_task(_received_task())
    store.transition(item.id, WorkbenchState.INSPECTING)
    store.transition(item.id, WorkbenchState.ANALYZED)
    store.transition(item.id, WorkbenchState.PLAN_READY, plan=_plan())
    return store.transition(item.id, WorkbenchState.AWAITING_APPROVAL)


def _pending_approval(task: WorkbenchTask) -> WorkbenchApproval:
    assert task.plan is not None
    bindings = {
        "task_id": task.id,
        "task_digest": task.task_digest,
        "purpose": ApprovalPurpose.EXECUTE.value,
        "plan_digest": task.plan.plan_digest,
        "source_snapshot_digest": task.imported.source_snapshot_digest,
        "repository_id": task.imported.repository_id,
        "examination_digest": None,
        "project": None,
        "candidate_identity": None,
        "execution_attempt": 1,
        "approved_tool_digests": tuple(step.request_digest for step in task.plan.steps),
        "policy_digest": POLICY_DIGEST,
        "runner_grant_digest": None,
        "network_mode": NetworkMode.DENIED.value,
        "nonce": "nonce:authenticated",
    }
    created = utc_now()
    return WorkbenchApproval(
        id="approval:authenticated",
        **bindings,
        approval_digest=content_digest(bindings),
        status="pending",
        created_at=created,
        expires_at=created + timedelta(minutes=10),
    )


def _submission(task_id: str) -> CandidateSubmission:
    values = {
        "id": "submission:authenticated",
        "task_id": task_id,
        "status": SubmissionStatus.BLOCKED,
        "summary": "Blocked before execution.",
        "resources": (),
        "verification": (),
        "reasoning": "No approved execution occurred.",
        "evidence": (),
        "known_issues": ("Source unavailable.",),
        "created_at": utc_now(),
    }
    return CandidateSubmission(
        **values,
        locked=False,
        submission_digest=content_digest(values),
    )


def _consume(
    store: WorkbenchStore,
    approval_id: str,
    task: WorkbenchTask,
) -> WorkbenchApproval:
    current = store.get_approval(approval_id)
    return store.consume_approval(
        approval_id,
        task=task,
        expected_attempt=1,
        tool_digests=current.approved_tool_digests,
        expected_purpose=ApprovalPurpose.EXECUTE,
        expected_owner_id="owner",
        policy_digest=POLICY_DIGEST,
        runner_grant_digest=None,
    )


def test_direct_sql_task_tampering_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path, "task.db")
    original = store.create_task(_received_task())
    forged = json.loads(original.model_dump_json())
    forged["imported"]["title"] = "forged task"
    store._connection.execute(
        "UPDATE workbench_tasks SET record_json=? WHERE id=?",
        (json.dumps(forged), original.id),
    )

    with pytest.raises(WorkbenchConflict, match="signature"):
        store.get_task(original.id)


def test_direct_sql_approval_tampering_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path, "approval.db")
    current = _awaiting_approval(store)
    pending = _pending_approval(current)
    store.publish_approval(pending)
    forged = pending.model_copy(
        update={"status": "approved", "approved_by": "owner", "decided_at": utc_now()}
    )
    store._connection.execute(
        "UPDATE workbench_approvals SET status='approved', record_json=? WHERE id=?",
        (forged.model_dump_json(), pending.id),
    )

    with pytest.raises(WorkbenchConflict, match="signature"):
        store.get_approval(pending.id)


def test_direct_sql_run_tampering_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path, "run.db")
    item = store.create_task(_received_task())
    now = utc_now()
    run = ToolRunRecord(
        id="run:authenticated",
        task_id=item.id,
        attempt=1,
        tool_id="test-1",
        request_digest="c" * 64,
        executable="pytest",
        args=("-q",),
        working_directory=".",
        started_at=now,
        ended_at=now,
        exit_code=0,
        timed_out=False,
        canceled=False,
        output_digest="d" * 64,
        redacted_output="passed",
        network_status=NetworkMode.DENIED,
        evidence_id="evidence:run",
        success=True,
    )
    store.save_run(run)
    forged = run.model_copy(update={"redacted_output": "forged output"})
    store._connection.execute(
        "UPDATE workbench_runs SET record_json=? WHERE id=?",
        (forged.model_dump_json(), run.id),
    )

    with pytest.raises(WorkbenchConflict, match="signature"):
        store.list_runs(item.id)


def test_direct_sql_locked_submission_tampering_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path, "submission.db")
    item = store.create_task(_received_task())
    submission = store.save_submission(_submission(item.id))
    locked = store.lock_submission(item.id, actor_id="owner")
    forged_values = locked.model_dump(
        mode="python",
        exclude={"submission_digest", "locked", "locked_at"},
    )
    forged_values["summary"] = "Forged completion claim."
    forged = locked.model_copy(
        update={
            "summary": forged_values["summary"],
            "submission_digest": content_digest(forged_values),
        }
    )
    store._connection.execute(
        """
        UPDATE workbench_submissions
        SET submission_digest=?, record_json=? WHERE id=?
        """,
        (forged.submission_digest, forged.model_dump_json(), submission.id),
    )

    with pytest.raises(WorkbenchConflict, match="signature"):
        store.get_submission_for_task(item.id)


def test_direct_sql_control_state_and_audit_tampering_fail_closed(tmp_path: Path) -> None:
    state_store = _store(tmp_path, "control-state.db")
    state_store.emergency_stop(True, actor_id="owner")
    state_store._connection.execute(
        "UPDATE workbench_control SET value='false' WHERE name='emergency_stop'"
    )
    with pytest.raises(WorkbenchConflict, match="signature"):
        state_store.is_emergency_stopped()

    audit_store = _store(tmp_path, "control-audit.db")
    audit_store.emergency_stop(True, actor_id="owner")
    audit_store._connection.execute(
        "UPDATE workbench_control_events SET actor_id='attacker' WHERE sequence=1"
    )
    with pytest.raises(WorkbenchConflict, match="audit chain"):
        audit_store.is_emergency_stopped()


def test_signed_approval_without_authenticated_decision_evidence_cannot_consume(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path, "missing-decision.db")
    current = _awaiting_approval(store)
    pending = _pending_approval(current)
    store.publish_approval(pending)
    store.decide_approval(
        pending.id,
        task_id=current.id,
        decision="approve",
        approval_digest=pending.approval_digest,
        actor_id="owner",
    )
    approved_task = store.transition(current.id, WorkbenchState.APPROVED)

    with pytest.raises(WorkbenchConflict, match="authenticated owner approval decision"):
        _consume(store, pending.id, approved_task)


def test_authenticated_decision_consumes_once_and_replay_fails(tmp_path: Path) -> None:
    store = _store(tmp_path, "single-use.db")
    current = _awaiting_approval(store)
    pending = _pending_approval(current)
    store.publish_approval(pending)
    decided = store.decide_approval(
        pending.id,
        task_id=current.id,
        decision="approve",
        approval_digest=pending.approval_digest,
        actor_id="owner",
    )
    store.append_evidence(
        current.id,
        kind=EvidenceKind.APPROVAL,
        event_type="approval_decided",
        payload={
            "approval_id": decided.id,
            "approval_digest": decided.approval_digest,
            "decision": "approve",
            "actor_id": "owner",
            "decided_at": decided.decided_at.isoformat() if decided.decided_at else None,
        },
    )
    approved_task = store.transition(current.id, WorkbenchState.APPROVED)

    consumed = _consume(store, pending.id, approved_task)
    assert consumed.status == "consumed"
    with pytest.raises(WorkbenchConflict, match="not approved"):
        _consume(store, pending.id, approved_task)
