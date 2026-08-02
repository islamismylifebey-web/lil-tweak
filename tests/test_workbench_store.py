from __future__ import annotations

from pathlib import Path

import pytest

from liltweak.workbench_contract import (
    CandidateSubmission,
    EvidenceKind,
    SubmissionStatus,
    TaskImport,
    WorkbenchState,
    WorkbenchTask,
    content_digest,
    utc_now,
)
from liltweak.workbench_store import WorkbenchConflict, WorkbenchStore

DIGEST = "a" * 64


def make_task(identifier: str = "task:1") -> WorkbenchTask:
    imported = TaskImport(
        title="task",
        direction="do the task",
        source_snapshot_digest=DIGEST,
    )
    return WorkbenchTask(
        id=identifier,
        imported=imported,
        task_digest=imported.task_digest,
        state=WorkbenchState.RECEIVED,
    )


def test_state_machine_and_evidence_chain(tmp_path: Path) -> None:
    store = WorkbenchStore(tmp_path / "workbench.db")
    task = store.create_task(make_task())
    assert store.transition(task.id, WorkbenchState.INSPECTING).state == WorkbenchState.INSPECTING
    assert store.transition(task.id, WorkbenchState.ANALYZED).state == WorkbenchState.ANALYZED
    first = store.append_evidence(
        task.id, kind=EvidenceKind.TASK, event_type="task_received", payload={"one": 1}
    )
    second = store.append_evidence(
        task.id, kind=EvidenceKind.SOURCE, event_type="source_inspected", payload={"two": 2}
    )
    assert second.previous_hash == first.record_hash
    assert store.list_evidence(task.id) == [first, second]


def test_evidence_tampering_is_detected(tmp_path: Path) -> None:
    store = WorkbenchStore(tmp_path / "workbench.db", signing_key=b"e" * 32)
    item = store.create_task(make_task())
    evidence = store.append_evidence(
        item.id,
        kind=EvidenceKind.TASK,
        event_type="task_received",
        payload={"truth": True},
    )
    store._connection.execute(
        "UPDATE workbench_evidence SET record_hash=? WHERE id=?",
        ("b" * 64, evidence.id),
    )
    with pytest.raises(WorkbenchConflict, match="integrity"):
        store.list_evidence(item.id)


def test_evidence_anchor_is_durable_and_key_authenticated(tmp_path: Path) -> None:
    database = tmp_path / "workbench.db"
    key = b"e" * 32
    store = WorkbenchStore(database, signing_key=key)
    item = store.create_task(make_task())
    evidence = store.append_evidence(
        item.id,
        kind=EvidenceKind.TASK,
        event_type="task_received",
        payload={"truth": True},
    )
    store.close()

    reopened = WorkbenchStore(database, signing_key=key)
    assert reopened.list_evidence(item.id) == [evidence]
    reopened.close()

    wrong_key = WorkbenchStore(database, signing_key=b"x" * 32)
    with pytest.raises(WorkbenchConflict, match="authenticated anchor"):
        wrong_key.list_evidence(item.id)


def test_invalid_state_transition_fails_closed(tmp_path: Path) -> None:
    store = WorkbenchStore(tmp_path / "workbench.db")
    task = store.create_task(make_task())
    with pytest.raises(WorkbenchConflict, match="invalid state"):
        store.transition(task.id, WorkbenchState.COMPLETED)


def test_task_digest_is_immutable_and_unique(tmp_path: Path) -> None:
    store = WorkbenchStore(tmp_path / "workbench.db")
    store.create_task(make_task())
    with pytest.raises(WorkbenchConflict):
        store.create_task(make_task("task:2"))


def test_only_one_nonterminal_task_is_admitted(tmp_path: Path) -> None:
    store = WorkbenchStore(tmp_path / "workbench.db")
    first = store.create_task(make_task())
    second_import = TaskImport(
        title="second",
        direction="different task",
        source_snapshot_digest=DIGEST,
    )
    second = WorkbenchTask(
        id="task:2",
        imported=second_import,
        task_digest=second_import.task_digest,
        state=WorkbenchState.RECEIVED,
    )
    with pytest.raises(WorkbenchConflict, match="active"):
        store.create_task(second)
    store.transition(first.id, WorkbenchState.BLOCKED)
    assert store.create_task(second).id == "task:2"


def test_model_admission_is_single_use_and_monthly_bounded(tmp_path: Path) -> None:
    store = WorkbenchStore(tmp_path / "workbench.db")
    store.claim_model_admission(
        admission_id="model-admission:one",
        task_digest=DIGEST,
        model="model",
        reservation_usd=0.1,
        monthly_limit_usd=1.0,
    )
    with pytest.raises(WorkbenchConflict, match="concurrent"):
        store.claim_model_admission(
            admission_id="model-admission:duplicate",
            task_digest=DIGEST,
            model="model",
            reservation_usd=0.1,
            monthly_limit_usd=1.0,
        )
    store.finish_model_admission(
        admission_id="model-admission:one",
        succeeded=True,
        input_tokens=10,
        output_tokens=20,
        response_id_hash=None,
    )
    for index in (2, 3):
        admission_id = f"model-admission:{index}"
        store.claim_model_admission(
            admission_id=admission_id,
            task_digest=DIGEST,
            model="model",
            reservation_usd=0.1,
            monthly_limit_usd=1.0,
        )
        store.finish_model_admission(
            admission_id=admission_id,
            succeeded=False,
            input_tokens=0,
            output_tokens=0,
            response_id_hash=None,
        )
    with pytest.raises(WorkbenchConflict, match="revision"):
        store.claim_model_admission(
            admission_id="model-admission:four",
            task_digest=DIGEST,
            model="model",
            reservation_usd=0.1,
            monthly_limit_usd=1.0,
        )
    with pytest.raises(WorkbenchConflict, match="monthly"):
        store.claim_model_admission(
            admission_id="model-admission:over-budget",
            task_digest="b" * 64,
            model="model",
            reservation_usd=0.8,
            monthly_limit_usd=1.0,
        )


def test_locked_submission_requires_auditable_reopen(tmp_path: Path) -> None:
    store = WorkbenchStore(tmp_path / "workbench.db")
    item = store.create_task(make_task())
    values = {
        "id": "submission:one",
        "task_id": item.id,
        "status": SubmissionStatus.BLOCKED,
        "summary": "Blocked before execution.",
        "resources": (),
        "verification": (),
        "reasoning": "No approved execution occurred.",
        "evidence": (),
        "known_issues": ("Source unavailable.",),
        "created_at": utc_now(),
    }
    submission = CandidateSubmission(
        **values,
        locked=False,
        submission_digest=content_digest(values),
    )
    store.save_submission(submission)
    assert store.lock_submission(item.id, actor_id="owner").locked is True
    with pytest.raises(WorkbenchConflict, match="locked"):
        store.save_submission(submission)
    assert store.reopen_submission(item.id, actor_id="owner").locked is False
