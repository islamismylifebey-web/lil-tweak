from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from liltweak.workbench_contract import (
    TaskImport,
    WorkbenchApproval,
    WorkbenchState,
    WorkbenchTask,
    content_digest,
    utc_now,
)
from liltweak.workbench_store import WorkbenchConflict, WorkbenchStore

DIGEST = "a" * 64


def task() -> WorkbenchTask:
    imported = TaskImport(title="task", direction="task", source_snapshot_digest=DIGEST)
    return WorkbenchTask(
        id="task:approval",
        imported=imported,
        task_digest=imported.task_digest,
        state=WorkbenchState.RECEIVED,
    )


def approval(created_offset: int = 0, expires_offset: int = 10) -> WorkbenchApproval:
    created = utc_now() + timedelta(minutes=created_offset)
    bindings = {
        "task_id": "task:approval",
        "purpose": "execute",
        "plan_digest": DIGEST,
        "source_snapshot_digest": DIGEST,
        "project": None,
        "candidate_identity": None,
        "execution_attempt": 1,
        "approved_tool_digests": (DIGEST,),
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
    store.create_task(task())
    store.publish_approval(approval(created_offset=-2, expires_offset=-1))
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
    original = task()
    store.create_task(original)
    pending = approval()
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
