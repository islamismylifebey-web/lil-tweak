from __future__ import annotations

import hashlib
import secrets
import sqlite3
from pathlib import Path
from threading import RLock

from .workbench_contract import (
    CandidateSubmission,
    EvidenceKind,
    ToolRunRecord,
    WorkbenchApproval,
    WorkbenchEvidence,
    WorkbenchPlan,
    WorkbenchState,
    WorkbenchTask,
    content_digest,
    utc_now,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS workbench_tasks (
    id TEXT PRIMARY KEY,
    task_digest TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_workbench_one_active_task
ON workbench_tasks((1))
WHERE state NOT IN ('COMPLETED','BLOCKED','FAILED','ROLLED_BACK','CANCELED');

CREATE TABLE IF NOT EXISTS workbench_approvals (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    status TEXT NOT NULL,
    approval_digest TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(task_id) REFERENCES workbench_tasks(id)
);
CREATE INDEX IF NOT EXISTS ix_workbench_approval_task ON workbench_approvals(task_id, status);

CREATE TABLE IF NOT EXISTS workbench_runs (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    tool_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(task_id, attempt, tool_id),
    FOREIGN KEY(task_id) REFERENCES workbench_tasks(id)
);

CREATE TABLE IF NOT EXISTS workbench_model_admissions (
    id TEXT PRIMARY KEY,
    task_digest TEXT NOT NULL,
    planning_attempt INTEGER NOT NULL CHECK(planning_attempt BETWEEN 1 AND 3),
    model TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('claimed','succeeded','failed')),
    reservation_usd REAL NOT NULL CHECK(reservation_usd > 0),
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    response_id_hash TEXT,
    created_at TEXT NOT NULL,
    finished_at TEXT,
    UNIQUE(task_digest, planning_attempt)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_workbench_one_claimed_model
ON workbench_model_admissions(task_digest) WHERE status='claimed';

CREATE TABLE IF NOT EXISTS workbench_evidence (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    kind TEXT NOT NULL,
    event_type TEXT NOT NULL,
    record_json TEXT NOT NULL,
    record_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    UNIQUE(task_id, sequence),
    FOREIGN KEY(task_id) REFERENCES workbench_tasks(id)
);

CREATE TABLE IF NOT EXISTS workbench_submissions (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    locked INTEGER NOT NULL DEFAULT 0,
    submission_digest TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(task_id) REFERENCES workbench_tasks(id)
);

CREATE TABLE IF NOT EXISTS workbench_control (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
INSERT OR IGNORE INTO workbench_control(name, value, updated_at)
VALUES ('emergency_stop', 'false', CURRENT_TIMESTAMP);
"""

_ALLOWED_TRANSITIONS: dict[WorkbenchState, frozenset[WorkbenchState]] = {
    WorkbenchState.RECEIVED: frozenset(
        {WorkbenchState.INSPECTING, WorkbenchState.CANCELED, WorkbenchState.BLOCKED}
    ),
    WorkbenchState.INSPECTING: frozenset(
        {
            WorkbenchState.ANALYZED,
            WorkbenchState.BLOCKED,
            WorkbenchState.FAILED,
            WorkbenchState.CANCELED,
        }
    ),
    WorkbenchState.ANALYZED: frozenset(
        {
            WorkbenchState.PLAN_READY,
            WorkbenchState.BLOCKED,
            WorkbenchState.FAILED,
            WorkbenchState.CANCELED,
        }
    ),
    WorkbenchState.PLAN_READY: frozenset(
        {WorkbenchState.AWAITING_APPROVAL, WorkbenchState.ANALYZED, WorkbenchState.CANCELED}
    ),
    WorkbenchState.AWAITING_APPROVAL: frozenset(
        {WorkbenchState.APPROVED, WorkbenchState.ANALYZED, WorkbenchState.CANCELED}
    ),
    WorkbenchState.APPROVED: frozenset(
        {
            WorkbenchState.EXECUTING,
            WorkbenchState.CANCELED,
            WorkbenchState.BLOCKED,
            WorkbenchState.ROLLED_BACK,
        }
    ),
    WorkbenchState.EXECUTING: frozenset(
        {
            WorkbenchState.TESTING,
            WorkbenchState.FAILED,
            WorkbenchState.CANCELED,
            WorkbenchState.BLOCKED,
        }
    ),
    WorkbenchState.TESTING: frozenset(
        {WorkbenchState.VERIFIED, WorkbenchState.FAILED, WorkbenchState.CANCELED}
    ),
    WorkbenchState.VERIFIED: frozenset(
        {WorkbenchState.COMPLETED, WorkbenchState.FAILED, WorkbenchState.ROLLED_BACK}
    ),
    WorkbenchState.COMPLETED: frozenset(),
    WorkbenchState.BLOCKED: frozenset({WorkbenchState.INSPECTING, WorkbenchState.CANCELED}),
    WorkbenchState.FAILED: frozenset({WorkbenchState.ANALYZED, WorkbenchState.ROLLED_BACK}),
    WorkbenchState.ROLLED_BACK: frozenset({WorkbenchState.ANALYZED}),
    WorkbenchState.CANCELED: frozenset(),
}


class WorkbenchStoreError(RuntimeError):
    pass


class WorkbenchNotFound(WorkbenchStoreError):
    pass


class WorkbenchConflict(WorkbenchStoreError):
    pass


class WorkbenchStore:
    def __init__(self, database_path: Path | str) -> None:
        self._path = str(database_path)
        self._connection = sqlite3.connect(self._path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = RLock()
        with self._lock, self._connection:
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA busy_timeout=30000")
            self._connection.executescript(SCHEMA)

    def close(self) -> None:
        self._connection.close()

    def create_task(self, task: WorkbenchTask) -> WorkbenchTask:
        if task.state != WorkbenchState.RECEIVED:
            raise WorkbenchConflict("new workbench tasks must start in RECEIVED")
        record = task.model_dump_json()
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """
                    INSERT INTO workbench_tasks(
                        id, task_digest, state, record_json, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        task.id,
                        task.task_digest,
                        task.state.value,
                        record,
                        task.created_at.isoformat(),
                        task.updated_at.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise WorkbenchConflict("duplicate task or another active Workbench task") from exc
        return task

    def get_task(self, task_id: str) -> WorkbenchTask:
        row = self._connection.execute(
            "SELECT record_json FROM workbench_tasks WHERE id=?", (task_id,)
        ).fetchone()
        if row is None:
            raise WorkbenchNotFound("workbench task was not found")
        return WorkbenchTask.model_validate_json(row["record_json"])

    def list_tasks(self, *, limit: int = 100) -> list[WorkbenchTask]:
        if limit < 1 or limit > 200:
            raise ValueError("task list limit is invalid")
        rows = self._connection.execute(
            "SELECT record_json FROM workbench_tasks ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [WorkbenchTask.model_validate_json(row["record_json"]) for row in rows]

    def transition(
        self,
        task_id: str,
        target: WorkbenchState,
        *,
        plan: WorkbenchPlan | None = None,
        blocked_reason: str | None = None,
        increment_attempt: bool = False,
    ) -> WorkbenchTask:
        with self._lock, self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            task = self._get_task_locked(task_id)
            if target not in _ALLOWED_TRANSITIONS[task.state]:
                raise WorkbenchConflict(
                    f"invalid state transition: {task.state.value} -> {target.value}"
                )
            update: dict[str, object] = {
                "state": target,
                "updated_at": utc_now(),
                "blocked_reason": blocked_reason,
            }
            if plan is not None:
                if plan.source_snapshot_digest != task.imported.source_snapshot_digest:
                    raise WorkbenchConflict("plan is bound to a different source snapshot")
                update["plan"] = plan
                update["plan_digest"] = plan.plan_digest
            if increment_attempt:
                update["active_attempt"] = task.active_attempt + 1
            changed = task.model_copy(update=update)
            changed = WorkbenchTask.model_validate(changed.model_dump(mode="python"))
            try:
                self._save_task_locked(changed)
            except sqlite3.IntegrityError as exc:
                raise WorkbenchConflict("another Workbench task is active") from exc
            return changed

    def set_creator_bindings(
        self, task_id: str, *, brief_digest: str, route_digest: str
    ) -> WorkbenchTask:
        with self._lock, self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            task = self._get_task_locked(task_id)
            changed = task.model_copy(
                update={
                    "creator_brief_digest": brief_digest,
                    "creator_route_digest": route_digest,
                    "updated_at": utc_now(),
                }
            )
            changed = WorkbenchTask.model_validate(changed.model_dump(mode="python"))
            self._save_task_locked(changed)
            return changed

    def publish_approval(self, approval: WorkbenchApproval) -> None:
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """
                    INSERT INTO workbench_approvals(
                        id, task_id, status, approval_digest, record_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        approval.id,
                        approval.task_id,
                        approval.status,
                        approval.approval_digest,
                        approval.model_dump_json(),
                        approval.created_at.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise WorkbenchConflict("approval already exists") from exc

    def get_approval(self, approval_id: str) -> WorkbenchApproval:
        row = self._connection.execute(
            "SELECT record_json FROM workbench_approvals WHERE id=?", (approval_id,)
        ).fetchone()
        if row is None:
            raise WorkbenchNotFound("workbench approval was not found")
        approval = WorkbenchApproval.model_validate_json(row["record_json"])
        if approval.status in {"pending", "approved"} and utc_now() >= approval.expires_at:
            approval = self._set_approval_status(approval, "expired")
        return approval

    def decide_approval(
        self,
        approval_id: str,
        *,
        task_id: str,
        decision: str,
        approval_digest: str,
        actor_id: str,
    ) -> WorkbenchApproval:
        statuses = {"approve": "approved", "reject": "rejected", "request_revision": "revision"}
        with self._lock, self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            approval = self._get_approval_locked(approval_id)
            if approval.task_id != task_id:
                raise WorkbenchConflict("approval task binding does not match")
            if approval.status != "pending":
                raise WorkbenchConflict("approval is not pending")
            if utc_now() >= approval.expires_at:
                self._save_approval_locked(approval.model_copy(update={"status": "expired"}))
                raise WorkbenchConflict("approval expired")
            submitted = hashlib.sha256(approval_digest.encode()).digest()
            expected = hashlib.sha256(approval.approval_digest.encode()).digest()
            if not secrets.compare_digest(submitted, expected):
                raise WorkbenchConflict("approval digest mismatch")
            changed = approval.model_copy(
                update={
                    "status": statuses[decision],
                    "approved_by": actor_id if decision == "approve" else None,
                    "decided_at": utc_now(),
                }
            )
            changed = WorkbenchApproval.model_validate(changed.model_dump(mode="python"))
            self._save_approval_locked(changed)
            return changed

    def consume_approval(
        self,
        approval_id: str,
        *,
        task: WorkbenchTask,
        expected_attempt: int,
        tool_digests: tuple[str, ...],
    ) -> WorkbenchApproval:
        with self._lock, self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            approval = self._get_approval_locked(approval_id)
            if approval.status != "approved":
                raise WorkbenchConflict("approval is not approved")
            if utc_now() >= approval.expires_at:
                self._save_approval_locked(approval.model_copy(update={"status": "expired"}))
                raise WorkbenchConflict("approval expired")
            if (
                approval.task_id != task.id
                or approval.plan_digest != task.plan_digest
                or approval.source_snapshot_digest != task.imported.source_snapshot_digest
                or approval.execution_attempt != expected_attempt
                or approval.approved_tool_digests != tool_digests
            ):
                raise WorkbenchConflict("approval binding changed")
            changed = approval.model_copy(update={"status": "consumed", "consumed_at": utc_now()})
            changed = WorkbenchApproval.model_validate(changed.model_dump(mode="python"))
            self._save_approval_locked(changed)
            return changed

    def save_run(self, run: ToolRunRecord) -> None:
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """
                    INSERT INTO workbench_runs(
                        id, task_id, attempt, tool_id, request_digest, record_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run.id,
                        run.task_id,
                        run.attempt,
                        run.tool_id,
                        run.request_digest,
                        run.model_dump_json(),
                        run.started_at.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise WorkbenchConflict("duplicate tool run") from exc

    def claim_model_admission(
        self,
        *,
        admission_id: str,
        task_digest: str,
        model: str,
        reservation_usd: float,
        monthly_limit_usd: float,
        max_calls_per_task: int = 3,
    ) -> None:
        if max_calls_per_task < 1 or max_calls_per_task > 3:
            raise ValueError("model call limit must be between one and three")
        month = utc_now().strftime("%Y-%m")
        with self._lock, self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            row = self._connection.execute(
                """
                SELECT COALESCE(SUM(reservation_usd), 0) AS total
                FROM workbench_model_admissions
                WHERE substr(created_at, 1, 7)=?
                """,
                (month,),
            ).fetchone()
            reserved = float(row["total"])
            if reserved + reservation_usd > monthly_limit_usd:
                raise WorkbenchConflict("Workbench model monthly cost limit exceeded")
            attempt_row = self._connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM workbench_model_admissions WHERE task_digest=?
                """,
                (task_digest,),
            ).fetchone()
            planning_attempt = int(attempt_row["count"]) + 1
            if planning_attempt > max_calls_per_task:
                raise WorkbenchConflict("explicit model revision limit exceeded")
            try:
                self._connection.execute(
                    """
                    INSERT INTO workbench_model_admissions(
                        id, task_digest, planning_attempt, model, status,
                        reservation_usd, created_at
                    ) VALUES (?, ?, ?, ?, 'claimed', ?, ?)
                    """,
                    (
                        admission_id,
                        task_digest,
                        planning_attempt,
                        model,
                        reservation_usd,
                        utc_now().isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise WorkbenchConflict(
                    "concurrent or duplicate paid model request is prohibited"
                ) from exc

    def finish_model_admission(
        self,
        *,
        admission_id: str,
        succeeded: bool,
        input_tokens: int,
        output_tokens: int,
        response_id_hash: str | None,
    ) -> None:
        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("model usage cannot be negative")
        if response_id_hash is not None and (
            len(response_id_hash) != 64
            or any(character not in "0123456789abcdef" for character in response_id_hash)
        ):
            raise ValueError("provider response identifier hash is invalid")
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE workbench_model_admissions
                SET status=?, input_tokens=?, output_tokens=?,
                    response_id_hash=?, finished_at=?
                WHERE id=? AND status='claimed'
                """,
                (
                    "succeeded" if succeeded else "failed",
                    input_tokens,
                    output_tokens,
                    response_id_hash,
                    utc_now().isoformat(),
                    admission_id,
                ),
            )
            if cursor.rowcount != 1:
                raise WorkbenchConflict("model admission is not claimable")

    def list_runs(self, task_id: str) -> list[ToolRunRecord]:
        rows = self._connection.execute(
            "SELECT record_json FROM workbench_runs WHERE task_id=? ORDER BY created_at, tool_id",
            (task_id,),
        ).fetchall()
        return [ToolRunRecord.model_validate_json(row["record_json"]) for row in rows]

    def append_evidence(
        self,
        task_id: str,
        *,
        kind: EvidenceKind,
        event_type: str,
        payload: dict[str, object],
    ) -> WorkbenchEvidence:
        now = utc_now()
        with self._lock, self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            row = self._connection.execute(
                """
                SELECT sequence, record_hash FROM workbench_evidence
                WHERE task_id=? ORDER BY sequence DESC LIMIT 1
                """,
                (task_id,),
            ).fetchone()
            sequence = 1 if row is None else int(row["sequence"]) + 1
            previous_hash = None if row is None else str(row["record_hash"])
            digest_payload = {
                "task_id": task_id,
                "sequence": sequence,
                "kind": kind.value,
                "event_type": event_type,
                "payload": payload,
                "previous_hash": previous_hash,
                "created_at": now.isoformat(),
            }
            record_hash = content_digest(digest_payload)
            evidence = WorkbenchEvidence(
                id=f"evidence:{record_hash[:24]}",
                task_id=task_id,
                sequence=sequence,
                kind=kind,
                event_type=event_type,
                payload=payload,
                previous_hash=previous_hash,
                record_hash=record_hash,
                created_at=now,
            )
            self._connection.execute(
                """
                INSERT INTO workbench_evidence(
                    id, task_id, sequence, kind, event_type, record_json, record_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence.id,
                    task_id,
                    sequence,
                    kind.value,
                    event_type,
                    evidence.model_dump_json(),
                    record_hash,
                    now.isoformat(),
                ),
            )
            return evidence

    def list_evidence(self, task_id: str) -> list[WorkbenchEvidence]:
        rows = self._connection.execute(
            "SELECT record_json, record_hash FROM workbench_evidence "
            "WHERE task_id=? ORDER BY sequence",
            (task_id,),
        ).fetchall()
        previous = None
        records: list[WorkbenchEvidence] = []
        for row in rows:
            record = WorkbenchEvidence.model_validate_json(row["record_json"])
            payload = {
                "task_id": record.task_id,
                "sequence": record.sequence,
                "kind": record.kind.value,
                "event_type": record.event_type,
                "payload": record.payload,
                "previous_hash": record.previous_hash,
                "created_at": record.created_at.isoformat(),
            }
            if (
                record.record_hash != row["record_hash"]
                or record.previous_hash != previous
                or record.record_hash != content_digest(payload)
            ):
                raise WorkbenchConflict("workbench evidence integrity chain is invalid")
            previous = record.record_hash
            records.append(record)
        return records

    def save_submission(self, submission: CandidateSubmission) -> CandidateSubmission:
        current = self.get_submission_for_task(submission.task_id, required=False)
        if current is not None and current.locked:
            raise WorkbenchConflict("locked submission is immutable")
        with self._lock, self._connection:
            if current is not None:
                self._connection.execute(
                    "DELETE FROM workbench_submissions WHERE id=?", (current.id,)
                )
            self._connection.execute(
                """
                INSERT INTO workbench_submissions(
                    id, task_id, locked, submission_digest, record_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    submission.id,
                    submission.task_id,
                    int(submission.locked),
                    submission.submission_digest,
                    submission.model_dump_json(),
                    submission.created_at.isoformat(),
                ),
            )
        return submission

    def get_submission_for_task(
        self, task_id: str, *, required: bool = True
    ) -> CandidateSubmission | None:
        row = self._connection.execute(
            """
            SELECT record_json FROM workbench_submissions
            WHERE task_id=? ORDER BY created_at DESC LIMIT 1
            """,
            (task_id,),
        ).fetchone()
        if row is None:
            if required:
                raise WorkbenchNotFound("candidate submission was not found")
            return None
        return CandidateSubmission.model_validate_json(row["record_json"])

    def lock_submission(self, task_id: str) -> CandidateSubmission:
        with self._lock, self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            submission = self.get_submission_for_task(task_id)
            if submission is None:
                raise WorkbenchNotFound("candidate submission was not found")
            if submission.locked:
                raise WorkbenchConflict("submission is already locked")
            locked = submission.model_copy(update={"locked": True, "locked_at": utc_now()})
            locked = CandidateSubmission.model_validate(locked.model_dump(mode="python"))
            self._connection.execute(
                "UPDATE workbench_submissions SET locked=1, record_json=? WHERE id=?",
                (locked.model_dump_json(), locked.id),
            )
            return locked

    def reopen_submission(self, task_id: str) -> CandidateSubmission:
        with self._lock, self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            submission = self.get_submission_for_task(task_id)
            if submission is None:
                raise WorkbenchNotFound("candidate submission was not found")
            if not submission.locked:
                raise WorkbenchConflict("submission is not locked")
            reopened = submission.model_copy(update={"locked": False, "locked_at": None})
            reopened = CandidateSubmission.model_validate(reopened.model_dump(mode="python"))
            self._connection.execute(
                "UPDATE workbench_submissions SET locked=0, record_json=? WHERE id=?",
                (reopened.model_dump_json(), reopened.id),
            )
            return reopened

    def emergency_stop(self, enabled: bool = True) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                UPDATE workbench_control SET value=?, updated_at=? WHERE name='emergency_stop'
                """,
                ("true" if enabled else "false", utc_now().isoformat()),
            )

    def is_emergency_stopped(self) -> bool:
        row = self._connection.execute(
            "SELECT value FROM workbench_control WHERE name='emergency_stop'"
        ).fetchone()
        return row is not None and row["value"] == "true"

    def _get_task_locked(self, task_id: str) -> WorkbenchTask:
        row = self._connection.execute(
            "SELECT record_json FROM workbench_tasks WHERE id=?", (task_id,)
        ).fetchone()
        if row is None:
            raise WorkbenchNotFound("workbench task was not found")
        return WorkbenchTask.model_validate_json(row["record_json"])

    def _save_task_locked(self, task: WorkbenchTask) -> None:
        self._connection.execute(
            """
            UPDATE workbench_tasks SET state=?, record_json=?, updated_at=? WHERE id=?
            """,
            (task.state.value, task.model_dump_json(), task.updated_at.isoformat(), task.id),
        )

    def _get_approval_locked(self, approval_id: str) -> WorkbenchApproval:
        row = self._connection.execute(
            "SELECT record_json FROM workbench_approvals WHERE id=?", (approval_id,)
        ).fetchone()
        if row is None:
            raise WorkbenchNotFound("workbench approval was not found")
        return WorkbenchApproval.model_validate_json(row["record_json"])

    def _save_approval_locked(self, approval: WorkbenchApproval) -> None:
        self._connection.execute(
            "UPDATE workbench_approvals SET status=?, record_json=? WHERE id=?",
            (approval.status, approval.model_dump_json(), approval.id),
        )

    def _set_approval_status(self, approval: WorkbenchApproval, status: str) -> WorkbenchApproval:
        changed = approval.model_copy(update={"status": status})
        changed = WorkbenchApproval.model_validate(changed.model_dump(mode="python"))
        with self._lock, self._connection:
            self._save_approval_locked(changed)
        return changed
