from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from pathlib import Path
from threading import RLock

from .canonical_lifecycle import (
    ApprovalPurpose as CanonicalApprovalPurpose,
)
from .canonical_lifecycle import (
    CapabilityName,
    TaskState,
)
from .canonical_lifecycle import (
    content_digest as canonical_content_digest,
)
from .canonical_store import (
    CanonicalStateStore,
    CanonicalStoreError,
)
from .workbench_contract import (
    ApprovalPurpose,
    CandidateSubmission,
    EvidenceKind,
    ToolRunRecord,
    WorkbenchApproval,
    WorkbenchEvidence,
    WorkbenchPlan,
    WorkbenchState,
    WorkbenchTask,
    canonical_json,
    content_digest,
    utc_now,
)

CANONICAL_BRIDGE_MIGRATION_PATH = (
    Path(__file__).resolve().parent.parent / "migrations" / "0010_workbench_canonical_authority.sql"
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS workbench_tasks (
    id TEXT PRIMARY KEY,
    task_digest TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    record_json TEXT NOT NULL,
    record_signature TEXT NOT NULL,
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
    record_signature TEXT NOT NULL,
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
    record_signature TEXT NOT NULL,
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

CREATE TABLE IF NOT EXISTS workbench_evidence_anchors (
    task_id TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL,
    head_hash TEXT NOT NULL,
    anchor_signature TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(task_id) REFERENCES workbench_tasks(id)
);

CREATE TABLE IF NOT EXISTS workbench_submissions (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    locked INTEGER NOT NULL DEFAULT 0,
    submission_digest TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    record_signature TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(task_id) REFERENCES workbench_tasks(id)
);

CREATE TABLE IF NOT EXISTS workbench_control (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    audit_sequence INTEGER NOT NULL DEFAULT 0,
    audit_hash TEXT,
    record_signature TEXT
);
INSERT OR IGNORE INTO workbench_control(name, value, updated_at)
VALUES ('emergency_stop', 'false', CURRENT_TIMESTAMP);

CREATE TABLE IF NOT EXISTS workbench_control_events (
    sequence INTEGER PRIMARY KEY,
    action TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    record_json TEXT NOT NULL,
    record_hash TEXT NOT NULL UNIQUE,
    record_signature TEXT NOT NULL,
    created_at TEXT NOT NULL
);
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
            WorkbenchState.AWAITING_APPROVAL,
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
    def __init__(
        self,
        database_path: Path | str,
        *,
        signing_key: bytes | None = None,
        runtime_id: str | None = None,
    ) -> None:
        self._signing_key = secrets.token_bytes(32) if signing_key is None else signing_key
        if not isinstance(self._signing_key, bytes) or len(self._signing_key) != 32:
            raise ValueError("Workbench evidence signing key must contain exactly 32 bytes")
        self.durable_evidence_integrity = signing_key is not None
        self._path = str(database_path)
        self._connection = sqlite3.connect(self._path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = RLock()
        with self._lock, self._connection:
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA busy_timeout=30000")
            self._connection.executescript(SCHEMA)
            self._ensure_record_signature_columns()
            self._ensure_control_integrity()
        self._canonical = CanonicalStateStore(
            database_path,
            runtime_id=runtime_id,
            connection=self._connection,
            lock=self._lock,
        )
        if not CANONICAL_BRIDGE_MIGRATION_PATH.is_file():
            raise WorkbenchStoreError("canonical Workbench bridge migration is missing")
        with self._lock:
            self._connection.executescript(
                CANONICAL_BRIDGE_MIGRATION_PATH.read_text(encoding="utf-8")
            )
        self._active_dispatch: dict[str, tuple[str, str]] = {}
        with self._lock:
            control_row = self._connection.execute(
                "SELECT value FROM workbench_control WHERE name='emergency_stop'"
            ).fetchone()
            workbench_stopped = control_row is not None and control_row["value"] == "true"
            canonical_stopped = self._canonical.control().emergency_stopped
        if workbench_stopped != canonical_stopped:
            # Divergence can only be reconciled toward the safer stopped state.
            self.emergency_stop(True, actor_id=self._canonical.runtime_id)

    @property
    def canonical(self) -> CanonicalStateStore:
        """The authoritative lifecycle store sharing this exact SQLite transaction boundary."""

        return self._canonical

    def close(self) -> None:
        self._canonical.close()
        self._connection.close()

    def create_task(self, task: WorkbenchTask) -> WorkbenchTask:
        if task.state != WorkbenchState.RECEIVED:
            raise WorkbenchConflict("new workbench tasks must start in RECEIVED")
        record = task.model_dump_json()
        signature = self._sign_record("task", task.id, record)
        try:
            with self._lock, self._connection:
                self._connection.execute("BEGIN IMMEDIATE")
                required_capabilities = [
                    CapabilityName.MODEL,
                    CapabilityName.RUNNER,
                    CapabilityName.EXTERNAL_CHECKPOINT,
                ]
                if task.imported.requires_changes:
                    required_capabilities.extend(
                        (CapabilityName.OWNER_TREE_APPLY, CapabilityName.LOCAL_COMMIT)
                    )
                self._canonical.create_task(
                    task_id=task.id,
                    task_digest=task.task_digest,
                    source_snapshot_digest=task.imported.source_snapshot_digest,
                    requires_change=task.imported.requires_changes,
                    required_capabilities=tuple(required_capabilities),
                )
                self._connection.execute(
                    """
                    INSERT INTO workbench_tasks(
                        id, task_digest, state, record_json, record_signature,
                        created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        task.id,
                        task.task_digest,
                        task.state.value,
                        record,
                        signature,
                        task.created_at.isoformat(),
                        task.updated_at.isoformat(),
                    ),
                )
                self._connection.execute(
                    """
                    INSERT INTO canonical_workbench_task_bindings(
                        workbench_task_id, canonical_task_id, created_at
                    ) VALUES (?, ?, ?)
                    """,
                    (task.id, task.id, task.created_at.isoformat()),
                )
        except (sqlite3.IntegrityError, CanonicalStoreError) as exc:
            raise WorkbenchConflict("duplicate task or another active Workbench task") from exc
        return task

    def get_task(self, task_id: str) -> WorkbenchTask:
        row = self._connection.execute(
            "SELECT * FROM workbench_tasks WHERE id=?", (task_id,)
        ).fetchone()
        if row is None:
            raise WorkbenchNotFound("workbench task was not found")
        return self._task_from_row(row)

    def list_tasks(self, *, limit: int = 100) -> list[WorkbenchTask]:
        if limit < 1 or limit > 200:
            raise ValueError("task list limit is invalid")
        rows = self._connection.execute(
            "SELECT * FROM workbench_tasks ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._task_from_row(row) for row in rows]

    def transition(
        self,
        task_id: str,
        target: WorkbenchState,
        *,
        plan: WorkbenchPlan | None = None,
        blocked_reason: str | None = None,
        increment_attempt: bool = False,
    ) -> WorkbenchTask:
        dispatch_completed = False
        try:
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
                self._advance_canonical_projection_locked(
                    task,
                    target=target,
                    plan=plan,
                    blocked_reason=blocked_reason,
                )
                self._save_task_locked(changed)
                dispatch_completed = target == WorkbenchState.TESTING
        except sqlite3.IntegrityError as exc:
            raise WorkbenchConflict("another Workbench task is active") from exc
        except CanonicalStoreError as exc:
            raise WorkbenchConflict(
                "authoritative canonical lifecycle rejected the Workbench transition"
            ) from exc
        if dispatch_completed:
            self._active_dispatch.pop(task_id, None)
        return changed

    def _advance_canonical_projection_locked(
        self,
        task: WorkbenchTask,
        *,
        target: WorkbenchState,
        plan: WorkbenchPlan | None,
        blocked_reason: str | None,
    ) -> None:
        canonical = self._canonical.get_task(task.id)
        projection_payload = {
            "workbench_from_state": task.state.value,
            "workbench_to_state": target.value,
        }
        if target == WorkbenchState.INSPECTING:
            self._canonical.record_event_atomic(
                task.id,
                expected_version=canonical.version,
                event_type="workbench.inspection.started",
                payload=projection_payload,
            )
            return
        if target == WorkbenchState.ANALYZED:
            if canonical.state == TaskState.RECEIVED:
                self._canonical.transition_with_evidence(
                    task.id,
                    expected_version=canonical.version,
                    target=TaskState.INSPECTED,
                    event_type="workbench.inspection.completed",
                    payload=projection_payload,
                )
                return
            if canonical.state == TaskState.FAILED:
                self._canonical.record_event_atomic(
                    task.id,
                    expected_version=canonical.version,
                    event_type="workbench.rollback.prepared",
                    payload=projection_payload,
                )
                return
            raise WorkbenchConflict("canonical task is not ready for analyzed projection")
        if target == WorkbenchState.PLAN_READY:
            if plan is None:
                raise WorkbenchConflict("plan-ready transition requires an exact plan")
            if canonical.state == TaskState.INSPECTED:
                canonical = self._canonical.transition_with_evidence(
                    task.id,
                    expected_version=canonical.version,
                    target=TaskState.PLANNING,
                    event_type="workbench.planning.started",
                    payload=projection_payload,
                )
                self._canonical.propose_plan_atomic(
                    task.id,
                    expected_version=canonical.version,
                    plan_digest=plan.plan_digest,
                )
                return
            if canonical.state == TaskState.FAILED and task.plan_digest == plan.plan_digest:
                self._canonical.record_event_atomic(
                    task.id,
                    expected_version=canonical.version,
                    event_type="workbench.rollback.plan.reused",
                    payload={**projection_payload, "plan_digest": plan.plan_digest},
                )
                return
            raise WorkbenchConflict("canonical task cannot accept this plan projection")
        if target == WorkbenchState.AWAITING_APPROVAL:
            if canonical.state not in {
                TaskState.PLAN_PROPOSED,
                TaskState.FAILED,
                TaskState.APPROVED,
            }:
                raise WorkbenchConflict("canonical task is not ready to await approval")
            self._canonical.record_event_atomic(
                task.id,
                expected_version=canonical.version,
                event_type="workbench.approval.awaited",
                payload=projection_payload,
            )
            return
        if target == WorkbenchState.APPROVED:
            if canonical.state not in {TaskState.APPROVED, TaskState.ROLLBACK_PENDING}:
                raise WorkbenchConflict("canonical approval decision is missing")
            self._canonical.record_event_atomic(
                task.id,
                expected_version=canonical.version,
                event_type="workbench.approval.projected",
                payload=projection_payload,
            )
            return
        if target == WorkbenchState.EXECUTING:
            if canonical.state != TaskState.EXECUTING:
                raise WorkbenchConflict("canonical dispatch lease was not claimed")
            self._canonical.record_event_atomic(
                task.id,
                expected_version=canonical.version,
                event_type="workbench.execution.projected",
                payload=projection_payload,
            )
            return
        if target == WorkbenchState.TESTING:
            dispatch = self._active_dispatch.get(task.id)
            if canonical.state != TaskState.EXECUTING or dispatch is None:
                raise WorkbenchConflict("canonical active dispatch authority is missing")
            lease_id, lease_token = dispatch
            rows = self._connection.execute(
                "SELECT record_json FROM workbench_runs WHERE task_id=? ORDER BY created_at, id",
                (task.id,),
            ).fetchall()
            result_digest = canonical_content_digest(
                {
                    "schema_version": "workbench-dispatch-result-v1",
                    "task_id": task.id,
                    "runs": [json.loads(str(row["record_json"])) for row in rows],
                }
            )
            completed = self._canonical.complete_dispatch_atomic(
                task.id,
                lease_id,
                expected_version=canonical.version,
                lease_token=lease_token,
                result_digest=result_digest,
            )
            if completed.state != TaskState.TESTING:
                raise WorkbenchConflict("canonical dispatch did not enter testing")
            return
        if target == WorkbenchState.VERIFIED:
            if canonical.state != TaskState.TESTING:
                raise WorkbenchConflict("canonical task is not ready for verification")
            self._canonical.transition_with_evidence(
                task.id,
                expected_version=canonical.version,
                target=TaskState.VERIFYING,
                event_type="workbench.verification.started",
                payload=projection_payload,
            )
            return
        if target == WorkbenchState.COMPLETED:
            if canonical.state != TaskState.LOCALLY_COMMITTED:
                raise WorkbenchConflict(
                    "canonical completion requires sealed evidence, applied patch, and local commit"
                )
            self._canonical.complete_atomic(task.id, expected_version=canonical.version)
            return
        if target in {WorkbenchState.FAILED, WorkbenchState.CANCELED}:
            canonical_target = (
                TaskState.FAILED if target == WorkbenchState.FAILED else TaskState.CANCELED
            )
            if (
                canonical_target == TaskState.CANCELED
                and canonical.state == TaskState.EMERGENCY_STOPPED
            ):
                return
            self._canonical.terminate_task_atomic(
                task.id,
                expected_version=canonical.version,
                target=canonical_target,
                event_type=f"workbench.task.{target.value.casefold()}",
                payload=projection_payload,
                failure_reason=blocked_reason if canonical_target == TaskState.FAILED else None,
            )
            return
        if target == WorkbenchState.BLOCKED:
            if canonical.state in {TaskState.RECEIVED, TaskState.INSPECTED}:
                self._canonical.record_event_atomic(
                    task.id,
                    expected_version=canonical.version,
                    event_type="workbench.task.blocked",
                    payload={**projection_payload, "reason": blocked_reason},
                )
                return
            self._canonical.terminate_task_atomic(
                task.id,
                expected_version=canonical.version,
                target=TaskState.FAILED,
                event_type="workbench.task.blocked",
                payload=projection_payload,
                failure_reason=blocked_reason or "Workbench task blocked",
            )
            return
        if target == WorkbenchState.ROLLED_BACK:
            if canonical.state != TaskState.ROLLBACK_PENDING:
                raise WorkbenchConflict("canonical rollback approval is not pending")
            canonical_approval_id = self._canonical_approval_id_locked(
                self._latest_workbench_approval_id_locked(task.id, ApprovalPurpose.ROLLBACK)
            )
            approval = self._canonical.get_approval(canonical_approval_id)
            result_digest = canonical_content_digest(
                {
                    "schema_version": "workbench-rollback-result-v1",
                    "task_id": task.id,
                    "source_snapshot_digest": task.imported.source_snapshot_digest,
                }
            )
            self._canonical.consume_delivery_approval_atomic(
                task.id,
                canonical_approval_id,
                expected_version=canonical.version,
                purpose=CanonicalApprovalPurpose.ROLLBACK,
                operation_digest=approval.operation_digest,
                policy_digest=approval.policy_digest,
                result_digest=result_digest,
            )
            return
        raise WorkbenchConflict("Workbench projection has no canonical lifecycle transition")

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
        if approval.status != "pending" or approval.approved_by is not None:
            raise WorkbenchConflict("only pending owner approvals may be published")
        try:
            with self._lock, self._connection:
                self._connection.execute("BEGIN IMMEDIATE")
                task = self._get_task_locked(approval.task_id)
                if task.state != WorkbenchState.AWAITING_APPROVAL:
                    raise WorkbenchConflict("approval task is not awaiting approval")
                canonical_purpose = self._canonical_approval_purpose(approval.purpose)
                operation_digest = self._canonical_operation_digest(approval)
                remaining_seconds = int((approval.expires_at - utc_now()).total_seconds())
                if remaining_seconds < 1:
                    raise WorkbenchConflict("approval expired before canonical publication")
                canonical_task = self._canonical.get_task(task.id)
                replacement_states = {
                    TaskState.APPROVAL_PENDING,
                    TaskState.ROLLBACK_PENDING,
                    TaskState.APPROVED,
                }
                if canonical_task.state in replacement_states:
                    previous_workbench_id = self._latest_workbench_approval_id_locked(
                        task.id,
                        approval.purpose,
                    )
                    previous_canonical_id = self._canonical_approval_id_locked(
                        previous_workbench_id
                    )
                    canonical_approval = self._canonical.build_replacement_approval(
                        task.id,
                        previous_canonical_id,
                        operation_digest=operation_digest,
                        policy_digest=approval.policy_digest,
                        ttl_seconds=min(remaining_seconds, 900),
                    )
                    self._canonical.replace_expired_approval_atomic(
                        task.id,
                        previous_canonical_id,
                        expected_version=canonical_task.version,
                        approval=canonical_approval,
                    )
                else:
                    canonical_approval = self._canonical.build_approval(
                        task.id,
                        purpose=canonical_purpose,
                        operation_digest=operation_digest,
                        policy_digest=approval.policy_digest,
                        ttl_seconds=min(remaining_seconds, 900),
                    )
                    self._canonical.publish_approval_atomic(
                        task.id,
                        expected_version=canonical_task.version,
                        approval=canonical_approval,
                    )
                self._connection.execute(
                    """
                    INSERT INTO workbench_approvals(
                        id, task_id, status, approval_digest, record_json,
                        record_signature, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        approval.id,
                        approval.task_id,
                        approval.status,
                        approval.approval_digest,
                        approval.model_dump_json(),
                        self._sign_record("approval", approval.id, approval.model_dump_json()),
                        approval.created_at.isoformat(),
                    ),
                )
                self._connection.execute(
                    """
                    INSERT INTO canonical_workbench_approval_bindings(
                        workbench_approval_id, canonical_approval_id, created_at
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        approval.id,
                        canonical_approval.id,
                        approval.created_at.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise WorkbenchConflict("approval already exists") from exc
        except CanonicalStoreError as exc:
            raise WorkbenchConflict(
                "authoritative canonical lifecycle rejected approval publication"
            ) from exc

    def get_approval(self, approval_id: str) -> WorkbenchApproval:
        row = self._connection.execute(
            "SELECT * FROM workbench_approvals WHERE id=?", (approval_id,)
        ).fetchone()
        if row is None:
            raise WorkbenchNotFound("workbench approval was not found")
        approval = self._approval_from_row(row)
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
        if decision == "request_revision":
            raise WorkbenchConflict(
                "canonical lifecycle requires a new task for a revised exact plan"
            )
        try:
            with self._lock, self._connection:
                self._connection.execute("BEGIN IMMEDIATE")
                approval = self._get_approval_locked(approval_id)
                if approval.task_id != task_id:
                    raise WorkbenchConflict("approval task binding does not match")
                if approval.status != "pending":
                    raise WorkbenchConflict("approval is not pending")
                workbench_task = self._get_task_locked(task_id)
                if workbench_task.state != WorkbenchState.AWAITING_APPROVAL:
                    raise WorkbenchConflict("approval task is not awaiting a decision")
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
                canonical_task = self._canonical.get_task(task_id)
                canonical_approval_id = self._canonical_approval_id_locked(approval.id)
                if decision == "approve":
                    decision_proof_digest = canonical_content_digest(
                        {
                            "schema_version": "workbench-owner-decision-v1",
                            "workbench_approval_id": approval.id,
                            "workbench_approval_digest": approval.approval_digest,
                            "decision": decision,
                            "actor_id": actor_id,
                            "decided_at": changed.decided_at,
                        }
                    )
                    self._canonical.approve_atomic(
                        task_id,
                        canonical_approval_id,
                        expected_version=canonical_task.version,
                        owner_id=actor_id,
                        decision_proof_digest=decision_proof_digest,
                    )
                else:
                    self._canonical.reject_approval_atomic(
                        task_id,
                        canonical_approval_id,
                        expected_version=canonical_task.version,
                        actor_id=actor_id,
                        reason_code="owner_rejected",
                    )
                self._save_approval_locked(changed)
                projected_state = (
                    WorkbenchState.APPROVED if decision == "approve" else WorkbenchState.CANCELED
                )
                projected = WorkbenchTask.model_validate(
                    workbench_task.model_copy(
                        update={
                            "state": projected_state,
                            "updated_at": utc_now(),
                            "blocked_reason": None,
                        }
                    ).model_dump(mode="python")
                )
                self._save_task_locked(projected)
                return changed
        except CanonicalStoreError as exc:
            raise WorkbenchConflict(
                "authoritative canonical lifecycle rejected the approval decision"
            ) from exc

    def consume_approval(
        self,
        approval_id: str,
        *,
        task: WorkbenchTask,
        expected_attempt: int,
        tool_digests: tuple[str, ...],
        expected_purpose: ApprovalPurpose,
        expected_owner_id: str,
        policy_digest: str,
        runner_grant_digest: str | None,
    ) -> WorkbenchApproval:
        dispatch: tuple[str, str] | None = None
        try:
            with self._lock, self._connection:
                self._connection.execute("BEGIN IMMEDIATE")
                current = self._get_task_locked(task.id)
                approval = self._get_approval_locked(approval_id)
                if approval.status != "approved":
                    raise WorkbenchConflict("approval is not approved")
                if approval.approved_by != expected_owner_id:
                    raise WorkbenchConflict("approval was not granted by the configured owner")
                if utc_now() >= approval.expires_at:
                    self._save_approval_locked(approval.model_copy(update={"status": "expired"}))
                    raise WorkbenchConflict("approval expired")
                if (
                    current != task
                    or current.state != WorkbenchState.APPROVED
                    or approval.task_id != current.id
                    or approval.task_digest != current.task_digest
                    or approval.purpose != expected_purpose
                    or approval.plan_digest != current.plan_digest
                    or approval.source_snapshot_digest != current.imported.source_snapshot_digest
                    or approval.repository_id != current.imported.repository_id
                    or approval.examination_digest
                    != (
                        current.imported.examination.config_digest
                        if current.imported.examination is not None
                        else None
                    )
                    or approval.project
                    != (
                        current.imported.examination.authorized_project
                        if current.imported.examination is not None
                        else None
                    )
                    or approval.candidate_identity
                    != (
                        current.imported.examination.candidate_service_account
                        if current.imported.examination is not None
                        else None
                    )
                    or approval.execution_attempt != expected_attempt
                    or approval.approved_tool_digests != tool_digests
                    or approval.policy_digest != policy_digest
                    or approval.runner_grant_digest != runner_grant_digest
                ):
                    raise WorkbenchConflict("approval binding changed")
                matching_decision = any(
                    record.event_type == "approval_decided"
                    and record.payload.get("approval_id") == approval.id
                    and record.payload.get("approval_digest") == approval.approval_digest
                    and record.payload.get("decision") == "approve"
                    and record.payload.get("actor_id") == expected_owner_id
                    and record.payload.get("decided_at")
                    == (approval.decided_at.isoformat() if approval.decided_at else None)
                    for record in self._verify_evidence_locked(task.id)
                )
                if not matching_decision:
                    raise WorkbenchConflict("authenticated owner approval decision is missing")
                canonical_task = self._canonical.get_task(task.id)
                canonical_approval_id = self._canonical_approval_id_locked(approval.id)
                canonical_approval = self._canonical.get_approval(canonical_approval_id)
                if expected_purpose == ApprovalPurpose.EXECUTE:
                    if canonical_task.state != TaskState.APPROVED:
                        raise WorkbenchConflict("canonical task is not approved for dispatch")
                    canonical_task = self._canonical.transition_with_evidence(
                        task.id,
                        expected_version=canonical_task.version,
                        target=TaskState.RUNNER_PREFLIGHT,
                        event_type="workbench.runner.preflight",
                        payload={
                            "runner_grant_digest": runner_grant_digest,
                            "workbench_approval_id": approval.id,
                        },
                    )
                    _, lease, lease_token = self._canonical.claim_dispatch_atomic(
                        task.id,
                        canonical_approval_id,
                        expected_version=canonical_task.version,
                        request_digest=canonical_approval.operation_digest,
                        policy_digest=policy_digest,
                    )
                    dispatch = (lease.id, lease_token)
                elif canonical_task.state != TaskState.ROLLBACK_PENDING:
                    raise WorkbenchConflict("canonical rollback approval is not pending")
                changed = approval.model_copy(
                    update={"status": "consumed", "consumed_at": utc_now()}
                )
                changed = WorkbenchApproval.model_validate(changed.model_dump(mode="python"))
                self._save_approval_locked(changed)
                if expected_purpose == ApprovalPurpose.EXECUTE:
                    projected = WorkbenchTask.model_validate(
                        current.model_copy(
                            update={
                                "state": WorkbenchState.EXECUTING,
                                "active_attempt": expected_attempt,
                                "updated_at": utc_now(),
                                "blocked_reason": None,
                            }
                        ).model_dump(mode="python")
                    )
                    self._save_task_locked(projected)
        except CanonicalStoreError as exc:
            raise WorkbenchConflict(
                "authoritative canonical lifecycle rejected approval consumption"
            ) from exc
        if dispatch is not None:
            self._active_dispatch[task.id] = dispatch
        return changed

    def save_run(self, run: ToolRunRecord) -> None:
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """
                    INSERT INTO workbench_runs(
                        id, task_id, attempt, tool_id, request_digest, record_json,
                        record_signature, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run.id,
                        run.task_id,
                        run.attempt,
                        run.tool_id,
                        run.request_digest,
                        run.model_dump_json(),
                        self._sign_record("run", run.id, run.model_dump_json()),
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
            "SELECT * FROM workbench_runs WHERE task_id=? ORDER BY created_at, tool_id",
            (task_id,),
        ).fetchall()
        return [self._run_from_row(row) for row in rows]

    def append_evidence(
        self,
        task_id: str,
        *,
        kind: EvidenceKind,
        event_type: str,
        payload: dict[str, object],
    ) -> WorkbenchEvidence:
        with self._lock, self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            return self._append_evidence_locked(
                task_id,
                kind=kind,
                event_type=event_type,
                payload=payload,
            )

    def _append_evidence_locked(
        self,
        task_id: str,
        *,
        kind: EvidenceKind,
        event_type: str,
        payload: dict[str, object],
    ) -> WorkbenchEvidence:
        now = utc_now()
        existing = self._verify_evidence_locked(task_id)
        sequence = len(existing) + 1
        previous_hash = existing[-1].record_hash if existing else None
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
        anchor_payload = {
            "schema": "liltweak-workbench-evidence-anchor-v1",
            "task_id": task_id,
            "sequence": sequence,
            "head_hash": record_hash,
        }
        anchor_signature = self._sign_anchor(anchor_payload)
        self._connection.execute(
            """
            INSERT INTO workbench_evidence_anchors(
                task_id, sequence, head_hash, anchor_signature, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(task_id) DO UPDATE SET
                sequence=excluded.sequence,
                head_hash=excluded.head_hash,
                anchor_signature=excluded.anchor_signature,
                updated_at=excluded.updated_at
            """,
            (task_id, sequence, record_hash, anchor_signature, now.isoformat()),
        )
        return evidence

    def list_evidence(self, task_id: str) -> list[WorkbenchEvidence]:
        with self._lock:
            return self._verify_evidence_locked(task_id)

    def _verify_evidence_locked(self, task_id: str) -> list[WorkbenchEvidence]:
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
                or record.id != f"evidence:{record.record_hash[:24]}"
                or record.previous_hash != previous
                or record.record_hash != content_digest(payload)
            ):
                raise WorkbenchConflict("workbench evidence integrity chain is invalid")
            previous = record.record_hash
            records.append(record)
        anchor = self._connection.execute(
            """
                SELECT sequence, head_hash, anchor_signature
                FROM workbench_evidence_anchors WHERE task_id=?
                """,
            (task_id,),
        ).fetchone()
        if records:
            if anchor is None:
                raise WorkbenchConflict("workbench evidence authenticated anchor is missing")
            anchor_payload = {
                "schema": "liltweak-workbench-evidence-anchor-v1",
                "task_id": task_id,
                "sequence": int(anchor["sequence"]),
                "head_hash": str(anchor["head_hash"]),
            }
            expected = self._sign_anchor(anchor_payload)
            if (
                int(anchor["sequence"]) != len(records)
                or str(anchor["head_hash"]) != previous
                or not hmac.compare_digest(str(anchor["anchor_signature"]), expected)
            ):
                raise WorkbenchConflict("workbench evidence authenticated anchor is invalid")
        elif anchor is not None:
            raise WorkbenchConflict("workbench evidence anchor exists without a ledger")
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
                    id, task_id, locked, submission_digest, record_json,
                    record_signature, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    submission.id,
                    submission.task_id,
                    int(submission.locked),
                    submission.submission_digest,
                    submission.model_dump_json(),
                    self._sign_record("submission", submission.id, submission.model_dump_json()),
                    submission.created_at.isoformat(),
                ),
            )
        return submission

    def get_submission_for_task(
        self, task_id: str, *, required: bool = True
    ) -> CandidateSubmission | None:
        row = self._connection.execute(
            """
            SELECT * FROM workbench_submissions
            WHERE task_id=? ORDER BY created_at DESC LIMIT 1
            """,
            (task_id,),
        ).fetchone()
        if row is None:
            if required:
                raise WorkbenchNotFound("candidate submission was not found")
            return None
        return self._submission_from_row(row)

    def lock_submission(self, task_id: str, *, actor_id: str) -> CandidateSubmission:
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
                """
                UPDATE workbench_submissions
                SET locked=1, record_json=?, record_signature=? WHERE id=?
                """,
                (
                    locked.model_dump_json(),
                    self._sign_record("submission", locked.id, locked.model_dump_json()),
                    locked.id,
                ),
            )
            self._append_evidence_locked(
                task_id,
                kind=EvidenceKind.SUBMISSION,
                event_type="submission_locked",
                payload={
                    "submission_id": locked.id,
                    "submission_digest": locked.submission_digest,
                    "actor_id": actor_id,
                },
            )
            return locked

    def reopen_submission(self, task_id: str, *, actor_id: str) -> CandidateSubmission:
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
                """
                UPDATE workbench_submissions
                SET locked=0, record_json=?, record_signature=? WHERE id=?
                """,
                (
                    reopened.model_dump_json(),
                    self._sign_record("submission", reopened.id, reopened.model_dump_json()),
                    reopened.id,
                ),
            )
            self._append_evidence_locked(
                task_id,
                kind=EvidenceKind.SUBMISSION,
                event_type="submission_reopened",
                payload={
                    "submission_id": reopened.id,
                    "submission_digest": reopened.submission_digest,
                    "actor_id": actor_id,
                },
            )
            return reopened

    def emergency_stop(self, enabled: bool = True, *, actor_id: str = "system") -> None:
        if (
            not actor_id
            or len(actor_id) > 128
            or any(ord(character) < 32 or ord(character) == 127 for character in actor_id)
        ):
            raise WorkbenchConflict("control actor identifier is invalid")
        with self._lock, self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            row = self._verified_control_locked()
            events = self._verify_control_events_locked(row)
            sequence = len(events) + 1
            previous_hash = events[-1]["record_hash"] if events else None
            now = utc_now().isoformat()
            payload = {
                "schema": "liltweak-workbench-control-event-v1",
                "sequence": sequence,
                "action": "engage" if enabled else "reset",
                "actor_id": actor_id,
                "enabled": enabled,
                "previous_hash": previous_hash,
                "created_at": now,
            }
            record = canonical_json(payload)
            record_hash = content_digest(payload)
            if enabled:
                self._canonical.engage_emergency_stop(
                    actor_id=actor_id,
                    reason_code="workbench_owner_stop",
                )
            else:
                self._canonical.clear_emergency_stop(
                    actor_id=actor_id,
                    reason_code="workbench_owner_reset",
                )
            self._connection.execute(
                """
                INSERT INTO workbench_control_events(
                    sequence, action, actor_id, record_json, record_hash,
                    record_signature, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sequence,
                    payload["action"],
                    actor_id,
                    record,
                    record_hash,
                    self._sign_record("control_event", str(sequence), record),
                    now,
                ),
            )
            value = "true" if enabled else "false"
            control_record = canonical_json(
                {
                    "name": "emergency_stop",
                    "value": value,
                    "updated_at": now,
                    "audit_sequence": sequence,
                    "audit_hash": record_hash,
                }
            )
            self._connection.execute(
                """
                UPDATE workbench_control
                SET value=?, updated_at=?, audit_sequence=?, audit_hash=?, record_signature=?
                WHERE name='emergency_stop'
                """,
                (
                    value,
                    now,
                    sequence,
                    record_hash,
                    self._sign_record("control", "emergency_stop", control_record),
                ),
            )

    def is_emergency_stopped(self) -> bool:
        with self._lock:
            row = self._verified_control_locked()
            self._verify_control_events_locked(row)
            workbench_stopped = row["value"] == "true"
            try:
                canonical_stopped = self._canonical.control().emergency_stopped
            except CanonicalStoreError as exc:
                raise WorkbenchConflict("authoritative emergency control is unavailable") from exc
            if canonical_stopped != workbench_stopped:
                raise WorkbenchConflict("Workbench and canonical emergency controls diverged")
            return canonical_stopped

    def _get_task_locked(self, task_id: str) -> WorkbenchTask:
        row = self._connection.execute(
            "SELECT * FROM workbench_tasks WHERE id=?", (task_id,)
        ).fetchone()
        if row is None:
            raise WorkbenchNotFound("workbench task was not found")
        return self._task_from_row(row)

    def _save_task_locked(self, task: WorkbenchTask) -> None:
        record = task.model_dump_json()
        self._connection.execute(
            """
            UPDATE workbench_tasks
            SET state=?, record_json=?, record_signature=?, updated_at=? WHERE id=?
            """,
            (
                task.state.value,
                record,
                self._sign_record("task", task.id, record),
                task.updated_at.isoformat(),
                task.id,
            ),
        )

    def _get_approval_locked(self, approval_id: str) -> WorkbenchApproval:
        row = self._connection.execute(
            "SELECT * FROM workbench_approvals WHERE id=?", (approval_id,)
        ).fetchone()
        if row is None:
            raise WorkbenchNotFound("workbench approval was not found")
        return self._approval_from_row(row)

    def _canonical_approval_id_locked(self, workbench_approval_id: str) -> str:
        row = self._connection.execute(
            """
            SELECT canonical_approval_id FROM canonical_workbench_approval_bindings
            WHERE workbench_approval_id=?
            """,
            (workbench_approval_id,),
        ).fetchone()
        if row is None:
            raise WorkbenchConflict("authoritative canonical approval binding is missing")
        return str(row["canonical_approval_id"])

    def _latest_workbench_approval_id_locked(
        self,
        task_id: str,
        purpose: ApprovalPurpose,
    ) -> str:
        rows = self._connection.execute(
            """
            SELECT * FROM workbench_approvals
            WHERE task_id=? ORDER BY created_at DESC, id DESC
            """,
            (task_id,),
        ).fetchall()
        for row in rows:
            approval = self._approval_from_row(row)
            if approval.purpose == purpose:
                return approval.id
        raise WorkbenchConflict("Workbench approval for canonical operation is missing")

    @staticmethod
    def _canonical_approval_purpose(purpose: ApprovalPurpose) -> CanonicalApprovalPurpose:
        mapping = {
            ApprovalPurpose.EXECUTE: CanonicalApprovalPurpose.EXECUTION,
            ApprovalPurpose.ROLLBACK: CanonicalApprovalPurpose.ROLLBACK,
            ApprovalPurpose.APPLY_PATCH: CanonicalApprovalPurpose.APPLY_PATCH,
            ApprovalPurpose.LOCAL_COMMIT: CanonicalApprovalPurpose.LOCAL_COMMIT,
        }
        return mapping[purpose]

    @staticmethod
    def _canonical_operation_digest(approval: WorkbenchApproval) -> str:
        if approval.purpose == ApprovalPurpose.ROLLBACK:
            if len(approval.approved_tool_digests) != 1:
                raise WorkbenchConflict("rollback approval requires one recovery snapshot digest")
            return approval.approved_tool_digests[0]
        if approval.purpose == ApprovalPurpose.APPLY_PATCH:
            if len(approval.approved_tool_digests) != 1:
                raise WorkbenchConflict("patch approval requires one patch manifest digest")
            return approval.approved_tool_digests[0]
        return approval.approval_digest

    def _save_approval_locked(self, approval: WorkbenchApproval) -> None:
        record = approval.model_dump_json()
        self._connection.execute(
            """
            UPDATE workbench_approvals
            SET status=?, record_json=?, record_signature=? WHERE id=?
            """,
            (
                approval.status,
                record,
                self._sign_record("approval", approval.id, record),
                approval.id,
            ),
        )

    def _set_approval_status(self, approval: WorkbenchApproval, status: str) -> WorkbenchApproval:
        changed = approval.model_copy(update={"status": status})
        changed = WorkbenchApproval.model_validate(changed.model_dump(mode="python"))
        with self._lock, self._connection:
            self._save_approval_locked(changed)
        return changed

    def _ensure_record_signature_columns(self) -> None:
        for table in (
            "workbench_tasks",
            "workbench_approvals",
            "workbench_runs",
            "workbench_submissions",
        ):
            columns = {
                str(row["name"])
                for row in self._connection.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if "record_signature" not in columns:
                self._connection.execute(f"ALTER TABLE {table} ADD COLUMN record_signature TEXT")

    def _ensure_control_integrity(self) -> None:
        columns = {
            str(row["name"])
            for row in self._connection.execute("PRAGMA table_info(workbench_control)").fetchall()
        }
        additions = {
            "audit_sequence": "INTEGER NOT NULL DEFAULT 0",
            "audit_hash": "TEXT",
            "record_signature": "TEXT",
        }
        for name, declaration in additions.items():
            if name not in columns:
                self._connection.execute(
                    f"ALTER TABLE workbench_control ADD COLUMN {name} {declaration}"
                )
        row = self._connection.execute(
            "SELECT * FROM workbench_control WHERE name='emergency_stop'"
        ).fetchone()
        if row is None:
            raise WorkbenchConflict("emergency control state is missing")
        if row["record_signature"] is None:
            task_count = int(
                self._connection.execute(
                    "SELECT COUNT(*) AS count FROM workbench_tasks"
                ).fetchone()["count"]
            )
            event_count = int(
                self._connection.execute(
                    "SELECT COUNT(*) AS count FROM workbench_control_events"
                ).fetchone()["count"]
            )
            if (
                task_count != 0
                or event_count != 0
                or row["value"] != "false"
                or int(row["audit_sequence"]) != 0
                or row["audit_hash"] is not None
            ):
                raise WorkbenchConflict("unsigned emergency control state cannot be trusted")
            record = self._control_record(row)
            self._connection.execute(
                """
                UPDATE workbench_control SET record_signature=?
                WHERE name='emergency_stop'
                """,
                (self._sign_record("control", "emergency_stop", record),),
            )

    @staticmethod
    def _control_record(row: sqlite3.Row) -> str:
        return canonical_json(
            {
                "name": row["name"],
                "value": row["value"],
                "updated_at": row["updated_at"],
                "audit_sequence": int(row["audit_sequence"]),
                "audit_hash": row["audit_hash"],
            }
        )

    def _verified_control_locked(self) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM workbench_control WHERE name='emergency_stop'"
        ).fetchone()
        if row is None or row["value"] not in {"true", "false"}:
            raise WorkbenchConflict("emergency control state is invalid")
        signature = row["record_signature"]
        expected = self._sign_record("control", "emergency_stop", self._control_record(row))
        if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
            raise WorkbenchConflict("emergency control state signature is invalid")
        return row

    def _verify_control_events_locked(self, control: sqlite3.Row) -> list[dict[str, object]]:
        rows = self._connection.execute(
            "SELECT * FROM workbench_control_events ORDER BY sequence"
        ).fetchall()
        events: list[dict[str, object]] = []
        previous_hash: str | None = None
        for expected_sequence, row in enumerate(rows, start=1):
            record = self._verify_record(
                "control_event",
                str(row["sequence"]),
                row["record_json"],
                row["record_signature"],
            )
            try:
                payload = json.loads(record)
            except json.JSONDecodeError as exc:
                raise WorkbenchConflict("control audit record is malformed") from exc
            if (
                not isinstance(payload, dict)
                or int(row["sequence"]) != expected_sequence
                or payload.get("sequence") != expected_sequence
                or row["action"] != payload.get("action")
                or row["actor_id"] != payload.get("actor_id")
                or row["created_at"] != payload.get("created_at")
                or payload.get("previous_hash") != previous_hash
                or row["record_hash"] != content_digest(payload)
            ):
                raise WorkbenchConflict("control audit chain is invalid")
            previous_hash = str(row["record_hash"])
            events.append({**payload, "record_hash": previous_hash})
        if int(control["audit_sequence"]) != len(events) or control["audit_hash"] != previous_hash:
            raise WorkbenchConflict("emergency control audit anchor is invalid")
        return events

    def _sign_record(self, domain: str, record_id: str, record_json: str) -> str:
        payload = {
            "schema": "liltweak-workbench-authenticated-row-v1",
            "domain": domain,
            "record_id": record_id,
            "record_json": record_json,
        }
        return hmac.new(
            self._signing_key,
            content_digest(payload).encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def _verify_record(
        self,
        domain: str,
        record_id: object,
        record_json: object,
        signature: object,
    ) -> str:
        if not isinstance(record_id, str) or not isinstance(record_json, str):
            raise WorkbenchConflict("authenticated Workbench row is malformed")
        if not isinstance(signature, str) or not hmac.compare_digest(
            signature,
            self._sign_record(domain, record_id, record_json),
        ):
            raise WorkbenchConflict("authenticated Workbench row signature is invalid")
        return record_json

    def _task_from_row(self, row: sqlite3.Row) -> WorkbenchTask:
        record = self._verify_record("task", row["id"], row["record_json"], row["record_signature"])
        task = WorkbenchTask.model_validate_json(record)
        if (
            row["id"] != task.id
            or row["task_digest"] != task.task_digest
            or row["state"] != task.state.value
            or row["created_at"] != task.created_at.isoformat()
            or row["updated_at"] != task.updated_at.isoformat()
        ):
            raise WorkbenchConflict("authenticated Workbench task columns do not match")
        binding = self._connection.execute(
            """
            SELECT canonical_task_id FROM canonical_workbench_task_bindings
            WHERE workbench_task_id=?
            """,
            (task.id,),
        ).fetchone()
        if binding is None or binding["canonical_task_id"] != task.id:
            raise WorkbenchConflict("authoritative canonical task binding is missing")
        try:
            canonical_task = self._canonical.get_task(task.id)
        except CanonicalStoreError as exc:
            raise WorkbenchConflict("authoritative canonical task is unavailable") from exc
        if (
            canonical_task.task_digest != task.task_digest
            or canonical_task.source_snapshot_digest != task.imported.source_snapshot_digest
            or canonical_task.state not in self._canonical_states_for_projection(task.state)
        ):
            raise WorkbenchConflict("Workbench projection contradicts authoritative lifecycle")
        return task

    @staticmethod
    def _canonical_states_for_projection(state: WorkbenchState) -> frozenset[TaskState]:
        mapping = {
            WorkbenchState.RECEIVED: frozenset({TaskState.RECEIVED}),
            WorkbenchState.INSPECTING: frozenset({TaskState.RECEIVED}),
            WorkbenchState.ANALYZED: frozenset({TaskState.INSPECTED, TaskState.FAILED}),
            WorkbenchState.PLAN_READY: frozenset({TaskState.PLAN_PROPOSED, TaskState.FAILED}),
            WorkbenchState.AWAITING_APPROVAL: frozenset(
                {
                    TaskState.PLAN_PROPOSED,
                    TaskState.APPROVAL_PENDING,
                    TaskState.APPROVED,
                    TaskState.FAILED,
                    TaskState.ROLLBACK_PENDING,
                }
            ),
            WorkbenchState.APPROVED: frozenset({TaskState.APPROVED, TaskState.ROLLBACK_PENDING}),
            WorkbenchState.EXECUTING: frozenset({TaskState.EXECUTING}),
            WorkbenchState.TESTING: frozenset({TaskState.TESTING}),
            WorkbenchState.VERIFIED: frozenset(
                {
                    TaskState.VERIFYING,
                    TaskState.EVIDENCE_SEALED,
                    TaskState.PATCH_READY,
                    TaskState.APPLY_APPROVAL_PENDING,
                    TaskState.APPLIED,
                    TaskState.COMMIT_APPROVAL_PENDING,
                    TaskState.LOCALLY_COMMITTED,
                }
            ),
            WorkbenchState.COMPLETED: frozenset({TaskState.COMPLETED}),
            WorkbenchState.BLOCKED: frozenset(
                {TaskState.RECEIVED, TaskState.INSPECTED, TaskState.FAILED}
            ),
            WorkbenchState.FAILED: frozenset({TaskState.FAILED}),
            WorkbenchState.ROLLED_BACK: frozenset({TaskState.ROLLED_BACK}),
            WorkbenchState.CANCELED: frozenset({TaskState.CANCELED, TaskState.EMERGENCY_STOPPED}),
        }
        return mapping[state] | frozenset({TaskState.EMERGENCY_STOPPED})

    def _approval_from_row(self, row: sqlite3.Row) -> WorkbenchApproval:
        record = self._verify_record(
            "approval", row["id"], row["record_json"], row["record_signature"]
        )
        approval = WorkbenchApproval.model_validate_json(record)
        if (
            row["id"] != approval.id
            or row["task_id"] != approval.task_id
            or row["status"] != approval.status
            or row["approval_digest"] != approval.approval_digest
            or row["created_at"] != approval.created_at.isoformat()
        ):
            raise WorkbenchConflict("authenticated Workbench approval columns do not match")
        return approval

    def _run_from_row(self, row: sqlite3.Row) -> ToolRunRecord:
        record = self._verify_record("run", row["id"], row["record_json"], row["record_signature"])
        run = ToolRunRecord.model_validate_json(record)
        if (
            row["id"] != run.id
            or row["task_id"] != run.task_id
            or int(row["attempt"]) != run.attempt
            or row["tool_id"] != run.tool_id
            or row["request_digest"] != run.request_digest
            or row["created_at"] != run.started_at.isoformat()
        ):
            raise WorkbenchConflict("authenticated Workbench run columns do not match")
        return run

    def _submission_from_row(self, row: sqlite3.Row) -> CandidateSubmission:
        record = self._verify_record(
            "submission", row["id"], row["record_json"], row["record_signature"]
        )
        submission = CandidateSubmission.model_validate_json(record)
        if (
            row["id"] != submission.id
            or row["task_id"] != submission.task_id
            or bool(row["locked"]) != submission.locked
            or row["submission_digest"] != submission.submission_digest
            or row["created_at"] != submission.created_at.isoformat()
        ):
            raise WorkbenchConflict("authenticated Workbench submission columns do not match")
        return submission

    def _sign_anchor(self, payload: dict[str, object]) -> str:
        return hmac.new(
            self._signing_key,
            content_digest(payload).encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
