from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import uuid
from datetime import timedelta
from pathlib import Path
from threading import RLock

from .canonical_lifecycle import (
    LEGAL_TRANSITIONS,
    RESTART_UNSAFE_STATES,
    SAFE_ID,
    ApprovalPurpose,
    ApprovalStatus,
    CanonicalApproval,
    CanonicalEvidence,
    CanonicalTask,
    CapabilityGate,
    CapabilityName,
    CapabilityStatus,
    DispatchLease,
    DispatchLeaseStatus,
    EmergencyControl,
    TaskState,
    assert_legal_transition,
    canonical_json,
    content_digest,
    utc_now,
)

MIGRATION_PATH = (
    Path(__file__).resolve().parent.parent / "migrations" / "0009_canonical_control_plane.sql"
)
MAX_EVIDENCE_BYTES = 100_000

_PURPOSE_PENDING_STATE = {
    ApprovalPurpose.EXECUTION: (TaskState.PLAN_PROPOSED, TaskState.APPROVAL_PENDING),
    ApprovalPurpose.APPLY_PATCH: (TaskState.PATCH_READY, TaskState.APPLY_APPROVAL_PENDING),
    ApprovalPurpose.LOCAL_COMMIT: (TaskState.APPLIED, TaskState.COMMIT_APPROVAL_PENDING),
}

_PURPOSE_CAPABILITIES = {
    ApprovalPurpose.EXECUTION: (
        CapabilityName.RUNNER,
        CapabilityName.EXTERNAL_CHECKPOINT,
    ),
    ApprovalPurpose.APPLY_PATCH: (
        CapabilityName.OWNER_TREE_APPLY,
        CapabilityName.EXTERNAL_CHECKPOINT,
    ),
    ApprovalPurpose.LOCAL_COMMIT: (
        CapabilityName.LOCAL_COMMIT,
        CapabilityName.EXTERNAL_CHECKPOINT,
    ),
    ApprovalPurpose.ROLLBACK: (
        CapabilityName.OWNER_TREE_APPLY,
        CapabilityName.EXTERNAL_CHECKPOINT,
    ),
}

_GENERIC_TRANSITION_TARGETS = frozenset(
    {
        TaskState.INSPECTED,
        TaskState.PLANNING,
        TaskState.RUNNER_PREFLIGHT,
        TaskState.VERIFYING,
        TaskState.CANCELED,
        TaskState.FAILED,
    }
)


class CanonicalStoreError(RuntimeError):
    pass


class CanonicalNotFound(CanonicalStoreError):
    pass


class CanonicalConflict(CanonicalStoreError):
    pass


class CanonicalCapabilityBlocked(CanonicalStoreError):
    pass


class CanonicalEmergencyStopped(CanonicalStoreError):
    pass


class CanonicalStateStore:
    """Authoritative lifecycle store with optional same-connection adapter composition.

    Every mutation is fenced to one runtime, uses optimistic versions, and couples its evidence
    append to the same SQLite transaction. A caller may inject its SQLite connection and reentrant
    lock so compatibility projections commit atomically with canonical changes; nested operations
    use savepoints and never open a second write connection. ``runtime_id`` must be a fresh process
    nonce, reused by adapters inside one process.
    """

    def __init__(
        self,
        database_path: Path | str,
        *,
        runtime_id: str | None = None,
        connection: sqlite3.Connection | None = None,
        lock: RLock | None = None,
    ) -> None:
        self.runtime_id = runtime_id or f"runtime:{uuid.uuid4().hex}"
        if re.fullmatch(SAFE_ID, self.runtime_id) is None:
            raise ValueError("canonical runtime id is invalid")
        if not MIGRATION_PATH.is_file():
            raise CanonicalStoreError("canonical control-plane migration is missing")
        self._owns_connection = connection is None
        self._connection = connection or sqlite3.connect(
            str(database_path),
            check_same_thread=False,
            timeout=30,
        )
        self._connection.row_factory = sqlite3.Row
        self._lock = lock or RLock()
        with self._lock:
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA busy_timeout=30000")
            self._connection.executescript(MIGRATION_PATH.read_text(encoding="utf-8"))
            self._initialize_capabilities()
            self._claim_runtime()

    def close(self) -> None:
        if self._owns_connection:
            self._connection.close()

    def control(self) -> EmergencyControl:
        with self._lock:
            row = self._control_locked()
            if row["active_runtime_id"] is None:
                raise CanonicalStoreError("canonical runtime is not initialized")
            return EmergencyControl(
                emergency_stopped=bool(row["emergency_stopped"]),
                generation=int(row["generation"]),
                active_runtime_id=str(row["active_runtime_id"]),
                reason_code=str(row["reason_code"]),
                updated_at=str(row["updated_at"]),
            )

    def create_task(
        self,
        *,
        task_id: str,
        task_digest: str,
        source_snapshot_digest: str,
        requires_change: bool = True,
        required_capabilities: tuple[CapabilityName, ...] = (),
    ) -> CanonicalTask:
        now = utc_now()
        task = CanonicalTask(
            id=task_id,
            task_digest=task_digest,
            source_snapshot_digest=source_snapshot_digest,
            requires_change=requires_change,
            required_capabilities=required_capabilities,
            created_at=now,
            updated_at=now,
        )
        try:
            with self._transaction():
                self._assert_runtime_locked()
                self._assert_not_stopped_locked()
                self._connection.execute(
                    """
                    INSERT INTO canonical_tasks(
                        id, task_digest, source_snapshot_digest, state, version,
                        record_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        task.id,
                        task.task_digest,
                        task.source_snapshot_digest,
                        task.state.value,
                        task.version,
                        task.model_dump_json(),
                        task.created_at.isoformat(),
                        task.updated_at.isoformat(),
                    ),
                )
                self._append_evidence_locked(
                    task.id,
                    event_type="task.received",
                    payload={
                        "task_digest": task.task_digest,
                        "source_snapshot_digest": task.source_snapshot_digest,
                        "version": task.version,
                    },
                )
        except sqlite3.IntegrityError as exc:
            raise CanonicalConflict("canonical task already exists") from exc
        return task

    def get_task(self, task_id: str) -> CanonicalTask:
        with self._lock:
            return self._get_task_locked(task_id)

    def record_event_atomic(
        self,
        task_id: str,
        *,
        expected_version: int,
        event_type: str,
        payload: dict[str, object],
    ) -> CanonicalTask:
        """Append an event and advance the canonical CAS version without changing state."""

        with self._transaction():
            self._assert_runtime_locked()
            self._assert_not_stopped_locked()
            task = self._get_task_locked(task_id)
            self._require_expected_version(task, expected_version)
            return self._touch_task_locked(task, event_type=event_type, payload=payload)

    def list_tasks(self) -> list[CanonicalTask]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM canonical_tasks ORDER BY created_at, id"
            ).fetchall()
            return [self._task_from_row(row) for row in rows]

    def transition_with_evidence(
        self,
        task_id: str,
        *,
        expected_version: int,
        target: TaskState,
        event_type: str,
        payload: dict[str, object],
        failure_reason: str | None = None,
    ) -> CanonicalTask:
        if target not in _GENERIC_TRANSITION_TARGETS:
            raise CanonicalConflict("target requires a specialized atomic lifecycle operation")
        with self._transaction():
            self._assert_runtime_locked()
            self._assert_not_stopped_locked()
            task = self._get_task_locked(task_id)
            self._require_expected_version(task, expected_version)
            required = ()
            if target == TaskState.PLANNING:
                required = (CapabilityName.MODEL,)
            elif target == TaskState.RUNNER_PREFLIGHT:
                required = (
                    CapabilityName.RUNNER,
                    CapabilityName.EXTERNAL_CHECKPOINT,
                )
            self._require_capabilities_locked(required)
            return self._transition_locked(
                task,
                target=target,
                event_type=event_type,
                payload=payload,
                failure_reason=failure_reason,
            )

    def propose_plan_atomic(
        self,
        task_id: str,
        *,
        expected_version: int,
        plan_digest: str,
    ) -> CanonicalTask:
        with self._transaction():
            self._assert_runtime_locked()
            self._assert_not_stopped_locked()
            task = self._get_task_locked(task_id)
            self._require_expected_version(task, expected_version)
            return self._transition_locked(
                task,
                target=TaskState.PLAN_PROPOSED,
                event_type="plan.proposed",
                payload={"plan_digest": plan_digest},
                plan_digest=plan_digest,
            )

    def seal_evidence_atomic(
        self,
        task_id: str,
        *,
        expected_version: int,
        verification_decision_digest: str,
        checkpoint_receipt_digest: str,
    ) -> CanonicalTask:
        with self._transaction():
            self._assert_runtime_locked()
            self._assert_not_stopped_locked()
            task = self._get_task_locked(task_id)
            self._require_expected_version(task, expected_version)
            self._require_capabilities_locked((CapabilityName.EXTERNAL_CHECKPOINT,))
            return self._transition_locked(
                task,
                target=TaskState.EVIDENCE_SEALED,
                event_type="evidence.sealed",
                payload={
                    "verification_decision_digest": verification_decision_digest,
                    "checkpoint_receipt_digest": checkpoint_receipt_digest,
                },
                verification_decision_digest=verification_decision_digest,
                checkpoint_receipt_digest=checkpoint_receipt_digest,
            )

    def mark_patch_ready_atomic(
        self,
        task_id: str,
        *,
        expected_version: int,
        final_tree_manifest_digest: str,
        patch_manifest_digest: str,
        changed_path_count: int,
    ) -> CanonicalTask:
        with self._transaction():
            self._assert_runtime_locked()
            self._assert_not_stopped_locked()
            task = self._get_task_locked(task_id)
            self._require_expected_version(task, expected_version)
            return self._transition_locked(
                task,
                target=TaskState.PATCH_READY,
                event_type="patch.ready",
                payload={
                    "final_tree_manifest_digest": final_tree_manifest_digest,
                    "patch_manifest_digest": patch_manifest_digest,
                    "changed_path_count": changed_path_count,
                },
                final_tree_manifest_digest=final_tree_manifest_digest,
                patch_manifest_digest=patch_manifest_digest,
                changed_path_count=changed_path_count,
            )

    def complete_atomic(
        self,
        task_id: str,
        *,
        expected_version: int,
    ) -> CanonicalTask:
        with self._transaction():
            self._assert_runtime_locked()
            self._assert_not_stopped_locked()
            task = self._get_task_locked(task_id)
            self._require_expected_version(task, expected_version)
            self._require_capabilities_locked(
                tuple(
                    dict.fromkeys(
                        (
                            CapabilityName.EXTERNAL_CHECKPOINT,
                            *task.required_capabilities,
                        )
                    )
                )
            )
            return self._transition_locked(
                task,
                target=TaskState.COMPLETED,
                event_type="task.completed",
                payload={
                    "checkpoint_receipt_digest": task.checkpoint_receipt_digest,
                    "verification_decision_digest": task.verification_decision_digest,
                    "final_tree_manifest_digest": task.final_tree_manifest_digest,
                    "patch_manifest_digest": task.patch_manifest_digest,
                    "changed_path_count": task.changed_path_count,
                },
            )

    def capability(self, name: CapabilityName) -> CapabilityGate:
        with self._lock:
            return self._capability_locked(name)

    def capabilities(self) -> tuple[CapabilityGate, ...]:
        with self._lock:
            return tuple(self._capability_locked(name) for name in CapabilityName)

    def update_capability(
        self,
        name: CapabilityName,
        *,
        expected_version: int,
        status: CapabilityStatus,
        feature_enabled: bool,
        installed: bool,
        configured: bool,
        connected: bool,
        healthy: bool,
        qualified: bool,
        authorized: bool,
        operational: bool,
        detail_code: str,
        actor_id: str,
    ) -> CapabilityGate:
        with self._transaction():
            self._assert_runtime_locked()
            current = self._capability_locked(name)
            if current.version != expected_version:
                raise CanonicalConflict("stale capability version")
            updated = CapabilityGate(
                name=name,
                version=current.version + 1,
                status=status,
                feature_enabled=feature_enabled,
                installed=installed,
                configured=configured,
                connected=connected,
                healthy=healthy,
                qualified=qualified,
                authorized=authorized,
                operational=operational,
                detail_code=detail_code,
                updated_at=utc_now(),
            )
            cursor = self._connection.execute(
                """
                UPDATE canonical_capabilities
                SET version=?, status=?, operational=?, record_json=?, updated_at=?
                WHERE name=? AND version=?
                """,
                (
                    updated.version,
                    updated.status.value,
                    int(updated.operational),
                    updated.model_dump_json(),
                    updated.updated_at.isoformat(),
                    name.value,
                    expected_version,
                ),
            )
            if cursor.rowcount != 1:
                raise CanonicalConflict("stale capability version")
            self._append_control_event_locked(
                "capability.updated",
                actor_id,
                {
                    "capability": name.value,
                    "version": updated.version,
                    "status": updated.status.value,
                    "operational": updated.operational,
                },
            )
            return updated

    def capability_snapshot_digest(
        self,
        names: tuple[CapabilityName, ...],
    ) -> str:
        with self._lock:
            return self._capability_snapshot_locked(names)

    def build_approval(
        self,
        task_id: str,
        *,
        purpose: ApprovalPurpose,
        operation_digest: str,
        policy_digest: str,
        ttl_seconds: int = 300,
    ) -> CanonicalApproval:
        if ttl_seconds < 1 or ttl_seconds > 900:
            raise ValueError("approval TTL is invalid")
        with self._lock:
            task = self._get_task_locked(task_id)
            self._approval_pending_target(task, purpose)
            required = _PURPOSE_CAPABILITIES[purpose]
            snapshot = self._capability_snapshot_locked(required)
            now = utc_now()
            payload = {
                "schema_version": "canonical-approval-v1",
                "id": f"approval:{uuid.uuid4().hex}",
                "task_id": task.id,
                "task_digest": task.task_digest,
                "task_version": task.version + 1,
                "purpose": purpose,
                "operation_digest": operation_digest,
                "policy_digest": policy_digest,
                "capability_snapshot_digest": snapshot,
                "nonce": f"nonce:{uuid.uuid4().hex}",
                "created_at": now,
                "expires_at": now + timedelta(seconds=ttl_seconds),
            }
            return CanonicalApproval(
                **payload,
                approval_digest=content_digest(payload),
            )

    def build_replacement_approval(
        self,
        task_id: str,
        previous_approval_id: str,
        *,
        operation_digest: str,
        policy_digest: str,
        ttl_seconds: int = 300,
    ) -> CanonicalApproval:
        """Build a fresh exact approval while retaining the monotonic pending task state."""

        if ttl_seconds < 1 or ttl_seconds > 900:
            raise ValueError("approval TTL is invalid")
        with self._lock:
            task = self._get_task_locked(task_id)
            previous = self._get_approval_locked(previous_approval_id)
            _, pending_state = self._approval_source_and_pending(previous.purpose, task)
            replacement_states = {pending_state}
            if previous.purpose == ApprovalPurpose.EXECUTION:
                replacement_states.add(TaskState.APPROVED)
            if (
                previous.task_id != task.id
                or previous.status not in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}
                or task.state not in replacement_states
                or utc_now() < previous.expires_at
            ):
                raise CanonicalConflict("only an expired approval may be replaced")
            required = _PURPOSE_CAPABILITIES[previous.purpose]
            snapshot = self._capability_snapshot_locked(required)
            now = utc_now()
            payload = {
                "schema_version": "canonical-approval-v1",
                "id": f"approval:{uuid.uuid4().hex}",
                "task_id": task.id,
                "task_digest": task.task_digest,
                "task_version": task.version + 1,
                "purpose": previous.purpose,
                "operation_digest": operation_digest,
                "policy_digest": policy_digest,
                "capability_snapshot_digest": snapshot,
                "nonce": f"nonce:{uuid.uuid4().hex}",
                "created_at": now,
                "expires_at": now + timedelta(seconds=ttl_seconds),
            }
            return CanonicalApproval(**payload, approval_digest=content_digest(payload))

    def replace_expired_approval_atomic(
        self,
        task_id: str,
        previous_approval_id: str,
        *,
        expected_version: int,
        approval: CanonicalApproval,
    ) -> CanonicalTask:
        """Expire the prior authorization and publish its replacement in one transaction."""

        with self._transaction():
            self._assert_runtime_locked()
            self._assert_not_stopped_locked()
            task = self._get_task_locked(task_id)
            self._require_expected_version(task, expected_version)
            previous = self._get_approval_locked(previous_approval_id)
            _, pending_state = self._approval_source_and_pending(previous.purpose, task)
            replacement_states = {pending_state}
            if previous.purpose == ApprovalPurpose.EXECUTION:
                replacement_states.add(TaskState.APPROVED)
            required = _PURPOSE_CAPABILITIES[previous.purpose]
            self._require_capabilities_locked(required)
            if (
                previous.task_id != task.id
                or previous.status not in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}
                or task.state not in replacement_states
                or utc_now() < previous.expires_at
            ):
                raise CanonicalConflict("only an expired approval may be replaced")
            if (
                approval.status != ApprovalStatus.PENDING
                or approval.task_id != task.id
                or approval.task_digest != task.task_digest
                or approval.task_version != task.version + 1
                or approval.purpose != previous.purpose
                or approval.capability_snapshot_digest != self._capability_snapshot_locked(required)
            ):
                raise CanonicalConflict("replacement approval binding is invalid")
            expired = CanonicalApproval.model_validate(
                previous.model_copy(update={"status": ApprovalStatus.EXPIRED}).model_dump(
                    mode="python"
                )
            )
            self._save_approval_locked(expired)
            try:
                self._connection.execute(
                    """
                    INSERT INTO canonical_approvals(
                        id, task_id, purpose, status, approval_digest, nonce,
                        record_json, created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        approval.id,
                        approval.task_id,
                        approval.purpose.value,
                        approval.status.value,
                        approval.approval_digest,
                        approval.nonce,
                        approval.model_dump_json(),
                        approval.created_at.isoformat(),
                        approval.expires_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise CanonicalConflict("replacement approval was already used") from exc
            return self._touch_task_locked(
                task,
                event_type="approval.replaced",
                payload={
                    "previous_approval_id": previous.id,
                    "replacement_approval_id": approval.id,
                    "purpose": approval.purpose.value,
                },
            )

    def publish_approval_atomic(
        self,
        task_id: str,
        *,
        expected_version: int,
        approval: CanonicalApproval,
    ) -> CanonicalTask:
        with self._transaction():
            self._assert_runtime_locked()
            self._assert_not_stopped_locked()
            task = self._get_task_locked(task_id)
            self._require_expected_version(task, expected_version)
            target = self._approval_pending_target(task, approval.purpose)
            required = _PURPOSE_CAPABILITIES[approval.purpose]
            self._require_capabilities_locked(required)
            if (
                approval.status != ApprovalStatus.PENDING
                or approval.task_id != task.id
                or approval.task_digest != task.task_digest
                or approval.task_version != task.version + 1
                or approval.capability_snapshot_digest != self._capability_snapshot_locked(required)
            ):
                raise CanonicalConflict("approval does not bind the pending task and capabilities")
            try:
                self._connection.execute(
                    """
                    INSERT INTO canonical_approvals(
                        id, task_id, purpose, status, approval_digest, nonce,
                        record_json, created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        approval.id,
                        approval.task_id,
                        approval.purpose.value,
                        approval.status.value,
                        approval.approval_digest,
                        approval.nonce,
                        approval.model_dump_json(),
                        approval.created_at.isoformat(),
                        approval.expires_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise CanonicalConflict("approval digest or nonce was already used") from exc
            return self._transition_locked(
                task,
                target=target,
                event_type="approval.published",
                payload={
                    "approval_id": approval.id,
                    "approval_digest": approval.approval_digest,
                    "purpose": approval.purpose.value,
                },
            )

    def approve_atomic(
        self,
        task_id: str,
        approval_id: str,
        *,
        expected_version: int,
        owner_id: str,
        decision_proof_digest: str,
    ) -> CanonicalTask:
        with self._transaction():
            self._assert_runtime_locked()
            self._assert_not_stopped_locked()
            task = self._get_task_locked(task_id)
            self._require_expected_version(task, expected_version)
            approval = self._get_approval_locked(approval_id)
            if approval.task_id != task.id or approval.status != ApprovalStatus.PENDING:
                raise CanonicalConflict("approval is not pending for this task")
            _, pending_state = self._approval_source_and_pending(approval.purpose, task)
            allowed_states = {pending_state}
            if approval.purpose == ApprovalPurpose.EXECUTION:
                allowed_states.add(TaskState.APPROVED)
            if task.state not in allowed_states:
                raise CanonicalConflict("task is not in the approval's pending state")
            if utc_now() >= approval.expires_at:
                raise CanonicalConflict("approval expired")
            now = utc_now()
            approved = CanonicalApproval.model_validate(
                approval.model_copy(
                    update={
                        "status": ApprovalStatus.APPROVED,
                        "approved_by": owner_id,
                        "decision_proof_digest": decision_proof_digest,
                        "approved_at": now,
                    }
                ).model_dump(mode="python")
            )
            self._save_approval_locked(approved)
            target = (
                TaskState.APPROVED
                if approval.purpose == ApprovalPurpose.EXECUTION
                and task.state != TaskState.APPROVED
                else None
            )
            if target is not None:
                return self._transition_locked(
                    task,
                    target=target,
                    event_type="approval.approved",
                    payload={
                        "approval_id": approval.id,
                        "purpose": approval.purpose.value,
                        "owner_id": owner_id,
                        "decision_proof_digest": decision_proof_digest,
                    },
                )
            return self._touch_task_locked(
                task,
                event_type="approval.approved",
                payload={
                    "approval_id": approval.id,
                    "purpose": approval.purpose.value,
                    "owner_id": owner_id,
                    "decision_proof_digest": decision_proof_digest,
                },
            )

    def reject_approval_atomic(
        self,
        task_id: str,
        approval_id: str,
        *,
        expected_version: int,
        actor_id: str,
        reason_code: str,
    ) -> CanonicalTask:
        """Reject one pending approval and atomically cancel its canonical task.

        The canonical graph is deliberately monotonic. A rejected exact plan therefore cannot
        rewind the same task to planning; callers must create a new task for a revised plan.
        """

        with self._transaction():
            self._assert_runtime_locked()
            self._assert_not_stopped_locked()
            task = self._get_task_locked(task_id)
            self._require_expected_version(task, expected_version)
            approval = self._get_approval_locked(approval_id)
            if approval.task_id != task.id or approval.status != ApprovalStatus.PENDING:
                raise CanonicalConflict("approval is not pending for this task")
            _, pending_state = self._approval_source_and_pending(approval.purpose, task)
            if task.state != pending_state:
                raise CanonicalConflict("task is not in the approval's pending state")
            if utc_now() >= approval.expires_at:
                raise CanonicalConflict("approval expired")
            rejected = CanonicalApproval.model_validate(
                approval.model_copy(update={"status": ApprovalStatus.REJECTED}).model_dump(
                    mode="python"
                )
            )
            self._save_approval_locked(rejected)
            return self._transition_locked(
                task,
                target=TaskState.CANCELED,
                event_type="approval.rejected",
                payload={
                    "approval_id": approval.id,
                    "purpose": approval.purpose.value,
                    "actor_id": actor_id,
                    "reason_code": reason_code,
                },
            )

    def terminate_task_atomic(
        self,
        task_id: str,
        *,
        expected_version: int,
        target: TaskState,
        event_type: str,
        payload: dict[str, object],
        failure_reason: str | None = None,
    ) -> CanonicalTask:
        """Close live dispatch/approval authority and enter CANCELED or FAILED atomically."""

        if target not in {TaskState.CANCELED, TaskState.FAILED}:
            raise CanonicalConflict("task termination target must be CANCELED or FAILED")
        with self._transaction():
            self._assert_runtime_locked()
            self._assert_not_stopped_locked()
            task = self._get_task_locked(task_id)
            self._require_expected_version(task, expected_version)
            now = utc_now()
            lease_rows = self._connection.execute(
                "SELECT record_json FROM canonical_dispatch_leases "
                "WHERE task_id=? AND status='active'",
                (task_id,),
            ).fetchall()
            for row in lease_rows:
                lease = DispatchLease.model_validate_json(row["record_json"])
                canceled = DispatchLease.model_validate(
                    lease.model_copy(
                        update={
                            "status": DispatchLeaseStatus.CANCELED,
                            "completed_at": now,
                        }
                    ).model_dump(mode="python")
                )
                self._save_lease_locked(canceled)
            approval_rows = self._connection.execute(
                "SELECT record_json FROM canonical_approvals "
                "WHERE task_id=? AND status IN ('pending','approved')",
                (task_id,),
            ).fetchall()
            for row in approval_rows:
                approval = CanonicalApproval.model_validate_json(row["record_json"])
                revoked = CanonicalApproval.model_validate(
                    approval.model_copy(update={"status": ApprovalStatus.REVOKED}).model_dump(
                        mode="python"
                    )
                )
                self._save_approval_locked(revoked)
            return self._transition_locked(
                task,
                target=target,
                event_type=event_type,
                payload={
                    **payload,
                    "canceled_dispatch_count": len(lease_rows),
                    "revoked_approval_count": len(approval_rows),
                },
                failure_reason=failure_reason,
            )

    def get_approval(self, approval_id: str) -> CanonicalApproval:
        with self._lock:
            approval = self._get_approval_locked(approval_id)
            if (
                approval.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}
                and utc_now() >= approval.expires_at
            ):
                return CanonicalApproval.model_validate(
                    approval.model_copy(update={"status": ApprovalStatus.EXPIRED}).model_dump(
                        mode="python"
                    )
                )
            return approval

    def claim_dispatch_atomic(
        self,
        task_id: str,
        approval_id: str,
        *,
        expected_version: int,
        request_digest: str,
        policy_digest: str,
        lease_seconds: int = 300,
    ) -> tuple[CanonicalTask, DispatchLease, str]:
        if lease_seconds < 1 or lease_seconds > 600:
            raise ValueError("dispatch lease duration is invalid")
        with self._transaction():
            self._assert_runtime_locked()
            self._assert_not_stopped_locked()
            task = self._get_task_locked(task_id)
            self._require_expected_version(task, expected_version)
            if task.state != TaskState.RUNNER_PREFLIGHT:
                raise CanonicalConflict("dispatch requires runner preflight state")
            required = _PURPOSE_CAPABILITIES[ApprovalPurpose.EXECUTION]
            self._require_capabilities_locked(required)
            approval = self._validated_consumable_approval_locked(
                task,
                approval_id,
                purpose=ApprovalPurpose.EXECUTION,
                operation_digest=request_digest,
                policy_digest=policy_digest,
                required_capabilities=required,
            )
            now = utc_now()
            consumed = self._consume_approval_model(approval, now)
            self._save_approval_locked(consumed)
            control = self._control_locked()
            token = secrets.token_urlsafe(32)
            lease = DispatchLease(
                id=f"lease:{uuid.uuid4().hex}",
                task_id=task.id,
                approval_id=approval.id,
                request_digest=request_digest,
                token_digest=hashlib.sha256(token.encode()).hexdigest(),
                runtime_id=self.runtime_id,
                generation=int(control["generation"]),
                status=DispatchLeaseStatus.ACTIVE,
                created_at=now,
                expires_at=now + timedelta(seconds=lease_seconds),
            )
            try:
                self._connection.execute(
                    """
                    INSERT INTO canonical_dispatch_leases(
                        id, task_id, approval_id, request_digest, token_digest,
                        runtime_id, generation, status, record_json, created_at, expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        lease.id,
                        lease.task_id,
                        lease.approval_id,
                        lease.request_digest,
                        lease.token_digest,
                        lease.runtime_id,
                        lease.generation,
                        lease.status.value,
                        lease.model_dump_json(),
                        lease.created_at.isoformat(),
                        lease.expires_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise CanonicalConflict("an active dispatch lease already exists") from exc
            changed = self._transition_locked(
                task,
                target=TaskState.EXECUTING,
                event_type="dispatch.claimed",
                payload={
                    "approval_id": approval.id,
                    "lease_id": lease.id,
                    "request_digest": request_digest,
                    "token_digest": lease.token_digest,
                    "generation": lease.generation,
                },
            )
            return changed, lease, token

    def complete_dispatch_atomic(
        self,
        task_id: str,
        lease_id: str,
        *,
        expected_version: int,
        lease_token: str,
        result_digest: str,
    ) -> CanonicalTask:
        with self._transaction():
            self._assert_runtime_locked()
            self._assert_not_stopped_locked()
            task = self._get_task_locked(task_id)
            self._require_expected_version(task, expected_version)
            if task.state != TaskState.EXECUTING:
                raise CanonicalConflict("dispatch completion requires executing state")
            lease = self._get_lease_locked(lease_id)
            control = self._control_locked()
            if (
                lease.task_id != task.id
                or lease.status != DispatchLeaseStatus.ACTIVE
                or lease.runtime_id != self.runtime_id
                or lease.generation != int(control["generation"])
                or not secrets.compare_digest(
                    lease.token_digest,
                    hashlib.sha256(lease_token.encode()).hexdigest(),
                )
            ):
                raise CanonicalConflict("dispatch lease binding is invalid")
            if utc_now() >= lease.expires_at:
                raise CanonicalConflict("dispatch lease expired")
            now = utc_now()
            completed = DispatchLease.model_validate(
                lease.model_copy(
                    update={
                        "status": DispatchLeaseStatus.COMPLETED,
                        "completed_at": now,
                    }
                ).model_dump(mode="python")
            )
            self._save_lease_locked(completed)
            return self._transition_locked(
                task,
                target=TaskState.TESTING,
                event_type="dispatch.completed",
                payload={
                    "lease_id": lease.id,
                    "request_digest": lease.request_digest,
                    "result_digest": result_digest,
                },
            )

    def get_lease(self, lease_id: str) -> DispatchLease:
        with self._lock:
            return self._get_lease_locked(lease_id)

    def assert_dispatch_active(
        self,
        task_id: str,
        lease_id: str,
        *,
        lease_token: str,
    ) -> DispatchLease:
        """Revalidate live dispatch authority immediately before delegated execution."""

        with self._lock:
            self._assert_runtime_locked()
            self._assert_not_stopped_locked()
            task = self._get_task_locked(task_id)
            lease = self._get_lease_locked(lease_id)
            control = self._control_locked()
            if (
                task.state != TaskState.EXECUTING
                or lease.task_id != task.id
                or lease.status != DispatchLeaseStatus.ACTIVE
                or lease.runtime_id != self.runtime_id
                or lease.generation != int(control["generation"])
                or not secrets.compare_digest(
                    lease.token_digest,
                    hashlib.sha256(lease_token.encode()).hexdigest(),
                )
            ):
                raise CanonicalConflict("dispatch authority is no longer active")
            if utc_now() >= lease.expires_at:
                raise CanonicalConflict("dispatch lease expired")
            return lease

    def list_leases(self, task_id: str) -> list[DispatchLease]:
        with self._lock:
            self._get_task_locked(task_id)
            rows = self._connection.execute(
                """
                SELECT record_json FROM canonical_dispatch_leases
                WHERE task_id=? ORDER BY created_at, id
                """,
                (task_id,),
            ).fetchall()
            return [DispatchLease.model_validate_json(row["record_json"]) for row in rows]

    def consume_delivery_approval_atomic(
        self,
        task_id: str,
        approval_id: str,
        *,
        expected_version: int,
        purpose: ApprovalPurpose,
        operation_digest: str,
        policy_digest: str,
        result_digest: str,
    ) -> CanonicalTask:
        mapping = {
            ApprovalPurpose.APPLY_PATCH: (
                TaskState.APPLY_APPROVAL_PENDING,
                TaskState.APPLIED,
            ),
            ApprovalPurpose.LOCAL_COMMIT: (
                TaskState.COMMIT_APPROVAL_PENDING,
                TaskState.LOCALLY_COMMITTED,
            ),
            ApprovalPurpose.ROLLBACK: (
                TaskState.ROLLBACK_PENDING,
                TaskState.ROLLED_BACK,
            ),
        }
        if purpose not in mapping:
            raise CanonicalConflict("execution approvals require the dispatch lease API")
        source, target = mapping[purpose]
        with self._transaction():
            self._assert_runtime_locked()
            self._assert_not_stopped_locked()
            task = self._get_task_locked(task_id)
            self._require_expected_version(task, expected_version)
            if task.state != source:
                raise CanonicalConflict("task is not pending this delivery operation")
            required = _PURPOSE_CAPABILITIES[purpose]
            self._require_capabilities_locked(required)
            approval = self._validated_consumable_approval_locked(
                task,
                approval_id,
                purpose=purpose,
                operation_digest=operation_digest,
                policy_digest=policy_digest,
                required_capabilities=required,
            )
            if (
                purpose == ApprovalPurpose.APPLY_PATCH
                and task.patch_manifest_digest != operation_digest
            ):
                raise CanonicalConflict("apply approval is not bound to the final patch manifest")
            self._save_approval_locked(self._consume_approval_model(approval, utc_now()))
            return self._transition_locked(
                task,
                target=target,
                event_type=f"delivery.{purpose.value}.completed",
                payload={
                    "approval_id": approval.id,
                    "operation_digest": operation_digest,
                    "result_digest": result_digest,
                },
            )

    def engage_emergency_stop(self, *, actor_id: str, reason_code: str) -> EmergencyControl:
        with self._transaction():
            self._assert_runtime_locked()
            control = self._control_locked()
            generation = int(control["generation"]) + 1
            self._engage_emergency_stop_locked(
                actor_id=actor_id,
                reason_code=reason_code,
                generation=generation,
                runtime_id=self.runtime_id,
            )
            return self.control()

    def clear_emergency_stop(self, *, actor_id: str, reason_code: str) -> EmergencyControl:
        with self._transaction():
            self._assert_runtime_locked()
            control = self._control_locked()
            if not bool(control["emergency_stopped"]):
                raise CanonicalConflict("emergency stop is not active")
            now = utc_now()
            generation = int(control["generation"]) + 1
            self._connection.execute(
                """
                UPDATE canonical_control
                SET emergency_stopped=0, generation=?, reason_code=?, updated_at=?
                WHERE singleton=1
                """,
                (generation, reason_code, now.isoformat()),
            )
            self._append_control_event_locked(
                "emergency_stop.cleared",
                actor_id,
                {"reason_code": reason_code, "generation": generation},
            )
            return EmergencyControl(
                emergency_stopped=False,
                generation=generation,
                active_runtime_id=self.runtime_id,
                reason_code=reason_code,
                updated_at=now,
            )

    def list_control_events(self) -> list[dict[str, object]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM canonical_control_events ORDER BY sequence"
            ).fetchall()
            previous = None
            records: list[dict[str, object]] = []
            for expected_sequence, row in enumerate(rows, start=1):
                record = json.loads(str(row["record_json"]))
                record_hash = record.pop("record_hash", None)
                if (
                    record.get("sequence") != expected_sequence
                    or record.get("previous_hash") != previous
                    or record_hash != content_digest(record)
                    or record_hash != row["record_hash"]
                    or record.get("event_type") != row["event_type"]
                    or record.get("actor_id") != row["actor_id"]
                ):
                    raise CanonicalConflict("canonical control-event chain is invalid")
                previous = str(record_hash)
                records.append({**record, "record_hash": record_hash})
            return records

    def _initialize_capabilities(self) -> None:
        with self._connection:
            for name in CapabilityName:
                row = self._connection.execute(
                    "SELECT 1 FROM canonical_capabilities WHERE name=?",
                    (name.value,),
                ).fetchone()
                if row is not None:
                    continue
                gate = CapabilityGate(
                    name=name,
                    version=0,
                    status=CapabilityStatus.DISABLED_BY_POLICY,
                    feature_enabled=False,
                    installed=False,
                    configured=False,
                    connected=False,
                    healthy=False,
                    qualified=False,
                    authorized=False,
                    operational=False,
                    detail_code="default_off",
                    updated_at=utc_now(),
                )
                self._connection.execute(
                    """
                    INSERT INTO canonical_capabilities(
                        name, version, status, operational, record_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        gate.name.value,
                        gate.version,
                        gate.status.value,
                        int(gate.operational),
                        gate.model_dump_json(),
                        gate.updated_at.isoformat(),
                    ),
                )

    def _claim_runtime(self) -> None:
        with self._transaction():
            control = self._control_locked()
            active = control["active_runtime_id"]
            if active == self.runtime_id:
                return
            restart_placeholders = ",".join("?" for _ in RESTART_UNSAFE_STATES)
            unsafe_count = int(
                self._connection.execute(
                    f"SELECT COUNT(*) FROM canonical_tasks WHERE state IN ({restart_placeholders})",
                    tuple(state.value for state in RESTART_UNSAFE_STATES),
                ).fetchone()[0]
            )
            active_leases = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM canonical_dispatch_leases WHERE status='active'"
                ).fetchone()[0]
            )
            if active is not None and (unsafe_count or active_leases):
                self._engage_emergency_stop_locked(
                    actor_id=self.runtime_id,
                    reason_code="restart_reconciliation",
                    generation=int(control["generation"]) + 1,
                    runtime_id=self.runtime_id,
                )
                return
            now = utc_now()
            generation = int(control["generation"]) + (1 if active is not None else 0)
            self._connection.execute(
                """
                UPDATE canonical_control
                SET generation=?, active_runtime_id=?, reason_code=?, updated_at=?
                WHERE singleton=1
                """,
                (generation, self.runtime_id, "runtime_claimed", now.isoformat()),
            )
            self._append_control_event_locked(
                "runtime.claimed",
                self.runtime_id,
                {
                    "previous_runtime_id": active,
                    "runtime_id": self.runtime_id,
                    "generation": generation,
                },
            )

    def _engage_emergency_stop_locked(
        self,
        *,
        actor_id: str,
        reason_code: str,
        generation: int,
        runtime_id: str,
    ) -> None:
        now = utc_now()
        lease_rows = self._connection.execute(
            "SELECT record_json FROM canonical_dispatch_leases WHERE status='active'"
        ).fetchall()
        for row in lease_rows:
            lease = DispatchLease.model_validate_json(row["record_json"])
            canceled = DispatchLease.model_validate(
                lease.model_copy(
                    update={
                        "status": DispatchLeaseStatus.CANCELED,
                        "completed_at": now,
                    }
                ).model_dump(mode="python")
            )
            self._save_lease_locked(canceled)
        approval_rows = self._connection.execute(
            """
            SELECT record_json FROM canonical_approvals
            WHERE status IN ('pending','approved')
            """
        ).fetchall()
        for row in approval_rows:
            approval = CanonicalApproval.model_validate_json(row["record_json"])
            revoked = CanonicalApproval.model_validate(
                approval.model_copy(update={"status": ApprovalStatus.REVOKED}).model_dump(
                    mode="python"
                )
            )
            self._save_approval_locked(revoked)
        task_rows = self._connection.execute(
            "SELECT * FROM canonical_tasks ORDER BY created_at, id"
        ).fetchall()
        for row in task_rows:
            task = self._task_from_row(row)
            if task.state in {
                TaskState.COMPLETED,
                TaskState.CANCELED,
                TaskState.ROLLED_BACK,
                TaskState.EMERGENCY_STOPPED,
            }:
                continue
            self._transition_locked(
                task,
                target=TaskState.EMERGENCY_STOPPED,
                event_type="emergency_stop.engaged",
                payload={"actor_id": actor_id, "reason_code": reason_code},
                enforce_capabilities=False,
            )
        self._connection.execute(
            """
            UPDATE canonical_control
            SET emergency_stopped=1, generation=?, active_runtime_id=?,
                reason_code=?, updated_at=?
            WHERE singleton=1
            """,
            (generation, runtime_id, reason_code, now.isoformat()),
        )
        self._append_control_event_locked(
            "emergency_stop.engaged",
            actor_id,
            {
                "reason_code": reason_code,
                "generation": generation,
                "runtime_id": runtime_id,
                "canceled_lease_count": len(lease_rows),
                "revoked_approval_count": len(approval_rows),
            },
        )

    def _transition_locked(
        self,
        task: CanonicalTask,
        *,
        target: TaskState,
        event_type: str,
        payload: dict[str, object],
        plan_digest: str | None = None,
        verification_decision_digest: str | None = None,
        checkpoint_receipt_digest: str | None = None,
        final_tree_manifest_digest: str | None = None,
        patch_manifest_digest: str | None = None,
        changed_path_count: int | None = None,
        failure_reason: str | None = None,
        enforce_capabilities: bool = True,
    ) -> CanonicalTask:
        try:
            assert_legal_transition(task.state, target)
        except ValueError as exc:
            raise CanonicalConflict(str(exc)) from exc
        if enforce_capabilities:
            required: tuple[CapabilityName, ...] = ()
            if target == TaskState.PLANNING:
                required = (CapabilityName.MODEL,)
            elif target == TaskState.RUNNER_PREFLIGHT:
                required = (
                    CapabilityName.RUNNER,
                    CapabilityName.EXTERNAL_CHECKPOINT,
                )
            elif target == TaskState.EVIDENCE_SEALED:
                required = (CapabilityName.EXTERNAL_CHECKPOINT,)
            elif target == TaskState.COMPLETED:
                required = tuple(
                    dict.fromkeys((CapabilityName.EXTERNAL_CHECKPOINT, *task.required_capabilities))
                )
            self._require_capabilities_locked(required)
        updates: dict[str, object] = {
            "state": target,
            "version": task.version + 1,
            "updated_at": utc_now(),
        }
        if plan_digest is not None:
            updates["plan_digest"] = plan_digest
        if verification_decision_digest is not None:
            updates["verification_decision_digest"] = verification_decision_digest
        if checkpoint_receipt_digest is not None:
            updates["checkpoint_receipt_digest"] = checkpoint_receipt_digest
        if final_tree_manifest_digest is not None:
            updates["final_tree_manifest_digest"] = final_tree_manifest_digest
        if patch_manifest_digest is not None:
            updates["patch_manifest_digest"] = patch_manifest_digest
        if changed_path_count is not None:
            updates["changed_path_count"] = changed_path_count
        if failure_reason is not None:
            updates["failure_reason"] = failure_reason
        changed = CanonicalTask.model_validate(
            task.model_copy(update=updates).model_dump(mode="python")
        )
        self._save_task_locked(changed, expected_version=task.version)
        self._append_evidence_locked(
            task.id,
            event_type=event_type,
            payload={
                **payload,
                "from_state": task.state.value,
                "to_state": target.value,
                "from_version": task.version,
                "to_version": changed.version,
            },
        )
        return changed

    def _touch_task_locked(
        self,
        task: CanonicalTask,
        *,
        event_type: str,
        payload: dict[str, object],
    ) -> CanonicalTask:
        changed = CanonicalTask.model_validate(
            task.model_copy(
                update={"version": task.version + 1, "updated_at": utc_now()}
            ).model_dump(mode="python")
        )
        self._save_task_locked(changed, expected_version=task.version)
        self._append_evidence_locked(
            task.id,
            event_type=event_type,
            payload={
                **payload,
                "state": task.state.value,
                "from_version": task.version,
                "to_version": changed.version,
            },
        )
        return changed

    def _save_task_locked(self, task: CanonicalTask, *, expected_version: int) -> None:
        try:
            cursor = self._connection.execute(
                """
                UPDATE canonical_tasks
                SET state=?, version=?, record_json=?, updated_at=?
                WHERE id=? AND version=?
                """,
                (
                    task.state.value,
                    task.version,
                    task.model_dump_json(),
                    task.updated_at.isoformat(),
                    task.id,
                    expected_version,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise CanonicalConflict("database rejected canonical task transition") from exc
        if cursor.rowcount != 1:
            raise CanonicalConflict("stale canonical task version")

    def _get_task_locked(self, task_id: str) -> CanonicalTask:
        row = self._connection.execute(
            "SELECT * FROM canonical_tasks WHERE id=?",
            (task_id,),
        ).fetchone()
        if row is None:
            raise CanonicalNotFound("canonical task was not found")
        return self._task_from_row(row)

    @staticmethod
    def _task_from_row(row: sqlite3.Row) -> CanonicalTask:
        task = CanonicalTask.model_validate_json(row["record_json"])
        if (
            task.id != row["id"]
            or task.task_digest != row["task_digest"]
            or task.source_snapshot_digest != row["source_snapshot_digest"]
            or task.state.value != row["state"]
            or task.version != int(row["version"])
        ):
            raise CanonicalConflict("canonical task columns and record differ")
        return task

    def _append_evidence_locked(
        self,
        task_id: str,
        *,
        event_type: str,
        payload: dict[str, object],
    ) -> CanonicalEvidence:
        if len(canonical_json(payload).encode()) > MAX_EVIDENCE_BYTES:
            raise CanonicalConflict("canonical evidence payload exceeds its byte limit")
        existing = self._list_evidence_locked(task_id)
        now = utc_now()
        sequence = len(existing) + 1
        previous = existing[-1].record_hash if existing else None
        hash_payload = {
            "schema_version": "canonical-evidence-v1",
            "task_id": task_id,
            "sequence": sequence,
            "event_type": event_type,
            "payload": payload,
            "previous_hash": previous,
            "created_at": now,
        }
        record_hash = content_digest(hash_payload)
        evidence = CanonicalEvidence(
            id=f"cev:{record_hash[:24]}",
            task_id=task_id,
            sequence=sequence,
            event_type=event_type,
            payload=payload,
            previous_hash=previous,
            record_hash=record_hash,
            created_at=now,
        )
        self._connection.execute(
            """
            INSERT INTO canonical_evidence(
                id, task_id, sequence, event_type, record_json,
                previous_hash, record_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence.id,
                evidence.task_id,
                evidence.sequence,
                evidence.event_type,
                evidence.model_dump_json(),
                evidence.previous_hash,
                evidence.record_hash,
                evidence.created_at.isoformat(),
            ),
        )
        return evidence

    def list_evidence(self, task_id: str) -> list[CanonicalEvidence]:
        with self._lock:
            self._get_task_locked(task_id)
            return self._list_evidence_locked(task_id)

    def _list_evidence_locked(self, task_id: str) -> list[CanonicalEvidence]:
        rows = self._connection.execute(
            """
            SELECT * FROM canonical_evidence
            WHERE task_id=? ORDER BY sequence
            """,
            (task_id,),
        ).fetchall()
        previous = None
        evidence: list[CanonicalEvidence] = []
        for expected_sequence, row in enumerate(rows, start=1):
            item = CanonicalEvidence.model_validate_json(row["record_json"])
            hash_payload = {
                "schema_version": item.schema_version,
                "task_id": item.task_id,
                "sequence": item.sequence,
                "event_type": item.event_type,
                "payload": item.payload,
                "previous_hash": item.previous_hash,
                "created_at": item.created_at,
            }
            if (
                item.sequence != expected_sequence
                or item.previous_hash != previous
                or item.record_hash != content_digest(hash_payload)
                or item.record_hash != row["record_hash"]
                or item.id != row["id"]
            ):
                raise CanonicalConflict("canonical evidence chain is invalid")
            previous = item.record_hash
            evidence.append(item)
        return evidence

    def _capability_locked(self, name: CapabilityName) -> CapabilityGate:
        row = self._connection.execute(
            "SELECT * FROM canonical_capabilities WHERE name=?",
            (name.value,),
        ).fetchone()
        if row is None:
            raise CanonicalNotFound("canonical capability was not found")
        gate = CapabilityGate.model_validate_json(row["record_json"])
        if (
            gate.name.value != row["name"]
            or gate.version != int(row["version"])
            or gate.status.value != row["status"]
            or gate.operational != bool(row["operational"])
        ):
            raise CanonicalConflict("canonical capability columns and record differ")
        return gate

    def _require_capabilities_locked(self, names: tuple[CapabilityName, ...]) -> None:
        blocked = [name.value for name in names if not self._capability_locked(name).operational]
        if blocked:
            raise CanonicalCapabilityBlocked(
                "required capabilities are not operational: " + ", ".join(blocked)
            )

    def _capability_snapshot_locked(self, names: tuple[CapabilityName, ...]) -> str:
        unique = sorted(set(names), key=lambda item: item.value)
        return content_digest(
            {
                "schema_version": "canonical-capability-snapshot-v1",
                "capabilities": [self._capability_locked(name) for name in unique],
            }
        )

    def _approval_pending_target(
        self,
        task: CanonicalTask,
        purpose: ApprovalPurpose,
    ) -> TaskState:
        if purpose == ApprovalPurpose.ROLLBACK:
            target = TaskState.ROLLBACK_PENDING
            if target not in LEGAL_TRANSITIONS[task.state]:
                raise CanonicalConflict("task cannot enter rollback approval from this state")
            return target
        source, target = _PURPOSE_PENDING_STATE[purpose]
        if task.state != source:
            raise CanonicalConflict("task is not ready for this approval purpose")
        return target

    @staticmethod
    def _approval_source_and_pending(
        purpose: ApprovalPurpose,
        task: CanonicalTask,
    ) -> tuple[TaskState | None, TaskState]:
        if purpose == ApprovalPurpose.ROLLBACK:
            return None, TaskState.ROLLBACK_PENDING
        return _PURPOSE_PENDING_STATE[purpose]

    def _get_approval_locked(self, approval_id: str) -> CanonicalApproval:
        row = self._connection.execute(
            "SELECT * FROM canonical_approvals WHERE id=?",
            (approval_id,),
        ).fetchone()
        if row is None:
            raise CanonicalNotFound("canonical approval was not found")
        approval = CanonicalApproval.model_validate_json(row["record_json"])
        if (
            approval.id != row["id"]
            or approval.status.value != row["status"]
            or approval.approval_digest != row["approval_digest"]
            or approval.nonce != row["nonce"]
        ):
            raise CanonicalConflict("canonical approval columns and record differ")
        return approval

    def _save_approval_locked(self, approval: CanonicalApproval) -> None:
        cursor = self._connection.execute(
            """
            UPDATE canonical_approvals
            SET status=?, record_json=?
            WHERE id=? AND approval_digest=?
            """,
            (
                approval.status.value,
                approval.model_dump_json(),
                approval.id,
                approval.approval_digest,
            ),
        )
        if cursor.rowcount != 1:
            raise CanonicalConflict("canonical approval update failed")

    def _validated_consumable_approval_locked(
        self,
        task: CanonicalTask,
        approval_id: str,
        *,
        purpose: ApprovalPurpose,
        operation_digest: str,
        policy_digest: str,
        required_capabilities: tuple[CapabilityName, ...],
    ) -> CanonicalApproval:
        approval = self._get_approval_locked(approval_id)
        if (
            approval.task_id != task.id
            or approval.task_digest != task.task_digest
            or approval.purpose != purpose
            or approval.status != ApprovalStatus.APPROVED
            or approval.operation_digest != operation_digest
            or approval.policy_digest != policy_digest
            or approval.capability_snapshot_digest
            != self._capability_snapshot_locked(required_capabilities)
        ):
            raise CanonicalConflict("approval is stale, changed, or not authorized")
        if utc_now() >= approval.expires_at:
            raise CanonicalConflict("approval expired")
        return approval

    @staticmethod
    def _consume_approval_model(
        approval: CanonicalApproval,
        consumed_at: object,
    ) -> CanonicalApproval:
        return CanonicalApproval.model_validate(
            approval.model_copy(
                update={
                    "status": ApprovalStatus.CONSUMED,
                    "consumed_at": consumed_at,
                }
            ).model_dump(mode="python")
        )

    def _get_lease_locked(self, lease_id: str) -> DispatchLease:
        row = self._connection.execute(
            "SELECT * FROM canonical_dispatch_leases WHERE id=?",
            (lease_id,),
        ).fetchone()
        if row is None:
            raise CanonicalNotFound("canonical dispatch lease was not found")
        lease = DispatchLease.model_validate_json(row["record_json"])
        if (
            lease.id != row["id"]
            or lease.status.value != row["status"]
            or lease.token_digest != row["token_digest"]
            or lease.generation != int(row["generation"])
        ):
            raise CanonicalConflict("canonical dispatch lease columns and record differ")
        return lease

    def _save_lease_locked(self, lease: DispatchLease) -> None:
        cursor = self._connection.execute(
            """
            UPDATE canonical_dispatch_leases
            SET status=?, record_json=?
            WHERE id=? AND token_digest=?
            """,
            (
                lease.status.value,
                lease.model_dump_json(),
                lease.id,
                lease.token_digest,
            ),
        )
        if cursor.rowcount != 1:
            raise CanonicalConflict("canonical dispatch lease update failed")

    def _control_locked(self) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM canonical_control WHERE singleton=1"
        ).fetchone()
        if row is None:
            raise CanonicalStoreError("canonical emergency control is missing")
        return row

    def _assert_runtime_locked(self) -> None:
        active = self._control_locked()["active_runtime_id"]
        if active != self.runtime_id:
            raise CanonicalConflict("canonical runtime was fenced by a newer runtime")

    def _assert_not_stopped_locked(self) -> None:
        if bool(self._control_locked()["emergency_stopped"]):
            raise CanonicalEmergencyStopped("canonical emergency stop is active")

    def _append_control_event_locked(
        self,
        event_type: str,
        actor_id: str,
        payload: dict[str, object],
    ) -> None:
        row = self._connection.execute(
            """
            SELECT sequence, record_hash FROM canonical_control_events
            ORDER BY sequence DESC LIMIT 1
            """
        ).fetchone()
        sequence = 1 if row is None else int(row["sequence"]) + 1
        previous = None if row is None else str(row["record_hash"])
        now = utc_now()
        record = {
            "schema_version": "canonical-control-event-v1",
            "sequence": sequence,
            "event_type": event_type,
            "actor_id": actor_id,
            "payload": payload,
            "previous_hash": previous,
            "created_at": now.isoformat(),
        }
        record_hash = content_digest(record)
        stored = {**record, "record_hash": record_hash}
        self._connection.execute(
            """
            INSERT INTO canonical_control_events(
                sequence, event_type, actor_id, record_json,
                previous_hash, record_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sequence,
                event_type,
                actor_id,
                canonical_json(stored),
                previous,
                record_hash,
                now.isoformat(),
            ),
        )

    @staticmethod
    def _require_expected_version(task: CanonicalTask, expected_version: int) -> None:
        if task.version != expected_version:
            raise CanonicalConflict(
                f"stale canonical task version: expected {expected_version}, current {task.version}"
            )

    class _Transaction:
        def __init__(self, store: CanonicalStateStore) -> None:
            self.store = store
            self.savepoint: str | None = None

        def __enter__(self) -> None:
            self.store._lock.acquire()
            try:
                if self.store._connection.in_transaction:
                    self.savepoint = f"canonical_{uuid.uuid4().hex}"
                    self.store._connection.execute(f"SAVEPOINT {self.savepoint}")
                else:
                    self.store._connection.execute("BEGIN IMMEDIATE")
            except Exception:
                self.store._lock.release()
                raise

        def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
            try:
                if self.savepoint is not None:
                    if exc_type is None:
                        self.store._connection.execute(f"RELEASE SAVEPOINT {self.savepoint}")
                    else:
                        self.store._connection.execute(f"ROLLBACK TO SAVEPOINT {self.savepoint}")
                        self.store._connection.execute(f"RELEASE SAVEPOINT {self.savepoint}")
                elif exc_type is None:
                    self.store._connection.commit()
                else:
                    self.store._connection.rollback()
            finally:
                self.store._lock.release()

    def _transaction(self) -> _Transaction:
        return self._Transaction(self)
