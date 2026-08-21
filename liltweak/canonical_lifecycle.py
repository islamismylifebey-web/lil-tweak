from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    StringConstraints,
    model_validator,
)
from pydantic_core import to_jsonable_python

SHA256 = r"^[0-9a-f]{64}$"
SAFE_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
EventType = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_.:-]*$"),
]


def utc_now() -> datetime:
    return datetime.now(UTC)


def canonical_json(value: object) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", exclude_none=False)
    else:
        value = to_jsonable_python(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class CanonicalSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TaskState(StrEnum):
    RECEIVED = "RECEIVED"
    INSPECTED = "INSPECTED"
    PLANNING = "PLANNING"
    PLAN_PROPOSED = "PLAN_PROPOSED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    APPROVED = "APPROVED"
    RUNNER_PREFLIGHT = "RUNNER_PREFLIGHT"
    EXECUTING = "EXECUTING"
    TESTING = "TESTING"
    VERIFYING = "VERIFYING"
    EVIDENCE_SEALED = "EVIDENCE_SEALED"
    PATCH_READY = "PATCH_READY"
    APPLY_APPROVAL_PENDING = "APPLY_APPROVAL_PENDING"
    APPLIED = "APPLIED"
    COMMIT_APPROVAL_PENDING = "COMMIT_APPROVAL_PENDING"
    LOCALLY_COMMITTED = "LOCALLY_COMMITTED"
    COMPLETED = "COMPLETED"
    CANCELED = "CANCELED"
    FAILED = "FAILED"
    ROLLBACK_PENDING = "ROLLBACK_PENDING"
    ROLLED_BACK = "ROLLED_BACK"
    EMERGENCY_STOPPED = "EMERGENCY_STOPPED"


STATE_ORDER: MappingProxyType[TaskState, int] = MappingProxyType(
    {
        TaskState.RECEIVED: 10,
        TaskState.INSPECTED: 20,
        TaskState.PLANNING: 30,
        TaskState.PLAN_PROPOSED: 40,
        TaskState.APPROVAL_PENDING: 50,
        TaskState.APPROVED: 60,
        TaskState.RUNNER_PREFLIGHT: 70,
        TaskState.EXECUTING: 80,
        TaskState.TESTING: 90,
        TaskState.VERIFYING: 100,
        TaskState.EVIDENCE_SEALED: 110,
        TaskState.PATCH_READY: 120,
        TaskState.APPLY_APPROVAL_PENDING: 130,
        TaskState.APPLIED: 140,
        TaskState.COMMIT_APPROVAL_PENDING: 150,
        TaskState.LOCALLY_COMMITTED: 160,
        TaskState.COMPLETED: 170,
        TaskState.CANCELED: 200,
        TaskState.FAILED: 210,
        TaskState.ROLLBACK_PENDING: 220,
        TaskState.ROLLED_BACK: 230,
        TaskState.EMERGENCY_STOPPED: 240,
    }
)

_E = TaskState.EMERGENCY_STOPPED
LEGAL_TRANSITIONS: MappingProxyType[TaskState, frozenset[TaskState]] = MappingProxyType(
    {
        TaskState.RECEIVED: frozenset(
            {TaskState.INSPECTED, TaskState.CANCELED, TaskState.FAILED, _E}
        ),
        TaskState.INSPECTED: frozenset(
            {TaskState.PLANNING, TaskState.CANCELED, TaskState.FAILED, _E}
        ),
        TaskState.PLANNING: frozenset(
            {TaskState.PLAN_PROPOSED, TaskState.CANCELED, TaskState.FAILED, _E}
        ),
        TaskState.PLAN_PROPOSED: frozenset(
            {TaskState.APPROVAL_PENDING, TaskState.CANCELED, TaskState.FAILED, _E}
        ),
        TaskState.APPROVAL_PENDING: frozenset(
            {TaskState.APPROVED, TaskState.CANCELED, TaskState.FAILED, _E}
        ),
        TaskState.APPROVED: frozenset(
            {TaskState.RUNNER_PREFLIGHT, TaskState.CANCELED, TaskState.FAILED, _E}
        ),
        TaskState.RUNNER_PREFLIGHT: frozenset(
            {
                TaskState.EXECUTING,
                TaskState.CANCELED,
                TaskState.FAILED,
                TaskState.ROLLBACK_PENDING,
                _E,
            }
        ),
        TaskState.EXECUTING: frozenset(
            {
                TaskState.TESTING,
                TaskState.CANCELED,
                TaskState.FAILED,
                TaskState.ROLLBACK_PENDING,
                _E,
            }
        ),
        TaskState.TESTING: frozenset(
            {
                TaskState.VERIFYING,
                TaskState.CANCELED,
                TaskState.FAILED,
                TaskState.ROLLBACK_PENDING,
                _E,
            }
        ),
        TaskState.VERIFYING: frozenset(
            {TaskState.EVIDENCE_SEALED, TaskState.FAILED, TaskState.ROLLBACK_PENDING, _E}
        ),
        TaskState.EVIDENCE_SEALED: frozenset(
            {TaskState.PATCH_READY, TaskState.FAILED, TaskState.ROLLBACK_PENDING, _E}
        ),
        TaskState.PATCH_READY: frozenset(
            {
                TaskState.APPLY_APPROVAL_PENDING,
                TaskState.CANCELED,
                TaskState.FAILED,
                TaskState.ROLLBACK_PENDING,
                _E,
            }
        ),
        TaskState.APPLY_APPROVAL_PENDING: frozenset(
            {
                TaskState.APPLIED,
                TaskState.CANCELED,
                TaskState.FAILED,
                TaskState.ROLLBACK_PENDING,
                _E,
            }
        ),
        TaskState.APPLIED: frozenset(
            {
                TaskState.COMMIT_APPROVAL_PENDING,
                TaskState.FAILED,
                TaskState.ROLLBACK_PENDING,
                _E,
            }
        ),
        TaskState.COMMIT_APPROVAL_PENDING: frozenset(
            {
                TaskState.LOCALLY_COMMITTED,
                TaskState.FAILED,
                TaskState.ROLLBACK_PENDING,
                _E,
            }
        ),
        TaskState.LOCALLY_COMMITTED: frozenset(
            {TaskState.COMPLETED, TaskState.FAILED, TaskState.ROLLBACK_PENDING, _E}
        ),
        TaskState.COMPLETED: frozenset(),
        TaskState.CANCELED: frozenset(),
        TaskState.FAILED: frozenset({TaskState.ROLLBACK_PENDING, _E}),
        TaskState.ROLLBACK_PENDING: frozenset({TaskState.ROLLED_BACK, _E}),
        TaskState.ROLLED_BACK: frozenset(),
        TaskState.EMERGENCY_STOPPED: frozenset(),
    }
)

TERMINAL_STATES = frozenset(
    {
        TaskState.COMPLETED,
        TaskState.CANCELED,
        TaskState.ROLLED_BACK,
        TaskState.EMERGENCY_STOPPED,
    }
)

RESTART_UNSAFE_STATES = frozenset(
    {
        TaskState.PLANNING,
        TaskState.APPROVAL_PENDING,
        TaskState.APPROVED,
        TaskState.RUNNER_PREFLIGHT,
        TaskState.EXECUTING,
        TaskState.TESTING,
        TaskState.VERIFYING,
        TaskState.APPLY_APPROVAL_PENDING,
        # These states prove that the owner tree has already changed. A replacement runtime
        # must not resume from the database record without independently reconciling Git state.
        TaskState.APPLIED,
        TaskState.COMMIT_APPROVAL_PENDING,
        TaskState.LOCALLY_COMMITTED,
        TaskState.ROLLBACK_PENDING,
    }
)


def assert_legal_transition(current: TaskState, target: TaskState) -> None:
    if target not in LEGAL_TRANSITIONS[current]:
        raise ValueError(f"illegal canonical transition: {current.value} -> {target.value}")
    if STATE_ORDER[target] <= STATE_ORDER[current]:
        raise ValueError("canonical lifecycle transitions must be monotonic")


class CapabilityName(StrEnum):
    MODEL = "model"
    RUNNER = "runner"
    OWNER_TREE_APPLY = "owner_tree_apply"
    LOCAL_COMMIT = "local_commit"
    EXTERNAL_CHECKPOINT = "external_checkpoint"
    BROWSER_EXECUTION = "browser_execution"


class CapabilityStatus(StrEnum):
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    IMPLEMENTED_UNVERIFIED = "IMPLEMENTED_UNVERIFIED"
    OFFLINE_TESTED = "OFFLINE_TESTED"
    QUALIFIED = "QUALIFIED"
    CONNECTED = "CONNECTED"
    OPERATIONAL = "OPERATIONAL"
    DEGRADED = "DEGRADED"
    DISABLED_BY_POLICY = "DISABLED_BY_POLICY"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class CapabilityGate(CanonicalSchema):
    schema_version: Literal["canonical-capability-gate-v1"] = "canonical-capability-gate-v1"
    name: CapabilityName
    version: StrictInt = Field(ge=0)
    status: CapabilityStatus
    feature_enabled: StrictBool
    installed: StrictBool
    configured: StrictBool
    connected: StrictBool
    healthy: StrictBool
    qualified: StrictBool
    authorized: StrictBool
    operational: StrictBool
    detail_code: StrictStr = Field(pattern=SAFE_ID)
    updated_at: datetime

    @model_validator(mode="after")
    def truthful_status(self) -> CapabilityGate:
        if self.updated_at.tzinfo is None or self.updated_at.utcoffset() is None:
            raise ValueError("capability timestamp must be timezone-aware")
        prerequisites = (
            self.feature_enabled,
            self.installed,
            self.configured,
            self.connected,
            self.healthy,
            self.qualified,
            self.authorized,
        )
        if self.operational != all(prerequisites):
            raise ValueError("capability operational status contradicts its gates")
        if self.operational != (self.status == CapabilityStatus.OPERATIONAL):
            raise ValueError("capability status contradicts its operational flag")
        return self


class CanonicalTask(CanonicalSchema):
    schema_version: Literal["canonical-task-v1"] = "canonical-task-v1"
    id: StrictStr = Field(pattern=SAFE_ID)
    task_digest: StrictStr = Field(pattern=SHA256)
    source_snapshot_digest: StrictStr = Field(pattern=SHA256)
    state: TaskState = TaskState.RECEIVED
    version: StrictInt = Field(default=0, ge=0)
    requires_change: StrictBool = True
    required_capabilities: tuple[CapabilityName, ...] = ()
    plan_digest: StrictStr | None = Field(default=None, pattern=SHA256)
    verification_decision_digest: StrictStr | None = Field(default=None, pattern=SHA256)
    checkpoint_receipt_digest: StrictStr | None = Field(default=None, pattern=SHA256)
    final_tree_manifest_digest: StrictStr | None = Field(default=None, pattern=SHA256)
    patch_manifest_digest: StrictStr | None = Field(default=None, pattern=SHA256)
    changed_path_count: StrictInt = Field(default=0, ge=0, le=100_000)
    failure_reason: StrictStr | None = Field(default=None, min_length=1, max_length=1_000)
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def lifecycle_bindings_are_consistent(self) -> CanonicalTask:
        if (
            self.created_at.tzinfo is None
            or self.created_at.utcoffset() is None
            or self.updated_at.tzinfo is None
            or self.updated_at.utcoffset() is None
        ):
            raise ValueError("task timestamps must be timezone-aware")
        if len(set(self.required_capabilities)) != len(self.required_capabilities):
            raise ValueError("required capabilities must be unique")
        plan_bound = {
            TaskState.PLAN_PROPOSED,
            TaskState.APPROVAL_PENDING,
            TaskState.APPROVED,
            TaskState.RUNNER_PREFLIGHT,
            TaskState.EXECUTING,
            TaskState.TESTING,
            TaskState.VERIFYING,
            TaskState.EVIDENCE_SEALED,
            TaskState.PATCH_READY,
            TaskState.APPLY_APPROVAL_PENDING,
            TaskState.APPLIED,
            TaskState.COMMIT_APPROVAL_PENDING,
            TaskState.LOCALLY_COMMITTED,
            TaskState.COMPLETED,
        }
        if self.state in plan_bound and self.plan_digest is None:
            raise ValueError("planned lifecycle state requires a plan digest")
        sealed = {
            TaskState.EVIDENCE_SEALED,
            TaskState.PATCH_READY,
            TaskState.APPLY_APPROVAL_PENDING,
            TaskState.APPLIED,
            TaskState.COMMIT_APPROVAL_PENDING,
            TaskState.LOCALLY_COMMITTED,
            TaskState.COMPLETED,
        }
        if self.state in sealed and (
            self.verification_decision_digest is None or self.checkpoint_receipt_digest is None
        ):
            raise ValueError(
                "sealed lifecycle state requires independent verification and checkpoint receipt"
            )
        delivery = {
            TaskState.PATCH_READY,
            TaskState.APPLY_APPROVAL_PENDING,
            TaskState.APPLIED,
            TaskState.COMMIT_APPROVAL_PENDING,
            TaskState.LOCALLY_COMMITTED,
            TaskState.COMPLETED,
        }
        if self.state in delivery and (
            self.final_tree_manifest_digest is None or self.patch_manifest_digest is None
        ):
            raise ValueError("delivery lifecycle state requires final-tree and patch manifests")
        if self.state in delivery and self.requires_change and self.changed_path_count < 1:
            raise ValueError("change-required task cannot enter delivery without a verified change")
        return self


class ApprovalPurpose(StrEnum):
    EXECUTION = "execution"
    APPLY_PATCH = "apply_patch"
    LOCAL_COMMIT = "local_commit"
    ROLLBACK = "rollback"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    CONSUMED = "consumed"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


class CanonicalApproval(CanonicalSchema):
    schema_version: Literal["canonical-approval-v1"] = "canonical-approval-v1"
    id: StrictStr = Field(pattern=SAFE_ID)
    task_id: StrictStr = Field(pattern=SAFE_ID)
    task_digest: StrictStr = Field(pattern=SHA256)
    task_version: StrictInt = Field(ge=1)
    purpose: ApprovalPurpose
    operation_digest: StrictStr = Field(pattern=SHA256)
    policy_digest: StrictStr = Field(pattern=SHA256)
    capability_snapshot_digest: StrictStr = Field(pattern=SHA256)
    nonce: StrictStr = Field(pattern=SAFE_ID)
    approval_digest: StrictStr = Field(pattern=SHA256)
    status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: StrictStr | None = Field(default=None, pattern=SAFE_ID)
    decision_proof_digest: StrictStr | None = Field(default=None, pattern=SHA256)
    created_at: datetime
    expires_at: datetime
    approved_at: datetime | None = None
    consumed_at: datetime | None = None

    @property
    def immutable_payload(self) -> dict[str, object]:
        return self.model_dump(
            mode="python",
            exclude={
                "approval_digest",
                "status",
                "approved_by",
                "decision_proof_digest",
                "approved_at",
                "consumed_at",
            },
        )

    @model_validator(mode="after")
    def approval_is_consistent(self) -> CanonicalApproval:
        timestamps = (self.created_at, self.expires_at, self.approved_at, self.consumed_at)
        if any(
            value is not None and (value.tzinfo is None or value.utcoffset() is None)
            for value in timestamps
        ):
            raise ValueError("approval timestamps must be timezone-aware")
        lifetime = (self.expires_at - self.created_at).total_seconds()
        if lifetime <= 0 or lifetime > 900:
            raise ValueError("approval lifetime is invalid")
        if not secrets.compare_digest(self.approval_digest, content_digest(self.immutable_payload)):
            raise ValueError("approval digest mismatch")
        if self.status == ApprovalStatus.PENDING and any(
            value is not None
            for value in (self.approved_by, self.decision_proof_digest, self.approved_at)
        ):
            raise ValueError("pending approval cannot contain a decision")
        if self.status in {ApprovalStatus.APPROVED, ApprovalStatus.CONSUMED} and any(
            value is None
            for value in (self.approved_by, self.decision_proof_digest, self.approved_at)
        ):
            raise ValueError("approved authorization requires authenticated owner decision")
        if self.status == ApprovalStatus.CONSUMED and self.consumed_at is None:
            raise ValueError("consumed approval requires a consumption timestamp")
        if self.status != ApprovalStatus.CONSUMED and self.consumed_at is not None:
            raise ValueError("only consumed approvals may record consumption time")
        return self


class CanonicalEvidence(CanonicalSchema):
    schema_version: Literal["canonical-evidence-v1"] = "canonical-evidence-v1"
    id: StrictStr = Field(pattern=SAFE_ID)
    task_id: StrictStr = Field(pattern=SAFE_ID)
    sequence: StrictInt = Field(ge=1)
    event_type: EventType
    payload: dict[StrictStr, object]
    previous_hash: StrictStr | None = Field(default=None, pattern=SHA256)
    record_hash: StrictStr = Field(pattern=SHA256)
    created_at: datetime


class DispatchLeaseStatus(StrEnum):
    ACTIVE = "active"
    COMPLETED = "completed"
    CANCELED = "canceled"
    EXPIRED = "expired"


class DispatchLease(CanonicalSchema):
    schema_version: Literal["canonical-dispatch-lease-v1"] = "canonical-dispatch-lease-v1"
    id: StrictStr = Field(pattern=SAFE_ID)
    task_id: StrictStr = Field(pattern=SAFE_ID)
    approval_id: StrictStr = Field(pattern=SAFE_ID)
    request_digest: StrictStr = Field(pattern=SHA256)
    token_digest: StrictStr = Field(pattern=SHA256)
    runtime_id: StrictStr = Field(pattern=SAFE_ID)
    generation: StrictInt = Field(ge=0)
    status: DispatchLeaseStatus
    created_at: datetime
    expires_at: datetime
    completed_at: datetime | None = None

    @model_validator(mode="after")
    def lease_is_consistent(self) -> DispatchLease:
        timestamps = (self.created_at, self.expires_at, self.completed_at)
        if any(
            value is not None and (value.tzinfo is None or value.utcoffset() is None)
            for value in timestamps
        ):
            raise ValueError("dispatch lease timestamps must be timezone-aware")
        lifetime = (self.expires_at - self.created_at).total_seconds()
        if lifetime <= 0 or lifetime > 600:
            raise ValueError("dispatch lease lifetime is invalid")
        if self.status == DispatchLeaseStatus.ACTIVE and self.completed_at is not None:
            raise ValueError("active dispatch lease cannot be completed")
        if self.status != DispatchLeaseStatus.ACTIVE and self.completed_at is None:
            raise ValueError("closed dispatch lease requires a completion timestamp")
        return self


class EmergencyControl(CanonicalSchema):
    schema_version: Literal["canonical-emergency-control-v1"] = "canonical-emergency-control-v1"
    emergency_stopped: StrictBool
    generation: StrictInt = Field(ge=0)
    active_runtime_id: StrictStr = Field(pattern=SAFE_ID)
    reason_code: StrictStr = Field(pattern=SAFE_ID)
    updated_at: datetime
