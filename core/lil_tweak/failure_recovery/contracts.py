"""Typed, fail-closed contracts for engineering failure recovery."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping


SCHEMA_VERSION = "failure-recovery-v1"
HANDOFF_SCHEMA_VERSION = "failure-recovery-handoff-v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")


class FailureClass(StrEnum):
    INPUT_CONTRACT = "input_contract"
    PLANNING = "planning"
    REPOSITORY_CONTEXT = "repository_context"
    EXECUTION = "execution"
    VERIFICATION = "verification"
    INFRASTRUCTURE_PROVIDER = "infrastructure_provider"
    RECOVERY = "recovery"
    UNKNOWN = "unknown"


class FailureCode(StrEnum):
    INVALID_REQUEST = "invalid_request"
    MISSING_CONTRACT = "missing_contract"
    CONFLICTING_CONTRACT = "conflicting_contract"
    STALE_CONTRACT = "stale_contract"
    MISSING_APPROVAL = "missing_approval"
    STALE_APPROVAL = "stale_approval"
    WRONG_DIGEST_BINDING = "wrong_digest_binding"

    PLAN_INCOMPLETE = "plan_incomplete"
    PLAN_INVALID = "plan_invalid"
    PLAN_CONTRACT_VIOLATION = "plan_contract_violation"
    PLAN_SCOPE_EXCESSIVE = "plan_scope_excessive"
    PLAN_CRITIC_FAILURE = "plan_critic_failure"

    STALE_SOURCE = "stale_source"
    SOURCE_CHANGED = "source_changed"
    REPOSITORY_UNAVAILABLE = "repository_unavailable"
    MAPPER_INCOMPLETE = "mapper_incomplete"
    DEPENDENCY_UNCERTAIN = "dependency_uncertain"
    REPOSITORY_INTEGRITY_FAILURE = "repository_integrity_failure"

    COMMAND_FAILED = "command_failed"
    TIMEOUT = "timeout"
    PROCESS_CRASH = "process_crash"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    SANDBOX_FAILURE = "sandbox_failure"
    RUNNER_UNAVAILABLE = "runner_unavailable"
    RUNNER_UNQUALIFIED = "runner_unqualified"
    LEASE_REJECTED = "lease_rejected"
    LEASE_EXPIRED = "lease_expired"
    LEASE_REPLAYED = "lease_replayed"
    CANCELLATION = "cancellation"
    CLEANUP_FAILURE = "cleanup_failure"

    TEST_FAILURE = "test_failure"
    LINT_FAILURE = "lint_failure"
    FORMAT_FAILURE = "format_failure"
    TYPECHECK_FAILURE = "typecheck_failure"
    BUILD_FAILURE = "build_failure"
    SECURITY_CHECK_FAILURE = "security_check_failure"
    DETERMINISTIC_VERIFICATION_FAILURE = "deterministic_verification_failure"
    INDEPENDENT_VERIFICATION_FAILURE = "independent_verification_failure"
    FALSE_COMPLETION_CLAIM = "false_completion_claim"

    PROVIDER_UNHEALTHY = "provider_unhealthy"
    PROVIDER_TIMEOUT = "provider_timeout"
    PROVIDER_CAPACITY_EXHAUSTED = "provider_capacity_exhausted"
    PROVIDER_COST_GATE = "provider_cost_gate"
    PROVIDER_AUTH_FAILURE = "provider_auth_failure"
    CONTROL_PLANE_FAILURE = "control_plane_failure"

    ROLLBACK_FAILED = "rollback_failed"
    REPAIR_REPEATED = "repair_repeated"
    REPAIR_BUDGET_EXHAUSTED = "repair_budget_exhausted"
    RECOVERY_EVIDENCE_INVALID = "recovery_evidence_invalid"
    RECOVERY_STRATEGY_INVALID = "recovery_strategy_invalid"
    RECOVERY_STRATEGY_NO_PROGRESS = "recovery_strategy_no_progress"

    UNKNOWN_FAILURE = "unknown_failure"


class RecoveryDisposition(StrEnum):
    RETRYABLE = "retryable"
    REPLAN_REQUIRED = "replan_required"
    ROLLBACK_REQUIRED = "rollback_required"
    RESOURCE_REROUTE_ALLOWED = "resource_reroute_allowed"
    APPROVAL_REQUIRED = "approval_required"
    HUMAN_ESCALATION_REQUIRED = "human_escalation_required"
    NON_RECOVERABLE = "non_recoverable"


class RecoveryAction(StrEnum):
    RETRY_STEP = "retry_step"
    REPLAN = "replan"
    REPAIR_CANDIDATE = "repair_candidate"
    ROLLBACK = "rollback"
    REROUTE_RESOURCE = "reroute_resource"
    REQUALIFY_RESOURCE = "requalify_resource"
    ESCALATE = "escalate"
    BLOCK = "block"


class RecoveryOutcomeStatus(StrEnum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"


def _require_id(value: str, code: str) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(code)


def _require_digest(value: str | None, code: str) -> None:
    if value is not None and not _SHA256.fullmatch(value):
        raise ValueError(code)


def _freeze(value: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if not value:
        return MappingProxyType({})
    result: dict[str, Any] = {}
    for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
        name = str(key)
        if isinstance(item, Mapping):
            result[name] = _freeze(item)
        elif isinstance(item, (list, tuple, set, frozenset)):
            result[name] = tuple(item)
        elif isinstance(item, (str, int, float, bool)) or item is None:
            result[name] = item
        else:
            result[name] = str(item)
    return MappingProxyType(result)


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    evidence_id: str
    kind: str
    sha256: str

    def __post_init__(self) -> None:
        _require_id(self.evidence_id, "evidence_id_invalid")
        _require_id(self.kind, "evidence_kind_invalid")
        _require_digest(self.sha256, "evidence_digest_invalid")


@dataclass(frozen=True, slots=True)
class RecoveryContext:
    owner_id: str
    task_id: str
    dag_run_id: str
    node_id: str
    source_revision: str | None
    attempt: int
    plan_digest: str | None = None
    candidate_digest: str | None = None
    contract_digest: str | None = None
    execution_id: str | None = None
    lease_id: str | None = None
    resource_id: str | None = None
    approval_present: bool = True
    new_authority_required: bool = False

    def __post_init__(self) -> None:
        for value, code in (
            (self.owner_id, "owner_id_invalid"),
            (self.task_id, "task_id_invalid"),
            (self.dag_run_id, "dag_run_id_invalid"),
            (self.node_id, "node_id_invalid"),
        ):
            _require_id(value, code)
        if self.source_revision is not None and not _REVISION.fullmatch(
            self.source_revision
        ):
            raise ValueError("source_revision_invalid")
        if not isinstance(self.attempt, int) or isinstance(self.attempt, bool) or self.attempt < 1:
            raise ValueError("attempt_must_be_positive")
        _require_digest(self.plan_digest, "plan_digest_invalid")
        _require_digest(self.candidate_digest, "candidate_digest_invalid")
        _require_digest(self.contract_digest, "contract_digest_invalid")
        for value, code in (
            (self.execution_id, "execution_id_invalid"),
            (self.lease_id, "lease_id_invalid"),
            (self.resource_id, "resource_id_invalid"),
        ):
            if value is not None:
                _require_id(value, code)


@dataclass(frozen=True, slots=True)
class FailureSignal:
    code: FailureCode | str
    exception_type: str = ""
    message: str = ""
    failed_checks: tuple[str, ...] = ()
    evidence: tuple[EvidenceRef, ...] = ()
    transient: bool = False
    partial_mutation: bool = False
    integrity_failure: bool = False
    security_sensitive: bool = False
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        raw = self.code.value if isinstance(self.code, FailureCode) else self.code
        if not isinstance(raw, str) or not raw or len(raw) > 128:
            raise ValueError("failure_code_invalid")
        try:
            normalized: FailureCode | str = FailureCode(raw)
        except ValueError:
            normalized = raw
        object.__setattr__(self, "code", normalized)
        object.__setattr__(self, "failed_checks", tuple(sorted(set(self.failed_checks))))
        object.__setattr__(
            self,
            "evidence",
            tuple(sorted(set(self.evidence), key=lambda item: (item.kind, item.evidence_id))),
        )
        object.__setattr__(self, "details", _freeze(self.details))


@dataclass(frozen=True, slots=True)
class RecoveryBudgets:
    max_node_retries: int = 2
    max_fingerprint_retries: int = 1
    max_full_replans: int = 2
    max_candidate_repairs: int = 2
    max_resource_reroutes: int = 1
    max_rollbacks: int = 1

    _HARD_MAXIMUMS = (3, 2, 2, 3, 1, 1)

    def __post_init__(self) -> None:
        values = (
            self.max_node_retries,
            self.max_fingerprint_retries,
            self.max_full_replans,
            self.max_candidate_repairs,
            self.max_resource_reroutes,
            self.max_rollbacks,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values):
            raise ValueError("recovery_budget_invalid")
        if any(value > maximum for value, maximum in zip(values, self._HARD_MAXIMUMS, strict=True)):
            raise ValueError("recovery_budget_exceeds_hard_limit")

    def limit_for(self, action: RecoveryAction) -> int:
        return {
            RecoveryAction.RETRY_STEP: self.max_node_retries,
            RecoveryAction.REPLAN: self.max_full_replans,
            RecoveryAction.REPAIR_CANDIDATE: self.max_candidate_repairs,
            RecoveryAction.REROUTE_RESOURCE: self.max_resource_reroutes,
            RecoveryAction.ROLLBACK: self.max_rollbacks,
            RecoveryAction.REQUALIFY_RESOURCE: self.max_resource_reroutes,
            RecoveryAction.ESCALATE: 0,
            RecoveryAction.BLOCK: 0,
        }[action]


@dataclass(frozen=True, slots=True)
class ResourceRecoveryDecision:
    resource_id: str
    qualified: bool
    healthy: bool
    authorized: bool
    cost_approved: bool
    fresh_lease: bool
    source_bound: bool

    def __post_init__(self) -> None:
        _require_id(self.resource_id, "resource_id_invalid")


@dataclass(frozen=True, slots=True)
class ClassifiedFailure:
    failure_class: FailureClass
    code: FailureCode
    disposition: RecoveryDisposition
    preferred_action: RecoveryAction
    reason_codes: tuple[str, ...]
    automatic_recovery_prohibited: bool = False
    requires_reauthorization: bool = False
    requires_fresh_lease: bool = False


@dataclass(frozen=True, slots=True)
class RecoveryDecision:
    schema_version: str
    owner_id: str
    task_id: str
    dag_run_id: str
    node_id: str
    source_revision: str | None
    plan_digest: str | None
    candidate_digest: str | None
    contract_digest: str | None
    execution_id: str | None
    lease_id: str | None
    resource_id: str | None
    attempt: int
    failure_class: FailureClass
    failure_code: FailureCode
    fingerprint: str
    disposition: RecoveryDisposition
    action: RecoveryAction
    allowed: bool
    requires_reauthorization: bool
    requires_fresh_lease: bool
    reason_codes: tuple[str, ...]
    decision_digest: str


@dataclass(frozen=True, slots=True)
class RecoveryOutcome:
    status: RecoveryOutcomeStatus
    progress: bool
    remaining_failed_checks: tuple[str, ...] = ()
    resulting_plan_digest: str | None = None
    resulting_candidate_digest: str | None = None
    resulting_resource_id: str | None = None
    independently_verified: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "remaining_failed_checks",
            tuple(sorted(set(self.remaining_failed_checks))),
        )
        _require_digest(self.resulting_plan_digest, "resulting_plan_digest_invalid")
        _require_digest(self.resulting_candidate_digest, "resulting_candidate_digest_invalid")
        if self.resulting_resource_id is not None:
            _require_id(self.resulting_resource_id, "resulting_resource_id_invalid")
        if self.status is RecoveryOutcomeStatus.SUCCEEDED and not self.independently_verified:
            raise ValueError("verified_outcome_required")


@dataclass(frozen=True, slots=True)
class RecoveryHistoryEntry:
    owner_id: str
    sequence: int
    task_id: str
    fingerprint: str
    action: RecoveryAction
    decision_digest: str
    outcome_status: RecoveryOutcomeStatus | None = None
    progress: bool | None = None
    remaining_failed_checks: tuple[str, ...] = ()
    resulting_plan_digest: str | None = None
    resulting_candidate_digest: str | None = None
    resulting_resource_id: str | None = None
