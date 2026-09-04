"""Governed vocabulary and immutable records for the Engineering Contract Registry."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Self


_ID_MAX_LENGTH = 128
_TEXT_MAX_LENGTH = 256
_LOCATOR_MAX_LENGTH = 2048
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_REVISION_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SOURCE_CODE_ACTIONS = frozenset(
    {
        "CODE_GENERATION",
        "PATCH_PREPARATION",
        "PATCH_APPLICATION",
    }
)


class RegistryValidationError(ValueError):
    """Raised when a governed registry record violates its closed contract."""


class ExecutionMode(StrEnum):
    BLOCKED = "BLOCKED"
    EXPLAIN_ONLY = "EXPLAIN_ONLY"
    DRAFT_CODE = "DRAFT_CODE"
    PREPARE_PATCH = "PREPARE_PATCH"
    APPLY_SANDBOX = "APPLY_SANDBOX"
    APPLY_NON_PRODUCTION = "APPLY_NON_PRODUCTION"


class Environment(StrEnum):
    DOCUMENT_ONLY = "DOCUMENT_ONLY"
    REPOSITORY = "REPOSITORY"
    SANDBOX = "SANDBOX"
    NON_PRODUCTION = "NON_PRODUCTION"
    PRODUCTION = "PRODUCTION"


class ActionClass(StrEnum):
    ANALYSIS = "ANALYSIS"
    CODE_GENERATION = "CODE_GENERATION"
    PATCH_PREPARATION = "PATCH_PREPARATION"
    PATCH_APPLICATION = "PATCH_APPLICATION"
    APPROVAL_BINDING = "APPROVAL_BINDING"
    EVIDENCE_BINDING = "EVIDENCE_BINDING"


class OperationIntent(StrEnum):
    READ = "READ"
    PROPOSE = "PROPOSE"
    MODIFY = "MODIFY"
    APPLY = "APPLY"
    PUBLISH = "PUBLISH"
    DEPLOY = "DEPLOY"


class ReasonCode(StrEnum):
    NO_MATCHING_CONTRACT = "no_matching_contract"
    INVALID_REQUEST = "invalid_request"
    AMBIGUOUS_REQUEST = "ambiguous_request"
    INACTIVE_PRINCIPAL = "inactive_principal"
    UNKNOWN_ASSET = "unknown_asset"
    CONTRACT_NOT_EFFECTIVE = "contract_not_effective"
    CONTRACT_EXPIRED = "contract_expired"
    CONFLICTING_ACTIVE_CONTRACTS = "conflicting_active_contracts"
    MISSING_REQUIRED_APPROVAL = "missing_required_approval"
    STALE_APPROVAL = "stale_approval"
    REVOKED_APPROVAL = "revoked_approval"
    WRONG_DIGEST_BINDING = "wrong_digest_binding"
    MISSING_REQUIRED_EVIDENCE = "missing_required_evidence"
    PROHIBITED_TARGET = "prohibited_target"
    PROHIBITED_ACTION = "prohibited_action"
    AUDIT_PERSIST_FAILED = "audit_persist_failed"
    INTEGRITY_CHECK_FAILED = "integrity_check_failed"


class PrincipalStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class AssetType(StrEnum):
    REPOSITORY = "REPOSITORY"
    SERVICE = "SERVICE"
    ENVIRONMENT = "ENVIRONMENT"
    PIPELINE = "PIPELINE"
    DATABASE = "DATABASE"
    DOCUMENT = "DOCUMENT"


def _require_text(value: object, name: str, *, max_length: int = _TEXT_MAX_LENGTH) -> str:
    if not isinstance(value, str):
        raise RegistryValidationError(f"{name} must be text")
    if not value or value.strip() != value or not value.strip():
        raise RegistryValidationError(f"{name} must be non-empty and trimmed")
    if len(value) > max_length:
        raise RegistryValidationError(f"{name} exceeds maximum length")
    return value


def _require_id(value: object, name: str) -> str:
    return _require_text(value, name, max_length=_ID_MAX_LENGTH)


def _require_enum(value: object, expected: type[StrEnum], name: str) -> None:
    if not isinstance(value, expected):
        raise RegistryValidationError(f"{name} must be {expected.__name__}")


def _require_bool(value: object, name: str) -> None:
    if not isinstance(value, bool):
        raise RegistryValidationError(f"{name} must be bool")


def _require_positive_int(value: object, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RegistryValidationError(f"{name} must be a positive integer")


def _require_utc(value: object, name: str) -> datetime:
    if not isinstance(value, datetime):
        raise RegistryValidationError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise RegistryValidationError(f"{name} must be timezone-aware UTC")
    if value.utcoffset() != timedelta(0):
        raise RegistryValidationError(f"{name} must use UTC")
    return value


def _require_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise RegistryValidationError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _require_optional_digest(value: object, name: str) -> None:
    if value is not None:
        _require_digest(value, name)


def _require_source_revision(value: object, name: str = "source_revision") -> str:
    if not isinstance(value, str) or _SOURCE_REVISION_RE.fullmatch(value) is None:
        raise RegistryValidationError(
            f"{name} must be an exact lowercase 40- or 64-character commit revision"
        )
    return value


def _require_id_tuple(
    values: object,
    name: str,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise RegistryValidationError(f"{name} must be a tuple")
    if not allow_empty and not values:
        raise RegistryValidationError(f"{name} must not be empty")
    for index, value in enumerate(values):
        _require_id(value, f"{name}[{index}]")
    if len(set(values)) != len(values):
        raise RegistryValidationError(f"{name} must not contain duplicates")
    return values


def _require_text_tuple(
    values: object,
    name: str,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise RegistryValidationError(f"{name} must be a tuple")
    if not allow_empty and not values:
        raise RegistryValidationError(f"{name} must not be empty")
    for index, value in enumerate(values):
        _require_text(value, f"{name}[{index}]")
    if len(set(values)) != len(values):
        raise RegistryValidationError(f"{name} must not contain duplicates")
    return values


def _require_enum_tuple(
    values: object,
    expected: type[StrEnum],
    name: str,
) -> tuple[StrEnum, ...]:
    if not isinstance(values, tuple) or not values:
        raise RegistryValidationError(f"{name} must be a non-empty tuple")
    for index, value in enumerate(values):
        _require_enum(value, expected, f"{name}[{index}]")
    if len(set(values)) != len(values):
        raise RegistryValidationError(f"{name} must not contain duplicates")
    return values


def _require_interval(effective_at: datetime, expires_at: datetime | None) -> None:
    _require_utc(effective_at, "effective_at")
    if expires_at is not None:
        _require_utc(expires_at, "expires_at")
        if expires_at <= effective_at:
            raise RegistryValidationError("expires_at must be later than effective_at")


@dataclass(frozen=True, slots=True)
class Principal:
    owner_id: str
    principal_id: str
    status: PrincipalStatus

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> Self:
        _require_id(self.owner_id, "owner_id")
        _require_id(self.principal_id, "principal_id")
        _require_enum(self.status, PrincipalStatus, "status")
        return self


@dataclass(frozen=True, slots=True)
class Asset:
    owner_id: str
    asset_id: str
    asset_type: AssetType
    canonical_locator: str
    active: bool = True
    prohibited: bool = False

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> Self:
        _require_id(self.owner_id, "owner_id")
        _require_id(self.asset_id, "asset_id")
        _require_enum(self.asset_type, AssetType, "asset_type")
        _require_text(
            self.canonical_locator,
            "canonical_locator",
            max_length=_LOCATOR_MAX_LENGTH,
        )
        _require_bool(self.active, "active")
        _require_bool(self.prohibited, "prohibited")
        return self


@dataclass(frozen=True, slots=True)
class ContractVersion:
    owner_id: str
    contract_id: str
    version: int
    requester_ids: tuple[str, ...]
    agent_ids: tuple[str, ...]
    asset_ids: tuple[str, ...]
    action_classes: tuple[ActionClass, ...]
    operation_intents: tuple[OperationIntent, ...]
    environments: tuple[Environment, ...]
    mode: ExecutionMode
    effective_at: datetime
    expires_at: datetime | None = None
    prohibited: bool = False
    required_approval_ids: tuple[str, ...] = ()
    required_evidence_types: tuple[str, ...] = ()
    supersedes_digest: str | None = None

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> Self:
        _require_id(self.owner_id, "owner_id")
        _require_id(self.contract_id, "contract_id")
        _require_positive_int(self.version, "version")
        _require_id_tuple(self.requester_ids, "requester_ids")
        _require_id_tuple(self.agent_ids, "agent_ids")
        _require_id_tuple(self.asset_ids, "asset_ids")
        _require_enum_tuple(self.action_classes, ActionClass, "action_classes")
        _require_enum_tuple(self.operation_intents, OperationIntent, "operation_intents")
        _require_enum_tuple(self.environments, Environment, "environments")
        _require_enum(self.mode, ExecutionMode, "mode")
        _require_interval(self.effective_at, self.expires_at)
        _require_bool(self.prohibited, "prohibited")
        _require_id_tuple(
            self.required_approval_ids,
            "required_approval_ids",
            allow_empty=True,
        )
        _require_text_tuple(
            self.required_evidence_types,
            "required_evidence_types",
            allow_empty=True,
        )
        _require_optional_digest(self.supersedes_digest, "supersedes_digest")
        return self


@dataclass(frozen=True, slots=True)
class ContractVersionRef:
    contract_id: str
    version: int
    digest: str

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> Self:
        _require_id(self.contract_id, "contract_id")
        _require_positive_int(self.version, "version")
        _require_digest(self.digest, "digest")
        return self


@dataclass(frozen=True, slots=True)
class DecisionRequest:
    owner_id: str
    requester_id: str
    agent_id: str
    asset_id: str
    action_class: ActionClass
    operation_intent: OperationIntent
    environment: Environment
    source_revision: str | None = None

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> Self:
        _require_id(self.owner_id, "owner_id")
        _require_id(self.requester_id, "requester_id")
        _require_id(self.agent_id, "agent_id")
        _require_id(self.asset_id, "asset_id")
        _require_enum(self.action_class, ActionClass, "action_class")
        _require_enum(self.operation_intent, OperationIntent, "operation_intent")
        _require_enum(self.environment, Environment, "environment")
        source_code_work = (
            isinstance(self.action_class, ActionClass)
            and self.action_class.value in _SOURCE_CODE_ACTIONS
        )
        needs_revision = self.environment is Environment.REPOSITORY or source_code_work
        if needs_revision:
            _require_source_revision(self.source_revision)
        elif self.source_revision is not None:
            _require_source_revision(self.source_revision)
        return self


@dataclass(frozen=True, slots=True)
class Decision:
    decision_id: str
    owner_id: str
    request: DecisionRequest
    contract_versions: tuple[ContractVersionRef, ...]
    contract_digests: tuple[str, ...]
    recommended_mode: ExecutionMode
    reason_codes: tuple[ReasonCode, ...]
    required_approval_ids: tuple[str, ...]
    required_evidence_types: tuple[str, ...]
    decision_digest: str
    created_at: datetime
    observed_mode: ExecutionMode | None = None
    enforced: bool = False

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> Self:
        _require_id(self.decision_id, "decision_id")
        _require_id(self.owner_id, "owner_id")
        if not isinstance(self.request, DecisionRequest):
            raise RegistryValidationError("request must be DecisionRequest")
        self.request.validate()
        if self.request.owner_id != self.owner_id:
            raise RegistryValidationError("decision owner_id must match request owner_id")
        if not isinstance(self.contract_versions, tuple):
            raise RegistryValidationError("contract_versions must be a tuple")
        for index, reference in enumerate(self.contract_versions):
            if not isinstance(reference, ContractVersionRef):
                raise RegistryValidationError(
                    f"contract_versions[{index}] must be ContractVersionRef"
                )
            reference.validate()
        identities = tuple(
            (reference.contract_id, reference.version)
            for reference in self.contract_versions
        )
        if len(set(identities)) != len(identities):
            raise RegistryValidationError("contract_versions must not contain duplicates")
        deterministic_order = tuple(
            sorted(
                self.contract_versions,
                key=lambda reference: (
                    reference.contract_id,
                    reference.version,
                    reference.digest,
                ),
            )
        )
        if self.contract_versions != deterministic_order:
            raise RegistryValidationError("contract_versions must use deterministic order")
        if not isinstance(self.contract_digests, tuple):
            raise RegistryValidationError("contract_digests must be a tuple")
        for index, digest in enumerate(self.contract_digests):
            _require_digest(digest, f"contract_digests[{index}]")
        if len(set(self.contract_digests)) != len(self.contract_digests):
            raise RegistryValidationError("contract_digests must not contain duplicates")
        reference_digests = tuple(
            reference.digest for reference in self.contract_versions
        )
        if self.contract_digests != reference_digests:
            raise RegistryValidationError(
                "contract_versions and contract_digests must identify the same ordered digests"
            )
        _require_enum(self.recommended_mode, ExecutionMode, "recommended_mode")
        if not isinstance(self.reason_codes, tuple):
            raise RegistryValidationError("reason_codes must be a tuple")
        for index, reason in enumerate(self.reason_codes):
            _require_enum(reason, ReasonCode, f"reason_codes[{index}]")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise RegistryValidationError("reason_codes must not contain duplicates")
        _require_id_tuple(
            self.required_approval_ids,
            "required_approval_ids",
            allow_empty=True,
        )
        _require_text_tuple(
            self.required_evidence_types,
            "required_evidence_types",
            allow_empty=True,
        )
        _require_digest(self.decision_digest, "decision_digest")
        _require_utc(self.created_at, "created_at")
        if self.observed_mode is not None:
            _require_enum(self.observed_mode, ExecutionMode, "observed_mode")
        _require_bool(self.enforced, "enforced")
        return self


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    owner_id: str
    approval_id: str
    approver_id: str
    target_digest: str
    requester_id: str
    agent_id: str
    asset_id: str
    action_class: ActionClass
    operation_intent: OperationIntent
    environment: Environment
    issued_at: datetime
    expires_at: datetime
    authenticated: bool
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> Self:
        _require_id(self.owner_id, "owner_id")
        _require_id(self.approval_id, "approval_id")
        _require_id(self.approver_id, "approver_id")
        _require_digest(self.target_digest, "target_digest")
        _require_id(self.requester_id, "requester_id")
        _require_id(self.agent_id, "agent_id")
        _require_id(self.asset_id, "asset_id")
        _require_enum(self.action_class, ActionClass, "action_class")
        _require_enum(self.operation_intent, OperationIntent, "operation_intent")
        _require_enum(self.environment, Environment, "environment")
        _require_utc(self.issued_at, "issued_at")
        _require_utc(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise RegistryValidationError("expires_at must be later than issued_at")
        _require_bool(self.authenticated, "authenticated")
        if self.revoked_at is not None:
            _require_utc(self.revoked_at, "revoked_at")
        return self


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    owner_id: str
    evidence_id: str
    target_digest: str
    digest_algorithm: str
    content_digest: str
    locator_class: str
    locator: str
    evidence_type: str
    source_system: str
    created_at: datetime
    source_revision: str | None
    asserted_safe: bool

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> Self:
        _require_id(self.owner_id, "owner_id")
        _require_id(self.evidence_id, "evidence_id")
        _require_digest(self.target_digest, "target_digest")
        _require_text(self.digest_algorithm, "digest_algorithm", max_length=32)
        _require_digest(self.content_digest, "content_digest")
        _require_text(self.locator_class, "locator_class", max_length=64)
        _require_text(self.locator, "locator", max_length=_LOCATOR_MAX_LENGTH)
        _require_text(self.evidence_type, "evidence_type", max_length=128)
        _require_text(self.source_system, "source_system", max_length=128)
        _require_utc(self.created_at, "created_at")
        if self.source_revision is not None:
            _require_source_revision(self.source_revision)
        _require_bool(self.asserted_safe, "asserted_safe")
        return self


@dataclass(frozen=True, slots=True)
class ExceptionVersion:
    owner_id: str
    exception_id: str
    version: int
    target_digest: str
    requester_id: str
    agent_id: str
    asset_id: str
    action_class: ActionClass
    operation_intent: OperationIntent
    environment: Environment
    compensating_controls: tuple[str, ...]
    approval_ids: tuple[str, ...]
    effective_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> Self:
        _require_id(self.owner_id, "owner_id")
        _require_id(self.exception_id, "exception_id")
        _require_positive_int(self.version, "version")
        _require_digest(self.target_digest, "target_digest")
        _require_id(self.requester_id, "requester_id")
        _require_id(self.agent_id, "agent_id")
        _require_id(self.asset_id, "asset_id")
        _require_enum(self.action_class, ActionClass, "action_class")
        _require_enum(self.operation_intent, OperationIntent, "operation_intent")
        _require_enum(self.environment, Environment, "environment")
        _require_text_tuple(self.compensating_controls, "compensating_controls")
        _require_id_tuple(self.approval_ids, "approval_ids")
        _require_interval(self.effective_at, self.expires_at)
        return self


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_id: str
    owner_id: str
    sequence: int
    subject_type: str
    subject_id: str
    event_type: str
    payload_digest: str
    previous_hash: str | None
    event_hash: str
    actor_id: str
    recorded_at: datetime

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> Self:
        _require_id(self.event_id, "event_id")
        _require_id(self.owner_id, "owner_id")
        _require_positive_int(self.sequence, "sequence")
        _require_text(self.subject_type, "subject_type", max_length=64)
        _require_id(self.subject_id, "subject_id")
        _require_text(self.event_type, "event_type", max_length=128)
        _require_digest(self.payload_digest, "payload_digest")
        _require_optional_digest(self.previous_hash, "previous_hash")
        _require_digest(self.event_hash, "event_hash")
        _require_id(self.actor_id, "actor_id")
        _require_utc(self.recorded_at, "recorded_at")
        return self
