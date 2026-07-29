from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PREVIEW = "preview"
    STAGING = "staging"
    PRODUCTION = "production"


class JobStatus(StrEnum):
    RECEIVED = "RECEIVED"
    INSPECTING = "INSPECTING"
    ANALYZED = "ANALYZED"
    PLAN_READY = "PLAN_READY"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    TESTING = "TESTING"
    VERIFIED = "VERIFIED"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    CANCELED = "CANCELED"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CONSUMED = "consumed"
    INVALIDATED = "invalidated"


class Role(StrEnum):
    OWNER = "owner"
    ADMINISTRATOR = "administrator"
    DEVELOPER = "developer"
    REVIEWER = "reviewer"
    VIEWER = "viewer"
    SERVICE_CLIENT = "service_client"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ArtifactKind(StrEnum):
    STAGED_PATCH = "staged_patch"
    UNSTAGED_PATCH = "unstaged_patch"
    UNTRACKED_ARCHIVE = "untracked_archive"
    RECOVERY_MANIFEST = "recovery_manifest"


class ArtifactStatus(StrEnum):
    READY = "ready"
    QUARANTINED = "quarantined"


class RecoveryStatus(StrEnum):
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    CAPTURING = "capturing"
    READY = "ready"
    INCOMPLETE = "incomplete"
    BLOCKED = "blocked"
    FAILED = "failed"
    REJECTED = "rejected"


class ChangePreparationStatus(StrEnum):
    READY_FOR_REVIEW = "ready_for_review"
    STALE = "stale"


class RepositoryRef(StrictModel):
    provider: str
    repository_id: str = Field(min_length=1, max_length=512)
    revision: str = Field(min_length=1, max_length=256)
    allowed_paths: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("provider")
    @classmethod
    def supported_provider(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"local", "github"}:
            raise ValueError("repository provider must be local or github")
        return normalized

    @field_validator("repository_id", "revision")
    @classmethod
    def reject_control_characters(cls, value: str) -> str:
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("repository values cannot contain control characters")
        return value

    @field_validator("allowed_paths")
    @classmethod
    def validate_allowed_paths(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value or value.startswith(("/", "\\")) or "\\" in value:
                raise ValueError("allowed paths must be non-empty repository-relative paths")
            parts = value.split("/")
            if any(part in {"", ".", ".."} for part in parts):
                raise ValueError("allowed paths must be normalized repository-relative paths")
            if any(ord(character) < 32 or ord(character) == 127 for character in value):
                raise ValueError("allowed paths cannot contain control characters")
        if len(set(values)) != len(values):
            raise ValueError("allowed paths cannot contain duplicates")
        return values


class Budget(StrictModel):
    currency: str = Field(default="USD", pattern="^USD$")
    warning: float = Field(default=1.0, ge=0)
    hard_limit: float = Field(default=5.0, gt=0)

    @model_validator(mode="after")
    def warning_not_above_limit(self) -> Budget:
        if self.warning > self.hard_limit:
            raise ValueError("budget warning cannot exceed hard limit")
        return self


class TaskCreate(StrictModel):
    task_id: str = Field(min_length=1, max_length=128)
    requested_by: str = Field(min_length=1, max_length=128)
    organization_id: str = Field(min_length=1, max_length=128)
    project_id: str = Field(min_length=1, max_length=128)
    repository: RepositoryRef | None = None
    environment: Environment = Environment.DEVELOPMENT
    objective: str = Field(min_length=1, max_length=20_000)
    constraints: list[str] = Field(default_factory=list, max_length=200)
    approved_actions: list[str] = Field(default_factory=list, max_length=200)
    prohibited_actions: list[str] = Field(default_factory=list, max_length=200)
    available_tools: list[str] = Field(default_factory=list, max_length=200)
    required_evidence: list[str] = Field(default_factory=list, max_length=200)
    budget: Budget = Field(default_factory=Budget)
    execution_permission: bool = False
    metadata: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict, max_length=50
    )

    @model_validator(mode="after")
    def bounded_serialized_request(self) -> TaskCreate:
        if len(self.model_dump_json().encode("utf-8")) > 128_000:
            raise ValueError("task request exceeds the bounded planning-input limit")
        return self


class PlanResult(StrictModel):
    objective: str
    confirmed_facts: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    inspection_required: list[str] = Field(default_factory=list)
    likely_root_causes: list[str] = Field(default_factory=list)
    proposed_plan: list[str] = Field(default_factory=list)
    files_and_systems: list[str] = Field(default_factory=list)
    tests_required: list[str] = Field(default_factory=list)
    risks: list[str] = Field(default_factory=list)
    approval_actions: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    estimated_cost_usd: float = Field(default=0.0, ge=0)


class PathFinding(StrictModel):
    path: str
    category: str
    detail: str | None = None


class SecretFinding(StrictModel):
    path: str
    rule_id: str
    severity: RiskLevel
    line: int | None = Field(default=None, ge=1)


class LanguageStat(StrictModel):
    language: str
    files: int = Field(ge=1)
    bytes: int = Field(ge=0)


class DependencyManifest(StrictModel):
    path: str
    ecosystem: str
    direct_dependencies: int = Field(default=0, ge=0)
    development_dependencies: int = Field(default=0, ge=0)
    parse_status: str


class GitRemote(StrictModel):
    name: str
    host: str | None = None
    provider: str | None = None


class GitState(StrictModel):
    is_repository: bool
    metadata_complete: bool = True
    requested_revision: str
    resolved_revision: str | None = None
    head_revision: str | None = None
    branch: str | None = None
    detached_head: bool = False
    upstream: str | None = None
    ahead: int = Field(default=0, ge=0)
    behind: int = Field(default=0, ge=0)
    shallow: bool = False
    staged_paths: list[str] = Field(default_factory=list)
    modified_paths: list[str] = Field(default_factory=list)
    deleted_paths: list[str] = Field(default_factory=list)
    renamed_paths: list[str] = Field(default_factory=list)
    untracked_paths: list[str] = Field(default_factory=list)
    conflicted_paths: list[str] = Field(default_factory=list)
    ignored_paths: list[str] = Field(default_factory=list)
    submodules: list[str] = Field(default_factory=list)
    remotes: list[GitRemote] = Field(default_factory=list)
    status_truncated: bool = False
    recovery_snapshot_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    snapshot_file_count: int = Field(default=0, ge=0)
    snapshot_total_bytes: int = Field(default=0, ge=0)
    ignored_paths_included: bool = True


class RecoveryAssessment(StrictModel):
    dirty_worktree: bool
    patch_recommended: bool
    untracked_archive_recommended: bool
    bundle_recommended: bool
    reasons: list[str] = Field(default_factory=list)


class RepositoryInspection(StrictModel):
    schema_version: str = "2.0"
    provider: str
    repository_id: str
    repository_fingerprint: str
    complete: bool
    inspected_at: datetime = Field(default_factory=utc_now)
    allowed_paths: list[str] = Field(default_factory=list)
    file_count: int = Field(ge=0)
    directory_count: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    scanned_text_bytes: int = Field(ge=0)
    symlinks: list[PathFinding] = Field(default_factory=list)
    large_files: list[PathFinding] = Field(default_factory=list)
    languages: list[LanguageStat] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    dependency_manifests: list[DependencyManifest] = Field(default_factory=list)
    test_configs: list[PathFinding] = Field(default_factory=list)
    build_configs: list[PathFinding] = Field(default_factory=list)
    deployment_configs: list[PathFinding] = Field(default_factory=list)
    ci_configs: list[PathFinding] = Field(default_factory=list)
    secret_findings: list[SecretFinding] = Field(default_factory=list)
    git: GitState
    recovery: RecoveryAssessment
    warnings: list[str] = Field(default_factory=list)
    limits_reached: list[str] = Field(default_factory=list)
    read_only_verified: bool


class ArtifactRecord(StrictModel):
    id: str
    job_id: str
    organization_id: str
    project_id: str
    kind: ArtifactKind
    status: ArtifactStatus
    media_type: str
    plaintext_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ciphertext_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    plaintext_bytes: int = Field(ge=0)
    storage_bytes: int = Field(ge=0)
    encryption_version: str
    created_at: datetime = Field(default_factory=utc_now)


class RecoveryCreateRequest(StrictModel):
    expected_repository_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    accept_incomplete_history: bool = False
    retention_hours: int = Field(default=24, ge=1, le=168)


class RecoveryPackage(StrictModel):
    id: str
    job_id: str
    status: RecoveryStatus
    repository_id: str
    source_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_snapshot_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    capture_scope: str = "tracked_and_all_non_index_files"
    base_head: str | None = None
    allowed_paths: list[str] = Field(default_factory=list)
    planned_artifacts: list[ArtifactKind] = Field(default_factory=list)
    complete_for_scope: bool
    exclusions: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    blocker_codes: list[str] = Field(default_factory=list)
    approval_id: str
    action_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifacts: list[ArtifactRecord] = Field(default_factory=list)
    manifest_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    after_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    retention_expires_at: datetime
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ChangePreparation(StrictModel):
    id: str
    job_id: str
    status: ChangePreparationStatus
    repository_id: str
    source_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_snapshot_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    base_head: str | None = None
    recovery_package_id: str | None = None
    objective: str
    proposed_steps: list[str] = Field(default_factory=list)
    files_and_systems: list[str] = Field(default_factory=list)
    tests_required: list[str] = Field(default_factory=list)
    rollback_plan: list[str] = Field(default_factory=list)
    risk_flags: dict[str, bool] = Field(default_factory=dict)
    preparation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_writes_performed: bool = False
    execution_ready: bool = False
    created_at: datetime = Field(default_factory=utc_now)


class JobRecord(StrictModel):
    id: str
    task: TaskCreate
    status: JobStatus
    inspection: RepositoryInspection | None = None
    plan: PlanResult | None = None
    approval_id: str | None = None
    recovery_package: RecoveryPackage | None = None
    change_preparation: ChangePreparation | None = None
    remaining_blockers: list[str] = Field(default_factory=list)
    estimated_cost_usd: float = Field(default=0.0, ge=0)
    budget_reserved_usd: float = Field(default=0.0, ge=0)
    actual_cost_usd: float = Field(default=0.0, ge=0)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ActionProposal(StrictModel):
    operation: str = Field(min_length=1, max_length=256)
    purpose: str = Field(default="technical_change_v1", min_length=1, max_length=128)
    environment: Environment
    repository_id: str | None = None
    recovery_package_id: str | None = None
    plan_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_snapshot_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    base_revision: str | None = None
    artifact_kinds: list[ArtifactKind] = Field(default_factory=list)
    retention_hours: int | None = Field(default=None, ge=1, le=168)
    exclusions: list[str] = Field(default_factory=list, max_length=100)
    commands: list[str] = Field(default_factory=list, max_length=100)
    files: list[str] = Field(default_factory=list, max_length=1000)
    destructive: bool = False
    changes_billing: bool = False
    changes_permissions: bool = False
    changes_live_credentials: bool = False
    changes_public_dns: bool = False
    changes_production_database: bool = False
    enables_money_movement: bool = False
    disables_security: bool = False
    estimated_cost_usd: float = Field(default=0.0, ge=0)
    rollback_plan: list[str] = Field(default_factory=list)


class PolicyDecision(StrictModel):
    allowed_to_prepare: bool
    allowed_to_execute: bool
    approval_required: bool
    reasons: list[str] = Field(default_factory=list)
    risk_level: RiskLevel


class ApprovalRecord(StrictModel):
    id: str
    job_id: str
    action_digest: str
    proposal: ActionProposal
    purpose: str = "technical_change_v1"
    status: ApprovalStatus
    created_by: str
    expires_at: datetime
    created_at: datetime = Field(default_factory=utc_now)
    decided_by: str | None = None
    decided_at: datetime | None = None
    consumed_by: str | None = None
    consumed_at: datetime | None = None
    invalidated_by: str | None = None
    invalidated_at: datetime | None = None


class ApprovalDecisionRequest(StrictModel):
    decision: str = Field(pattern="^(approve|reject)$")
    action_digest: str


class EvidenceRecord(StrictModel):
    id: str
    job_id: str
    sequence: int
    event_type: str
    payload: dict[str, Any]
    previous_hash: str | None
    record_hash: str
    created_at: datetime


class HealthResponse(StrictModel):
    status: str
    phase: int
    execution_connected: bool
    repository_inspection_enabled: bool = False
    recovery_preparation_enabled: bool = False
    durable_evidence_integrity: bool = False
    emergency_stopped: bool
