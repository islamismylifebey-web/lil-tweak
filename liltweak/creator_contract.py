from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    computed_field,
    model_validator,
)

MAX_CREATOR_REQUEST_BYTES = 128_000
MAX_DIRECTION_BYTES = 32_000
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SIGNATURE_PATTERN = r"^[0-9a-f]{64}$"


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_digest(value: object) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", exclude_none=False)
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class CreatorSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class WorkKind(StrEnum):
    ENGINEERING = "engineering"
    VISUAL = "visual"
    RESEARCH = "research"
    WRITING = "writing"
    OPERATIONS = "operations"
    ANALYSIS = "analysis"
    GENERAL = "general"


class RiskDomain(StrEnum):
    MEDICAL = "medical"
    LEGAL = "legal"
    FINANCIAL = "financial"
    SAFETY_CRITICAL = "safety_critical"
    CREDENTIALS = "credentials"
    PRODUCTION = "production"


class ModelTier(StrEnum):
    ECONOMY = "economy"
    STANDARD = "standard"
    FRONTIER = "frontier"


class ReasoningEffort(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"


class RouteStatus(StrEnum):
    READY = "ready"
    NEEDS_INPUT = "needs_input"
    BLOCKED = "blocked"


class CommandKind(StrEnum):
    BASELINE = "baseline"
    TEST = "test"
    BUILD = "build"
    LINT = "lint"
    INSPECTION = "inspection"


class CreatorContextItem(CreatorSchema):
    label: StrictStr = Field(min_length=1, max_length=128)
    value: StrictStr = Field(min_length=1, max_length=8_000)


class CreatorCompileRequest(CreatorSchema):
    direction: StrictStr = Field(min_length=1, max_length=20_000)
    context: tuple[CreatorContextItem, ...] = Field(default_factory=tuple, max_length=32)
    desired_output: StrictStr | None = Field(default=None, min_length=1, max_length=512)

    @model_validator(mode="after")
    def bounded_request(self) -> CreatorCompileRequest:
        raw = self.model_dump_json().encode("utf-8")
        if len(raw) > MAX_CREATOR_REQUEST_BYTES:
            raise ValueError("creator request exceeds the bounded input limit")
        if len(self.direction.encode("utf-8")) > MAX_DIRECTION_BYTES:
            raise ValueError("creator direction exceeds the bounded input limit")
        labels = [item.label.casefold() for item in self.context]
        if len(labels) != len(set(labels)):
            raise ValueError("creator context labels must be unique")
        return self


class AuthorityGrant(CreatorSchema):
    actor_id: StrictStr = Field(min_length=1, max_length=128)
    source: Literal["authenticated_server_context"] = "authenticated_server_context"
    permitted_actions: tuple[StrictStr, ...] = ("compile", "route_preview")
    prohibited_actions: tuple[StrictStr, ...] = (
        "model_call",
        "tool_use",
        "spend",
        "source_write",
        "execution",
        "deployment",
    )


class QualityControl(CreatorSchema):
    source_phrase: StrictStr = Field(min_length=1, max_length=128)
    controllable_qualities: tuple[StrictStr, ...] = Field(min_length=1, max_length=8)
    failure_conditions: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=8)


class CreatorBrief(CreatorSchema):
    schema_version: Literal["1.0"] = "1.0"
    input_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    direction: StrictStr
    work_kind: WorkKind
    objective: StrictStr
    deliverables: tuple[StrictStr, ...] = Field(min_length=1, max_length=12)
    constraints: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=32)
    negative_constraints: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=32)
    quality_controls: tuple[QualityControl, ...] = Field(default_factory=tuple, max_length=16)
    acceptance_criteria: tuple[StrictStr, ...] = Field(min_length=1, max_length=24)
    material_questions: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=6)
    risk_domains: tuple[RiskDomain, ...] = Field(default_factory=tuple)
    trusted_prerequisites: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=12)
    untrusted_context_labels: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=32)
    creator_cycle: tuple[StrictStr, ...] = Field(min_length=8, max_length=8)
    authority: AuthorityGrant

    @property
    def brief_digest(self) -> str:
        return content_digest(self.model_dump(mode="json"))


class CreatorBriefEnvelope(CreatorSchema):
    brief: CreatorBrief
    brief_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    signature: StrictStr = Field(pattern=_SIGNATURE_PATTERN)
    signature_version: Literal["hmac-sha256-v1"] = "hmac-sha256-v1"

    @model_validator(mode="after")
    def digest_matches_brief(self) -> CreatorBriefEnvelope:
        if self.brief_digest != self.brief.brief_digest:
            raise ValueError("creator brief digest mismatch")
        return self


class RoutePreviewRequest(CreatorSchema):
    envelope: CreatorBriefEnvelope


class RouteDecision(CreatorSchema):
    schema_version: Literal["1.0"] = "1.0"
    brief_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    status: RouteStatus
    selected_tier: ModelTier | None = None
    reasoning_effort: ReasoningEffort | None = None
    context_token_ceiling: StrictInt = Field(ge=0, le=200_000)
    max_turns: StrictInt = Field(ge=0, le=32)
    complexity_score: StrictInt = Field(ge=1, le=10)
    required_capabilities: tuple[StrictStr, ...] = Field(default_factory=tuple)
    suggested_tools: tuple[StrictStr, ...] = Field(default_factory=tuple)
    blocked_reasons: tuple[StrictStr, ...] = Field(default_factory=tuple)
    escalation_triggers: tuple[StrictStr, ...] = Field(default_factory=tuple)
    deescalation_triggers: tuple[StrictStr, ...] = Field(default_factory=tuple)
    synthetic_cost_units: StrictFloat = Field(ge=0)
    preview_only: Literal[True] = True
    model_call_authorized: Literal[False] = False
    tool_use_authorized: Literal[False] = False
    spend_authorized: Literal[False] = False
    execution_authorized: Literal[False] = False

    @computed_field
    @property
    def decision_digest(self) -> str:
        return content_digest(self.model_dump(mode="json", exclude={"decision_digest"}))


class CreatorRunPreview(CreatorSchema):
    envelope: CreatorBriefEnvelope
    route: RouteDecision
    next_action: StrictStr
    execution_connected: Literal[False] = False


class SandboxCommand(CreatorSchema):
    command_id: StrictStr = Field(min_length=1, max_length=128)
    kind: CommandKind
    argv: tuple[StrictStr, ...] = Field(min_length=1, max_length=32)
    timeout_seconds: StrictInt = Field(ge=1, le=1_800)
    required: StrictBool = True

    @model_validator(mode="after")
    def safe_argv(self) -> SandboxCommand:
        for value in self.argv:
            if not value or len(value) > 1_024:
                raise ValueError("sandbox arguments must be non-empty and bounded")
            if "\x00" in value or "\n" in value or "\r" in value:
                raise ValueError("sandbox arguments cannot contain control separators")
        return self


class ExecutionPlan(CreatorSchema):
    schema_version: Literal["1.0"] = "1.0"
    id: StrictStr = Field(min_length=1, max_length=128)
    brief_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    route_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    repository_fingerprint: StrictStr = Field(pattern=_SHA256_PATTERN)
    workspace_mount_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    commands: tuple[SandboxCommand, ...] = Field(min_length=1, max_length=32)
    allowed_write_paths: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=128)
    network_allowed: Literal[False] = False
    wall_clock_seconds: StrictInt = Field(ge=1, le=3_600)
    memory_megabytes: StrictInt = Field(ge=128, le=32_768)
    cpu_count: StrictInt = Field(ge=1, le=32)
    artifact_byte_limit: StrictInt = Field(ge=1, le=1_000_000_000)
    secrets_in_manifest: Literal[False] = False
    execution_authorized: Literal[False] = False

    @model_validator(mode="after")
    def bounded_plan(self) -> ExecutionPlan:
        command_ids = [item.command_id for item in self.commands]
        if len(command_ids) != len(set(command_ids)):
            raise ValueError("sandbox command ids must be unique")
        for path in self.allowed_write_paths:
            if (
                not path
                or path.startswith(("/", "\\"))
                or "\\" in path
                or any(part in {"", ".", ".."} for part in path.split("/"))
            ):
                raise ValueError("allowed write paths must be normalized workspace paths")
        return self

    @property
    def plan_digest(self) -> str:
        return content_digest(self.model_dump(mode="json"))


class ExecutionApproval(CreatorSchema):
    id: StrictStr = Field(min_length=1, max_length=128)
    plan_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    approved_by: StrictStr = Field(min_length=1, max_length=128)
    signature: StrictStr = Field(pattern=_SIGNATURE_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime

    @model_validator(mode="after")
    def expiry_after_creation(self) -> ExecutionApproval:
        if self.expires_at <= self.created_at:
            raise ValueError("execution approval must expire after creation")
        return self


class CommandObservation(CreatorSchema):
    command_id: StrictStr = Field(min_length=1, max_length=128)
    exit_code: StrictInt = Field(ge=0, le=255)
    stdout_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    stderr_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    duration_ms: StrictInt = Field(ge=0, le=3_600_000)


class SandboxResult(CreatorSchema):
    plan_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    session_id: StrictStr = Field(min_length=1, max_length=128)
    source_before_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    source_after_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    observations: tuple[CommandObservation, ...] = Field(max_length=32)
    artifact_digests: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=128)
    artifact_bytes: StrictInt = Field(ge=0)
    credential_finding_count: StrictInt = Field(ge=0)
    network_used: StrictBool
    sandbox_isolated: StrictBool


class VerificationReport(CreatorSchema):
    plan_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    verified: StrictBool
    required_check_count: StrictInt = Field(ge=0)
    passed_required_check_count: StrictInt = Field(ge=0)
    evidence_digests: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=128)
    failure_codes: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=32)
    completion_claim_allowed: StrictBool


class RuntimeOutcome(CreatorSchema):
    plan: ExecutionPlan
    result: SandboxResult
    verification: VerificationReport
    outcome: Literal["verified_success", "verified_failure"]


class CreatorHealth(CreatorSchema):
    status: Literal["foundation_ready"] = "foundation_ready"
    version: Literal["0.5.0"] = "0.5.0"
    compiler_ready: Literal[True] = True
    adaptive_router_ready: Literal[True] = True
    causal_learning_ready: Literal[True] = True
    execution_connected: Literal[False] = False
    model_calls_enabled: Literal[False] = False
    tool_execution_enabled: Literal[False] = False
    durable_brief_signatures: StrictBool


class VerificationCheck(CreatorSchema):
    check_id: StrictStr = Field(min_length=1, max_length=128)
    evidence_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    passed: StrictBool
    source: Literal["trusted_harness"] = "trusted_harness"


class VerifiedOutcome(CreatorSchema):
    problem_signature: StrictStr = Field(min_length=1, max_length=512)
    intervention_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    checks: tuple[VerificationCheck, ...] = Field(min_length=1, max_length=64)
    executor_session_id: StrictStr = Field(min_length=1, max_length=128)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def outcome_digest(self) -> str:
        return content_digest(self.model_dump(mode="json"))


class VerifiedOutcomeEnvelope(CreatorSchema):
    outcome: VerifiedOutcome
    outcome_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    verifier_signature: StrictStr = Field(pattern=_SIGNATURE_PATTERN)

    @model_validator(mode="after")
    def digest_matches_outcome(self) -> VerifiedOutcomeEnvelope:
        if self.outcome_digest != self.outcome.outcome_digest:
            raise ValueError("verified outcome digest mismatch")
        return self


class LearningCandidate(CreatorSchema):
    problem_signature: StrictStr = Field(min_length=1, max_length=512)
    intervention_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    causal_claim: StrictStr = Field(min_length=1, max_length=2_000)
    confounders: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=16)
    reusable_when: tuple[StrictStr, ...] = Field(min_length=1, max_length=16)


class CausalLearningRecord(CreatorSchema):
    id: StrictStr = Field(min_length=1, max_length=128)
    problem_signature: StrictStr
    intervention_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    outcome_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    outcome: Literal["verified_success", "verified_failure"]
    causal_claim: StrictStr
    confounders: tuple[StrictStr, ...]
    reusable_when: tuple[StrictStr, ...]
    evidence_digests: tuple[StrictStr, ...] = Field(min_length=1, max_length=64)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def record_digest(self) -> str:
        return content_digest(self.model_dump(mode="json"))
