from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    StringConstraints,
    model_validator,
)

REASONING_CONTRACT_VERSION = "1.0.0"

Sha256 = Annotated[StrictStr, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
SafeId = Annotated[
    StrictStr,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
]
RelativePath = Annotated[
    StrictStr,
    StringConstraints(min_length=1, max_length=512, pattern=r"^[^\\\x00-\x1f\x7f]+$"),
]
OpaqueWorkspaceId = Annotated[
    StrictStr,
    StringConstraints(pattern=r"^workspace_[A-Za-z0-9][A-Za-z0-9._:-]{0,118}$"),
]


class ReasoningSchema(BaseModel):
    """Strict base for every controller- or model-consumed reasoning contract."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class OutcomeStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    PASSED = "PASSED"


class CapabilityState(StrEnum):
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    IMPLEMENTED_UNVERIFIED = "IMPLEMENTED_UNVERIFIED"
    OFFLINE_TESTED = "OFFLINE_TESTED"
    INSTALLED = "INSTALLED"
    CONFIGURED = "CONFIGURED"
    CONNECTED = "CONNECTED"
    HEALTHY = "HEALTHY"
    QUALIFIED = "QUALIFIED"
    AUTHORIZED = "AUTHORIZED"
    OPERATIONAL = "OPERATIONAL"
    DEGRADED = "DEGRADED"
    DISABLED_BY_POLICY = "DISABLED_BY_POLICY"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class ProviderQualificationState(StrEnum):
    LIVE_QUALIFIED = "LIVE_QUALIFIED"
    OFFLINE_CONTRACT_ONLY = "OFFLINE_CONTRACT_ONLY"
    DISCONNECTED = "DISCONNECTED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class ProviderHealthState(StrEnum):
    UNKNOWN = "UNKNOWN"
    MISSING_KEY = "MISSING_KEY"
    INVALID_KEY = "INVALID_KEY"
    ENTITLEMENT_BLOCKED = "ENTITLEMENT_BLOCKED"
    QUOTA_BLOCKED = "QUOTA_BLOCKED"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    CANCELED = "CANCELED"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    REFUSED = "REFUSED"
    INCOMPLETE = "INCOMPLETE"
    SERVICE_ERROR = "SERVICE_ERROR"
    DISCONNECTED = "DISCONNECTED"
    CONNECTED = "CONNECTED"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    DISABLED_BY_POLICY = "DISABLED_BY_POLICY"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class EvidenceMode(StrEnum):
    LIVE = "LIVE"
    OFFLINE = "OFFLINE"
    MOCKED = "MOCKED"
    INTERFACE_ONLY = "INTERFACE_ONLY"


class ReasoningRole(StrEnum):
    INTAKE = "intake"
    RETRIEVER = "retriever"
    ANALYST = "analyst"
    ARCHITECT = "architect"
    PLANNER = "planner"
    IMPLEMENTER = "implementer"
    CRITIC = "critic"
    VERIFIER = "verifier"
    FINALIZER = "finalizer"
    CLASSIFIER = "classifier"
    DIAGNOSTIC = "diagnostic"


class ToolAuthority(StrEnum):
    NONE = "none"
    READ_ONLY_BROKERED = "read_only_brokered"
    MUTATION_BROKERED = "mutation_brokered"


class CognitiveState(StrEnum):
    REQUESTED = "REQUESTED"
    CONTRACT_READY = "CONTRACT_READY"
    CONTEXT_READY = "CONTEXT_READY"
    PLAN_PROPOSED = "PLAN_PROPOSED"
    PLAN_CRITIQUED = "PLAN_CRITIQUED"
    PLAN_VERIFIED = "PLAN_VERIFIED"
    CANDIDATE_GENERATED = "CANDIDATE_GENERATED"
    CANDIDATE_CRITIQUED = "CANDIDATE_CRITIQUED"
    DETERMINISTIC_CHECKED = "DETERMINISTIC_CHECKED"
    INDEPENDENTLY_VERIFIED = "INDEPENDENTLY_VERIFIED"
    COGNITIVE_READY = "COGNITIVE_READY"
    NO_CHANGE_PROPOSED = "NO_CHANGE_PROPOSED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class RiskClass(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PlanPhaseKind(StrEnum):
    READ = "read"
    MUTATION = "mutation"
    TEST = "test"
    VERIFICATION = "verification"


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(StrEnum):
    EVIDENCE = "evidence"
    CAUSALITY = "causality"
    ARCHITECTURE = "architecture"
    DEPENDENCY = "dependency"
    SECURITY = "security"
    PRIVACY = "privacy"
    COMPATIBILITY = "compatibility"
    MIGRATION = "migration"
    TESTING = "testing"
    AUTHORITY = "authority"
    COMPLETION = "completion"


class ChangeKind(StrEnum):
    ADD = "add"
    MODIFY = "modify"
    DELETE = "delete"
    RENAME = "rename"
    MODE_CHANGE = "mode_change"


class TokenMeasurement(StrEnum):
    PROVIDER_TOKENIZER = "provider_tokenizer"
    CONSERVATIVE_VERIFIED = "conservative_verified"


class CompletionVerdict(StrEnum):
    FULLY_OPERATIONAL = "FULLY OPERATIONAL"
    PLANNING_ONLY = "OPERATIONAL FOR VERIFIED PLANNING ONLY"
    ARCHITECTURE_ONLY = "ARCHITECTURE IMPLEMENTED AND TESTED — NOT OPERATIONAL"
    FAILED = "FAILED — RELEASE GATES NOT MET"


class StatusedContract(ReasoningSchema):
    status: OutcomeStatus
    status_reasons: tuple[Annotated[StrictStr, Field(min_length=1, max_length=1_000)], ...]

    @model_validator(mode="after")
    def validate_status_reasons(self) -> StatusedContract:
        needs_reason = self.status in {
            OutcomeStatus.UNKNOWN,
            OutcomeStatus.NOT_APPLICABLE,
            OutcomeStatus.BLOCKED,
            OutcomeStatus.FAILED,
        }
        if needs_reason and not self.status_reasons:
            raise ValueError(f"{self.status.value} requires at least one status reason")
        if self.status == OutcomeStatus.PASSED and self.status_reasons:
            raise ValueError("PASSED cannot carry failure or blocker reasons")
        return self


class SourceBinding(ReasoningSchema):
    repository_id: SafeId
    branch: Annotated[StrictStr, Field(min_length=1, max_length=256)]
    base_commit: Sha256 | None
    source_tree_digest: Sha256
    worktree_digest: Sha256
    source_fingerprint: Sha256


class PolicyBinding(ReasoningSchema):
    policy_version: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    policy_digest: Sha256
    prompt_version: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    prompt_digest: Sha256
    profile_name: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    profile_version: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    model_id: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    request_mode: Annotated[StrictStr, Field(min_length=1, max_length=32)]
    reasoning_effort: Annotated[StrictStr, Field(min_length=1, max_length=32)]


class EvidenceReference(ReasoningSchema):
    evidence_id: SafeId
    evidence_digest: Sha256
    source_path: RelativePath | None
    source_commit: Sha256 | None
    start_line: StrictInt | None
    end_line: StrictInt | None
    summary: Annotated[StrictStr, Field(min_length=1, max_length=2_000)]

    @model_validator(mode="after")
    def validate_line_range(self) -> EvidenceReference:
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("evidence line range must provide both endpoints")
        if self.start_line is not None and (
            self.source_path is None or self.start_line < 1 or self.end_line < self.start_line
        ):
            raise ValueError("evidence line range is invalid")
        return self


class TaskIntake(StatusedContract):
    schema_version: Literal[REASONING_CONTRACT_VERSION]
    role: Literal[ReasoningRole.INTAKE]
    tool_authority: Literal[ToolAuthority.NONE]
    task_id: SafeId
    objective: Annotated[StrictStr, Field(min_length=1, max_length=20_000)]
    non_goals: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    requirements: tuple[Annotated[StrictStr, Field(min_length=1, max_length=4_000)], ...]
    constraints: tuple[Annotated[StrictStr, Field(min_length=1, max_length=4_000)], ...]
    prohibited_actions: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    source_binding: SourceBinding
    expected_artifacts: tuple[Annotated[StrictStr, Field(min_length=1, max_length=512)], ...]
    acceptance_criteria: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    stop_conditions: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    risk_class: RiskClass


class RetrievalQuery(ReasoningSchema):
    query_id: SafeId
    purpose: Annotated[StrictStr, Field(min_length=1, max_length=1_000)]
    terms: tuple[Annotated[StrictStr, Field(min_length=1, max_length=256)], ...]
    path_hints: tuple[RelativePath, ...]
    symbol_hints: tuple[Annotated[StrictStr, Field(min_length=1, max_length=512)], ...]
    required: StrictBool


class RetrievalPlan(StatusedContract):
    schema_version: Literal[REASONING_CONTRACT_VERSION]
    role: Literal[ReasoningRole.RETRIEVER]
    tool_authority: Literal[ToolAuthority.READ_ONLY_BROKERED]
    task_id: SafeId
    source_binding: SourceBinding
    policy_binding: PolicyBinding
    queries: tuple[RetrievalQuery, ...]
    discover_governing_instructions: StrictBool
    discover_manifests_and_locks: StrictBool
    discover_ci_and_deployment: StrictBool
    inspect_git_history_and_diff: StrictBool
    parse_diagnostics: StrictBool
    excluded_content_classes: tuple[Annotated[StrictStr, Field(min_length=1, max_length=128)], ...]
    maximum_expansions: Annotated[StrictInt, Field(ge=0, le=32)]
    context_token_budget: Annotated[StrictInt, Field(gt=0)]
    reserved_output_tokens: Annotated[StrictInt, Field(gt=0)]
    exact_provenance_required: Literal[True]


class GoverningInstruction(ReasoningSchema):
    path: RelativePath
    digest: Sha256
    scope_path: RelativePath
    precedence: Annotated[StrictInt, Field(ge=0)]


class ContextExcerpt(ReasoningSchema):
    excerpt_id: SafeId
    path: RelativePath
    file_digest: Sha256
    source_commit: Sha256 | None
    start_line: Annotated[StrictInt, Field(ge=1)]
    end_line: Annotated[StrictInt, Field(ge=1)]
    content_digest: Sha256
    relevance_reason: Annotated[StrictStr, Field(min_length=1, max_length=1_000)]
    token_count: Annotated[StrictInt, Field(ge=0)]

    @model_validator(mode="after")
    def validate_excerpt_lines(self) -> ContextExcerpt:
        if self.end_line < self.start_line:
            raise ValueError("context excerpt line range is invalid")
        return self


class TokenAccounting(ReasoningSchema):
    measurement: TokenMeasurement
    tokenizer_model: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    stable_prompt_tokens: Annotated[StrictInt, Field(ge=0)]
    context_tokens: Annotated[StrictInt, Field(ge=0)]
    reserved_reasoning_tokens: Annotated[StrictInt, Field(ge=0)]
    reserved_tool_tokens: Annotated[StrictInt, Field(ge=0)]
    reserved_output_tokens: Annotated[StrictInt, Field(ge=0)]
    total_context_limit: Annotated[StrictInt, Field(gt=0)]

    @model_validator(mode="after")
    def validate_total_budget(self) -> TokenAccounting:
        committed = (
            self.stable_prompt_tokens
            + self.context_tokens
            + self.reserved_reasoning_tokens
            + self.reserved_tool_tokens
            + self.reserved_output_tokens
        )
        if committed > self.total_context_limit:
            raise ValueError("context and reserves exceed the verified context limit")
        return self


class CompactionRecord(ReasoningSchema):
    triggered: StrictBool
    policy_version: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    input_state_digest: Sha256
    output_state_digest: Sha256
    provider_opaque_items_preserved: StrictBool
    response_item_ids_preserved: StrictBool
    tool_call_ids_preserved: StrictBool


class ContextManifest(StatusedContract):
    schema_version: Literal[REASONING_CONTRACT_VERSION]
    role: Literal[ReasoningRole.RETRIEVER]
    tool_authority: Literal[ToolAuthority.READ_ONLY_BROKERED]
    task_id: SafeId
    source_binding: SourceBinding
    policy_binding: PolicyBinding
    retrieval_plan_digest: Sha256
    governing_instructions: tuple[GoverningInstruction, ...]
    excerpts: tuple[ContextExcerpt, ...]
    evidence_references: tuple[EvidenceReference, ...]
    missing_evidence: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    token_accounting: TokenAccounting
    compaction: CompactionRecord | None
    manifest_digest: Sha256


class CompetingHypothesis(ReasoningSchema):
    hypothesis_id: SafeId
    statement: Annotated[StrictStr, Field(min_length=1, max_length=2_000)]
    causal_mechanism: Annotated[StrictStr, Field(min_length=1, max_length=2_000)]
    supporting_evidence_ids: tuple[SafeId, ...]
    contradicting_evidence_ids: tuple[SafeId, ...]
    falsification: Annotated[StrictStr, Field(min_length=1, max_length=2_000)]
    confidence: Annotated[StrictFloat, Field(ge=0.0, le=1.0)]


class FileSymbolTarget(ReasoningSchema):
    path: RelativePath
    symbols: tuple[Annotated[StrictStr, Field(min_length=1, max_length=512)], ...]
    expected_change: Annotated[StrictStr, Field(min_length=1, max_length=2_000)]


class ToolIntent(ReasoningSchema):
    intent_id: SafeId
    tool_id: SafeId
    tool_schema_version: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    authority: ToolAuthority
    operation: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    normalized_arguments_json: Annotated[StrictStr, Field(min_length=2, max_length=32_000)]
    arguments_digest: Sha256
    purpose: Annotated[StrictStr, Field(min_length=1, max_length=1_000)]
    approval_purpose: Annotated[StrictStr, Field(min_length=1, max_length=128)] | None

    @model_validator(mode="after")
    def validate_arguments_digest(self) -> ToolIntent:
        observed = hashlib.sha256(self.normalized_arguments_json.encode("utf-8")).hexdigest()
        if observed != self.arguments_digest:
            raise ValueError("tool intent arguments digest does not match")
        return self


class PlanPhase(ReasoningSchema):
    ordinal: Annotated[StrictInt, Field(ge=1, le=256)]
    kind: PlanPhaseKind
    objective: Annotated[StrictStr, Field(min_length=1, max_length=2_000)]
    tool_intents: tuple[ToolIntent, ...]
    required_evidence: tuple[Annotated[StrictStr, Field(min_length=1, max_length=1_000)], ...]
    completion_condition: Annotated[StrictStr, Field(min_length=1, max_length=2_000)]


class RiskAssessment(ReasoningSchema):
    category: FindingCategory
    risk_class: RiskClass
    description: Annotated[StrictStr, Field(min_length=1, max_length=2_000)]
    mitigation: Annotated[StrictStr, Field(min_length=1, max_length=2_000)]
    residual_risk: Annotated[StrictStr, Field(min_length=1, max_length=2_000)]


class RecoveryPlan(ReasoningSchema):
    preconditions: tuple[Annotated[StrictStr, Field(min_length=1, max_length=1_000)], ...]
    rollback_steps: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    recovery_evidence: tuple[Annotated[StrictStr, Field(min_length=1, max_length=1_000)], ...]
    stop_on_restore_failure: Literal[True]


class ResourceBudget(ReasoningSchema):
    maximum_model_calls: Annotated[StrictInt, Field(ge=1, le=16)]
    maximum_full_repairs: Annotated[StrictInt, Field(ge=0, le=2)]
    input_token_ceiling: Annotated[StrictInt, Field(gt=0)]
    output_token_ceiling: Annotated[StrictInt, Field(gt=0)]
    timeout_seconds: Annotated[StrictInt, Field(gt=0, le=3_600)]
    cost_ceiling_usd: Annotated[StrictFloat, Field(ge=0.0)]


class ApprovalBoundary(ReasoningSchema):
    purpose: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    before_phase: Annotated[StrictInt, Field(ge=1, le=256)]
    bound_intent_ids: tuple[SafeId, ...]
    owner_required: StrictBool


class ExpectedArtifact(ReasoningSchema):
    artifact_id: SafeId
    kind: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    required: StrictBool
    verification: Annotated[StrictStr, Field(min_length=1, max_length=1_000)]


class EngineeringPlan(StatusedContract):
    schema_version: Literal[REASONING_CONTRACT_VERSION]
    role: Literal[ReasoningRole.PLANNER]
    tool_authority: Literal[ToolAuthority.NONE]
    plan_id: SafeId
    task_id: SafeId
    objective: Annotated[StrictStr, Field(min_length=1, max_length=20_000)]
    non_goals: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    source_binding: SourceBinding
    policy_binding: PolicyBinding
    evidence_used: tuple[EvidenceReference, ...]
    assumptions: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    missing_evidence: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    competing_hypotheses: tuple[CompetingHypothesis, ...]
    architecture_impact: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    dependency_impact: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    change_targets: tuple[FileSymbolTarget, ...]
    phases: tuple[PlanPhase, ...]
    risks: tuple[RiskAssessment, ...]
    recovery: RecoveryPlan
    acceptance_criteria: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    stop_conditions: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    expected_artifacts: tuple[ExpectedArtifact, ...]
    resource_budget: ResourceBudget
    approvals: tuple[ApprovalBoundary, ...]

    @model_validator(mode="after")
    def validate_phase_order(self) -> EngineeringPlan:
        ordinals = [phase.ordinal for phase in self.phases]
        if ordinals != list(range(1, len(ordinals) + 1)):
            raise ValueError("engineering plan phases must be ordered contiguously from one")
        return self


class CritiqueFinding(ReasoningSchema):
    finding_id: SafeId
    category: FindingCategory
    severity: FindingSeverity
    statement: Annotated[StrictStr, Field(min_length=1, max_length=2_000)]
    evidence_ids: tuple[SafeId, ...]
    repair_required: StrictBool


class PlanCritique(StatusedContract):
    schema_version: Literal[REASONING_CONTRACT_VERSION]
    role: Literal[ReasoningRole.CRITIC]
    tool_authority: Literal[ToolAuthority.NONE]
    fresh_context: Literal[True]
    critique_id: SafeId
    task_id: SafeId
    plan_digest: Sha256
    source_binding: SourceBinding
    policy_binding: PolicyBinding
    evidence_used: tuple[EvidenceReference, ...]
    findings: tuple[CritiqueFinding, ...]
    hypothesis_assessment: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    unmet_acceptance_criteria: tuple[
        Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...
    ]
    required_repairs: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    recurring_material_failure: StrictBool


class CandidateChange(ReasoningSchema):
    path: RelativePath
    kind: ChangeKind
    symbols: tuple[Annotated[StrictStr, Field(min_length=1, max_length=512)], ...]
    summary: Annotated[StrictStr, Field(min_length=1, max_length=2_000)]
    content_digest: Sha256 | None


class CandidateManifest(StatusedContract):
    schema_version: Literal[REASONING_CONTRACT_VERSION]
    role: Literal[ReasoningRole.IMPLEMENTER]
    tool_authority: Literal[ToolAuthority.NONE]
    candidate_id: SafeId
    task_id: SafeId
    plan_digest: Sha256
    source_binding: SourceBinding
    policy_binding: PolicyBinding
    task_workspace_identity: OpaqueWorkspaceId
    starting_tree_digest: Sha256
    proposed_tree_digest: Sha256
    proposed_diff_digest: Sha256
    changes: tuple[CandidateChange, ...]
    evidence_references: tuple[EvidenceReference, ...]
    generated_artifacts: tuple[ExpectedArtifact, ...]
    mutation_applied: Literal[False]
    execution_claimed: Literal[False]


class CandidateCritique(StatusedContract):
    schema_version: Literal[REASONING_CONTRACT_VERSION]
    role: Literal[ReasoningRole.CRITIC]
    tool_authority: Literal[ToolAuthority.NONE]
    fresh_context: Literal[True]
    critique_id: SafeId
    task_id: SafeId
    plan_digest: Sha256
    candidate_digest: Sha256
    source_binding: SourceBinding
    policy_binding: PolicyBinding
    evidence_used: tuple[EvidenceReference, ...]
    findings: tuple[CritiqueFinding, ...]
    required_repairs: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    recurring_material_failure: StrictBool


class CheckResult(StatusedContract):
    check_id: SafeId
    command_or_check: Annotated[StrictStr, Field(min_length=1, max_length=2_000)]
    exit_code: StrictInt | None
    output_digest: Sha256 | None
    evidence_ids: tuple[SafeId, ...]


class RequirementDecision(StatusedContract):
    requirement_id: SafeId
    statement: Annotated[StrictStr, Field(min_length=1, max_length=2_000)]
    evidence_ids: tuple[SafeId, ...]


class VerificationDecision(StatusedContract):
    schema_version: Literal[REASONING_CONTRACT_VERSION]
    role: Literal[ReasoningRole.VERIFIER]
    tool_authority: Literal[ToolAuthority.NONE]
    fresh_context: Literal[True]
    verification_id: SafeId
    task_id: SafeId
    plan_digest: Sha256
    candidate_digest: Sha256
    source_binding: SourceBinding
    policy_binding: PolicyBinding
    observed_tree_digest: Sha256
    observed_diff_digest: Sha256
    requirement_decisions: tuple[RequirementDecision, ...]
    deterministic_checks: tuple[CheckResult, ...]
    artifact_evidence: tuple[EvidenceReference, ...]
    unresolved_findings: tuple[CritiqueFinding, ...]
    completion_authorized: Literal[False]


class ProviderUsage(ReasoningSchema):
    requests: Annotated[StrictInt, Field(ge=0)]
    input_tokens: Annotated[StrictInt, Field(ge=0)]
    cached_input_tokens: Annotated[StrictInt, Field(ge=0)]
    output_tokens: Annotated[StrictInt, Field(ge=0)]
    reasoning_tokens: Annotated[StrictInt, Field(ge=0)]
    total_tokens: Annotated[StrictInt, Field(ge=0)]
    estimated_cost_usd: Annotated[StrictFloat, Field(ge=0.0)] | None

    @model_validator(mode="after")
    def validate_usage_total(self) -> ProviderUsage:
        if self.total_tokens < self.input_tokens + self.output_tokens:
            raise ValueError("provider total tokens are less than input plus output")
        if self.cached_input_tokens > self.input_tokens:
            raise ValueError("cached input tokens exceed total input tokens")
        return self


class QualificationScenario(StatusedContract):
    scenario_id: SafeId
    live: StrictBool
    response_id_digest: Sha256 | None
    evidence_digest: Sha256


class ProviderQualification(StatusedContract):
    schema_version: Literal[REASONING_CONTRACT_VERSION]
    qualification_id: SafeId
    provider: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    configured: StrictBool
    connected: StrictBool
    requested_model: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    effective_model: Annotated[StrictStr, Field(min_length=1, max_length=128)] | None
    profile_name: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    profile_version: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    request_mode: Annotated[StrictStr, Field(min_length=1, max_length=32)]
    reasoning_effort: Annotated[StrictStr, Field(min_length=1, max_length=32)]
    health_state: ProviderHealthState
    qualification_state: ProviderQualificationState
    evidence_mode: EvidenceMode
    strict_schema_qualified: StrictBool
    refusal_qualified: StrictBool
    incomplete_qualified: StrictBool
    continuation_qualified: StrictBool
    compaction_qualified: StrictBool
    timeout_qualified: StrictBool
    cancellation_qualified: StrictBool
    concurrency_qualified: StrictBool
    usage_reconciliation_qualified: StrictBool
    caching_telemetry_qualified: StrictBool
    store_disabled: StrictBool
    sensitive_tracing_disabled: StrictBool
    approved_data_controls: Annotated[StrictStr, Field(min_length=1, max_length=2_000)]
    scenarios: tuple[QualificationScenario, ...]
    usage: ProviderUsage
    qualified_at: datetime | None

    @model_validator(mode="after")
    def validate_live_qualification(self) -> ProviderQualification:
        if self.qualification_state == ProviderQualificationState.LIVE_QUALIFIED and (
            not self.configured
            or not self.connected
            or self.health_state != ProviderHealthState.HEALTHY
            or self.evidence_mode != EvidenceMode.LIVE
            or self.effective_model is None
            or self.qualified_at is None
        ):
            raise ValueError("LIVE_QUALIFIED requires live, healthy provider evidence")
        return self


class CapabilityDimensions(ReasoningSchema):
    installed: OutcomeStatus
    configured: OutcomeStatus
    connected: OutcomeStatus
    healthy: OutcomeStatus
    qualified: OutcomeStatus
    authorized: OutcomeStatus
    operational: OutcomeStatus


class CapabilityClassification(StatusedContract):
    schema_version: Literal[REASONING_CONTRACT_VERSION]
    capability_id: SafeId
    name: Annotated[StrictStr, Field(min_length=1, max_length=256)]
    state: CapabilityState
    dimensions: CapabilityDimensions
    evidence_mode: EvidenceMode
    evidence_references: tuple[EvidenceReference, ...]
    blockers: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    last_checked_at: datetime


class CompletionCommand(ReasoningSchema):
    command_id: SafeId
    purpose: Annotated[StrictStr, Field(min_length=1, max_length=1_000)]
    command_digest: Sha256
    exit_code: StrictInt
    evidence_digest: Sha256


class CompletionCounts(ReasoningSchema):
    tests_collected: Annotated[StrictInt, Field(ge=0)]
    tests_passed: Annotated[StrictInt, Field(ge=0)]
    tests_failed: Annotated[StrictInt, Field(ge=0)]
    tests_skipped: Annotated[StrictInt, Field(ge=0)]
    capabilities_passed: Annotated[StrictInt, Field(ge=0)]
    capabilities_blocked: Annotated[StrictInt, Field(ge=0)]
    capabilities_failed: Annotated[StrictInt, Field(ge=0)]

    @model_validator(mode="after")
    def validate_test_counts(self) -> CompletionCounts:
        observed = self.tests_passed + self.tests_failed + self.tests_skipped
        if observed != self.tests_collected:
            raise ValueError("test result counts do not equal collected tests")
        return self


class CompletionArtifact(ReasoningSchema):
    artifact_id: SafeId
    kind: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    path: RelativePath | None
    digest: Sha256
    evidence_mode: EvidenceMode


class CompletionReport(StatusedContract):
    schema_version: Literal[REASONING_CONTRACT_VERSION]
    role: Literal[ReasoningRole.FINALIZER]
    tool_authority: Literal[ToolAuthority.NONE]
    report_id: SafeId
    verdict: CompletionVerdict
    repository_id: SafeId
    branch: Annotated[StrictStr, Field(min_length=1, max_length=256)]
    baseline_commit: Sha256
    tested_tree_digest: Sha256
    candidate_commit: Sha256 | None
    environment: Annotated[StrictStr, Field(min_length=1, max_length=512)]
    policy_binding: PolicyBinding
    commands: tuple[CompletionCommand, ...]
    counts: CompletionCounts
    artifacts: tuple[CompletionArtifact, ...]
    evidence_digests: tuple[Sha256, ...]
    provider_qualification_digest: Sha256 | None
    capabilities: tuple[CapabilityClassification, ...]
    live_evidence_present: StrictBool
    mocked_evidence_present: StrictBool
    unverified_conditions: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    remaining_blockers: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    completed_at: datetime

    @model_validator(mode="after")
    def validate_verdict_truthfulness(self) -> CompletionReport:
        if self.status == OutcomeStatus.FAILED and self.verdict != CompletionVerdict.FAILED:
            raise ValueError("a failed completion status requires the exact failed verdict")
        if self.verdict == CompletionVerdict.FAILED and self.status != OutcomeStatus.FAILED:
            raise ValueError("the failed verdict requires a failed completion status")
        if self.verdict not in {
            CompletionVerdict.ARCHITECTURE_ONLY,
            CompletionVerdict.FAILED,
        }:
            if self.status != OutcomeStatus.PASSED or self.remaining_blockers:
                raise ValueError("an operational verdict cannot contain unresolved blockers")
            if not self.live_evidence_present or self.mocked_evidence_present:
                raise ValueError("an operational verdict requires unmocked live evidence")
        return self


DIRECTIVE_MACHINE_CONTRACTS: Final[tuple[type[ReasoningSchema], ...]] = (
    TaskIntake,
    RetrievalPlan,
    ContextManifest,
    EngineeringPlan,
    PlanCritique,
    CandidateManifest,
    CandidateCritique,
    VerificationDecision,
    ProviderQualification,
    CapabilityClassification,
    CompletionReport,
)

ROLE_OUTPUT_CONTRACTS: Final[tuple[type[ReasoningSchema], ...]] = (
    EngineeringPlan,
    PlanCritique,
    CandidateManifest,
    CandidateCritique,
    VerificationDecision,
    CompletionReport,
)
