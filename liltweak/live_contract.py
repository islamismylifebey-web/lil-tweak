from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictFloat, StrictInt, StrictStr, model_validator

from .creator_contract import (
    CreatorBriefEnvelope,
    CreatorSchema,
    ReasoningEffort,
    RouteDecision,
    content_digest,
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SIGNATURE_PATTERN = r"^[0-9a-f]{64}$"
WorkOrderLine = Annotated[StrictStr, Field(min_length=1, max_length=360)]


class LiveProposalStatus(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    EXPIRED = "expired"


class LiveRunProposal(CreatorSchema):
    schema_version: Literal["1.0"] = "1.0"
    id: StrictStr = Field(min_length=1, max_length=128)
    brief_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    route_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    model: StrictStr = Field(min_length=1, max_length=128)
    reasoning_effort: ReasoningEffort
    input_token_ceiling: StrictInt = Field(ge=1, le=200_000)
    output_token_ceiling: StrictInt = Field(ge=1, le=32_000)
    max_turns: Literal[1] = 1
    price_schedule: Literal["openai-standard-2026-07-29-v1"] = "openai-standard-2026-07-29-v1"
    input_price_per_million_usd: StrictFloat = Field(gt=0, le=1_000)
    output_price_per_million_usd: StrictFloat = Field(gt=0, le=1_000)
    cost_ceiling_usd: StrictFloat = Field(gt=0, le=100)
    requested_by: StrictStr = Field(min_length=1, max_length=128)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    model_call_authorized: Literal[False] = False
    spend_authorized: Literal[False] = False
    tool_use_authorized: Literal[False] = False
    execution_authorized: Literal[False] = False
    proposal_digest: StrictStr = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_proposal(self) -> LiveRunProposal:
        if self.expires_at <= self.created_at:
            raise ValueError("live proposal must expire after creation")
        expected = content_digest(self.model_dump(mode="json", exclude={"proposal_digest"}))
        if self.proposal_digest != expected:
            raise ValueError("live proposal digest mismatch")
        return self


class LiveProposalRecord(CreatorSchema):
    proposal: LiveRunProposal
    status: LiveProposalStatus
    approval_id: StrictStr | None = Field(default=None, min_length=1, max_length=128)
    result_digest: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    failure_code: StrictStr | None = Field(default=None, min_length=1, max_length=128)


class LiveProposalPrepareRequest(CreatorSchema):
    envelope: CreatorBriefEnvelope
    route: RouteDecision


class LiveProposalDecisionRequest(CreatorSchema):
    decision: Literal["approve", "reject"]
    proposal_digest: StrictStr = Field(pattern=_SHA256_PATTERN)


class LiveRunApproval(CreatorSchema):
    id: StrictStr = Field(min_length=1, max_length=128)
    proposal_id: StrictStr = Field(min_length=1, max_length=128)
    proposal_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    approved_by: StrictStr = Field(min_length=1, max_length=128)
    max_cost_usd: StrictFloat = Field(gt=0, le=100)
    signature: StrictStr = Field(pattern=_SIGNATURE_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime

    @model_validator(mode="after")
    def validate_expiry(self) -> LiveRunApproval:
        if self.expires_at <= self.created_at:
            raise ValueError("live approval must expire after creation")
        return self


class LiveProposalDecisionResponse(CreatorSchema):
    record: LiveProposalRecord
    approval: LiveRunApproval | None = None


class LiveRunExecuteRequest(CreatorSchema):
    proposal_id: StrictStr = Field(min_length=1, max_length=128)
    approval_id: StrictStr = Field(min_length=1, max_length=128)
    envelope: CreatorBriefEnvelope
    route: RouteDecision


class CreatorWorkOrder(CreatorSchema):
    schema_version: Literal["1.0"] = "1.0"
    functional_gap: StrictStr = Field(min_length=1, max_length=1_000)
    confirmed_facts: tuple[WorkOrderLine, ...] = Field(min_length=1, max_length=8)
    unknowns: tuple[WorkOrderLine, ...] = Field(default_factory=tuple, max_length=8)
    hypotheses: tuple[WorkOrderLine, ...] = Field(min_length=1, max_length=6)
    smallest_intervention: tuple[WorkOrderLine, ...] = Field(min_length=1, max_length=8)
    verification_checks: tuple[WorkOrderLine, ...] = Field(min_length=1, max_length=10)
    stop_conditions: tuple[WorkOrderLine, ...] = Field(min_length=1, max_length=8)
    execution_required: StrictBool
    authority_statement: Literal[
        "Analysis only. No spend, tool, write, execution, or deployment authority is granted."
    ] = "Analysis only. No spend, tool, write, execution, or deployment authority is granted."

    @property
    def work_order_digest(self) -> str:
        return content_digest(self.model_dump(mode="json"))


class LiveModelUsage(CreatorSchema):
    requests: StrictInt = Field(ge=1, le=4)
    input_tokens: StrictInt = Field(ge=0, le=200_000)
    output_tokens: StrictInt = Field(ge=0, le=32_000)
    total_tokens: StrictInt = Field(ge=0, le=232_000)


class LiveRunResult(CreatorSchema):
    schema_version: Literal["1.0"] = "1.0"
    proposal_id: StrictStr = Field(min_length=1, max_length=128)
    proposal_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    model: StrictStr = Field(min_length=1, max_length=128)
    work_order: CreatorWorkOrder
    usage: LiveModelUsage
    reserved_cost_usd: StrictFloat = Field(gt=0, le=100)
    estimated_actual_cost_usd: StrictFloat = Field(ge=0, le=100)
    provider_request_id_digest: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    model_call_observed: Literal[True] = True
    tools_observed: Literal[False] = False
    completion_claim_allowed: Literal[False] = False
    execution_connected: Literal[False] = False

    @property
    def result_digest(self) -> str:
        return content_digest(self.model_dump(mode="json"))


class HostedSandboxProbeResult(CreatorSchema):
    schema_version: Literal["1.0"] = "1.0"
    model: StrictStr = Field(min_length=1, max_length=128)
    challenge_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    observed_output_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    shell_call_count: StrictInt = Field(ge=1, le=4)
    network_policy: Literal["disabled"] = "disabled"
    disposable_container_requested: Literal[True] = True
    synthetic_inputs_only: Literal[True] = True
    real_source_uploaded: Literal[False] = False
    repository_execution_connected: Literal[False] = False
    usage: LiveModelUsage
    approved_cost_ceiling_usd: StrictFloat = Field(gt=0, le=1)
    estimated_actual_cost_usd: StrictFloat = Field(ge=0, le=1)
    verified: StrictBool
