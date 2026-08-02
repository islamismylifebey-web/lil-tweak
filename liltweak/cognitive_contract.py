from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, StrictStr

from .reasoning_contract import (
    REASONING_CONTRACT_VERSION,
    CognitiveState,
    EvidenceReference,
    ReasoningRole,
    SafeId,
    Sha256,
    StatusedContract,
    ToolAuthority,
)


class CognitiveFinalization(StatusedContract):
    """Non-authoritative final cognitive synthesis; it can never complete a task."""

    schema_version: Literal[REASONING_CONTRACT_VERSION]
    role: Literal[ReasoningRole.FINALIZER]
    tool_authority: Literal[ToolAuthority.NONE]
    fresh_context: Literal[True]
    finalization_id: SafeId
    task_id: SafeId
    plan_digest: Sha256
    candidate_digest: Sha256
    verification_digest: Sha256
    evidence_references: tuple[EvidenceReference, ...]
    readiness_summary: Annotated[StrictStr, Field(min_length=1, max_length=4_000)]
    unresolved_conditions: tuple[Annotated[StrictStr, Field(min_length=1, max_length=2_000)], ...]
    recommended_state: Literal[
        CognitiveState.COGNITIVE_READY,
        CognitiveState.NO_CHANGE_PROPOSED,
        CognitiveState.BLOCKED,
        CognitiveState.FAILED,
    ]
    task_completion_claimed: Literal[False]
