"""Authoritative job-state and side-effect policy."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .contracts import JobState, SideEffect, TERMINAL_STATES


class StatePolicyError(ValueError):
    code = "state_policy_error"


class InvalidTransition(StatePolicyError):
    code = "invalid_transition"

    def __init__(self) -> None:
        super().__init__("invalid state transition")


class ApprovalRequired(StatePolicyError):
    code = "approval_required"

    def __init__(self) -> None:
        super().__init__("approval required")


_APPROVAL_REQUIRED = frozenset(
    {
        SideEffect.COMMIT,
        SideEffect.PUSH,
        SideEffect.DEPLOY,
        SideEffect.PUBLISH,
        SideEffect.EXTERNAL_DELETE,
        SideEffect.SEND_MESSAGE,
        SideEffect.SPEND,
    }
)


def approval_required(effect: SideEffect | str) -> bool:
    return SideEffect(effect) in _APPROVAL_REQUIRED


_FORWARD: Mapping[JobState, frozenset[JobState]] = {
    JobState.DRAFT: frozenset({JobState.QUEUED}),
    JobState.QUEUED: frozenset({JobState.INGESTING}),
    JobState.INGESTING: frozenset({JobState.PLANNING}),
    JobState.PLANNING: frozenset({JobState.EXECUTING}),
    JobState.EXECUTING: frozenset({JobState.TESTING, JobState.COLLECTING}),
    JobState.TESTING: frozenset({JobState.COLLECTING}),
    JobState.COLLECTING: frozenset(
        {JobState.AWAITING_APPROVAL, JobState.COMPLETED}
    ),
    JobState.AWAITING_APPROVAL: frozenset(
        {JobState.APPLYING, JobState.REJECTED}
    ),
    JobState.APPLYING: frozenset({JobState.COMPLETED}),
}


def transition(
    current: JobState | str,
    target: JobState | str,
    *,
    proposal_digest: str | None = None,
    evidence_manifest: Mapping[str, Any] | None = None,
    approved_digest: str | None = None,
    approval_recorded: bool = False,
    approval_consumed: bool = False,
) -> JobState:
    current_state = JobState(current)
    target_state = JobState(target)
    if current_state in TERMINAL_STATES:
        raise InvalidTransition()

    allowed = _FORWARD.get(current_state, frozenset())
    exceptional = {JobState.CANCELLED, JobState.FAILED, JobState.TIMED_OUT}
    if target_state not in allowed and target_state not in exceptional:
        raise InvalidTransition()

    if target_state is JobState.AWAITING_APPROVAL and not (
        proposal_digest and evidence_manifest
    ):
        raise ApprovalRequired()
    if target_state is JobState.APPLYING and not (
        proposal_digest
        and approved_digest
        and hmac_digest_equal(proposal_digest, approved_digest)
        and approval_recorded
        and not approval_consumed
    ):
        raise ApprovalRequired()
    return target_state


def hmac_digest_equal(left: str, right: str) -> bool:
    # Proposal digests are public evidence identifiers; constant-time comparison
    # still avoids making the approval boundary depend on early string mismatch.
    import hmac

    return hmac.compare_digest(left, right)
