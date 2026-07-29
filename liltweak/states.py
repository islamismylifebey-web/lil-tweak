from __future__ import annotations

from .models import JobStatus


class InvalidTransitionError(ValueError):
    pass


TERMINAL_STATES = {
    JobStatus.COMPLETED,
    JobStatus.BLOCKED,
    JobStatus.FAILED,
    JobStatus.ROLLED_BACK,
    JobStatus.CANCELED,
}

ALLOWED_TRANSITIONS: dict[JobStatus, set[JobStatus]] = {
    JobStatus.RECEIVED: {JobStatus.INSPECTING, JobStatus.CANCELED, JobStatus.BLOCKED},
    JobStatus.INSPECTING: {
        JobStatus.ANALYZED,
        JobStatus.BLOCKED,
        JobStatus.FAILED,
        JobStatus.CANCELED,
    },
    JobStatus.ANALYZED: {
        JobStatus.PLAN_READY,
        JobStatus.BLOCKED,
        JobStatus.FAILED,
        JobStatus.CANCELED,
    },
    JobStatus.PLAN_READY: {
        JobStatus.AWAITING_APPROVAL,
        JobStatus.APPROVED,
        JobStatus.BLOCKED,
        JobStatus.CANCELED,
    },
    JobStatus.AWAITING_APPROVAL: {
        JobStatus.APPROVED,
        JobStatus.CANCELED,
        JobStatus.BLOCKED,
    },
    JobStatus.APPROVED: {
        JobStatus.EXECUTING,
        JobStatus.BLOCKED,
        JobStatus.CANCELED,
    },
    JobStatus.EXECUTING: {
        JobStatus.TESTING,
        JobStatus.BLOCKED,
        JobStatus.FAILED,
        JobStatus.ROLLED_BACK,
        JobStatus.CANCELED,
    },
    JobStatus.TESTING: {
        JobStatus.VERIFIED,
        JobStatus.BLOCKED,
        JobStatus.FAILED,
        JobStatus.ROLLED_BACK,
        JobStatus.CANCELED,
    },
    JobStatus.VERIFIED: {
        JobStatus.COMPLETED,
        JobStatus.ROLLED_BACK,
        JobStatus.CANCELED,
    },
    JobStatus.COMPLETED: set(),
    JobStatus.BLOCKED: set(),
    JobStatus.FAILED: {JobStatus.ROLLED_BACK},
    JobStatus.ROLLED_BACK: set(),
    JobStatus.CANCELED: set(),
}


def require_transition(current: JobStatus, target: JobStatus) -> None:
    if target not in ALLOWED_TRANSITIONS[current]:
        raise InvalidTransitionError(f"invalid job transition: {current} -> {target}")
