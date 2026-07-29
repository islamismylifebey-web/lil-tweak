import pytest

from liltweak.models import JobStatus
from liltweak.states import InvalidTransitionError, require_transition


def test_valid_transition() -> None:
    require_transition(JobStatus.RECEIVED, JobStatus.INSPECTING)


def test_invalid_transition_to_completed() -> None:
    with pytest.raises(InvalidTransitionError):
        require_transition(JobStatus.RECEIVED, JobStatus.COMPLETED)


def test_completed_is_terminal() -> None:
    with pytest.raises(InvalidTransitionError):
        require_transition(JobStatus.COMPLETED, JobStatus.EXECUTING)
