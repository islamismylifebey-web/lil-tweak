"""Stable protocol contracts shared by the trusted core components."""

from __future__ import annotations

from enum import StrEnum


class JobMode(StrEnum):
    BUILD = "build"
    DEBUG = "debug"
    REFACTOR = "refactor"
    TEST = "test"
    ARCHITECT = "architect"
    CHAT = "chat"


class JobState(StrEnum):
    DRAFT = "draft"
    QUEUED = "queued"
    INGESTING = "ingesting"
    PLANNING = "planning"
    EXECUTING = "executing"
    TESTING = "testing"
    COLLECTING = "collecting"
    AWAITING_APPROVAL = "awaiting_approval"
    APPLYING = "applying"
    COMPLETED = "completed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class SideEffect(StrEnum):
    READ_LOCAL = "read_local"
    WRITE_LOCAL = "write_local"
    TEST_LOCAL = "test_local"
    COMMIT = "commit"
    PUSH = "push"
    DEPLOY = "deploy"
    PUBLISH = "publish"
    EXTERNAL_DELETE = "external_delete"
    SEND_MESSAGE = "send_message"
    SPEND = "spend"


TERMINAL_STATES = frozenset(
    {
        JobState.COMPLETED,
        JobState.REJECTED,
        JobState.CANCELLED,
        JobState.FAILED,
        JobState.TIMED_OUT,
    }
)
