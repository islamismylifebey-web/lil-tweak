from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from liltweak.canonical_lifecycle import (
    LEGAL_TRANSITIONS,
    STATE_ORDER,
    TERMINAL_STATES,
    CanonicalTask,
    CapabilityGate,
    CapabilityName,
    CapabilityStatus,
    TaskState,
    assert_legal_transition,
)


def test_lifecycle_contains_every_directive_state_exactly_once() -> None:
    assert {state.value for state in TaskState} == {
        "RECEIVED",
        "INSPECTED",
        "PLANNING",
        "PLAN_PROPOSED",
        "APPROVAL_PENDING",
        "APPROVED",
        "RUNNER_PREFLIGHT",
        "EXECUTING",
        "TESTING",
        "VERIFYING",
        "EVIDENCE_SEALED",
        "PATCH_READY",
        "APPLY_APPROVAL_PENDING",
        "APPLIED",
        "COMMIT_APPROVAL_PENDING",
        "LOCALLY_COMMITTED",
        "COMPLETED",
        "CANCELED",
        "FAILED",
        "ROLLBACK_PENDING",
        "ROLLED_BACK",
        "EMERGENCY_STOPPED",
    }
    assert set(LEGAL_TRANSITIONS) == set(TaskState)
    assert set(STATE_ORDER) == set(TaskState)


def test_every_legal_transition_is_strictly_monotonic_and_terminals_are_final() -> None:
    for current, targets in LEGAL_TRANSITIONS.items():
        for target in targets:
            assert STATE_ORDER[target] > STATE_ORDER[current]
            assert_legal_transition(current, target)
    assert all(not LEGAL_TRANSITIONS[state] for state in TERMINAL_STATES)
    with pytest.raises(ValueError, match="illegal canonical transition"):
        assert_legal_transition(TaskState.EXECUTING, TaskState.APPROVED)


def test_capability_cannot_claim_operational_from_a_single_ready_flag() -> None:
    with pytest.raises(ValidationError, match="contradicts its gates"):
        CapabilityGate(
            name=CapabilityName.RUNNER,
            version=1,
            status=CapabilityStatus.OPERATIONAL,
            feature_enabled=True,
            installed=True,
            configured=True,
            connected=True,
            healthy=True,
            qualified=False,
            authorized=True,
            operational=True,
            detail_code="ready",
            updated_at=datetime.now(UTC),
        )


def test_nonoperational_capability_must_not_use_operational_status() -> None:
    with pytest.raises(ValidationError, match="status contradicts"):
        CapabilityGate(
            name=CapabilityName.MODEL,
            version=1,
            status=CapabilityStatus.OPERATIONAL,
            feature_enabled=False,
            installed=False,
            configured=False,
            connected=False,
            healthy=False,
            qualified=False,
            authorized=False,
            operational=False,
            detail_code="disabled",
            updated_at=datetime.now(UTC),
        )


def test_delivery_state_requires_independent_verification_and_a_real_change() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="verified change"):
        CanonicalTask(
            id="task:delivery",
            task_digest="a" * 64,
            source_snapshot_digest="b" * 64,
            state=TaskState.PATCH_READY,
            plan_digest="c" * 64,
            verification_decision_digest="d" * 64,
            checkpoint_receipt_digest="e" * 64,
            final_tree_manifest_digest="f" * 64,
            patch_manifest_digest="1" * 64,
            changed_path_count=0,
            created_at=now,
            updated_at=now,
        )

    with pytest.raises(ValidationError, match="independent verification"):
        CanonicalTask(
            id="task:sealed",
            task_digest="a" * 64,
            source_snapshot_digest="b" * 64,
            state=TaskState.EVIDENCE_SEALED,
            plan_digest="c" * 64,
            checkpoint_receipt_digest="e" * 64,
            created_at=now,
            updated_at=now,
        )
