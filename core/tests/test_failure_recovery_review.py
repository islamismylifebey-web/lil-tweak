from dataclasses import replace
import unittest

from core.lil_tweak.failure_recovery import (
    FailureCode,
    FailureRecoveryController,
    FailureSignal,
    InMemoryRecoveryHistoryStore,
    RecoveryAction,
    RecoveryContext,
    RecoveryOutcome,
    RecoveryOutcomeStatus,
    ResourceRecoveryDecision,
)


HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64


def context(**overrides):
    values = {
        "owner_id": "owner",
        "task_id": "task",
        "dag_run_id": "run",
        "node_id": "execute",
        "source_revision": "1" * 40,
        "attempt": 1,
        "plan_digest": HEX_A,
        "candidate_digest": HEX_B,
        "contract_digest": HEX_C,
        "execution_id": "execution",
        "lease_id": "lease",
        "resource_id": "runner-a",
    }
    values.update(overrides)
    return RecoveryContext(**values)


class FailureRecoveryReviewTests(unittest.TestCase):
    def test_failure_details_are_deeply_immutable(self):
        signal = FailureSignal(
            code=FailureCode.TEST_FAILURE,
            details={"nested": [{"value": "original"}], "labels": {"b", "a"}},
        )
        with self.assertRaises(TypeError):
            signal.details["nested"][0]["value"] = "changed"
        self.assertEqual(signal.details["labels"], ("a", "b"))

    def test_resource_gate_values_must_be_real_booleans(self):
        with self.assertRaisesRegex(ValueError, "resource_gate_must_be_boolean"):
            ResourceRecoveryDecision(
                resource_id="runner-b",
                qualified=1,
                healthy=True,
                authorized=True,
                cost_approved=True,
                fresh_lease=True,
                source_bound=True,
            )

    def test_reroute_cannot_select_the_failed_resource_again(self):
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        resource = ResourceRecoveryDecision(
            resource_id="runner-a",
            qualified=True,
            healthy=True,
            authorized=True,
            cost_approved=True,
            fresh_lease=True,
            source_bound=True,
        )
        decision = controller.decide(
            FailureSignal(code=FailureCode.RUNNER_UNAVAILABLE, transient=True),
            context(),
            resource_decision=resource,
        )
        self.assertEqual(decision.action, RecoveryAction.BLOCK)
        self.assertIn("alternate_resource_not_distinct", decision.reason_codes)

    def test_success_outcome_requires_actual_progress(self):
        with self.assertRaisesRegex(ValueError, "successful_outcome_requires_progress"):
            RecoveryOutcome(
                status=RecoveryOutcomeStatus.SUCCEEDED,
                progress=False,
                independently_verified=True,
            )

    def test_recovery_decision_rejects_forged_digest(self):
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        decision = controller.decide(
            FailureSignal(code=FailureCode.TEST_FAILURE), context()
        )
        with self.assertRaisesRegex(ValueError, "decision_digest_invalid"):
            replace(decision, decision_digest="forged")

    def test_blocking_action_cannot_claim_allowed(self):
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        decision = controller.decide(
            FailureSignal(code=FailureCode.TEST_FAILURE), context()
        )
        with self.assertRaisesRegex(ValueError, "blocking_recovery_cannot_be_allowed"):
            replace(decision, action=RecoveryAction.BLOCK, allowed=True)

    def test_validly_shaped_but_unissued_decision_cannot_record_outcome(self):
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        decision = controller.decide(
            FailureSignal(code=FailureCode.TEST_FAILURE), context()
        )
        forged = replace(decision, decision_digest="f" * 64)
        with self.assertRaisesRegex(ValueError, "recovery_decision_not_issued"):
            controller.record_outcome(
                forged,
                context(),
                RecoveryOutcome(status=RecoveryOutcomeStatus.FAILED, progress=False),
            )

    def test_validly_shaped_but_unissued_decision_cannot_generate_handoff(self):
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        decision = controller.decide(
            FailureSignal(code=FailureCode.TEST_FAILURE), context()
        )
        forged = replace(decision, decision_digest="e" * 64)
        with self.assertRaisesRegex(ValueError, "recovery_decision_not_issued"):
            controller.dag_handoff(forged)


if __name__ == "__main__":
    unittest.main()
