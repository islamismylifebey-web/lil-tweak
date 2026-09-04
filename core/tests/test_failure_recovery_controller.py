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
        "owner_id": "owner-1",
        "task_id": "task-1",
        "dag_run_id": "run-1",
        "node_id": "execute",
        "source_revision": "1" * 40,
        "attempt": 1,
        "plan_digest": HEX_A,
        "candidate_digest": HEX_B,
        "contract_digest": HEX_C,
        "execution_id": "execution-1",
        "lease_id": "lease-1",
        "resource_id": "runner-1",
    }
    values.update(overrides)
    return RecoveryContext(**values)


def healthy_resource(**overrides):
    values = {
        "resource_id": "runner-2",
        "qualified": True,
        "healthy": True,
        "authorized": True,
        "cost_approved": True,
        "fresh_lease": True,
        "source_bound": True,
    }
    values.update(overrides)
    return ResourceRecoveryDecision(**values)


class FailureRecoveryControllerTests(unittest.TestCase):
    def setUp(self):
        self.history = InMemoryRecoveryHistoryStore()
        self.controller = FailureRecoveryController(history=self.history)

    def test_transient_timeout_gets_one_bounded_retry(self):
        decision = self.controller.decide(
            FailureSignal(code=FailureCode.TIMEOUT, transient=True), context()
        )
        self.assertEqual(decision.action, RecoveryAction.RETRY_STEP)
        self.assertTrue(decision.allowed)

    def test_test_failure_repairs_candidate(self):
        decision = self.controller.decide(
            FailureSignal(code=FailureCode.TEST_FAILURE, failed_checks=("unit",)),
            context(),
        )
        self.assertEqual(decision.action, RecoveryAction.REPAIR_CANDIDATE)
        self.assertTrue(decision.allowed)

    def test_plan_critic_failure_requires_replan(self):
        decision = self.controller.decide(
            FailureSignal(code=FailureCode.PLAN_CRITIC_FAILURE), context(node_id="plan")
        )
        self.assertEqual(decision.action, RecoveryAction.REPLAN)
        self.assertTrue(decision.allowed)

    def test_partial_mutation_requires_rollback_before_other_action(self):
        decision = self.controller.decide(
            FailureSignal(
                code=FailureCode.TEST_FAILURE,
                failed_checks=("unit",),
                partial_mutation=True,
            ),
            context(),
        )
        self.assertEqual(decision.action, RecoveryAction.ROLLBACK)
        self.assertTrue(decision.allowed)

    def test_integrity_failure_blocks_even_when_marked_transient(self):
        decision = self.controller.decide(
            FailureSignal(
                code=FailureCode.REPOSITORY_INTEGRITY_FAILURE,
                transient=True,
                integrity_failure=True,
            ),
            context(),
        )
        self.assertEqual(decision.action, RecoveryAction.BLOCK)
        self.assertFalse(decision.allowed)

    def test_missing_approval_escalates_without_execution_authority(self):
        decision = self.controller.decide(
            FailureSignal(code=FailureCode.MISSING_APPROVAL), context(approval_present=False)
        )
        self.assertEqual(decision.action, RecoveryAction.ESCALATE)
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.requires_reauthorization)

    def test_provider_failure_can_reroute_only_to_proven_resource(self):
        decision = self.controller.decide(
            FailureSignal(code=FailureCode.PROVIDER_UNHEALTHY, transient=True),
            context(),
            resource_decision=healthy_resource(),
        )
        self.assertEqual(decision.action, RecoveryAction.REROUTE_RESOURCE)
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.requires_fresh_lease)

    def test_unqualified_resource_blocks_reroute(self):
        decision = self.controller.decide(
            FailureSignal(code=FailureCode.PROVIDER_UNHEALTHY, transient=True),
            context(),
            resource_decision=healthy_resource(qualified=False),
        )
        self.assertEqual(decision.action, RecoveryAction.BLOCK)
        self.assertFalse(decision.allowed)
        self.assertIn("alternate_resource_not_qualified", decision.reason_codes)

    def test_failed_no_progress_outcome_stops_identical_strategy(self):
        first = self.controller.decide(
            FailureSignal(code=FailureCode.TIMEOUT, transient=True), context()
        )
        self.controller.record_outcome(
            first,
            context(),
            RecoveryOutcome(status=RecoveryOutcomeStatus.FAILED, progress=False),
        )
        second = self.controller.decide(
            FailureSignal(code=FailureCode.TIMEOUT, transient=True), context(attempt=2)
        )
        self.assertEqual(second.action, RecoveryAction.BLOCK)
        self.assertIn("recovery_strategy_no_progress", second.reason_codes)

    def test_successful_progress_allows_new_failure_evaluation(self):
        first = self.controller.decide(
            FailureSignal(code=FailureCode.TEST_FAILURE, failed_checks=("unit", "integration")),
            context(),
        )
        self.controller.record_outcome(
            first,
            context(),
            RecoveryOutcome(
                status=RecoveryOutcomeStatus.FAILED,
                progress=True,
                remaining_failed_checks=("integration",),
                resulting_candidate_digest="d" * 64,
            ),
        )
        second = self.controller.decide(
            FailureSignal(code=FailureCode.TEST_FAILURE, failed_checks=("integration",)),
            context(attempt=2, candidate_digest="d" * 64),
        )
        self.assertEqual(second.action, RecoveryAction.REPAIR_CANDIDATE)
        self.assertTrue(second.allowed)

    def test_record_outcome_rejects_wrong_context_binding(self):
        decision = self.controller.decide(
            FailureSignal(code=FailureCode.TEST_FAILURE), context()
        )
        with self.assertRaisesRegex(ValueError, "recovery_decision_binding_mismatch"):
            self.controller.record_outcome(
                decision,
                context(task_id="other-task"),
                RecoveryOutcome(
                    status=RecoveryOutcomeStatus.SUCCEEDED,
                    progress=True,
                    independently_verified=True,
                ),
            )

    def test_history_is_owner_isolated_and_monotonic(self):
        first = self.controller.decide(
            FailureSignal(code=FailureCode.TEST_FAILURE), context(owner_id="owner-a")
        )
        second = self.controller.decide(
            FailureSignal(code=FailureCode.BUILD_FAILURE),
            context(owner_id="owner-a", task_id="task-2"),
        )
        other = self.controller.decide(
            FailureSignal(code=FailureCode.TEST_FAILURE), context(owner_id="owner-b")
        )
        self.assertEqual([item.sequence for item in self.history.list("owner-a")], [1, 2])
        self.assertEqual([item.sequence for item in self.history.list("owner-b")], [1])
        self.assertNotEqual(first.decision_digest, second.decision_digest)
        self.assertNotEqual(first.decision_digest, other.decision_digest)

    def test_dag_handoff_is_typed_and_has_no_execution_authority(self):
        decision = self.controller.decide(
            FailureSignal(code=FailureCode.TEST_FAILURE), context()
        )
        handoff = self.controller.dag_handoff(decision)
        self.assertEqual(handoff["schemaVersion"], "failure-recovery-handoff-v1")
        self.assertFalse(handoff["mayExecute"])
        self.assertFalse(handoff["mayAuthorize"])
        self.assertEqual(handoff["decisionDigest"], decision.decision_digest)


if __name__ == "__main__":
    unittest.main()
