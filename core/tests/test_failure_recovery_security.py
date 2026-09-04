import unittest

from core.lil_tweak.failure_recovery import (
    FailureCode,
    FailureRecoveryController,
    FailureSignal,
    InMemoryRecoveryHistoryStore,
    RecoveryAction,
    RecoveryBudgets,
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


class FailureRecoverySecurityTests(unittest.TestCase):
    def setUp(self):
        self.controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())

    def test_model_requested_retry_cannot_override_security_failure(self):
        decision = self.controller.decide(
            FailureSignal(
                code=FailureCode.SECURITY_CHECK_FAILURE,
                security_sensitive=True,
                details={"modelRequestedAction": "retry_step"},
            ),
            context(),
        )
        self.assertEqual(decision.action, RecoveryAction.BLOCK)
        self.assertFalse(decision.allowed)

    def test_expired_lease_blocks(self):
        decision = self.controller.decide(
            FailureSignal(code=FailureCode.LEASE_EXPIRED, transient=True), context()
        )
        self.assertEqual(decision.action, RecoveryAction.BLOCK)
        self.assertTrue(decision.requires_fresh_lease)

    def test_replayed_lease_blocks(self):
        decision = self.controller.decide(
            FailureSignal(code=FailureCode.LEASE_REPLAYED, transient=True), context()
        )
        self.assertEqual(decision.action, RecoveryAction.BLOCK)
        self.assertIn("lease_replayed", decision.reason_codes)

    def test_wrong_digest_binding_blocks(self):
        decision = self.controller.decide(
            FailureSignal(code=FailureCode.WRONG_DIGEST_BINDING), context()
        )
        self.assertEqual(decision.action, RecoveryAction.BLOCK)
        self.assertTrue(decision.requires_reauthorization)

    def test_stale_source_requires_new_authority(self):
        decision = self.controller.decide(
            FailureSignal(code=FailureCode.STALE_SOURCE), context()
        )
        self.assertEqual(decision.action, RecoveryAction.ESCALATE)
        self.assertTrue(decision.requires_reauthorization)

    def test_resource_reroute_requires_every_gate(self):
        fields = {
            "qualified": True,
            "healthy": True,
            "authorized": True,
            "cost_approved": True,
            "fresh_lease": True,
            "source_bound": True,
        }
        for gate in tuple(fields):
            with self.subTest(gate=gate):
                denied = dict(fields)
                denied[gate] = False
                resource = ResourceRecoveryDecision(resource_id="runner-b", **denied)
                decision = self.controller.decide(
                    FailureSignal(code=FailureCode.RUNNER_UNAVAILABLE, transient=True),
                    context(),
                    resource_decision=resource,
                )
                self.assertEqual(decision.action, RecoveryAction.BLOCK)
                self.assertFalse(decision.allowed)

    def test_same_fingerprint_retry_budget_is_fail_closed(self):
        controller = FailureRecoveryController(
            history=InMemoryRecoveryHistoryStore(),
            budgets=RecoveryBudgets(max_node_retries=2, max_fingerprint_retries=1),
        )
        first = controller.decide(
            FailureSignal(code=FailureCode.TIMEOUT, transient=True), context()
        )
        controller.record_outcome(
            first,
            context(),
            RecoveryOutcome(status=RecoveryOutcomeStatus.FAILED, progress=True),
        )
        second = controller.decide(
            FailureSignal(code=FailureCode.TIMEOUT, transient=True), context(attempt=2)
        )
        self.assertEqual(second.action, RecoveryAction.BLOCK)
        self.assertIn("fingerprint_retry_budget_exhausted", second.reason_codes)

    def test_rollback_failure_never_retries(self):
        decision = self.controller.decide(
            FailureSignal(code=FailureCode.ROLLBACK_FAILED, transient=True), context()
        )
        self.assertEqual(decision.action, RecoveryAction.BLOCK)
        self.assertIn("rollback_failed", decision.reason_codes)

    def test_self_declared_recovery_is_not_success_evidence(self):
        decision = self.controller.decide(
            FailureSignal(code=FailureCode.TEST_FAILURE), context()
        )
        with self.assertRaisesRegex(ValueError, "verified_outcome_required"):
            self.controller.record_outcome(
                decision,
                context(),
                RecoveryOutcome(
                    status=RecoveryOutcomeStatus.SUCCEEDED,
                    progress=True,
                    independently_verified=False,
                ),
            )

    def test_controller_exposes_no_execute_method(self):
        self.assertFalse(hasattr(self.controller, "execute"))
        self.assertFalse(hasattr(self.controller, "run_command"))
        self.assertFalse(hasattr(self.controller, "select_provider"))


if __name__ == "__main__":
    unittest.main()
