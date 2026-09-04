import unittest

from core.lil_tweak.failure_recovery import (
    EvidenceRef,
    FailureCode,
    FailureRecoveryController,
    FailureSignal,
    InMemoryRecoveryHistoryStore,
    RecoveryAction,
    RecoveryBudgets,
    RecoveryContext,
    RecoveryDisposition,
    failure_fingerprint,
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


class FailureRecoveryContractTests(unittest.TestCase):
    def test_safe_default_budgets_are_bounded(self):
        budgets = RecoveryBudgets()
        self.assertEqual(budgets.max_node_retries, 2)
        self.assertEqual(budgets.max_fingerprint_retries, 1)
        self.assertEqual(budgets.max_full_replans, 2)
        self.assertEqual(budgets.max_candidate_repairs, 2)
        self.assertEqual(budgets.max_resource_reroutes, 1)
        self.assertEqual(budgets.max_rollbacks, 1)

    def test_budget_cannot_exceed_hard_maximum(self):
        with self.assertRaisesRegex(ValueError, "recovery_budget_exceeds_hard_limit"):
            RecoveryBudgets(max_rollbacks=2)

    def test_context_rejects_invalid_digest(self):
        with self.assertRaisesRegex(ValueError, "plan_digest_invalid"):
            context(plan_digest="not-a-digest")

    def test_context_requires_positive_attempt(self):
        with self.assertRaisesRegex(ValueError, "attempt_must_be_positive"):
            context(attempt=0)

    def test_evidence_reference_requires_sha256(self):
        with self.assertRaisesRegex(ValueError, "evidence_digest_invalid"):
            EvidenceRef("evidence-1", "test", "bad")

    def test_same_failure_has_same_fingerprint(self):
        first = FailureSignal(
            code=FailureCode.TEST_FAILURE,
            exception_type="AssertionError",
            message="first prose",
            failed_checks=("unit",),
            evidence=(EvidenceRef("e1", "test", HEX_A),),
        )
        second = FailureSignal(
            code=FailureCode.TEST_FAILURE,
            exception_type="AssertionError",
            message="different prose must not change identity",
            failed_checks=("unit",),
            evidence=(EvidenceRef("e1", "test", HEX_A),),
        )
        self.assertEqual(failure_fingerprint(first, context()), failure_fingerprint(second, context()))

    def test_materially_different_failure_changes_fingerprint(self):
        first = FailureSignal(code=FailureCode.TEST_FAILURE, failed_checks=("unit",))
        second = FailureSignal(code=FailureCode.BUILD_FAILURE, failed_checks=("build",))
        self.assertNotEqual(
            failure_fingerprint(first, context()),
            failure_fingerprint(second, context()),
        )

    def test_fingerprint_is_source_bound(self):
        signal = FailureSignal(code=FailureCode.TEST_FAILURE, failed_checks=("unit",))
        self.assertNotEqual(
            failure_fingerprint(signal, context(source_revision="1" * 40)),
            failure_fingerprint(signal, context(source_revision="2" * 40)),
        )

    def test_unknown_failure_fails_closed(self):
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        decision = controller.decide(FailureSignal(code="future_unmapped_failure"), context())
        self.assertEqual(decision.action, RecoveryAction.BLOCK)
        self.assertEqual(decision.disposition, RecoveryDisposition.NON_RECOVERABLE)
        self.assertFalse(decision.allowed)
        self.assertIn("unknown_failure", decision.reason_codes)


if __name__ == "__main__":
    unittest.main()
