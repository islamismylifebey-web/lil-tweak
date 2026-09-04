import unittest
from dataclasses import replace

from core.lil_tweak.contracts import JobMode
from core.lil_tweak.failure_recovery import (
    FailureCode,
    FailureRecoveryController,
    FailureSignal,
    InMemoryRecoveryHistoryStore,
    RecoveryAwareEngineeringOrchestrator,
    RecoveryContext,
    RecoveryOutcome,
    RecoveryOutcomeStatus,
    failure_fingerprint,
)
from core.lil_tweak.store import GitSourceSpec, MemoryJobStore


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
        "execution_id": "execution-1",
        "lease_id": "lease-1",
        "resource_id": "runner-a",
    }
    values.update(overrides)
    return RecoveryContext(**values)


class FailureRecoveryFinalReviewTests(unittest.TestCase):
    def test_retry_attempt_ids_do_not_change_causal_fingerprint(self):
        signal = FailureSignal(code=FailureCode.TIMEOUT, transient=True)
        first = context()
        retry = context(attempt=2, execution_id="execution-2", lease_id="lease-2")
        self.assertEqual(
            failure_fingerprint(signal, first),
            failure_fingerprint(signal, retry),
        )

    def test_missing_remaining_check_evidence_is_not_progress(self):
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        first_context = context()
        decision = controller.decide(
            FailureSignal(code=FailureCode.TEST_FAILURE, failed_checks=("unit",)),
            first_context,
        )
        entry = controller.record_outcome(
            decision,
            first_context,
            RecoveryOutcome(status=RecoveryOutcomeStatus.FAILED, progress=False),
        )
        self.assertFalse(entry.progress)
        retry = controller.decide(
            FailureSignal(code=FailureCode.TEST_FAILURE, failed_checks=("unit",)),
            context(attempt=2, execution_id="execution-2", lease_id="lease-2"),
        )
        self.assertIn("recovery_strategy_no_progress", retry.reason_codes)

    def test_non_reroute_cannot_claim_progress_from_another_resource(self):
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        current = context()
        decision = controller.decide(
            FailureSignal(code=FailureCode.TEST_FAILURE, failed_checks=("unit",)),
            current,
        )
        with self.assertRaisesRegex(ValueError, "recovery_outcome_resource_not_authorized"):
            controller.record_outcome(
                decision,
                current,
                RecoveryOutcome(
                    status=RecoveryOutcomeStatus.FAILED,
                    progress=True,
                    resulting_resource_id="runner-unapproved",
                ),
            )

    def test_final_captured_source_digest_outranks_declared_git_commit(self):
        store = MemoryJobStore()
        job = store.create_job("owner", "source", JobMode.BUILD, "Build")
        bound = replace(
            job,
            source_digest="3" * 64,
            git_source=GitSourceSpec(
                repository_url="https://github.com/example/example.git",
                commit="2" * 40,
            ),
        )
        adapter = object.__new__(RecoveryAwareEngineeringOrchestrator)
        adapter.lease = None
        self.assertEqual(adapter._context(bound).source_revision, "3" * 64)


if __name__ == "__main__":
    unittest.main()
