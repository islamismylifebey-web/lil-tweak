import tempfile
import threading
import unittest
from pathlib import Path

from core.lil_tweak.failure_recovery import (
    FailureCode,
    FailureRecoveryController,
    FailureSignal,
    RecoveryContext,
    RecoveryOutcome,
    RecoveryOutcomeStatus,
    SQLiteRecoveryHistoryStore,
)


HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64


def context(task_id="task", attempt=1):
    return RecoveryContext(
        owner_id="owner",
        task_id=task_id,
        dag_run_id=f"run:{task_id}",
        node_id="execute",
        source_revision="1" * 40,
        attempt=attempt,
        plan_digest=HEX_A,
        candidate_digest=HEX_B,
        contract_digest=HEX_C,
    )


class SQLiteRecoveryHistoryTests(unittest.TestCase):
    def test_history_survives_reopen_and_preserves_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recovery.sqlite3"
            store = SQLiteRecoveryHistoryStore(path)
            controller = FailureRecoveryController(history=store)
            decision = controller.decide(
                FailureSignal(code=FailureCode.TEST_FAILURE), context()
            )
            controller.record_outcome(
                decision,
                context(),
                RecoveryOutcome(
                    status=RecoveryOutcomeStatus.SUCCEEDED,
                    progress=True,
                    independently_verified=True,
                    resulting_candidate_digest="d" * 64,
                ),
            )
            store.close()

            reopened = SQLiteRecoveryHistoryStore(path)
            entries = reopened.list("owner")
            self.assertEqual([entry.sequence for entry in entries], [1, 2])
            self.assertIsNone(entries[0].outcome_status)
            self.assertEqual(entries[1].outcome_status, RecoveryOutcomeStatus.SUCCEEDED)
            self.assertEqual(entries[1].resulting_candidate_digest, "d" * 64)
            reopened.close()

    def test_concurrent_decisions_have_unique_monotonic_sequences(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteRecoveryHistoryStore(Path(directory) / "history.sqlite3")
            controller = FailureRecoveryController(history=store)
            errors = []

            def decide(index):
                try:
                    controller.decide(
                        FailureSignal(code=FailureCode.TEST_FAILURE),
                        context(task_id=f"task-{index}"),
                    )
                except Exception as error:  # pragma: no cover - asserted below
                    errors.append(error)

            threads = [threading.Thread(target=decide, args=(index,)) for index in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual(errors, [])
            self.assertEqual(
                [entry.sequence for entry in store.list("owner")],
                list(range(1, 9)),
            )
            store.close()

    def test_store_has_no_mutating_history_rewrite_surface(self):
        store = SQLiteRecoveryHistoryStore(":memory:")
        self.assertFalse(hasattr(store, "update"))
        self.assertFalse(hasattr(store, "delete"))
        self.assertFalse(hasattr(store, "clear"))
        store.close()


if __name__ == "__main__":
    unittest.main()
