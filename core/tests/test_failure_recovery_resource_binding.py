import tempfile
import unittest
from pathlib import Path

from core.lil_tweak.failure_recovery import (
    FailureCode,
    FailureRecoveryController,
    FailureSignal,
    InMemoryRecoveryHistoryStore,
    RecoveryContext,
    ResourceRecoveryDecision,
    SQLiteRecoveryHistoryStore,
)


HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64


def context():
    return RecoveryContext(
        owner_id="owner",
        task_id="task",
        dag_run_id="run",
        node_id="execute",
        source_revision="1" * 40,
        attempt=1,
        plan_digest=HEX_A,
        candidate_digest=HEX_B,
        contract_digest=HEX_C,
        execution_id="execution",
        lease_id="lease",
        resource_id="runner-a",
    )


def alternate():
    return ResourceRecoveryDecision(
        resource_id="runner-b",
        qualified=True,
        healthy=True,
        authorized=True,
        cost_approved=True,
        fresh_lease=True,
        source_bound=True,
    )


class FailureRecoveryResourceBindingTests(unittest.TestCase):
    def test_reroute_decision_and_handoff_bind_exact_alternate_resource(self):
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        decision = controller.decide(
            FailureSignal(code=FailureCode.RUNNER_UNAVAILABLE, transient=True),
            context(),
            resource_decision=alternate(),
        )
        self.assertEqual(decision.resource_id, "runner-a")
        self.assertEqual(decision.target_resource_id, "runner-b")
        handoff = controller.dag_handoff(decision)
        self.assertEqual(handoff["resourceId"], "runner-a")
        self.assertEqual(handoff["targetResourceId"], "runner-b")

    def test_changing_target_resource_changes_decision_digest(self):
        first = FailureRecoveryController(history=InMemoryRecoveryHistoryStore()).decide(
            FailureSignal(code=FailureCode.RUNNER_UNAVAILABLE, transient=True),
            context(),
            resource_decision=alternate(),
        )
        other = ResourceRecoveryDecision(
            resource_id="runner-c",
            qualified=True,
            healthy=True,
            authorized=True,
            cost_approved=True,
            fresh_lease=True,
            source_bound=True,
        )
        second = FailureRecoveryController(history=InMemoryRecoveryHistoryStore()).decide(
            FailureSignal(code=FailureCode.RUNNER_UNAVAILABLE, transient=True),
            context(),
            resource_decision=other,
        )
        self.assertNotEqual(first.decision_digest, second.decision_digest)

    def test_sqlite_history_preserves_target_resource_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.sqlite3"
            store = SQLiteRecoveryHistoryStore(path)
            controller = FailureRecoveryController(history=store)
            decision = controller.decide(
                FailureSignal(code=FailureCode.RUNNER_UNAVAILABLE, transient=True),
                context(),
                resource_decision=alternate(),
            )
            store.close()

            reopened = SQLiteRecoveryHistoryStore(path)
            entry = reopened.list("owner")[0]
            self.assertEqual(entry.target_resource_id, "runner-b")
            self.assertTrue(reopened.contains_decision(decision))
            reopened.close()


if __name__ == "__main__":
    unittest.main()
