import tempfile
import unittest
from pathlib import Path

from core.lil_tweak.contracts import JobMode, JobState
from core.lil_tweak.evidence import LocalEvidenceStore
from core.lil_tweak.failure_recovery import (
    FailureRecoveryController,
    InMemoryRecoveryHistoryStore,
    RecoveryAction,
    RecoveryAwareEngineeringOrchestrator,
)
from core.lil_tweak.openai_agent import AgentDeadlineError
from core.lil_tweak.orchestrator import EngineeringOrchestrator
from core.lil_tweak.store import MemoryJobStore


class FailingAgent:
    tools = None

    def __init__(self, error):
        self.error = error
        self.calls = 0

    def run(self, **_kwargs):
        self.calls += 1
        raise self.error


class BrokenRecoveryController:
    def signal_from_exception(self, _error):
        raise RuntimeError("recovery internals must not leak")


class FailureRecoveryOrchestratorTests(unittest.TestCase):
    def run_failure(self, error, recovery_controller):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = MemoryJobStore()
        job = store.create_job("owner", "failure", JobMode.BUILD, "Build")
        agent = FailingAgent(error)
        common = {
            "store": store,
            "agent": agent,
            "evidence_store": LocalEvidenceStore(Path(directory.name) / "evidence"),
        }
        if recovery_controller is None:
            orchestrator = EngineeringOrchestrator(**common)
        else:
            orchestrator = RecoveryAwareEngineeringOrchestrator(
                **common,
                recovery_controller=recovery_controller,
            )
        result = orchestrator.run_job(job.id, "owner")
        return store, job, agent, orchestrator, result

    def test_unknown_failure_is_recorded_and_job_remains_failed(self):
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        _store, _job, agent, orchestrator, result = self.run_failure(
            RuntimeError("secret detail"), controller
        )
        self.assertEqual(result.state, JobState.FAILED)
        decision = orchestrator.last_recovery_decision
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, RecoveryAction.BLOCK)
        self.assertEqual(decision.failure_code.value, "unknown_failure")
        self.assertNotIn("secret detail", str(decision))
        self.assertEqual(len(controller.history.list("owner")), 1)
        self.assertEqual(agent.calls, 1)

    def test_deadline_records_bounded_retry_recommendation_but_does_not_retry(self):
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        _store, _job, agent, orchestrator, result = self.run_failure(
            AgentDeadlineError("deadline"), controller
        )
        self.assertEqual(result.state, JobState.TIMED_OUT)
        decision = orchestrator.last_recovery_decision
        self.assertIsNotNone(decision)
        self.assertEqual(decision.action, RecoveryAction.RETRY_STEP)
        self.assertTrue(decision.allowed)
        self.assertEqual(agent.calls, 1)

    def test_existing_behavior_is_unchanged_when_controller_is_absent(self):
        store, job, agent, orchestrator, result = self.run_failure(
            RuntimeError("boom"), None
        )
        self.assertIsInstance(orchestrator, EngineeringOrchestrator)
        self.assertEqual(result.state, JobState.FAILED)
        self.assertNotIn(
            "failure_recovery_decision",
            [event.kind for event in store.list_events(job.id, "owner")],
        )
        self.assertEqual(agent.calls, 1)

    def test_recovery_controller_failure_fails_closed_without_masking_job_failure(self):
        _store, _job, agent, orchestrator, result = self.run_failure(
            RuntimeError("boom"), BrokenRecoveryController()
        )
        self.assertEqual(result.state, JobState.FAILED)
        self.assertTrue(orchestrator.recovery_unavailable)
        self.assertIsNone(orchestrator.last_recovery_decision)
        self.assertEqual(agent.calls, 1)


if __name__ == "__main__":
    unittest.main()
