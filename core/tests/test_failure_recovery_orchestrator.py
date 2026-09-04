import tempfile
import unittest
from pathlib import Path

from core.lil_tweak.contracts import JobMode, JobState
from core.lil_tweak.evidence import LocalEvidenceStore
from core.lil_tweak.failure_recovery import (
    FailureRecoveryController,
    InMemoryRecoveryHistoryStore,
    RecoveryAction,
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
    def decide(self, *_args, **_kwargs):
        raise RuntimeError("recovery internals must not leak")


class FailureRecoveryOrchestratorTests(unittest.TestCase):
    def run_failure(self, error, recovery_controller):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = MemoryJobStore()
        job = store.create_job("owner", "failure", JobMode.BUILD, "Build")
        agent = FailingAgent(error)
        result = EngineeringOrchestrator(
            store=store,
            agent=agent,
            evidence_store=LocalEvidenceStore(Path(directory.name) / "evidence"),
            recovery_controller=recovery_controller,
        ).run_job(job.id, "owner")
        return store, job, agent, result

    def test_unknown_failure_is_recorded_and_job_remains_failed(self):
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        store, job, agent, result = self.run_failure(RuntimeError("secret detail"), controller)
        self.assertEqual(result.state, JobState.FAILED)
        events = store.list_events(job.id, "owner")
        recovery = next(event for event in events if event.kind == "failure_recovery_decision")
        self.assertEqual(recovery.data["action"], RecoveryAction.BLOCK.value)
        self.assertEqual(recovery.data["failure_code"], "unknown_failure")
        self.assertNotIn("secret detail", str(recovery.data))
        self.assertEqual(agent.calls, 1)

    def test_deadline_records_bounded_retry_recommendation_but_does_not_retry(self):
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        store, job, agent, result = self.run_failure(
            AgentDeadlineError("deadline"), controller
        )
        self.assertEqual(result.state, JobState.TIMED_OUT)
        recovery = next(
            event
            for event in store.list_events(job.id, "owner")
            if event.kind == "failure_recovery_decision"
        )
        self.assertEqual(recovery.data["action"], RecoveryAction.RETRY_STEP.value)
        self.assertTrue(recovery.data["allowed"])
        self.assertEqual(agent.calls, 1)

    def test_existing_behavior_is_unchanged_when_controller_is_absent(self):
        store, job, agent, result = self.run_failure(RuntimeError("boom"), None)
        self.assertEqual(result.state, JobState.FAILED)
        self.assertNotIn(
            "failure_recovery_decision",
            [event.kind for event in store.list_events(job.id, "owner")],
        )
        self.assertEqual(agent.calls, 1)

    def test_recovery_controller_failure_fails_closed_without_masking_job_failure(self):
        store, job, agent, result = self.run_failure(
            RuntimeError("boom"), BrokenRecoveryController()
        )
        self.assertEqual(result.state, JobState.FAILED)
        unavailable = next(
            event
            for event in store.list_events(job.id, "owner")
            if event.kind == "failure_recovery_unavailable"
        )
        self.assertEqual(unavailable.data, {"code": "failure_recovery_unavailable"})
        self.assertEqual(agent.calls, 1)


if __name__ == "__main__":
    unittest.main()
