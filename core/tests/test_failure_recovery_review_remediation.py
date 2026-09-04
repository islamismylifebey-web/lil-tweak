import tempfile
import unittest
from pathlib import Path

from core.lil_tweak.contracts import JobMode, JobState
from core.lil_tweak.evidence import LocalEvidenceStore
from core.lil_tweak.failure_recovery import (
    FailureCode,
    FailureRecoveryController,
    FailureSignal,
    InMemoryRecoveryHistoryStore,
    RecoveryAction,
    RecoveryAwareEngineeringOrchestrator,
    RecoveryContext,
    RecoveryOutcome,
    RecoveryOutcomeStatus,
)
from core.lil_tweak.openai_agent import AgentResult
from core.lil_tweak.store import MemoryJobStore


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


class Agent:
    def __init__(self, *, result=None, error=None, tools=None):
        self.result = result
        self.error = error
        self.tools = tools
        self.calls = 0

    def run(self, **_kwargs):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result


class TimedOutTools:
    command_observations = (
        {
            "operation": "run_command",
            "command": ["python", "-m", "unittest"],
            "exit_code": None,
            "timed_out": True,
            "truncated": False,
            "stdout": "",
            "stderr": "",
        },
    )
    edit_journal = ()


class FailingEvidenceStore:
    def put(self, *_args, **_kwargs):
        raise RuntimeError("evidence write failed")


class FailureRecoveryReviewRemediationTests(unittest.TestCase):
    def test_partial_mutation_never_discards_authority_requirements(self):
        for code in (
            FailureCode.MISSING_APPROVAL,
            FailureCode.STALE_APPROVAL,
            FailureCode.STALE_SOURCE,
        ):
            with self.subTest(code=code):
                controller = FailureRecoveryController(
                    history=InMemoryRecoveryHistoryStore()
                )
                decision = controller.decide(
                    FailureSignal(code=code, partial_mutation=True),
                    context(approval_present=True),
                )
                self.assertFalse(decision.allowed)
                self.assertNotEqual(decision.action, RecoveryAction.ROLLBACK)
                self.assertTrue(decision.requires_reauthorization)

    def test_failed_outcome_cannot_self_declare_progress(self):
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        decision = controller.decide(
            FailureSignal(
                code=FailureCode.TEST_FAILURE,
                failed_checks=("unit", "integration"),
            ),
            context(),
        )
        with self.assertRaisesRegex(ValueError, "unsupported_recovery_progress"):
            controller.record_outcome(
                decision,
                context(),
                RecoveryOutcome(
                    status=RecoveryOutcomeStatus.FAILED,
                    progress=True,
                    remaining_failed_checks=("unit", "integration"),
                ),
            )

    def test_failed_check_reduction_is_derived_as_progress(self):
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        decision = controller.decide(
            FailureSignal(
                code=FailureCode.TEST_FAILURE,
                failed_checks=("unit", "integration"),
            ),
            context(),
        )
        entry = controller.record_outcome(
            decision,
            context(),
            RecoveryOutcome(
                status=RecoveryOutcomeStatus.FAILED,
                progress=False,
                remaining_failed_checks=("integration",),
            ),
        )
        self.assertTrue(entry.progress)

    def _run_orchestrator(self, *, agent, evidence_store=None):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = MemoryJobStore()
        job = store.create_job("owner", "review", JobMode.BUILD, "Build")
        controller = FailureRecoveryController(history=InMemoryRecoveryHistoryStore())
        orchestrator = RecoveryAwareEngineeringOrchestrator(
            store=store,
            agent=agent,
            evidence_store=evidence_store
            or LocalEvidenceStore(Path(directory.name) / "evidence"),
            recovery_controller=controller,
        )
        result = orchestrator.run_job(job.id, "owner")
        return result, orchestrator, controller

    def test_agent_failure_decision_uses_final_ingested_source_digest(self):
        result, orchestrator, _controller = self._run_orchestrator(
            agent=Agent(error=RuntimeError("agent failed"))
        )
        self.assertEqual(result.state, JobState.FAILED)
        self.assertIsNotNone(result.source_digest)
        self.assertEqual(
            orchestrator.last_recovery_decision.source_revision,
            result.source_digest,
        )

    def test_failure_outside_agent_call_still_gets_recovery_decision(self):
        result, orchestrator, _controller = self._run_orchestrator(
            agent=Agent(result=AgentResult("Plan", "Done", "", "")),
            evidence_store=FailingEvidenceStore(),
        )
        self.assertEqual(result.state, JobState.FAILED)
        self.assertIsNotNone(orchestrator.last_recovery_decision)
        self.assertEqual(
            orchestrator.last_recovery_decision.source_revision,
            result.source_digest,
        )

    def test_observed_command_timeout_gets_recovery_decision(self):
        result, orchestrator, _controller = self._run_orchestrator(
            agent=Agent(
                result=AgentResult("Plan", "Timed out", "", ""),
                tools=TimedOutTools(),
            )
        )
        self.assertEqual(result.state, JobState.TIMED_OUT)
        self.assertIsNotNone(orchestrator.last_recovery_decision)
        self.assertEqual(
            orchestrator.last_recovery_decision.failure_code,
            FailureCode.TIMEOUT,
        )
        self.assertEqual(
            orchestrator.last_recovery_decision.source_revision,
            result.source_digest,
        )


if __name__ == "__main__":
    unittest.main()
