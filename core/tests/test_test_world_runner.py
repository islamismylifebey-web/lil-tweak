import unittest

from core.lil_tweak.openai_agent import AgentResult
from core.lil_tweak.test_world import AttemptStatus, MemoryTestWorldStore, TestCheck, WorldStatus
from core.lil_tweak.test_world_runner import TestWorldAttemptRunner


OWNER = "0123456789abcdef0123456789abcdef"


class FakeRuntime:
    def __init__(self):
        self.prepared = []
        self.replayed = []
        self.prompts = []
        self.check_calls = []
        self.cleaned = []
        self.patch_values = []
        self.check_results = []
        self.agent_results = []

    def prepare_workspace(self, world, attempt):
        workspace = f"workspace-{attempt.number}"
        self.prepared.append((world.id, attempt.id, workspace))
        return workspace

    def apply_previous_patch(self, workspace, patch):
        self.replayed.append((workspace, patch))

    def run_agent(self, workspace, prompt):
        self.prompts.append((workspace, prompt))
        return self.agent_results.pop(0)

    def capture_cumulative_patch(self, workspace):
        return self.patch_values.pop(0)

    def run_check(self, workspace, check):
        self.check_calls.append((workspace, check.name, check.command, check.timeout_seconds))
        return self.check_results.pop(0)

    def cleanup_workspace(self, workspace):
        self.cleaned.append(workspace)


class TestWorldAttemptRunnerTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryTestWorldStore(clock=lambda: 1786636800.0)
        self.runtime = FakeRuntime()
        self.world = self.store.create_world(
            OWNER,
            idempotency_key="world",
            name="Practice repair",
            objective="Repair the broken behavior without changing unrelated code.",
            repository_url="https://github.com/example/project.git",
            commit="a" * 40,
            checks=(TestCheck("unit tests", ("python3", "-m", "unittest"), 60),),
            max_attempts=3,
        )
        self.runner = TestWorldAttemptRunner(
            store=self.store,
            worker_id="test-worker",
            lease_seconds=60,
            prepare_workspace=self.runtime.prepare_workspace,
            apply_previous_patch=self.runtime.apply_previous_patch,
            run_agent=self.runtime.run_agent,
            capture_cumulative_patch=self.runtime.capture_cumulative_patch,
            run_check=self.runtime.run_check,
            cleanup_workspace=self.runtime.cleanup_workspace,
            clock=lambda: 100.0,
        )

    def enqueue(self, number):
        return self.store.enqueue_attempt(
            self.world.id,
            OWNER,
            idempotency_key=f"attempt-{number}",
        )

    def test_deterministic_judge_overrides_agent_self_report(self):
        attempt = self.enqueue(1)
        self.runtime.agent_results.append(
            AgentResult("Fix it", "Looks good", "all tests passed", "", model_calls=2, total_tokens=150)
        )
        self.runtime.patch_values.append("cumulative patch one")
        self.runtime.check_results.append(
            {
                "passed": False,
                "exitCode": 1,
                "timedOut": False,
                "truncated": False,
                "stdout": "FAILED test_example",
                "stderr": "",
            }
        )

        completed = self.runner.run_attempt(attempt.id, OWNER)

        self.assertEqual(completed.status, AttemptStatus.FAILED)
        self.assertEqual(self.store.get_world(self.world.id, OWNER).status, WorldStatus.FAILED)
        self.assertEqual(completed.feedback[0]["check"], "unit tests")
        self.assertFalse(completed.feedback[0]["passed"])
        self.assertEqual(completed.summary, "Looks good")
        self.assertEqual(completed.total_tokens, 150)
        self.assertEqual(self.runtime.cleaned, ["workspace-1"])

    def test_retry_replays_previous_cumulative_patch_and_supplies_bounded_feedback(self):
        first = self.enqueue(1)
        self.runtime.agent_results.append(AgentResult("First plan", "First result", "failed", ""))
        self.runtime.patch_values.append("first cumulative patch")
        self.runtime.check_results.append(
            {
                "passed": False,
                "exitCode": 2,
                "timedOut": False,
                "truncated": False,
                "stdout": "expected 2 got 1",
                "stderr": "",
            }
        )
        self.runner.run_attempt(first.id, OWNER)

        second = self.enqueue(2)
        self.runtime.agent_results.append(AgentResult("Second plan", "Repaired", "passed", ""))
        self.runtime.patch_values.append("second cumulative patch")
        self.runtime.check_results.append(
            {
                "passed": True,
                "exitCode": 0,
                "timedOut": False,
                "truncated": False,
                "stdout": "OK",
                "stderr": "",
            }
        )

        completed = self.runner.run_attempt(second.id, OWNER)

        self.assertEqual(self.runtime.replayed, [("workspace-2", "first cumulative patch")])
        retry_prompt = self.runtime.prompts[-1][1]
        self.assertIn("Repair the broken behavior", retry_prompt)
        self.assertIn("Previous attempt feedback", retry_prompt)
        self.assertIn("unit tests", retry_prompt)
        self.assertIn("expected 2 got 1", retry_prompt)
        self.assertEqual(completed.status, AttemptStatus.PASSED)
        self.assertEqual(self.store.get_world(self.world.id, OWNER).status, WorldStatus.PASSED)
        self.assertEqual(completed.cumulative_patch, "second cumulative patch")

    def test_all_configured_checks_must_pass(self):
        world = self.store.create_world(
            OWNER,
            idempotency_key="world-two-checks",
            name="Two checks",
            objective="Pass both checks",
            repository_url="https://github.com/example/project.git",
            commit="b" * 40,
            checks=(
                TestCheck("unit", ("python3", "-m", "unittest"), 60),
                TestCheck("lint", ("npm", "run", "lint"), 120),
            ),
            max_attempts=2,
        )
        attempt = self.store.enqueue_attempt(world.id, OWNER, idempotency_key="two-check-attempt")
        self.runtime.agent_results.append(AgentResult("Plan", "Done", "done", ""))
        self.runtime.patch_values.append("patch")
        self.runtime.check_results.extend(
            [
                {"passed": True, "exitCode": 0, "timedOut": False, "truncated": False, "stdout": "ok", "stderr": ""},
                {"passed": False, "exitCode": 1, "timedOut": False, "truncated": False, "stdout": "", "stderr": "lint failed"},
            ]
        )

        result = self.runner.run_attempt(attempt.id, OWNER)

        self.assertEqual(result.status, AttemptStatus.FAILED)
        self.assertEqual([item[1] for item in self.runtime.check_calls[-2:]], ["unit", "lint"])
        self.assertEqual(len(result.feedback), 2)

    def test_runtime_failure_is_persisted_as_error_and_workspace_is_cleaned(self):
        attempt = self.enqueue(1)

        def broken_agent(_workspace, _prompt):
            raise RuntimeError("host secret detail must not escape")

        self.runner.run_agent = broken_agent
        completed = self.runner.run_attempt(attempt.id, OWNER)

        self.assertEqual(completed.status, AttemptStatus.ERROR)
        self.assertEqual(completed.outcome, "error")
        self.assertEqual(completed.feedback, ({"code": "attempt_runtime_failed"},))
        self.assertNotIn("secret", completed.summary.lower())
        self.assertEqual(self.runtime.cleaned, ["workspace-1"])
        self.assertEqual(self.store.get_world(self.world.id, OWNER).status, WorldStatus.FAILED)


if __name__ == "__main__":
    unittest.main()
