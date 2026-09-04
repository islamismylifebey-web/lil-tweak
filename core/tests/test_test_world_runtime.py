import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.lil_tweak.openai_agent import AgentResult
from core.lil_tweak.sandbox import CommandResult, SandboxLimits, build_podman_argv
from core.lil_tweak.test_world import MemoryTestWorldStore, TestCheck
from core.lil_tweak.test_world_api import _attempt_json, _world_json
from core.lil_tweak.test_world_runner import TestWorldAttemptRunner
from core.lil_tweak.test_world_runtime import TestWorldRuntime


OWNER = "0123456789abcdef0123456789abcdef"
CANARIES = (
    "sk-testworld-CANARY-OPENAI-90125",
    "CANARY-SIGNING-445566",
    "postgres://CANARY-DATABASE-778899",
)


class FakeSnapshot:
    def __init__(self, label):
        self.label = label


class FakeSandbox:
    lifecycle_failed = False

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.teardown_called = False

    def teardown(self):
        self.teardown_called = True


class FakeTools:
    def __init__(self, root, sandbox):
        self.root = Path(root)
        self.sandbox = sandbox
        self.applied = []
        self.commands = []

    def execute(self, name, arguments):
        if name == "apply_patch":
            self.applied.append(arguments["patch"])
            return {
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
                "truncated": False,
                "promoted": True,
            }
        if name == "run_command":
            self.commands.append((tuple(arguments["command"]), arguments["timeout"]))
            return {
                "exit_code": 0,
                "stdout": "ok",
                "stderr": "",
                "timed_out": False,
                "truncated": False,
            }
        raise AssertionError(name)


class FakeAgent:
    def __init__(self, _client, tools, *, model, instructions):
        self.tools = tools
        self.model = model
        self.instructions = instructions
        self.calls = []

    def run(self, **kwargs):
        self.calls.append(kwargs)
        return AgentResult(
            plan="repair",
            summary="done",
            tests="judge owns truth",
            patch="",
            model_calls=1,
            input_tokens=20,
            output_tokens=10,
            total_tokens=30,
        )


class TestWorldRuntimeTests(unittest.TestCase):
    def test_runtime_reuses_git_sandbox_tools_agent_and_builds_host_observed_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = {"ingest": [], "capture": [], "patch": [], "sandboxes": [], "agents": []}

            def ingest(source, destination, *, allowed_hosts):
                calls["ingest"].append((source.repository_url, source.commit, Path(destination), tuple(allowed_hosts)))
                Path(destination, "app.py").write_text("print('safe')\n")
                return ["app.py"]

            def capture(path):
                calls["capture"].append(Path(path))
                return FakeSnapshot(f"snap-{len(calls['capture'])}")

            def build_patch(before, after):
                calls["patch"].append((before.label, after.label))
                return b"--- a/app.py\n+++ b/app.py\n"

            def sandbox_factory(**kwargs):
                value = FakeSandbox(**kwargs)
                calls["sandboxes"].append(value)
                return value

            def agent_factory(*args, **kwargs):
                value = FakeAgent(*args, **kwargs)
                calls["agents"].append(value)
                return value

            runtime = TestWorldRuntime(
                work_root=root,
                runner_image="registry.example/runner@sha256:" + "a" * 64,
                git_allowed_hosts=("github.com",),
                responses_client=object(),
                model="gpt-test",
                instructions="reviewed instructions",
                job_timeout_seconds=900,
                ingest_git=ingest,
                capture_workspace=capture,
                build_workspace_patch=build_patch,
                sandbox_factory=sandbox_factory,
                tools_factory=FakeTools,
                agent_factory=agent_factory,
            )
            store = MemoryTestWorldStore()
            world = store.create_world(
                OWNER,
                idempotency_key="world",
                name="Runtime",
                objective="Repair the code",
                repository_url="https://github.com/example/project.git",
                commit="b" * 40,
                checks=(TestCheck("unit", ("python3", "-m", "unittest"), 60),),
                max_attempts=2,
            )
            attempt = store.enqueue_attempt(world.id, OWNER, idempotency_key="attempt")

            workspace = runtime.prepare_workspace(world, attempt)
            result = runtime.run_agent(workspace, "bounded prompt")
            patch_text = runtime.capture_cumulative_patch(workspace)
            check = runtime.run_check(workspace, world.checks[0])
            runtime.cleanup_workspace(workspace)

            self.assertEqual(result.summary, "done")
            self.assertEqual(patch_text, "--- a/app.py\n+++ b/app.py\n")
            self.assertTrue(check["passed"])
            self.assertEqual(check["exitCode"], 0)
            self.assertEqual(calls["ingest"][0][:2], (world.repository_url, world.commit))
            self.assertEqual(calls["patch"], [("snap-1", "snap-2")])
            self.assertEqual(calls["agents"][0].calls[0]["source_inventory"], ["app.py"])
            self.assertTrue(calls["sandboxes"][0].teardown_called)
            self.assertFalse(Path(workspace).exists())

    def test_secret_canaries_never_cross_the_runtime_or_public_evidence_boundary(self):
        host_environment = {
            "OPENAI_API_KEY": CANARIES[0],
            "LIL_TWEAK_SIGNING_KEY": CANARIES[1],
            "DATABASE_URL": CANARIES[2],
        }
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, host_environment, clear=False):
            root = Path(directory)
            observed = {"sandbox": [], "agent": []}

            def ingest(_source, destination, *, allowed_hosts):
                self.assertEqual(tuple(allowed_hosts), ("github.com",))
                Path(destination, "safe.txt").write_text("safe\n")
                return ["safe.txt"]

            snapshots = iter((FakeSnapshot("baseline"), FakeSnapshot("final")))

            def sandbox_factory(**kwargs):
                observed["sandbox"].append(kwargs)
                return FakeSandbox(**kwargs)

            class CanaryAgent(FakeAgent):
                def run(self, **kwargs):
                    observed["agent"].append(kwargs)
                    return super().run(**kwargs)

            runtime = TestWorldRuntime(
                work_root=root,
                runner_image="registry.example/runner@sha256:" + "c" * 64,
                git_allowed_hosts=("github.com",),
                responses_client=object(),
                model="gpt-test",
                instructions="safe reviewed instructions",
                job_timeout_seconds=900,
                ingest_git=ingest,
                capture_workspace=lambda _path: next(snapshots),
                build_workspace_patch=lambda _before, _after: b"",
                sandbox_factory=sandbox_factory,
                tools_factory=FakeTools,
                agent_factory=CanaryAgent,
            )
            store = MemoryTestWorldStore(clock=lambda: 1000.0)
            world = store.create_world(
                OWNER,
                idempotency_key="world-canary",
                name="Canary",
                objective="Repair safely",
                repository_url="https://github.com/example/project.git",
                commit="d" * 40,
                checks=(TestCheck("unit", ("python3", "-m", "unittest"), 60),),
                max_attempts=1,
            )
            attempt = store.enqueue_attempt(world.id, OWNER, idempotency_key="attempt-canary")
            runner = TestWorldAttemptRunner(
                store=store,
                worker_id="worker",
                lease_seconds=60,
                prepare_workspace=runtime.prepare_workspace,
                apply_previous_patch=runtime.apply_previous_patch,
                run_agent=runtime.run_agent,
                capture_cumulative_patch=runtime.capture_cumulative_patch,
                run_check=runtime.run_check,
                cleanup_workspace=runtime.cleanup_workspace,
                clock=lambda: 1001.0,
            )
            completed = runner.run_attempt(attempt.id, OWNER)
            public_json = json.dumps(_world_json(world, [completed]), sort_keys=True)
            observed_json = json.dumps(observed, default=str, sort_keys=True)
            workspace_text = "".join(
                path.read_text(errors="ignore")
                for path in root.rglob("*")
                if path.is_file()
            )
            podman_argv = build_podman_argv(
                image="registry.example/runner@sha256:" + "e" * 64,
                workspace=root.resolve(),
                name="canary-runner",
                command=("python3", "-V"),
                limits=SandboxLimits(),
            )
            combined = "\n".join((public_json, observed_json, workspace_text, json.dumps(podman_argv)))
            for canary in CANARIES:
                self.assertNotIn(canary, combined)


if __name__ == "__main__":
    unittest.main()
