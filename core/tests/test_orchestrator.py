import json
import shutil
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from core.lil_tweak.contracts import JobMode, JobState, SideEffect
from core.lil_tweak.evidence import LocalEvidenceStore
from core.lil_tweak.openai_agent import (
    AgentResult,
    PromotionRecoveryRequired,
    WorkspaceTools,
)
from core.lil_tweak.sandbox import CommandResult
from core.lil_tweak.orchestrator import (
    BackgroundJobRunner,
    DurableJobScheduler,
    EngineeringOrchestrator,
)
from core.lil_tweak.store import GitSourceSpec, Job, JobLease, MemoryJobStore


def stored_evidence(store, job, name):
    return store.get(job.evidence_manifest[name]["objectKey"])


class FakeAgent:
    def __init__(self, result=None, error=None, on_run=None, tools=None):
        self.result = result
        self.error = error
        self.on_run = on_run
        self.tools = tools
        self.calls = []

    def run(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        if self.on_run:
            self.on_run()
        return self.result


class OrchestratorTests(unittest.TestCase):
    def test_snapshot_cleanup_failure_is_fatal_and_preserves_staging(self):
        for phase in ("preexisting", "final"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                root = parent / "proposal"
                root.mkdir()
                (root / "app.py").write_text("value = 1\n")
                store = MemoryJobStore()
                job = store.create_job("owner", phase, JobMode.BUILD, "Build")
                tools = WorkspaceTools(root, None)
                agent = FakeAgent(
                    AgentResult("Plan", "Done", "", ""), tools=tools
                )
                snapshot_root = parent / ".snapshots" / job.id
                if phase == "preexisting":
                    snapshot_root.mkdir(parents=True)
                    (snapshot_root / "preserve.txt").write_text("preserve\n")
                original_rmtree = shutil.rmtree

                def fail_snapshot_cleanup(path, *args, **kwargs):
                    if Path(path) == snapshot_root and snapshot_root.exists():
                        raise OSError("secret cleanup detail")
                    return original_rmtree(path, *args, **kwargs)

                with patch(
                    "core.lil_tweak.orchestrator.shutil.rmtree",
                    side_effect=fail_snapshot_cleanup,
                ):
                    with self.assertRaisesRegex(
                        PromotionRecoveryRequired, "^patch_cleanup_failed$"
                    ):
                        EngineeringOrchestrator(
                            store=store,
                            agent=agent,
                            evidence_store=LocalEvidenceStore(parent / "evidence"),
                        ).run_job(job.id, "owner", workspace=root)

                self.assertTrue(snapshot_root.exists())

    def test_recovery_marker_or_unjournaled_mutation_blocks_evidence_and_preserves_baseline(self):
        class RecordingEvidence:
            def __init__(self):
                self.puts = []

            def put(self, *args):
                self.puts.append(args)
                raise AssertionError("evidence must not be written")

        for case in ("marker", "unjournaled"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory)
                root = parent / "proposal"
                root.mkdir()
                source = root / "app.py"
                source.write_text("value = 1\n")
                store = MemoryJobStore()
                job = store.create_job("owner", case, JobMode.BUILD, "Build")
                tools = WorkspaceTools(root, None)

                def mutate():
                    if case == "marker":
                        (parent / ".proposal-promotion-v1.json").write_text("{}")
                    else:
                        source.write_text("value = 2\n")

                agent = FakeAgent(
                    AgentResult("Plan", "Done", "", ""),
                    on_run=mutate,
                    tools=tools,
                )
                evidence = RecordingEvidence()
                with self.assertRaises(PromotionRecoveryRequired):
                    EngineeringOrchestrator(
                        store=store,
                        agent=agent,
                        evidence_store=evidence,
                    ).run_job(job.id, "owner", workspace=root)

                snapshot_root = parent / ".snapshots" / job.id
                self.assertTrue(list(snapshot_root.glob("attempt-*/baseline/app.py")))
                self.assertFalse(list(snapshot_root.glob("attempt-*/final")))
                self.assertEqual(evidence.puts, [])
                self.assertNotIn(
                    "engineering_failed",
                    [event.kind for event in store.list_events(job.id, "owner")],
                )

    def test_system_exit_with_marker_preserves_workspace_marker_and_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "proposal"
            root.mkdir()
            source = root / "app.py"
            source.write_text("before\n")
            store = MemoryJobStore()
            job = store.create_job("owner", "crash", JobMode.BUILD, "Build")
            tools = WorkspaceTools(root, None)
            marker = parent / ".proposal-promotion-v1.json"

            def crash():
                marker.write_text("{}")
                marker.chmod(0o600)
                raise SystemExit("crash")

            agent = FakeAgent(
                AgentResult("Plan", "Done", "", ""), tools=tools, on_run=crash
            )
            with self.assertRaises(SystemExit):
                EngineeringOrchestrator(
                    store=store,
                    agent=agent,
                    evidence_store=self.evidence,
                ).run_job(job.id, "owner", workspace=root)

            snapshot_root = parent / ".snapshots" / job.id
            self.assertEqual(source.read_text(), "before\n")
            self.assertTrue(marker.exists())
            self.assertTrue(list(snapshot_root.glob("attempt-*/baseline/app.py")))
            self.assertFalse(list(snapshot_root.glob("attempt-*/final")))
            self.assertNotIn(
                "engineering_failed",
                [event.kind for event in store.list_events(job.id, "owner")],
            )

    def test_evidence_staging_recovers_after_put_before_manifest_crash(self):
        class CrashOnceStore(MemoryJobStore):
            def __init__(self):
                super().__init__()
                self.crash = True

            def update_job(self, *args, **kwargs):
                if self.crash and kwargs.get("state") is JobState.COMPLETED:
                    self.crash = False
                    raise SystemExit("simulated process death")
                return super().update_job(*args, **kwargs)

        store = CrashOnceStore()
        job = store.create_job("owner", "crash-evidence", JobMode.BUILD, "Build")
        clock_value = [100.0]

        def clock():
            clock_value[0] += 1
            return clock_value[0]

        orchestrator = EngineeringOrchestrator(
            store=store,
            agent=FakeAgent(AgentResult("Plan", "Done", "", "")),
            evidence_store=self.evidence,
            clock=clock,
        )
        with self.assertRaises(SystemExit):
            orchestrator.run_job(job.id, "owner")
        recovered = store.reconcile_active_jobs(now=200, limit=1)
        self.assertEqual(recovered[0].state, JobState.QUEUED)
        completed = orchestrator.run_job(job.id, "owner")
        self.assertEqual(completed.state, JobState.COMPLETED)
        object_keys = {
            descriptor["objectKey"]
            for descriptor in completed.evidence_manifest.values()
        }
        self.assertTrue(
            all(completed.proposal_digest in key for key in object_keys)
        )

    def test_galor_is_fail_open_and_records_only_stable_unavailable_event(self):
        class Galor:
            def fetch(self, context):
                from core.lil_tweak.galor import GalorResult

                return GalorResult(None, "galor_unavailable")

        agent = FakeAgent(AgentResult("Answer", "Done", "", ""))
        completed = EngineeringOrchestrator(
            store=self.store,
            agent=agent,
            evidence_store=self.evidence,
            galor=Galor(),
        ).run_job(self.job.id, "owner")
        self.assertEqual(completed.state, JobState.COMPLETED)
        self.assertIsNone(agent.calls[0]["galor_context"])
        events = self.store.list_events(self.job.id, "owner")
        self.assertIn(("galor_unavailable", {"code": "galor_unavailable"}), [
            (event.kind, event.data) for event in events
        ])

    def setUp(self):
        self.store = MemoryJobStore()
        self.job = self.store.create_job("owner", "idem", JobMode.BUILD, "Build it")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.evidence = LocalEvidenceStore(self.temp.name)

    def test_local_engineering_run_creates_evidence_and_completes(self):
        agent = FakeAgent(
            AgentResult(
                plan="Plan",
                summary="Done",
                tests="1 passed",
                patch="diff",
                model_calls=2,
                input_tokens=30,
                output_tokens=12,
                total_tokens=42,
            )
        )
        completed = EngineeringOrchestrator(
            store=self.store,
            agent=agent,
            evidence_store=self.evidence,
        ).run_job(self.job.id, "owner", source_inventory=["a.py"])

        self.assertEqual(completed.state, JobState.COMPLETED)
        self.assertEqual(completed.summary, "Done")
        self.assertIsNotNone(completed.proposal_digest)
        self.assertEqual(stored_evidence(self.evidence, completed, "summary.md"), b"Done")
        self.assertEqual(agent.calls[0]["prompt"], "Build it")
        manifest = json.loads(
            stored_evidence(self.evidence, completed, "manifest.json")
        )
        self.assertEqual(
            manifest["run"]["model_usage"],
            {
                "calls": 2,
                "input_tokens": 30,
                "output_tokens": 12,
                "total_tokens": 42,
            },
        )

    def test_evidence_uses_trusted_workspace_diff_not_model_claims(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        root = Path(workspace.name) / "proposal"
        root.mkdir()
        source = root / "app.py"
        source.write_text("value = 1\n")
        snapshot_root = (
            root.parent / ".snapshots" / self.job.id
        )
        (snapshot_root / "stale-attempt").mkdir(parents=True)
        (snapshot_root / "stale-attempt" / "orphan").write_text("old")

        class Sandbox:
            def stage_patch_candidate(self, patch_file, candidate):
                shutil.copytree(root, candidate, dirs_exist_ok=True)
                (Path(candidate) / "app.py").write_text("value = 2\n")
                return CommandResult(0, "applied", "")

        tools = WorkspaceTools(root, Sandbox())

        def mutate():
            tools.execute(
                "apply_patch",
                {
                    "patch": (
                        "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n"
                        "-value = 1\n+value = 2\n"
                    )
                },
            )

        agent = FakeAgent(
            AgentResult(
                plan="Plan",
                summary="Done",
                tests="HALLUCINATED TEST PASS",
                patch="HALLUCINATED PATCH",
            ),
            on_run=mutate,
            tools=tools,
        )
        completed = EngineeringOrchestrator(
            store=self.store,
            agent=agent,
            evidence_store=self.evidence,
        ).run_job(self.job.id, "owner", workspace=root)
        patch = stored_evidence(self.evidence, completed, "changes.patch").decode()
        tests = stored_evidence(self.evidence, completed, "tests.log").decode()
        manifest = json.loads(
            stored_evidence(self.evidence, completed, "manifest.json")
        )
        self.assertIn("-value = 1", patch)
        self.assertIn("+value = 2", patch)
        self.assertNotIn("HALLUCINATED", patch)
        self.assertNotIn("HALLUCINATED", tests)
        self.assertEqual(manifest["run"]["source_digest"], completed.source_digest)
        self.assertRegex(manifest["run"]["proposal_source_digest"], r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            manifest["run"]["source_digest"],
            manifest["run"]["proposal_source_digest"],
        )
        self.assertEqual(manifest["run"]["edit_journal_count"], 1)
        self.assertRegex(manifest["run"]["edit_journal_digest"], r"^[0-9a-f]{64}$")
        self.assertFalse(snapshot_root.exists())

    def test_git_job_requires_and_records_remote_runner_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "proposal"
            root.mkdir()
            (root / "app.py").write_text("value = 1\n")
            store = MemoryJobStore()
            job = store.create_job(
                "owner",
                "github-runner",
                JobMode.BUILD,
                "Edit",
                git_source=GitSourceSpec(
                    "https://github.com/islamismylifebey-web/lil-tweak.git",
                    "1" * 40,
                ),
            )

            class Sandbox:
                def stage_patch_candidate(self, patch_file, candidate):
                    shutil.copytree(root, candidate, dirs_exist_ok=True)
                    (Path(candidate) / "app.py").write_text("value = 2\n")
                    return CommandResult(0, "applied", "")

            tools = WorkspaceTools(root, Sandbox())

            def mutate():
                tools.execute(
                    "apply_patch",
                    {"patch": "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-value = 1\n+value = 2\n"},
                )

            class Verifier:
                def __init__(self):
                    self.calls = []

                def verify(self, **kwargs):
                    self.calls.append(kwargs)
                    return {"receiptDigest": "9" * 64, "outcome": "succeeded"}

            verifier = Verifier()
            completed = EngineeringOrchestrator(
                store=store,
                agent=FakeAgent(AgentResult("Plan", "Done", "", ""), on_run=mutate, tools=tools),
                evidence_store=self.evidence,
                runner_verifier=verifier,
            ).run_job(job.id, "owner", workspace=root)

            self.assertEqual(len(verifier.calls), 1)
            self.assertEqual(verifier.calls[0]["job"].id, job.id)
            self.assertIn(b"+value = 2", verifier.calls[0]["patch"])
            manifest = json.loads(stored_evidence(self.evidence, completed, "manifest.json"))
            self.assertEqual(manifest["run"]["github_runner"]["receiptDigest"], "9" * 64)

    def test_all_editing_modes_evidence_excludes_disposable_build_artifacts(self):
        for mode in (
            JobMode.BUILD,
            JobMode.DEBUG,
            JobMode.REFACTOR,
            JobMode.TEST,
            JobMode.ARCHITECT,
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                store = MemoryJobStore()
                job = store.create_job("owner", f"job-{mode.value}", mode, "Edit")
                root = Path(directory) / "proposal"
                root.mkdir()
                (root / "app.py").write_text("before\n")
                (root / "asset.bin").write_bytes(b"\x00\xffunchanged")

                class DisposableSandbox:
                    def __init__(self):
                        self.scratch = tempfile.TemporaryDirectory()

                    def run_ephemeral(self, command, timeout=None):
                        scratch = Path(self.scratch.name)
                        for relative in (
                            "__pycache__/app.pyc",
                            "target/debug/bin",
                            "node_modules/pkg/index.js",
                            "dist/command-only.js",
                            "unpatched.py",
                        ):
                            target = scratch / relative
                            target.parent.mkdir(parents=True, exist_ok=True)
                            target.write_text("scratch only\n")
                        return CommandResult(0, "built in disposable scratch", "")

                    def stage_patch_candidate(self, patch_file, candidate):
                        shutil.copytree(root, candidate, dirs_exist_ok=True)
                        (Path(candidate) / "app.py").write_text("after\n")
                        generated = Path(candidate) / "dist" / "intentional.js"
                        generated.parent.mkdir()
                        generated.write_text("intentional\n")
                        return CommandResult(0, "patch applied", "")

                sandbox = DisposableSandbox()
                tools = WorkspaceTools(root, sandbox)

                def exercise_real_tools():
                    tools.execute(
                        "run_command",
                        {"command": ["python", "build.py"], "timeout": 5},
                    )
                    result = tools.execute(
                        "apply_patch",
                        {
                            "patch": (
                                "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n"
                                "-before\n+after\n"
                                "--- /dev/null\n+++ b/dist/intentional.js\n"
                                "@@ -0,0 +1 @@\n+intentional\n"
                            )
                        },
                    )
                    self.assertTrue(result["promoted"])

                result = EngineeringOrchestrator(
                    store=store,
                    agent=FakeAgent(
                        AgentResult("Plan", "Done", "claim", "claim"),
                        tools=tools,
                        on_run=exercise_real_tools,
                    ),
                    evidence_store=self.evidence,
                ).run_job(job.id, "owner", workspace=root)
                patch = stored_evidence(self.evidence, result, "changes.patch").decode()
                self.assertIn("+after", patch)
                self.assertIn("b/dist/intentional.js", patch)
                for artifact in (
                    ".pyc",
                    "target/",
                    "node_modules/",
                    "command-only.js",
                    "unpatched.py",
                ):
                    self.assertNotIn(artifact, patch)
                for host_path in (
                    "__pycache__/app.pyc",
                    "target/debug/bin",
                    "node_modules/pkg/index.js",
                    "dist/command-only.js",
                    "unpatched.py",
                ):
                    self.assertFalse((root / host_path).exists())
                self.assertTrue((root / "dist" / "intentional.js").exists())
                sandbox.scratch.cleanup()

    def test_empty_workspace_change_produces_empty_patch(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        (Path(workspace.name) / "app.py").write_text("unchanged\n")
        tools = WorkspaceTools(workspace.name, None)
        completed = EngineeringOrchestrator(
            store=self.store,
            agent=FakeAgent(
                AgentResult("Plan", "Done", "fake", "fake"), tools=tools
            ),
            evidence_store=self.evidence,
        ).run_job(self.job.id, "owner", workspace=workspace.name)
        self.assertEqual(stored_evidence(self.evidence, completed, "changes.patch"), b"")

    def test_actual_command_observations_drive_tests_log_and_manifest(self):
        class Sandbox:
            def run_ephemeral(self, command, timeout=None):
                return CommandResult(
                    1, "real output", "real failure", truncated=True
                )

        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        tools = WorkspaceTools(workspace.name, Sandbox())
        agent = FakeAgent(
            AgentResult("Plan", "Done", "fake passed", "fake patch"),
            tools=tools,
            on_run=lambda: tools.execute(
                "run_command",
                {"command": ["python", "-m", "unittest"], "timeout": 5},
            ),
        )
        completed = EngineeringOrchestrator(
            store=self.store,
            agent=agent,
            evidence_store=self.evidence,
        ).run_job(self.job.id, "owner", workspace=workspace.name)
        tests_log = stored_evidence(self.evidence, completed, "tests.log").decode()
        manifest = json.loads(
            stored_evidence(self.evidence, completed, "manifest.json")
        )
        self.assertIn("real output", tests_log)
        self.assertIn("real failure", tests_log)
        self.assertNotIn("fake passed", tests_log)
        self.assertEqual(
            manifest["run"]["commands"], [["python", "-m", "unittest"]]
        )
        self.assertEqual(manifest["run"]["exit_statuses"], [1])
        self.assertEqual(manifest["run"]["timeouts"], [False])
        self.assertEqual(manifest["run"]["truncation"], [True])
        self.assertRegex(manifest["run"]["source_digest"], r"^[0-9a-f]{64}$")

    def test_timed_out_sandbox_observation_makes_job_timed_out(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        source = Path(workspace.name) / "partial.py"
        source.write_text("before\n")

        class Sandbox:
            def run_ephemeral(self, command, timeout=None):
                return CommandResult(
                    None, "", "command_timed_out", timed_out=True
                )

        tools = WorkspaceTools(workspace.name, Sandbox())

        result = EngineeringOrchestrator(
            store=self.store,
            agent=FakeAgent(
                AgentResult("Plan", "Timed out", "", ""),
                tools=tools,
                on_run=lambda: tools.execute(
                    "run_command",
                    {"command": ["python", "slow.py"], "timeout": 5},
                ),
            ),
            evidence_store=self.evidence,
        ).run_job(self.job.id, "owner", workspace=workspace.name)
        self.assertEqual(result.state, JobState.TIMED_OUT)
        self.assertEqual(source.read_text(), "before\n")

    def test_mid_run_cancellation_discards_agent_result(self):
        def cancel():
            current = self.store.get_job(self.job.id, "owner")
            self.store.request_cancel(
                current.id, owner_id="owner", expected_revision=current.revision
            )

        result = EngineeringOrchestrator(
            store=self.store,
            agent=FakeAgent(
                AgentResult(
                    "Plan",
                    "Stale",
                    "fake",
                    "fake",
                    external_action={"effect": "push", "target": "origin"},
                ),
                on_run=cancel,
            ),
            evidence_store=self.evidence,
        ).run_job(self.job.id, "owner")
        self.assertEqual(result.state, JobState.CANCELLED)
        self.assertIsNone(result.evidence_manifest)
        self.assertIsNone(result.proposal_digest)

    def test_external_action_waits_for_digest_bound_approval(self):
        agent = FakeAgent(
            AgentResult(
                plan="Plan",
                summary="Ready",
                tests="passed",
                patch="diff",
                external_action={
                    "effect": "export_patch",
                    "target": "owner_download",
                },
            )
        )
        waiting = EngineeringOrchestrator(
            store=self.store,
            agent=agent,
            evidence_store=self.evidence,
            clock=lambda: 0,
        ).run_job(self.job.id, "owner")
        self.assertEqual(waiting.state, JobState.AWAITING_APPROVAL)
        self.assertEqual(waiting.summary, "Ready")
        self.assertTrue(waiting.evidence_manifest)
        self.assertEqual(
            waiting.approval_proposal,
            {
                "action": "export_patch",
                "target": "owner_download",
                "policyVersion": "v1",
                "resourceProfile": {
                    "cpus": 1,
                    "memory": "1g",
                    "pids": 256,
                    "wallSeconds": 1200,
                },
                "sourceDigest": waiting.source_digest,
                "proposalDigest": waiting.proposal_digest,
                "expiresAt": "1970-01-01T00:05:00Z",
            },
        )
        self.assertGreater(waiting.evidence_manifest["manifest.json"]["bytes"], 0)
        events = self.store.list_events(self.job.id, "owner")
        self.assertEqual(events[-1].kind, "approval_required")
        self.assertNotIn("prompt", events[-1].data)

    def test_agent_failure_moves_job_to_failed(self):
        orchestrator = EngineeringOrchestrator(
            store=self.store,
            agent=FakeAgent(error=RuntimeError("model secret detail")),
            evidence_store=self.evidence,
        )
        failed = orchestrator.run_job(self.job.id, "owner")
        self.assertEqual(failed.state, JobState.FAILED)
        self.assertEqual(
            self.store.list_events(self.job.id, "owner")[-1].data,
            {"code": "engineering_failed"},
        )

    def test_cancelled_job_never_calls_agent(self):
        cancelled = self.store.request_cancel(
            self.job.id, owner_id="owner", expected_revision=0
        )
        agent = FakeAgent(result=AgentResult("", "", "", ""))
        result = EngineeringOrchestrator(
            store=self.store, agent=agent, evidence_store=self.evidence
        ).run_job(cancelled.id, "owner")
        self.assertEqual(result.state, JobState.CANCELLED)
        self.assertEqual(agent.calls, [])


class BackgroundRunnerTests(unittest.TestCase):
    def test_cross_process_guard_covers_source_intake_and_execution(self):
        events = []

        @contextmanager
        def execution_guard():
            events.append("acquire")
            try:
                yield
            finally:
                events.append("release")

        def ingest(job_id, owner_id):
            events.append(("ingest", job_id, owner_id))
            return ["app.py"]

        def run(job_id, owner_id, inventory):
            events.append(("run", job_id, owner_id, tuple(inventory)))
            return "done"

        runner = BackgroundJobRunner(
            run,
            source_intake=ingest,
            max_admitted=1,
            execution_guard=execution_guard,
        )
        self.addCleanup(runner.shutdown)

        self.assertEqual(runner.submit("job", "owner").result(timeout=2), "done")
        self.assertEqual(
            events,
            [
                "acquire",
                ("ingest", "job", "owner"),
                ("run", "job", "owner", ("app.py",)),
                "release",
            ],
        )

    def test_durable_scheduler_keeps_polling_until_queued_work_is_admitted(self):
        completed = []
        condition = threading.Condition()

        class Store:
            def __init__(self):
                self.jobs = [
                    Job("job-1", "owner", JobMode.BUILD, "one", state=JobState.QUEUED),
                    Job("job-2", "owner", JobMode.BUILD, "two", state=JobState.QUEUED),
                ]
                self.generation = 0

            def reconcile_active_jobs(self, **kwargs):
                return []

            def list_schedulable_jobs(self, **kwargs):
                return self.jobs[:1]

            def claim_job(self, job_id, owner_id, worker_id, **kwargs):
                self.generation += 1
                return JobLease(job_id, owner_id, worker_id, self.generation, time.time() + 1)

            def renew_claim(self, lease, **kwargs):
                return lease

            def release_claim(self, lease):
                self.jobs = [job for job in self.jobs if job.id != lease.job_id]

        store = Store()

        def run(job_id, owner_id, lease):
            with condition:
                completed.append(job_id)
                condition.notify_all()

        runner = BackgroundJobRunner(run, max_admitted=1)
        scheduler = DurableJobScheduler(
            store,
            runner,
            worker_id="worker",
            lease_seconds=1,
            poll_interval=0.01,
        )
        self.addCleanup(scheduler.shutdown)
        self.addCleanup(runner.shutdown)
        scheduler.start()
        with condition:
            condition.wait_for(lambda: len(completed) == 2, timeout=2)
        self.assertEqual(completed, ["job-1", "job-2"])

    def test_admission_is_bounded_and_recovers_after_completion(self):
        release = threading.Event()

        def run(job_id, owner_id):
            release.wait(timeout=1)
            return (job_id, owner_id)

        runner = BackgroundJobRunner(run, max_admitted=1)
        first = runner.submit("one", "owner")
        self.assertFalse(runner.has_capacity)
        with self.assertRaises(RuntimeError) as rejected:
            runner.submit("two", "owner")
        self.assertEqual(rejected.exception.code, "admission_unavailable")
        release.set()
        self.assertEqual(first.result(timeout=1), ("one", "owner"))
        deadline = time.monotonic() + 1
        while not runner.has_capacity and time.monotonic() < deadline:
            time.sleep(0.001)
        self.assertTrue(runner.has_capacity)
        runner.shutdown()

    def test_jobs_execute_one_at_a_time(self):
        lock = threading.Lock()
        active = 0
        maximum = 0

        def run(job_id, owner_id):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.01)
            with lock:
                active -= 1
            return (job_id, owner_id)

        runner = BackgroundJobRunner(run)
        first = runner.submit("one", "owner")
        second = runner.submit("two", "owner")
        self.assertEqual(first.result(timeout=1), ("one", "owner"))
        self.assertEqual(second.result(timeout=1), ("two", "owner"))
        self.assertEqual(maximum, 1)
        runner.shutdown()

    def test_runner_passes_ingested_inventory_to_job(self):
        calls = []

        def ingest(job_id, owner_id):
            calls.append(("ingest", job_id, owner_id))
            return ["src/main.py"]

        def run(job_id, owner_id, source_inventory):
            calls.append(("run", job_id, owner_id, source_inventory))

        runner = BackgroundJobRunner(run, source_intake=ingest)
        runner.submit("job", "owner").result(timeout=1)
        runner.shutdown()
        self.assertEqual(
            calls,
            [
                ("ingest", "job", "owner"),
                ("run", "job", "owner", ["src/main.py"]),
            ],
        )


if __name__ == "__main__":
    unittest.main()
