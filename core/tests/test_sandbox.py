import subprocess
import sys
import tempfile
import unittest
import re
from pathlib import Path
from unittest.mock import patch

from core.lil_tweak.sandbox import (
    CommandRejected,
    PodmanSandbox,
    SandboxLimits,
    WORKSPACE_TMPFS_BYTES,
    WORKSPACE_TMPFS_INODES,
    atomic_exchange_directories,
    build_podman_argv,
)


class PodmanArgvTests(unittest.TestCase):
    def test_builds_literal_hardened_rootless_argv(self):
        limits = SandboxLimits()
        argv = build_podman_argv(
            image="localhost/lil-tweak-runner@sha256:" + "a" * 64,
            workspace=Path("/srv/lil-tweak/jobs/job-1"),
            name="lt-job-1",
            command=["python", "-m", "unittest"],
            limits=limits,
        )

        for expected in (
            "--network=none",
            "--http-proxy=false",
            "--pull=never",
            "--read-only",
            "--read-only-tmpfs=false",
            "--image-volume=ignore",
            "--cap-drop=all",
            "--security-opt=no-new-privileges",
            "--pids-limit=256",
            "--memory=1g",
            "--memory-swap=1g",
            "--cpus=1",
            "--ulimit=nofile=1024:1024",
            "--user=65532:65532",
            "--userns=keep-id:uid=65532,gid=65532",
            "--pid=private",
            "--ipc=private",
            "--label=io.lil-tweak.runner=code-engineer-v1",
            f"--tmpfs=/workspace:rw,exec,nosuid,nodev,notmpcopyup,size={WORKSPACE_TMPFS_BYTES},nr_inodes={WORKSPACE_TMPFS_INODES},uid=65532,gid=65532,mode=0700",
            "--tmpfs=/tmp:rw,exec,nosuid,nodev,size=64m,nr_inodes=8192",
        ):
            self.assertIn(expected, argv)
        self.assertEqual(argv[:2], ["podman", "create"])
        self.assertNotIn("--volume=/srv/lil-tweak/jobs/job-1:/workspace:rw,z", argv)
        self.assertFalse(any(item.startswith("--volume=") for item in argv))
        self.assertFalse(any("noexec" in item for item in argv))
        self.assertNotIn("--privileged", argv)

    def test_holder_is_finite_auto_removed_and_bounded_by_wall_plus_grace(self):
        limits = SandboxLimits(wall_timeout_seconds=20)
        argv = build_podman_argv(
            image="runner@sha256:" + "a" * 64,
            workspace=Path("/tmp/job"),
            name="job",
            command=["python", "-V"],
            limits=limits,
        )

        self.assertIn("--rm", argv)
        holder = argv[-1]
        self.assertNotIn("signal.pause", holder)
        matched = re.fullmatch(r"import time; time\.sleep\((\d+)\)", holder)
        self.assertIsNotNone(matched)
        self.assertEqual(int(matched.group(1)), 80)

        with self.assertRaises(ValueError):
            build_podman_argv(
                image="runner@sha256:" + "a" * 64,
                workspace=Path("/tmp/job"),
                name="job",
                command=["python", "-V"],
                limits=limits,
                holder_timeout_seconds=0,
            )

    def test_command_must_be_an_argv_list_from_allowlist(self):
        common = dict(
            image="runner@sha256:" + "a" * 64,
            workspace=Path("/tmp/job"),
            name="job",
            limits=SandboxLimits(),
        )
        for command in ("python -m unittest", [], ["sh", "-c", "id"], ["../python"]):
            with self.subTest(command=command):
                with self.assertRaises(CommandRejected):
                    build_podman_argv(command=command, **common)

    def test_unshipped_toolchains_are_rejected(self):
        common = dict(
            image="runner@sha256:" + "a" * 64,
            workspace=Path("/tmp/job"),
            name="job",
            limits=SandboxLimits(),
        )
        for executable in ("deno", "pnpm", "yarn", "dotnet"):
            with self.subTest(executable=executable):
                with self.assertRaises(CommandRejected):
                    build_podman_argv(command=[executable, "--version"], **common)

    def test_runner_has_patch_but_no_git_boundary(self):
        common = dict(
            image="runner@sha256:" + "a" * 64,
            workspace=Path("/tmp/job"),
            name="job",
            limits=SandboxLimits(),
        )
        for subcommand in ("diff", "commit", "push", "apply"):
            with self.subTest(subcommand=subcommand), self.assertRaises(CommandRejected):
                build_podman_argv(command=["git", subcommand], **common)
        self.assertEqual(
            build_podman_argv(command=["patch", "--version"], **common)[:2],
            ["podman", "create"],
        )


class SandboxExecutionTests(unittest.TestCase):
    def test_atomic_exchange_swaps_complete_directory_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            left = parent / "left"
            right = parent / "right"
            left.mkdir()
            right.mkdir()
            (left / "value.txt").write_text("left")
            (right / "value.txt").write_text("right")
            left_identity = left.stat().st_ino
            right_identity = right.stat().st_ino

            atomic_exchange_directories(left, right)

            self.assertEqual(left.stat().st_ino, right_identity)
            self.assertEqual(right.stat().st_ino, left_identity)
            self.assertEqual((left / "value.txt").read_text(), "right")
            self.assertEqual((right / "value.txt").read_text(), "left")

    def test_run_never_copies_disposable_workspace_back(self):
        calls = []

        def execute(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as directory:
            sandbox = PodmanSandbox(
                image="runner@sha256:" + "a" * 64,
                workspace=directory,
                name="job-lifecycle",
                executor=execute,
            )
            result = sandbox.run_ephemeral(["python", "-V"])

        argv_calls = [call[0] for call in calls]
        create_index = next(
            i
            for i, argv in enumerate(argv_calls)
            if argv[:2] == ["podman", "create"]
        )
        start_index = next(
            i
            for i, argv in enumerate(argv_calls)
            if argv[:2] == ["podman", "start"]
        )
        copy_in_index = next(
            i
            for i, argv in enumerate(argv_calls)
            if argv[:2] == ["podman", "cp"] and argv[-1] == "job-lifecycle:/workspace"
        )
        exec_index = next(
            i
            for i, argv in enumerate(argv_calls)
            if argv[:2] == ["podman", "exec"]
        )
        remove_index = next(i for i, argv in enumerate(argv_calls) if argv[:2] == ["podman", "rm"])
        self.assertEqual(
            [create_index, start_index, copy_in_index, exec_index, remove_index],
            sorted(
                [
                    create_index,
                    start_index,
                    copy_in_index,
                    exec_index,
                    remove_index,
                ]
            ),
        )
        self.assertFalse(
            any(
                argv[:2] == ["podman", "cp"]
                and argv[2] == "job-lifecycle:/workspace/."
                for argv in argv_calls
            )
        )
        self.assertTrue(all(kwargs["shell"] is False for _, kwargs in calls))
        self.assertEqual(result.exit_code, 0)

    def test_bounded_batch_shares_one_disposable_container(self):
        calls = []

        def execute(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as directory:
            results = PodmanSandbox(
                image="runner@sha256:" + "a" * 64,
                workspace=directory,
                name="job-batch",
                executor=execute,
            ).run_ephemeral_batch(
                [(["python", "write.py"], 5), (["python", "read.py"], None)]
            )

        argv_calls = [call[0] for call in calls]
        self.assertEqual(len(results), 2)
        self.assertEqual(sum(argv[:2] == ["podman", "create"] for argv in argv_calls), 1)
        self.assertEqual(sum(argv[:2] == ["podman", "start"] for argv in argv_calls), 1)
        self.assertEqual(sum(argv[:2] == ["podman", "exec"] for argv in argv_calls), 2)
        self.assertEqual(sum(argv[:2] == ["podman", "rm"] for argv in argv_calls), 1)
        self.assertFalse(
            any(
                argv[:2] == ["podman", "cp"] and argv[2] == "job-batch:/workspace/."
                for argv in argv_calls
            )
        )

    def test_batch_output_uses_one_aggregate_budget(self):
        def execute(argv, **kwargs):
            if argv[:2] == ["podman", "exec"]:
                return subprocess.CompletedProcess(argv, 0, stdout="x" * 20, stderr="")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as directory:
            results = PodmanSandbox(
                image="runner@sha256:" + "a" * 64,
                workspace=directory,
                name="job-batch-output",
                limits=SandboxLimits(max_output_bytes=24),
                executor=execute,
            ).run_ephemeral_batch(
                [(["python", "one.py"], None), (["python", "two.py"], None)]
            )
        self.assertEqual(
            sum(len(result.stdout.encode()) + len(result.stderr.encode()) for result in results),
            24,
        )
        self.assertTrue(results[-1].truncated)

    def test_batch_size_is_bounded_before_container_creation(self):
        calls = []

        def execute(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as directory:
            sandbox = PodmanSandbox(
                image="runner@sha256:" + "a" * 64,
                workspace=directory,
                name="job-batch-limit",
                executor=execute,
            )
            with self.assertRaises(ValueError):
                sandbox.run_ephemeral_batch([(["python", "-V"], None)] * 33)
        self.assertEqual(calls, [])

    def test_patch_candidate_copies_out_only_after_exact_clean_exit(self):
        for exit_code, timed_out, truncated, should_copy in (
            (0, False, False, True),
            (1, False, False, False),
            (None, True, False, False),
            (0, False, True, False),
        ):
            with self.subTest(exit_code=exit_code, timed_out=timed_out, truncated=truncated):
                calls = []

                def execute(argv, **kwargs):
                    calls.append(argv)
                    if argv[:2] == ["podman", "exec"]:
                        if timed_out:
                            raise subprocess.TimeoutExpired(argv, 1)
                        return subprocess.CompletedProcess(
                            argv,
                            exit_code if exit_code is not None else 0,
                            stdout="x" * (4096 if truncated else 0),
                            stderr="",
                        )
                    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    workspace = root / "proposal"
                    workspace.mkdir()
                    patch_file = root / "input.patch"
                    patch_file.write_text("patch")
                    candidate = root / "candidate"
                    candidate.mkdir()
                    sandbox = PodmanSandbox(
                        image="runner@sha256:" + "a" * 64,
                        workspace=workspace,
                        name="job-patch",
                        limits=SandboxLimits(max_output_bytes=32 if truncated else 4096),
                        executor=execute,
                    )
                    result = sandbox.stage_patch_candidate(patch_file, candidate)

                copied = any(
                    argv[:2] == ["podman", "cp"]
                    and argv[2] == "job-patch:/workspace/."
                    for argv in calls
                )
                self.assertEqual(copied, should_copy)
                self.assertEqual(result.exit_code, exit_code)

    def test_patch_is_staged_under_container_tmp_not_workspace(self):
        calls = []

        def execute(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "proposal"
            workspace.mkdir()
            patch_file = root / "input.patch"
            patch_file.write_text("patch")
            candidate = root / "candidate"
            candidate.mkdir()
            PodmanSandbox(
                image="runner@sha256:" + "a" * 64,
                workspace=workspace,
                name="job-patch-path",
                executor=execute,
            ).stage_patch_candidate(patch_file, candidate)

        self.assertIn(
            ["podman", "cp", str(patch_file), "job-patch-path:/tmp/lil-tweak.patch"],
            calls,
        )
        patch_exec = next(argv for argv in calls if argv[:2] == ["podman", "exec"])
        self.assertIn("--input=/tmp/lil-tweak.patch", patch_exec)

    def test_patch_setup_consumes_shared_wall_clock_before_exec(self):
        for after_setup, expected_timeout in ((112.0, 8), (121.0, None)):
            with self.subTest(after_setup=after_setup):
                now = [100.0]
                calls = []

                def execute(argv, **kwargs):
                    calls.append((argv, kwargs))
                    if (
                        argv[:2] == ["podman", "cp"]
                        and argv[-1] == "job-patch-wall:/tmp/lil-tweak.patch"
                    ):
                        now[0] = after_setup
                    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    workspace = root / "proposal"
                    workspace.mkdir()
                    patch_file = root / "input.patch"
                    patch_file.write_text("patch")
                    candidate = root / "candidate"
                    candidate.mkdir()
                    result = PodmanSandbox(
                        image="runner@sha256:" + "a" * 64,
                        workspace=workspace,
                        name="job-patch-wall",
                        limits=SandboxLimits(
                            wall_timeout_seconds=20,
                            command_timeout_seconds=15,
                        ),
                        executor=execute,
                        clock=lambda: now[0],
                    ).stage_patch_candidate(patch_file, candidate)

                exec_calls = [call for call in calls if call[0][:2] == ["podman", "exec"]]
                copy_out = any(
                    call[0][:2] == ["podman", "cp"]
                    and call[0][2] == "job-patch-wall:/workspace/."
                    for call in calls
                )
                if expected_timeout is None:
                    self.assertEqual(exec_calls, [])
                    self.assertFalse(copy_out)
                    self.assertTrue(result.timed_out)
                    self.assertEqual(
                        result.stderr, "sandbox wall-clock limit exceeded"
                    )
                else:
                    self.assertEqual(exec_calls[0][1]["timeout"], expected_timeout)
                    self.assertTrue(copy_out)
                    self.assertFalse(result.timed_out)

    def test_lifecycle_failure_is_stable_bounded_and_still_removes(self):
        calls = []

        def execute(argv, **_kwargs):
            calls.append(argv)
            if argv[:2] == ["podman", "start"]:
                return subprocess.CompletedProcess(
                    argv,
                    125,
                    stdout="",
                    stderr="token=do-not-disclose " + "x" * 1000,
                )
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as directory:
            sandbox = PodmanSandbox(
                image="runner@sha256:" + "a" * 64,
                workspace=directory,
                name="job-failure",
                limits=SandboxLimits(max_output_bytes=64),
                executor=execute,
            )
            result = sandbox.run_ephemeral(["python", "-V"])

        self.assertIsNone(result.exit_code)
        self.assertEqual(result.stderr, "sandbox lifecycle failed")
        self.assertNotIn("do-not-disclose", result.stderr)
        self.assertLessEqual(len(result.stderr.encode()), 64)
        self.assertTrue(sandbox.lifecycle_failed)
        self.assertEqual(calls[-1], ["podman", "rm", "--force", "--ignore", "job-failure"])

    def test_command_created_source_and_binary_never_replace_trusted_workspace(self):
        calls = []

        def execute(argv, **_kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory, "trusted.txt")
            marker.write_text("trusted", encoding="utf-8")
            result = PodmanSandbox(
                image="runner@sha256:" + "a" * 64,
                workspace=directory,
                name="job-copy",
                executor=execute,
            ).run_ephemeral(["python", "-V"])

            self.assertEqual(marker.read_text(encoding="utf-8"), "trusted")
            self.assertFalse(Path(directory, "escape").exists())

        self.assertEqual(result.exit_code, 0)
        self.assertFalse(
            any(
                argv[:2] == ["podman", "cp"] and argv[2] == "job-copy:/workspace/."
                for argv in calls
            )
        )

    def test_run_uses_shell_false_timeout_and_redacts_bounded_output(self):
        calls = []

        def execute(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[:2] != ["podman", "exec"]:
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(
                argv,
                1,
                stdout="Authorization: Bearer bearer-secret token=secret-value " + "A" * 200,
                stderr="B" * 20,
            )

        with tempfile.TemporaryDirectory() as directory:
            sandbox = PodmanSandbox(
                image="runner@sha256:" + "a" * 64,
                workspace=directory,
                name="job-1",
                limits=SandboxLimits(command_timeout_seconds=7, max_output_bytes=100),
                executor=execute,
            )
            with patch.object(sandbox, "_seed_workspace"):
                result = sandbox.run_ephemeral(["python", "-V"])

        command_call = next(call for call in calls if call[0][:2] == ["podman", "exec"])
        self.assertFalse(command_call[1]["shell"])
        self.assertEqual(command_call[1]["timeout"], 7)
        self.assertEqual(sum(call[0][:2] == ["podman", "create"] for call in calls), 1)
        self.assertLessEqual(len(result.stdout.encode()), 100)
        self.assertNotIn("secret-value", result.stdout)
        self.assertNotIn("bearer-secret", result.stdout)
        self.assertTrue(result.truncated)
        self.assertEqual(result.exit_code, 1)

    def test_timeout_returns_stable_bounded_result(self):
        calls = []

        def timeout(argv, **_kwargs):
            calls.append(argv)
            if argv[:2] == ["podman", "exec"]:
                raise subprocess.TimeoutExpired(
                    ["podman"], 1, output=b"partial", stderr=b""
                )
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as directory:
            sandbox = PodmanSandbox(
                image="runner@sha256:" + "a" * 64,
                workspace=directory,
                name="job-1",
                limits=SandboxLimits(command_timeout_seconds=1),
                executor=timeout,
            )
            result = sandbox.run_ephemeral(["python", "-V"])
        self.assertTrue(result.timed_out)
        self.assertIsNone(result.exit_code)
        self.assertIn(
            ["podman", "rm", "--force", "--ignore", "job-1"], calls
        )
        self.assertFalse(
            any(
                argv[:2] == ["podman", "cp"]
                and argv[2] == "job-1:/workspace/."
                for argv in calls
            )
        )

    def test_stdout_and_stderr_share_one_output_budget(self):
        def execute(argv, **kwargs):
            if argv[:2] != ["podman", "exec"]:
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(argv, 0, stdout="A" * 20, stderr="B" * 20)

        with tempfile.TemporaryDirectory() as directory:
            sandbox = PodmanSandbox(
                image="runner@sha256:" + "a" * 64,
                workspace=directory,
                name="job-1",
                limits=SandboxLimits(max_output_bytes=24),
                executor=execute,
            )
            with patch.object(sandbox, "_seed_workspace"):
                result = sandbox.run_ephemeral(["python", "-V"])
        self.assertLessEqual(
            len(result.stdout.encode()) + len(result.stderr.encode()),
            24,
        )

    def test_job_wall_clock_budget_is_shared_across_commands(self):
        now = [100.0]
        timeouts = []
        holder_durations = []

        def execute(argv, **kwargs):
            if argv[:2] == ["podman", "create"]:
                matched = re.fullmatch(
                    r"import time; time\.sleep\((\d+)\)", argv[-1]
                )
                holder_durations.append(
                    int(matched.group(1)) if matched is not None else None
                )
            if argv[:2] == ["podman", "exec"]:
                timeouts.append(kwargs["timeout"])
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as directory:
            sandbox = PodmanSandbox(
                image="runner@sha256:" + "a" * 64,
                workspace=directory,
                name="job-1",
                limits=SandboxLimits(
                    wall_timeout_seconds=20, command_timeout_seconds=15
                ),
                executor=execute,
                clock=lambda: now[0],
            )
            with patch.object(sandbox, "_seed_workspace"):
                sandbox.run_ephemeral(["python", "-V"])
                now[0] = 112.0
                sandbox.run_ephemeral(["python", "-V"])
                now[0] = 121.0
                expired = sandbox.run_ephemeral(["python", "-V"])
        self.assertEqual(timeouts, [15, 8])
        self.assertEqual(holder_durations, [80, 68])
        self.assertTrue(expired.timed_out)

    def test_streaming_capture_kills_at_aggregate_output_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            sandbox = PodmanSandbox(
                image="runner@sha256:" + "a" * 64,
                workspace=directory,
                name="job-output",
                limits=SandboxLimits(max_output_bytes=4096),
            )
            result = sandbox._execute_bounded(
                [sys.executable, "-c", "import sys; sys.stdout.write('x'*10000000)"],
                timeout=10,
            )
        self.assertTrue(result.truncated)
        self.assertLessEqual(
            len(result.stdout.encode()) + len(result.stderr.encode()), 4096
        )

    def test_final_remove_failure_overrides_success_and_all_batch_results(self):
        for removal in ("nonzero", "exception"):
            with self.subTest(removal=removal):
                def execute(argv, **_kwargs):
                    if argv[:2] == ["podman", "rm"]:
                        if removal == "exception":
                            raise OSError("podman unavailable")
                        return subprocess.CompletedProcess(
                            argv, 125, stdout="", stderr="failed"
                        )
                    return subprocess.CompletedProcess(
                        argv, 0, stdout="ok", stderr=""
                    )

                with tempfile.TemporaryDirectory() as directory:
                    sandbox = PodmanSandbox(
                        image="runner@sha256:" + "a" * 64,
                        workspace=directory,
                        name="job-remove",
                        executor=execute,
                    )
                    results = sandbox.run_ephemeral_batch(
                        ((["python", "one.py"], None), (["python", "two.py"], None))
                    )

                self.assertEqual(len(results), 1)
                self.assertIsNone(results[0].exit_code)
                self.assertEqual(results[0].stderr, "sandbox lifecycle failed")
                self.assertFalse(results[0].timed_out)
                self.assertFalse(results[0].truncated)
                self.assertTrue(sandbox.lifecycle_failed)

    def test_final_remove_failure_overrides_timeout_and_truncation(self):
        for outcome in ("timeout", "truncated"):
            with self.subTest(outcome=outcome):
                def execute(argv, **_kwargs):
                    if argv[:2] == ["podman", "rm"]:
                        return subprocess.CompletedProcess(
                            argv, 125, stdout="", stderr="failed"
                        )
                    if argv[:2] == ["podman", "exec"]:
                        if outcome == "timeout":
                            raise subprocess.TimeoutExpired(argv, 1, output="partial")
                        return subprocess.CompletedProcess(
                            argv, 0, stdout="x" * 128, stderr=""
                        )
                    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

                with tempfile.TemporaryDirectory() as directory:
                    result = PodmanSandbox(
                        image="runner@sha256:" + "a" * 64,
                        workspace=directory,
                        name="job-remove-outcome",
                        limits=SandboxLimits(max_output_bytes=64),
                        executor=execute,
                    ).run_ephemeral(["python", "probe.py"])

                self.assertIsNone(result.exit_code)
                self.assertEqual(result.stderr, "sandbox lifecycle failed")
                self.assertFalse(result.timed_out)
                self.assertFalse(result.truncated)

    def test_patch_cleanup_failure_overrides_every_apparent_outcome(self):
        for outcome in ("success", "timeout", "truncated"):
            for removal in ("nonzero", "exception"):
                with self.subTest(outcome=outcome, removal=removal):
                    def execute(argv, **_kwargs):
                        if argv[:2] == ["podman", "rm"]:
                            if removal == "exception":
                                raise OSError("podman unavailable")
                            return subprocess.CompletedProcess(
                                argv, 125, stdout="", stderr="failed"
                            )
                        if argv[:2] == ["podman", "exec"]:
                            if outcome == "timeout":
                                raise subprocess.TimeoutExpired(argv, 1)
                            return subprocess.CompletedProcess(
                                argv,
                                0,
                                stdout="x" * (128 if outcome == "truncated" else 0),
                                stderr="",
                            )
                        return subprocess.CompletedProcess(
                            argv, 0, stdout="", stderr=""
                        )

                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        workspace = root / "proposal"
                        workspace.mkdir()
                        (workspace / "input.txt").write_text(
                            "trusted\n", encoding="utf-8"
                        )
                        patch_file = root / "input.patch"
                        patch_file.write_text("patch", encoding="utf-8")
                        candidate = root / "candidate"
                        candidate.mkdir()
                        sandbox = PodmanSandbox(
                            image="runner@sha256:" + "a" * 64,
                            workspace=workspace,
                            name="job-patch-remove",
                            limits=SandboxLimits(max_output_bytes=64),
                            executor=execute,
                        )
                        result = sandbox.stage_patch_candidate(
                            patch_file, candidate
                        )

                        self.assertEqual(
                            (workspace / "input.txt").read_text(encoding="utf-8"),
                            "trusted\n",
                        )
                        self.assertEqual(list(candidate.iterdir()), [])
                    self.assertIsNone(result.exit_code)
                    self.assertEqual(result.stderr, "sandbox lifecycle failed")
                    self.assertFalse(result.timed_out)
                    self.assertFalse(result.truncated)
                    self.assertTrue(sandbox.lifecycle_failed)

    def test_teardown_surfaces_strict_remove_failures(self):
        for removal in ("nonzero", "exception"):
            with self.subTest(removal=removal):
                def execute(argv, **_kwargs):
                    if removal == "exception":
                        raise OSError("podman unavailable")
                    return subprocess.CompletedProcess(
                        argv, 125, stdout="", stderr="failed"
                    )

                with tempfile.TemporaryDirectory() as directory:
                    sandbox = PodmanSandbox(
                        image="runner@sha256:" + "a" * 64,
                        workspace=directory,
                        name="job-teardown",
                        executor=execute,
                    )
                    with self.assertRaisesRegex(
                        RuntimeError, "sandbox lifecycle failed"
                    ):
                        sandbox.teardown()
                self.assertTrue(sandbox.lifecycle_failed)

    def test_executor_exceptions_are_content_free_but_base_exceptions_propagate(self):
        for error_type in (RuntimeError, AttributeError):
            with self.subTest(boundary="final-remove", error_type=error_type):
                def remove_fails(argv, **_kwargs):
                    if argv[:2] == ["podman", "rm"]:
                        raise error_type("secret executor detail")
                    return subprocess.CompletedProcess(
                        argv, 0, stdout="", stderr=""
                    )

                with tempfile.TemporaryDirectory() as directory:
                    result = PodmanSandbox(
                        image="runner@sha256:" + "a" * 64,
                        workspace=directory,
                        name="job-generic-remove",
                        executor=remove_fails,
                    ).run_ephemeral(["python", "-V"])
                self.assertEqual(result.stderr, "sandbox lifecycle failed")
                self.assertNotIn("secret", result.stderr)

            with self.subTest(boundary="stale-list", error_type=error_type):
                def list_fails(_argv, **_kwargs):
                    raise error_type("secret executor detail")

                with self.assertRaisesRegex(
                    RuntimeError, "^sandbox lifecycle failed$"
                ):
                    PodmanSandbox.cleanup_stale(executor=list_fails)

        for error in (SystemExit("stop"), KeyboardInterrupt()):
            with self.subTest(base_exception=type(error).__name__):
                def interrupted(_argv, **_kwargs):
                    raise error

                with self.assertRaises(type(error)):
                    PodmanSandbox.cleanup_stale(executor=interrupted)

    def test_lifecycle_body_executor_exceptions_are_removed_and_content_free(self):
        for phase in ("create", "start", "copy", "exec"):
            with self.subTest(api="run_ephemeral", phase=phase):
                calls = []

                def execute(argv, **_kwargs):
                    calls.append(list(argv))
                    boundary = (
                        "create"
                        if argv[:2] == ["podman", "create"]
                        else "start"
                        if argv[:2] == ["podman", "start"]
                        else "copy"
                        if argv[:2] == ["podman", "cp"]
                        else "exec"
                        if argv[:2] == ["podman", "exec"]
                        else "remove"
                    )
                    if boundary == phase:
                        raise RuntimeError("secret executor detail")
                    return subprocess.CompletedProcess(
                        argv, 0, stdout="", stderr=""
                    )

                with tempfile.TemporaryDirectory() as directory:
                    result = PodmanSandbox(
                        image="runner@sha256:" + "a" * 64,
                        workspace=directory,
                        name="job-body-error",
                        executor=execute,
                    ).run_ephemeral(["python", "-V"])

                self.assertEqual(result.stderr, "sandbox lifecycle failed")
                self.assertNotIn("secret", result.stderr)
                self.assertIn(
                    ["podman", "rm", "--force", "--ignore", "job-body-error"],
                    calls,
                )

        for phase in ("create", "exec", "copy-out"):
            with self.subTest(api="stage_patch_candidate", phase=phase):
                calls = []

                def execute(argv, **_kwargs):
                    calls.append(list(argv))
                    copy_out = (
                        argv[:2] == ["podman", "cp"]
                        and len(argv) >= 4
                        and argv[2].endswith(":/workspace/.")
                    )
                    if (
                        (phase == "create" and argv[:2] == ["podman", "create"])
                        or (phase == "exec" and argv[:2] == ["podman", "exec"])
                        or (phase == "copy-out" and copy_out)
                    ):
                        raise AttributeError("secret executor detail")
                    return subprocess.CompletedProcess(
                        argv, 0, stdout="", stderr=""
                    )

                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    workspace = root / "proposal"
                    workspace.mkdir()
                    patch_file = root / "input.patch"
                    patch_file.write_text("patch", encoding="utf-8")
                    candidate = root / "candidate"
                    candidate.mkdir()
                    result = PodmanSandbox(
                        image="runner@sha256:" + "a" * 64,
                        workspace=workspace,
                        name="job-patch-body-error",
                        executor=execute,
                    ).stage_patch_candidate(patch_file, candidate)

                self.assertEqual(result.stderr, "sandbox lifecycle failed")
                self.assertNotIn("secret", result.stderr)
                self.assertIn(
                    [
                        "podman",
                        "rm",
                        "--force",
                        "--ignore",
                        "job-patch-body-error",
                    ],
                    calls,
                )

    def test_stale_cleanup_is_scoped_to_the_dedicated_runner_label(self):
        calls = []

        def execute(argv, **_kwargs):
            calls.append(argv)
            if argv[:2] == ["podman", "ps"]:
                return subprocess.CompletedProcess(argv, 0, stdout="a" * 64 + "\n", stderr="")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        PodmanSandbox.cleanup_stale(executor=execute)
        self.assertIn(
            "--filter=label=io.lil-tweak.runner=code-engineer-v1", calls[0]
        )
        self.assertEqual(
            calls[1], ["podman", "rm", "--force", "--ignore", "a" * 64]
        )

    def test_stale_cleanup_failure_is_fatal(self):
        def execute(argv, **_kwargs):
            return subprocess.CompletedProcess(argv, 125, stdout="", stderr="failed")

        with self.assertRaisesRegex(RuntimeError, "sandbox lifecycle failed"):
            PodmanSandbox.cleanup_stale(executor=execute)

    def test_stale_cleanup_fails_closed_for_every_unprovable_state(self):
        valid_id = "a" * 64
        for failure in (
            "list_exception",
            "list_timeout",
            "malformed_id",
            "remove_nonzero",
            "remove_exception",
        ):
            with self.subTest(failure=failure):
                def execute(argv, **_kwargs):
                    if argv[:2] == ["podman", "ps"]:
                        if failure == "list_exception":
                            raise OSError("podman unavailable")
                        if failure == "list_timeout":
                            raise subprocess.TimeoutExpired(argv, 30)
                        output = "not-a-container-id\n" if failure == "malformed_id" else valid_id + "\n"
                        return subprocess.CompletedProcess(
                            argv, 0, stdout=output, stderr=""
                        )
                    if failure == "remove_exception":
                        raise OSError("podman unavailable")
                    return subprocess.CompletedProcess(
                        argv,
                        125 if failure == "remove_nonzero" else 0,
                        stdout="",
                        stderr="failed",
                    )

                with self.assertRaisesRegex(
                    RuntimeError, "^sandbox lifecycle failed$"
                ):
                    PodmanSandbox.cleanup_stale(executor=execute)


if __name__ == "__main__":
    unittest.main()
