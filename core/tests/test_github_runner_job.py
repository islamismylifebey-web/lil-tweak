import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import call, patch

from core.lil_tweak.github_runner import RunnerManifest, verify_receipt


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "tueiq_github_runner.py"


def load_runner_script():
    spec = importlib.util.spec_from_file_location("tueiq_github_runner_script", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load GitHub runner script")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNNER_SCRIPT = load_runner_script()


def git(root, *args):
    return subprocess.run(
        ("git", "-C", str(root), *args),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class GitHubRunnerJobTests(unittest.TestCase):
    def test_npm_verify_installs_dependencies_before_verification(self):
        workspace = Path("candidate-source")
        clean_environment = {
            "PATH": "fixture-path",
            "OPENAI_API_KEY": "",
            "LIL_TWEAK_LIVE_MODEL_ENABLED": "false",
            "GIT_TERMINAL_PROMPT": "0",
        }
        with (
            patch.dict(os.environ, {"PATH": "fixture-path"}, clear=True),
            patch.object(
                RUNNER_SCRIPT.subprocess,
                "run",
                side_effect=(
                    subprocess.CompletedProcess(("npm", "ci"), 0),
                    subprocess.CompletedProcess(("npm", "run", "verify"), 0),
                ),
            ) as run,
        ):
            result = RUNNER_SCRIPT.run_action("npm_verify", workspace, None)

        self.assertEqual(result, 0)
        self.assertEqual(
            run.call_args_list,
            [
                call(
                    ("npm", "ci"),
                    cwd=workspace,
                    capture_output=True,
                    text=True,
                    timeout=1200,
                    env=clean_environment,
                ),
                call(
                    ("npm", "run", "verify"),
                    cwd=workspace,
                    capture_output=True,
                    text=True,
                    timeout=1200,
                    env=clean_environment,
                ),
            ],
        )

    def test_npm_verify_stops_when_dependency_installation_fails(self):
        workspace = Path("candidate-source")
        with patch.object(
            RUNNER_SCRIPT.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(("npm", "ci"), 23),
        ) as run:
            result = RUNNER_SCRIPT.run_action("npm_verify", workspace, None)

        self.assertEqual(result, 23)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], ("npm", "ci"))

    def test_npm_verify_converts_each_subprocess_timeout_to_fixed_failure(self):
        workspace = Path("candidate-source")
        cases = (
            (subprocess.TimeoutExpired(("npm", "ci"), 1200),),
            (
                subprocess.CompletedProcess(("npm", "ci"), 0),
                subprocess.TimeoutExpired(("npm", "run", "verify"), 1200),
            ),
        )
        for side_effect in cases:
            with self.subTest(command=side_effect[-1].cmd):
                with patch.object(
                    RUNNER_SCRIPT.subprocess,
                    "run",
                    side_effect=side_effect,
                ):
                    result = RUNNER_SCRIPT.run_action("npm_verify", workspace, None)

                self.assertEqual(result, 70)

    def test_cli_guard_hides_subprocess_failure_details(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "source"
            output = Path(directory) / "output"
            workspace.mkdir()
            manifest = RunnerManifest.issue(
                execution_id="tueiq-cli-guard-test",
                repository="islamismylifebey-web/lil-tweak",
                source_commit="1" * 40,
                source_tree="2" * 40,
                patch="",
                authorized_paths=(),
                actions=("inspect_source", "git_diff"),
                issued_at=datetime.now(UTC) - timedelta(seconds=1),
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
                authority_digest="3" * 64,
            )
            manifest_path = Path(directory) / "manifest.json"
            manifest_path.write_text(json.dumps(manifest.as_dict()), encoding="utf-8")
            stderr = io.StringIO()
            stdout = io.StringIO()
            argv = [
                str(SCRIPT),
                "--manifest",
                str(manifest_path),
                "--workspace",
                str(workspace),
                "--output",
                str(output),
            ]

            with (
                patch.object(sys, "argv", argv),
                patch.object(
                    RUNNER_SCRIPT,
                    "execute",
                    side_effect=subprocess.TimeoutExpired(("git", "status"), 30),
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                result = RUNNER_SCRIPT.main()

            self.assertEqual(result, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "Tueiq GitHub runner failed\n")

    def test_tracked_python_edit_returns_exact_changed_path(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            (workspace / "core").mkdir()
            source = workspace / "core" / "sample.py"
            source.write_text("VALUE = 1\n", encoding="utf-8")
            git(workspace, "init", "-b", "main")
            git(workspace, "config", "user.name", "Tueiq Runner Test")
            git(workspace, "config", "user.email", "runner@example.invalid")
            git(workspace, "add", ".")
            git(workspace, "commit", "-m", "fixture")
            job = RunnerManifest.issue(
                execution_id="tueiq-tracked-edit-test",
                repository="islamismylifebey-web/lil-tweak",
                source_commit=git(workspace, "rev-parse", "HEAD"),
                source_tree=git(workspace, "rev-parse", "HEAD^{tree}"),
                patch=(
                    "--- a/core/sample.py\n+++ b/core/sample.py\n"
                    "@@ -1 +1 @@\n-VALUE = 1\n+VALUE = 2\n"
                ),
                authorized_paths=("core/sample.py",),
                actions=("inspect_source", "apply_patch", "compile_python", "git_diff"),
                issued_at=datetime.now(UTC) - timedelta(seconds=1),
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
                authority_digest="3" * 64,
            )

            with patch.dict(os.environ, {"GITHUB_REPOSITORY": job.repository}):
                receipt = RUNNER_SCRIPT.execute(job, workspace)

            self.assertEqual(source.read_text(encoding="utf-8"), "VALUE = 2\n")
            self.assertEqual(receipt["changedPaths"], ["core/sample.py"])
            self.assertEqual(receipt["outcome"], "succeeded")
            self.assertIs(receipt["workspaceChanged"], True)
            self.assertEqual(verify_receipt(receipt, job), receipt)

    def test_read_only_job_returns_digest_bound_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            output = Path(directory) / "output"
            workspace.mkdir()
            (workspace / "core").mkdir()
            (workspace / "core" / "sample.py").write_text("VALUE = 1\n", encoding="utf-8")
            git(workspace, "init", "-b", "main")
            git(workspace, "config", "user.name", "Tueiq Runner Test")
            git(workspace, "config", "user.email", "runner@example.invalid")
            git(workspace, "add", ".")
            git(workspace, "commit", "-m", "fixture")
            commit = git(workspace, "rev-parse", "HEAD")
            tree = git(workspace, "rev-parse", "HEAD^{tree}")
            job = RunnerManifest.issue(
                execution_id="tueiq-e2e-test",
                repository="islamismylifebey-web/lil-tweak",
                source_commit=commit,
                source_tree=tree,
                patch="",
                authorized_paths=(),
                actions=("inspect_source", "compile_python", "git_diff"),
                issued_at=datetime.now(UTC) - timedelta(seconds=1),
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
                authority_digest="3" * 64,
            )
            manifest_path = Path(directory) / "manifest.json"
            manifest_path.write_text(json.dumps(job.as_dict()), encoding="utf-8")

            completed = subprocess.run(
                (
                    sys.executable,
                    str(SCRIPT),
                    "--manifest",
                    str(manifest_path),
                    "--workspace",
                    str(workspace),
                    "--output",
                    str(output),
                ),
                cwd=ROOT,
                capture_output=True,
                text=True,
                env={**os.environ, "GITHUB_REPOSITORY": job.repository},
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            receipt = json.loads((output / "runner-receipt.json").read_text())
            digest = receipt.pop("receiptDigest")
            unsigned = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
            self.assertEqual(digest, hashlib.sha256(unsigned).hexdigest())
            self.assertEqual(receipt["manifestDigest"], job.manifest_digest)
            self.assertEqual(receipt["sourceCommit"], commit)
            self.assertEqual(receipt["outcome"], "succeeded")
            self.assertFalse(receipt["workspaceChanged"])
            self.assertEqual(receipt["changedPaths"], [])
            self.assertEqual(
                [step["action"] for step in receipt["steps"]],
                ["inspect_source", "compile_python", "git_diff"],
            )


if __name__ == "__main__":
    unittest.main()
