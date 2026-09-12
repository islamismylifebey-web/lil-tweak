import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from core.lil_tweak.github_runner import RunnerManifest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "tueiq_github_runner.py"


def git(root, *args):
    return subprocess.run(
        ("git", "-C", str(root), *args),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class GitHubRunnerJobTests(unittest.TestCase):
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
                    "python3",
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
