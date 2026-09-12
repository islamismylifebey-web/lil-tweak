import hashlib
import io
import json
import unittest
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

try:
    from core.lil_tweak.github_runner import (
        GitHubActionsRunner,
        GitHubPatchVerifier,
        GitHubRunnerError,
        RunnerManifest,
        verify_receipt,
    )
except ImportError:
    GitHubActionsRunner = None
    GitHubPatchVerifier = None
    GitHubRunnerError = RuntimeError
    RunnerManifest = None
    verify_receipt = None


COMMIT = "1" * 40
TREE = "2" * 40
DIGEST = "3" * 64


class Response:
    def __init__(self, status, body=b"", headers=None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    def read(self, size=-1):
        return self._body if size < 0 else self._body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class Opener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return self.responses.pop(0)


def manifest():
    return RunnerManifest.issue(
        execution_id="tueiq-canary-01",
        repository="islamismylifebey-web/lil-tweak",
        source_commit=COMMIT,
        source_tree=TREE,
        patch="",
        authorized_paths=(),
        actions=("inspect_source", "compile_python", "git_diff"),
        issued_at=datetime(2026, 9, 12, tzinfo=UTC),
        expires_at=datetime(2026, 9, 12, tzinfo=UTC) + timedelta(minutes=10),
        authority_digest=DIGEST,
    )


def receipt_bytes(value):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("runner-receipt.json", json.dumps(value, separators=(",", ":")))
    return stream.getvalue()


class GitHubRunnerTests(unittest.TestCase):
    def setUp(self):
        if GitHubActionsRunner is None:
            self.fail("GitHub runner adapter is missing")

    def test_manifest_has_no_shell_channel_and_binds_authority(self):
        value = manifest()

        payload = value.as_dict()
        self.assertEqual(payload["actions"], ["inspect_source", "compile_python", "git_diff"])
        self.assertEqual(payload["authorityDigest"], DIGEST)
        self.assertNotIn("command", payload)
        self.assertNotIn("shell", payload)
        self.assertEqual(len(payload["manifestDigest"]), 64)

    def test_manifest_rejects_patch_outside_authorized_paths(self):
        with self.assertRaisesRegex(GitHubRunnerError, "patch paths"):
            RunnerManifest.issue(
                execution_id="tueiq-canary-01",
                repository="islamismylifebey-web/lil-tweak",
                source_commit=COMMIT,
                source_tree=TREE,
                patch="diff --git a/secret.txt b/secret.txt\n--- /dev/null\n+++ b/secret.txt\n",
                authorized_paths=("docs/dag.md",),
                actions=("inspect_source", "apply_patch", "git_diff"),
                issued_at=datetime(2026, 9, 12, tzinfo=UTC),
                expires_at=datetime(2026, 9, 12, tzinfo=UTC) + timedelta(minutes=10),
                authority_digest=DIGEST,
            )

    def test_manifest_accepts_trusted_unified_patch_for_exact_path(self):
        value = RunnerManifest.issue(
            execution_id="tueiq-dag-01",
            repository="islamismylifebey-web/lil-tweak",
            source_commit=COMMIT,
            source_tree=TREE,
            patch="--- a/docs/dag.md\n+++ b/docs/dag.md\n@@ -1 +1 @@\n-old\n+new\n",
            authorized_paths=("docs/dag.md",),
            actions=("inspect_source", "apply_patch", "git_diff"),
            issued_at=datetime(2026, 9, 12, tzinfo=UTC),
            expires_at=datetime(2026, 9, 12, tzinfo=UTC) + timedelta(minutes=10),
            authority_digest=DIGEST,
        )

        self.assertEqual(value.authorized_paths, ("docs/dag.md",))

    def test_dispatch_parses_executes_and_returns_verified_receipt(self):
        job = manifest()
        receipt = {
            "schemaVersion": "lil-tweak-github-runner-receipt-v1",
            "executionId": job.execution_id,
            "repository": job.repository,
            "sourceCommit": job.source_commit,
            "sourceTree": job.source_tree,
            "manifestDigest": job.manifest_digest,
            "authorityDigest": job.authority_digest,
            "outcome": "succeeded",
            "workspaceChanged": False,
            "changedPaths": [],
            "steps": [
                {"action": "inspect_source", "exitCode": 0},
                {"action": "compile_python", "exitCode": 0},
                {"action": "git_diff", "exitCode": 0},
            ],
        }
        unsigned = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        receipt["receiptDigest"] = hashlib.sha256(unsigned).hexdigest()
        runs = json.dumps({
            "workflow_runs": [{
                "id": 44,
                "display_title": "Tueiq Runner tueiq-canary-01",
                "status": "completed",
                "conclusion": "success",
                # The dispatch run belongs to main; the checkout is bound by the
                # manifest and receipt instead of this workflow metadata field.
                "head_sha": "9" * 40,
            }]
        }).encode()
        artifacts = json.dumps({
            "artifacts": [{
                "id": 55,
                "name": "tueiq-runner-evidence-44",
                "expired": False,
                "size_in_bytes": 4096,
            }]
        }).encode()
        opener = Opener([
            Response(204),
            Response(200, runs),
            Response(200, artifacts),
            Response(200, receipt_bytes(receipt)),
        ])
        runner = GitHubActionsRunner(
            token="x" * 40,
            repository="islamismylifebey-web/lil-tweak",
            workflow="tueiq-runner.yml",
            opener=opener,
            sleeper=lambda _seconds: None,
            now=lambda: datetime(2026, 9, 12, tzinfo=UTC),
        )

        result = runner.execute(job)

        self.assertEqual(result["receiptDigest"], receipt["receiptDigest"])
        dispatch = opener.requests[0][0]
        self.assertEqual(dispatch.method, "POST")
        body = json.loads(dispatch.data)
        self.assertEqual(body["ref"], "main")
        self.assertEqual(body["inputs"]["execution_id"], "tueiq-canary-01")
        self.assertEqual(body["inputs"].get("expected_commit"), COMMIT)
        self.assertEqual(body["inputs"]["manifest_digest"], job.manifest_digest)
        self.assertNotIn("patch", body["inputs"])

    def test_receipt_rejects_wrong_authority(self):
        job = manifest()
        value = {
            "schemaVersion": "lil-tweak-github-runner-receipt-v1",
            "executionId": job.execution_id,
            "repository": job.repository,
            "sourceCommit": job.source_commit,
            "sourceTree": job.source_tree,
            "manifestDigest": job.manifest_digest,
            "authorityDigest": "4" * 64,
            "outcome": "succeeded",
            "workspaceChanged": False,
            "changedPaths": [],
            "steps": [],
        }
        unsigned = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        value["receiptDigest"] = hashlib.sha256(unsigned).hexdigest()

        with self.assertRaisesRegex(GitHubRunnerError, "receipt binding"):
            verify_receipt(value, job)

    def test_receipt_rejects_changed_paths_outside_manifest(self):
        job = manifest()
        value = {
            "schemaVersion": "lil-tweak-github-runner-receipt-v1",
            "executionId": job.execution_id,
            "repository": job.repository,
            "sourceCommit": job.source_commit,
            "sourceTree": job.source_tree,
            "manifestDigest": job.manifest_digest,
            "authorityDigest": job.authority_digest,
            "outcome": "succeeded",
            "workspaceChanged": True,
            "changedPaths": ["unexpected.txt"],
            "steps": [
                {"action": "inspect_source", "exitCode": 0},
                {"action": "compile_python", "exitCode": 0},
                {"action": "git_diff", "exitCode": 0},
            ],
        }
        unsigned = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        value["receiptDigest"] = hashlib.sha256(unsigned).hexdigest()

        with self.assertRaisesRegex(GitHubRunnerError, "receipt binding"):
            verify_receipt(value, job)

    def test_patch_verifier_binds_job_source_patch_and_authority(self):
        if GitHubPatchVerifier is None:
            self.fail("GitHub patch verifier is missing")
        class Runner:
            def __init__(self):
                self.manifest = None
                self.repository = "islamismylifebey-web/lil-tweak"

            def execute(self, value):
                self.manifest = value
                return {"receiptDigest": "9" * 64, "outcome": "succeeded"}

        runner = Runner()
        verifier = GitHubPatchVerifier(
            runner,
            now=lambda: datetime(2026, 9, 12, tzinfo=UTC),
        )
        job = SimpleNamespace(
            id="job-7",
            revision=4,
            git_source=SimpleNamespace(
                repository_url="https://github.com/islamismylifebey-web/lil-tweak.git",
                commit=COMMIT,
            ),
        )

        result = verifier.verify(
            job=job,
            workspace=Path("."),
            patch=b"--- a/docs/dag.md\n+++ b/docs/dag.md\n@@ -1 +1 @@\n-old\n+new\n",
            baseline_digest="5" * 64,
            final_digest="6" * 64,
            source_tree=TREE,
        )

        self.assertEqual(result["receiptDigest"], "9" * 64)
        self.assertEqual(runner.manifest.repository, "islamismylifebey-web/lil-tweak")
        self.assertEqual(runner.manifest.authorized_paths, ("docs/dag.md",))
        self.assertEqual(
            runner.manifest.actions,
            ("inspect_source", "apply_patch", "compile_python", "npm_verify", "git_diff"),
        )
        self.assertRegex(runner.manifest.authority_digest, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
