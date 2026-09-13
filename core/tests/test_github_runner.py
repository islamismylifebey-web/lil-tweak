import hashlib
import http.client
import io
import json
import unittest
import zipfile
from datetime import UTC, datetime, timedelta
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlsplit
from urllib.request import BaseHandler, HTTPRedirectHandler
from urllib.response import addinfourl

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


class ArtifactRedirectFixture(BaseHandler):
    handler_order = 100

    def __init__(self, location, download_body=None):
        self.location = location
        self.download_body = download_body
        self.requests = []

    def https_open(self, request):
        self.requests.append(request)
        headers = Message()
        if request.host != "api.github.com":
            if self.download_body is None:
                return None
            code, body = 200, self.download_body
        elif request.selector.endswith("/actions/runs/44/artifacts"):
            code = 200
            body = json.dumps({"artifacts": [{
                "id": 91, "name": "tueiq-runner-evidence-44",
                "expired": False, "size_in_bytes": 4096,
            }]}).encode()
        elif request.selector.endswith("/actions/artifacts/91/zip"):
            code, body = 302, b""
            headers["Location"] = self.location
        else:
            raise AssertionError("unexpected API request")
        response = addinfourl(io.BytesIO(body), headers, request.full_url, code)
        response.msg = "Found" if code == 302 else "OK"
        return response


def receipt_bytes(value):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("runner-receipt.json", json.dumps(value, separators=(",", ":")))
    return stream.getvalue()


def signed_receipt(job, *, steps=None):
    value = {
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
        "steps": steps if steps is not None else [
            {"action": "inspect_source", "exitCode": 0},
            {"action": "compile_python", "exitCode": 0},
            {"action": "git_diff", "exitCode": 0},
        ],
    }
    value["receiptDigest"] = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return value


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

    def test_manifest_parse_rejects_non_string_scalars(self):
        scalar_keys = (
            "schemaVersion",
            "executionId",
            "repository",
            "sourceCommit",
            "sourceTree",
            "patch",
            "issuedAt",
            "expiresAt",
            "authorityDigest",
            "manifestDigest",
        )
        for key in scalar_keys:
            with self.subTest(key=key):
                payload = manifest().as_dict()
                payload[key] = [payload[key]]
                with self.assertRaises(GitHubRunnerError):
                    RunnerManifest.parse(payload)

    def test_manifest_parse_rejects_invalid_array_shapes(self):
        for key, value in (
            ("authorizedPaths", ()),
            ("actions", ("inspect_source", "compile_python", "git_diff")),
            ("authorizedPaths", [None]),
            ("actions", ["inspect_source", None, "git_diff"]),
        ):
            with self.subTest(key=key, value=value):
                payload = manifest().as_dict()
                payload[key] = value
                with self.assertRaises(GitHubRunnerError):
                    RunnerManifest.parse(payload)

    def test_manifest_parse_rejects_non_mapping(self):
        for value in (None, [], "manifest"):
            with self.subTest(value=value):
                with self.assertRaises(GitHubRunnerError):
                    RunnerManifest.parse(value)

    def test_manifest_parse_rejects_non_ascii_digest_without_leaking(self):
        payload = manifest().as_dict()
        payload["manifestDigest"] = "é"

        with self.assertRaisesRegex(GitHubRunnerError, "manifest digest mismatch"):
            RunnerManifest.parse(payload)

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
        dispatch_result = json.dumps({"workflow_run_id": 44}).encode()
        run = json.dumps({
            "id": 44,
            "event": "workflow_dispatch",
            "display_title": "Tueiq Runner tueiq-canary-01",
            "status": "completed",
            "conclusion": "success",
            # The dispatch run belongs to main; the checkout is bound by the
            # manifest and receipt instead of this workflow metadata field.
            "head_sha": "9" * 40,
        }).encode()
        artifacts = json.dumps({
            "artifacts": [{
                "id": 91,
                "name": "tueiq-runner-evidence-44",
                "expired": False,
                "size_in_bytes": 4096,
            }]
        }).encode()
        opener = Opener([
            Response(200, dispatch_result),
            Response(200, run),
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
        self.assertTrue(body["return_run_details"])
        self.assertEqual(body["inputs"]["execution_id"], "tueiq-canary-01")
        self.assertEqual(body["inputs"].get("expected_commit"), COMMIT)
        self.assertEqual(body["inputs"]["manifest_digest"], job.manifest_digest)
        self.assertNotIn("patch", body["inputs"])
        repository_prefix = "/repos/islamismylifebey-web/lil-tweak"
        request_paths = [
            urlsplit(request.full_url).path.removeprefix(repository_prefix)
            for request, _ in opener.requests
        ]
        self.assertEqual(request_paths, [
            "/actions/workflows/tueiq-runner.yml/dispatches",
            "/actions/runs/44",
            "/actions/runs/44/artifacts",
            "/actions/artifacts/91/zip",
        ])

    def test_dispatch_rejects_ambiguous_workflow_run_ids(self):
        for body in (
            {},
            {"workflow_run_id": "44"},
            {"workflow_run_id": True},
            {"workflow_run_id": 0},
            {"workflow_run_id": -1},
        ):
            with self.subTest(body=body):
                opener = Opener([Response(200, json.dumps(body).encode())])
                runner = GitHubActionsRunner(
                    token="x" * 40,
                    repository="islamismylifebey-web/lil-tweak",
                    opener=opener,
                    now=lambda: datetime(2026, 9, 12, tzinfo=UTC),
                )

                with self.assertRaisesRegex(GitHubRunnerError, "dispatch failed"):
                    runner.execute(manifest())

    def test_api_authorization_is_not_forwarded_to_https_artifact_redirect(self):
        runner = GitHubActionsRunner(token="x" * 40, repository="owner/repository")
        with patch.object(runner._opener, "open", return_value=Response(200)) as opened:
            runner._request("GET", "/actions/artifacts/91/zip")
        initial = opened.call_args.args[0]
        self.assertTrue(initial.get_header("Authorization") == "Bearer " + "x" * 40)
        self.assertEqual(urlsplit(initial.full_url).hostname, "api.github.com")
        handler = next(
            item for item in runner._opener.handlers
            if isinstance(item, HTTPRedirectHandler)
        )
        target = "https://download.example.invalid/evidence.zip?sig=a%2Fb%2Bc%3D&part=1"

        redirected = handler.redirect_request(initial, None, 302, "Found", {}, target)

        self.assertEqual(redirected.full_url, target)
        self.assertFalse(redirected.has_header("Authorization"))
        self.assertNotIn("Authorization", initial.headers)
        self.assertIn("Authorization", initial.unredirected_hdrs)

    def test_artifact_redirect_rejects_unsafe_targets_with_content_free_error(self):
        runner = GitHubActionsRunner(token="x" * 40, repository="owner/repository")
        with patch.object(runner._opener, "open", return_value=Response(200)) as opened:
            runner._request("GET", "/actions/artifacts/91/zip")
        initial = opened.call_args.args[0]
        handler = next(
            item for item in runner._opener.handlers
            if isinstance(item, HTTPRedirectHandler)
        )
        for label, target in (
            ("HTTP", "http://download.example.invalid/evidence.zip"),
            ("username", "https://user@download.example.invalid/evidence.zip"),
            ("password", "https://user:pass@download.example.invalid/evidence.zip"),
            ("missing hostname", "https:///evidence.zip"),
            ("empty hostname", "https://:443/evidence.zip"),
        ):
            with self.subTest(case=label):
                with self.assertRaises(GitHubRunnerError) as caught:
                    handler.redirect_request(initial, None, 302, "Found", {}, target)
                self.assertEqual(str(caught.exception), "GitHub runner redirect rejected")

    def test_redirect_entry_point_hides_urllib_parsing_and_protocol_errors(self):
        runner = GitHubActionsRunner(token="x" * 40, repository="owner/repository")
        with patch.object(runner._opener, "open", return_value=Response(200)) as opened:
            runner._request("GET", "/actions/artifacts/91/zip")
        initial = opened.call_args.args[0]
        handler = next(
            item for item in runner._opener.handlers
            if isinstance(item, HTTPRedirectHandler)
        )
        for label, target in (
            ("unsupported protocol", "file:///evidence.zip"),
            ("malformed hostname", "https://[invalid/evidence.zip"),
        ):
            with self.subTest(case=label):
                with self.assertRaises(GitHubRunnerError) as caught:
                    handler.http_error_302(
                        initial, io.BytesIO(), 302, "Found", {"location": target}
                    )
                self.assertEqual(str(caught.exception), "GitHub runner redirect rejected")

    def test_production_opener_rejects_malformed_redirect_authorities(self):
        for authority in (
            "download.example.invalid:authority-marker",
            "download.example.invalid:65536",
            "download.example.invalid:0",
            "download.example.invalid:",
            "authority%20marker.invalid",
            "authority%0amarker.invalid",
            "authority%2fmarker.invalid",
            "authority\\marker.invalid",
        ):
            with self.subTest(authority=authority):
                job = manifest()
                with patch("urllib.request.getproxies", return_value={}):
                    runner = GitHubActionsRunner(token="x" * 40, repository=job.repository)
                fixture = ArtifactRedirectFixture(
                    f"https://{authority}/evidence.zip?sig=query-marker"
                )
                runner._opener.add_handler(fixture)
                with patch.object(
                    http.client.HTTPConnection, "connect",
                    side_effect=AssertionError("network forbidden"),
                ), self.assertRaises(GitHubRunnerError) as caught:
                    runner._collect(44, job)
                self.assertEqual(str(caught.exception), "GitHub runner redirect rejected")
                self.assertEqual(len(fixture.requests), 2)

    def test_production_opener_preserves_signed_redirect_without_credentials(self):
        job = manifest()
        receipt = signed_receipt(job)
        target = "https://download.example.invalid:443/evidence.zip?sig=a%2Fb%2Bc%3D"
        with patch("urllib.request.getproxies", return_value={}):
            runner = GitHubActionsRunner(token="x" * 40, repository=job.repository)
        fixture = ArtifactRedirectFixture(target, receipt_bytes(receipt))
        runner._opener.add_handler(fixture)
        with patch.object(
            http.client.HTTPConnection, "connect",
            side_effect=AssertionError("network forbidden"),
        ):
            self.assertEqual(runner._collect(44, job), receipt)
        self.assertEqual(len(fixture.requests), 3)
        for request in fixture.requests[:2]:
            self.assertEqual(request.get_header("Authorization"), "Bearer " + "x" * 40)
        self.assertEqual(fixture.requests[-1].full_url, target)
        self.assertFalse(fixture.requests[-1].has_header("Authorization"))

    def test_production_opener_hides_transport_invalid_url(self):
        job = manifest()
        with patch("urllib.request.getproxies", return_value={}):
            runner = GitHubActionsRunner(token="x" * 40, repository=job.repository)
        runner._opener.add_handler(ArtifactRedirectFixture(
            "https://download.example.invalid/evidence.zip?sig=query-marker"
        ))
        with patch.object(
            http.client, "HTTPSConnection",
            side_effect=http.client.InvalidURL("authority-marker query-marker"),
        ), self.assertRaises(GitHubRunnerError) as caught:
            runner._collect(44, job)
        self.assertEqual(str(caught.exception), "GitHub runner redirect rejected")

    def test_artifact_collection_rejects_malformed_shapes_before_download(self):
        artifact = {
            "id": 91,
            "name": "tueiq-runner-evidence-44",
            "expired": False,
            "size_in_bytes": 4096,
        }
        cases = [
            ("non-mapping response", value)
            for value in (None, [], "response", 7, True)
        ]
        cases.extend(
            ("non-list artifacts", {"artifacts": value})
            for value in (None, {}, "artifacts", 7, True)
        )
        cases.extend(
            ("malformed list member", {"artifacts": [artifact, value]})
            for value in (None, [], "artifact", 7, True)
        )
        cases.extend([
            ("missing artifacts", {}),
            ("no matching artifact", {"artifacts": [{**artifact, "name": "other"}]}),
            ("duplicate matching artifacts", {"artifacts": [artifact, {**artifact, "id": 92}]}),
            ("missing id", {"artifacts": [{key: value for key, value in artifact.items() if key != "id"}]}),
            ("missing size", {"artifacts": [{key: value for key, value in artifact.items() if key != "size_in_bytes"}]}),
        ])
        for field, values in (
            ("id", ("91", 91.0, True, False, 0, -1, None)),
            ("size_in_bytes", ("4096", 4096.0, True, False, -1, 1_000_001, None)),
            ("expired", (True, 0, 1, "false", None)),
        ):
            cases.extend(
                (f"invalid {field}", {"artifacts": [{**artifact, field: value}]})
                for value in values
            )
        job = manifest()
        for index, (label, body) in enumerate(cases):
            with self.subTest(case=label, index=index):
                opener = Opener([
                    Response(200, json.dumps(body).encode()),
                    Response(200, receipt_bytes(signed_receipt(job))),
                ])
                runner = GitHubActionsRunner(
                    token="x" * 40, repository=job.repository, opener=opener
                )

                with self.assertRaises(GitHubRunnerError) as caught:
                    runner._collect(44, job)

                self.assertEqual(str(caught.exception), "GitHub runner evidence unavailable")
                self.assertEqual(len(opener.requests), 1)
                self.assertEqual(
                    urlsplit(opener.requests[0][0].full_url).path,
                    f"/repos/{job.repository}/actions/runs/44/artifacts",
                )

    def test_artifact_collection_accepts_integer_size_boundaries(self):
        job = manifest()
        for size in (0, 1_000_000):
            with self.subTest(size=size):
                body = {"artifacts": [{
                    "id": 91,
                    "name": "tueiq-runner-evidence-44",
                    "expired": False,
                    "size_in_bytes": size,
                }]}
                receipt = signed_receipt(job)
                opener = Opener([
                    Response(200, json.dumps(body).encode()),
                    Response(200, receipt_bytes(receipt)),
                ])
                runner = GitHubActionsRunner(
                    token="x" * 40, repository=job.repository, opener=opener
                )

                self.assertEqual(runner._collect(44, job), receipt)
                self.assertEqual(
                    urlsplit(opener.requests[-1][0].full_url).path,
                    f"/repos/{job.repository}/actions/artifacts/91/zip",
                )

    def test_exact_run_rejects_misbound_metadata(self):
        expected = {
            "id": 44,
            "event": "workflow_dispatch",
            "display_title": "Tueiq Runner tueiq-canary-01",
            "status": "completed",
            "conclusion": "success",
        }
        for field, value in (
            ("id", 45),
            ("event", "push"),
            ("display_title", "Tueiq Runner another-execution"),
        ):
            with self.subTest(field=field):
                run = {**expected, field: value}
                opener = Opener([
                    Response(200, b'{"workflow_run_id":44}'),
                    Response(200, json.dumps(run).encode()),
                ])
                runner = GitHubActionsRunner(
                    token="x" * 40,
                    repository="islamismylifebey-web/lil-tweak",
                    opener=opener,
                    sleeper=lambda _seconds: None,
                    now=lambda: datetime(2026, 9, 12, tzinfo=UTC),
                )

                with self.assertRaisesRegex(GitHubRunnerError, "status failed"):
                    runner.execute(manifest())

    def test_exact_run_timeout_sleeps_then_cancels_only_that_run(self):
        queued = json.dumps({
            "id": 44,
            "event": "workflow_dispatch",
            "display_title": "Tueiq Runner tueiq-canary-01",
            "status": "queued",
            "conclusion": None,
        }).encode()
        sleeps = []
        opener = Opener([
            Response(200, b'{"workflow_run_id":44}'),
            *[Response(200, queued) for _ in range(360)],
            Response(202),
        ])
        runner = GitHubActionsRunner(
            token="x" * 40,
            repository="islamismylifebey-web/lil-tweak",
            opener=opener,
            sleeper=sleeps.append,
            now=lambda: datetime(2026, 9, 12, tzinfo=UTC),
        )

        with self.assertRaisesRegex(GitHubRunnerError, "GitHub runner timed out"):
            runner.execute(manifest())

        self.assertEqual(sleeps, [5] * 360)
        cancel = opener.requests[-1][0]
        self.assertEqual(cancel.method, "POST")
        self.assertEqual(
            urlsplit(cancel.full_url).path.removeprefix(
                "/repos/islamismylifebey-web/lil-tweak"
            ),
            "/actions/runs/44/cancel",
        )

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

    def test_receipt_rejects_numeric_workspace_changed_values(self):
        unchanged = manifest()
        changed = RunnerManifest.issue(
            execution_id=unchanged.execution_id,
            repository=unchanged.repository,
            source_commit=unchanged.source_commit,
            source_tree=unchanged.source_tree,
            patch="--- a/docs/dag.md\n+++ b/docs/dag.md\n@@ -1 +1 @@\n-old\n+new\n",
            authorized_paths=("docs/dag.md",),
            actions=("inspect_source", "apply_patch", "git_diff"),
            issued_at=datetime(2026, 9, 12, tzinfo=UTC),
            expires_at=datetime(2026, 9, 12, tzinfo=UTC) + timedelta(minutes=10),
            authority_digest=DIGEST,
        )
        for job, numeric_values in ((unchanged, (0, 0.0)), (changed, (1, 1.0))):
            for workspace_changed in numeric_values:
                with self.subTest(value=workspace_changed):
                    value = signed_receipt(job, steps=[
                        {"action": action, "exitCode": 0} for action in job.actions
                    ])
                    value.pop("receiptDigest")
                    value["workspaceChanged"] = workspace_changed
                    value["changedPaths"] = list(job.authorized_paths)
                    value["receiptDigest"] = hashlib.sha256(
                        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()

                    with self.assertRaises(GitHubRunnerError) as caught:
                        verify_receipt(value, job)

                    self.assertEqual(str(caught.exception), "runner receipt binding failed")

    def test_receipt_rejects_malformed_steps(self):
        job = manifest()
        cases = (
            [None],
            [
                {"action": "inspect_source", "exitCode": 0},
                {"action": "compile_python"},
                {"action": "git_diff", "exitCode": 0},
            ],
            [
                {"action": "inspect_source", "exitCode": 0},
                {"action": "compile_python", "exitCode": 0, "detail": "extra"},
                {"action": "git_diff", "exitCode": 0},
            ],
            [
                {"action": "inspect_source", "exitCode": False},
                {"action": "compile_python", "exitCode": 0},
                {"action": "git_diff", "exitCode": 0},
            ],
        )
        for steps in cases:
            with self.subTest(steps=steps):
                with self.assertRaises(GitHubRunnerError):
                    verify_receipt(signed_receipt(job, steps=steps), job)

    def test_receipt_rejects_non_string_digest(self):
        job = manifest()
        for digest in (None, 123, ["digest"], False):
            with self.subTest(digest=digest):
                value = signed_receipt(job)
                value["receiptDigest"] = digest
                with self.assertRaises(GitHubRunnerError):
                    verify_receipt(value, job)

    def test_receipt_rejects_non_ascii_digest_without_leaking(self):
        job = manifest()
        value = signed_receipt(job)
        value["receiptDigest"] = "é"

        with self.assertRaisesRegex(GitHubRunnerError, "receipt binding failed"):
            verify_receipt(value, job)

    def test_patch_verifier_binds_job_source_patch_and_authority(self):
        if GitHubPatchVerifier is None:
            self.fail("GitHub patch verifier is missing")
        class Runner:
            def __init__(self):
                self.manifests = []
                self.repository = "islamismylifebey-web/lil-tweak"

            def execute(self, value):
                self.manifests.append(value)
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
            patch=b"--- a/docs/dag.md\n+++ b/docs/dag.md\n@@ -1 +1 @@\n-old\n+new\n",
            baseline_digest="5" * 64,
            final_digest="6" * 64,
            source_commit=COMMIT,
            source_tree=TREE,
        )

        verifier.verify(
            job=job,
            patch=b"--- a/docs/dag.md\n+++ b/docs/dag.md\n@@ -1 +1 @@\n-old\n+new\n",
            baseline_digest="5" * 64,
            final_digest="6" * 64,
            source_commit=COMMIT,
            source_tree="7" * 40,
        )

        self.assertEqual(result["receiptDigest"], "9" * 64)
        manifest = runner.manifests[0]
        self.assertEqual(manifest.repository, "islamismylifebey-web/lil-tweak")
        self.assertEqual(manifest.source_commit, COMMIT)
        self.assertEqual(manifest.source_tree, TREE)
        self.assertEqual(manifest.authorized_paths, ("docs/dag.md",))
        self.assertEqual(
            manifest.actions,
            ("inspect_source", "apply_patch", "compile_python", "npm_verify", "git_diff"),
        )
        self.assertRegex(manifest.authority_digest, r"^[0-9a-f]{64}$")
        self.assertNotEqual(manifest.authority_digest, runner.manifests[1].authority_digest)

    def test_patch_verifier_rejects_commit_that_differs_from_requested_source(self):
        runner = SimpleNamespace(repository="islamismylifebey-web/lil-tweak")
        verifier = GitHubPatchVerifier(runner)
        job = SimpleNamespace(
            id="job-8",
            revision=1,
            git_source=SimpleNamespace(
                repository_url="https://github.com/islamismylifebey-web/lil-tweak.git",
                commit=COMMIT,
            ),
        )

        with self.assertRaisesRegex(GitHubRunnerError, "source commit"):
            verifier.verify(
                job=job,
                patch=b"",
                baseline_digest="5" * 64,
                final_digest="6" * 64,
                source_commit="8" * 40,
                source_tree=TREE,
            )

    def test_patch_verifier_accepts_safe_github_url_variants(self):
        class Runner:
            repository = "islamismylifebey-web/lil-tweak"

            def __init__(self):
                self.manifests = []

            def execute(self, value):
                self.manifests.append(value)
                return {"outcome": "succeeded"}

        for url in (
            "https://github.com/ISLAMISMYLIFEBEY-WEB/LIL-TWEAK",
            "https://github.com/IslamIsMyLifeBey-Web/Lil-Tweak/",
            "https://github.com/ISLAMISMYLIFEBEY-WEB/LIL-TWEAK.GIT",
            "https://GitHub.Com:443/IslamIsMyLifeBey-Web/Lil-Tweak.git/",
        ):
            with self.subTest(url=url):
                runner = Runner()
                verifier = GitHubPatchVerifier(
                    runner,
                    now=lambda: datetime(2026, 9, 12, tzinfo=UTC),
                )
                job = SimpleNamespace(
                    id="job-9",
                    revision=1,
                    git_source=SimpleNamespace(
                        repository_url=url,
                        commit=COMMIT,
                    ),
                )

                verifier.verify(
                    job=job,
                    patch=b"",
                    baseline_digest="5" * 64,
                    final_digest="6" * 64,
                    source_commit=COMMIT,
                    source_tree=TREE,
                )

                self.assertEqual(
                    runner.manifests[0].repository,
                    "islamismylifebey-web/lil-tweak",
                )

    def test_patch_verifier_rejects_unsafe_github_urls(self):
        runner = SimpleNamespace(repository="owner/repository")
        verifier = GitHubPatchVerifier(runner)
        for url in (
            "https://user@github.com/owner/repository",
            "https://user:pass@github.com/owner/repository",
            "https://github.com/owner/repository?ref=main",
            "https://github.com/owner/repository?",
            "https://github.com/owner/repository#fragment",
            "https://github.com/owner/repository#",
            "https://github.com:/owner/repository",
            "https://github.com:444/owner/repository",
            "https://github.com:notaport/owner/repository",
            "https://github.com/ow\nner/repository",
            "https://github.com/ow\rner/repository",
            "https://github.com/ow\tner/repository",
            "https://github.com/owner%2Frepository/repository",
            "https://github.com/owner/repository%2Fextra",
            "https://github.com/owner/repository%5Cextra",
            "https://github.com//owner/repository",
            "https://github.com/owner//repository",
            "https://github.com/owner/repository/extra",
            "https://github.com/owner/repository//",
            "https://github.com/./repository",
            "https://github.com/../repository",
            "https://github.com/owner/.",
            "https://github.com/owner/..",
        ):
            with self.subTest(url=url):
                job = SimpleNamespace(
                    id="job-10",
                    revision=1,
                    git_source=SimpleNamespace(
                        repository_url=url,
                        commit=COMMIT,
                    ),
                )

                with self.assertRaises(GitHubRunnerError):
                    verifier.verify(
                        job=job,
                        patch=b"",
                        baseline_digest="5" * 64,
                        final_digest="6" * 64,
                        source_commit=COMMIT,
                        source_tree=TREE,
                    )


if __name__ == "__main__":
    unittest.main()
