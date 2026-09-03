import io
import json
import unittest
from datetime import UTC, datetime
from urllib.error import HTTPError

from core.lil_tweak.galor_runner_v3 import (
    GALOR_RUNNER_CONTRACT_SHA256,
    GALOR_RUNNER_EXECUTION_HOST,
    GalorRunnerV3Client,
)


NOW = datetime(2026, 9, 3, 21, 50, 0, tzinfo=UTC)
COMMIT = "a" * 40
TOKEN = "service-token-" + "x" * 32
NONCE = "n" * 32


class FakeResponse:
    def __init__(self, body, *, status=200, headers=None):
        self._body = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        self.status = status
        self.headers = headers or {
            "content-type": "application/json",
            "content-length": str(len(self._body)),
        }

    def read(self, size=-1):
        return self._body if size < 0 else self._body[:size]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeOpener:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if self.error:
            raise self.error
        return self.response


def success_payload(**overrides):
    authorization = {
        "schemaVersion": "runner-connection-authorization-v1",
        "serviceId": "lil-tweak",
        "nonce": NONCE,
        "tenantId": "tenant-01",
        "runnerId": GALOR_RUNNER_EXECUTION_HOST,
        "executionHost": GALOR_RUNNER_EXECUTION_HOST,
        "contractSha256": GALOR_RUNNER_CONTRACT_SHA256,
        "repositoryId": "github:islamismylifebey-web/lil-tweak",
        "repositoryCommit": COMMIT,
        "action": "runner.reportIdentity",
        "expiresAt": int(NOW.timestamp() * 1000) + 30_000,
    }
    payload = {
        "schemaVersion": "galor-executor-health-handshake-v2",
        "authenticated": True,
        "serviceId": "lil-tweak",
        "hub": "islamismylifebey-web/galor-hub",
        "nonce": NONCE,
        "runnerId": GALOR_RUNNER_EXECUTION_HOST,
        "tenantId": "tenant-01",
        "checkedAt": NOW.isoformat().replace("+00:00", "Z"),
        "expiresAt": datetime.fromtimestamp(
            NOW.timestamp() + 30, UTC
        ).isoformat().replace("+00:00", "Z"),
        "gateway": {
            "healthy": True,
            "storeAvailable": True,
            "transportConfigured": True,
            "signingAvailable": True,
        },
        "heartbeat": {
            "action": "runner.reportIdentity",
            "scope": f"repo:lil-tweak@{COMMIT}",
            "maxAgeMs": 60_000,
        },
        "qualification": {"schema_version": "runner-qualification-bundle-v1"},
        "authorization": authorization,
    }
    for key, value in overrides.items():
        if key.startswith("authorization__"):
            authorization[key.split("__", 1)[1]] = value
        else:
            payload[key] = value
    return payload


class RunnerV3HandshakeTests(unittest.TestCase):
    def client(self, opener):
        return GalorRunnerV3Client(
            "https://galor.example",
            service_token=TOKEN,
            repository_commit=COMMIT,
            opener=opener,
            nonce=lambda: NONCE,
            now=lambda: NOW,
        )

    def test_authenticated_handshake_binds_exact_v3_identity_and_candidate(self):
        opener = FakeOpener(FakeResponse(success_payload()))
        result = self.client(opener).handshake()

        self.assertTrue(result.connected)
        self.assertEqual(result.reason, "connected_unqualified")
        self.assertEqual(result.runner_id, GALOR_RUNNER_EXECUTION_HOST)
        self.assertEqual(result.tenant_id, "tenant-01")
        self.assertEqual(result.checked_at, NOW.isoformat().replace("+00:00", "Z"))
        request, timeout = opener.requests[0]
        self.assertEqual(request.full_url, "https://galor.example/api/executor/handshake")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(timeout, 2.0)
        self.assertEqual(request.get_header("Authorization"), f"Bearer {TOKEN}")
        self.assertEqual(request.get_header("X-galor-service-id"), "lil-tweak")
        self.assertEqual(json.loads(request.data), {"nonce": NONCE})
        self.assertNotIn(TOKEN, repr(result))

    def test_handshake_rejects_wrong_identity_contract_commit_or_nonce(self):
        cases = (
            {"runnerId": "wrong-runner"},
            {"nonce": "x" * 32},
            {"authorization__executionHost": "galor-private-cloud-01"},
            {"authorization__contractSha256": "0" * 64},
            {"authorization__repositoryCommit": "b" * 40},
            {"authorization__runnerId": "wrong-runner"},
            {"authorization__action": "runner.inspectRepository"},
            {"serviceId": "owner"},
            {"hub": "other/repository"},
        )
        for change in cases:
            with self.subTest(change=change):
                opener = FakeOpener(FakeResponse(success_payload(**change)))
                result = self.client(opener).handshake()
                self.assertFalse(result.connected)
                self.assertEqual(result.reason, "invalid_handshake")

    def test_handshake_requires_gateway_and_heartbeat_proof(self):
        payload = success_payload()
        payload["gateway"]["signingAvailable"] = False
        result = self.client(FakeOpener(FakeResponse(payload))).handshake()
        self.assertFalse(result.connected)
        self.assertEqual(result.reason, "invalid_handshake")

        payload = success_payload()
        payload["heartbeat"]["action"] = "runner.inspectRepository"
        result = self.client(FakeOpener(FakeResponse(payload))).handshake()
        self.assertFalse(result.connected)
        self.assertEqual(result.reason, "invalid_handshake")

    def test_handshake_rejects_expired_or_future_timestamps(self):
        expired = success_payload(
            expiresAt=datetime.fromtimestamp(
                NOW.timestamp() - 1, UTC
            ).isoformat().replace("+00:00", "Z")
        )
        result = self.client(FakeOpener(FakeResponse(expired))).handshake()
        self.assertFalse(result.connected)
        self.assertEqual(result.reason, "invalid_handshake")

        future = success_payload(
            checkedAt=datetime.fromtimestamp(
                NOW.timestamp() + 10, UTC
            ).isoformat().replace("+00:00", "Z")
        )
        result = self.client(FakeOpener(FakeResponse(future))).handshake()
        self.assertFalse(result.connected)
        self.assertEqual(result.reason, "invalid_handshake")

    def test_handshake_fails_closed_on_redirect_malformed_or_oversized_response(self):
        redirect = HTTPError(
            "https://galor.example/api/executor/handshake",
            302,
            "Found",
            {},
            io.BytesIO(b""),
        )
        result = self.client(FakeOpener(error=redirect)).handshake()
        self.assertFalse(result.connected)
        self.assertEqual(result.reason, "handshake_unavailable")

        result = self.client(
            FakeOpener(FakeResponse(b"not-json", headers={"content-type": "application/json"}))
        ).handshake()
        self.assertFalse(result.connected)
        self.assertEqual(result.reason, "invalid_handshake")

        body = b"{" + b"x" * (64 * 1024) + b"}"
        result = self.client(FakeOpener(FakeResponse(body))).handshake()
        self.assertFalse(result.connected)
        self.assertEqual(result.reason, "handshake_unavailable")

    def test_runtime_supervisor_blocker_remains_disconnected_and_secret_safe(self):
        body = json.dumps(
            {
                "error": "Live runner execution remains blocked.",
                "code": "VERIFIED_SANDBOX_RUNTIME_NOT_CONNECTED",
                "authenticated": True,
                "serviceId": "lil-tweak",
            }
        ).encode("utf-8")
        error = HTTPError(
            "https://galor.example/api/executor/handshake",
            503,
            "Unavailable",
            {"content-type": "application/json", "content-length": str(len(body))},
            io.BytesIO(body),
        )
        result = self.client(FakeOpener(error=error)).handshake()
        self.assertFalse(result.connected)
        self.assertEqual(result.reason, "runtime_supervisor_not_connected")
        self.assertNotIn(TOKEN, repr(result))

    def test_generic_http_failure_does_not_expose_response_or_service_token(self):
        body = json.dumps({"error": TOKEN}).encode("utf-8")
        error = HTTPError(
            "https://galor.example/api/executor/handshake",
            503,
            "Unavailable",
            {"content-type": "application/json", "content-length": str(len(body))},
            io.BytesIO(body),
        )
        result = self.client(FakeOpener(error=error)).handshake()
        self.assertFalse(result.connected)
        self.assertEqual(result.reason, "handshake_unavailable")
        self.assertNotIn(TOKEN, repr(result))


if __name__ == "__main__":
    unittest.main()
