import asyncio
import hashlib
import json
import unittest
from urllib.parse import urlsplit

from core.lil_tweak.signing import sign_request
from core.lil_tweak.store import MemoryJobStore
from core.lil_tweak.test_world import MemoryTestWorldStore
from core.lil_tweak.test_world_api import TestWorldApi


OWNER = "0123456789abcdef0123456789abcdef"


async def asgi_request(app, method, target, body=b"", headers=None):
    parsed = urlsplit(target)
    sent = []
    messages = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await app(
        {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "path": parsed.path,
            "raw_path": parsed.path.encode(),
            "query_string": parsed.query.encode(),
            "headers": [(name.lower().encode(), value.encode()) for name, value in (headers or {}).items()],
        },
        receive,
        send,
    )
    response_body = b"".join(item.get("body", b"") for item in sent[1:])
    return sent[0]["status"], json.loads(response_body) if response_body else None


class TestWorldApiTests(unittest.TestCase):
    def setUp(self):
        self.nonce_store = MemoryJobStore()
        self.world_store = MemoryTestWorldStore(clock=lambda: 1786636800.0)
        self.secret = b"test-secret"
        self.now = 1786636800
        self.notified = []

        async def fallback(_scope, _receive, send):
            await send({"type": "http.response.start", "status": 418, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        self.app = TestWorldApi(
            fallback=fallback,
            nonce_store=self.nonce_store,
            world_store=self.world_store,
            signing_keys={"primary": self.secret},
            canonical_owner_id=OWNER,
            clock=lambda: self.now,
            on_attempt_queued=lambda attempt_id, owner_id: self.notified.append((attempt_id, owner_id)),
        )
        self.nonce = 0

    def signed_headers(self, method, target, body=b"", *, idem="idem-1", owner=OWNER):
        self.nonce += 1
        digest = hashlib.sha256(body).hexdigest()
        fields = {
            "method": method,
            "path_and_query": target,
            "timestamp": str(self.now),
            "nonce": f"nonce-{self.nonce}",
            "body_sha256": digest,
            "request_id": f"request-{self.nonce}",
            "idempotency_key": idem or "",
            "owner_id": owner,
        }
        signature = sign_request(self.secret, key_id="primary", **fields)
        headers = {
            "X-Lil-Tweak-Key-Id": "primary",
            "X-Lil-Tweak-Timestamp": fields["timestamp"],
            "X-Lil-Tweak-Nonce": fields["nonce"],
            "X-Lil-Tweak-Request-Id": fields["request_id"],
            "X-Lil-Tweak-Body-SHA256": digest,
            "X-Lil-Tweak-Signature": signature,
            "X-Lil-Tweak-Owner": owner,
        }
        if idem is not None:
            headers["Idempotency-Key"] = idem
        return headers

    def request(self, method, target, body=b"", headers=None):
        return asyncio.run(asgi_request(self.app, method, target, body, headers))

    @staticmethod
    def create_body(objective="Repair the bug"):
        return json.dumps(
            {
                "name": "Durable repair",
                "objective": objective,
                "repositoryUrl": "https://github.com/example/project.git",
                "commit": "a" * 40,
                "maxAttempts": 3,
                "checks": [
                    {"name": "unit tests", "command": ["python3", "-m", "unittest"], "timeoutSeconds": 60}
                ],
            },
            separators=(",", ":"),
        ).encode()

    def test_non_test_world_path_delegates_without_interference(self):
        self.assertEqual(self.request("GET", "/healthz"), (418, None))

    def test_create_list_get_and_enqueue_use_authoritative_store(self):
        body = self.create_body()
        headers = self.signed_headers("POST", "/v1/test-worlds", body)
        status, created = self.request("POST", "/v1/test-worlds", body, headers)
        self.assertEqual(status, 201)
        self.assertEqual(created["status"], "ready")
        self.assertEqual(created["attempts"], [])
        self.assertNotIn("leaseGeneration", json.dumps(created))
        self.assertNotIn("worker", json.dumps(created).lower())

        retry = self.request(
            "POST", "/v1/test-worlds", body,
            self.signed_headers("POST", "/v1/test-worlds", body, idem="idem-1"),
        )
        self.assertEqual(retry[0], 201)
        self.assertEqual(retry[1]["id"], created["id"])

        list_target = "/v1/test-worlds?limit=5"
        list_status, listed = self.request(
            "GET", list_target, headers=self.signed_headers("GET", list_target, idem=None)
        )
        self.assertEqual(list_status, 200)
        self.assertEqual([item["id"] for item in listed["worlds"]], [created["id"]])

        detail_target = f"/v1/test-worlds/{created['id']}"
        detail_status, detail = self.request(
            "GET", detail_target, headers=self.signed_headers("GET", detail_target, idem=None)
        )
        self.assertEqual(detail_status, 200)
        self.assertEqual(detail["source"]["commit"], "a" * 40)

        attempt_target = f"{detail_target}/attempts"
        attempt_status, attempt = self.request(
            "POST", attempt_target, b"{}",
            self.signed_headers("POST", attempt_target, b"{}", idem="attempt-1"),
        )
        self.assertEqual(attempt_status, 202)
        self.assertEqual(attempt["number"], 1)
        self.assertEqual(attempt["status"], "queued")
        self.assertEqual(self.notified, [(attempt["id"], OWNER)])

        _, refreshed = self.request(
            "GET", detail_target, headers=self.signed_headers("GET", detail_target, idem=None)
        )
        self.assertEqual(refreshed["status"], "running")
        self.assertEqual([item["id"] for item in refreshed["attempts"]], [attempt["id"]])

    def test_create_rejects_unknown_fields_owner_mismatch_and_idempotency_conflict(self):
        body = self.create_body()
        payload = json.loads(body)
        payload["fakeStatus"] = "passed"
        invalid = json.dumps(payload, separators=(",", ":")).encode()
        status, result = self.request(
            "POST", "/v1/test-worlds", invalid,
            self.signed_headers("POST", "/v1/test-worlds", invalid),
        )
        self.assertEqual((status, result["error"]["code"]), (400, "invalid_request"))

        status, result = self.request(
            "POST", "/v1/test-worlds", body,
            self.signed_headers("POST", "/v1/test-worlds", body, idem="owner", owner="f" * 32),
        )
        self.assertEqual((status, result["error"]["code"]), (403, "owner_forbidden"))

        first_headers = self.signed_headers("POST", "/v1/test-worlds", body, idem="same")
        self.assertEqual(self.request("POST", "/v1/test-worlds", body, first_headers)[0], 201)
        conflicting = self.create_body(objective="Different objective")
        status, result = self.request(
            "POST", "/v1/test-worlds", conflicting,
            self.signed_headers("POST", "/v1/test-worlds", conflicting, idem="same"),
        )
        self.assertEqual((status, result["error"]["code"]), (409, "idempotency_conflict"))

    def test_list_uses_one_authoritative_store_operation_for_worlds_and_counts(self):
        body = self.create_body()
        self.request(
            "POST", "/v1/test-worlds", body,
            self.signed_headers("POST", "/v1/test-worlds", body),
        )

        calls = 0
        original = self.world_store.list_worlds_with_attempt_counts

        def counted(owner_id, *, limit=20):
            nonlocal calls
            calls += 1
            return original(owner_id, limit=limit)

        self.world_store.list_worlds_with_attempt_counts = counted
        self.world_store.list_attempts = lambda *_args, **_kwargs: self.fail("list endpoint loaded attempt payloads")
        target = "/v1/test-worlds?limit=5"
        status, listed = self.request("GET", target, headers=self.signed_headers("GET", target, idem=None))

        self.assertEqual(status, 200)
        self.assertEqual(calls, 1)
        self.assertEqual(listed["worlds"][0]["attemptCount"], 0)


if __name__ == "__main__":
    unittest.main()
