import asyncio
import hashlib
import json
import unittest
from urllib.parse import urlsplit

from core.lil_tweak.openai_agent import AgentResult
from core.lil_tweak.signing import sign_request
from core.lil_tweak.store import MemoryJobStore
from core.lil_tweak.test_world import (
    AttemptMode,
    MemoryTestWorldStore,
    TestCheck,
    TestWorldConflict,
)
from core.lil_tweak.test_world_api import TestWorldApi
from core.lil_tweak.test_world_runner import TestWorldAttemptRunner


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


class Runtime:
    def __init__(self):
        self.replayed = []
        self.prompts = []

    def prepare(self, _world, attempt):
        return f"workspace-{attempt.number}"

    def replay(self, workspace, patch):
        self.replayed.append((workspace, patch))

    def agent(self, workspace, prompt):
        self.prompts.append((workspace, prompt))
        return AgentResult("plan", "summary", "tests", "")

    def patch(self, workspace):
        return f"patch-{workspace}"

    def check(self, _workspace, _check):
        return {
            "passed": True,
            "exitCode": 0,
            "timedOut": False,
            "truncated": False,
            "stdout": "ok",
            "stderr": "",
        }

    def cleanup(self, _workspace):
        pass


class TestWorldAttemptModeTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryTestWorldStore(clock=lambda: 1786636800.0)
        self.world = self.store.create_world(
            OWNER,
            idempotency_key="world",
            name="Mode test",
            objective="Repair the bug",
            repository_url="https://github.com/example/project.git",
            commit="a" * 40,
            checks=(TestCheck("unit", ("python3", "-m", "unittest"), 60),),
            max_attempts=5,
        )

    def _fail_first(self):
        first = self.store.enqueue_attempt(
            self.world.id,
            OWNER,
            idempotency_key="first",
            mode=AttemptMode.RETRY,
        )
        lease = self.store.claim_attempt(first.id, "worker", lease_seconds=60, now=100.0)
        self.store.complete_attempt(
            lease,
            passed=False,
            feedback=({"check": "unit", "passed": False, "stdout": "old failure"},),
            cumulative_patch="old patch",
            now=101.0,
        )
        return first

    def test_attempt_mode_is_durable_and_idempotency_conflicts_across_modes(self):
        attempt = self.store.enqueue_attempt(
            self.world.id,
            OWNER,
            idempotency_key="mode-key",
            mode=AttemptMode.FRESH,
        )
        self.assertEqual(attempt.mode, AttemptMode.FRESH)
        retried = self.store.enqueue_attempt(
            self.world.id,
            OWNER,
            idempotency_key="mode-key",
            mode=AttemptMode.FRESH,
        )
        self.assertEqual(retried.id, attempt.id)
        with self.assertRaises(TestWorldConflict):
            self.store.enqueue_attempt(
                self.world.id,
                OWNER,
                idempotency_key="mode-key",
                mode=AttemptMode.RETRY,
            )

    def test_fresh_attempt_keeps_history_but_replays_no_patch_or_feedback(self):
        first = self._fail_first()
        fresh = self.store.enqueue_attempt(
            self.world.id,
            OWNER,
            idempotency_key="fresh",
            mode=AttemptMode.FRESH,
        )
        self.assertEqual(fresh.previous_attempt_id, first.id)
        self.assertEqual(fresh.mode, AttemptMode.FRESH)

        runtime = Runtime()
        runner = TestWorldAttemptRunner(
            store=self.store,
            worker_id="runner",
            lease_seconds=60,
            prepare_workspace=runtime.prepare,
            apply_previous_patch=runtime.replay,
            run_agent=runtime.agent,
            capture_cumulative_patch=runtime.patch,
            run_check=runtime.check,
            cleanup_workspace=runtime.cleanup,
            clock=lambda: 200.0,
        )
        completed = runner.run_attempt(fresh.id, OWNER)
        self.assertEqual(completed.mode, AttemptMode.FRESH)
        self.assertEqual(runtime.replayed, [])
        self.assertNotIn("Previous attempt feedback", runtime.prompts[-1][1])
        self.assertNotIn("old failure", runtime.prompts[-1][1])

    def test_retry_attempt_replays_prior_patch_and_feedback(self):
        self._fail_first()
        retry = self.store.enqueue_attempt(
            self.world.id,
            OWNER,
            idempotency_key="retry",
            mode=AttemptMode.RETRY,
        )
        runtime = Runtime()
        runner = TestWorldAttemptRunner(
            store=self.store,
            worker_id="runner",
            lease_seconds=60,
            prepare_workspace=runtime.prepare,
            apply_previous_patch=runtime.replay,
            run_agent=runtime.agent,
            capture_cumulative_patch=runtime.patch,
            run_check=runtime.check,
            cleanup_workspace=runtime.cleanup,
            clock=lambda: 200.0,
        )
        runner.run_attempt(retry.id, OWNER)
        self.assertEqual(runtime.replayed, [("workspace-2", "old patch")])
        self.assertIn("Previous attempt feedback", runtime.prompts[-1][1])
        self.assertIn("old failure", runtime.prompts[-1][1])


class TestWorldAttemptModeApiTests(unittest.TestCase):
    def setUp(self):
        self.nonce_store = MemoryJobStore()
        self.world_store = MemoryTestWorldStore(clock=lambda: 1786636800.0)
        self.secret = b"secret"
        self.now = 1786636800
        world = self.world_store.create_world(
            OWNER,
            idempotency_key="world",
            name="API mode",
            objective="Repair",
            repository_url="https://github.com/example/project.git",
            commit="b" * 40,
            checks=(TestCheck("unit", ("python3", "-m", "unittest"), 60),),
            max_attempts=3,
        )
        self.world_id = world.id

        async def fallback(_scope, _receive, send):
            await send({"type": "http.response.start", "status": 404, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        self.app = TestWorldApi(
            fallback=fallback,
            nonce_store=self.nonce_store,
            world_store=self.world_store,
            signing_keys={"primary": self.secret},
            canonical_owner_id=OWNER,
            clock=lambda: self.now,
        )
        self.nonce = 0

    def headers(self, target, body, idem):
        self.nonce += 1
        digest = hashlib.sha256(body).hexdigest()
        fields = {
            "method": "POST",
            "path_and_query": target,
            "timestamp": str(self.now),
            "nonce": f"nonce-{self.nonce}",
            "body_sha256": digest,
            "request_id": f"request-{self.nonce}",
            "idempotency_key": idem,
            "owner_id": OWNER,
        }
        return {
            "X-Lil-Tweak-Key-Id": "primary",
            "X-Lil-Tweak-Timestamp": fields["timestamp"],
            "X-Lil-Tweak-Nonce": fields["nonce"],
            "X-Lil-Tweak-Request-Id": fields["request_id"],
            "X-Lil-Tweak-Body-SHA256": digest,
            "X-Lil-Tweak-Signature": sign_request(self.secret, key_id="primary", **fields),
            "X-Lil-Tweak-Owner": OWNER,
            "Idempotency-Key": idem,
        }

    def test_api_accepts_explicit_fresh_mode_and_returns_authoritative_mode(self):
        target = f"/v1/test-worlds/{self.world_id}/attempts"
        body = b'{"mode":"fresh"}'
        status, attempt = asyncio.run(asgi_request(self.app, "POST", target, body, self.headers(target, body, "fresh")))
        self.assertEqual(status, 202)
        self.assertEqual(attempt["mode"], "fresh")

    def test_api_empty_body_object_defaults_to_retry(self):
        target = f"/v1/test-worlds/{self.world_id}/attempts"
        body = b"{}"
        status, attempt = asyncio.run(asgi_request(self.app, "POST", target, body, self.headers(target, body, "retry")))
        self.assertEqual(status, 202)
        self.assertEqual(attempt["mode"], "retry")


if __name__ == "__main__":
    unittest.main()
