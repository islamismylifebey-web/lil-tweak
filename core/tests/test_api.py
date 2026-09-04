import asyncio
import hashlib
import hmac
import json
import unittest
from urllib.parse import urlsplit

from core.lil_tweak.api import create_app
from core.lil_tweak.contracts import JobMode, JobState
from core.lil_tweak.limits import MAX_EVIDENCE_BYTES
from core.lil_tweak.orchestrator import AdmissionUnavailable
from core.lil_tweak.signing import sign_request
from core.lil_tweak.store import MemoryJobStore


OWNER = "a0885bc0b2c079e996629061a723c74d"


async def asgi_request(app, method, target, body=b"", headers=None, chunks=None):
    parsed = urlsplit(target)
    sent = []
    messages = []
    if chunks is None:
        chunks = [body]
    for index, chunk in enumerate(chunks):
        messages.append(
            {
                "type": "http.request",
                "body": chunk,
                "more_body": index < len(chunks) - 1,
            }
        )

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
            "headers": [
                (name.lower().encode(), value.encode())
                for name, value in (headers or {}).items()
            ],
        },
        receive,
        send,
    )
    status = sent[0]["status"]
    response_body = b"".join(item.get("body", b"") for item in sent[1:])
    try:
        payload = json.loads(response_body) if response_body else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = response_body
    response_headers = {
        name.decode("latin-1"): value.decode("latin-1")
        for name, value in sent[0].get("headers", [])
    }
    return status, payload, response_headers


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryJobStore()
        self.secret = b"test-secret"
        self.now = 1786636800
        self.app = create_app(
            store=self.store,
            signing_keys={"primary": self.secret},
            canonical_owner_id=OWNER,
            readiness=lambda: {
                "database": True,
                "runner": True,
                "git": True,
                "workspace": True,
                "evidence": True,
                "signing": True,
                "admission": True,
            },
            clock=lambda: self.now,
        )
        self.nonce = 0

    def approval_job(self, idempotency_key):
        job = self.store.create_job(OWNER, idempotency_key, JobMode.BUILD, "Build")
        for state in (
            JobState.QUEUED,
            JobState.INGESTING,
            JobState.PLANNING,
            JobState.EXECUTING,
            JobState.COLLECTING,
        ):
            job = self.store.update_job(
                job.id, owner_id=OWNER, expected_revision=job.revision, state=state
            )
        return self.store.update_job(
            job.id,
            owner_id=OWNER,
            expected_revision=job.revision,
            state=JobState.AWAITING_APPROVAL,
            proposal_digest="a" * 64,
            source_digest="c" * 64,
            approval_proposal={
                "action": "export_patch",
                "target": "owner_download",
                "policyVersion": "v1",
                "resourceProfile": {"cpus": 1},
                "sourceDigest": "c" * 64,
                "proposalDigest": "a" * 64,
                "expiresAt": "2026-08-13T16:05:00Z",
            },
            evidence_manifest={"changes.patch": {"sha256": "b" * 64, "bytes": 4}},
        )

    def signed_headers(self, method, target, body=b"", *, nonce=None, idem="idem-1", owner=OWNER):
        self.nonce += 1
        nonce = nonce or f"nonce-{self.nonce}"
        digest = hashlib.sha256(body).hexdigest()
        fields = {
            "method": method,
            "path_and_query": target,
            "timestamp": str(self.now),
            "nonce": nonce,
            "body_sha256": digest,
            "request_id": f"request-{self.nonce}",
            "idempotency_key": idem or "",
            "owner_id": owner,
        }
        signature = sign_request(self.secret, key_id="primary", **fields)
        result = {
            "X-Lil-Tweak-Key-Id": "primary",
            "X-Lil-Tweak-Timestamp": fields["timestamp"],
            "X-Lil-Tweak-Nonce": nonce,
            "X-Lil-Tweak-Request-Id": fields["request_id"],
            "X-Lil-Tweak-Body-SHA256": digest,
            "X-Lil-Tweak-Signature": signature,
            "X-Lil-Tweak-Owner": owner,
        }
        if idem is not None:
            result["Idempotency-Key"] = idem
        return result

    def request(self, method, target, body=b"", headers=None, chunks=None):
        status, payload, _ = asyncio.run(
            asgi_request(self.app, method, target, body, headers, chunks)
        )
        return status, payload

    def request_with_headers(self, method, target, body=b"", headers=None, chunks=None):
        return asyncio.run(asgi_request(self.app, method, target, body, headers, chunks))

    def test_health_is_public_but_readiness_is_signed(self):
        self.assertEqual(self.request("GET", "/healthz"), (200, {"status": "ok"}))
        self.assertEqual(self.request("GET", "/readyz")[0], 401)
        status, payload = self.request(
            "GET",
            "/readyz",
            headers=self.signed_headers("GET", "/readyz", idem=None),
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            payload,
            {
                "status": "ready",
                "checks": {
                    "database": True,
                    "runner": True,
                    "git": True,
                    "workspace": True,
                    "evidence": True,
                    "signing": True,
                    "admission": True,
                },
            },
        )

    def test_ready_accepts_absent_http_idempotency_as_empty_canonical_field(self):
        nonce = "readiness-empty-idempotency"
        request_id = "readiness-request"
        digest = hashlib.sha256(b"").hexdigest()
        canonical = "\n".join(
            (
                "v2",
                "primary",
                "GET",
                "/readyz",
                str(self.now),
                nonce,
                digest,
                request_id,
                "",
                OWNER,
            )
        )
        signature = hmac.new(
            self.secret, canonical.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        headers = {
            "X-Lil-Tweak-Key-Id": "primary",
            "X-Lil-Tweak-Timestamp": str(self.now),
            "X-Lil-Tweak-Nonce": nonce,
            "X-Lil-Tweak-Request-Id": request_id,
            "X-Lil-Tweak-Body-SHA256": digest,
            "X-Lil-Tweak-Signature": signature,
            "X-Lil-Tweak-Owner": OWNER,
        }

        self.assertNotIn("Idempotency-Key", headers)
        status, payload = self.request("GET", "/readyz", headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ready")

    def test_job_creation_status_and_idempotency(self):
        body = json.dumps({"mode": "build", "prompt": "Build it"}).encode()
        headers = self.signed_headers("POST", "/v1/jobs", body)
        status, created = self.request("POST", "/v1/jobs", body, headers)
        self.assertEqual(status, 202)
        self.assertEqual(created["state"], "queued")
        self.assertEqual(created["coreRevision"], 1)
        self.assertNotIn("prompt", created)
        self.assertIsNone(created["proposalDigest"])
        self.assertEqual(created["evidence"], [])

        retry_headers = self.signed_headers("POST", "/v1/jobs", body, idem="idem-1")
        retry_status, retried = self.request("POST", "/v1/jobs", body, retry_headers)
        self.assertEqual(retry_status, 202)
        self.assertEqual(retried["id"], created["id"])

        target = f"/v1/jobs/{created['id']}"
        status_headers = self.signed_headers("GET", target, idem=None)
        get_status, fetched = self.request("GET", target, headers=status_headers)
        self.assertEqual(get_status, 200)
        self.assertEqual(fetched["revision"], 1)

    def test_get_idempotency_header_does_not_cache_a_job_snapshot(self):
        job = self.store.create_job(OWNER, "poll-job", JobMode.BUILD, "Build")
        target = f"/v1/jobs/{job.id}"
        first_status, first = self.request(
            "GET",
            target,
            headers=self.signed_headers("GET", target, idem="poll-key"),
        )
        job = self.store.update_job(
            job.id,
            owner_id=OWNER,
            expected_revision=job.revision,
            state=JobState.QUEUED,
        )
        second_status, second = self.request(
            "GET",
            target,
            headers=self.signed_headers("GET", target, idem="poll-key"),
        )
        self.assertEqual((first_status, second_status), (200, 200))
        self.assertEqual(first["coreRevision"], 0)
        self.assertEqual(second["coreRevision"], job.revision)

    def test_queued_transition_and_audit_event_do_not_have_a_crash_window(self):
        original = self.store.append_event
        self.store.append_event = lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("split audit write")
        )
        body = json.dumps({"mode": "build", "prompt": "Build"}).encode()
        status, created = self.request(
            "POST",
            "/v1/jobs",
            body,
            self.signed_headers("POST", "/v1/jobs", body, idem="atomic-queued"),
        )
        self.store.append_event = original
        self.assertEqual(status, 202)
        self.assertEqual(created["state"], "queued")
        self.assertEqual(
            [event.kind for event in self.store.list_events(created["id"], OWNER)],
            ["queued"],
        )

    def test_admission_rejection_is_retryable_and_does_not_leave_queued_job(self):
        submitted = []

        def reject(job_id, owner_id):
            submitted.append((job_id, owner_id))
            raise AdmissionUnavailable()

        app = create_app(
            store=self.store,
            signing_keys={"primary": self.secret},
            canonical_owner_id=OWNER,
            readiness=lambda: {"admission": False},
            clock=lambda: self.now,
            on_job_queued=reject,
        )
        body = json.dumps({"mode": "build", "prompt": "Build it"}).encode()
        status, payload, _ = asyncio.run(
            asgi_request(
                app,
                "POST",
                "/v1/jobs",
                body,
                self.signed_headers("POST", "/v1/jobs", body, idem="overloaded"),
            )
        )
        self.assertEqual(
            (status, payload),
            (503, {"error": {"code": "admission_unavailable"}}),
        )
        rejected = self.store.get_job(submitted[0][0], OWNER)
        self.assertEqual(rejected.state, JobState.FAILED)
        self.assertEqual(
            self.store.list_events(rejected.id, OWNER)[-1].kind,
            "admission_unavailable",
        )

    def test_signed_ingress_without_identity_header_maps_to_canonical_owner(self):
        body = b'{"mode":"build","prompt":"Build"}'
        headers = self.signed_headers("POST", "/v1/jobs", body, idem="canonical")
        del headers["X-Lil-Tweak-Owner"]
        status, created = self.request("POST", "/v1/jobs", body, headers)
        self.assertEqual(status, 202)
        self.assertEqual(
            self.store.get_job(created["id"], OWNER).owner_id,
            OWNER,
        )

    def test_cloudflare_control_payload_shape_is_accepted(self):
        body = json.dumps(
            {
                "id": "job:0123456789abcdef0123456789abcdef",
                "ownerKey": OWNER,
                "mode": "debug",
                "projectId": None,
                "prompt": "Fix it",
                "requestR2Key": "engineering/opaque/request.json",
                "sources": [],
            }
        ).encode()
        headers = self.signed_headers("POST", "/v1/jobs", body, idem="control-shape")
        del headers["X-Lil-Tweak-Owner"]
        status, created = self.request("POST", "/v1/jobs", body, headers)
        self.assertEqual(status, 202)
        self.assertEqual(created["mode"], "debug")

    def test_authentication_happens_before_domain_json_parsing_and_replay_is_conflict(self):
        body = b"not-json"
        unsigned_status, unsigned = self.request("POST", "/v1/jobs", body)
        self.assertEqual(unsigned_status, 401)
        self.assertEqual(unsigned, {"error": {"code": "authentication_failed"}})

        headers = self.signed_headers("POST", "/v1/jobs", body, nonce="replay")
        status, payload = self.request("POST", "/v1/jobs", body, headers)
        self.assertEqual((status, payload), (400, {"error": {"code": "invalid_request"}}))
        status, payload = self.request("POST", "/v1/jobs", body, headers)
        self.assertEqual((status, payload), (409, {"error": {"code": "request_replayed"}}))

    def test_streaming_body_cap_is_enforced(self):
        chunks = [b"x" * 20_000, b"y" * 20_000]
        body = b"".join(chunks)
        headers = self.signed_headers("POST", "/v1/jobs", body)
        status, payload = self.request(
            "POST", "/v1/jobs", headers=headers, chunks=chunks
        )
        self.assertEqual((status, payload), (413, {"error": {"code": "body_too_large"}}))

    def test_owner_isolation_and_chat_execution_are_rejected(self):
        body = b'{"mode":"build","prompt":"Build"}'
        status, payload = self.request(
            "POST",
            "/v1/jobs",
            body,
            self.signed_headers("POST", "/v1/jobs", body, owner="other"),
        )
        self.assertEqual((status, payload), (403, {"error": {"code": "owner_forbidden"}}))

        chat = b'{"mode":"chat","prompt":"Explain this project"}'
        status, payload = self.request(
            "POST",
            "/v1/jobs",
            chat,
            self.signed_headers("POST", "/v1/jobs", chat, idem="chat"),
        )
        self.assertEqual(
            (status, payload),
            (400, {"error": {"code": "invalid_project_context"}}),
        )

    def test_project_context_is_bounded_and_persisted_for_chat(self):
        context = {
            "schemaVersion": "project-context-v1",
            "projectId": "project:one",
            "name": "One",
            "description": "Selected project",
            "status": "active",
            "requirements": ["Explain status"],
        }
        body = json.dumps(
            {
                "mode": "chat",
                "prompt": "What is next?",
                "projectId": "project:one",
                "projectContext": context,
            }
        ).encode()
        status, created = self.request(
            "POST",
            "/v1/jobs",
            body,
            self.signed_headers("POST", "/v1/jobs", body, idem="chat-context"),
        )
        self.assertEqual(status, 202)
        stored = self.store.get_job(created["id"], OWNER)
        self.assertEqual(stored.project_context, context)

        mismatch = json.dumps(
            {
                "mode": "chat",
                "prompt": "What is next?",
                "projectId": "project:other",
                "projectContext": context,
            }
        ).encode()
        status, response = self.request(
            "POST",
            "/v1/jobs",
            mismatch,
            self.signed_headers("POST", "/v1/jobs", mismatch, idem="context-mismatch"),
        )
        self.assertEqual(
            (status, response),
            (400, {"error": {"code": "invalid_project_context"}}),
        )

    def test_chat_rejects_uploaded_and_git_source_intake(self):
        context = {
            "schemaVersion": "project-context-v1",
            "projectId": "project:one",
            "name": "One",
            "status": "active",
        }
        source = {
            "id": "src:0123456789abcdef0123456789abcdef",
            "filename": "main.py",
            "mediaType": "text/x-python",
            "sizeBytes": 1,
            "sha256": "a" * 64,
            "r2Key": f"engineering/{OWNER}/jobs/job:0123456789abcdef0123456789abcdef/sources/src:0123456789abcdef0123456789abcdef",
        }
        additions = (
            {
                "id": "job:0123456789abcdef0123456789abcdef",
                "ownerKey": OWNER,
                "sources": [source],
            },
            {
                "gitSource": {
                    "repositoryUrl": "https://example.com/project.git",
                    "commit": "a" * 40,
                }
            },
        )
        for index, addition in enumerate(additions):
            payload = {
                "mode": "chat",
                "prompt": "Explain",
                "projectId": "project:one",
                "projectContext": context,
                **addition,
            }
            body = json.dumps(payload).encode()
            status, response = self.request(
                "POST",
                "/v1/jobs",
                body,
                self.signed_headers(
                    "POST", "/v1/jobs", body, idem=f"chat-source-{index}"
                ),
            )
            self.assertEqual(
                (status, response),
                (400, {"error": {"code": "invalid_source_manifest"}}),
            )

    def test_create_payload_identity_is_bound_to_authenticated_owner(self):
        for payload in (
            {"mode": "build", "prompt": "Build", "ownerKey": "other"},
            {"mode": "build", "prompt": "Build", "id": "not-a-public-job"},
        ):
            with self.subTest(payload=payload):
                body = json.dumps(payload).encode()
                status, _response = self.request(
                    "POST",
                    "/v1/jobs",
                    body,
                    self.signed_headers("POST", "/v1/jobs", body, idem=str(payload)),
                )
                self.assertIn(status, {400, 403})

    def test_git_source_requires_https_and_an_immutable_commit(self):
        good = {
            "repositoryUrl": "https://example.com/owner/repository.git",
            "commit": "A" * 40,
        }
        body = json.dumps(
            {"mode": "build", "prompt": "Inspect", "gitSource": good}
        ).encode()
        status, created = self.request(
            "POST",
            "/v1/jobs",
            body,
            self.signed_headers("POST", "/v1/jobs", body, idem="git-source"),
        )
        self.assertEqual(status, 202)
        stored = self.store.get_job(created["id"], OWNER)
        self.assertEqual(stored.git_source.commit, "a" * 40)
        self.assertEqual(stored.git_source.repository_url, good["repositoryUrl"])
        expected_source = {"repositoryUrl": good["repositoryUrl"], "commit": "a" * 40}
        self.assertEqual(created.get("gitSource"), expected_source)
        path = f"/v1/jobs/{created['id']}"
        status, observed = self.request("GET", path, headers=self.signed_headers("GET", path))
        self.assertEqual(status, 200)
        self.assertEqual(observed.get("gitSource"), expected_source)

        bad = json.dumps(
            {
                "mode": "build",
                "prompt": "Inspect",
                "gitSource": {
                    "repositoryUrl": "https://user:token@example.com/repo.git",
                    "commit": "main",
                },
            }
        ).encode()
        status, payload = self.request(
            "POST",
            "/v1/jobs",
            bad,
            self.signed_headers("POST", "/v1/jobs", bad, idem="bad-git"),
        )
        self.assertEqual(
            (status, payload),
            (400, {"error": {"code": "invalid_git_source"}}),
        )

    def test_source_manifest_is_capped_at_ten(self):
        body = json.dumps(
            {"mode": "build", "prompt": "Build", "sources": [None] * 11}
        ).encode()
        status, payload = self.request(
            "POST",
            "/v1/jobs",
            body,
            self.signed_headers("POST", "/v1/jobs", body, idem="too-many-sources"),
        )
        self.assertEqual(
            (status, payload), (400, {"error": {"code": "invalid_request"}})
        )

    def test_uploaded_sources_require_sha256_and_bind_idempotency(self):
        source = {
            "id": "src:0123456789abcdef0123456789abcdef",
            "filename": "main.py",
            "mediaType": "text/x-python",
            "sizeBytes": 12,
            "sha256": "a" * 64,
            "r2Key": f"engineering/{OWNER}/jobs/job:0123456789abcdef0123456789abcdef/sources/src:0123456789abcdef0123456789abcdef",
        }
        payload = {
            "id": "job:0123456789abcdef0123456789abcdef",
            "ownerKey": OWNER,
            "mode": "build",
            "prompt": "Build",
            "sources": [source],
        }
        body = json.dumps(payload).encode()
        status, created = self.request(
            "POST",
            "/v1/jobs",
            body,
            self.signed_headers("POST", "/v1/jobs", body, idem="source-sha"),
        )
        self.assertEqual(status, 202)
        self.assertEqual(
            self.store.get_job(created["id"], OWNER).sources[0].sha256,
            "a" * 64,
        )

        missing = json.loads(body)
        del missing["sources"][0]["sha256"]
        missing_body = json.dumps(missing).encode()
        status, response = self.request(
            "POST",
            "/v1/jobs",
            missing_body,
            self.signed_headers(
                "POST", "/v1/jobs", missing_body, idem="missing-source-sha"
            ),
        )
        self.assertEqual(
            (status, response),
            (400, {"error": {"code": "invalid_source_manifest"}}),
        )

        changed = json.loads(body)
        changed["sources"][0]["sha256"] = "b" * 64
        changed_body = json.dumps(changed).encode()
        status, response = self.request(
            "POST",
            "/v1/jobs",
            changed_body,
            self.signed_headers(
                "POST", "/v1/jobs", changed_body, idem="source-sha"
            ),
        )
        self.assertEqual(
            (status, response),
            (409, {"error": {"code": "idempotency_conflict"}}),
        )

    def test_decision_and_cancel_routes_enforce_revision(self):
        job = self.store.create_job(OWNER, "manual", JobMode.BUILD, "Build")
        job = self.store.update_job(
            job.id, owner_id=OWNER, expected_revision=0, state=JobState.QUEUED
        )
        cancel_target = f"/v1/jobs/{job.id}/cancel"
        cancel_body = json.dumps(
            {
                "jobId": "job:local",
                "ownerKey": "opaque",
                "revision": 999,
                "expectedCoreRevision": job.revision,
            }
        ).encode()
        status, cancelled = self.request(
            "POST",
            cancel_target,
            cancel_body,
            self.signed_headers("POST", cancel_target, cancel_body, idem="cancel"),
        )
        self.assertEqual(status, 202)
        self.assertTrue(cancelled["cancel_requested"])
        self.assertEqual(cancelled["coreRevision"], job.revision + 1)

        stale_headers = self.signed_headers(
            "POST", cancel_target, cancel_body, idem="cancel-stale"
        )
        stale_status, stale = self.request(
            "POST", cancel_target, cancel_body, stale_headers
        )
        self.assertEqual((stale_status, stale), (409, {"error": {"code": "stale_revision"}}))

    def test_cancel_retry_is_idempotent_and_rejects_changed_bytes(self):
        job = self.store.create_job(OWNER, "cancel-retry", JobMode.BUILD, "Build")
        job = self.store.update_job(
            job.id, owner_id=OWNER, expected_revision=0, state=JobState.QUEUED
        )
        target = f"/v1/jobs/{job.id}/cancel"
        body = json.dumps({"expectedCoreRevision": job.revision}).encode()
        headers = self.signed_headers("POST", target, body, idem="cancel-lost-response")

        first_status, first = self.request("POST", target, body, headers)
        retry_status, retry = self.request(
            "POST",
            target,
            body,
            self.signed_headers(
                "POST", target, body, idem="cancel-lost-response"
            ),
        )
        self.assertEqual((first_status, retry_status), (202, 202))
        self.assertEqual(retry, first)

        changed = json.dumps(
            {"expectedCoreRevision": job.revision, "jobId": "different"}
        ).encode()
        changed_status, changed_payload = self.request(
            "POST",
            target,
            changed,
            self.signed_headers(
                "POST", target, changed, idem="cancel-lost-response"
            ),
        )
        self.assertEqual(
            (changed_status, changed_payload),
            (409, {"error": {"code": "idempotency_conflict"}}),
        )

    def test_cancel_retry_recovers_after_reserved_request_crash_window(self):
        job = self.store.create_job(OWNER, "cancel-crash", JobMode.BUILD, "Build")
        job = self.store.update_job(
            job.id, owner_id=OWNER, expected_revision=0, state=JobState.QUEUED
        )
        target = f"/v1/jobs/{job.id}/cancel"
        body = json.dumps({"expectedCoreRevision": job.revision}).encode()
        original = self.store.request_cancel_idempotent
        self.store.request_cancel_idempotent = lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("process died")
        )
        status, _ = self.request(
            "POST",
            target,
            body,
            self.signed_headers("POST", target, body, idem="cancel-crash-key"),
        )
        self.assertEqual(status, 500)
        self.assertFalse(self.store.get_job(job.id, OWNER).cancel_requested)
        self.store.request_cancel_idempotent = original
        retry_status, retry = self.request(
            "POST",
            target,
            body,
            self.signed_headers("POST", target, body, idem="cancel-crash-key"),
        )
        self.assertEqual(retry_status, 202)
        self.assertTrue(retry["cancel_requested"])

    def test_rejection_decision_is_terminal(self):
        job = self.store.create_job(OWNER, "decision-job", JobMode.BUILD, "Build")
        states = [
            JobState.QUEUED,
            JobState.INGESTING,
            JobState.PLANNING,
            JobState.EXECUTING,
            JobState.COLLECTING,
        ]
        for state in states:
            job = self.store.update_job(
                job.id, owner_id=OWNER, expected_revision=job.revision, state=state
            )
        job = self.store.update_job(
            job.id,
            owner_id=OWNER,
            expected_revision=job.revision,
            state=JobState.AWAITING_APPROVAL,
            proposal_digest="a" * 64,
            evidence_manifest={"manifest.json": "b" * 64},
        )
        target = f"/v1/jobs/{job.id}/decisions"
        body = json.dumps(
            {
                "jobId": "job:local",
                "ownerKey": "opaque",
                "decision": "reject",
                "reason": "Not this proposal",
                "revision": 999,
                "expectedCoreRevision": job.revision,
                "proposalDigest": "a" * 64,
            }
        ).encode()
        status, payload = self.request(
            "POST",
            target,
            body,
            self.signed_headers("POST", target, body, idem="decision"),
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["state"], "rejected")

    def test_rejection_retry_recovers_after_idempotency_reservation(self):
        job = self.store.create_job(OWNER, "reject-crash", JobMode.BUILD, "Build")
        for state in (
            JobState.QUEUED,
            JobState.INGESTING,
            JobState.PLANNING,
            JobState.EXECUTING,
            JobState.COLLECTING,
        ):
            job = self.store.update_job(
                job.id, owner_id=OWNER, expected_revision=job.revision, state=state
            )
        job = self.store.update_job(
            job.id,
            owner_id=OWNER,
            expected_revision=job.revision,
            state=JobState.AWAITING_APPROVAL,
            proposal_digest="a" * 64,
            evidence_manifest={"manifest.json": "b" * 64},
        )
        target = f"/v1/jobs/{job.id}/decisions"
        body = json.dumps(
            {
                "decision": "reject",
                "expectedCoreRevision": job.revision,
                "proposalDigest": job.proposal_digest,
            }
        ).encode()
        original = self.store.decide_job_idempotent
        self.store.decide_job_idempotent = lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("process died")
        )
        first_status, _ = self.request(
            "POST",
            target,
            body,
            self.signed_headers("POST", target, body, idem="reject-crash-key"),
        )
        self.assertEqual(first_status, 500)
        self.assertEqual(
            self.store.get_job(job.id, OWNER).state,
            JobState.AWAITING_APPROVAL,
        )
        self.store.decide_job_idempotent = original
        retry_status, retry = self.request(
            "POST",
            target,
            body,
            self.signed_headers("POST", target, body, idem="reject-crash-key"),
        )
        self.assertEqual(retry_status, 200)
        self.assertEqual(retry["state"], "rejected")

    def test_cancel_awaiting_approval_reaches_terminal_cancelled(self):
        job = self.store.create_job(OWNER, "cancel-approval", JobMode.BUILD, "Build")
        for state in (
            JobState.QUEUED,
            JobState.INGESTING,
            JobState.PLANNING,
            JobState.EXECUTING,
            JobState.COLLECTING,
        ):
            job = self.store.update_job(
                job.id, owner_id=OWNER, expected_revision=job.revision, state=state
            )
        job = self.store.update_job(
            job.id,
            owner_id=OWNER,
            expected_revision=job.revision,
            state=JobState.AWAITING_APPROVAL,
            proposal_digest="a" * 64,
            evidence_manifest={"manifest.json": "b" * 64},
            source_digest="c" * 64,
        )
        target = f"/v1/jobs/{job.id}/cancel"
        body = json.dumps({"expectedCoreRevision": job.revision}).encode()
        status, payload = self.request(
            "POST",
            target,
            body,
            self.signed_headers("POST", target, body, idem="cancel-approval"),
        )
        self.assertEqual(status, 202)
        self.assertEqual(payload["state"], "cancelled")
        self.assertTrue(payload["cancel_requested"])
        self.assertEqual(
            self.store.list_events(job.id, OWNER)[-1].kind, "cancelled"
        )

        events_after_cancel = self.store.list_events(job.id, OWNER)
        retry_status, retry = self.request(
            "POST",
            target,
            body,
            self.signed_headers("POST", target, body, idem="cancel-approval"),
        )
        self.assertEqual((retry_status, retry), (202, payload))
        self.assertEqual(
            self.store.list_events(job.id, OWNER), events_after_cancel
        )

    def test_signed_cancel_of_pending_export_revokes_the_download(self):
        job = self.approval_job("cancel-pending-export")
        token = "A" * 43
        decision_target = f"/v1/jobs/{job.id}/decisions"
        decision_body = json.dumps({
            "decision": "approve",
            "expectedCoreRevision": job.revision,
            "approvalProposal": dict(job.approval_proposal),
            "approvalTokenHash": hashlib.sha256(token.encode("ascii")).hexdigest(),
        }).encode()
        approved_status, applying = self.request(
            "POST",
            decision_target,
            decision_body,
            self.signed_headers("POST", decision_target, decision_body, idem="approve-before-cancel"),
        )
        self.assertEqual(approved_status, 200)

        cancel_target = f"/v1/jobs/{job.id}/cancel"
        cancel_body = json.dumps({"expectedCoreRevision": applying["coreRevision"]}).encode()
        cancel_headers = self.signed_headers(
            "POST", cancel_target, cancel_body, idem="cancel-pending-export"
        )
        cancelled_status, cancelled = self.request(
            "POST", cancel_target, cancel_body, cancel_headers
        )
        retry_status, retry = self.request(
            "POST",
            cancel_target,
            cancel_body,
            self.signed_headers("POST", cancel_target, cancel_body, idem="cancel-pending-export"),
        )
        self.assertEqual((cancelled_status, retry_status), (202, 202))
        self.assertEqual(retry, cancelled)
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertFalse(cancelled["approvalConsumed"])

        evidence = applying["evidence"][0]
        export_target = f"/v1/jobs/{job.id}/exports/patch"
        export_body = json.dumps({
            "approvalToken": token,
            "expectedCoreRevision": applying["coreRevision"],
            "proposalDigest": applying["proposalDigest"],
            "sourceDigest": applying["sourceDigest"],
            "policyVersion": applying["approvalProposal"]["policyVersion"],
            "resourceProfile": applying["approvalProposal"]["resourceProfile"],
            "evidenceId": evidence["id"],
            "evidenceName": evidence["filename"],
            "evidenceSha256": evidence["sha256"],
            "evidenceSizeBytes": evidence["sizeBytes"],
        }).encode()
        export_status, export = self.request(
            "POST",
            export_target,
            export_body,
            self.signed_headers("POST", export_target, export_body, idem="export-after-cancel"),
        )
        self.assertEqual((export_status, export), (409, {"error": {"code": "invalid_approval"}}))

    def test_signed_cancel_rejects_every_terminal_job_without_mutation(self):
        for state in (
            JobState.COMPLETED,
            JobState.REJECTED,
            JobState.CANCELLED,
            JobState.FAILED,
            JobState.TIMED_OUT,
        ):
            with self.subTest(state=state.value):
                job = self._terminal_job(state, f"signed-cancel:{state.value}")
                events_before = self.store.list_events(job.id, OWNER)
                target = f"/v1/jobs/{job.id}/cancel"
                body = json.dumps({"expectedCoreRevision": job.revision}).encode()

                status, payload = self.request(
                    "POST",
                    target,
                    body,
                    self.signed_headers(
                        "POST", target, body, idem=f"terminal:{state.value}"
                    ),
                )

                self.assertEqual(
                    (status, payload),
                    (400, {"error": {"code": "invalid_request"}}),
                )
                self.assertEqual(self.store.get_job(job.id, OWNER), job)
                self.assertEqual(
                    self.store.list_events(job.id, OWNER), events_before
                )

    def test_snapshot_evidence_descriptors_include_signed_core_paths(self):
        job = self.store.create_job(OWNER, "evidence-job", JobMode.BUILD, "Build")
        for state in (
            JobState.QUEUED,
            JobState.INGESTING,
            JobState.PLANNING,
            JobState.EXECUTING,
            JobState.COLLECTING,
        ):
            job = self.store.update_job(
                job.id, owner_id=OWNER, expected_revision=job.revision, state=state
            )
        job = self.store.update_job(
            job.id,
            owner_id=OWNER,
            expected_revision=job.revision,
            state=JobState.COMPLETED,
            proposal_digest="a" * 64,
            evidence_manifest={"summary.md": hashlib.sha256(b"Done").hexdigest()},
        )
        target = f"/v1/jobs/{job.id}"
        status, snapshot = self.request(
            "GET", target, headers=self.signed_headers("GET", target, idem=None)
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            snapshot["evidence"][0]["corePath"],
            f"/v1/jobs/{job.id}/evidence/summary.md",
        )

    def _terminal_job(self, state, idempotency_key):
        job = self.store.create_job(OWNER, idempotency_key, JobMode.BUILD, "Build")
        if state in {JobState.CANCELLED, JobState.FAILED, JobState.TIMED_OUT}:
            return self.store.update_job(
                job.id,
                owner_id=OWNER,
                expected_revision=job.revision,
                state=state,
            )
        for next_state in (
            JobState.QUEUED,
            JobState.INGESTING,
            JobState.PLANNING,
            JobState.EXECUTING,
            JobState.COLLECTING,
        ):
            job = self.store.update_job(
                job.id,
                owner_id=OWNER,
                expected_revision=job.revision,
                state=next_state,
            )
        if state is JobState.COMPLETED:
            return self.store.update_job(
                job.id,
                owner_id=OWNER,
                expected_revision=job.revision,
                state=state,
            )
        job = self.store.update_job(
            job.id,
            owner_id=OWNER,
            expected_revision=job.revision,
            state=JobState.AWAITING_APPROVAL,
            proposal_digest="a" * 64,
            evidence_manifest={"manifest.json": "b" * 64},
        )
        return self.store.update_job(
            job.id,
            owner_id=OWNER,
            expected_revision=job.revision,
            state=state,
        )

    def test_evidence_download_is_signed_owner_scoped_and_digest_verified(self):
        import tempfile

        from core.lil_tweak.evidence import LocalEvidenceStore

        with tempfile.TemporaryDirectory() as directory:
            evidence_store = LocalEvidenceStore(directory)
            app = create_app(
                store=self.store,
                evidence_store=evidence_store,
                signing_keys={"primary": self.secret},
                canonical_owner_id=OWNER,
                readiness=lambda: True,
                clock=lambda: self.now,
            )
            job = self.store.create_job(OWNER, "download", JobMode.BUILD, "Build")
            for state in (
                JobState.QUEUED,
                JobState.INGESTING,
                JobState.PLANNING,
                JobState.EXECUTING,
                JobState.COLLECTING,
            ):
                job = self.store.update_job(
                    job.id, owner_id=OWNER, expected_revision=job.revision, state=state
                )
            digest = hashlib.sha256(b"Done").hexdigest()
            job = self.store.update_job(
                job.id,
                owner_id=OWNER,
                expected_revision=job.revision,
                state=JobState.COMPLETED,
                proposal_digest="a" * 64,
                evidence_manifest={"summary.md": {"sha256": digest, "bytes": 4}},
            )
            owner_prefix = hashlib.sha256(OWNER.encode()).hexdigest()
            evidence_store.put(f"{owner_prefix}/{job.id}/summary.md", b"Done", digest)
            target = f"/v1/jobs/{job.id}/evidence/summary.md"
            self.assertEqual(asyncio.run(asgi_request(app, "GET", target))[0], 401)
            status, payload, response_headers = asyncio.run(
                asgi_request(
                    app,
                    "GET",
                    target,
                    headers=self.signed_headers("GET", target, idem=None),
                )
            )
            self.assertEqual((status, payload), (200, b"Done"))
            self.assertEqual(response_headers["x-content-sha256"], digest)

    def test_evidence_descriptor_reports_exact_manifest_size(self):
        job = self.store.create_job(OWNER, "sized-evidence", JobMode.BUILD, "Build")
        for state in (
            JobState.QUEUED,
            JobState.INGESTING,
            JobState.PLANNING,
            JobState.EXECUTING,
            JobState.COLLECTING,
        ):
            job = self.store.update_job(
                job.id, owner_id=OWNER, expected_revision=job.revision, state=state
            )
        digest = hashlib.sha256(b"Done").hexdigest()
        job = self.store.update_job(
            job.id,
            owner_id=OWNER,
            expected_revision=job.revision,
            state=JobState.COMPLETED,
            proposal_digest="a" * 64,
            evidence_manifest={"summary.md": {"sha256": digest, "bytes": 4}},
        )
        target = f"/v1/jobs/{job.id}"
        status, snapshot = self.request(
            "GET", target, headers=self.signed_headers("GET", target, idem=None)
        )
        self.assertEqual(status, 200)
        self.assertEqual(snapshot["evidence"][0]["sizeBytes"], 4)
        self.assertEqual(snapshot["summary"], job.summary)

    def test_evidence_download_passes_a_hard_read_limit_to_storage(self):
        from core.lil_tweak.evidence import EvidenceTooLarge

        class OversizedStore:
            def get(self, _key, *, max_bytes):
                self.max_bytes = max_bytes
                raise EvidenceTooLarge("oversized")

        evidence_store = OversizedStore()
        app = create_app(
            store=self.store,
            evidence_store=evidence_store,
            signing_keys={"primary": self.secret},
            canonical_owner_id=OWNER,
            readiness=lambda: True,
            clock=lambda: self.now,
        )
        job = self.store.create_job(OWNER, "bounded-download", JobMode.BUILD, "Build")
        for state in (
            JobState.QUEUED,
            JobState.INGESTING,
            JobState.PLANNING,
            JobState.EXECUTING,
            JobState.COLLECTING,
        ):
            job = self.store.update_job(
                job.id, owner_id=OWNER, expected_revision=job.revision, state=state
            )
        job = self.store.update_job(
            job.id,
            owner_id=OWNER,
            expected_revision=job.revision,
            state=JobState.COMPLETED,
            evidence_manifest={
                "summary.md": {"sha256": "a" * 64, "bytes": MAX_EVIDENCE_BYTES}
            },
        )
        target = f"/v1/jobs/{job.id}/evidence/summary.md"
        status, payload, _headers = asyncio.run(
            asgi_request(
                app,
                "GET",
                target,
                headers=self.signed_headers("GET", target, idem=None),
            )
        )
        self.assertEqual((status, payload), (413, {"error": {"code": "evidence_too_large"}}))
        self.assertEqual(evidence_store.max_bytes, MAX_EVIDENCE_BYTES)

    def test_approval_and_export_are_two_signed_idempotent_phases(self):
        evidence_clock = [self.now]
        self.store._clock = lambda: evidence_clock[0]
        job = self.store.create_job(OWNER, "approval-job", JobMode.BUILD, "Build")
        for state in (
            JobState.QUEUED,
            JobState.INGESTING,
            JobState.PLANNING,
            JobState.EXECUTING,
            JobState.COLLECTING,
        ):
            job = self.store.update_job(
                job.id, owner_id=OWNER, expected_revision=job.revision, state=state
            )
        job = self.store.update_job(
            job.id,
            owner_id=OWNER,
            expected_revision=job.revision,
            state=JobState.AWAITING_APPROVAL,
            proposal_digest="a" * 64,
            source_digest="c" * 64,
            approval_proposal={
                "action": "export_patch",
                "target": "owner_download",
                "policyVersion": "v1",
                "resourceProfile": {"cpus": 1},
                "sourceDigest": "c" * 64,
                "proposalDigest": "a" * 64,
                "expiresAt": "2026-08-13T16:05:00Z",
            },
            evidence_manifest={
                "changes.patch": {"sha256": "b" * 64, "bytes": 4}
            },
        )
        target = f"/v1/jobs/{job.id}/decisions"
        status_target = f"/v1/jobs/{job.id}"
        awaiting_status, awaiting_snapshot = self.request(
            "GET",
            status_target,
            headers=self.signed_headers("GET", status_target, idem=None),
        )
        self.assertEqual(awaiting_status, 200)
        awaiting_evidence = awaiting_snapshot["evidence"]
        evidence_clock[0] += 60
        body = json.dumps(
            {
                "decision": "approve",
                "expectedCoreRevision": job.revision,
                "approvalProposal": dict(job.approval_proposal),
            }
        ).encode()
        approval_token = "A" * 43
        approval_token_hash = hashlib.sha256(approval_token.encode()).hexdigest()
        approval_body = json.loads(body)
        approval_body["approvalTokenHash"] = approval_token_hash
        body = json.dumps(approval_body).encode()
        status, applying = self.request(
            "POST",
            target,
            body,
            self.signed_headers("POST", target, body, idem="approve-once"),
        )
        self.assertEqual(status, 200)
        self.assertEqual(applying["state"], "applying")
        self.assertFalse(applying["approvalConsumed"])
        self.assertEqual(applying["evidence"], awaiting_evidence)
        self.assertEqual(applying["coreRevision"], job.revision + 1)
        self.assertNotIn(approval_token, json.dumps(applying))
        self.assertEqual(
            [event.kind for event in self.store.list_events(job.id, OWNER)[-2:]],
            ["approved", "applying"],
        )

        replay_status, decision_replay = self.request(
            "POST",
            target,
            body,
            self.signed_headers("POST", target, body, idem="approve-once"),
        )
        self.assertEqual(replay_status, 200)
        self.assertEqual(decision_replay, applying)

        evidence = applying["evidence"][0]
        export_target = f"/v1/jobs/{job.id}/exports/patch"
        export_body = json.dumps(
            {
                "approvalToken": approval_token,
                "expectedCoreRevision": applying["coreRevision"],
                "proposalDigest": applying["proposalDigest"],
                "sourceDigest": applying["sourceDigest"],
                "policyVersion": applying["approvalProposal"]["policyVersion"],
                "resourceProfile": applying["approvalProposal"]["resourceProfile"],
                "evidenceId": evidence["id"],
                "evidenceName": evidence["filename"],
                "evidenceSha256": evidence["sha256"],
                "evidenceSizeBytes": evidence["sizeBytes"],
            }
        ).encode()
        completed_status, completed = self.request(
            "POST",
            export_target,
            export_body,
            self.signed_headers("POST", export_target, export_body, idem="export-attempt-one"),
        )
        self.assertEqual(completed_status, 200)
        self.assertEqual(completed["state"], "completed")
        self.assertTrue(completed["approvalConsumed"])
        self.assertEqual(completed["coreRevision"], applying["coreRevision"] + 1)
        export_replay_status, export_replay = self.request(
            "POST",
            export_target,
            export_body,
            self.signed_headers("POST", export_target, export_body, idem="export-attempt-one"),
        )
        self.assertEqual((export_replay_status, export_replay), (200, completed))

    def test_approval_proposal_comparison_is_json_type_exact(self):
        job = self.approval_job("typed-proposal")
        proposal = dict(job.approval_proposal)
        proposal["resourceProfile"] = {"cpus": True}
        body = json.dumps(
            {
                "decision": "approve",
                "expectedCoreRevision": job.revision,
                "approvalProposal": proposal,
                "approvalTokenHash": "f" * 64,
            }
        ).encode()
        target = f"/v1/jobs/{job.id}/decisions"
        status, response = self.request(
            "POST",
            target,
            body,
            self.signed_headers("POST", target, body, idem="typed-proposal"),
        )
        self.assertEqual(
            (status, response),
            (400, {"error": {"code": "invalid_request"}}),
        )

    def test_approval_retry_after_atomic_transaction_failure(self):
        job = self.approval_job("approval-crash")
        target = f"/v1/jobs/{job.id}/decisions"
        body = json.dumps(
            {
                "decision": "approve",
                "expectedCoreRevision": job.revision,
                "approvalProposal": dict(job.approval_proposal),
                "approvalTokenHash": "e" * 64,
            }
        ).encode()
        original = self.store.decide_job_idempotent

        def fail_transaction(*args, **kwargs):
            raise RuntimeError("process died")

        self.store.decide_job_idempotent = fail_transaction
        first_status, _ = self.request(
            "POST",
            target,
            body,
            self.signed_headers("POST", target, body, idem="approval-crash-key"),
        )
        self.assertEqual(first_status, 500)
        awaiting = self.store.get_job(job.id, OWNER)
        self.assertEqual(awaiting.state, JobState.AWAITING_APPROVAL)
        self.assertFalse(awaiting.approval_consumed)
        self.store.decide_job_idempotent = original
        retry_status, retry = self.request(
            "POST",
            target,
            body,
            self.signed_headers("POST", target, body, idem="approval-crash-key"),
        )
        self.assertEqual(retry_status, 200)
        self.assertEqual(retry["state"], "applying")
        self.assertFalse(retry["approvalConsumed"])

    def test_export_rejects_owner_or_binding_changes_and_expiry_boundary(self):
        job = self.approval_job("export-bindings")
        token = "B" * 42 + "A"
        decision_target = f"/v1/jobs/{job.id}/decisions"
        decision_body = json.dumps(
            {
                "decision": "approve",
                "expectedCoreRevision": job.revision,
                "approvalProposal": dict(job.approval_proposal),
                "approvalTokenHash": hashlib.sha256(token.encode()).hexdigest(),
            }
        ).encode()
        status, applying = self.request(
            "POST",
            decision_target,
            decision_body,
            self.signed_headers("POST", decision_target, decision_body, idem="binding-approve"),
        )
        self.assertEqual(status, 200)
        evidence = applying["evidence"][0]
        payload = {
            "approvalToken": token,
            "expectedCoreRevision": applying["coreRevision"],
            "proposalDigest": applying["proposalDigest"],
            "sourceDigest": applying["sourceDigest"],
            "policyVersion": "v1",
            "resourceProfile": {"cpus": 1},
            "evidenceId": evidence["id"],
            "evidenceName": "changes.patch",
            "evidenceSha256": evidence["sha256"],
            "evidenceSizeBytes": evidence["sizeBytes"],
        }
        export_target = f"/v1/jobs/{job.id}/exports/patch"
        for index, changed in enumerate((
            {**payload, "proposalDigest": "0" * 64},
            {**payload, "evidenceSha256": "1" * 64},
            {**payload, "evidenceId": "evidence:" + "2" * 32},
        )):
            body = json.dumps(changed).encode()
            rejected_status, rejected = self.request(
                "POST",
                export_target,
                body,
                self.signed_headers("POST", export_target, body, idem=f"changed-{index}"),
            )
            self.assertEqual((rejected_status, rejected), (409, {"error": {"code": "invalid_approval"}}))
            self.assertFalse(self.store.get_job(job.id, OWNER).approval_consumed)

        body = json.dumps(payload).encode()
        other_status, other = self.request(
            "POST",
            export_target,
            body,
            self.signed_headers("POST", export_target, body, idem="other-owner", owner="f" * 32),
        )
        self.assertEqual((other_status, other), (403, {"error": {"code": "owner_forbidden"}}))
        self.now = int(__import__("datetime").datetime.fromisoformat("2026-08-13T16:05:00+00:00").timestamp())
        expired_status, expired = self.request(
            "POST",
            export_target,
            body,
            self.signed_headers("POST", export_target, body, idem="expired"),
        )
        self.assertEqual((expired_status, expired), (409, {"error": {"code": "invalid_approval"}}))


if __name__ == "__main__":
    unittest.main()
