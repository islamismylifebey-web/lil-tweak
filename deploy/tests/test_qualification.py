"""Offline qualification integration: real Core handler, socket and boundaries."""
from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import io
import importlib.util
import json
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.request import Request, build_opener, ProxyHandler

from core.lil_tweak.api import LilTweakApi
from core.lil_tweak.contracts import JobState
from core.lil_tweak.evidence import LocalEvidenceStore, WorkspaceEvidenceError
from core.lil_tweak.git_source import GitIntakeError, ingest_git_source
from core.lil_tweak.openai_agent import AgentResult, WorkspaceTools
from core.lil_tweak.orchestrator import EngineeringOrchestrator
from core.lil_tweak.sandbox import CommandResult
from core.lil_tweak.store import MemoryJobStore

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/lil-tweak-qualification.py"
OWNER = "a0885bc0b2c079e996629061a723c74d"
COMMIT = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"
URL = "https://github.com/octocat/Hello-World.git"
PATCH = b"--- a/README\n+++ b/README\n@@ -1 +1 @@\n-Hello World!\n+Hello Tueiq!\n"
CONTENT_CHECK = ["python3", "-c", "from pathlib import Path; assert Path('README').read_bytes() == b'Hello Tueiq!\\n'"]
NEGATIVES = ("stale_lease", "wrong_runner_identity", "wrong_source_revision",
             "expired_authorization", "forbidden_action", "path_escape",
             "production_deployment_request", "replay", "mismatched_evidence_digest")
READY = dict.fromkeys(("database", "runner", "git", "workspace", "evidence", "signing", "admission"), True)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def timestamp(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def provider(now):
    return {
        "schema": "tueiq-digitalocean-provider-evidence-v1",
        "observedAt": timestamp(now),
        "operation": "mcp__codex_apps__digitalocean_droplet_get",
        "rawResponseSha256": hashlib.sha256(b'{"droplet":{"id":597343619,"networks":{"private":[]}}}').hexdigest(),
        "provider": "DigitalOcean",
        "droplet": {"id": "597343619", "name": "galor-tweak-runner-01", "status": "active",
                    "region": "nyc1", "image": {"distribution": "Ubuntu", "slug": "ubuntu-24-04-x64", "name": "24.04 (LTS) x64"},
                    "size": {"slug": "s-4vcpu-8gb", "memoryMiB": 8192, "vcpus": 4, "diskGiB": 160}, "roleTag": "role-tweak-runner"},
    }


def sealed(path, data):
    path.write_bytes(data)
    path.chmod(0o600)
    return path


class Clock:
    def __init__(self):
        self.value = float(int(time.time()))
        self.elapsed = 0.0

    def now(self):
        return self.value

    def monotonic(self):
        return self.elapsed

    def sleep(self, seconds):
        assert 0 < seconds <= 5
        self.value += seconds
        self.elapsed += seconds


class LocalSandbox:
    """Only the container engine is replaced; production tools own edits/journal."""
    lifecycle_failed = False

    def __init__(self, root, fixture):
        self.root, self.fixture = root, fixture

    def stage_patch_candidate(self, patch_path, candidate):
        self.fixture.invocations += 1
        shutil.copytree(self.root, candidate, dirs_exist_ok=True)
        result = subprocess.run(["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch_path)],
                                cwd=candidate, capture_output=True, text=True, check=False)
        return CommandResult(result.returncode, result.stdout, result.stderr)

    def run_ephemeral(self, command, timeout=60):
        self.fixture.invocations += 1
        with tempfile.TemporaryDirectory() as directory:
            shutil.copytree(self.root, directory, dirs_exist_ok=True)
            result = subprocess.run(command, cwd=directory, capture_output=True, text=True, check=False, timeout=timeout)
        return CommandResult(result.returncode, result.stdout, result.stderr)


class Fixture:
    def __init__(self, q, root):
        self.q, self.root, self.clock = q, root, Clock()
        self.invocations = 0
        self.requests, self.prompts, self.order, self.intakes = [], [], [], []
        self.fault = None
        self.fault_when = lambda: True
        self.rejected_snapshots = []
        self.store = MemoryJobStore(clock=self.clock.now)
        self.evidence = LocalEvidenceStore(root / "objects")
        self.api = LilTweakApi(store=self.store, signing_keys={"primary": "secret-CANARY-key"}, canonical_owner_id=OWNER,
                               readiness=lambda: READY, clock=self.clock.now, on_job_queued=self.queued, evidence_store=self.evidence)
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.handle_core()

            def do_POST(self):
                self.handle_core()

            def handle_core(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                h = self.headers
                fields = ["v2", h["X-Lil-Tweak-Key-Id"], self.command, self.path,
                          h["X-Lil-Tweak-Timestamp"], h["X-Lil-Tweak-Nonce"], hashlib.sha256(body).hexdigest(),
                          h["X-Lil-Tweak-Request-Id"], h.get("Idempotency-Key", ""), OWNER]
                assert h["X-Lil-Tweak-Owner"] == OWNER
                assert h["X-Lil-Tweak-Body-SHA256"] == fields[6]
                assert hmac.compare_digest(h["X-Lil-Tweak-Signature"], hmac.new(b"secret-CANARY-key", "\n".join(fields).encode(), hashlib.sha256).hexdigest())
                if body:
                    assert canonical(json.loads(body)) == body
                fixture.requests.append((self.command, self.path, json.loads(body) if body else None, dict(h)))
                sent = []
                before = copy.deepcopy((fixture.store._jobs, fixture.store._approvals,
                                        fixture.store._decisions, fixture.store._events))
                runtime_before = fixture.runtime_snapshot()

                async def receive():
                    return {"type": "http.request", "body": body, "more_body": False}

                async def send(item):
                    sent.append(item)

                asyncio.run(fixture.api({"type": "http", "method": self.command, "path": self.path,
                                        "query_string": b"", "headers": [(k.lower().encode(), v.encode()) for k, v in h.items()]}, receive, send))
                payload = b"".join(m.get("body", b"") for m in sent[1:])
                headers = dict(sent[0]["headers"])
                status = sent[0]["status"]
                if self.path.endswith("/decisions") and status >= 400:
                    after = copy.deepcopy((fixture.store._jobs, fixture.store._approvals,
                                           fixture.store._decisions, fixture.store._events))
                    assert after == before
                    assert fixture.runtime_snapshot() == runtime_before
                    fixture.rejected_snapshots.append((status, json.loads(payload)))
                if fixture.fault and fixture.fault[0] in self.path and fixture.fault_when():
                    kind = fixture.fault[1]
                    if kind == "digest":
                        headers[b"x-content-sha256"] = b"0" * 64
                    elif kind == "media":
                        headers[b"content-type"] = b"text/html"
                    elif kind == "length":
                        headers[b"content-length"] = b"999999999"
                    elif kind == "short-body":
                        payload = payload[:-1]
                    elif kind == "body":
                        payload = b"x" * len(payload)
                    elif kind == "missing-length":
                        del headers[b"content-length"]
                    elif kind == "redirect":
                        status, payload = 302, b""
                        headers[b"location"] = b"https://example.invalid/secret"
                        headers[b"content-length"] = b"0"
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k.decode(), v.decode())
                if fixture.fault and fixture.fault[0] in self.path and fixture.fault_when() and fixture.fault[1] == "duplicate-length":
                    self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        base = build_opener(ProxyHandler({}), q.RejectRedirects())

        class Transport:
            def open(self, request, timeout):
                assert request.full_url.startswith("http://127.0.0.1:8017/")
                forwarded = Request(request.full_url.replace(":8017/", f":{fixture.server.server_port}/", 1),
                                    data=request.data, headers=dict(request.header_items()), method=request.method)
                response = base.open(forwarded, timeout=timeout)
                # The only injected component is the TCP port, not the signed target.
                response.geturl = lambda: request.full_url
                return response

        self.client = q.CoreClient({"LIL_TWEAK_SIGNING_KEYS_JSON": '{"primary":"secret-CANARY-key"}',
                                    "LIL_TWEAK_CANONICAL_OWNER_ID": OWNER}, opener=Transport(), clock=self.clock.now)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def intake(self, destination, commit=COMMIT):
        self.intakes.append(commit)

        def execute(argv, **kwargs):
            if "remote" in argv:
                assert argv[-1] == URL
            if "fetch" in argv:
                assert argv[-1] == commit
            if "checkout" in argv:
                Path(kwargs["cwd"], "README").write_bytes(b"Hello World!\n")
            return subprocess.CompletedProcess(argv, 0, COMMIT + "\n" if "rev-parse" in argv else "", "")

        return ingest_git_source(self.q.GitSourceSpec(URL, commit), destination, allowed_hosts=("github.com",),
                                 execute=execute, resolve=lambda *_: [(None, None, None, None, ("93.184.216.34", 443))])

    def queued(self, job_id, owner):
        job = self.store.get_job(job_id, owner)
        self.prompts.append((job.mode.value, job.prompt, job.git_source, self.clock.now()))
        root = self.root / job_id / "workspace"
        try:
            self.intake(root, job.git_source.commit)
        except GitIntakeError:
            self.store.transition_job(job_id, owner_id=owner, expected_revision=job.revision,
                                      state=JobState.FAILED, event_kind="source_intake_failed", event_data={"code": "source_intake_failed"})
            return
        tools = WorkspaceTools(root, LocalSandbox(root, self))
        fixture = self

        class Agent:
            def run(self, **kwargs):
                if kwargs["mode"].value == "architect":
                    tools.execute("run_command", {"command": ["sha256sum", "README"], "timeout": 30})
                else:
                    tools.execute("apply_patch", {"patch": PATCH.decode()})
                    tools.execute("run_command", {"command": CONTENT_CHECK, "timeout": 30})
                return AgentResult("Plan CANARY-RAW", "Findings CANARY-RAW", "", "")

        agent = Agent()
        agent.tools = tools
        EngineeringOrchestrator(store=self.store, agent=agent, evidence_store=self.evidence,
                                clock=self.clock.now, monotonic=self.clock.monotonic).run_job(job_id, owner, workspace=root, source_inventory=["README"])

    def verify_guest(self):
        self.order.append("guest")
        return self.q.target_module().verify_target(lambda: "galor-tweak-runner-01", lambda: b"597343619\n")

    def deployment(self):
        self.order.append("deployment")
        return 0

    def source_head(self):
        return "a" * 40

    def images(self):
        return {"core": "sha256:" + "1" * 64, "postgres": "sha256:" + "2" * 64, "runner": "sha256:" + "3" * 64}

    def runtime_snapshot(self):
        return {"containers": [], "invocations": self.invocations}


class QualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.q = None
        if SCRIPT.exists():
            spec = importlib.util.spec_from_file_location("qualification_under_test", SCRIPT)
            cls.q = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = cls.q
            spec.loader.exec_module(cls.q)

    def setUp(self):
        self.assertIsNotNone(self.q, "executable qualification harness does not exist")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)

    def fixture(self):
        f = Fixture(self.q, self.root)
        self.addCleanup(f.close)
        return f

    def run_fixture(self, f=None, name="result"):
        f = f or self.fixture()
        evidence = sealed(self.root / "provider.json", canonical(provider(f.clock.now())))
        runner = self.q.Qualification(f.client, f, clock=f.clock.now, monotonic=f.clock.monotonic, sleep=f.clock.sleep)
        result = runner.run(evidence, self.root / name)
        return f, result

    def test_full_signed_production_flow_publishes_only_local_truth(self):
        f, path = self.run_fixture()
        raw = path.read_bytes()
        value = json.loads(raw)
        self.assertEqual(raw, canonical(value))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(value["schema"], "tueiq-direct-runner-local-qualification-v1")
        self.assertEqual(value["jobA"]["state"], "completed")
        self.assertEqual(value["jobA"]["fileSha256"], "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340")
        self.assertEqual(value["jobA"]["evidence"]["changes.patch"]["bytes"], 0)
        self.assertEqual(value["jobB"]["state"], "rejected")
        self.assertEqual(value["jobB"]["evidence"]["changes.patch"]["sha256"], "f1620f84800d8ca024720f16c01e68248a18d29801c036a62da54f7e8d522766")
        self.assertEqual(value["jobB"]["fileSha256"], "30a62e82bef5e3bad05d4444ad9cd850cf35407d58f53e06e415de83f50cec28")
        self.assertEqual(set(value["negativeChecks"]), set(NEGATIVES))
        self.assertTrue(all(v is True for v in value["negativeChecks"].values()))
        self.assertEqual(value["providerEvidence"]["sha256"], hashlib.sha256(canonical(value["providerEvidence"]["document"])).hexdigest())
        self.assertEqual(f.order, ["guest", "deployment"])
        self.assertEqual([p[0] for p in f.prompts], ["architect", "refactor", "refactor", "architect"])
        self.assertEqual(f.prompts[0][1], "Inspect README, run literal sha256sum README, report only findings, and make no edit or external action.")
        self.assertEqual(f.prompts[2][1], "Change only README from Hello World!\\n to Hello Tueiq!\\n. Use apply_patch, then run exactly: " + json.dumps(CONTENT_CHECK, separators=(",", ":")) + ". Propose only export_patch to owner_download; do not approve, export, or take any external action.")
        self.assertGreater(f.prompts[2][3] - f.prompts[1][3], 300)
        self.assertGreaterEqual(f.intakes.count(COMMIT), 5)
        requests = f.requests
        self.assertFalse(any("/exports/" in p for _, p, _, _ in requests))
        decisions = [body for method, target, body, _ in requests if target.endswith("/decisions")]
        self.assertEqual(sum(d["decision"] == "reject" for d in decisions), 1)
        for forbidden in ("CONNECTED", "QUALIFIED", "READY_TO_WORK", "CANARY", "secret-", "http:", "https:", "objectKey", "corePath", "stdout", "stderr", "prompt", "/workspace", "127.0.0.1", "signature"):
            self.assertNotIn(forbidden, raw.decode())
        with patch("socket.create_connection", side_effect=AssertionError("offline")), patch("subprocess.Popen", side_effect=AssertionError("offline")):
            self.assertEqual(self.q.verify_local(path, now=f.clock.now()), hashlib.sha256(raw).hexdigest())

    def test_provider_rejects_wrong_values_extra_fields_and_stale_time(self):
        now = int(time.time())
        valid = provider(now)
        self.assertEqual(self.q.validate_provider(valid, now=now), valid)
        bads = []
        for field in valid:
            bad = copy.deepcopy(valid); del bad[field]; bads.append(bad)
        for key in valid["droplet"]:
            bad = copy.deepcopy(valid); del bad["droplet"][key]; bads.append(bad)
        for part in ("size", "image"):
            for key in valid["droplet"][part]:
                bad = copy.deepcopy(valid); del bad["droplet"][part][key]; bads.append(bad)
        for change in (lambda d: d.update(networks={}), lambda d: d.update(rawResponseSha256="A" * 64),
                       lambda d: d.update(observedAt=timestamp(now - 1801)), lambda d: d.update(observedAt=timestamp(now + 61)),
                       lambda d: d["droplet"].update(id="597343620"), lambda d: d["droplet"].update(networks=[]),
                       lambda d: d.update(operation="untrusted_operation"), lambda d: d.update(provider="Other"),
                       lambda d: d["droplet"].update(status="off"), lambda d: d["droplet"].update(name="other"),
                       lambda d: d["droplet"].update(region="sfo1"), lambda d: d["droplet"].update(roleTag="other"),
                       lambda d: d["droplet"]["size"].update(memoryMiB=4096), lambda d: d["droplet"]["size"].update(diskGiB=80),
                       lambda d: d["droplet"]["size"].update(extra=1), lambda d: d["droplet"]["image"].update(extra=1),
                       lambda d: d["droplet"]["size"].update(vcpus=True), lambda d: d["droplet"]["image"].update(slug="ubuntu-22-04-x64")):
            bad = copy.deepcopy(valid); change(bad); bads.append(bad)
        for bad in bads:
            with self.subTest(bad=bad), self.assertRaises(self.q.QualificationError):
                self.q.validate_provider(bad, now=now)

    def test_secure_provider_receipt_and_environment_files_fail_closed(self):
        p = sealed(self.root / "input", canonical(provider(time.time())))
        self.q.read_provider(p)
        for mode in (0o644, 0o400, 0o660):
            p.chmod(mode)
            with self.assertRaises(self.q.QualificationError): self.q.read_provider(p)
        p.chmod(0o600)
        link = self.root / "link"; link.symlink_to(p)
        with self.assertRaises(self.q.QualificationError): self.q.read_provider(link)
        link.unlink(); os.link(p, link)
        with self.assertRaises(self.q.QualificationError): self.q.read_provider(p)
        link.unlink()
        sealed(p, b"x" * (16384 + 1))
        with self.assertRaises(self.q.QualificationError): self.q.read_provider(p)
        sealed(p, canonical(provider(time.time())) + b"\n")
        with self.assertRaises(self.q.QualificationError): self.q.read_provider(p)
        env = sealed(self.root / "core.env", b'# comment\nLIL_TWEAK_SIGNING_KEYS_JSON={"primary":"secret-CANARY-key"}\nLIL_TWEAK_CANONICAL_OWNER_ID=' + OWNER.encode() + b'\n')
        service = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        self.assertEqual(self.q.load_core_environment(env, service)["LIL_TWEAK_CANONICAL_OWNER_ID"], OWNER)
        env.chmod(0o644)
        with self.assertRaises(self.q.QualificationError): self.q.load_core_environment(env, service)
        env.chmod(0o600)
        with self.assertRaises(self.q.QualificationError): self.q.load_core_environment(env, SimpleNamespace(pw_uid=123456, pw_gid=os.getgid()))
        with self.assertRaises(self.q.QualificationError): self.q.load_core_environment(env, SimpleNamespace(pw_uid=os.getuid(), pw_gid=123456))
        for hard_link in (False, True):
            alias = self.root / "env-alias"
            if hard_link: os.link(env, alias)
            else: alias.symlink_to(env)
            with self.assertRaises(self.q.QualificationError): self.q.load_core_environment(alias, service)
            alias.unlink()
        sealed(env, b"x" * (65536 + 1))
        with self.assertRaises(self.q.QualificationError): self.q.load_core_environment(env, service)

    def test_secure_reads_reject_ownership_ancestors_and_pinned_file_changes(self):
        path = sealed(self.root / "provider-secure", canonical(provider(time.time())))
        # This workspace maps only UID 0. Inject just the stat ownership field
        # while the real secure-reader still owns descriptor and policy checks.
        metadata = path.stat()
        wrong_owner = SimpleNamespace(st_mode=metadata.st_mode, st_uid=1, st_gid=metadata.st_gid)
        with patch.object(self.q.os, "stat", return_value=wrong_owner), self.assertRaises(self.q.QualificationError):
            self.q.read_provider(path)
        ancestor = self.root / "ancestor"; ancestor.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(self.q.QualificationError): self.q.read_provider(ancestor / path.name)
        real_open = os.open

        def mutate_before_pin(name, *args, **kwargs):
            if name == path.name:
                path.write_bytes(canonical(provider(time.time())) + b" ")
            return real_open(name, *args, **kwargs)

        with patch.object(self.q.os, "open", side_effect=mutate_before_pin), self.assertRaises(self.q.QualificationError):
            self.q.read_provider(path)

    def test_canonical_json_rejects_duplicates_nonfinite_and_noncanonical(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{ "a":1}', b'{"a":1}\n', b'[]'):
            with self.subTest(raw=raw), self.assertRaises(self.q.QualificationError):
                self.q.parse_canonical(raw)

    def test_receipt_tampering_recomputes_provider_binding_and_all_gates(self):
        f, path = self.run_fixture()
        valid = json.loads(path.read_bytes())
        mutations = []
        for field in valid:
            def remove(v, key=field): del v[key]
            mutations.append(remove)
        mutations.extend([
            lambda v: v.update(CONNECTED=True), lambda v: v.update(QUALIFIED=True), lambda v: v.update(READY_TO_WORK=True),
            lambda v: v["providerEvidence"]["document"].update(rawResponseSha256="0" * 64),
            lambda v: v["providerEvidence"].update(sha256="0" * 64),
            lambda v: v["identity"].update(ownerScope="0" * 32),
            lambda v: v["identity"].update(region="sfo1"),
            lambda v: v["jobA"].update(approvalProposal={}),
            lambda v: v["jobA"].update(approvalConsumed=True),
            lambda v: v["jobA"].update(sourceDigest="0" * 64),
            lambda v: v["jobA"]["evidence"]["changes.patch"].update(sha256="0" * 64),
            lambda v: v["jobA"]["evidence"]["changes.patch"].update(bytes=1),
            lambda v: v["jobA"].update(finalTreeSha256="0" * 64),
            lambda v: v["jobB"].update(sourceRevision="0" * 40),
            lambda v: v["jobB"].pop("lineage"),
            lambda v: v["jobB"]["lineage"].update(jobA=v["jobB"]["id"]),
            lambda v: v["jobB"].update(exported=True),
            lambda v: v["jobB"]["evidence"]["plan.md"].update(id="evidence:" + "0" * 32),
            lambda v: v["negativeChecks"].pop("replay"),
            lambda v: v["negativeChecks"].update(extra=True),
            lambda v: v["negativeChecks"].update(replay=1),
            lambda v: v["cleanup"].update(noContainers=False),
            lambda v: v["images"].update(core="latest"),
            lambda v: v.update(startedAt=timestamp(f.clock.now() - 1201)),
            lambda v: v["deployment"].update(checkedAt=timestamp(f.clock.now() + 1)),
        ])
        for mutation in mutations:
            bad = copy.deepcopy(valid); mutation(bad); sealed(path, canonical(bad))
            with self.subTest(mutation=mutation), self.assertRaises(self.q.QualificationError):
                self.q.verify_local(path, now=f.clock.now())
        sealed(path, canonical(valid))
        for invalid in (canonical(valid) + b"\n", canonical(valid).replace(b'"replay":true', b'"replay":true,"replay":true')):
            sealed(path, invalid)
            with self.assertRaises(self.q.QualificationError): self.q.verify_local(path, now=f.clock.now())
        sealed(path, canonical(valid))
        with self.assertRaises(self.q.QualificationError): self.q.verify_local(path, now=f.clock.now() + 901)
        path.chmod(0o644)
        with self.assertRaises(self.q.QualificationError): self.q.verify_local(path, now=f.clock.now())
        path.chmod(0o600)
        alias = self.root / "alias"; os.link(path, alias)
        with self.assertRaises(self.q.QualificationError): self.q.verify_local(path, now=f.clock.now())
        alias.unlink(); alias.symlink_to(path)
        with self.assertRaises(self.q.QualificationError): self.q.verify_local(alias, now=f.clock.now())
        sealed(path, b"x" * (65536 + 1))
        with self.assertRaises(self.q.QualificationError): self.q.verify_local(path, now=f.clock.now())

    def test_failed_protocol_and_partial_run_publish_no_receipt_and_cleanup(self):
        f = self.fixture()
        for index, fault in enumerate((("/readyz", "redirect"), ("/readyz", "media"),
                                       ("/readyz", "missing-length"), ("/readyz", "duplicate-length"),
                                       ("/evidence/plan.md", "digest"), ("/evidence/changes.patch", "length"),
                                       ("/evidence/plan.md", "body"), ("/evidence/plan.md", "short-body"),
                                       ("/evidence/plan.md", "media"))):
            f.fault = fault
            with self.subTest(fault=fault), self.assertRaises(self.q.QualificationError):
                self.run_fixture(f, f"fail-{index}")
            self.assertFalse((self.root / f"fail-{index}/local-qualification.json").exists())
            self.assertTrue(all(j.state in {JobState.COMPLETED, JobState.REJECTED, JobState.FAILED, JobState.CANCELLED} for j in f.store._jobs.values()))

    def test_evidence_metadata_and_canonical_manifest_tampering_fail_closed(self):
        f = self.fixture()
        identifier = f.client.json("POST", "/v1/jobs", self.q.submission("refactor"), status=202)["id"]
        original = f.store.get_job(identifier, OWNER)
        job = f.client.json("GET", f"/v1/jobs/{identifier}")
        self.q.verify_job_evidence(f.client, job, mode="refactor", started=f.clock.now(), now=f.clock.now())
        mutations = [lambda j: j.update(sourceDigest="0" * 64), lambda j: j.update(coreRevision=0),
                     lambda j: j.update(approvalConsumed=True), lambda j: j.update(proposalDigest="0" * 64),
                     lambda j: j["approvalProposal"].update(sourceDigest="0" * 64),
                     lambda j: j["evidence"].pop(), lambda j: j["evidence"].append(j["evidence"][0]),
                     lambda j: j["evidence"][0].update(id="evidence:" + "0" * 32),
                     lambda j: j["evidence"][0].update(sizeBytes=0),
                     lambda j: j["evidence_manifest"]["plan.md"].update(objectKey="secret-canary")]
        for mutation in mutations:
            bad = copy.deepcopy(job); mutation(bad)
            with self.subTest(mutation=mutation), self.assertRaises(self.q.QualificationError):
                self.q.verify_job_evidence(f.client, bad, mode="refactor", started=f.clock.now(), now=f.clock.now())
        manifest = json.loads(f.evidence.get(original.evidence_manifest["manifest.json"]["objectKey"]))
        for mutation in (lambda m: m["run"]["timeouts"].__setitem__(0, True),
                         lambda m: m["run"]["truncation"].__setitem__(0, True),
                         lambda m: m["run"]["exit_statuses"].__setitem__(0, 1),
                         lambda m: m["run"]["limits"].update(network="host"),
                         lambda m: m["run"].update(source_digest="0" * 64),
                         lambda m: m["run"].update(commands_digest="0" * 64),
                         lambda m: m["run"].update(edit_journal_digest="0" * 64),
                         lambda m: m["run"]["edit_journal"][0].update(actual_changed_paths=["other"]),
                         lambda m: m["artifacts"].pop("summary.md"),
                         lambda m: m["artifacts"]["tests.log"].update(sha256="0" * 64)):
            altered = copy.deepcopy(manifest); mutation(altered)
            self.rebind_manifest(f, original, altered)
            bad = f.client.json("GET", f"/v1/jobs/{identifier}")
            with self.subTest(mutation=mutation), self.assertRaises((self.q.QualificationError, WorkspaceEvidenceError)):
                self.q.verify_job_evidence(f.client, bad, mode="refactor", started=f.clock.now(), now=f.clock.now())
        self.rebind_manifest(f, original, manifest, extra_newline=True)
        with self.assertRaises(self.q.QualificationError):
            self.q.verify_job_evidence(f.client, f.client.json("GET", f"/v1/jobs/{identifier}"), mode="refactor", started=f.clock.now(), now=f.clock.now())

    def test_test_log_must_agree_with_rehashed_command_metadata(self):
        f = self.fixture()
        identifier = f.client.json("POST", "/v1/jobs", self.q.submission("architect"), status=202)["id"]
        original = f.store.get_job(identifier, OWNER)
        manifest = json.loads(f.evidence.get(original.evidence_manifest["manifest.json"]["objectKey"]))
        for changed in (b"forged log", f.evidence.get(original.evidence_manifest["tests.log"]["objectKey"]).replace(b"exit_code=0", b"exit_code=1"),
                        f.evidence.get(original.evidence_manifest["tests.log"]["objectKey"]).replace(b"03ba204e", b"03ba204f")):
            altered = copy.deepcopy(manifest)
            altered["artifacts"]["tests.log"] = {"sha256": hashlib.sha256(changed).hexdigest(), "bytes": len(changed)}
            self.rebind_manifest(f, original, altered, replacements={"tests.log": changed})
            with self.subTest(changed=changed), self.assertRaises(self.q.QualificationError):
                self.q.verify_job_evidence(f.client, f.client.json("GET", f"/v1/jobs/{identifier}"), mode="architect", started=f.clock.now(), now=f.clock.now())

    def rebind_manifest(self, fixture, original, manifest, *, extra_newline=False, replacements=None):
        proposal = hashlib.sha256(canonical({k: manifest[k] for k in ("version", "artifacts", "run")})).hexdigest()
        manifest["proposal_digest"] = proposal
        descriptors = copy.deepcopy(original.evidence_manifest)
        for name, descriptor in descriptors.items():
            data = canonical(manifest) + (b"\n\n" if extra_newline else b"\n") if name == "manifest.json" else fixture.evidence.get(original.evidence_manifest[name]["objectKey"])
            data = (replacements or {}).get(name, data)
            key = f"{hashlib.sha256(OWNER.encode()).hexdigest()}/{original.id}/{proposal}/{name}"
            # Tamper only the test's evidence fixture; the real Core handler
            # still validates descriptor digests and serves the actual bytes.
            path = fixture.evidence.root / key; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            descriptors[name] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "objectKey": key}
        fixture.store._jobs[original.id] = replace(original, proposal_digest=proposal, evidence_manifest=descriptors,
                                                   approval_proposal={**original.approval_proposal, "proposalDigest": proposal} if original.approval_proposal else None)

    def test_partial_failure_after_job_b_awaits_approval_rejects_it(self):
        f = self.fixture()
        f.fault = ("/evidence/plan.md", "digest")
        f.fault_when = lambda: len(f.prompts) >= 3
        with self.assertRaises(self.q.QualificationError): self.run_fixture(f)
        self.assertFalse((self.root / "result/local-qualification.json").exists())
        self.assertEqual([j.state for j in f.store._jobs.values()], [JobState.COMPLETED, JobState.CANCELLED, JobState.REJECTED])
        self.assertEqual(f.store._approvals, {})

    def test_ambiguous_submission_is_resolved_idempotently_and_cleaned(self):
        f = self.fixture()
        f.fault = ("/v1/jobs", "short-body")
        f.fault_when = lambda: f.requests[-1][0:2] == ("POST", "/v1/jobs") and sum(
            method == "POST" and target == "/v1/jobs" for method, target, _, _ in f.requests) == 2
        with self.assertRaises(self.q.QualificationError): self.run_fixture(f)
        self.assertFalse((self.root / "result/local-qualification.json").exists())
        self.assertEqual([j.state for j in f.store._jobs.values()], [JobState.COMPLETED, JobState.REJECTED])
        posts = [item for item in f.requests if item[0:2] == ("POST", "/v1/jobs")]
        self.assertEqual(len(posts), 3)
        self.assertEqual(posts[1][2], posts[2][2])
        self.assertEqual(posts[1][3]["Idempotency-Key"], posts[2][3]["Idempotency-Key"])
        self.assertNotEqual(posts[1][3]["X-Lil-Tweak-Nonce"], posts[2][3]["X-Lil-Tweak-Nonce"])

    def test_observed_core_git_identity_mismatch_is_rejected_for_both_jobs(self):
        f = self.fixture()
        for mode in ("architect", "refactor"):
            identifier = f.client.json("POST", "/v1/jobs", self.q.submission(mode), status=202)["id"]
            original = f.store.get_job(identifier, OWNER)
            for source in (self.q.GitSourceSpec(URL, "0" + COMMIT[1:]), self.q.GitSourceSpec(URL + "/other", COMMIT), None):
                f.store._jobs[identifier] = replace(original, git_source=source)
                observed = f.client.json("GET", f"/v1/jobs/{identifier}")
                with self.subTest(mode=mode, source=source), self.assertRaises(self.q.QualificationError):
                    self.q.verify_job_evidence(f.client, observed, mode=mode, started=f.clock.now(), now=f.clock.now())

    def test_runner_image_is_bound_to_installed_file_and_effective_core(self):
        installed = sealed(self.root / "installed.env", b'LIL_TWEAK_SIGNING_KEYS_JSON={"primary":"fixture-key"}\nLIL_TWEAK_CANONICAL_OWNER_ID=' + OWNER.encode()
                           + b'\nLIL_TWEAK_RUNNER_IMAGE=runner@sha256:' + b'3' * 64 + b'\n')
        copied = sealed(self.root / "copied.env", installed.read_bytes().replace(b"3" * 64, b"4" * 64))
        service = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        calls = []

        def podman(*args):
            calls.append(args)
            return (("runner@sha256:" + "3" * 64) if args[0] == "exec" else ("image@sha256:" + "1" * 64)).encode() + b"\n"

        with patch.object(self.q, "CORE_ENV_PATH", installed, create=True), patch.object(self.q.InstalledBoundaries, "podman", side_effect=podman):
            with self.assertRaises(self.q.QualificationError):
                self.q.InstalledBoundaries(ROOT, service, self.q.load_core_environment(copied, service), time.time()).images()
            self.assertEqual(calls, [], "stale supplied configuration must fail before runtime probing")
            host = self.q.InstalledBoundaries(ROOT, service, self.q.load_core_environment(installed, service), time.time())
            self.assertEqual(host.images()["runner"], "sha256:" + "3" * 64)
            self.assertTrue(any(args[0] == "exec" for args in calls))
            with patch.object(host, "podman", return_value=("runner@sha256:" + "4" * 64 + "\n").encode()):
                with self.assertRaises(self.q.QualificationError): host.images()

    def test_descendant_holding_pipes_is_killed_after_leader_exits(self):
        child_pid_path = self.root / "descendant.pid"
        code = "import os,subprocess,sys; from pathlib import Path; child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); Path(sys.argv[1]).write_text(str(child.pid)); os._exit(0)"
        child_pid = None
        try:
            with patch.object(self.q.os, "killpg", wraps=os.killpg) as kill_group:
                with self.assertRaises(self.q.QualificationError):
                    self.q.bounded_command([sys.executable, "-c", code, str(child_pid_path)], timeout=0.4)
                self.assertTrue(kill_group.called, "owned group must be terminated even after its leader exits")
            child_pid = int(child_pid_path.read_text())
            for _ in range(50):
                status = Path(f"/proc/{child_pid}/stat")
                if not status.exists() or status.read_text().split()[2] == "Z":
                    break
                time.sleep(0.01)
            else:
                self.fail("descendant remains running after bounded command exits")
        finally:
            if child_pid_path.exists():
                child_pid = int(child_pid_path.read_text())
                try: os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError: pass

    def test_absolute_http_deadline_interrupts_slow_headers(self):
        finished = threading.Event()

        class SlowHeaders(BaseHTTPRequestHandler):
            def log_message(self, *args): pass

            def do_GET(self):
                try:
                    for fragment in (b"HTTP/1.1 200 OK\r\n",) + (b"X-Drip: yes\r\n",) * 40:
                        self.wfile.write(fragment); self.wfile.flush(); time.sleep(0.01)
                    payload = canonical({"status": "ready", "checks": READY})
                    self.wfile.write(b"Content-Type: application/json\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload)
                except (BrokenPipeError, ConnectionResetError): pass
                finally: finished.set()

        server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHeaders)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        base = build_opener(ProxyHandler({}), self.q.RejectRedirects())

        class Transport:
            def open(self, request, timeout):
                response = base.open(Request(request.full_url.replace(":8017/", f":{server.server_port}/", 1), headers=dict(request.header_items())), timeout=timeout)
                response.geturl = lambda: request.full_url
                return response

        client = self.q.CoreClient({"LIL_TWEAK_SIGNING_KEYS_JSON": '{"primary":"fixture-key"}', "LIL_TWEAK_CANONICAL_OWNER_ID": OWNER}, opener=Transport())
        client.remaining_budget = lambda: 0.07
        previous_handler = signal.getsignal(signal.SIGALRM)
        started = time.monotonic()
        try:
            with self.assertRaises(self.q.QualificationError): client.json("GET", "/readyz")
            self.assertLess(time.monotonic() - started, 0.25)
            self.assertTrue(finished.wait(1))
            self.assertEqual(signal.getsignal(signal.SIGALRM), previous_handler)
            self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_existing_output_and_insecure_parent_rejected_before_jobs(self):
        f = self.fixture()
        for kind in ("directory", "symlink", "file"):
            out = self.root / kind
            if kind == "directory": out.mkdir()
            elif kind == "symlink": out.symlink_to(self.root, target_is_directory=True)
            else: out.write_bytes(b"preserve")
            with self.assertRaises(self.q.QualificationError): self.run_fixture(f, kind)
        self.assertEqual(f.requests, [])
        self.root.chmod(0o755)
        with self.assertRaises(self.q.QualificationError): self.run_fixture(f, "bad-parent")
        self.root.chmod(0o700)

    def test_publication_rolls_back_its_receipt_if_directory_fsync_fails(self):
        output = self.q.EvidenceDirectory(self.root / "publication-failure")
        self.addCleanup(output.close)
        real_fsync = os.fsync

        def fail_directory(fd):
            if fd == output.descriptor:
                raise OSError("CANARY-storage-error")
            return real_fsync(fd)

        with patch.object(self.q.os, "fsync", side_effect=fail_directory), self.assertRaises(self.q.QualificationError):
            output.publish({"test": True})
        self.assertEqual(list(output.path.iterdir()), [])

    def test_publication_rechecks_parent_and_never_overwrites_links(self):
        output = self.q.EvidenceDirectory(self.root / "publication-guard")
        self.addCleanup(output.close)
        self.root.chmod(0o755)
        with self.assertRaises(self.q.QualificationError): output.publish({"test": True})
        self.root.chmod(0o700)
        target = sealed(self.root / "untouched", b"preserve")
        alias = output.path / "local-qualification.json"
        for hard_link in (False, True):
            if hard_link: os.link(target, alias)
            else: alias.symlink_to(target)
            with self.assertRaises(self.q.QualificationError): output.publish({"test": True})
            self.assertEqual(target.read_bytes(), b"preserve")
            alias.unlink()

    def test_streamed_body_has_total_deadline_and_byte_bound(self):
        class SlowBody(io.BytesIO):
            def read1(self, size):
                clock[0] += 2
                return super().read1(min(size, 1))

        clock = [0.0]
        with patch.object(self.q.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaises(self.q.QualificationError):
                self.q.bounded_body(SlowBody(b"123456789"), 9, deadline=5)
        self.assertEqual(self.q.bounded_body(io.BytesIO(b"abc"), 3, deadline=time.monotonic() + 5), b"abc")
        with self.assertRaises(self.q.QualificationError):
            self.q.bounded_body(io.BytesIO(b"ab"), 3, deadline=time.monotonic() + 5)

    def test_child_output_and_timeout_are_bounded_and_content_free(self):
        for code, timeout in (("import sys; sys.stderr.write('CANARY' * 50000)", 2),
                              ("import time; time.sleep(30)", 0.05),
                              ("raise RuntimeError('CANARY-child-secret')", 2)):
            with self.subTest(code=code), self.assertRaises(self.q.QualificationError) as error:
                self.q.bounded_command([sys.executable, "-c", code], timeout=timeout)
            self.assertEqual(str(error.exception), "local qualification failed")

    def test_cleanup_cancels_and_polls_after_invocation_deadline(self):
        f = self.fixture()
        with patch.object(f.api, "on_job_queued", None):
            identifier = f.client.json("POST", "/v1/jobs", self.q.submission("architect"), status=202)["id"]
        def worker_tick(seconds):
            f.clock.sleep(seconds)
            EngineeringOrchestrator(store=f.store, agent=None, evidence_store=f.evidence,
                                    clock=f.clock.now, monotonic=f.clock.monotonic).run_job(identifier, OWNER)

        runner = self.q.Qualification(f.client, f, clock=f.clock.now, monotonic=f.clock.monotonic, sleep=worker_tick)
        runner.jobs = [identifier]
        runner.deadline = -1
        runner.cleanup()
        self.assertEqual(f.store.get_job(identifier, OWNER).state, JobState.CANCELLED)

    def test_negative_http_rejections_do_not_mutate_production_state_or_runtime(self):
        f, path = self.run_fixture()
        value = json.loads(path.read_bytes())
        self.assertTrue(value["negativeChecks"]["expired_authorization"])
        self.assertTrue(value["negativeChecks"]["production_deployment_request"])
        self.assertTrue(value["negativeChecks"]["forbidden_action"])
        self.assertTrue(value["negativeChecks"]["replay"])
        self.assertEqual(value["cleanup"]["sacrificialState"], "cancelled")
        self.assertEqual(f.rejected_snapshots, [(409, {"error": {"code": "invalid_approval"}}),
                                              (400, {"error": {"code": "invalid_request"}}),
                                              (400, {"error": {"code": "invalid_request"}})])
        stale = [r for r in f.requests if int(r[3]["X-Lil-Tweak-Timestamp"]) < int(f.clock.now()) - 300]
        self.assertTrue(stale)

    def test_boundary_checks_use_real_lease_identity_path_intake_and_evidence_functions(self):
        f = self.fixture()
        results = self.q.local_negative_checks(f, self.root)
        self.assertEqual(results, {"stale_lease": True, "wrong_runner_identity": True,
                                   "wrong_source_revision": True, "path_escape": True, "mismatched_evidence_digest": True})
        self.assertEqual(f.intakes, ["0" + COMMIT[1:]])

    def test_check_cli_is_offline_and_never_emits_final_activation_truth(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--check"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "local qualification check: ok\n", ""))
        for arg in ("--origin", "--owner", "--timeout", "--repository", "--target"):
            result = subprocess.run([sys.executable, str(SCRIPT), "run", arg, "bad"], cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
