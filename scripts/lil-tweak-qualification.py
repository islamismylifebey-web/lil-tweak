#!/usr/bin/env python3
"""Bounded direct-Core qualification. This produces local evidence, not activation.

The provider raw-response hash is a supplied observation, not derivable from the
normalized document. Task 6 must independently witness the raw bytes before they
are discarded. Neither this runner nor verify-local claims to perform that step.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import importlib.util
import json
import os
import pwd
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.lil_tweak.archive import ArchiveError, validate_portable_path
from core.lil_tweak.evidence import (
    LocalEvidenceStore, build_edit_journal_evidence, build_workspace_patch,
    capture_workspace, workspace_changed_paths, workspace_delta_digest,
)
from core.lil_tweak.git_source import GitIntakeError, ingest_git_source
from core.lil_tweak.limits import MAX_EVIDENCE_BYTES
from core.lil_tweak.openai_agent import WorkspaceTools
from core.lil_tweak.store import GitSourceSpec
from core.lil_tweak.test_world import MemoryTestWorldStore, TestCheck, TestWorldConflict

SOURCE_URL = "https://github.com/octocat/Hello-World.git"
SOURCE_COMMIT = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"
SOURCE_FILE = "README"
SOURCE_SHA256 = "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340"
PATCHED_SHA256 = "30a62e82bef5e3bad05d4444ad9cd850cf35407d58f53e06e415de83f50cec28"
BASELINE_TREE_SHA256 = "d23d6b2878e2ce3351e8e155c282d20290e4d6dfe49795669023aac75b574922"
PATCHED_TREE_SHA256 = "aeb26da02bb4201906f381e59e390dd42545e05651957743a2fa3d9db83e8429"
PATCH_SHA256 = "f1620f84800d8ca024720f16c01e68248a18d29801c036a62da54f7e8d522766"
PATCH_BYTES = 66
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
OWNER_SCOPE = "a0885bc0b2c079e996629061a723c74d"
ORIGIN = "http://127.0.0.1:8017"
NEGATIVE_KEYS = (
    "stale_lease", "wrong_runner_identity", "wrong_source_revision", "expired_authorization",
    "forbidden_action", "path_escape", "production_deployment_request", "replay", "mismatched_evidence_digest",
)
READY_KEYS = {"database", "runner", "git", "workspace", "evidence", "signing", "admission"}
ARTIFACTS = {"plan.md": "text/markdown", "changes.patch": "text/x-diff", "tests.log": "text/plain",
             "manifest.json": "application/json", "summary.md": "text/markdown"}
CATEGORIES = {"plan.md": "plan", "changes.patch": "patch", "tests.log": "tests", "manifest.json": "manifest", "summary.md": "summary"}
CONTENT_CHECK = ["python3", "-c", "from pathlib import Path; assert Path('README').read_bytes() == b'Hello Tueiq!\\n'"]
PROMPT_A = "Inspect README, run literal sha256sum README, report only findings, and make no edit or external action."
PROMPT_B = ("Change only README from Hello World!\\n to Hello Tueiq!\\n. Use apply_patch, then run exactly: "
            + json.dumps(CONTENT_CHECK, separators=(",", ":"))
            + ". Propose only export_patch to owner_download; do not approve, export, or take any external action.")
SCHEMA = "tueiq-direct-runner-local-qualification-v1"
MAX_JSON_BYTES = 256 * 1024
MAX_ENV_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_PROVIDER_BYTES = 16 * 1024
TERMINAL = {"completed", "rejected", "cancelled", "failed", "timed_out"}
PROFILE = {"cpus": 1, "memory": "1g", "pids": 256, "wallSeconds": 1200}


class QualificationError(RuntimeError):
    """Only a fixed message crosses the CLI failure boundary."""


def require(condition):
    if not condition:
        raise QualificationError("local qualification failed")


def canonical(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise QualificationError("local qualification failed") from None


def sha(data):
    return hashlib.sha256(data).hexdigest()


def exact(value, expected):
    require(canonical(value) == canonical(expected))


def fields(value, names):
    require(type(value) is dict and set(value) == set(names))


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None)


def job_id(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) is not None)


def integer(value, minimum=0, maximum=2**53):
    require(type(value) is int and minimum <= value <= maximum)


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def epoch(value):
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value) is not None)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        raise QualificationError("local qualification failed") from None


def production_epoch(value):
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z", value) is not None)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        raise QualificationError("local qualification failed") from None


def parse_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False))
    except (ValueError, UnicodeError, RecursionError):
        raise QualificationError("local qualification failed") from None
    require(type(value) is dict)
    return value


def parse_canonical(raw):
    value = parse_json(raw)
    require(canonical(value) == raw)
    return value


def directory_fd(path):
    """Walk every component without following symlinks, including ancestors."""
    path = Path(os.path.abspath(path))
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def secure_read(path, *, limit, uid=0, gid=0):
    """Parse callers only after a pinned, bounded, stable non-following read."""
    path = Path(path)
    try:
        parent = directory_fd(path.parent)
        try:
            before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
                    and before.st_uid == uid and before.st_gid == gid and before.st_nlink == 1 and before.st_size <= limit)
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            with os.fdopen(descriptor, "rb") as handle:
                require(signature(os.fstat(handle.fileno())) == signature(before))
                data = handle.read(limit + 1)
                require(len(data) == before.st_size and len(data) <= limit)
                require(signature(os.fstat(handle.fileno())) == signature(before))
            require(signature(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) == signature(before))
            return data
        finally:
            os.close(parent)
    except OSError:
        raise QualificationError("local qualification failed") from None


def load_core_environment(path, service):
    raw = secure_read(path, limit=MAX_ENV_BYTES, uid=service.pw_uid, gid=service.pw_gid)
    try:
        values = {}
        for line in raw.decode("utf-8").splitlines():
            if not line or line.lstrip().startswith("#"):
                continue
            require("=" in line)
            name, value = line.split("=", 1)
            require(bool(name) and name not in values)
            values[name] = value
        # Validate secret-bearing values without logging or returning an error detail.
        validate_environment(values)
        return values
    except (UnicodeError, KeyError, TypeError, ValueError):
        raise QualificationError("local qualification failed") from None


def validate_environment(values):
    exact(values.get("LIL_TWEAK_CANONICAL_OWNER_ID"), OWNER_SCOPE)
    keys = parse_json(values.get("LIL_TWEAK_SIGNING_KEYS_JSON", ""))
    require(bool(keys))
    for key, secret in keys.items():
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", key) is not None
                and isinstance(secret, str) and bool(secret) and len(secret.encode()) <= 4096)
    key_id = sorted(keys)[0]
    return key_id, keys[key_id]


def validate_provider(document, *, now=None):
    now = time.time() if now is None else now
    fields(document, ("schema", "observedAt", "operation", "rawResponseSha256", "provider", "droplet"))
    exact(document["schema"], "tueiq-digitalocean-provider-evidence-v1")
    exact(document["operation"], "mcp__codex_apps__digitalocean_droplet_get")
    exact(document["provider"], "DigitalOcean")
    require(-60 <= now - epoch(document["observedAt"]) <= 1800)
    digest(document["rawResponseSha256"])
    exact(document["droplet"], {
        "id": "597343619", "name": "galor-tweak-runner-01", "status": "active", "region": "nyc1",
        "image": {"distribution": "Ubuntu", "slug": "ubuntu-24-04-x64", "name": "24.04 (LTS) x64"},
        "size": {"slug": "s-4vcpu-8gb", "memoryMiB": 8192, "vcpus": 4, "diskGiB": 160}, "roleTag": "role-tweak-runner",
    })
    return document


def read_provider(path, *, now=None):
    return validate_provider(parse_canonical(secure_read(path, limit=MAX_PROVIDER_BYTES)), now=now)


def identity(document):
    droplet = document["droplet"]
    return {"owner": "tueiq", "ownerScope": OWNER_SCOPE, "provider": document["provider"],
            "dropletId": droplet["id"], "host": droplet["name"], "region": droplet["region"],
            "os": droplet["image"]["distribution"] + " " + droplet["image"]["name"].replace("(LTS)", "LTS"),
            "size": droplet["size"]["slug"], "role": droplet["roleTag"]}


class EvidenceDirectory:
    def __init__(self, path):
        self.path = Path(os.path.abspath(path))
        self.parent = self.descriptor = None
        try:
            self.parent = directory_fd(self.path.parent)
            info = os.fstat(self.parent)
            require(info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
            os.mkdir(self.path.name, mode=0o700, dir_fd=self.parent)
            self.descriptor = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent)
            self.info = os.fstat(self.descriptor)
            require(self.info.st_uid == 0 and self.info.st_gid == 0 and stat.S_IMODE(self.info.st_mode) == 0o700)
        except (OSError, QualificationError):
            self.close()
            raise QualificationError("local qualification failed") from None

    def publish(self, value):
        data = canonical(value)
        require(len(data) <= MAX_RECEIPT_BYTES)
        name = ".pending-" + secrets.token_hex(16)
        parent = os.fstat(self.parent)
        require(parent.st_uid == 0 and parent.st_gid == 0 and stat.S_IMODE(parent.st_mode) == 0o700)
        current_parent = directory_fd(self.path.parent)
        try:
            named_parent = os.fstat(current_parent)
            require((named_parent.st_dev, named_parent.st_ino) == (parent.st_dev, parent.st_ino))
        finally:
            os.close(current_parent)
        require((os.fstat(self.descriptor).st_dev, os.fstat(self.descriptor).st_ino) == (self.info.st_dev, self.info.st_ino))
        named = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
        require((named.st_dev, named.st_ino) == (self.info.st_dev, self.info.st_ino))
        require(stat.S_IMODE(named.st_mode) == 0o700 and named.st_uid == 0 and named.st_gid == 0)
        published = False
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.descriptor)
            with os.fdopen(fd, "wb") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
                pinned = os.fstat(output.fileno())
                require(stat.S_ISREG(pinned.st_mode) and stat.S_IMODE(pinned.st_mode) == 0o600
                        and pinned.st_uid == 0 and pinned.st_gid == 0 and pinned.st_nlink == 1 and pinned.st_size == len(data))
            # Hard-link publication is atomic and does not overwrite an existing name.
            os.link(name, "local-qualification.json", src_dir_fd=self.descriptor, dst_dir_fd=self.descriptor, follow_symlinks=False)
            published = True
            os.unlink(name, dir_fd=self.descriptor)
            final = os.stat("local-qualification.json", dir_fd=self.descriptor, follow_symlinks=False)
            require((final.st_dev, final.st_ino) == (pinned.st_dev, pinned.st_ino) and final.st_nlink == 1)
            os.fsync(self.descriptor)
        except BaseException:
            if published:
                final = os.stat("local-qualification.json", dir_fd=self.descriptor, follow_symlinks=False)
                if (final.st_dev, final.st_ino) == (pinned.st_dev, pinned.st_ino):
                    os.unlink("local-qualification.json", dir_fd=self.descriptor)
            try:
                os.unlink(name, dir_fd=self.descriptor)
            except FileNotFoundError:
                pass
            raise QualificationError("local qualification failed") from None
        return self.path / "local-qualification.json"

    def close(self):
        for name in ("descriptor", "parent"):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def bounded_body(response, length, *, deadline):
    """read1 avoids an unbounded slow-drip read behind a socket idle timeout."""
    data = bytearray()
    while len(data) < length:
        require(time.monotonic() < deadline)
        chunk = response.read1(min(16384, length - len(data)))
        require(chunk and len(chunk) <= length - len(data))
        data.extend(chunk)
    require(time.monotonic() < deadline)
    return bytes(data)


class CoreClient:
    def __init__(self, environment, *, opener=None, clock=time.time):
        self.key_id, self.secret = validate_environment(environment)
        self.clock = clock
        self.opener = opener if opener is not None else build_opener(ProxyHandler({}), RejectRedirects())
        self.last_binding = None

    def request(self, method, path, payload=None, *, nonce=None, request_id=None, timestamp=None, evidence=False):
        require(method in {"GET", "POST"})
        require(path in {"/readyz", "/v1/jobs"} or re.fullmatch(
            r"/v1/jobs/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?:/(?:decisions|cancel|evidence/(?:plan\.md|changes\.patch|tests\.log|manifest\.json|summary\.md)))?", path) is not None)
        raw = b"" if payload is None else canonical(payload)
        request_id = request_id or str(uuid.uuid4())
        nonce = nonce or secrets.token_hex(24)
        timestamp = str(int(self.clock())) if timestamp is None else str(timestamp)
        idem = request_id if method == "POST" else ""
        body_sha = sha(raw)
        message = "\n".join(["v2", self.key_id, method, path, timestamp, nonce, body_sha, request_id, idem, OWNER_SCOPE])
        headers = {"X-Lil-Tweak-Key-Id": self.key_id, "X-Lil-Tweak-Timestamp": timestamp,
                   "X-Lil-Tweak-Nonce": nonce, "X-Lil-Tweak-Request-Id": request_id,
                   "X-Lil-Tweak-Body-SHA256": body_sha, "X-Lil-Tweak-Owner": OWNER_SCOPE,
                   "X-Lil-Tweak-Signature": hmac.new(self.secret.encode(), message.encode(), hashlib.sha256).hexdigest()}
        if method == "POST":
            headers.update({"Content-Type": "application/json", "Idempotency-Key": idem})
        self.last_binding = {"requestId": request_id, "nonce": nonce, "timestamp": timestamp, "bodySha256": body_sha}
        request = Request(ORIGIN + path, data=raw if method == "POST" else None, headers=headers, method=method)
        response_deadline = time.monotonic() + 5
        try:
            try:
                response = self.opener.open(request, timeout=5)
            except HTTPError as error:
                response = error
            with response:
                status = response.getcode()
                require(status < 300 or status >= 400)
                if not isinstance(response, HTTPError):
                    require(response.geturl() == ORIGIN + path)
                limit = MAX_EVIDENCE_BYTES if evidence and status == 200 else MAX_JSON_BYTES
                for name in ("Content-Length", "Content-Type"):
                    require(len(response.headers.get_all(name, [])) == 1)
                length = response.headers["Content-Length"]
                require(re.fullmatch(r"0|[1-9][0-9]{0,8}", length) is not None and int(length) <= limit)
                media = response.headers["Content-Type"].split(";", 1)[0].strip().lower()
                if not evidence or status != 200:
                    require(media == "application/json")
                data = bounded_body(response, int(length), deadline=response_deadline)
                require(len(data) == int(length) and len(data) <= limit)
                response_headers = dict(response.headers.items())
                if evidence and status == 200:
                    require(len(response.headers.get_all("X-Content-Sha256", [])) == 1)
                    return status, data, {k.lower(): v for k, v in response_headers.items()}
                return status, parse_json(data), {k.lower(): v for k, v in response_headers.items()}
        except QualificationError:
            raise
        except Exception:
            raise QualificationError("local qualification failed") from None

    def json(self, method, path, payload=None, *, status=200, **kwargs):
        actual, value, _ = self.request(method, path, payload, **kwargs)
        require(actual == status and type(value) is dict)
        return value


def ready(value):
    fields(value, ("status", "checks"))
    exact(value["status"], "ready")
    exact(value["checks"], dict.fromkeys(READY_KEYS, True))


def target_module():
    name = "qualification_guest_target"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, ROOT / "scripts/lil-tweak-digitalocean-target.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def bounded_command(argv, *, cwd=None, env=None, input_bytes=None, timeout=60, max_output=MAX_JSON_BYTES):
    """Drain both pipes under one byte/deadline budget; never surface child text."""
    require(type(argv) is list and bool(argv) and 0 < timeout <= 1200)
    started = time.monotonic()
    with tempfile.TemporaryFile() as source:
        if input_bytes is not None:
            require(len(input_bytes) <= MAX_EVIDENCE_BYTES)
            source.write(input_bytes)
            source.seek(0)
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=source,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        output, total = bytearray(), 0
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, True)
                selector.register(process.stderr, selectors.EVENT_READ, False)
                while selector.get_map():
                    require(time.monotonic() - started < timeout)
                    for key, _ in selector.select(min(0.25, timeout)):
                        data = os.read(key.fileobj.fileno(), 16384)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(data)
                        require(total <= max_output)
                        if key.data:
                            output.extend(data)
            require(process.wait(timeout=max(0.01, timeout - (time.monotonic() - started))) == 0)
            return bytes(output)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            process.stdout.close()
            process.stderr.close()


class InstalledBoundaries:
    def __init__(self, source_root, service, environment, started):
        require(Path(source_root).absolute() == ROOT and not Path(source_root).is_symlink())
        self.service, self.environment, self.started = service, environment, started

    def source_head(self):
        require(bounded_command(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT) == b"")
        value = bounded_command(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
        require(re.fullmatch(r"[0-9a-f]{40}", value) is not None)
        return value

    def verify_guest(self):
        return target_module().verify_target()

    def deployment(self):
        bounded_command(["bash", "scripts/verify-deployment.sh"], cwd=ROOT,
                        env={**os.environ, "LIL_TWEAK_VERIFY_R2": "1"}, timeout=240)
        return 0

    def podman(self, *argv):
        return bounded_command(["runuser", "--user", "lil-tweak", "--", "env",
                                f"XDG_RUNTIME_DIR=/run/user/{self.service.pw_uid}",
                                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{self.service.pw_uid}/bus", "podman", *argv], timeout=30)

    def images(self):
        values = {name: self.podman("inspect", container, "--format", "{{.ImageName}}").decode().strip()
                  for name, container in (("core", "lil-tweak-core"), ("postgres", "lil-tweak-postgres"))}
        values["runner"] = self.environment.get("LIL_TWEAK_RUNNER_IMAGE", "")
        for value in values.values():
            require(re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", value) is not None)
        return {name: value.rsplit("@", 1)[1] for name, value in values.items()}

    def runtime_snapshot(self):
        # Infrastructure containers are not disposable job sandboxes. All other
        # containers, including stopped ones, must be absent. Event counts also
        # detect a rejected request briefly creating/removing a sandbox.
        raw = self.podman("ps", "--all", "--format", "json")
        try:
            containers = json.loads(raw)
            require(type(containers) is list and len(containers) <= 1024)
            names = []
            for item in containers:
                require(type(item) is dict and type(item.get("Names")) is list)
                if item["Names"] not in (["lil-tweak-core"], ["lil-tweak-postgres"]):
                    digest(item.get("Id"))
                    names.append(item["Id"])
            events = self.podman("events", "--stream=false", "--since", iso(self.started),
                                 "--filter", "type=container", "--filter", "event=create", "--format", "json")
            count = 0
            for line in events.splitlines():
                event = parse_json(line)
                require(event.get("Type") == "container" and event.get("Status") == "create")
                count += 1
            return {"containers": sorted(names), "invocations": count}
        except (ValueError, KeyError, TypeError):
            raise QualificationError("local qualification failed") from None

    def intake(self, destination, commit=SOURCE_COMMIT):
        def execute(argv, **options):
            output = bounded_command(argv, cwd=options["cwd"], env=options["env"],
                                     timeout=options["timeout"], max_output=64 * 1024)
            return subprocess.CompletedProcess(argv, 0, output.decode("utf-8"), "")

        return ingest_git_source(GitSourceSpec(SOURCE_URL, commit), destination,
                                 allowed_hosts=("github.com",), execute=execute)


def verify_source(boundaries, destination):
    exact(boundaries.intake(destination), [SOURCE_FILE])
    snapshot = capture_workspace(destination, max_files=1, max_total_bytes=13, max_file_bytes=13)
    exact(snapshot.source_digest, BASELINE_TREE_SHA256)
    require(snapshot.files == {SOURCE_FILE: b"Hello World!\n"})
    exact(sha(snapshot.files[SOURCE_FILE]), SOURCE_SHA256)
    return snapshot


def clean_replay(boundaries, destination, patch_bytes):
    require(len(patch_bytes) == PATCH_BYTES and sha(patch_bytes) == PATCH_SHA256)
    before = verify_source(boundaries, destination)
    bounded_command(["patch", "--batch", "--forward", "--fuzz=0", "-p1"], cwd=destination, input_bytes=patch_bytes, timeout=10)
    after = capture_workspace(destination, max_files=1, max_total_bytes=13, max_file_bytes=13)
    exact(workspace_changed_paths(before, after), (SOURCE_FILE,))
    require(after.files == {SOURCE_FILE: b"Hello Tueiq!\n"})
    exact(sha(after.files[SOURCE_FILE]), PATCHED_SHA256)
    exact(after.source_digest, PATCHED_TREE_SHA256)
    require(build_workspace_patch(before, after) == patch_bytes)
    bounded_command(CONTENT_CHECK, cwd=destination, timeout=10)
    return before, after


def local_negative_checks(boundaries, directory):
    results = {}
    clock = [1000.0]
    store = MemoryTestWorldStore(clock=lambda: clock[0])
    world = store.create_world(OWNER_SCOPE, idempotency_key="qualification", name="Qualification",
                               objective="Exercise lease fencing", repository_url=SOURCE_URL, commit=SOURCE_COMMIT,
                               checks=(TestCheck("content", tuple(CONTENT_CHECK), 30),), max_attempts=1)
    attempt = store.enqueue_attempt(world.id, OWNER_SCOPE, idempotency_key="qualification-attempt")
    lease = store.claim_attempt(attempt.id, "qualification", lease_seconds=60, now=clock[0])
    require(lease is not None)
    before = store.get_attempt(attempt.id, OWNER_SCOPE)
    try:
        store.renew_attempt(replace(lease, generation=lease.generation - 1), lease_seconds=60, now=clock[0])
    except TestWorldConflict:
        require(store.get_attempt(attempt.id, OWNER_SCOPE) == before)
        results["stale_lease"] = True
    module = target_module()
    try:
        module.verify_target(lambda: "galor-tweak-runner-01", lambda: b"597343620\n")
    except module.TargetVerificationError:
        results["wrong_runner_identity"] = True
    with tempfile.TemporaryDirectory(dir=directory) as temporary:
        root = Path(temporary)
        try:
            boundaries.intake(root / "wrong-revision", "0" + SOURCE_COMMIT[1:])
        except GitIntakeError:
            results["wrong_source_revision"] = True
        try:
            validate_portable_path("../escape")
        except ArchiveError:
            workspace = root / "workspace"; workspace.mkdir()
            try:
                WorkspaceTools(workspace, None).execute("read_file", {"path": "../escape"})
            except (ValueError, OSError):
                results["path_escape"] = True
        evidence = LocalEvidenceStore(root / "evidence")
        try:
            evidence.put("digest-check", b"qualification", "0" * 64)
        except ValueError:
            require(not (root / "evidence/digest-check").exists())
            results["mismatched_evidence_digest"] = True
    require(set(results) == {"stale_lease", "wrong_runner_identity", "wrong_source_revision", "path_escape", "mismatched_evidence_digest"})
    return results


def submission(mode, commit=SOURCE_COMMIT):
    return {"mode": mode, "ownerKey": OWNER_SCOPE, "prompt": PROMPT_A if mode == "architect" else PROMPT_B,
            "gitSource": {"repositoryUrl": SOURCE_URL, "commit": commit}}


def evidence_id(identifier, name):
    return "evidence:" + sha(f"{identifier}\n{name}".encode())[:32]


def verify_test_log(raw, commands, operations, expected_check):
    # The production log is derived from the same observations as command
    # metadata. Validate that connection without retaining any output text.
    entries = re.split(rb"(?m)^\$ ", raw)
    require(entries[0] == b"" and len(entries) == len(commands) + 1)
    for entry, command, operation in zip(entries[1:], commands, operations):
        prefix = canonical(command) + b"\nexit_code=0 timed_out=false truncated=false\n[stdout]\n"
        require(entry.startswith(prefix))
        body = entry[len(prefix):]
        require(body.count(b"\n[stderr]\n") == 1 and body.endswith(b"\n"))
        stdout, _ = body.split(b"\n[stderr]\n", 1)
        if command == expected_check and operation == "run_command":
            require(stdout == ((SOURCE_SHA256 + "  README\n").encode() if expected_check == ["sha256sum", "README"] else b""))


def verify_job_evidence(client, job, *, mode, started, now):
    job_id(job.get("id"))
    exact(job.get("mode"), mode)
    exact(job.get("state"), "completed" if mode == "architect" else "awaiting_approval")
    integer(job.get("revision"), 1)
    exact(job.get("coreRevision"), job["revision"])
    exact(job.get("sourceDigest"), BASELINE_TREE_SHA256)
    exact(job.get("approvalConsumed"), False)
    digest(job.get("proposalDigest"))
    exact(job.get("proposal_digest"), job["proposalDigest"])
    descriptors = job.get("evidence")
    require(type(descriptors) is list and len(descriptors) == len(ARTIFACTS))
    require({d.get("filename") for d in descriptors if type(d) is dict} == set(ARTIFACTS))
    fields(job.get("evidence_manifest"), ARTIFACTS)
    bodies, retained = {}, {}
    for descriptor in descriptors:
        fields(descriptor, ("id", "category", "filename", "mediaType", "sizeBytes", "sha256", "createdAt", "corePath"))
        name = descriptor["filename"]
        exact(descriptor["id"], evidence_id(job["id"], name))
        exact(descriptor["mediaType"], ARTIFACTS[name])
        exact(descriptor["category"], CATEGORIES[name])
        exact(descriptor["corePath"], f"/v1/jobs/{job['id']}/evidence/{name}")
        integer(descriptor["sizeBytes"], 0, MAX_EVIDENCE_BYTES)
        digest(descriptor["sha256"])
        require(started <= production_epoch(descriptor["createdAt"]) <= now)
        listed = job["evidence_manifest"][name]
        fields(listed, ("sha256", "bytes", "objectKey"))
        exact(listed["bytes"], descriptor["sizeBytes"])
        exact(listed["sha256"], descriptor["sha256"])
        exact(listed["objectKey"], f"{sha(OWNER_SCOPE.encode())}/{job['id']}/{job['proposalDigest']}/{name}")
        status, data, headers = client.request("GET", descriptor["corePath"], evidence=True)
        require(status == 200 and type(data) is bytes)
        exact(headers["content-type"].split(";", 1)[0].strip().lower(), ARTIFACTS[name])
        exact(headers.get("x-content-sha256"), descriptor["sha256"])
        require(len(data) == descriptor["sizeBytes"] and sha(data) == descriptor["sha256"])
        bodies[name] = data
        retained[name] = {"id": descriptor["id"], "sha256": descriptor["sha256"], "bytes": len(data), "createdAt": descriptor["createdAt"]}
    manifest = parse_json(bodies["manifest.json"])
    require(canonical(manifest) + b"\n" == bodies["manifest.json"])
    fields(manifest, ("version", "artifacts", "run", "proposal_digest"))
    exact(manifest["version"], 1)
    exact(manifest["artifacts"], {name: {"sha256": sha(data), "bytes": len(data)} for name, data in bodies.items() if name != "manifest.json"})
    expected_digest = sha(canonical({k: manifest[k] for k in ("version", "artifacts", "run")}))
    exact(manifest["proposal_digest"], expected_digest)
    exact(job["proposalDigest"], expected_digest)
    run = manifest["run"]
    fields(run, ("commands", "command_hashes", "commands_digest", "argv_truncated", "operations", "exit_statuses", "timeouts", "truncation",
                 "edit_journal", "edit_journal_count", "edit_journal_digest", "source_digest", "proposal_source_digest", "approval", "limits",
                 "started_at_epoch", "finished_at_epoch", "model_usage"))
    exact(run["source_digest"], BASELINE_TREE_SHA256)
    exact(run["proposal_source_digest"], BASELINE_TREE_SHA256 if mode == "architect" else PATCHED_TREE_SHA256)
    exact(run["limits"], {"network": "none", "max_tool_rounds": 40})
    require(type(run["started_at_epoch"]) in (float, int) and type(run["finished_at_epoch"]) in (float, int)
            and started <= run["started_at_epoch"] <= run["finished_at_epoch"] <= now)
    fields(run["model_usage"], ("calls", "input_tokens", "output_tokens", "total_tokens"))
    for count in run["model_usage"].values(): integer(count)
    require(run["model_usage"]["total_tokens"] == run["model_usage"]["input_tokens"] + run["model_usage"]["output_tokens"])
    commands = run["commands"]
    require(type(commands) is list and 1 <= len(commands) <= 128)
    hashes = []
    for command in commands:
        require(type(command) is list and bool(command) and all(type(v) is str for v in command))
        hashes.append(sha(canonical(command)))
    exact(run["command_hashes"], hashes)
    exact(run["commands_digest"], sha(canonical(hashes)))
    for flag in ("argv_truncated", "timeouts", "truncation"): exact(run[flag], [False] * len(commands))
    exact(run["exit_statuses"], [0] * len(commands))
    require(type(run["operations"]) is list and len(run["operations"]) == len(commands))
    for operation in run["operations"]: require(operation in {"run_command", "apply_patch"})
    expected_check = ["sha256sum", "README"] if mode == "architect" else CONTENT_CHECK
    require(any(command == expected_check and operation == "run_command" for command, operation in zip(commands, run["operations"])))
    verify_test_log(bodies["tests.log"], commands, run["operations"], expected_check)
    journal = build_edit_journal_evidence(run["edit_journal"])
    for key, value in journal.items(): exact(run[key], value)
    if mode == "architect":
        exact(run["approval"], None)
        exact(job.get("approvalProposal"), None)
        exact(run["edit_journal"], [])
        require("apply_patch" not in run["operations"])
        require(bodies["changes.patch"] == b"" and sha(bodies["changes.patch"]) == EMPTY_SHA256)
    else:
        require(len(bodies["changes.patch"]) == PATCH_BYTES and sha(bodies["changes.patch"]) == PATCH_SHA256)
        fields(run["approval"], ("action", "target", "policyVersion", "resourceProfile", "sourceDigest", "expiresAt"))
        binding = run["approval"]
        exact({k: binding[k] for k in binding if k != "expiresAt"},
              {"action": "export_patch", "target": "owner_download", "policyVersion": "v1", "resourceProfile": PROFILE, "sourceDigest": BASELINE_TREE_SHA256})
        expires = production_epoch(binding["expiresAt"])
        require(now < expires <= run["finished_at_epoch"] + 300 and expires >= run["finished_at_epoch"] + 299)
        exact(job.get("approvalProposal"), {**binding, "proposalDigest": expected_digest})
        require(len(run["edit_journal"]) == 1 and run["operations"].count("apply_patch") == 1)
        entry = run["edit_journal"][0]
        exact(entry["actual_changed_paths"], [SOURCE_FILE])
        exact(entry["before_source_digest"], BASELINE_TREE_SHA256)
        exact(entry["after_source_digest"], PATCHED_TREE_SHA256)
        exact({k: entry[k] for k in ("result", "exit_code", "timed_out", "truncated", "rejection_code")},
              {"result": "promoted", "exit_code": 0, "timed_out": False, "truncated": False, "rejection_code": None})
    retained_job = {"id": job["id"], "mode": mode, "state": job["state"], "revision": job["revision"],
                    "sourceRevision": SOURCE_COMMIT, "sourceDigest": BASELINE_TREE_SHA256, "proposalDigest": expected_digest,
                    "approvalProposal": copy.deepcopy(job["approvalProposal"]), "approvalConsumed": False,
                    "evidence": retained, "baselineTreeSha256": BASELINE_TREE_SHA256, "finalTreeSha256": run["proposal_source_digest"],
                    "fileSha256": SOURCE_SHA256 if mode == "architect" else PATCHED_SHA256,
                    "commandDigest": run["commands_digest"], "editJournalDigest": run["edit_journal_digest"], "checkedAt": iso(now)}
    return retained_job, bodies, run


class Qualification:
    def __init__(self, client, boundaries, *, clock=time.time, monotonic=time.monotonic, sleep=time.sleep):
        self.client, self.boundaries, self.clock, self.monotonic, self.sleep = client, boundaries, clock, monotonic, sleep
        self.jobs, self.bindings = [], {}

    def check_deadline(self):
        require(self.monotonic() < self.deadline)

    def poll(self, identifier, expected, *, deadline=None):
        deadline = self.deadline if deadline is None else deadline
        while True:
            require(self.monotonic() < deadline)
            value = self.client.json("GET", f"/v1/jobs/{identifier}")
            exact(value.get("id"), identifier)
            if value.get("state") in expected:
                return value
            require(value.get("state") not in TERMINAL | {"awaiting_approval"})
            self.sleep(min(1, max(0.01, deadline - self.monotonic())))

    def create(self, mode, commit=SOURCE_COMMIT):
        self.check_deadline()
        result = self.client.json("POST", "/v1/jobs", submission(mode, commit), status=202)
        identifier = result.get("id")
        job_id(identifier)
        require(identifier not in self.jobs)
        self.jobs.append(identifier)
        self.bindings[identifier] = dict(self.client.last_binding)
        return identifier

    @staticmethod
    def decision(job, decision, *, proposal=None):
        payload = {"decision": decision, "expectedCoreRevision": job["revision"], "proposalDigest": job["proposalDigest"]}
        if decision == "approve":
            payload.update(approvalProposal=proposal or job["approvalProposal"], approvalTokenHash=sha(secrets.token_bytes(32)))
        return payload

    def reject(self, job):
        result = self.client.json("POST", f"/v1/jobs/{job['id']}/decisions", self.decision(job, "reject"))
        exact(result.get("state"), "rejected")
        exact(result.get("approvalConsumed"), False)
        exact(result.get("revision"), job["revision"] + 1)
        for key in ("id", "sourceDigest", "proposalDigest", "approvalProposal", "evidence_manifest", "evidence"):
            exact(result.get(key), job.get(key))
        return result

    def absence_rejection(self, job, payload, expected_status, expected_codes):
        self.check_deadline()
        before = self.client.json("GET", f"/v1/jobs/{job['id']}")
        exact(before, job)
        runtime = self.boundaries.runtime_snapshot()
        exact(runtime["containers"], [])
        status, body, _ = self.client.request("POST", f"/v1/jobs/{job['id']}/decisions", payload)
        require(status == expected_status and body in [{"error": {"code": code}} for code in expected_codes])
        exact(self.client.json("GET", f"/v1/jobs/{job['id']}"), before)
        exact(self.boundaries.runtime_snapshot(), runtime)
        # The status includes unconsumed approval and immutable evidence. No
        # export endpoint is invoked, even for an absence check.
        exact(before["approvalConsumed"], False)

    def run(self, provider_path, evidence_dir):
        self.started = self.clock()
        self.deadline = self.monotonic() + 1200
        document = read_provider(provider_path, now=self.started)
        output = EvidenceDirectory(evidence_dir)
        try:
            guest = self.boundaries.verify_guest()
            exact(guest.as_dict(), {"provider": document["provider"], "droplet_id": document["droplet"]["id"],
                                    "hostname": document["droplet"]["name"], "role": document["droplet"]["roleTag"]})
            head = self.boundaries.source_head()
            exact(self.boundaries.deployment(), 0)
            deployment = {"checkedAt": iso(self.clock()), "exitStatus": 0}
            images = self.boundaries.images()
            exact(self.boundaries.runtime_snapshot()["containers"], [])
            with tempfile.TemporaryDirectory() as temporary:
                scratch = Path(temporary)
                verify_source(self.boundaries, scratch / "baseline")
                before_ready = self.client.json("GET", "/readyz"); ready(before_ready)
                readiness = {"before": {"checkedAt": iso(self.clock()), "checks": before_ready["checks"]}}
                a = self.poll(self.create("architect"), {"completed"})
                job_a, _, _ = verify_job_evidence(self.client, a, mode="architect", started=self.started, now=self.clock())
                job_a["submission"] = self.bindings[a["id"]]
                sacrifice = self.poll(self.create("refactor"), {"awaiting_approval"})
                verify_job_evidence(self.client, sacrifice, mode="refactor", started=self.started, now=self.clock())
                expiry = production_epoch(sacrifice["approvalProposal"]["expiresAt"])
                while self.clock() <= expiry:
                    self.check_deadline()
                    self.sleep(min(5, expiry - self.clock() + 0.1))
                self.absence_rejection(sacrifice, self.decision(sacrifice, "approve"), 409, {"invalid_approval"})
                cancelled = self.client.json("POST", f"/v1/jobs/{sacrifice['id']}/cancel", {"expectedCoreRevision": sacrifice["revision"]}, status=202)
                cancelled = self.poll(cancelled["id"], {"cancelled"})
                exact(cancelled["approvalConsumed"], False)
                exact(self.boundaries.runtime_snapshot()["containers"], [])
                b = self.poll(self.create("refactor"), {"awaiting_approval"})
                job_b, bodies_b, run_b = verify_job_evidence(self.client, b, mode="refactor", started=self.started, now=self.clock())
                replay_before, replay_after = clean_replay(self.boundaries, scratch / "replay", bodies_b["changes.patch"])
                exact(run_b["edit_journal"][0]["delta_digest"], workspace_delta_digest(replay_before, replay_after, (SOURCE_FILE,)))
                negatives = {"expired_authorization": True, **local_negative_checks(self.boundaries, scratch)}
                self.absence_rejection(b, self.decision(b, "deploy"), 400, {"invalid_request"})
                negatives["forbidden_action"] = True
                proposal = {**b["approvalProposal"], "action": "deploy", "target": "production"}
                self.absence_rejection(b, self.decision(b, "approve", proposal=proposal), 400, {"invalid_request", "unsupported_action"})
                negatives["production_deployment_request"] = True
                status, body, _ = self.client.request("GET", "/readyz", timestamp=int(self.clock()) - 301)
                exact((status, body), (401, {"error": {"code": "authentication_failed"}}))
                nonce, request_id = secrets.token_hex(24), str(uuid.uuid4())
                ready(self.client.json("GET", "/readyz", nonce=nonce, request_id=request_id))
                status, body, _ = self.client.request("GET", "/readyz", nonce=nonce, request_id=request_id)
                exact((status, body), (409, {"error": {"code": "request_replayed"}}))
                negatives["replay"] = True
                wrong = self.poll(self.create("architect", "0" + SOURCE_COMMIT[1:]), {"failed"})
                exact(wrong.get("sourceDigest"), None)
                exact(wrong.get("evidence"), [])
                exact(wrong.get("evidence_manifest"), {})
                require(self.clock() < production_epoch(b["approvalProposal"]["expiresAt"]))
                rejected = self.reject(b)
                job_b.update(state="rejected", revision=rejected["revision"], submission=self.bindings[b["id"]], exported=False,
                             checkedAt=iso(self.clock()), lineage={"jobA": a["id"], "jobB": b["id"], "sourceRevision": SOURCE_COMMIT, "sourceDigest": BASELINE_TREE_SHA256})
                exact(self.boundaries.runtime_snapshot()["containers"], [])
                after_ready = self.client.json("GET", "/readyz"); ready(after_ready)
                readiness["after"] = {"checkedAt": iso(self.clock()), "checks": after_ready["checks"]}
                exact(self.boundaries.images(), images)
                exact(self.boundaries.source_head(), head)
                self.check_deadline()
                receipt = {"schema": SCHEMA, "startedAt": iso(self.started), "completedAt": iso(self.clock()), "sourceHead": head,
                           "providerEvidence": {"document": document, "sha256": sha(canonical(document))}, "identity": identity(document),
                           "topology": {"route": "direct_core_to_local_podman", "intermediary": "none", "policy": "ENGINEERING_EXECUTION_ONLY"},
                           "images": images, "deployment": deployment, "readiness": readiness, "jobA": job_a, "jobB": job_b,
                           "negativeChecks": negatives, "cleanup": {"checkedAt": iso(self.clock()), "noContainers": True, "allJobsTerminal": True,
                                                                      "sacrificialJobId": sacrifice["id"], "sacrificialState": "cancelled", "wrongRevisionJobId": wrong["id"], "wrongRevisionState": "failed"}}
                validate_receipt(receipt, now=self.clock())
            # Cleanup runs before publication and is also repeated on failure.
            self.cleanup()
            self.check_deadline()
            receipt["cleanup"]["checkedAt"] = iso(self.clock())
            receipt["completedAt"] = iso(self.clock())
            validate_receipt(receipt, now=self.clock())
            self.jobs = []
            return output.publish(receipt)
        finally:
            try:
                self.cleanup()
            finally:
                output.close()

    def cleanup(self):
        failure = False
        cleanup_deadline = self.monotonic() + 30
        for identifier in self.jobs:
            try:
                value = self.client.json("GET", f"/v1/jobs/{identifier}")
                if value.get("state") == "awaiting_approval":
                    self.reject(value)
                elif value.get("state") not in TERMINAL:
                    self.client.json("POST", f"/v1/jobs/{identifier}/cancel", {"expectedCoreRevision": value["revision"]}, status=202)
                    self.poll(identifier, {"cancelled"}, deadline=cleanup_deadline)
            except Exception:
                failure = True
        if self.jobs:
            try:
                exact(self.boundaries.runtime_snapshot()["containers"], [])
            except Exception:
                failure = True
        require(not failure)


def validate_receipt(value, *, now=None):
    now = time.time() if now is None else now
    fields(value, ("schema", "startedAt", "completedAt", "sourceHead", "providerEvidence", "identity", "topology", "images", "deployment", "readiness", "jobA", "jobB", "negativeChecks", "cleanup"))
    exact(value["schema"], SCHEMA)
    start, finish = epoch(value["startedAt"]), epoch(value["completedAt"])
    require(start <= finish <= now and finish - start <= 1200 and now - finish <= 900)
    require(isinstance(value["sourceHead"], str) and re.fullmatch(r"[0-9a-f]{40}", value["sourceHead"]) is not None)
    fields(value["providerEvidence"], ("document", "sha256"))
    document = validate_provider(value["providerEvidence"]["document"], now=start)
    exact(value["providerEvidence"]["sha256"], sha(canonical(document)))
    exact(value["identity"], identity(document))
    exact(value["topology"], {"route": "direct_core_to_local_podman", "intermediary": "none", "policy": "ENGINEERING_EXECUTION_ONLY"})
    fields(value["images"], ("core", "postgres", "runner"))
    for image in value["images"].values():
        require(isinstance(image, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", image) is not None)

    def gate(timestamp):
        require(start <= epoch(timestamp) <= finish)

    fields(value["deployment"], ("checkedAt", "exitStatus"))
    gate(value["deployment"]["checkedAt"])
    exact(value["deployment"]["exitStatus"], 0)
    fields(value["readiness"], ("before", "after"))
    for probe in value["readiness"].values():
        fields(probe, ("checkedAt", "checks")); gate(probe["checkedAt"])
        exact(probe["checks"], dict.fromkeys(READY_KEYS, True))
    a, b = value["jobA"], value["jobB"]
    for label, job, mode, state in (("jobA", a, "architect", "completed"), ("jobB", b, "refactor", "rejected")):
        names = {"id", "mode", "state", "revision", "sourceRevision", "sourceDigest", "proposalDigest", "approvalProposal", "approvalConsumed", "evidence",
                 "baselineTreeSha256", "finalTreeSha256", "fileSha256", "commandDigest", "editJournalDigest", "checkedAt", "submission"}
        fields(job, names | ({"lineage", "exported"} if label == "jobB" else set()))
        job_id(job["id"]); integer(job["revision"], 1); gate(job["checkedAt"])
        exact(job["mode"], mode); exact(job["state"], state)
        exact(job["sourceRevision"], SOURCE_COMMIT)
        exact(job["sourceDigest"], BASELINE_TREE_SHA256)
        exact(job["baselineTreeSha256"], BASELINE_TREE_SHA256)
        exact(job["finalTreeSha256"], BASELINE_TREE_SHA256 if label == "jobA" else PATCHED_TREE_SHA256)
        exact(job["fileSha256"], SOURCE_SHA256 if label == "jobA" else PATCHED_SHA256)
        for name in ("proposalDigest", "commandDigest", "editJournalDigest"): digest(job[name])
        exact(job["approvalConsumed"], False)
        fields(job["evidence"], ARTIFACTS)
        for name, descriptor in job["evidence"].items():
            fields(descriptor, ("id", "sha256", "bytes", "createdAt"))
            exact(descriptor["id"], evidence_id(job["id"], name)); digest(descriptor["sha256"])
            integer(descriptor["bytes"], 0, MAX_EVIDENCE_BYTES)
            require(start <= production_epoch(descriptor["createdAt"]) < finish + 1)
        exact(job["evidence"]["changes.patch"]["sha256"], EMPTY_SHA256 if label == "jobA" else PATCH_SHA256)
        exact(job["evidence"]["changes.patch"]["bytes"], 0 if label == "jobA" else PATCH_BYTES)
        binding = job["submission"]
        fields(binding, ("requestId", "nonce", "timestamp", "bodySha256"))
        require(isinstance(binding["requestId"], str) and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", binding["requestId"]) is not None)
        require(isinstance(binding["nonce"], str) and re.fullmatch(r"[0-9a-f]{48}", binding["nonce"]) is not None)
        require(isinstance(binding["timestamp"], str) and re.fullmatch(r"[0-9]{10,11}", binding["timestamp"]) is not None)
        require(start <= int(binding["timestamp"]) <= epoch(job["checkedAt"]))
        exact(binding["bodySha256"], sha(canonical(submission(mode))))
    exact(a["approvalProposal"], None)
    exact(b["exported"], False)
    fields(b["approvalProposal"], ("action", "target", "policyVersion", "resourceProfile", "sourceDigest", "expiresAt", "proposalDigest"))
    proposal = b["approvalProposal"]
    exact({k: v for k, v in proposal.items() if k != "expiresAt"}, {"action": "export_patch", "target": "owner_download", "policyVersion": "v1",
          "resourceProfile": PROFILE, "sourceDigest": BASELINE_TREE_SHA256, "proposalDigest": b["proposalDigest"]})
    require(epoch(b["checkedAt"]) < production_epoch(proposal["expiresAt"]) < finish + 301)
    exact(b["lineage"], {"jobA": a["id"], "jobB": b["id"], "sourceRevision": a["sourceRevision"], "sourceDigest": a["sourceDigest"]})
    exact(value["negativeChecks"], dict.fromkeys(NEGATIVE_KEYS, True))
    cleanup = value["cleanup"]
    fields(cleanup, ("checkedAt", "noContainers", "allJobsTerminal", "sacrificialJobId", "sacrificialState", "wrongRevisionJobId", "wrongRevisionState"))
    gate(cleanup["checkedAt"])
    for name in ("noContainers", "allJobsTerminal"): exact(cleanup[name], True)
    exact(cleanup["sacrificialState"], "cancelled"); exact(cleanup["wrongRevisionState"], "failed")
    job_id(cleanup["sacrificialJobId"]); job_id(cleanup["wrongRevisionJobId"])
    require(len({a["id"], b["id"], cleanup["sacrificialJobId"], cleanup["wrongRevisionJobId"]}) == 4)
    require(epoch(value["deployment"]["checkedAt"]) <= epoch(value["readiness"]["before"]["checkedAt"])
            <= epoch(a["checkedAt"]) <= epoch(b["checkedAt"]) <= epoch(value["readiness"]["after"]["checkedAt"]) <= epoch(cleanup["checkedAt"]))
    return value


def verify_local(path, *, now=None):
    raw = secure_read(path, limit=MAX_RECEIPT_BYTES)
    validate_receipt(parse_canonical(raw), now=now)
    return sha(raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Direct runner local qualification evidence")
    parser.add_argument("--check", action="store_true")
    commands = parser.add_subparsers(dest="command")
    run = commands.add_parser("run")
    for name in ("core-env", "source-root", "provider-evidence", "evidence-dir"):
        run.add_argument("--" + name, required=True, type=Path)
    verify = commands.add_parser("verify-local")
    verify.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.check:
            require(args.command is None)
            require(sha(b"Hello World!\n") == SOURCE_SHA256 and sha(b"Hello Tueiq!\n") == PATCHED_SHA256)
            require(len(NEGATIVE_KEYS) == len(set(NEGATIVE_KEYS)) == 9)
            target_module().offline_check()
            print("local qualification check: ok")
        elif args.command == "verify-local":
            print("local receipt sha256: " + verify_local(args.path))
        elif args.command == "run":
            require(os.geteuid() == 0)
            # Provider freshness is checked before metadata, credentials or host work.
            read_provider(args.provider_evidence)
            service = pwd.getpwnam("lil-tweak")
            require(service.pw_uid > 0 and service.pw_gid > 0 and service.pw_dir == "/var/lib/lil-tweak")
            environment = load_core_environment(args.core_env, service)
            host = InstalledBoundaries(args.source_root, service, environment, time.time())
            result = Qualification(CoreClient(environment), host).run(args.provider_evidence, args.evidence_dir)
            print("local receipt sha256: " + verify_local(result))
        else:
            parser.error("choose --check, run, or verify-local")
        return 0
    except (Exception, KeyboardInterrupt):
        print("local qualification failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
