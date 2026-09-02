#!/usr/bin/python3
"""Root supervisor for fail-closed, execution-disconnected Gate 3 evidence.

The two world-executable entrypoints contain no privileged logic.  They may only
cross sudo into this root-owned program.  This program accepts a signed,
short-lived challenge, binds it to immutable local configuration, performs the
fixed probe suite, destroys every probe resource, and only then signs evidence.
It never accepts a repository URL, command, argument vector, or file content
from a job.
"""

# The embedded, fixed sandbox programs are intentionally single string literals.
# ruff: noqa: E501

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

try:  # pragma: no cover - available on the Linux qualification host
    import pwd
except ImportError:  # pragma: no cover - permits deterministic unit tests on Windows
    pwd = None  # type: ignore[assignment]

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

CHALLENGE_DOMAIN = b"liltweak:runner-qualification-challenge:v1\0"
ATTESTATION_DOMAIN = b"liltweak:runner-qualification:v1\0"
MAX_BYTES = 128_000
MAX_LIFETIME_SECONDS = 600
CONFIG_PATH = Path("/etc/liltweak-qualification/config.json")
SIGNING_KEY_PATH = Path("/etc/liltweak-runner/runner_signing_key.pem")
ROOTFS = Path("/opt/liltweak-runtime/rootfs")
ROOTFS_MANIFEST = ROOTFS / ".liltweak-rootfs-manifest.json"
SECCOMP_PATH = Path("/opt/liltweak-runner/seccomp.bpf")
APPARMOR_PATH = Path("/etc/apparmor.d/liltweak-runner-job")
DEPLOY_KEY_PATH = Path("/etc/liltweak-runner/repository_deploy_key")
KNOWN_HOSTS_PATH = Path("/etc/liltweak-runner/github_known_hosts")
COLLECT_PATH = Path("/opt/liltweak-qualification/bin/collect")
DESTROY_PATH = Path("/opt/liltweak-qualification/bin/destroy")
SUPERVISOR_PATH = Path("/opt/liltweak-qualification/libexec/supervisor")
STATE_ROOT = Path("/var/lib/liltweak-qualification")
WORK_ROOT = Path("/opt/actions-runner/_work")
CGROUP_ROOT = Path("/sys/fs/cgroup/liltweak-qualification")
FIXED_REPOSITORY_SSH = "git@github.com:islamismylifebey-web/lil-tweak.git"
APPARMOR_PROFILE = "liltweak-runner-job"
EXPECTED_IMAGE_REF = (
    "python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
)

REQUIRED_CHECKS: tuple[str, ...] = (
    "network.ipv4_egress_denied",
    "network.ipv6_egress_denied",
    "network.dns_denied",
    "network.loopback_host_denied",
    "network.metadata_denied",
    "network.proxy_environment_absent",
    "network.host_unix_sockets_absent",
    "identity.non_root",
    "isolation.no_new_privileges",
    "isolation.capabilities_dropped",
    "isolation.mac_policy_enforced",
    "isolation.seccomp_enforced",
    "isolation.host_pid_namespace_absent",
    "resource.cpu_hard_limit",
    "resource.memory_hard_limit",
    "resource.pid_hard_limit",
    "resource.disk_bytes_hard_limit",
    "resource.inode_hard_limit",
    "resource.wall_clock_hard_limit",
    "resource.output_hard_limit",
    "filesystem.source_read_only",
    "filesystem.root_read_only",
    "filesystem.git_metadata_absent",
    "filesystem.credentials_absent",
    "filesystem.other_repositories_absent",
    "filesystem.host_devices_absent",
    "filesystem.container_socket_absent",
    "filesystem.ssh_agent_absent",
    "filesystem.host_proc_environ_absent",
    "filesystem.control_plane_state_absent",
    "adversarial.timeout_terminated",
    "adversarial.oom_terminated",
    "adversarial.fork_bomb_terminated",
    "adversarial.output_flood_terminated",
    "adversarial.disk_flood_terminated",
    "adversarial.inode_flood_terminated",
    "adversarial.sleeping_child_terminated",
    "control.live_cancel_kills_cgroup",
    "control.emergency_stop_kills_cgroup",
    "control.crash_recovery_reaps_orphans",
    "integrity.source_digest_unchanged",
    "cleanup.cgroup_empty",
    "cleanup.cgroup_removed",
    "cleanup.mounts_detached",
    "cleanup.network_namespace_removed",
    "cleanup.workspace_destroyed",
    "cleanup.process_tree_dead",
)
SUITE_DIGEST = hashlib.sha256(
    json.dumps(
        {"schema_version": "runner-qualification-suite-v1", "checks": REQUIRED_CHECKS},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
).hexdigest()

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_QUALIFICATION_ID = re.compile(r"^rq_[0-9a-f]{32}$")
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,255}@sha256:[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class QualificationError(RuntimeError):
    """Fail-closed qualification rejection."""


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _b64decode(value: object, *, length: int) -> bytes:
    if not isinstance(value, str):
        raise QualificationError("encoded value is invalid")
    try:
        decoded = base64.b64decode(value + ("=" * (-len(value) % 4)), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise QualificationError("encoded value is invalid") from exc
    if len(decoded) != length:
        raise QualificationError("encoded value length is invalid")
    return decoded


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise QualificationError("pinned file is not a single regular file")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        final = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino, metadata.st_size) != (
            final.st_dev,
            final.st_ino,
            final.st_size,
        ):
            raise QualificationError("pinned file changed while hashing")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _strict_json(raw: bytes) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise QualificationError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationError("JSON input is invalid") from exc


def _read_bounded(path: Path, *, owner_uid: int | None = None) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size < 2
            or metadata.st_size > MAX_BYTES
            or (owner_uid is not None and metadata.st_uid != owner_uid)
        ):
            raise QualificationError("bounded input metadata is invalid")
        raw = os.read(descriptor, MAX_BYTES + 1)
        final = os.fstat(descriptor)
        if (
            len(raw) != metadata.st_size
            or final.st_dev != metadata.st_dev
            or final.st_ino != metadata.st_ino
            or final.st_size != metadata.st_size
            or final.st_nlink != 1
        ):
            raise QualificationError("bounded input changed while reading")
        return raw
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class HostConfig:
    runner_id: str
    key_id: str
    repository_id: str
    image_ref: str
    sandbox_profile_digest: str
    runtime_sha256: str
    limiter_sha256: str
    qualifier_sha256: str
    destroyer_sha256: str
    supervisor_sha256: str
    rootfs_manifest_sha256: str
    apparmor_profile_sha256: str
    seccomp_sha256: str
    sandbox_uid: int
    sandbox_gid: int

    @classmethod
    def from_mapping(cls, payload: object) -> HostConfig:
        expected = {
            "schema_version",
            "runner_id",
            "key_id",
            "repository_id",
            "image_ref",
            "sandbox_profile_digest",
            "runtime_sha256",
            "limiter_sha256",
            "qualifier_sha256",
            "destroyer_sha256",
            "supervisor_sha256",
            "rootfs_manifest_sha256",
            "apparmor_profile_sha256",
            "seccomp_sha256",
            "sandbox_uid",
            "sandbox_gid",
        }
        if not isinstance(payload, dict) or set(payload) != expected:
            raise QualificationError("host qualification config shape is invalid")
        if payload["schema_version"] != "liltweak-host-qualification-config/v1":
            raise QualificationError("host qualification config schema is invalid")
        strings = {
            key: payload[key] for key in expected - {"schema_version", "sandbox_uid", "sandbox_gid"}
        }
        if not all(isinstance(value, str) for value in strings.values()):
            raise QualificationError("host qualification config values are invalid")
        if not _SAFE_ID.fullmatch(strings["runner_id"]):
            raise QualificationError("runner id is invalid")
        if not _REPOSITORY.fullmatch(strings["repository_id"]):
            raise QualificationError("repository id is invalid")
        if not _IMAGE.fullmatch(strings["image_ref"]):
            raise QualificationError("image reference is invalid")
        for key in (
            "key_id",
            "sandbox_profile_digest",
            "runtime_sha256",
            "limiter_sha256",
            "qualifier_sha256",
            "destroyer_sha256",
            "supervisor_sha256",
            "rootfs_manifest_sha256",
            "apparmor_profile_sha256",
            "seccomp_sha256",
        ):
            if not _SHA256.fullmatch(strings[key]):
                raise QualificationError(f"{key} is invalid")
        uid = payload["sandbox_uid"]
        gid = payload["sandbox_gid"]
        if isinstance(uid, bool) or isinstance(gid, bool) or uid != 17001 or gid != 17001:
            raise QualificationError("sandbox identity is invalid")
        return cls(**strings, sandbox_uid=uid, sandbox_gid=gid)  # type: ignore[arg-type]


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise QualificationError("challenge timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise QualificationError("challenge timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise QualificationError("challenge timestamp is not timezone aware")
    return parsed.astimezone(UTC)


def validate_challenge(
    payload: object,
    issuer_payload: object,
    config: HostConfig,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    expected = {
        "schema_version",
        "qualification_id",
        "runner_id",
        "key_id",
        "issuer_key_id",
        "nonce",
        "suite_digest",
        "repository_id",
        "repository_commit",
        "repository_tree",
        "image_ref",
        "sandbox_profile_digest",
        "runtime_sha256",
        "limiter_sha256",
        "qualifier_sha256",
        "destroyer_sha256",
        "issued_at",
        "expires_at",
        "challenge_digest",
        "issuer_signature",
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise QualificationError("challenge shape is invalid")
    challenge = dict(payload)
    patterns = {
        "qualification_id": _QUALIFICATION_ID,
        "runner_id": _SAFE_ID,
        "key_id": _SHA256,
        "issuer_key_id": _SHA256,
        "nonce": _SHA256,
        "suite_digest": _SHA256,
        "repository_id": _REPOSITORY,
        "repository_commit": _OBJECT_ID,
        "repository_tree": _OBJECT_ID,
        "image_ref": _IMAGE,
        "sandbox_profile_digest": _SHA256,
        "runtime_sha256": _SHA256,
        "limiter_sha256": _SHA256,
        "qualifier_sha256": _SHA256,
        "destroyer_sha256": _SHA256,
        "challenge_digest": _SHA256,
    }
    if challenge["schema_version"] != "runner-qualification-challenge-v1":
        raise QualificationError("challenge schema is invalid")
    for key, pattern in patterns.items():
        if not isinstance(challenge[key], str) or not pattern.fullmatch(challenge[key]):
            raise QualificationError(f"challenge {key} is invalid")
    if challenge["suite_digest"] != SUITE_DIGEST:
        raise QualificationError("challenge suite is not exact")
    unsigned_digest = {
        key: value
        for key, value in challenge.items()
        if key not in {"challenge_digest", "issuer_signature"}
    }
    if challenge["challenge_digest"] != content_digest(unsigned_digest):
        raise QualificationError("challenge digest is invalid")
    bindings = {
        "runner_id": config.runner_id,
        "key_id": config.key_id,
        "repository_id": config.repository_id,
        "image_ref": config.image_ref,
        "sandbox_profile_digest": config.sandbox_profile_digest,
        "runtime_sha256": config.runtime_sha256,
        "limiter_sha256": config.limiter_sha256,
        "qualifier_sha256": config.qualifier_sha256,
        "destroyer_sha256": config.destroyer_sha256,
    }
    if any(challenge[key] != value for key, value in bindings.items()):
        raise QualificationError("challenge is not bound to this host configuration")
    issued = _parse_time(challenge["issued_at"])
    expires = _parse_time(challenge["expires_at"])
    observed = (now or datetime.now(UTC)).astimezone(UTC)
    lifetime = (expires - issued).total_seconds()
    if lifetime <= 0 or lifetime > MAX_LIFETIME_SECONDS or observed < issued or observed > expires:
        raise QualificationError("challenge is outside its validity window")
    if not isinstance(issuer_payload, dict) or set(issuer_payload) != {"public_key_b64"}:
        raise QualificationError("issuer key artifact is invalid")
    public = _b64decode(issuer_payload["public_key_b64"], length=32)
    if hashlib.sha256(public).hexdigest() != challenge["issuer_key_id"]:
        raise QualificationError("issuer key id is invalid")
    signature = _b64decode(challenge["issuer_signature"], length=64)
    signed = {key: value for key, value in challenge.items() if key != "issuer_signature"}
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, CHALLENGE_DOMAIN + canonical_json(signed).encode("utf-8")
        )
    except (InvalidSignature, ValueError) as exc:
        raise QualificationError("issuer signature is invalid") from exc
    return challenge


@dataclass(frozen=True)
class Observation:
    check_id: str
    passed: bool
    evidence: object
    duration_ms: int
    failure_code: str | None = None

    def document(self) -> dict[str, object]:
        if self.check_id not in REQUIRED_CHECKS:
            raise QualificationError("observation check id is invalid")
        if self.passed == bool(self.failure_code):
            raise QualificationError("observation result is contradictory")
        return {
            "check_id": self.check_id,
            "passed": self.passed,
            "evidence_digest": content_digest(self.evidence),
            "duration_ms": max(0, min(int(self.duration_ms), 600_000)),
            "source": "external_host_supervisor",
            "failure_code": self.failure_code,
        }


def build_attestation(
    *,
    challenge: dict[str, object],
    observations: list[Observation],
    private_key: Ed25519PrivateKey,
    boot_id_digest: str,
    session_id: str,
    started_at: datetime,
    finished_at: datetime,
) -> dict[str, object]:
    if tuple(item.check_id for item in observations) != REQUIRED_CHECKS:
        raise QualificationError("observations are not exact and ordered")
    if any(not item.passed for item in observations):
        raise QualificationError("a failed probe cannot produce passing evidence")
    if not _SHA256.fullmatch(boot_id_digest) or not _SAFE_ID.fullmatch(session_id):
        raise QualificationError("attestation host identity is invalid")
    draft: dict[str, object] = {
        "schema_version": "runner-qualification-v1",
        "qualification_id": challenge["qualification_id"],
        "challenge_digest": challenge["challenge_digest"],
        "runner_id": challenge["runner_id"],
        "key_id": challenge["key_id"],
        "nonce": challenge["nonce"],
        "suite_digest": challenge["suite_digest"],
        "repository_id": challenge["repository_id"],
        "repository_commit": challenge["repository_commit"],
        "repository_tree": challenge["repository_tree"],
        "image_ref": challenge["image_ref"],
        "sandbox_profile_digest": challenge["sandbox_profile_digest"],
        "runtime_sha256": challenge["runtime_sha256"],
        "limiter_sha256": challenge["limiter_sha256"],
        "qualifier_sha256": challenge["qualifier_sha256"],
        "destroyer_sha256": challenge["destroyer_sha256"],
        "boot_id_digest": boot_id_digest,
        "session_id": session_id,
        "started_at": started_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "finished_at": finished_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "observations": [item.document() for item in observations],
        "cleanup_verified": True,
        "raw_output_retained": False,
    }
    draft["evidence_digest"] = content_digest(draft)
    draft["signature"] = _b64encode(
        private_key.sign(ATTESTATION_DOMAIN + canonical_json(draft).encode("utf-8"))
    )
    return draft


def validate_output_path(path: Path, *, caller_uid: int) -> None:
    if not path.is_absolute() or path.exists() or path.name in {"", ".", ".."}:
        raise QualificationError("output path is invalid")
    try:
        parent = path.parent.resolve(strict=True)
    except FileNotFoundError as exc:
        raise QualificationError("output directory does not exist") from exc
    metadata = parent.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != caller_uid:
        raise QualificationError("output directory is not caller owned")


def _ensure_under(path: Path, root: Path) -> None:
    resolved = path.resolve(strict=path.exists())
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise QualificationError("workflow path is outside the runner work root") from exc


def build_sandbox_command(
    *,
    source: Path,
    workspace: Path,
    sandbox_uid: int,
    sandbox_gid: int,
    seccomp_fd: int,
    program: str,
) -> tuple[str, ...]:
    if (
        not str(source).replace("\\", "/").startswith("/")
        or not str(workspace).replace("\\", "/").startswith("/")
        or seccomp_fd < 3
    ):
        raise QualificationError("sandbox path or descriptor is invalid")
    if sandbox_uid != 17001 or sandbox_gid != 17001:
        raise QualificationError("sandbox identity is invalid")
    return (
        "/usr/bin/aa-exec",
        "-p",
        APPARMOR_PROFILE,
        "--",
        "/usr/bin/prlimit",
        "--cpu=4",
        "--as=268435456",
        "--nproc=64",
        "--nofile=128",
        "--fsize=131072",
        "--",
        "/usr/bin/bwrap",
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        ROOTFS.as_posix(),
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
        "--dir",
        "/source",
        "--ro-bind",
        source.as_posix(),
        "/source",
        "--dir",
        "/workspace",
        "--bind",
        workspace.as_posix(),
        "/workspace",
        "--chdir",
        "/workspace",
        "--clearenv",
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "PATH",
        "/usr/local/bin:/usr/bin:/bin",
        "--setenv",
        "LILTWEAK_QUALIFICATION_SANDBOX",
        "1",
        "--uid",
        str(sandbox_uid),
        "--gid",
        str(sandbox_gid),
        "--seccomp",
        str(seccomp_fd),
        "--",
        "/usr/local/bin/python3",
        "-I",
        "-c",
        program,
    )


def _trusted_root_file(path: Path, *, allowed_modes: set[int]) -> None:
    metadata = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) not in allowed_modes
        or path.is_symlink()
    ):
        raise QualificationError(f"untrusted root file: {path}")


def _load_private_key() -> Ed25519PrivateKey:
    _trusted_root_file(SIGNING_KEY_PATH, allowed_modes={0o400, 0o600})
    key = serialization.load_pem_private_key(_read_bounded(SIGNING_KEY_PATH), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise QualificationError("runner signing key type is invalid")
    return key


def _public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _write_atomic(path: Path, value: bytes, *, mode: int, uid: int = 0, gid: int = 0) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        written = 0
        while written < len(value):
            count = os.write(descriptor, value[written:])
            if count <= 0:
                raise QualificationError("atomic write made no progress")
            written += count
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _configure(arguments: argparse.Namespace) -> int:
    _require_root_direct()
    if arguments.runner_id != "galor-tweak-runner-01":
        raise QualificationError("only the dedicated runner id is authorized")
    if arguments.repository_id != "github:islamismylifebey-web/lil-tweak":
        raise QualificationError("only the Lil Tweak repository is authorized")
    for path, modes in (
        (Path("/usr/bin/bwrap"), {0o755}),
        (Path("/usr/bin/prlimit"), {0o755}),
        (COLLECT_PATH, {0o555}),
        (DESTROY_PATH, {0o555}),
        (SUPERVISOR_PATH, {0o500}),
        (ROOTFS_MANIFEST, {0o400, 0o444, 0o600, 0o644}),
        (APPARMOR_PATH, {0o400, 0o444, 0o600, 0o644}),
        (SECCOMP_PATH, {0o400, 0o444, 0o600, 0o644}),
    ):
        _trusted_root_file(path, allowed_modes=modes)
    rootfs_manifest = _strict_json(_read_bounded(ROOTFS_MANIFEST))
    if (
        not isinstance(rootfs_manifest, dict)
        or rootfs_manifest.get("image_ref") != EXPECTED_IMAGE_REF
    ):
        raise QualificationError("rootfs manifest does not pin the approved image")
    private_key = _load_private_key()
    public_key = _public_bytes(private_key)
    hashes = {
        "runtime_sha256": _sha256_file(Path("/usr/bin/bwrap")),
        "limiter_sha256": _sha256_file(Path("/usr/bin/prlimit")),
        "qualifier_sha256": _sha256_file(COLLECT_PATH),
        "destroyer_sha256": _sha256_file(DESTROY_PATH),
        "supervisor_sha256": _sha256_file(SUPERVISOR_PATH),
        "rootfs_manifest_sha256": _sha256_file(ROOTFS_MANIFEST),
        "apparmor_profile_sha256": _sha256_file(APPARMOR_PATH),
        "seccomp_sha256": _sha256_file(SECCOMP_PATH),
    }
    profile = {
        "schema_version": "liltweak-host-qualification-profile/v1",
        **{
            key: hashes[key]
            for key in (
                "supervisor_sha256",
                "rootfs_manifest_sha256",
                "apparmor_profile_sha256",
                "seccomp_sha256",
            )
        },
        "apparmor_profile": APPARMOR_PROFILE,
        "sandbox_uid": 17001,
        "sandbox_gid": 17001,
        "network_namespace": "unshare-all",
        "source_mount": "read-only-export",
        "root_mount": "read-only-rootfs",
        "workspace": {"type": "tmpfs", "bytes": 8_388_608, "inodes": 256},
        "cgroup": {"cpu_max": "10000 100000", "memory_max": 67_108_864, "pids_max": 32},
        "raw_output_retained": False,
        "execution_connected": False,
    }
    config = {
        "schema_version": "liltweak-host-qualification-config/v1",
        "runner_id": arguments.runner_id,
        "key_id": hashlib.sha256(public_key).hexdigest(),
        "repository_id": arguments.repository_id,
        "image_ref": EXPECTED_IMAGE_REF,
        "sandbox_profile_digest": content_digest(profile),
        **hashes,
        "sandbox_uid": 17001,
        "sandbox_gid": 17001,
    }
    HostConfig.from_mapping(config)
    encoded = json.dumps(config, indent=2, sort_keys=True).encode("ascii") + b"\n"
    _write_atomic(CONFIG_PATH, encoded, mode=0o600)
    public = {
        "LILTWEAK_QUALIFICATION_RUNNER_ID": config["runner_id"],
        "LILTWEAK_QUALIFICATION_KEY_ID": config["key_id"],
        "LILTWEAK_QUALIFICATION_RUNNER_PUBLIC_KEY": _b64encode(public_key),
        "LILTWEAK_QUALIFICATION_IMAGE_REF": config["image_ref"],
        "LILTWEAK_QUALIFICATION_PROFILE_DIGEST": config["sandbox_profile_digest"],
        "LILTWEAK_QUALIFICATION_RUNTIME_SHA256": config["runtime_sha256"],
        "LILTWEAK_QUALIFICATION_LIMITER_SHA256": config["limiter_sha256"],
        "LILTWEAK_QUALIFIER_SHA256": config["qualifier_sha256"],
        "LILTWEAK_DESTROYER_SHA256": config["destroyer_sha256"],
    }
    print(json.dumps(public, sort_keys=True))
    return 0


def _load_config() -> HostConfig:
    _trusted_root_file(CONFIG_PATH, allowed_modes={0o600})
    return HostConfig.from_mapping(_strict_json(_read_bounded(CONFIG_PATH)))


def _verify_local_pins(config: HostConfig) -> None:
    expected = {
        Path("/usr/bin/bwrap"): config.runtime_sha256,
        Path("/usr/bin/prlimit"): config.limiter_sha256,
        COLLECT_PATH: config.qualifier_sha256,
        DESTROY_PATH: config.destroyer_sha256,
        SUPERVISOR_PATH: config.supervisor_sha256,
        ROOTFS_MANIFEST: config.rootfs_manifest_sha256,
        APPARMOR_PATH: config.apparmor_profile_sha256,
        SECCOMP_PATH: config.seccomp_sha256,
    }
    for path, digest in expected.items():
        if _sha256_file(path) != digest:
            raise QualificationError("host qualification pin mismatch")
    loaded_profiles = Path("/sys/kernel/security/apparmor/profiles")
    if loaded_profiles.exists():
        profiles = loaded_profiles.read_text(encoding="utf-8", errors="strict")
        if not any(line.startswith(APPARMOR_PROFILE + " ") for line in profiles.splitlines()):
            raise QualificationError("AppArmor profile is not loaded")
    if not ROOTFS.is_dir() or ROOTFS.is_symlink():
        raise QualificationError("pinned rootfs is not a dedicated directory")
    for path in (DEPLOY_KEY_PATH, KNOWN_HOSTS_PATH, SIGNING_KEY_PATH):
        _trusted_root_file(path, allowed_modes={0o400, 0o444, 0o600, 0o644})


def _source_digest(root: Path) -> str:
    records: list[dict[str, object]] = []
    for path in sorted(root.rglob("*"), key=lambda value: value.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise QualificationError("source export contains an unsupported entry")
        if path.is_dir():
            records.append(
                {"path": relative, "kind": "directory", "mode": stat.S_IMODE(metadata.st_mode)}
            )
        else:
            records.append(
                {
                    "path": relative,
                    "kind": "file",
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "bytes": metadata.st_size,
                    "sha256": _sha256_file(path),
                }
            )
    return content_digest(records)


def _run_checked(command: list[str], *, env: dict[str, str] | None = None) -> bytes:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
        timeout=90,
        check=False,
    )
    if result.returncode != 0 or len(result.stdout) > 256 * 1024 * 1024:
        raise QualificationError("fixed source preparation command failed")
    return result.stdout


def _prepare_source(session: Path, challenge: dict[str, object]) -> tuple[Path, str]:
    repository = session / "repository.git"
    source = session / "source"
    archive = session / "source.tar"
    repository.mkdir(mode=0o700)
    source.mkdir(mode=0o755)
    _run_checked(["/usr/bin/git", "init", "--bare", str(repository)])
    ssh = (
        "/usr/bin/ssh -i /etc/liltweak-runner/repository_deploy_key "
        "-o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes "
        "-o UserKnownHostsFile=/etc/liltweak-runner/github_known_hosts "
        "-o GlobalKnownHostsFile=/dev/null -o PermitLocalCommand=no"
    )
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_SSH_COMMAND": ssh,
    }
    commit = str(challenge["repository_commit"])
    _run_checked(
        [
            "/usr/bin/git",
            "-C",
            str(repository),
            "fetch",
            "--no-tags",
            "--depth=1",
            FIXED_REPOSITORY_SSH,
            commit,
        ],
        env=env,
    )
    observed_commit = (
        _run_checked(
            ["/usr/bin/git", "-C", str(repository), "rev-parse", "FETCH_HEAD^{commit}"], env=env
        )
        .decode("ascii")
        .strip()
    )
    observed_tree = (
        _run_checked(
            ["/usr/bin/git", "-C", str(repository), "rev-parse", "FETCH_HEAD^{tree}"], env=env
        )
        .decode("ascii")
        .strip()
    )
    if observed_commit != commit or observed_tree != challenge["repository_tree"]:
        raise QualificationError("exact repository source binding failed")
    result = subprocess.run(
        [
            "/usr/bin/git",
            "-C",
            str(repository),
            "archive",
            "--format=tar",
            f"--output={archive}",
            "FETCH_HEAD",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        timeout=90,
        check=False,
    )
    if (
        result.returncode != 0
        or not archive.is_file()
        or archive.stat().st_size > 256 * 1024 * 1024
    ):
        raise QualificationError("exact source export failed")
    with tarfile.open(archive, "r:") as tar:
        members = tar.getmembers()
        for member in members:
            pure = Path(member.name)
            if pure.is_absolute() or ".." in pure.parts or not (member.isdir() or member.isfile()):
                raise QualificationError("source archive contains an unsafe entry")
        tar.extractall(source, members=members, filter="data")
    archive.unlink()
    shutil.rmtree(repository)
    for path in source.rglob("*"):
        if path.is_file():
            path.chmod(0o444)
        elif path.is_dir():
            path.chmod(0o555)
    source.chmod(0o555)
    return source, _source_digest(source)


_STATIC_PROBE = r"""import errno, json, os, pathlib, socket, stat
def denied(family, address):
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        code = sock.connect_ex(address)
        sock.close()
        return code != 0, code
    except OSError as exc:
        return True, exc.errno
def write_denied(path):
    try:
        pathlib.Path(path).write_bytes(b'x')
    except OSError as exc:
        return exc.errno in {errno.EROFS, errno.EACCES, errno.EPERM}, exc.errno
    return False, 0
status = {}
for line in pathlib.Path('/proc/self/status').read_text(encoding='ascii').splitlines():
    if ':' in line:
        key, value = line.split(':', 1); status[key] = value.strip()
label = pathlib.Path('/proc/self/attr/current').read_text(encoding='ascii').strip()
pids = sorted(int(p.name) for p in pathlib.Path('/proc').iterdir() if p.name.isdigit())
marker_seen = False
for pid in pids:
    try:
        marker_seen |= b'LILTWEAK_HOST_CONTROL_MARKER=' in pathlib.Path(f'/proc/{pid}/environ').read_bytes()
    except OSError:
        pass
ipv4, ipv4_errno = denied(socket.AF_INET, ('1.1.1.1', 443))
ipv6, ipv6_errno = denied(socket.AF_INET6, ('::1', 443, 0, 0))
loopback, loopback_errno = denied(socket.AF_INET, ('127.0.0.1', 9))
metadata, metadata_errno = denied(socket.AF_INET, ('169.254.169.254', 80))
try:
    socket.getaddrinfo('github.com', 443); dns = False; dns_error = 0
except OSError as exc:
    dns = True; dns_error = getattr(exc, 'errno', None)
proxy_keys = sorted(key for key in os.environ if key.lower() in {'http_proxy','https_proxy','all_proxy','no_proxy'})
unix_sockets = []
for root, dirs, files in os.walk('/run'):
    for name in files:
        path = os.path.join(root, name)
        try:
            if stat.S_ISSOCK(os.lstat(path).st_mode): unix_sockets.append(path)
        except OSError:
            pass
source_ro, source_errno = write_denied('/source/.qualification-write')
root_ro, root_errno = write_denied('/.qualification-write')
git_metadata = any(path.name == '.git' for path in pathlib.Path('/source').rglob('.git'))
credential_paths = [p for p in ('/root/.ssh','/root/.gitconfig','/etc/liltweak-runner') if pathlib.Path(p).exists()]
credential_env = sorted(key for key in os.environ if any(word in key.upper() for word in ('TOKEN','SECRET','PASSWORD','SSH_AUTH_SOCK','OPENAI_API_KEY')))
block_devices = []
for path in pathlib.Path('/dev').iterdir():
    try:
        if stat.S_ISBLK(path.stat().st_mode): block_devices.append(path.name)
    except OSError:
        pass
container_sockets = [p for p in ('/var/run/docker.sock','/run/containerd/containerd.sock','/run/podman/podman.sock') if pathlib.Path(p).exists()]
visible_mounts = pathlib.Path('/proc/self/mountinfo').read_text(encoding='utf-8').splitlines()
result = {
 'ipv4': ipv4, 'ipv4_errno': ipv4_errno, 'ipv6': ipv6, 'ipv6_errno': ipv6_errno,
 'dns': dns, 'dns_error': dns_error, 'loopback': loopback, 'loopback_errno': loopback_errno,
 'metadata': metadata, 'metadata_errno': metadata_errno, 'proxy_keys': proxy_keys,
 'unix_sockets': unix_sockets, 'euid': os.geteuid(), 'egid': os.getegid(),
 'no_new_privileges': status.get('NoNewPrivs') == '1',
 'capabilities_dropped': int(status.get('CapEff','1'), 16) == 0,
 'apparmor_label': label, 'seccomp': status.get('Seccomp'),
 'nspid': status.get('NSpid','').split(), 'pids': pids,
 'source_ro': source_ro, 'source_errno': source_errno, 'root_ro': root_ro, 'root_errno': root_errno,
 'git_metadata': git_metadata, 'credential_paths': credential_paths, 'credential_env': credential_env,
 'workspace_initial': sorted(p.name for p in pathlib.Path('/workspace').iterdir()),
 'block_devices': block_devices, 'container_sockets': container_sockets,
 'ssh_agent': os.environ.get('SSH_AUTH_SOCK'), 'host_marker_seen': marker_seen,
 'control_state': pathlib.Path('/var/lib/liltweak-runner').exists() or pathlib.Path('/etc/liltweak-runner/credentials.json').exists(),
 'mounts_digest': __import__('hashlib').sha256('\n'.join(visible_mounts).encode()).hexdigest(),
}
print(json.dumps(result, sort_keys=True, separators=(',', ':')))
"""


@dataclass(frozen=True)
class SandboxResult:
    name: str
    returncode: int
    timed_out: bool
    stdout: bytes
    stderr_digest: str
    output_bytes: int
    cgroup_limits: dict[str, str]
    cgroup_events: dict[str, dict[str, int]]
    cgroup_was_empty: bool
    cgroup_removed: bool
    mount_detached: bool
    workspace_destroyed: bool
    process_tree_dead: bool
    network_namespace_removed: bool
    duration_ms: int

    def evidence(self) -> dict[str, object]:
        return {
            "probe": self.name,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "stdout_digest": hashlib.sha256(self.stdout).hexdigest(),
            "stderr_digest": self.stderr_digest,
            "output_bytes": self.output_bytes,
            "cgroup_limits": self.cgroup_limits,
            "cgroup_events": self.cgroup_events,
            "cgroup_was_empty": self.cgroup_was_empty,
            "cgroup_removed": self.cgroup_removed,
            "mount_detached": self.mount_detached,
            "workspace_destroyed": self.workspace_destroyed,
            "process_tree_dead": self.process_tree_dead,
            "network_namespace_removed": self.network_namespace_removed,
            "duration_ms": self.duration_ms,
        }


def _read_counter(path: Path) -> dict[str, int]:
    values: dict[str, int] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].isdigit():
            values[fields[0]] = int(fields[1])
    return values


def _cgroup_populated(path: Path) -> bool:
    events = _read_counter(path / "cgroup.events")
    return bool(events.get("populated", 0))


def _kill_cgroup(path: Path) -> None:
    kill = path / "cgroup.kill"
    if kill.exists():
        kill.write_text("1\n", encoding="ascii")
    else:  # Linux older than cgroup.kill; still fixed and scoped to this cgroup.
        for value in (path / "cgroup.procs").read_text(encoding="ascii").split():
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(value), signal.SIGKILL)
    deadline = time.monotonic() + 3
    while _cgroup_populated(path) and time.monotonic() < deadline:
        time.sleep(0.02)


class SandboxRunner:
    def __init__(self, *, session: Path, source: Path, config: HostConfig) -> None:
        self.session = session
        self.source = source
        self.config = config
        self.results: list[SandboxResult] = []
        CGROUP_ROOT.mkdir(mode=0o700, exist_ok=True)

    def run(self, name: str, program: str, *, timeout: float = 5.0) -> SandboxResult:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", name):
            raise QualificationError("probe name is invalid")
        probe = self.session / "probes" / name
        workspace = probe / "workspace"
        probe.mkdir(mode=0o700, parents=True)
        workspace.mkdir(mode=0o700)
        cgroup = CGROUP_ROOT / f"{self.session.name}-{name}"
        cgroup.mkdir(mode=0o700)
        (cgroup / "cpu.max").write_text("10000 100000\n", encoding="ascii")
        (cgroup / "memory.max").write_text("67108864\n", encoding="ascii")
        if (cgroup / "memory.swap.max").exists():
            (cgroup / "memory.swap.max").write_text("0\n", encoding="ascii")
        (cgroup / "pids.max").write_text("32\n", encoding="ascii")
        mount = subprocess.run(
            [
                "/usr/bin/mount",
                "-t",
                "tmpfs",
                "-o",
                f"size=8388608,nr_inodes=256,mode=0700,uid={self.config.sandbox_uid},gid={self.config.sandbox_gid},nosuid,nodev,noexec",
                "liltweak-qualification",
                str(workspace),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
        if mount.returncode != 0:
            cgroup.rmdir()
            raise QualificationError("bounded workspace mount failed")
        limits = {
            key: (cgroup / key).read_text(encoding="ascii").strip()
            for key in ("cpu.max", "memory.max", "pids.max")
        }
        before = {
            "cpu.stat": _read_counter(cgroup / "cpu.stat"),
            "memory.events": _read_counter(cgroup / "memory.events"),
            "pids.events": _read_counter(cgroup / "pids.events"),
        }
        stdout_path = probe / "stdout"
        stderr_path = probe / "stderr"
        started = time.monotonic()
        pid = -1
        timed_out = False
        returncode = -255
        seccomp_descriptor = os.open(SECCOMP_PATH, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            command = build_sandbox_command(
                source=self.source,
                workspace=workspace,
                sandbox_uid=self.config.sandbox_uid,
                sandbox_gid=self.config.sandbox_gid,
                seccomp_fd=seccomp_descriptor,
                program=program,
            )

            def enter_cgroup() -> None:
                os.setsid()
                with (cgroup / "cgroup.procs").open("w", encoding="ascii") as handle:
                    handle.write(str(os.getpid()))

            with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    close_fds=True,
                    pass_fds=(seccomp_descriptor,),
                    preexec_fn=enter_cgroup,
                    env={
                        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                        "LILTWEAK_HOST_CONTROL_MARKER": "host-secret-boundary",
                    },
                )
                pid = process.pid
                try:
                    returncode = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _kill_cgroup(cgroup)
                    returncode = process.wait(timeout=3)
        except BaseException:
            _force_cleanup(cgroup=cgroup, workspace=workspace, probe=probe)
            raise
        finally:
            os.close(seccomp_descriptor)
        _kill_cgroup(cgroup)
        process_tree_dead = not _cgroup_populated(cgroup)
        events = {
            "cpu.stat": _read_counter(cgroup / "cpu.stat"),
            "memory.events": _read_counter(cgroup / "memory.events"),
            "pids.events": _read_counter(cgroup / "pids.events"),
            "before.cpu.stat": before["cpu.stat"],
            "before.memory.events": before["memory.events"],
            "before.pids.events": before["pids.events"],
        }
        cgroup_was_empty = not _cgroup_populated(cgroup)
        cgroup.rmdir()
        cgroup_removed = not cgroup.exists()
        network_removed = pid <= 0 or not Path(f"/proc/{pid}/ns/net").exists()
        unmount = subprocess.run(
            ["/usr/bin/umount", "--", str(workspace)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
        mount_detached = unmount.returncode == 0
        stdout = stdout_path.read_bytes()[:65_537]
        stderr = stderr_path.read_bytes()[:65_537]
        output_bytes = stdout_path.stat().st_size + stderr_path.stat().st_size
        shutil.rmtree(probe)
        workspace_destroyed = not probe.exists()
        result = SandboxResult(
            name=name,
            returncode=returncode,
            timed_out=timed_out,
            stdout=stdout,
            stderr_digest=hashlib.sha256(stderr).hexdigest(),
            output_bytes=output_bytes,
            cgroup_limits=limits,
            cgroup_events=events,
            cgroup_was_empty=cgroup_was_empty,
            cgroup_removed=cgroup_removed,
            mount_detached=mount_detached,
            workspace_destroyed=workspace_destroyed,
            process_tree_dead=process_tree_dead,
            network_namespace_removed=network_removed,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        self.results.append(result)
        return result


def _force_cleanup(*, cgroup: Path, workspace: Path, probe: Path) -> None:
    try:
        if cgroup.exists():
            _kill_cgroup(cgroup)
    except OSError:
        pass
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run(
            ["/usr/bin/umount", "-l", "--", str(workspace)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    shutil.rmtree(probe, ignore_errors=True)
    try:
        if cgroup.exists() and not _cgroup_populated(cgroup):
            cgroup.rmdir()
    except OSError:
        pass


def _delta(result: SandboxResult, group: str, key: str) -> int:
    after = result.cgroup_events.get(group, {}).get(key, 0)
    before = result.cgroup_events.get(f"before.{group}", {}).get(key, 0)
    return after - before


def _observation(check_id: str, passed: bool, evidence: object, *, duration_ms: int) -> Observation:
    return Observation(
        check_id=check_id,
        passed=bool(passed),
        evidence={"check_id": check_id, "measurement": evidence},
        duration_ms=duration_ms,
        failure_code=None if passed else "probe_failed",
    )


def _parse_probe_json(result: SandboxResult) -> dict[str, object]:
    if result.returncode != 0 or result.timed_out or len(result.stdout) > 32_768:
        raise QualificationError("static sandbox probe failed")
    try:
        payload = _strict_json(result.stdout)
    except QualificationError as exc:
        raise QualificationError("static sandbox probe output is invalid") from exc
    if not isinstance(payload, dict):
        raise QualificationError("static sandbox probe output is invalid")
    return payload


def _run_probe_suite(
    *,
    session: Path,
    source: Path,
    source_digest_before: str,
    config: HostConfig,
) -> list[Observation]:
    runner = SandboxRunner(session=session, source=source, config=config)
    static_result = runner.run("static", _STATIC_PROBE)
    static = _parse_probe_json(static_result)
    cpu = runner.run(
        "cpu",
        "import time\nend=time.monotonic()+1.2\nx=0\nwhile time.monotonic()<end: x+=1\nprint(x)",
        timeout=3,
    )
    memory = runner.run(
        "memory",
        "x=[]\nwhile True: x.append(bytearray(1024*1024))",
        timeout=4,
    )
    forks = runner.run(
        "forks",
        "import os,time\nwhile True:\n try:\n  p=os.fork()\n except OSError as e:\n  print(e.errno); break\n if p==0:\n  time.sleep(60); os._exit(0)",
        timeout=3,
    )
    disk = runner.run(
        "disk",
        "import os\nf=open('/workspace/fill','wb',buffering=0)\ntry:\n while True: f.write(b'x'*(1024*1024))\nexcept OSError as e: print(e.errno)",
        timeout=4,
    )
    inodes = runner.run(
        "inodes",
        "import os\ni=0\ntry:\n while True:\n  open(f'/workspace/i{i}','xb').close(); i+=1\nexcept OSError as e: print(i,e.errno)",
        timeout=4,
    )
    wall = runner.run(
        "wall",
        "import os,time\np=os.fork()\nif p==0: time.sleep(60)\ntime.sleep(60)",
        timeout=0.5,
    )
    output = runner.run(
        "output",
        "import os\nblock=b'x'*4096\nwhile True: os.write(1,block)",
        timeout=3,
    )
    cancel = runner.run("cancel", "import time; time.sleep(60)", timeout=0.4)
    emergency = runner.run("emergency", "import time; time.sleep(60)", timeout=0.4)
    crash = runner.run(
        "crash",
        "import os,time\np=os.fork()\nif p==0:\n os.close(1); os.close(2); time.sleep(60); os._exit(0)\nprint(p)",
        timeout=0.8,
    )
    source_digest_after = _source_digest(source)

    def exact_limits(item: SandboxResult) -> bool:
        return (
            item.cgroup_limits.get("cpu.max") == "10000 100000"
            and item.cgroup_limits.get("memory.max") == "67108864"
            and item.cgroup_limits.get("pids.max") == "32"
        )

    def result_evidence(item: SandboxResult) -> dict[str, object]:
        return item.evidence()

    observations: dict[str, Observation] = {}

    def add(
        check_id: str, passed: bool, evidence: object, duration: int = static_result.duration_ms
    ) -> None:
        observations[check_id] = _observation(check_id, passed, evidence, duration_ms=duration)

    for check_id, key in (
        ("network.ipv4_egress_denied", "ipv4"),
        ("network.ipv6_egress_denied", "ipv6"),
        ("network.dns_denied", "dns"),
        ("network.loopback_host_denied", "loopback"),
        ("network.metadata_denied", "metadata"),
    ):
        add(
            check_id,
            static.get(key) is True,
            {key: static.get(key), f"{key}_errno": static.get(f"{key}_errno")},
        )
    add(
        "network.proxy_environment_absent",
        static.get("proxy_keys") == [],
        {"proxy_keys": static.get("proxy_keys")},
    )
    add(
        "network.host_unix_sockets_absent",
        static.get("unix_sockets") == [],
        {"unix_sockets": static.get("unix_sockets")},
    )
    add(
        "identity.non_root",
        static.get("euid") == 17001 and static.get("egid") == 17001,
        {"euid": static.get("euid"), "egid": static.get("egid")},
    )
    add(
        "isolation.no_new_privileges",
        static.get("no_new_privileges") is True,
        {"no_new_privileges": static.get("no_new_privileges")},
    )
    add(
        "isolation.capabilities_dropped",
        static.get("capabilities_dropped") is True,
        {"capabilities_dropped": static.get("capabilities_dropped")},
    )
    label = static.get("apparmor_label")
    add(
        "isolation.mac_policy_enforced",
        isinstance(label, str) and label.startswith(APPARMOR_PROFILE),
        {"apparmor_label": label},
    )
    add(
        "isolation.seccomp_enforced",
        static.get("seccomp") == "2",
        {"seccomp": static.get("seccomp"), "filter_sha256": config.seccomp_sha256},
    )
    pids = static.get("pids")
    nspid = static.get("nspid")
    add(
        "isolation.host_pid_namespace_absent",
        isinstance(pids, list) and len(pids) <= 8 and isinstance(nspid, list) and len(nspid) == 1,
        {"visible_pid_count": len(pids) if isinstance(pids, list) else -1, "nspid": nspid},
    )

    add(
        "resource.cpu_hard_limit",
        exact_limits(cpu) and cpu.returncode == 0 and _delta(cpu, "cpu.stat", "nr_throttled") > 0,
        result_evidence(cpu),
        cpu.duration_ms,
    )
    add(
        "resource.memory_hard_limit",
        exact_limits(memory) and _delta(memory, "memory.events", "oom_kill") > 0,
        result_evidence(memory),
        memory.duration_ms,
    )
    add(
        "resource.pid_hard_limit",
        exact_limits(forks) and _delta(forks, "pids.events", "max") > 0,
        result_evidence(forks),
        forks.duration_ms,
    )
    add(
        "resource.disk_bytes_hard_limit",
        disk.returncode == 0 and disk.stdout.strip() in {b"28", b"27"},
        result_evidence(disk),
        disk.duration_ms,
    )
    add(
        "resource.inode_hard_limit",
        inodes.returncode == 0 and bool(inodes.stdout.strip()),
        result_evidence(inodes),
        inodes.duration_ms,
    )
    add(
        "resource.wall_clock_hard_limit",
        wall.timed_out and wall.process_tree_dead,
        result_evidence(wall),
        wall.duration_ms,
    )
    add(
        "resource.output_hard_limit",
        output.returncode != 0 and output.output_bytes <= 131_074,
        result_evidence(output),
        output.duration_ms,
    )

    add(
        "filesystem.source_read_only",
        static.get("source_ro") is True,
        {"source_ro": static.get("source_ro"), "errno": static.get("source_errno")},
    )
    add(
        "filesystem.root_read_only",
        static.get("root_ro") is True,
        {"root_ro": static.get("root_ro"), "errno": static.get("root_errno")},
    )
    add(
        "filesystem.git_metadata_absent",
        static.get("git_metadata") is False,
        {"git_metadata": static.get("git_metadata")},
    )
    add(
        "filesystem.credentials_absent",
        static.get("credential_paths") == [] and static.get("credential_env") == [],
        {
            "paths": static.get("credential_paths"),
            "environment_names": static.get("credential_env"),
        },
    )
    add(
        "filesystem.other_repositories_absent",
        static.get("workspace_initial") == [] and static.get("git_metadata") is False,
        {"workspace_initial": static.get("workspace_initial")},
    )
    add(
        "filesystem.host_devices_absent",
        static.get("block_devices") == [],
        {"block_devices": static.get("block_devices")},
    )
    add(
        "filesystem.container_socket_absent",
        static.get("container_sockets") == [],
        {"container_sockets": static.get("container_sockets")},
    )
    add(
        "filesystem.ssh_agent_absent",
        static.get("ssh_agent") is None,
        {"ssh_agent_present": static.get("ssh_agent") is not None},
    )
    add(
        "filesystem.host_proc_environ_absent",
        static.get("host_marker_seen") is False,
        {
            "host_marker_seen": static.get("host_marker_seen"),
            "visible_pid_count": len(pids) if isinstance(pids, list) else -1,
        },
    )
    add(
        "filesystem.control_plane_state_absent",
        static.get("control_state") is False,
        {"control_state": static.get("control_state")},
    )

    add(
        "adversarial.timeout_terminated",
        wall.timed_out and wall.process_tree_dead,
        result_evidence(wall),
        wall.duration_ms,
    )
    add(
        "adversarial.oom_terminated",
        memory.returncode != 0
        and _delta(memory, "memory.events", "oom_kill") > 0
        and memory.process_tree_dead,
        result_evidence(memory),
        memory.duration_ms,
    )
    add(
        "adversarial.fork_bomb_terminated",
        _delta(forks, "pids.events", "max") > 0 and forks.process_tree_dead,
        result_evidence(forks),
        forks.duration_ms,
    )
    add(
        "adversarial.output_flood_terminated",
        output.returncode != 0 and output.process_tree_dead and output.output_bytes <= 131_074,
        result_evidence(output),
        output.duration_ms,
    )
    add(
        "adversarial.disk_flood_terminated",
        disk.returncode == 0 and disk.process_tree_dead and disk.stdout.strip() in {b"28", b"27"},
        result_evidence(disk),
        disk.duration_ms,
    )
    add(
        "adversarial.inode_flood_terminated",
        inodes.returncode == 0 and inodes.process_tree_dead and bool(inodes.stdout.strip()),
        result_evidence(inodes),
        inodes.duration_ms,
    )
    add(
        "adversarial.sleeping_child_terminated",
        wall.timed_out and wall.process_tree_dead,
        result_evidence(wall),
        wall.duration_ms,
    )
    add(
        "control.live_cancel_kills_cgroup",
        cancel.timed_out and cancel.cgroup_was_empty and cancel.process_tree_dead,
        result_evidence(cancel),
        cancel.duration_ms,
    )
    add(
        "control.emergency_stop_kills_cgroup",
        emergency.timed_out and emergency.cgroup_was_empty and emergency.process_tree_dead,
        result_evidence(emergency),
        emergency.duration_ms,
    )
    add(
        "control.crash_recovery_reaps_orphans",
        crash.process_tree_dead and crash.cgroup_was_empty,
        result_evidence(crash),
        crash.duration_ms,
    )
    add(
        "integrity.source_digest_unchanged",
        source_digest_after == source_digest_before,
        {"before": source_digest_before, "after": source_digest_after},
    )

    all_empty = all(item.cgroup_was_empty for item in runner.results)
    all_removed = all(item.cgroup_removed for item in runner.results)
    all_unmounted = all(item.mount_detached for item in runner.results)
    all_net_removed = all(item.network_namespace_removed for item in runner.results)
    all_workspaces = all(item.workspace_destroyed for item in runner.results)
    all_dead = all(item.process_tree_dead for item in runner.results)
    cleanup_evidence = {
        "probe_count": len(runner.results),
        "probe_digests": [content_digest(item.evidence()) for item in runner.results],
    }
    add("cleanup.cgroup_empty", all_empty, {**cleanup_evidence, "all_empty": all_empty})
    add("cleanup.cgroup_removed", all_removed, {**cleanup_evidence, "all_removed": all_removed})
    add(
        "cleanup.mounts_detached",
        all_unmounted,
        {**cleanup_evidence, "all_unmounted": all_unmounted},
    )
    add(
        "cleanup.network_namespace_removed",
        all_net_removed,
        {**cleanup_evidence, "all_network_namespaces_removed": all_net_removed},
    )
    add(
        "cleanup.workspace_destroyed",
        all_workspaces,
        {**cleanup_evidence, "all_workspaces_destroyed": all_workspaces},
    )
    add(
        "cleanup.process_tree_dead",
        all_dead,
        {**cleanup_evidence, "all_process_trees_dead": all_dead},
    )

    if set(observations) != set(REQUIRED_CHECKS):
        raise QualificationError("probe implementation does not cover the exact suite")
    return [observations[check_id] for check_id in REQUIRED_CHECKS]


def _require_root_direct() -> None:
    if os.name != "posix" or os.geteuid() != 0:
        raise QualificationError("qualification supervisor requires root")


def _caller_uid() -> int:
    _require_root_direct()
    value = os.environ.get("SUDO_UID", "")
    if not value.isdigit() or int(value) == 0 or pwd is None:
        raise QualificationError("qualification caller is invalid")
    uid = int(value)
    if pwd.getpwuid(uid).pw_name != "liltweak-runner":
        raise QualificationError("qualification caller is not the runner service user")
    return uid


def _destroy_all_sessions() -> dict[str, bool]:
    STATE_ROOT.mkdir(mode=0o700, exist_ok=True)
    (STATE_ROOT / "sessions").mkdir(mode=0o700, exist_ok=True)
    if CGROUP_ROOT.exists():
        for cgroup in list(CGROUP_ROOT.iterdir()):
            if cgroup.is_dir() and not cgroup.is_symlink():
                try:
                    _kill_cgroup(cgroup)
                    cgroup.rmdir()
                except OSError:
                    pass
    sessions = STATE_ROOT / "sessions"
    for workspace in sessions.glob("*/probes/*/workspace"):
        subprocess.run(
            ["/usr/bin/umount", "-l", "--", str(workspace)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    for child in list(sessions.iterdir()):
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child, ignore_errors=True)
    cgroups_absent = not CGROUP_ROOT.exists() or not any(CGROUP_ROOT.iterdir())
    sessions_absent = not any(sessions.iterdir())
    mountinfo = Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="strict")
    mounts_absent = str(sessions) not in mountinfo
    return {
        "cgroups_absent": cgroups_absent,
        "sessions_absent": sessions_absent,
        "mounts_absent": mounts_absent,
    }


def _collect(arguments: argparse.Namespace) -> int:
    caller_uid = _caller_uid()
    required_flags = (
        "deny_all_network",
        "require_non_root",
        "require_mac_and_seccomp",
        "require_cgroup_and_filesystem_limits",
        "require_live_cancel_and_emergency_kill",
        "require_orphan_reaping",
        "require_host_process_and_control_plane_denial",
        "require_signed_attestation",
        "require_complete_cleanup",
        "require_execution_disconnected",
    )
    if not all(getattr(arguments, name) is True for name in required_flags):
        raise QualificationError("all fail-closed qualification requirements are mandatory")
    if not arguments.github_run_id.isdigit() or not arguments.github_run_attempt.isdigit():
        raise QualificationError("GitHub run binding is invalid")
    for path in (arguments.challenge, arguments.issuer_public_key):
        _ensure_under(path, WORK_ROOT)
    _ensure_under(arguments.output, WORK_ROOT)
    validate_output_path(arguments.output, caller_uid=caller_uid)
    config = _load_config()
    _verify_local_pins(config)
    private_key = _load_private_key()
    if hashlib.sha256(_public_bytes(private_key)).hexdigest() != config.key_id:
        raise QualificationError("runner signing key does not match the host config")
    challenge_payload = _strict_json(_read_bounded(arguments.challenge, owner_uid=caller_uid))
    issuer_payload = _strict_json(_read_bounded(arguments.issuer_public_key, owner_uid=caller_uid))
    challenge = validate_challenge(challenge_payload, issuer_payload, config)
    qualification_id = str(challenge["qualification_id"])
    session = STATE_ROOT / "sessions" / qualification_id
    used = STATE_ROOT / "used" / str(challenge["challenge_digest"])
    (STATE_ROOT / "sessions").mkdir(mode=0o700, parents=True, exist_ok=True)
    (STATE_ROOT / "used").mkdir(mode=0o700, parents=True, exist_ok=True)
    used_descriptor = os.open(
        used,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.write(
            used_descriptor,
            f"{arguments.github_run_id}:{arguments.github_run_attempt}\n".encode("ascii"),
        )
        os.fsync(used_descriptor)
    finally:
        os.close(used_descriptor)
    session.mkdir(mode=0o700)
    started = datetime.now(UTC)
    try:
        source, source_digest = _prepare_source(session, challenge)
        observations = _run_probe_suite(
            session=session,
            source=source,
            source_digest_before=source_digest,
            config=config,
        )
        if any(not item.passed for item in observations):
            raise QualificationError("one or more host probes failed")
        cleanup = _destroy_all_sessions()
        if not all(cleanup.values()):
            raise QualificationError("complete cleanup could not be verified")
        finished = datetime.now(UTC)
        if finished > _parse_time(challenge["expires_at"]):
            raise QualificationError("challenge expired during qualification")
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_bytes()
        if not (2 <= len(boot_id) <= 128):
            raise QualificationError("boot identity is invalid")
        attestation = build_attestation(
            challenge=challenge,
            observations=observations,
            private_key=private_key,
            boot_id_digest=hashlib.sha256(boot_id.strip()).hexdigest(),
            session_id=qualification_id,
            started_at=started,
            finished_at=finished,
        )
        encoded = json.dumps(attestation, indent=2, sort_keys=True).encode("ascii") + b"\n"
        if len(encoded) > MAX_BYTES:
            raise QualificationError("attestation exceeds the bounded output size")
        caller_gid = pwd.getpwuid(caller_uid).pw_gid  # type: ignore[union-attr]
        _write_atomic(arguments.output, encoded, mode=0o600, uid=caller_uid, gid=caller_gid)
    except BaseException:
        _destroy_all_sessions()
        raise
    print(str(challenge["challenge_digest"]))
    return 0


def _destroy(arguments: argparse.Namespace) -> int:
    _caller_uid()
    if not arguments.github_run_id.isdigit() or not arguments.github_run_attempt.isdigit():
        raise QualificationError("GitHub run binding is invalid")
    if not all(
        (
            arguments.require_no_processes,
            arguments.require_no_mounts,
            arguments.require_no_cgroups,
            arguments.require_no_workspaces,
        )
    ):
        raise QualificationError("all destroy verification requirements are mandatory")
    state = _destroy_all_sessions()
    if not all(state.values()):
        raise QualificationError("qualification cleanup remains incomplete")
    print(
        content_digest(
            {
                "run_id": arguments.github_run_id,
                "run_attempt": arguments.github_run_attempt,
                **state,
            }
        )
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lil Tweak host qualification supervisor")
    commands = parser.add_subparsers(dest="command", required=True)
    configure = commands.add_parser("configure")
    configure.add_argument("--runner-id", required=True)
    configure.add_argument("--repository-id", required=True)
    configure.set_defaults(handler=_configure)
    collect = commands.add_parser("collect")
    collect.add_argument("--github-run-id", required=True)
    collect.add_argument("--github-run-attempt", required=True)
    collect.add_argument("--challenge", required=True, type=Path)
    collect.add_argument("--issuer-public-key", required=True, type=Path)
    collect.add_argument("--output", required=True, type=Path)
    for name in (
        "deny-all-network",
        "require-non-root",
        "require-mac-and-seccomp",
        "require-cgroup-and-filesystem-limits",
        "require-live-cancel-and-emergency-kill",
        "require-orphan-reaping",
        "require-host-process-and-control-plane-denial",
        "require-signed-attestation",
        "require-complete-cleanup",
        "require-execution-disconnected",
    ):
        collect.add_argument(f"--{name}", action="store_true")
    collect.set_defaults(handler=_collect)
    destroy = commands.add_parser("destroy")
    destroy.add_argument("--github-run-id", required=True)
    destroy.add_argument("--github-run-attempt", required=True)
    for name in (
        "require-no-processes",
        "require-no-mounts",
        "require-no-cgroups",
        "require-no-workspaces",
    ):
        destroy.add_argument(f"--{name}", action="store_true")
    destroy.set_defaults(handler=_destroy)
    return parser


def _reject() -> NoReturn:
    print("runner qualification rejected", file=sys.stderr)
    raise SystemExit(2)


def main() -> int:
    try:
        arguments = _parser().parse_args()
        return int(arguments.handler(arguments))
    except (QualificationError, OSError, ValueError, subprocess.SubprocessError):
        _reject()


if __name__ == "__main__":
    raise SystemExit(main())
