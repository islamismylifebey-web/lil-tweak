from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qualification.supervisor import (
    ATTESTATION_DOMAIN,
    CHALLENGE_DOMAIN,
    REQUIRED_CHECKS,
    HostConfig,
    Observation,
    QualificationError,
    _prepare_cgroup_root,
    build_attestation,
    build_sandbox_command,
    canonical_json,
    content_digest,
    validate_challenge,
    validate_output_path,
)


def test_prepare_cgroup_root_enables_required_controllers(tmp_path: Path) -> None:
    root = tmp_path / "qualification"
    root.mkdir()
    (root / "cgroup.controllers").write_text("cpu io memory pids\n", encoding="ascii")
    (root / "cgroup.subtree_control").write_text("", encoding="ascii")

    _prepare_cgroup_root(root)

    assert set(
        value.lstrip("+-")
        for value in (root / "cgroup.subtree_control").read_text(encoding="ascii").split()
    ) == {"cpu", "memory", "pids"}


def _raw_public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _config(runner_key: Ed25519PrivateKey) -> HostConfig:
    public = _raw_public(runner_key)
    return HostConfig.from_mapping(
        {
            "schema_version": "liltweak-host-qualification-config/v1",
            "runner_id": "galor-tweak-runner-01",
            "key_id": hashlib.sha256(public).hexdigest(),
            "repository_id": "github:islamismylifebey-web/lil-tweak",
            "image_ref": "liltweak/qualification-rootfs@sha256:" + "1" * 64,
            "sandbox_profile_digest": "2" * 64,
            "runtime_sha256": "3" * 64,
            "limiter_sha256": "4" * 64,
            "qualifier_sha256": "5" * 64,
            "destroyer_sha256": "6" * 64,
            "supervisor_sha256": "7" * 64,
            "rootfs_manifest_sha256": "8" * 64,
            "apparmor_profile_sha256": "9" * 64,
            "seccomp_sha256": "a" * 64,
            "sandbox_uid": 17001,
            "sandbox_gid": 17001,
        }
    )


def _challenge(
    *,
    issuer_key: Ed25519PrivateKey,
    runner_key: Ed25519PrivateKey,
    now: datetime,
) -> tuple[dict[str, object], dict[str, str]]:
    config = _config(runner_key)
    payload: dict[str, object] = {
        "schema_version": "runner-qualification-challenge-v1",
        "qualification_id": "rq_" + "b" * 32,
        "runner_id": config.runner_id,
        "key_id": config.key_id,
        "issuer_key_id": hashlib.sha256(_raw_public(issuer_key)).hexdigest(),
        "nonce": "c" * 64,
        "suite_digest": content_digest(
            {
                "schema_version": "runner-qualification-suite-v1",
                "checks": REQUIRED_CHECKS,
            }
        ),
        "repository_id": config.repository_id,
        "repository_commit": "d" * 40,
        "repository_tree": "e" * 40,
        "image_ref": config.image_ref,
        "sandbox_profile_digest": config.sandbox_profile_digest,
        "runtime_sha256": config.runtime_sha256,
        "limiter_sha256": config.limiter_sha256,
        "qualifier_sha256": config.qualifier_sha256,
        "destroyer_sha256": config.destroyer_sha256,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
    }
    payload["challenge_digest"] = content_digest(payload)
    payload["issuer_signature"] = _b64url(
        issuer_key.sign(
            CHALLENGE_DOMAIN
            + canonical_json(
                {key: value for key, value in payload.items() if key != "issuer_signature"}
            ).encode()
        )
    )
    return payload, {"public_key_b64": _b64url(_raw_public(issuer_key))}


def test_signed_challenge_is_strictly_verified_and_bound_to_host_config() -> None:
    now = datetime(2026, 9, 1, 15, 0, tzinfo=UTC)
    issuer_key = Ed25519PrivateKey.generate()
    runner_key = Ed25519PrivateKey.generate()
    payload, issuer = _challenge(
        issuer_key=issuer_key,
        runner_key=runner_key,
        now=now,
    )

    validated = validate_challenge(payload, issuer, _config(runner_key), now=now)

    assert validated["repository_commit"] == "d" * 40
    changed = dict(payload)
    changed["repository_tree"] = "f" * 40
    with pytest.raises(QualificationError):
        validate_challenge(changed, issuer, _config(runner_key), now=now)


def test_attestation_has_exact_order_and_ed25519_signature() -> None:
    now = datetime(2026, 9, 1, 15, 0, tzinfo=UTC)
    issuer_key = Ed25519PrivateKey.generate()
    runner_key = Ed25519PrivateKey.generate()
    challenge, issuer = _challenge(
        issuer_key=issuer_key,
        runner_key=runner_key,
        now=now,
    )
    validate_challenge(challenge, issuer, _config(runner_key), now=now)
    observations = [
        Observation(check_id=item, passed=True, evidence={"probe": item}, duration_ms=1)
        for item in REQUIRED_CHECKS
    ]

    attestation = build_attestation(
        challenge=challenge,
        observations=observations,
        private_key=runner_key,
        boot_id_digest="0" * 64,
        session_id="rq-session",
        started_at=now,
        finished_at=now + timedelta(seconds=1),
    )

    assert [item["check_id"] for item in attestation["observations"]] == list(REQUIRED_CHECKS)
    assert attestation["raw_output_retained"] is False
    unsigned = dict(attestation)
    signature = unsigned.pop("signature")
    runner_key.public_key().verify(
        base64.urlsafe_b64decode(signature + "=="),
        ATTESTATION_DOMAIN + canonical_json(unsigned).encode(),
    )


def test_sandbox_command_reuses_shared_pinned_runtime_and_is_execution_disconnected() -> None:
    command = build_sandbox_command(
        source=Path("/var/lib/liltweak-qualification/rq_b/source"),
        workspace=Path("/var/lib/liltweak-qualification/rq_b/workspace"),
        sandbox_uid=17001,
        sandbox_gid=17001,
        seccomp_fd=9,
        program="print('probe')",
    )

    joined = "\n".join(command)
    assert command[:6] == (
        "/usr/bin/aa-exec",
        "-p",
        "liltweak-runner-job",
        "--",
        "/usr/bin/prlimit",
        "--cpu=4",
    )
    assert "/opt/liltweak-runtime/rootfs" in command
    assert "/opt/liltweak-runtime/venv" not in command
    for namespace in ("ipc", "pid", "net", "uts", "cgroup"):
        assert f"--unshare-{namespace}" in command
    assert "--unshare-all" not in command
    assert "--unshare-user" not in command
    assert "--share-net" not in command
    assert "--seccomp\n9" in joined
    assert "/usr/bin/setpriv" in command
    assert "--reuid=17001" in command
    assert "--regid=17001" in command
    assert "--bounding-set=-all" in command
    assert "--no-new-privs" in command
    assert "--ro-bind\n/var/lib/liltweak-qualification/rq_b/source\n/source" in joined
    assert joined.index("/usr/bin/aa-exec") < joined.index("/usr/bin/bwrap")
    assert joined.index("/usr/bin/prlimit") < joined.index("/usr/bin/bwrap")
    assert "--fsize=131072" in command
    assert "/usr/local/bin/python3" in command
    assert "/etc/liltweak-runner" not in joined
    supervisor = (Path(__file__).parents[1] / "qualification" / "supervisor.py").read_text(
        encoding="utf-8"
    )
    assert "/etc/liltweak-runner/repository_deploy_key" in supervisor
    assert "/etc/liltweak-runner/github-deploy-key" not in supervisor


def test_output_path_must_be_single_link_in_caller_owned_directory(tmp_path: Path) -> None:
    owned = tmp_path / "workspace"
    owned.mkdir()
    output = owned / "evidence.json"
    validate_output_path(output, caller_uid=owned.stat().st_uid)

    outside = tmp_path / "missing" / "evidence.json"
    with pytest.raises(QualificationError):
        validate_output_path(outside, caller_uid=owned.stat().st_uid)


def test_host_wrappers_and_installer_keep_root_surface_fixed() -> None:
    root = Path(__file__).parents[1]
    collect = (root / "qualification" / "bin" / "collect").read_text(encoding="utf-8")
    destroy = (root / "qualification" / "bin" / "destroy").read_text(encoding="utf-8")
    installer = (root / "qualification" / "install.sh").read_text(encoding="utf-8")

    assert "/opt/liltweak-qualification/libexec/supervisor collect" in collect
    assert "/opt/liltweak-qualification/libexec/supervisor destroy" in destroy
    assert "eval " not in collect + destroy + installer
    assert "curl " not in installer
    assert "chmod 0555" in installer
    assert "liltweak-runner ALL=(root) NOPASSWD:" in installer
    assert "/opt/liltweak-qualification/libexec/supervisor" in installer
