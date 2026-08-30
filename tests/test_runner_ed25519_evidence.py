from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from liltweak.runner_evidence import RunnerQualificationBundleVerifier
from liltweak.workbench_executor import ExecutorUnavailableError

NOW = datetime(2026, 8, 30, 12, 5, tzinfo=UTC)
ISSUED = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
REPOSITORY_COMMIT = "0123456789abcdef0123456789abcdef01234567"
REPOSITORY_TREE = "89abcdef0123456789abcdef0123456789abcdef"
RUNNER_ID = "galor-private-cloud-01"
REPOSITORY_ID = "github:islamismylifebey-web/lil-tweak"

REQUIRED_CHECKS = (
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


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def fixture_bundle() -> dict[str, object]:
    issuer = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    runner = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
    issuer_public = public_bytes(issuer)
    runner_public = public_bytes(runner)
    issuer_key_id = hashlib.sha256(issuer_public).hexdigest()
    runner_key_id = hashlib.sha256(runner_public).hexdigest()
    expires = ISSUED + timedelta(minutes=10)
    suite_digest = content_digest(
        {
            "schema_version": "runner-qualification-suite-v1",
            "checks": REQUIRED_CHECKS,
        }
    )
    challenge_body: dict[str, object] = {
        "schema_version": "runner-qualification-challenge-v1",
        "qualification_id": "rq_" + "1" * 32,
        "runner_id": RUNNER_ID,
        "key_id": runner_key_id,
        "issuer_key_id": issuer_key_id,
        "nonce": "2" * 64,
        "suite_digest": suite_digest,
        "repository_id": REPOSITORY_ID,
        "repository_commit": REPOSITORY_COMMIT,
        "repository_tree": REPOSITORY_TREE,
        "image_ref": "ghcr.io/galor/liltweak-runner@sha256:" + "3" * 64,
        "sandbox_profile_digest": "4" * 64,
        "runtime_sha256": "5" * 64,
        "limiter_sha256": "6" * 64,
        "qualifier_sha256": "7" * 64,
        "destroyer_sha256": "8" * 64,
        "issued_at": iso(ISSUED),
        "expires_at": iso(expires),
    }
    challenge_digest = content_digest(challenge_body)
    challenge_unsigned = {**challenge_body, "challenge_digest": challenge_digest}
    challenge = {
        **challenge_unsigned,
        "issuer_signature": b64u(
            issuer.sign(
                b"liltweak:runner-qualification-challenge:v1\0"
                + canonical_json(challenge_unsigned).encode()
            )
        ),
    }
    observations = [
        {
            "check_id": check_id,
            "passed": True,
            "evidence_digest": hashlib.sha256(f"{index}:{check_id}".encode()).hexdigest(),
            "duration_ms": index + 1,
            "source": "external_host_supervisor",
            "failure_code": None,
        }
        for index, check_id in enumerate(REQUIRED_CHECKS)
    ]
    started = ISSUED + timedelta(seconds=10)
    finished = ISSUED + timedelta(minutes=2)
    attestation_body: dict[str, object] = {
        "schema_version": "runner-qualification-v1",
        "qualification_id": challenge["qualification_id"],
        "challenge_digest": challenge_digest,
        "runner_id": RUNNER_ID,
        "key_id": runner_key_id,
        "nonce": challenge["nonce"],
        "suite_digest": suite_digest,
        "repository_id": REPOSITORY_ID,
        "repository_commit": REPOSITORY_COMMIT,
        "repository_tree": REPOSITORY_TREE,
        "image_ref": challenge["image_ref"],
        "sandbox_profile_digest": challenge["sandbox_profile_digest"],
        "runtime_sha256": challenge["runtime_sha256"],
        "limiter_sha256": challene["limiter_sha256"],
        "qualifier_sha256": challenge["qualifier_sha256"],
        "destroyer_sha256": challenge["destroyer_sha256"],
        "boot_id_digest": "9" * 64,
        "session_id": "session:fixture",
        "started_at": iso(started),
        "finished_at": iso(finished),
        "observations": observations,
        "cleanup_verified": True,
        "raw_output_retained": False,
    }
    evidence_digest = content_digest(attestation_body)
    attestation_unsigned = {**attestation_body, "evidence_digest": evidence_digest}
    attestation = {
        **attestation_unsigned,
        "signature": b64u(
            runner.sign(
                b"liltweak:runner-qualification:v1\0"
                + canonical_json(attestation_unsigned).encode()
            )
        ),
    }
    decision = {
        "schema_version": "runner-qualification-decision-v1",
        "qualification_id": challenge["qualification_id"],
        "evidence_digest": evidence_digest,
        "qualified": True,
        "connection_authorized": False,
        "failure_codes": [],
        "verified_at": iso(finished + timedelta(seconds=1)),
    }
    bundle_body: dict[str, object] = {
        "schema_version": "runner-qualification-bundle-v1",
        "challenge": challenge,
        "attestation": attestation,
        "decision": decision,
        "issuer_public_key": b64u(issuer_public),
        "runner_public_key": b64u(runner_public),
    }
    return {**bundle_body, "bundle_digest": content_digest(bundle_body)}


def verifier(bundle: dict[str, object] | None = None) -> RunnerQualificationBundleVerifier:
    resolved = bundle or fixture_bundle()
    attestation = resolved["attestation"]
    assert isinstance(attestation, dict)
    return RunnerQualificationBundleVerifier(
        expected_runner_id=RUNNER_ID,
        expected_repository_id=REPOSITORY_ID,
        expected_repository_commit=REPOSITORY_COMMIT,
        expected_evidence_digest=str(attestation["evidence_digest"]),
        maximum_age=timedelta(hours=24),
    )


def resign_bundle(bundle: dict[str, object]) -> None:
    bundle["bundle_digest"] = content_digest(
        {key: value for key, value in bundle.items() if key != "bundle_digest"}
    )


def test_full_ed25519_qualification_bundle_is_verified() -> None:
    bundle = fixture_bundle()
    verified = verifier(bundle).verify(bundle, now=NOW)

    assert verified.runner_id == RUNNER_ID
    assert verified.repository_id == REPOSITORY_ID
    assert verified.repository_commit == REPOSITORY_COMMIT
    assert verified.repository_tree == REPOSITORY_TREE
    assert verified.qualification_id == "rq_" + "1" * 32
    assert verified.evidence_digest == bundle["attestation"]["evidence_digest"]  # type: ignore[index]
    assert verified.bundle_digest == bundle["bundle_digest"]
    assert verified.issuer_key_id == bundle["challenge"]["issuer_key_id"] # type: ignore[index]
    assert verified.runner_key_id == bundle["challenge"]["key_id"]  # type: ignore[index]
    assert verified.verified_at == ISSUED + timedelta(minutes=2, seconds=1)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda bundle: bundle["attestation"]["observations"][0].__setitem__(  # type: ignore[index,union-attr]
                "evidence_digest", "f" * 64
            ),
            "attestation|evidence|signature",
        ),
        (
            lambda bundle: bundle.__setitem__(
                "issuer_public_key", b64u(bytes([7]) * 32)
            ),
            "issuer.*key|fingerprint",
        ),
        (
            lambda bundle: bundle.__setitem__(
                "runner_public_key", b64u(bytes([8]) * 32)
            ),
            "runner.*key|fingerprint",
        ),
        (
            lambda bundle: bundle["decision"].__setitem__("qualified", False),  # type: ignore[union-attr]
            "decision|qualified",
        ),
        (
            lambda bundle: bundle["attestation"].__setitem__(  # type: ignore[union-attr]
                "cleanup_verified", False
            ),
            "cleanup|attestation|evidence|signature",
        ),
    ],
)
def test_tampered_or_self_signed_qualification_bundle_fails_closed(
    mutate,
    message: str,
) -> None:
    bundle = fixture_bundle()
    mutate(bundle)
    resign_bundle(bundle)

    with pytest.raises(ExecutorUnavailableError, match=message):
        verifier(bundle).verify(bundle, now=NOW)


def test_wrong_repository_binding_and_stale_evidence_fail_closed() -> None:
    bundle = fixture_bundle()
    attestation = bundle["attestation"]
    assert isinstance(attestation, dict)
    wrong_repository = RunnerQualificationBundleVerifier(
        expected_runner_id=RUNNER_ID,
        expected_repository_id=REPOSITORY_ID,
        expected_repository_commit="f" * 40,
        expected_evidence_digest=str(attestation["evidence_digest"]),
        maximum_age=timedelta(hours=24),
    )
    with pytest.raises(ExecutorUnavailableError, match="repository.*commit|binding"):
        wrong_repository.verify(bundle, now=NOW)

    with pytest.raises(ExecutorUnavailableError, match="stale|expired"):
        verifier(bundle).verify(bundle, now=NOW + timedelta(days=2))


def test_unknown_fields_and_wrong_pinned_evidence_digest_fail_closed() -> None:
    bundle = fixture_bundle()
    bundle["unexpected"] = True
    resign_bundle(bundle)
    with pytest.raises(ExecutorUnavailableError, match="fields|schema"):
        verifier(bundle).verify(bundle, now=NOW)

    clean = fixture_bundle()
    wrong_digest = RunnerQualificationBundleVerifier(
        expected_runner_id=RUNNER_ID,
        expected_repository_id=REPOSITORY_ID,
        expected_repository_commit=REPOSITORY_COMMIT,
        expected_evidence_digest="f" * 64,
        maximum_age=timedelta(hours=24),
    )
    with pytest.raises(ExecutorUnavailableError, match="evidence digest|pinned"):
        wrong_digest.verify(clean, now=NOW)
