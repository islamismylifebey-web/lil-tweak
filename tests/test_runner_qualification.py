from __future__ import annotations

import base64
import hashlib
import subprocess
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from liltweak.creator_contract import content_digest
from liltweak.runner_qualification import (
    LOCAL_RUNNER_PROBE_GATES,
    QUALIFICATION_SUITE_DIGEST,
    REQUIRED_QUALIFICATION_CHECKS,
    LocalCommandProbeObservation,
    LocalExecutableObservation,
    LocalKernelObservation,
    LocalRunnerCapabilityReport,
    LocalRunnerConnectionAuthorization,
    LocalRunnerExecutionBindings,
    LocalRunnerProbeExpectations,
    LocalRunnerQualificationProbe,
    LocalRuntimeRootObservation,
    QualificationObservation,
    RunnerQualificationChallenge,
    RunnerQualificationDecision,
    RunnerQualificationExpectations,
    RunnerQualificationVerifier,
    SignedRunnerQualificationAttestation,
    build_runner_qualification_challenge,
    encode_runner_signature,
    local_runner_authorization_signature_message,
    runner_key_id,
    runner_qualification_challenge_signature_message,
    runner_qualification_signature_message,
)

NOW = datetime(2026, 7, 29, 18, 0, tzinfo=UTC)
RUNNER_ID = "runner-phase71"
REPOSITORY_ID = "github:islamismylifebey-web/lil-tweak"
IMAGE = "registry.invalid/liltweak-python@sha256:" + ("a" * 64)
COMMIT = "c" * 40
TREE = "d" * 40
PROFILE = "e" * 64
RUNTIME = "f" * 64
LIMITER = "1" * 64
QUALIFIER = "2" * 64
DESTROYER = "6" * 64
DIGEST = "b" * 64

EXPECTED_QUALIFICATION_CHECKS = (
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


def public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def issuer_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def runner_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))


def challenge(
    issuer_key: Ed25519PrivateKey,
    runner_key: Ed25519PrivateKey,
) -> RunnerQualificationChallenge:
    return build_runner_qualification_challenge(
        runner_id=RUNNER_ID,
        key_id=runner_key_id(public_bytes(runner_key)),
        repository_id=REPOSITORY_ID,
        repository_commit=COMMIT,
        repository_tree=TREE,
        image_ref=IMAGE,
        sandbox_profile_digest=PROFILE,
        runtime_sha256=RUNTIME,
        limiter_sha256=LIMITER,
        qualifier_sha256=QUALIFIER,
        destroyer_sha256=DESTROYER,
        issuer_private_key=issuer_key,
        issued_at=NOW,
        lifetime_seconds=600,
        qualification_id="rq_" + ("3" * 32),
        nonce="4" * 64,
    )


def observations(
    *,
    failed_check: str | None = None,
) -> tuple[QualificationObservation, ...]:
    return tuple(
        QualificationObservation(
            check_id=check_id,
            passed=check_id != failed_check,
            evidence_digest=content_digest({"check_id": check_id, "fixture": True}),
            duration_ms=10,
            failure_code="fixture_failure" if check_id == failed_check else None,
        )
        for check_id in REQUIRED_QUALIFICATION_CHECKS
    )


def attestation(
    runner_key: Ed25519PrivateKey,
    bound_challenge: RunnerQualificationChallenge,
    *,
    failed_check: str | None = None,
    cleanup_verified: bool = True,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    overrides: dict[str, object] | None = None,
) -> SignedRunnerQualificationAttestation:
    values: dict[str, object] = {
        "qualification_id": bound_challenge.qualification_id,
        "challenge_digest": bound_challenge.challenge_digest,
        "runner_id": bound_challenge.runner_id,
        "key_id": bound_challenge.key_id,
        "nonce": bound_challenge.nonce,
        "suite_digest": QUALIFICATION_SUITE_DIGEST,
        "repository_id": bound_challenge.repository_id,
        "repository_commit": bound_challenge.repository_commit,
        "repository_tree": bound_challenge.repository_tree,
        "image_ref": bound_challenge.image_ref,
        "sandbox_profile_digest": bound_challenge.sandbox_profile_digest,
        "runtime_sha256": bound_challenge.runtime_sha256,
        "limiter_sha256": bound_challenge.limiter_sha256,
        "qualifier_sha256": bound_challenge.qualifier_sha256,
        "destroyer_sha256": bound_challenge.destroyer_sha256,
        "boot_id_digest": "5" * 64,
        "session_id": "session-phase71",
        "started_at": started_at or NOW + timedelta(seconds=1),
        "finished_at": finished_at or NOW + timedelta(seconds=30),
        "observations": observations(failed_check=failed_check),
        "cleanup_verified": cleanup_verified,
    }
    values.update(overrides or {})
    draft = SignedRunnerQualificationAttestation.model_construct(
        **values,
        evidence_digest="0" * 64,
        signature="A" * 86,
    )
    evidence_digest = content_digest(
        draft.model_dump(
            mode="json",
            exclude={"evidence_digest", "signature"},
        )
    )
    unsigned = SignedRunnerQualificationAttestation.model_construct(
        **values,
        evidence_digest=evidence_digest,
        signature="A" * 86,
    )
    signature = encode_runner_signature(
        runner_key.sign(runner_qualification_signature_message(unsigned))
    )
    return SignedRunnerQualificationAttestation(
        **values,
        evidence_digest=evidence_digest,
        signature=signature,
    )


def expectations(
    **overrides: object,
) -> RunnerQualificationExpectations:
    values: dict[str, object] = {
        "runner_id": RUNNER_ID,
        "repository_id": REPOSITORY_ID,
        "repository_commit": COMMIT,
        "repository_tree": TREE,
        "image_ref": IMAGE,
        "sandbox_profile_digest": PROFILE,
        "runtime_sha256": RUNTIME,
        "limiter_sha256": LIMITER,
        "qualifier_sha256": QUALIFIER,
        "destroyer_sha256": DESTROYER,
    }
    values.update(overrides)
    return RunnerQualificationExpectations.model_validate(values)


def verifier(
    issuer_key: Ed25519PrivateKey,
    runner_key: Ed25519PrivateKey,
    *,
    expected: RunnerQualificationExpectations | None = None,
) -> RunnerQualificationVerifier:
    expected = expected or expectations()
    issuer_public_key = public_bytes(issuer_key)
    runner_public_key = public_bytes(runner_key)
    return RunnerQualificationVerifier(
        expectations=expected,
        trusted_issuer_public_keys={
            runner_key_id(issuer_public_key): issuer_public_key,
        },
        trusted_runner_public_keys={
            RUNNER_ID: runner_public_key,
            expected.runner_id: runner_public_key,
        },
    )


def test_required_qualification_suite_is_the_exact_47_check_contract() -> None:
    assert len(REQUIRED_QUALIFICATION_CHECKS) == 47
    assert REQUIRED_QUALIFICATION_CHECKS == EXPECTED_QUALIFICATION_CHECKS
    assert len(set(REQUIRED_QUALIFICATION_CHECKS)) == 47
    assert (
        content_digest(
            {
                "schema_version": "runner-qualification-suite-v1",
                "checks": EXPECTED_QUALIFICATION_CHECKS,
            }
        )
        == QUALIFICATION_SUITE_DIGEST
    )


def test_separate_issuer_and_runner_keys_qualify_but_never_connect() -> None:
    issuer_key = issuer_private_key()
    runner_key = runner_private_key()
    issued = challenge(issuer_key, runner_key)
    report = attestation(runner_key, issued)

    assert issued.issuer_key_id == runner_key_id(public_bytes(issuer_key))
    assert issued.key_id == runner_key_id(public_bytes(runner_key))
    assert issued.issuer_key_id != issued.key_id

    decision = verifier(issuer_key, runner_key).verify(
        challenge=issued,
        attestation=report,
        now=NOW + timedelta(seconds=31),
    )

    assert decision.qualified is True
    assert decision.failure_codes == ()
    assert decision.connection_authorized is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("runner_id", "runner-other"),
        ("repository_id", "github:other/repository"),
        ("repository_commit", "7" * 40),
        ("repository_tree", "8" * 40),
        ("image_ref", "registry.invalid/other@sha256:" + ("9" * 64)),
        ("sandbox_profile_digest", "9" * 64),
        ("runtime_sha256", "9" * 64),
        ("limiter_sha256", "9" * 64),
        ("qualifier_sha256", "9" * 64),
        ("destroyer_sha256", "9" * 64),
    ],
)
def test_challenge_must_match_independently_pinned_expectations(
    field: str,
    value: object,
) -> None:
    issuer_key = issuer_private_key()
    runner_key = runner_private_key()
    issued = challenge(issuer_key, runner_key)
    report = attestation(runner_key, issued)
    expected = expectations(**{field: value})

    decision = verifier(
        issuer_key,
        runner_key,
        expected=expected,
    ).verify(
        challenge=issued,
        attestation=report,
        now=NOW + timedelta(seconds=31),
    )

    assert decision.qualified is False
    assert f"unexpected_{field}" in decision.failure_codes
    assert decision.connection_authorized is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("runner_id", "other-runner"),
        ("nonce", "6" * 64),
        ("repository_id", "github:other/repository"),
        ("repository_commit", "7" * 40),
        ("repository_tree", "8" * 40),
        ("image_ref", "registry.invalid/other@sha256:" + ("9" * 64)),
        ("sandbox_profile_digest", "9" * 64),
        ("runtime_sha256", "9" * 64),
        ("limiter_sha256", "9" * 64),
        ("qualifier_sha256", "9" * 64),
        ("destroyer_sha256", "9" * 64),
    ],
)
def test_runner_signature_cannot_override_challenge_bindings(
    field: str,
    value: object,
) -> None:
    issuer_key = issuer_private_key()
    runner_key = runner_private_key()
    issued = challenge(issuer_key, runner_key)
    report = attestation(runner_key, issued, overrides={field: value})

    decision = verifier(issuer_key, runner_key).verify(
        challenge=issued,
        attestation=report,
        now=NOW + timedelta(seconds=31),
    )

    assert decision.qualified is False
    assert f"{field}_mismatch" in decision.failure_codes
    assert decision.connection_authorized is False


def test_tampered_challenge_issuer_signature_fails_closed() -> None:
    issuer_key = issuer_private_key()
    runner_key = runner_private_key()
    issued = challenge(issuer_key, runner_key)
    signature = base64.urlsafe_b64decode(issued.issuer_signature + "==")
    tampered = issued.model_copy(
        update={
            "issuer_signature": encode_runner_signature(bytes([signature[0] ^ 1]) + signature[1:])
        }
    )

    decision = verifier(issuer_key, runner_key).verify(
        challenge=tampered,
        attestation=attestation(runner_key, issued),
        now=NOW + timedelta(seconds=31),
    )

    assert decision.qualified is False
    assert "challenge_signature_invalid" in decision.failure_codes
    assert decision.connection_authorized is False


def test_untrusted_challenge_issuer_fails_closed() -> None:
    untrusted_issuer = issuer_private_key()
    trusted_issuer = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
    runner_key = runner_private_key()
    issued = challenge(untrusted_issuer, runner_key)

    decision = verifier(trusted_issuer, runner_key).verify(
        challenge=issued,
        attestation=attestation(runner_key, issued),
        now=NOW + timedelta(seconds=31),
    )

    assert decision.qualified is False
    assert "untrusted_challenge_issuer" in decision.failure_codes
    assert decision.connection_authorized is False


def test_tampered_runner_signature_fails_closed() -> None:
    issuer_key = issuer_private_key()
    runner_key = runner_private_key()
    issued = challenge(issuer_key, runner_key)
    report = attestation(runner_key, issued)
    signature = base64.urlsafe_b64decode(report.signature + "==")
    tampered = report.model_copy(
        update={"signature": encode_runner_signature(bytes([signature[0] ^ 1]) + signature[1:])}
    )

    decision = verifier(issuer_key, runner_key).verify(
        challenge=issued,
        attestation=tampered,
        now=NOW + timedelta(seconds=31),
    )

    assert decision.qualified is False
    assert "runner_signature_invalid" in decision.failure_codes
    assert decision.connection_authorized is False


def test_wrong_runner_key_fails_closed() -> None:
    issuer_key = issuer_private_key()
    runner_key = runner_private_key()
    other_runner_key = Ed25519PrivateKey.from_private_bytes(b"\xff" * 32)
    issued = challenge(issuer_key, runner_key)

    decision = verifier(issuer_key, other_runner_key).verify(
        challenge=issued,
        attestation=attestation(runner_key, issued),
        now=NOW + timedelta(seconds=31),
    )

    assert decision.qualified is False
    assert "untrusted_runner_key" in decision.failure_codes
    assert decision.connection_authorized is False


def test_verifier_revalidates_model_construct_with_zero_observations() -> None:
    issuer_key = issuer_private_key()
    runner_key = runner_private_key()
    issued = challenge(issuer_key, runner_key)
    payload = attestation(runner_key, issued).model_dump(mode="python")
    payload["observations"] = ()
    bypassed = SignedRunnerQualificationAttestation.model_construct(**payload)

    with pytest.raises(ValidationError, match=r"at least 47 items|not exact and ordered"):
        verifier(issuer_key, runner_key).verify(
            challenge=issued,
            attestation=bypassed,
            now=NOW + timedelta(seconds=31),
        )


def test_verifier_revalidates_model_construct_challenge_digest() -> None:
    issuer_key = issuer_private_key()
    runner_key = runner_private_key()
    issued = challenge(issuer_key, runner_key)
    payload = issued.model_dump(mode="python")
    payload["repository_id"] = "github:tampered/repository"
    bypassed = RunnerQualificationChallenge.model_construct(**payload)

    with pytest.raises(ValidationError, match="challenge digest mismatch"):
        verifier(issuer_key, runner_key).verify(
            challenge=bypassed,
            attestation=attestation(runner_key, issued),
            now=NOW + timedelta(seconds=31),
        )


def test_signature_message_domains_have_stable_nul_separated_sha_vectors() -> None:
    issuer_key = issuer_private_key()
    runner_key = runner_private_key()
    issued = challenge(issuer_key, runner_key)
    report = attestation(runner_key, issued)
    challenge_message = runner_qualification_challenge_signature_message(issued)
    attestation_message = runner_qualification_signature_message(report)

    assert challenge_message.startswith(b"liltweak:runner-qualification-challenge:v1\0{")
    assert attestation_message.startswith(b"liltweak:runner-qualification:v1\0{")
    assert hashlib.sha256(challenge_message).hexdigest() == (
        "c4424982e4bb0067634ab82f8fcc525f046097093d5213a0b52970b8f753dd58"
    )
    assert hashlib.sha256(attestation_message).hexdigest() == (
        "aa0795b94dc991145e40966544df3d6d3e7fd37f971bee490bd4f0e013e263dd"
    )


def test_expired_or_future_evidence_fails_closed() -> None:
    issuer_key = issuer_private_key()
    runner_key = runner_private_key()
    issued = challenge(issuer_key, runner_key)
    report = attestation(runner_key, issued)

    expired = verifier(issuer_key, runner_key).verify(
        challenge=issued,
        attestation=report,
        now=issued.expires_at + timedelta(seconds=1),
    )
    future_report = attestation(
        runner_key,
        issued,
        started_at=NOW + timedelta(seconds=100),
        finished_at=NOW + timedelta(seconds=110),
    )
    future = verifier(issuer_key, runner_key).verify(
        challenge=issued,
        attestation=future_report,
        now=NOW + timedelta(seconds=50),
    )

    assert "challenge_expired" in expired.failure_codes
    assert "attestation_from_future" in future.failure_codes
    assert expired.connection_authorized is future.connection_authorized is False


@pytest.mark.parametrize(
    "failed_check",
    [
        "network.ipv4_egress_denied",
        "isolation.host_pid_namespace_absent",
        "filesystem.control_plane_state_absent",
        "resource.memory_hard_limit",
        "control.live_cancel_kills_cgroup",
        "cleanup.workspace_destroyed",
    ],
)
def test_any_required_failure_forces_unqualified(failed_check: str) -> None:
    issuer_key = issuer_private_key()
    runner_key = runner_private_key()
    issued = challenge(issuer_key, runner_key)
    report = attestation(runner_key, issued, failed_check=failed_check)

    decision = verifier(issuer_key, runner_key).verify(
        challenge=issued,
        attestation=report,
        now=NOW + timedelta(seconds=31),
    )

    assert decision.qualified is False
    assert f"check_failed:{failed_check}" in decision.failure_codes
    assert decision.connection_authorized is False


def test_cleanup_summary_cannot_contradict_passing_observations() -> None:
    issuer_key = issuer_private_key()
    runner_key = runner_private_key()
    issued = challenge(issuer_key, runner_key)
    report = attestation(runner_key, issued, cleanup_verified=False)

    decision = verifier(issuer_key, runner_key).verify(
        challenge=issued,
        attestation=report,
        now=NOW + timedelta(seconds=31),
    )

    assert decision.qualified is False
    assert "cleanup_unverified" in decision.failure_codes


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "reordered"])
def test_observation_set_must_be_exact_unique_and_ordered(mutation: str) -> None:
    issuer_key = issuer_private_key()
    runner_key = runner_private_key()
    issued = challenge(issuer_key, runner_key)
    payload = attestation(runner_key, issued).model_dump(mode="json")
    observed = payload["observations"]
    if mutation == "missing":
        payload["observations"] = observed[:-1]
    elif mutation == "duplicate":
        payload["observations"] = [*observed[:-1], observed[0]]
    else:
        payload["observations"] = [observed[1], observed[0], *observed[2:]]

    with pytest.raises(ValidationError, match=r"at least 47 items|not exact and ordered"):
        SignedRunnerQualificationAttestation.model_validate(payload)


def test_models_reject_digest_tampering_and_extra_fields() -> None:
    issuer_key = issuer_private_key()
    runner_key = runner_private_key()
    issued = challenge(issuer_key, runner_key)
    challenge_payload = issued.model_dump(mode="json")
    challenge_payload["challenge_digest"] = DIGEST
    with pytest.raises(ValidationError, match="challenge digest mismatch"):
        RunnerQualificationChallenge.model_validate(challenge_payload)

    report_payload = attestation(runner_key, issued).model_dump(mode="json")
    report_payload["evidence_digest"] = DIGEST
    with pytest.raises(ValidationError, match="evidence digest mismatch"):
        SignedRunnerQualificationAttestation.model_validate(report_payload)

    extra_payload = issued.model_dump(mode="json")
    extra_payload["execution_connected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RunnerQualificationChallenge.model_validate(extra_payload)


def test_naive_times_and_long_lifetimes_are_rejected() -> None:
    issuer_key = issuer_private_key()
    runner_key = runner_private_key()
    kwargs = {
        "runner_id": RUNNER_ID,
        "key_id": runner_key_id(public_bytes(runner_key)),
        "repository_id": REPOSITORY_ID,
        "repository_commit": COMMIT,
        "repository_tree": TREE,
        "image_ref": IMAGE,
        "sandbox_profile_digest": PROFILE,
        "runtime_sha256": RUNTIME,
        "limiter_sha256": LIMITER,
        "qualifier_sha256": QUALIFIER,
        "destroyer_sha256": DESTROYER,
        "issuer_private_key": issuer_key,
    }
    with pytest.raises(ValidationError, match="timezone-aware"):
        build_runner_qualification_challenge(
            **kwargs,
            issued_at=NOW.replace(tzinfo=None),
        )
    with pytest.raises(ValueError, match="lifetime is invalid"):
        build_runner_qualification_challenge(
            **kwargs,
            issued_at=NOW,
            lifetime_seconds=601,
        )


def local_bindings() -> LocalRunnerExecutionBindings:
    return LocalRunnerExecutionBindings(
        repository_id=REPOSITORY_ID,
        repository_commit=COMMIT,
        repository_tree=TREE,
        source_snapshot_digest="7" * 64,
        task_id="task:local-runner",
        plan_digest="8" * 64,
        execution_attempt=1,
        sandbox_profile_digest=PROFILE,
        resource_profile_digest="9" * 64,
    )


def passing_local_report(
    probe: LocalRunnerQualificationProbe,
) -> LocalRunnerCapabilityReport:
    executables = tuple(
        LocalExecutableObservation(
            role=role,
            path=f"/trusted/{role}",
            present=True,
            trusted=True,
            sha256=str(index) * 64,
            expected_sha256=str(index) * 64,
            version="trusted 1.0" if role in {"runtime", "limiter"} else None,
            version_probe="passed" if role in {"runtime", "limiter"} else "not_run",
            version_output_digest=(str(index + 4) * 64 if role in {"runtime", "limiter"} else None),
        )
        for index, role in enumerate(("runtime", "limiter", "qualifier", "destroyer"), 1)
    )
    runtime_root = LocalRuntimeRootObservation(
        path="/trusted/rootfs",
        present=True,
        trusted=True,
        manifest_path="/trusted/rootfs/.liltweak-rootfs-manifest.json",
        manifest_sha256="5" * 64,
        expected_manifest_sha256="5" * 64,
    )
    kernel = LocalKernelObservation(
        system="Linux",
        no_new_privileges=True,
        seccomp_mode=2,
        cap_sys_admin_effective=False,
        cgroup_v2_present=True,
        cgroup_v2_delegated=True,
    )
    namespace_probe = LocalCommandProbeObservation(
        command_digest="6" * 64,
        exit_code=0,
        timed_out=False,
        stdout_digest="7" * 64,
        stderr_digest=hashlib.sha256(b"").hexdigest(),
        stdout_bytes=5,
        stderr_bytes=0,
        result_code="passed",
    )
    gates = tuple(probe._gate(gate_id, True, "unused") for gate_id in LOCAL_RUNNER_PROBE_GATES)
    values = {
        "provider_id": probe.expectations.provider_id,
        "expectations_digest": content_digest(probe.expectations.model_dump(mode="json")),
        "executables": executables,
        "runtime_root": runtime_root,
        "kernel": kernel,
        "namespace_probe": namespace_probe,
        "gates": gates,
        "blockers": (),
        "host_qualified": True,
    }
    draft = LocalRunnerCapabilityReport.model_construct(**values, report_digest="0" * 64)
    return LocalRunnerCapabilityReport(
        **values,
        report_digest=content_digest(draft.model_dump(mode="json", exclude={"report_digest"})),
    )


def signed_local_authorization(
    *,
    owner_key: Ed25519PrivateKey,
    report: LocalRunnerCapabilityReport,
    qualification: RunnerQualificationDecision,
    bindings: LocalRunnerExecutionBindings,
) -> LocalRunnerConnectionAuthorization:
    owner_public = public_bytes(owner_key)
    values = {
        "authorization_id": "lra_" + ("a" * 32),
        "owner_key_id": runner_key_id(owner_public),
        "provider_id": report.provider_id,
        "report_digest": report.report_digest,
        "qualification_id": qualification.qualification_id,
        "qualification_evidence_digest": qualification.evidence_digest,
        "bindings": bindings,
        "bindings_digest": bindings.bindings_digest,
        "nonce": "b" * 64,
        "generation": 1,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
    }
    draft = LocalRunnerConnectionAuthorization.model_construct(
        **values,
        authorization_digest="0" * 64,
        signature="A" * 86,
    )
    digest = content_digest(
        draft.model_dump(
            mode="json",
            exclude={"authorization_digest", "signature"},
        )
    )
    unsigned = LocalRunnerConnectionAuthorization.model_construct(
        **values,
        authorization_digest=digest,
        signature="A" * 86,
    )
    return LocalRunnerConnectionAuthorization(
        **values,
        authorization_digest=digest,
        signature=encode_runner_signature(
            owner_key.sign(local_runner_authorization_signature_message(unsigned))
        ),
    )


def test_local_probe_report_is_deterministic_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = "/definitely-missing-liltweak-runner"
    expectations = LocalRunnerProbeExpectations(
        provider_id="bubblewrap-local-v1",
        runtime_path=f"{missing}/bwrap",
        limiter_path=f"{missing}/prlimit",
        qualifier_path=f"{missing}/collect",
        destroyer_path=f"{missing}/destroy",
        runtime_root=f"{missing}/rootfs",
        runtime_sha256="1" * 64,
        limiter_sha256="2" * 64,
        qualifier_sha256="3" * 64,
        destroyer_sha256="4" * 64,
        runtime_manifest_sha256="5" * 64,
    )
    probe = LocalRunnerQualificationProbe(expectations)
    kernel = LocalKernelObservation(
        system="Linux",
        no_new_privileges=True,
        seccomp_mode=2,
        cap_sys_admin_effective=False,
        cgroup_v2_present=True,
        cgroup_v2_delegated=False,
    )
    monkeypatch.setattr(probe, "_observe_kernel", lambda: kernel)

    first = probe.collect()
    second = probe.collect()

    assert first == second
    assert first.report_digest == second.report_digest
    assert first.host_qualified is False
    assert first.blockers == (
        "runtime_executable_missing",
        "runtime_sha256_unavailable",
        "runtime_version_probe_not_run",
        "limiter_executable_missing",
        "limiter_sha256_unavailable",
        "limiter_version_probe_not_run",
        "qualifier_executable_missing",
        "qualifier_sha256_unavailable",
        "destroyer_executable_missing",
        "destroyer_sha256_unavailable",
        "runtime_root_missing",
        "runtime_manifest_missing_or_untrusted",
        "cgroup_v2_not_delegated",
        "bubblewrap_namespace_probe_not_run_untrusted",
    )


def test_local_probe_never_qualifies_host_with_effective_cap_sys_admin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expectations = LocalRunnerProbeExpectations(
        provider_id="bubblewrap-local-v1",
        runtime_sha256="1" * 64,
        limiter_sha256="2" * 64,
        qualifier_sha256="3" * 64,
        destroyer_sha256="4" * 64,
        runtime_manifest_sha256="5" * 64,
    )
    probe = LocalRunnerQualificationProbe(expectations)
    role_hashes = {
        "runtime": expectations.runtime_sha256,
        "limiter": expectations.limiter_sha256,
        "qualifier": expectations.qualifier_sha256,
        "destroyer": expectations.destroyer_sha256,
    }

    def passing_executable(role, path, expected_sha256, *, observe_version):
        assert expected_sha256 == role_hashes[role]
        return LocalExecutableObservation(
            role=role,
            path=path,
            present=True,
            trusted=True,
            sha256=expected_sha256,
            expected_sha256=expected_sha256,
            version="trusted 1.0" if observe_version else None,
            version_probe="passed" if observe_version else "not_run",
            version_output_digest="6" * 64 if observe_version else None,
        )

    monkeypatch.setattr(probe, "_observe_executable", passing_executable)
    monkeypatch.setattr(
        probe,
        "_observe_runtime_root",
        lambda: LocalRuntimeRootObservation(
            path=expectations.runtime_root,
            present=True,
            trusted=True,
            manifest_path=(f"{expectations.runtime_root}/{expectations.runtime_manifest_name}"),
            manifest_sha256=expectations.runtime_manifest_sha256,
            expected_manifest_sha256=expectations.runtime_manifest_sha256,
        ),
    )
    monkeypatch.setattr(
        probe,
        "_observe_kernel",
        lambda: LocalKernelObservation(
            system="Linux",
            no_new_privileges=True,
            seccomp_mode=2,
            cap_sys_admin_effective=True,
            cgroup_v2_present=True,
            cgroup_v2_delegated=True,
        ),
    )
    monkeypatch.setattr(
        probe,
        "_namespace_probe",
        lambda _observed: LocalCommandProbeObservation(
            command_digest="7" * 64,
            exit_code=0,
            timed_out=False,
            stdout_digest="8" * 64,
            stderr_digest=hashlib.sha256(b"").hexdigest(),
            stdout_bytes=5,
            stderr_bytes=0,
            result_code="passed",
        ),
    )

    report = probe.collect()

    assert report.host_qualified is False
    assert report.blockers == ("kernel_cap_sys_admin_effective",)
    cap_gate = next(gate for gate in report.gates if gate.gate_id == "kernel.cap_sys_admin_absent")
    assert cap_gate.passed is False
    assert cap_gate.failure_code == "kernel_cap_sys_admin_effective"


def test_local_probe_subprocess_never_uses_a_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    probe = LocalRunnerQualificationProbe(
        LocalRunnerProbeExpectations(provider_id="bubblewrap-local-v1")
    )
    observed: dict[str, object] = {}

    class FakeProcess:
        pid = 12_345
        returncode = 0

        @staticmethod
        def communicate(*, timeout: int) -> tuple[bytes, bytes]:
            observed["timeout"] = timeout
            return b"probe 1.0\n", b""

    def fake_popen(command: tuple[str, ...], **kwargs: object) -> FakeProcess:
        observed["command"] = command
        observed["shell"] = kwargs.get("shell")
        observed["start_new_session"] = kwargs.get("start_new_session")
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    result = probe._run_bounded(("/trusted/probe", "--version"))

    assert observed == {
        "command": ("/trusted/probe", "--version"),
        "shell": False,
        "start_new_session": True,
        "timeout": 3,
    }
    assert result.exit_code == 0
    assert result.timed_out is False


def test_local_connection_requires_all_gates_and_independent_owner_signature() -> None:
    probe = LocalRunnerQualificationProbe(
        LocalRunnerProbeExpectations(provider_id="bubblewrap-local-v1")
    )
    report = passing_local_report(probe)
    qualification = RunnerQualificationDecision(
        qualification_id="rq_" + ("c" * 32),
        evidence_digest="d" * 64,
        qualified=True,
        connection_authorized=False,
        failure_codes=(),
        verified_at=NOW,
    )
    bindings = local_bindings()
    owner_key = Ed25519PrivateKey.from_private_bytes(b"\x44" * 32)
    owner_public = public_bytes(owner_key)
    authorization = signed_local_authorization(
        owner_key=owner_key,
        report=report,
        qualification=qualification,
        bindings=bindings,
    )

    first = probe.decide(
        report=report,
        qualification=qualification,
        authorization=authorization,
        expected_bindings=bindings,
        trusted_owner_public_keys={runner_key_id(owner_public): owner_public},
        now=NOW + timedelta(minutes=1),
    )
    second = probe.decide(
        report=report,
        qualification=qualification,
        authorization=authorization,
        expected_bindings=bindings,
        trusted_owner_public_keys={runner_key_id(owner_public): owner_public},
        now=NOW + timedelta(minutes=1),
    )

    assert first == second
    assert first.connection_authorized is True
    assert first.qualification_verified is True
    assert first.authorization_verified is True
    assert first.failure_codes == ()

    self_authorized = probe.decide(
        report=report,
        qualification=qualification,
        authorization=authorization,
        expected_bindings=bindings,
        trusted_owner_public_keys={runner_key_id(owner_public): owner_public},
        forbidden_owner_key_ids={runner_key_id(owner_public)},
        now=NOW + timedelta(minutes=1),
    )
    assert self_authorized.connection_authorized is False
    assert "candidate_or_runner_self_authorization" in self_authorized.failure_codes

    replayed = probe.decide(
        report=report,
        qualification=qualification,
        authorization=authorization,
        expected_bindings=bindings,
        trusted_owner_public_keys={runner_key_id(owner_public): owner_public},
        used_authorization_ids={authorization.authorization_id},
        now=NOW + timedelta(minutes=1),
    )
    assert replayed.connection_authorized is False
    assert "authorization_replayed" in replayed.failure_codes


def test_real_local_probe_cannot_connect_without_external_evidence() -> None:
    probe = LocalRunnerQualificationProbe(
        LocalRunnerProbeExpectations(provider_id="bubblewrap-local-v1")
    )
    report = probe.collect()
    decision = probe.decide(
        report=report,
        qualification=None,
        authorization=None,
        expected_bindings=local_bindings(),
        trusted_owner_public_keys={},
        now=NOW,
    )

    assert decision.connection_authorized is False
    assert "independent_qualification_missing" in decision.failure_codes
    assert "signed_connection_authorization_missing" in decision.failure_codes
    assert report.report_digest
