from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from liltweak.creator_contract import content_digest
from liltweak.runner_evidence import RunnerQualificationBundleVerifier
from liltweak.runner_qualification import (
    QUALIFICATION_SUITE_DIGEST,
    REQUIRED_QUALIFICATION_CHECKS,
    QualificationObservation,
    RunnerQualificationDecision,
    RunnerQualificationExpectations,
    RunnerQualificationVerifier,
    SignedRunnerQualificationAttestation,
    build_runner_qualification_challenge,
    encode_runner_signature,
    runner_key_id,
    runner_qualification_signature_message,
)
from liltweak.workbench_executor import ExecutorUnavailableError

NOW = datetime(2026, 8, 30, 12, 5, tzinfo=UTC)
RUNNER_ID = "galor-private-cloud-01"
REPOSITORY_ID = "github:islamismylifebey-web/lil-tweak"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
TREE = "89abcdef0123456789abcdef0123456789abcdef"
IMAGE = "ghcr.io/galor/liltweak-runner@sha256:" + ("3" * 64)
PROFILE, RUNTIME, LIMITER, QUALIFIER, DESTROYER = ((str(index) * 64) for index in range(4, 9))
ISSUER_SEED = bytes(range(1, 33))
RUNNER_SEED = bytes(range(33, 65))


def public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def build_bundle(
    *, issuer_seed: bytes = ISSUER_SEED, runner_seed: bytes = RUNNER_SEED
) -> tuple[dict[str, object], bytes, bytes]:
    issuer = Ed25519PrivateKey.from_private_bytes(issuer_seed)
    runner = Ed25519PrivateKey.from_private_bytes(runner_seed)
    issuer_public = public_bytes(issuer)
    runner_public = public_bytes(runner)
    challenge = build_runner_qualification_challenge(
        runner_id=RUNNER_ID,
        key_id=runner_key_id(runner_public),
        repository_id=REPOSITORY_ID,
        repository_commit=COMMIT,
        repository_tree=TREE,
        image_ref=IMAGE,
        sandbox_profile_digest=PROFILE,
        runtime_sha256=RUNTIME,
        limiter_sha256=LIMITER,
        qualifier_sha256=QUALIFIER,
        destroyer_sha256=DESTROYER,
        issuer_private_key=issuer,
        issued_at=NOW - timedelta(minutes=5),
        lifetime_seconds=600,
        qualification_id="rq_" + ("1" * 32),
        nonce="2" * 64,
    )
    observations = tuple(
        QualificationObservation(
            check_id=check_id,
            passed=True,
            evidence_digest=content_digest({"check_id": check_id}),
            duration_ms=index + 1,
        )
        for index, check_id in enumerate(REQUIRED_QUALIFICATION_CHECKS)
    )
    values: dict[str, object] = {
        "qualification_id": challenge.qualification_id,
        "challenge_digest": challenge.challenge_digest,
        "runner_id": challenge.runner_id,
        "key_id": challenge.key_id,
        "nonce": challenge.nonce,
        "suite_digest": QUALIFICATION_SUITE_DIGEST,
        "repository_id": challenge.repository_id,
        "repository_commit": challenge.repository_commit,
        "repository_tree": challenge.repository_tree,
        "image_ref": challenge.image_ref,
        "sandbox_profile_digest": challenge.sandbox_profile_digest,
        "runtime_sha256": challenge.runtime_sha256,
        "limiter_sha256": challenge.limiter_sha256,
        "qualifier_sha256": challenge.qualifier_sha256,
        "destroyer_sha256": challenge.destroyer_sha256,
        "boot_id_digest": "9" * 64,
        "session_id": "session:fixture",
        "started_at": NOW - timedelta(minutes=4, seconds=50),
        "finished_at": NOW - timedelta(minutes=3),
        "observations": observations,
        "cleanup_verified": True,
    }
    draft = SignedRunnerQualificationAttestation.model_construct(
        **values, evidence_digest="0" * 64, signature="A" * 86
    )
    evidence_digest = content_digest(
        draft.model_dump(mode="json", exclude={"evidence_digest", "signature"})
    )
    unsigned = SignedRunnerQualificationAttestation.model_construct(
        **values, evidence_digest=evidence_digest, signature="A" * 86
    )
    attestation = SignedRunnerQualificationAttestation(
        **values,
        evidence_digest=evidence_digest,
        signature=encode_runner_signature(
            runner.sign(runner_qualification_signature_message(unsigned))
        ),
    )
    expectations = RunnerQualificationExpectations(
        runner_id=RUNNER_ID,
        repository_id=REPOSITORY_ID,
        repository_commit=COMMIT,
        repository_tree=TREE,
        image_ref=IMAGE,
        sandbox_profile_digest=PROFILE,
        runtime_sha256=RUNTIME,
        limiter_sha256=LIMITER,
        qualifier_sha256=QUALIFIER,
        destroyer_sha256=DESTROYER,
    )
    decision = RunnerQualificationVerifier(
        expectations=expectations,
        trusted_issuer_public_keys={challenge.issuer_key_id: issuer_public},
        trusted_runner_public_keys={RUNNER_ID: runner_public},
    ).verify(
        challenge=challenge,
        attestation=attestation,
        now=NOW - timedelta(minutes=2, seconds=59),
    )
    assert isinstance(decision, RunnerQualificationDecision)
    body = {
        "schema_version": "runner-qualification-bundle-v1",
        "challenge": challenge.model_dump(mode="json"),
        "attestation": attestation.model_dump(mode="json"),
        "decision": decision.model_dump(mode="json"),
        "issuer_public_key": base64.urlsafe_b64encode(issuer_public).decode().rstrip("="),
        "runner_public_key": base64.urlsafe_b64encode(runner_public).decode().rstrip("="),
    }
    return ({**body, "bundle_digest": content_digest(body)}, issuer_public, runner_public)


def verifier(
    bundle: dict[str, object],
    *,
    trusted_issuer: bytes,
    trusted_runner: bytes,
    **overrides: object,
) -> RunnerQualificationBundleVerifier:
    attestation = bundle["attestation"]
    assert isinstance(attestation, dict)
    values: dict[str, object] = {
        "expected_runner_id": RUNNER_ID,
        "expected_repository_id": REPOSITORY_ID,
        "expected_repository_commit": COMMIT,
        "expected_evidence_digest": attestation["evidence_digest"],
        "trusted_issuer_public_keys": {hashlib.sha256(trusted_issuer).hexdigest(): trusted_issuer},
        "trusted_runner_public_keys": {RUNNER_ID: trusted_runner},
        "maximum_age": timedelta(hours=24),
    }
    values.update(overrides)
    return RunnerQualificationBundleVerifier(**values)  # type: ignore[arg-type]


def test_full_ed25519_qualification_bundle_is_verified() -> None:
    bundle, issuer_public, runner_public = build_bundle()
    verified = verifier(bundle, trusted_issuer=issuer_public, trusted_runner=runner_public).verify(
        bundle, now=NOW
    )

    assert verified.runner_id == RUNNER_ID
    assert verified.repository_id == REPOSITORY_ID
    assert verified.repository_commit == COMMIT
    assert verified.repository_tree == TREE
    assert verified.bundle_digest == bundle["bundle_digest"]


def test_self_signed_tampered_stale_or_wrongly_bound_bundle_fails_closed() -> None:
    trusted, issuer_public, runner_public = build_bundle()
    forged, _, _ = build_bundle(issuer_seed=bytes(range(65, 97)), runner_seed=bytes(range(97, 129)))
    with pytest.raises(ExecutorUnavailableError, match=r"untrusted|issuer|runner.*key"):
        verifier(forged, trusted_issuer=issuer_public, trusted_runner=runner_public).verify(
            forged, now=NOW
        )

    tampered, _, _ = build_bundle()
    report = tampered["attestation"]
    assert isinstance(report, dict)
    observations = report["observations"]
    assert isinstance(observations, list)
    observations[0]["evidence_digest"] = "f" * 64
    body = {key: value for key, value in tampered.items() if key != "bundle_digest"}
    tampered["bundle_digest"] = content_digest(body)
    with pytest.raises(ExecutorUnavailableError, match=r"attestation|evidence|signature"):
        verifier(tampered, trusted_issuer=issuer_public, trusted_runner=runner_public).verify(
            tampered, now=NOW
        )

    with pytest.raises(ExecutorUnavailableError, match=r"repository.*commit|binding"):
        verifier(
            trusted,
            trusted_issuer=issuer_public,
            trusted_runner=runner_public,
            expected_repository_commit="f" * 40,
        ).verify(trusted, now=NOW)
    with pytest.raises(ExecutorUnavailableError, match=r"stale|expired"):
        verifier(trusted, trusted_issuer=issuer_public, trusted_runner=runner_public).verify(
            trusted, now=NOW + timedelta(days=2)
        )
