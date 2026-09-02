from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from liltweak.cloudflare_runner_qualification import (
    CloudflareRunnerPollObservation,
    CloudflareRunnerPollRequest,
    CloudflareRunnerQualificationError,
    CloudflareRunnerQualificationVerifier,
)
from liltweak.creator_contract import content_digest
from liltweak.private_runner_activation import GALOR_TWEAK_PROFILE_SPEC_DIGEST
from liltweak.runner_qualification import (
    LocalRunnerConnectionAuthorization,
    LocalRunnerConnectionDecision,
    LocalRunnerExecutionBindings,
    RunnerQualificationDecision,
    SignedRunnerQualificationAttestation,
    runner_key_id,
)

NOW = datetime(2026, 9, 1, 20, 0, tzinfo=UTC)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _qualification_metadata(runner_key: Ed25519PrivateKey):
    public = runner_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    attestation = SignedRunnerQualificationAttestation.model_construct(
        qualification_id="rq_" + "1" * 32,
        challenge_digest="2" * 64,
        runner_id="galor-tweak-runner-01",
        key_id=runner_key_id(public),
        nonce="3" * 64,
        suite_digest="4" * 64,
        repository_id="github:islamismylifebey-web/lil-tweak",
        repository_commit="f" * 40,
        repository_tree="e" * 40,
        image_ref="ghcr.io/galor/liltweak-runner@sha256:" + "5" * 64,
        sandbox_profile_digest="6" * 64,
        runtime_sha256="7" * 64,
        limiter_sha256="8" * 64,
        qualifier_sha256="9" * 64,
        destroyer_sha256="a" * 64,
        boot_id_digest="b" * 64,
        session_id="session-001",
        started_at=NOW - timedelta(seconds=10),
        finished_at=NOW - timedelta(seconds=5),
        observations=(),
        cleanup_verified=True,
        raw_output_retained=False,
        evidence_digest="c" * 64,
        signature="A" * 86,
    )
    decision = RunnerQualificationDecision(
        qualification_id=attestation.qualification_id,
        evidence_digest=attestation.evidence_digest,
        qualified=True,
        connection_authorized=False,
        failure_codes=(),
        verified_at=NOW - timedelta(seconds=4),
    )
    return decision, attestation


def _local_metadata(qualification: RunnerQualificationDecision):
    bindings = LocalRunnerExecutionBindings(
        repository_id="github:islamismylifebey-web/lil-tweak",
        repository_commit="f" * 40,
        repository_tree="e" * 40,
        source_snapshot_digest="d" * 64,
        task_id="task:private-runner-activation",
        plan_digest="e" * 64,
        execution_attempt=1,
        sandbox_profile_digest="6" * 64,
        resource_profile_digest=GALOR_TWEAK_PROFILE_SPEC_DIGEST,
    )
    authorization = LocalRunnerConnectionAuthorization.model_construct(
        authorization_id="lra_" + "1" * 32,
        owner_key_id="2" * 64,
        provider_id="galor-tweak-runner-01",
        report_digest="3" * 64,
        qualification_id=qualification.qualification_id,
        qualification_evidence_digest=qualification.evidence_digest,
        bindings=bindings,
        bindings_digest=bindings.bindings_digest,
        nonce="4" * 64,
        generation=5,
        issued_at=NOW - timedelta(seconds=20),
        expires_at=NOW + timedelta(minutes=4),
        authorization_digest="5" * 64,
        signature="A" * 86,
    )
    decision = LocalRunnerConnectionDecision.model_construct(
        provider_id="galor-tweak-runner-01",
        report_digest=authorization.report_digest,
        host_qualified=True,
        qualification_verified=True,
        authorization_verified=True,
        connection_authorized=True,
        authorization_id=authorization.authorization_id,
        authorization_digest=authorization.authorization_digest,
        failure_codes=(),
        verified_at=NOW - timedelta(seconds=3),
        decision_digest="6" * 64,
    )
    return decision, authorization


class QualificationSource:
    def __init__(self, decision, attestation) -> None:
        self.decision = decision
        self.attestation = attestation

    def verify(self, *, now: datetime):
        return self.decision, self.attestation


class LocalSource:
    def __init__(self, decision, authorization) -> None:
        self.decision = decision
        self.authorization = authorization

    def verify(self, *, qualification, now: datetime):
        return self.decision, self.authorization


def _poll_observation(
    runner_key: Ed25519PrivateKey,
    *,
    issued_at: datetime = NOW - timedelta(seconds=2),
    observed_at: datetime = NOW - timedelta(seconds=1),
) -> CloudflareRunnerPollObservation:
    request = {
        "schema_version": "lil-tweak.runner-request/v1",
        "runner_id": "galor-tweak-runner-01",
        "operation": "poll",
        "request_nonce": _b64(b"N" * 32),
        "issued_at_ms": int(issued_at.timestamp() * 1_000),
        "payload": {},
    }
    message = (
        "lil-tweak.runner-request/poll/v1\n"
        + __import__("json").dumps(
            request, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
    ).encode()
    values = {
        "endpoint": "https://runner-control.liltweak.galorweb.works",
        "request": CloudflareRunnerPollRequest(**request),
        "signature": _b64(runner_key.sign(message)),
        "worker_response_status": 404,
        "worker_response_digest": hashlib.sha256(b'{"error":"no offer"}').hexdigest(),
        "observed_at": observed_at,
        "nonce_consumed": True,
    }
    draft = CloudflareRunnerPollObservation.model_construct(**values, observation_digest="0" * 64)
    return CloudflareRunnerPollObservation(
        **values,
        observation_digest=content_digest(
            draft.model_dump(mode="json", exclude={"observation_digest"})
        ),
    )


def _verifier(runner_key: Ed25519PrivateKey, **changes: object):
    qualification, attestation = _qualification_metadata(runner_key)
    local, authorization = _local_metadata(qualification)
    values = {
        "qualification_source": QualificationSource(qualification, attestation),
        "local_source": LocalSource(local, authorization),
        "poll_observation": _poll_observation(runner_key),
        "runner_public_key": runner_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ),
        "clock": lambda: NOW,
    }
    values.update(changes)
    return CloudflareRunnerQualificationVerifier(**values)


@pytest.mark.asyncio
async def test_derives_fresh_cloudflare_proof_without_galor_hub_fields() -> None:
    runner_key = Ed25519PrivateKey.generate()
    proof = await _verifier(runner_key).refresh()

    assert proof.runner_id == "galor-tweak-runner-01"
    assert proof.repository_commit == "f" * 40
    assert proof.qualification_evidence_digest == "c" * 64
    assert proof.authorization_sequence == 5
    assert proof.profile_spec_digest == GALOR_TWEAK_PROFILE_SPEC_DIGEST
    assert proof.cloudflare_poll_observation_digest
    assert proof.is_fresh(NOW)
    assert not hasattr(proof, "hub_commit")
    assert not hasattr(proof, "heartbeat_job_id")


@pytest.mark.asyncio
async def test_rejects_forged_or_stale_runner_poll() -> None:
    runner_key = Ed25519PrivateKey.generate()
    wrong_key = Ed25519PrivateKey.generate()
    with pytest.raises(CloudflareRunnerQualificationError, match="signature"):
        await _verifier(
            runner_key,
            poll_observation=_poll_observation(wrong_key),
        ).refresh()
    with pytest.raises(CloudflareRunnerQualificationError, match="stale"):
        await _verifier(
            runner_key,
            poll_observation=_poll_observation(
                runner_key,
                issued_at=NOW - timedelta(minutes=2),
                observed_at=NOW - timedelta(minutes=2),
            ),
        ).refresh()


@pytest.mark.asyncio
async def test_rejects_unqualified_or_unbound_host_decisions() -> None:
    runner_key = Ed25519PrivateKey.generate()
    qualification, attestation = _qualification_metadata(runner_key)
    failed = qualification.model_copy(
        update={"qualified": False, "failure_codes": ("check_failed",)}
    )
    with pytest.raises(CloudflareRunnerQualificationError, match="qualification"):
        await _verifier(
            runner_key,
            qualification_source=QualificationSource(failed, attestation),
        ).refresh()

    local, authorization = _local_metadata(qualification)
    wrong_profile = authorization.bindings.model_copy(update={"resource_profile_digest": "0" * 64})
    wrong_authorization = authorization.model_copy(
        update={"bindings": wrong_profile, "bindings_digest": wrong_profile.bindings_digest}
    )
    with pytest.raises(CloudflareRunnerQualificationError, match="profile"):
        await _verifier(
            runner_key,
            local_source=LocalSource(local, wrong_authorization),
        ).refresh()
