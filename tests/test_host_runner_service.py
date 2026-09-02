from __future__ import annotations

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from liltweak.providers.self_hosted.qualification_manifest import (
    QualificationReadOnlyManifest,
    QualificationSource,
)
from runner.execution import ExecutionResult
from runner.protocol import canonical_json
from runner.service import RunnerService


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _signed_offer() -> tuple[dict[str, object], str, bytes]:
    key = Ed25519PrivateKey.from_private_bytes(b"c" * 32)
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    manifest = QualificationReadOnlyManifest(
        source=QualificationSource(commit_sha="a" * 40, tree_sha="b" * 40),
        timeout_seconds=900,
    )
    payload = {
        "schema_version": "lil-tweak.dispatch-attestation/v1",
        "execution_id": "exec-001",
        "runner_id": "galor-tweak-runner-01",
        "runner_role": "role-tweak-runner",
        "lease_digest": "1" * 64,
        "contract_digest": "2" * 64,
        "commands_digest": manifest.commands_digest,
        "approval_digest": "4" * 64,
        "policy_digest": "5" * 64,
        "attempt_nonce": _b64url(b"a" * 32),
        "issued_at_ms": 1_000_000,
        "expires_at_ms": 1_240_000,
    }
    return (
        {
            "execution_id": "exec-001",
            "status": "OFFERED",
            "expires_at_ms": 1_240_000,
            "attestation": {
                "key_id": hashlib.sha256(public).hexdigest(),
                "attestation": payload,
                "signature": _b64url(key.sign(canonical_json(payload).encode())),
            },
            "manifest": manifest.model_dump(mode="json"),
        },
        hashlib.sha256(public).hexdigest(),
        public,
    )


class _Client:
    def __init__(self, offer: dict[str, object], *, reject_claim: bool = False) -> None:
        self.offer = offer
        self.reject_claim = reject_claim
        self.evidence: dict[str, object] | None = None

    def poll(self) -> dict[str, object]:
        return self.offer

    def claim(self, *, execution_id: str, attempt_nonce: str) -> dict[str, object]:
        if self.reject_claim:
            raise RuntimeError("claim rejected")
        return {"execution_id": execution_id, "status": "CLAIMED"}

    def status(self, *, execution_id: str) -> dict[str, object]:
        return {"execution_id": execution_id, "status": "CLAIMED"}

    def submit_evidence(
        self,
        *,
        execution_id: str,
        attempt_nonce: str,
        evidence: dict[str, object],
    ) -> dict[str, object]:
        self.evidence = evidence
        return {"execution_id": execution_id, "status": "EVIDENCE_RECORDED"}


class _Executor:
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, offer: object, *, cancellation_requested: object) -> ExecutionResult:
        self.calls += 1
        return ExecutionResult(
            outcome="succeeded",
            exit_code=0,
            stdout=b"bounded stdout",
            stderr=b"",
            receipt={"candidate_sha": None, "source_mutated": False},
            started_at_ms=1_011_000,
            finished_at_ms=1_012_000,
        )


def test_service_claims_before_execution_and_returns_only_digest_evidence() -> None:
    offer, key_id, public = _signed_offer()
    client = _Client(offer)
    executor = _Executor()
    service = RunnerService(
        client=client,
        executor=executor,
        controller_key_id=key_id,
        controller_public_key=public,
        clock_ms=lambda: 1_010_000,
    )

    assert service.run_once() is True
    assert executor.calls == 1
    assert client.evidence == {
        "schema_version": "lil-tweak.runner-evidence/v1",
        "outcome": "succeeded",
        "operation_digest": offer["attestation"]["attestation"]["commands_digest"],
        "stdout_digest": hashlib.sha256(b"bounded stdout").hexdigest(),
        "stderr_digest": hashlib.sha256(b"").hexdigest(),
        "receipt_digest": hashlib.sha256(
            canonical_json({"candidate_sha": None, "source_mutated": False}).encode()
        ).hexdigest(),
        "exit_code": 0,
        "started_at_ms": 1_011_000,
        "finished_at_ms": 1_012_000,
    }


def test_service_never_executes_when_atomic_claim_fails() -> None:
    offer, key_id, public = _signed_offer()
    executor = _Executor()
    service = RunnerService(
        client=_Client(offer, reject_claim=True),
        executor=executor,
        controller_key_id=key_id,
        controller_public_key=public,
        clock_ms=lambda: 1_010_000,
    )

    with pytest.raises(RuntimeError, match="claim rejected"):
        service.run_once()
    assert executor.calls == 0
