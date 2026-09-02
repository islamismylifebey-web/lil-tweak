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
from runner.offer import OfferError, verify_offer
from runner.protocol import canonical_json


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _offer(*, mismatch: bool = False) -> tuple[dict[str, object], str, bytes]:
    controller_key = Ed25519PrivateKey.from_private_bytes(b"c" * 32)
    public_key = controller_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = hashlib.sha256(public_key).hexdigest()
    manifest = QualificationReadOnlyManifest(
        source=QualificationSource(commit_sha="a" * 40, tree_sha="b" * 40),
        timeout_seconds=900,
    )
    attestation = {
        "schema_version": "lil-tweak.dispatch-attestation/v1",
        "execution_id": "exec-001",
        "runner_id": "galor-tweak-runner-01",
        "runner_role": "role-tweak-runner",
        "lease_digest": "1" * 64,
        "contract_digest": "2" * 64,
        "commands_digest": "9" * 64 if mismatch else manifest.commands_digest,
        "approval_digest": "4" * 64,
        "policy_digest": "5" * 64,
        "attempt_nonce": _b64url(b"n" * 32),
        "issued_at_ms": 1_000_000,
        "expires_at_ms": 1_240_000,
    }
    signed = {
        "key_id": key_id,
        "attestation": attestation,
        "signature": _b64url(controller_key.sign(canonical_json(attestation).encode())),
    }
    return (
        {
            "execution_id": "exec-001",
            "status": "OFFERED",
            "expires_at_ms": 1_240_000,
            "attestation": signed,
            "manifest": manifest.model_dump(mode="json"),
        },
        key_id,
        public_key,
    )


def test_offer_is_accepted_only_when_manifest_digest_matches_attestation() -> None:
    offer, key_id, public_key = _offer()

    verified = verify_offer(
        offer,
        expected_key_id=key_id,
        controller_public_key=public_key,
        now_ms=1_010_000,
    )

    assert verified.execution_id == "exec-001"
    assert verified.manifest.source.commit_sha == "a" * 40
    assert verified.commands_digest == verified.manifest.commands_digest


def test_offer_rejects_manifest_command_substitution_after_attestation() -> None:
    offer, key_id, public_key = _offer(mismatch=True)

    with pytest.raises(OfferError, match="commands digest"):
        verify_offer(
            offer,
            expected_key_id=key_id,
            controller_public_key=public_key,
            now_ms=1_010_000,
        )


def test_offer_rejects_manifest_with_arbitrary_argv() -> None:
    offer, key_id, public_key = _offer()
    offer["manifest"]["argv"] = ["sh", "-c", "id"]

    with pytest.raises(OfferError, match="manifest"):
        verify_offer(
            offer,
            expected_key_id=key_id,
            controller_public_key=public_key,
            now_ms=1_010_000,
        )
