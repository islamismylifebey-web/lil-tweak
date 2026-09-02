from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from runner.protocol import (
    ProtocolError,
    canonical_json,
    sign_runner_request,
    verify_dispatch_attestation,
)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _attestation_payload(*, commands_digest: str) -> dict[str, object]:
    return {
        "schema_version": "lil-tweak.dispatch-attestation/v1",
        "execution_id": "exec-001",
        "runner_id": "galor-tweak-runner-01",
        "runner_role": "role-tweak-runner",
        "lease_digest": "1" * 64,
        "contract_digest": "2" * 64,
        "commands_digest": commands_digest,
        "approval_digest": "4" * 64,
        "policy_digest": "5" * 64,
        "attempt_nonce": _b64url(b"n" * 32),
        "issued_at_ms": 1_000_000,
        "expires_at_ms": 1_240_000,
    }


def test_runner_request_signature_uses_operation_domain_and_canonical_request() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(b"r" * 32)

    envelope = sign_runner_request(
        operation="poll",
        payload={},
        private_key=private_key,
        issued_at_ms=1_000_000,
        request_nonce=b"q" * 32,
    )

    assert envelope["request"] == {
        "schema_version": "lil-tweak.runner-request/v1",
        "runner_id": "galor-tweak-runner-01",
        "operation": "poll",
        "request_nonce": _b64url(b"q" * 32),
        "issued_at_ms": 1_000_000,
        "payload": {},
    }
    signing_bytes = (
        "lil-tweak.runner-request/poll/v1\n" + canonical_json(envelope["request"])
    ).encode()
    private_key.public_key().verify(
        base64.urlsafe_b64decode(str(envelope["signature"]) + "=="),
        signing_bytes,
    )


def test_dispatch_attestation_rejects_tampered_commands_digest() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(b"c" * 32)
    payload = _attestation_payload(commands_digest="3" * 64)
    signature = private_key.sign(canonical_json(payload).encode())
    envelope = {
        "key_id": hashlib.sha256(_raw_public_key(private_key)).hexdigest(),
        "attestation": payload,
        "signature": _b64url(signature),
    }
    envelope["attestation"]["commands_digest"] = "9" * 64

    with pytest.raises(ProtocolError, match="signature is invalid"):
        verify_dispatch_attestation(
            envelope,
            expected_key_id=hashlib.sha256(_raw_public_key(private_key)).hexdigest(),
            public_key_bytes=_raw_public_key(private_key),
            now_ms=1_010_000,
        )


def test_dispatch_attestation_accepts_exact_pinned_valid_envelope() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(b"c" * 32)
    payload = _attestation_payload(commands_digest="3" * 64)
    envelope = {
        "key_id": hashlib.sha256(_raw_public_key(private_key)).hexdigest(),
        "attestation": payload,
        "signature": _b64url(private_key.sign(canonical_json(payload).encode())),
    }

    verified = verify_dispatch_attestation(
        envelope,
        expected_key_id=str(envelope["key_id"]),
        public_key_bytes=_raw_public_key(private_key),
        now_ms=1_010_000,
    )

    assert verified == payload
    assert json.loads(canonical_json(verified)) == payload
