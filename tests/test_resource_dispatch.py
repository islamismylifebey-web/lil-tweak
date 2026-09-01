from __future__ import annotations

import json
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from liltweak.resource.dispatch import (
    DispatchAttestationError,
    DispatchAttestationVerifier,
    SignedDispatchAttestation,
    canonical_dispatch_attestation_json,
    canonical_signed_dispatch_attestation_json,
    dispatch_issuer_key_id,
    parse_canonical_signed_dispatch_attestation,
)

NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


def _public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _timestamp_ms(value: datetime) -> int:
    return int(value.timestamp() * 1_000)


def _signed_attestation(
    private_key: Ed25519PrivateKey,
    *,
    issued_at: datetime = NOW,
    expires_at: datetime = NOW + timedelta(minutes=2),
) -> SignedDispatchAttestation:
    return SignedDispatchAttestation.issue(
        issuer_private_key=private_key,
        execution_id="execution_001",
        lease_digest="a" * 64,
        contract_digest="b" * 64,
        commands_digest="c" * 64,
        approval_digest="d" * 64,
        policy_digest="e" * 64,
        attempt_nonce=urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("="),
        issued_at_ms=_timestamp_ms(issued_at),
        expires_at_ms=_timestamp_ms(expires_at),
    )


def _verifier(private_key: Ed25519PrivateKey) -> DispatchAttestationVerifier:
    public_key = _public_bytes(private_key)
    return DispatchAttestationVerifier(
        trusted_issuer_public_keys={dispatch_issuer_key_id(public_key): public_key}
    )


def test_canonical_signed_attestation_is_bound_to_the_private_runner() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = _signed_attestation(private_key)
    verifier = _verifier(private_key)

    payload = canonical_signed_dispatch_attestation_json(signed)
    verified = verifier.verify(payload, now=NOW + timedelta(seconds=1))

    assert verified == signed.attestation
    assert signed.attestation.runner_id == "galor-tweak-runner-01"
    assert signed.attestation.runner_role == "role-tweak-runner"
    assert signed.key_id == dispatch_issuer_key_id(_public_bytes(private_key))
    assert canonical_dispatch_attestation_json(signed.attestation) == (
        '{"approval_digest":"'
        + "d" * 64
        + '","attempt_nonce":"'
        + signed.attestation.attempt_nonce
        + '","commands_digest":"'
        + "c" * 64
        + '","contract_digest":"'
        + "b" * 64
        + '","execution_id":"execution_001","expires_at_ms":1788264120000,'
        + '"issued_at_ms":1788264000000,"lease_digest":"'
        + "a" * 64
        + '","policy_digest":"'
        + "e" * 64
        + '","runner_id":"galor-tweak-runner-01","runner_role":"role-tweak-runner",'
        + '"schema_version":"lil-tweak.dispatch-attestation/v1"}'
    )


def test_attestation_exposes_only_digests_not_commands_or_secret_values() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = _signed_attestation(private_key)
    payload = json.loads(canonical_dispatch_attestation_json(signed.attestation))

    assert set(payload) == {
        "schema_version",
        "execution_id",
        "runner_id",
        "runner_role",
        "lease_digest",
        "contract_digest",
        "commands_digest",
        "approval_digest",
        "policy_digest",
        "attempt_nonce",
        "issued_at_ms",
        "expires_at_ms",
    }

    payload["command"] = "echo forbidden"
    malicious = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    envelope = {
        "attestation": json.loads(malicious),
        "key_id": signed.key_id,
        "signature": signed.signature,
    }
    with pytest.raises(DispatchAttestationError, match="invalid"):
        parse_canonical_signed_dispatch_attestation(
            json.dumps(
                envelope,
                sort_keys=True,
                separators=(",", ":"),
            )
        )


def test_verifier_rejects_tampered_digest_and_unknown_signer() -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = _signed_attestation(private_key)
    tampered = signed.model_copy(
        update={"attestation": signed.attestation.model_copy(update={"lease_digest": "f" * 64})}
    )

    with pytest.raises(DispatchAttestationError, match="signature"):
        _verifier(private_key).verify(tampered, now=NOW + timedelta(seconds=1))

    with pytest.raises(DispatchAttestationError, match="untrusted"):
        DispatchAttestationVerifier(trusted_issuer_public_keys={}).verify(
            signed,
            now=NOW + timedelta(seconds=1),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("runner_id", "other-runner"),
        ("runner_role", "role-other-runner"),
    ),
)
def test_parser_rejects_wrong_pinned_runner_identity(field: str, value: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    signed = _signed_attestation(private_key)
    payload = json.loads(canonical_dispatch_attestation_json(signed.attestation))
    payload[field] = value

    with pytest.raises(DispatchAttestationError, match="invalid"):
        parse_canonical_signed_dispatch_attestation(
            json.dumps(
                {"attestation": payload, "key_id": signed.key_id, "signature": signed.signature},
                sort_keys=True,
                separators=(",", ":"),
            )
        )


def test_verifier_rejects_expired_and_replayed_attestations() -> None:
    private_key = Ed25519PrivateKey.generate()
    expired = _signed_attestation(
        private_key,
        issued_at=NOW - timedelta(minutes=3),
        expires_at=NOW - timedelta(minutes=1),
    )
    with pytest.raises(DispatchAttestationError, match="expired"):
        _verifier(private_key).verify(expired, now=NOW)

    valid = _signed_attestation(private_key)
    verifier = _verifier(private_key)
    assert verifier.verify(valid, now=NOW + timedelta(seconds=1)) == valid.attestation
    with pytest.raises(DispatchAttestationError, match="replayed"):
        verifier.verify(valid, now=NOW + timedelta(seconds=2))


def test_verifier_rejects_noncanonical_wire_payload() -> None:
    private_key = Ed25519PrivateKey.generate()
    canonical = canonical_signed_dispatch_attestation_json(_signed_attestation(private_key))
    noncanonical = json.dumps(
        json.loads(canonical),
        sort_keys=True,
        separators=(", ", ": "),
    )

    with pytest.raises(DispatchAttestationError, match="noncanonical"):
        _verifier(private_key).verify(noncanonical, now=NOW + timedelta(seconds=1))


def test_cloudflare_golden_vector_verifies_in_python() -> None:
    fixture_path = (
        Path(__file__).parents[1]
        / "cloudflare"
        / "runner-control-plane"
        / "test"
        / "fixtures"
        / "dispatch-attestation-v1.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    decoded_public_key = urlsafe_b64decode(fixture["public_key"] + "=")
    envelope = SignedDispatchAttestation.model_validate(fixture["attestation"])
    verifier = DispatchAttestationVerifier(
        trusted_issuer_public_keys={fixture["key_id"]: decoded_public_key}
    )

    verified = verifier.verify(envelope, now=datetime(2025, 1, 1, 0, 1, tzinfo=UTC))

    assert verified.execution_id == "golden-fixture-001"
