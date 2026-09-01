from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import Field, StrictInt, StrictStr, ValidationError, model_validator

from ..creator_contract import CreatorSchema, canonical_json

TWEAK_RUNNER_ID = "galor-tweak-runner-01"
TWEAK_RUNNER_ROLE = "role-tweak-runner"
DISPATCH_ATTESTATION_SCHEMA_VERSION = "lil-tweak.dispatch-attestation/v1"
MAX_DISPATCH_ATTESTATION_LIFETIME_MS = 300_000
MAX_DISPATCH_ATTESTATION_BYTES = 8_192

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SAFE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_BASE64URL_32_BYTE_PATTERN = r"^[A-Za-z0-9_-]{43}$"
_BASE64URL_SIGNATURE_PATTERN = r"^[A-Za-z0-9_-]{86}$"


class DispatchAttestationError(ValueError):
    """A signed private-runner dispatch envelope is malformed or unsafe to use."""


def dispatch_issuer_key_id(public_key: bytes) -> str:
    """Return the stable SHA-256 identifier for one raw Ed25519 public key."""

    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise DispatchAttestationError(
            "dispatch attestation issuer public key must contain exactly 32 bytes"
        )
    return hashlib.sha256(public_key).hexdigest()


def _public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _decode_base64url(value: str, *, expected_bytes: int, label: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise DispatchAttestationError(f"dispatch attestation {label} is invalid")
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise DispatchAttestationError(f"dispatch attestation {label} is invalid") from exc
    if len(decoded) != expected_bytes:
        raise DispatchAttestationError(f"dispatch attestation {label} is invalid")
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != value:
        raise DispatchAttestationError(f"dispatch attestation {label} is invalid")
    return decoded


def _timestamp_ms(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DispatchAttestationError("dispatch attestation timestamp must be timezone-aware")
    return int(value.timestamp() * 1_000)


class DispatchAttestation(CreatorSchema):
    """The exact canonical payload signed for one outbound private-runner dispatch."""

    schema_version: Literal["lil-tweak.dispatch-attestation/v1"] = (
        "lil-tweak.dispatch-attestation/v1"
    )
    execution_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    runner_id: Literal["galor-tweak-runner-01"] = "galor-tweak-runner-01"
    runner_role: Literal["role-tweak-runner"] = "role-tweak-runner"
    lease_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    contract_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    commands_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    approval_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    policy_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    attempt_nonce: StrictStr = Field(pattern=_BASE64URL_32_BYTE_PATTERN)
    issued_at_ms: StrictInt = Field(ge=0)
    expires_at_ms: StrictInt = Field(ge=0)

    @model_validator(mode="after")
    def validate_attestation(self) -> Self:
        _decode_base64url(self.attempt_nonce, expected_bytes=32, label="attempt nonce")
        lifetime_ms = self.expires_at_ms - self.issued_at_ms
        if lifetime_ms <= 0 or lifetime_ms > MAX_DISPATCH_ATTESTATION_LIFETIME_MS:
            raise ValueError("dispatch attestation lifetime is invalid")
        return self


class SignedDispatchAttestation(CreatorSchema):
    """A public-key-verifiable wrapper around the canonical dispatch payload."""

    attestation: DispatchAttestation
    key_id: StrictStr = Field(pattern=_SHA256_PATTERN)
    signature: StrictStr = Field(pattern=_BASE64URL_SIGNATURE_PATTERN)

    @classmethod
    def issue(
        cls,
        *,
        issuer_private_key: Ed25519PrivateKey,
        execution_id: str,
        lease_digest: str,
        contract_digest: str,
        commands_digest: str,
        approval_digest: str,
        policy_digest: str,
        attempt_nonce: str,
        issued_at_ms: int,
        expires_at_ms: int,
    ) -> SignedDispatchAttestation:
        if not isinstance(issuer_private_key, Ed25519PrivateKey):
            raise DispatchAttestationError("dispatch attestation issuer private key is invalid")
        attestation = DispatchAttestation(
            execution_id=execution_id,
            lease_digest=lease_digest,
            contract_digest=contract_digest,
            commands_digest=commands_digest,
            approval_digest=approval_digest,
            policy_digest=policy_digest,
            attempt_nonce=attempt_nonce,
            issued_at_ms=issued_at_ms,
            expires_at_ms=expires_at_ms,
        )
        signature = issuer_private_key.sign(
            canonical_dispatch_attestation_json(attestation).encode("utf-8")
        )
        return cls(
            attestation=attestation,
            key_id=dispatch_issuer_key_id(_public_bytes(issuer_private_key)),
            signature=base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        )


def canonical_dispatch_attestation_json(attestation: DispatchAttestation) -> str:
    """Serialize the exact Ed25519 message: sorted, compact JSON encoded as UTF-8 by callers."""

    try:
        validated = DispatchAttestation.model_validate(attestation.model_dump(mode="json"))
    except (AttributeError, ValidationError) as exc:
        raise DispatchAttestationError("dispatch attestation payload is invalid") from exc
    return canonical_json(validated.model_dump(mode="json"))


def canonical_signed_dispatch_attestation_json(envelope: SignedDispatchAttestation) -> str:
    """Serialize the complete wire envelope without permitting alternate JSON spellings."""

    try:
        validated = SignedDispatchAttestation.model_validate(envelope.model_dump(mode="json"))
    except (AttributeError, ValidationError) as exc:
        raise DispatchAttestationError("signed dispatch attestation envelope is invalid") from exc
    return canonical_json(validated.model_dump(mode="json"))


def parse_canonical_signed_dispatch_attestation(
    payload: str | bytes,
) -> SignedDispatchAttestation:
    """Parse a canonical envelope; alternate JSON spellings and extra fields fail closed."""

    if isinstance(payload, bytes):
        if len(payload) > MAX_DISPATCH_ATTESTATION_BYTES:
            raise DispatchAttestationError("dispatch attestation payload exceeds its byte limit")
        try:
            raw = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DispatchAttestationError("dispatch attestation payload is invalid") from exc
    elif isinstance(payload, str):
        if len(payload.encode("utf-8")) > MAX_DISPATCH_ATTESTATION_BYTES:
            raise DispatchAttestationError("dispatch attestation payload exceeds its byte limit")
        raw = payload
    else:
        raise DispatchAttestationError("dispatch attestation payload is invalid")
    try:
        decoded = json.loads(raw)
        envelope = SignedDispatchAttestation.model_validate(decoded)
    except (json.JSONDecodeError, ValidationError, TypeError, ValueError) as exc:
        raise DispatchAttestationError("dispatch attestation payload is invalid") from exc
    if canonical_signed_dispatch_attestation_json(envelope) != raw:
        raise DispatchAttestationError("dispatch attestation payload is noncanonical")
    return envelope


class DispatchAttestationVerifier:
    """Verify trusted Ed25519 issuers and consume one private-runner nonce at most once."""

    def __init__(self, *, trusted_issuer_public_keys: Mapping[str, bytes]) -> None:
        trusted_keys = dict(trusted_issuer_public_keys)
        for key_id, public_key in trusted_keys.items():
            if key_id != dispatch_issuer_key_id(public_key):
                raise DispatchAttestationError("dispatch attestation issuer key mapping is invalid")
        self._trusted_keys = trusted_keys
        self._consumed_nonces: set[str] = set()
        self._consumed_lease_digests: set[str] = set()

    def verify(
        self,
        envelope: SignedDispatchAttestation | str | bytes,
        *,
        now: datetime | None = None,
        consume: bool = True,
    ) -> DispatchAttestation:
        signed = self._normalize_envelope(envelope)
        observed_at = now or datetime.now(UTC)
        observed_at_ms = _timestamp_ms(observed_at)
        attestation = signed.attestation
        if observed_at_ms < attestation.issued_at_ms:
            raise DispatchAttestationError("dispatch attestation is not yet valid")
        if observed_at_ms >= attestation.expires_at_ms:
            raise DispatchAttestationError("dispatch attestation is expired")
        public_key = self._trusted_keys.get(signed.key_id)
        if public_key is None:
            raise DispatchAttestationError("dispatch attestation issuer is untrusted")
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                _decode_base64url(signed.signature, expected_bytes=64, label="signature"),
                canonical_dispatch_attestation_json(attestation).encode("utf-8"),
            )
        except (InvalidSignature, ValueError) as exc:
            raise DispatchAttestationError("dispatch attestation signature is invalid") from exc
        if consume and (
            attestation.attempt_nonce in self._consumed_nonces
            or attestation.lease_digest in self._consumed_lease_digests
        ):
            raise DispatchAttestationError("dispatch attestation was replayed")
        if consume:
            self._consumed_nonces.add(attestation.attempt_nonce)
            self._consumed_lease_digests.add(attestation.lease_digest)
        return attestation

    @staticmethod
    def _normalize_envelope(
        envelope: SignedDispatchAttestation | str | bytes,
    ) -> SignedDispatchAttestation:
        if isinstance(envelope, (str, bytes)):
            return parse_canonical_signed_dispatch_attestation(envelope)
        try:
            return SignedDispatchAttestation.model_validate(envelope.model_dump(mode="json"))
        except (AttributeError, ValidationError) as exc:
            raise DispatchAttestationError(
                "signed dispatch attestation envelope is invalid"
            ) from exc
