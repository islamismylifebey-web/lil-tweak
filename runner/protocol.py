from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping
from typing import Literal, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

RUNNER_ID = "galor-tweak-runner-01"
RUNNER_ROLE = "role-tweak-runner"
RUNNER_REQUEST_SCHEMA = "lil-tweak.runner-request/v1"
DISPATCH_ATTESTATION_SCHEMA = "lil-tweak.dispatch-attestation/v1"
MAX_CLOCK_SKEW_MS = 30_000
MAX_ATTESTATION_TTL_MS = 300_000

Operation = Literal["poll", "claim", "status", "evidence"]

_DOMAINS: dict[Operation, str] = {
    "poll": "lil-tweak.runner-request/poll/v1",
    "claim": "lil-tweak.runner-request/claim/v1",
    "status": "lil-tweak.runner-request/status/v1",
    "evidence": "lil-tweak.runner-request/evidence/v1",
}
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_EXECUTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class ProtocolError(ValueError):
    """Reject malformed, forged, stale, or unbound control-plane data."""


def canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ProtocolError("value is not canonical JSON") from exc


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: object, *, expected_bytes: int, label: str) -> bytes:
    if not isinstance(value, str) or not _BASE64URL.fullmatch(value):
        raise ProtocolError(f"{label} is not URL-safe base64")
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ProtocolError(f"{label} is not URL-safe base64") from exc
    if len(decoded) != expected_bytes:
        raise ProtocolError(f"{label} has an invalid length")
    return decoded


def _exact_mapping(value: object, keys: set[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ProtocolError(f"{label} has an invalid shape")
    if not all(isinstance(key, str) for key in value):
        raise ProtocolError(f"{label} has an invalid shape")
    return cast(Mapping[str, object], value)


def _safe_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(f"{label} must be an integer")
    if value < 0 or value > 9_007_199_254_740_991:
        raise ProtocolError(f"{label} is outside the safe integer range")
    return value


def sign_runner_request(
    *,
    operation: Operation,
    payload: Mapping[str, object],
    private_key: Ed25519PrivateKey,
    issued_at_ms: int,
    request_nonce: bytes,
) -> dict[str, object]:
    if operation not in _DOMAINS:
        raise ProtocolError("runner operation is not authorized")
    if len(request_nonce) != 32:
        raise ProtocolError("request nonce must contain exactly 32 bytes")
    issued_at = _safe_integer(issued_at_ms, "issued_at_ms")
    request: dict[str, object] = {
        "schema_version": RUNNER_REQUEST_SCHEMA,
        "runner_id": RUNNER_ID,
        "operation": operation,
        "request_nonce": _b64url_encode(request_nonce),
        "issued_at_ms": issued_at,
        "payload": dict(payload),
    }
    signing_bytes = f"{_DOMAINS[operation]}\n{canonical_json(request)}".encode()
    return {
        "request": request,
        "signature": _b64url_encode(private_key.sign(signing_bytes)),
    }


def verify_dispatch_attestation(
    envelope_value: object,
    *,
    expected_key_id: str,
    public_key_bytes: bytes,
    now_ms: int,
) -> dict[str, object]:
    envelope = _exact_mapping(
        envelope_value,
        {"key_id", "attestation", "signature"},
        "dispatch attestation",
    )
    key_id = envelope["key_id"]
    if not isinstance(key_id, str) or not _DIGEST.fullmatch(key_id):
        raise ProtocolError("attestation key id is invalid")
    if key_id != expected_key_id:
        raise ProtocolError("attestation key is not authorized")
    if len(public_key_bytes) != 32:
        raise ProtocolError("attestation public key has an invalid length")

    payload = _exact_mapping(
        envelope["attestation"],
        {
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
        },
        "dispatch attestation payload",
    )
    if payload["schema_version"] != DISPATCH_ATTESTATION_SCHEMA:
        raise ProtocolError("attestation schema is not authorized")
    execution_id = payload["execution_id"]
    if not isinstance(execution_id, str) or not _EXECUTION_ID.fullmatch(execution_id):
        raise ProtocolError("attestation execution id is invalid")
    if payload["runner_id"] != RUNNER_ID or payload["runner_role"] != RUNNER_ROLE:
        raise ProtocolError("attestation runner identity is not authorized")
    for field in (
        "lease_digest",
        "contract_digest",
        "commands_digest",
        "approval_digest",
        "policy_digest",
    ):
        value = payload[field]
        if not isinstance(value, str) or not _DIGEST.fullmatch(value):
            raise ProtocolError(f"attestation {field} is invalid")
    _b64url_decode(
        payload["attempt_nonce"],
        expected_bytes=32,
        label="attestation attempt nonce",
    )
    issued_at = _safe_integer(payload["issued_at_ms"], "attestation issued_at_ms")
    expires_at = _safe_integer(payload["expires_at_ms"], "attestation expires_at_ms")
    now = _safe_integer(now_ms, "current time")
    if (
        issued_at > now + MAX_CLOCK_SKEW_MS
        or expires_at <= now
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_ATTESTATION_TTL_MS
    ):
        raise ProtocolError("attestation validity window is invalid")
    signature = _b64url_decode(
        envelope["signature"],
        expected_bytes=64,
        label="attestation signature",
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature,
            canonical_json(dict(payload)).encode("utf-8"),
        )
    except InvalidSignature as exc:
        raise ProtocolError("attestation signature is invalid") from exc
    return dict(payload)
