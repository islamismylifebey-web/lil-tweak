from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from pydantic import TypeAdapter, ValidationError

from liltweak.providers.self_hosted.qualification_manifest import (
    QualificationBoundedWriteManifest,
    QualificationJobManifest,
    QualificationReadOnlyManifest,
)

from .protocol import ProtocolError, verify_dispatch_attestation


class OfferError(ValueError):
    """Reject a control-plane offer before any claim or execution."""


@dataclass(frozen=True)
class VerifiedOffer:
    execution_id: str
    expires_at_ms: int
    attempt_nonce: str
    commands_digest: str
    manifest: QualificationReadOnlyManifest | QualificationBoundedWriteManifest


_MANIFEST_ADAPTER: TypeAdapter[
    QualificationReadOnlyManifest | QualificationBoundedWriteManifest
] = TypeAdapter(QualificationJobManifest)


def verify_offer(
    value: object,
    *,
    expected_key_id: str,
    controller_public_key: bytes,
    now_ms: int,
) -> VerifiedOffer:
    if not isinstance(value, Mapping) or set(value) != {
        "execution_id",
        "status",
        "expires_at_ms",
        "attestation",
        "manifest",
    }:
        raise OfferError("offer has an invalid shape")
    offer = cast(Mapping[str, object], value)
    if offer["status"] != "OFFERED":
        raise OfferError("offer status is not authorized")
    try:
        attestation = verify_dispatch_attestation(
            offer["attestation"],
            expected_key_id=expected_key_id,
            public_key_bytes=controller_public_key,
            now_ms=now_ms,
        )
    except ProtocolError as exc:
        raise OfferError("offer attestation is invalid") from exc
    try:
        manifest = _MANIFEST_ADAPTER.validate_python(offer["manifest"])
    except ValidationError as exc:
        raise OfferError("offer manifest is invalid") from exc

    execution_id = offer["execution_id"]
    expires_at = offer["expires_at_ms"]
    if execution_id != attestation["execution_id"]:
        raise OfferError("offer execution identity is not attested")
    if expires_at != attestation["expires_at_ms"]:
        raise OfferError("offer expiry is not attested")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise OfferError("offer expiry is invalid")
    if manifest.commands_digest != attestation["commands_digest"]:
        raise OfferError("offer commands digest does not match the manifest")
    return VerifiedOffer(
        execution_id=cast(str, execution_id),
        expires_at_ms=expires_at,
        attempt_nonce=cast(str, attestation["attempt_nonce"]),
        commands_digest=manifest.commands_digest,
        manifest=manifest,
    )
