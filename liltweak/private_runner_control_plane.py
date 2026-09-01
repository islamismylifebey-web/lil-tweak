from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from .config import Settings
from .providers.self_hosted.galor_tweak_runner import (
    GALOR_TWEAK_RUNNER_ID,
    RunnerOfferReceipt,
)
from .resource.contracts import ResourceExecutionContractV2, ResourceProvider, ResourceType
from .resource.dispatch import (
    DispatchAttestationError,
    SignedDispatchAttestation,
    dispatch_issuer_key_id,
)
from .resource.leases import ExecutionLease

_MAX_ATTESTATION_LIFETIME = timedelta(minutes=5)


class PrivateRunnerControlPlaneError(RuntimeError):
    """The private-runner control plane is not safe to use for this operation."""


class HttpPrivateRunnerControlPlaneClient:
    """Server-side-only typed offer client; it has no shell, secret, or completion API."""

    def __init__(
        self,
        *,
        base_url: str,
        bearer_token: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("private runner control-plane URL must be an HTTPS origin or path")
        if len(bearer_token) < 16 or any(
            ord(character) < 33 or ord(character) == 127 for character in bearer_token
        ):
            raise ValueError("private runner control-plane bearer token is invalid")
        self._base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {bearer_token}"}
        self._client = client

    def _http_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient()
        return self._client

    async def offer(self, *, attestation: SignedDispatchAttestation) -> RunnerOfferReceipt:
        try:
            envelope = SignedDispatchAttestation.model_validate(attestation.model_dump(mode="json"))
        except (AttributeError, ValidationError) as exc:
            raise PrivateRunnerControlPlaneError("signed private runner offer is invalid") from exc
        try:
            response = await self._http_client().post(
                f"{self._base_url}/v1/control/offer",
                json={"attestation": envelope.model_dump(mode="json")},
                headers=self._headers,
                timeout=15.0,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise PrivateRunnerControlPlaneError(
                "private runner control plane did not accept the signed offer"
            ) from exc
        try:
            payload: Any = response.json()
            return RunnerOfferReceipt.model_validate(payload)
        except (ValidationError, ValueError, TypeError) as exc:
            raise PrivateRunnerControlPlaneError(
                "private runner control plane returned an invalid offer receipt"
            ) from exc


def build_private_runner_control_plane_client(
    settings: Settings,
    *,
    client: httpx.AsyncClient | None = None,
) -> HttpPrivateRunnerControlPlaneClient:
    """Build the outbound offer client only from the fully validated server configuration."""

    if not settings.private_runner_control_plane_enabled:
        raise PrivateRunnerControlPlaneError("private runner control plane is disabled")
    if (
        settings.private_runner_control_plane_url is None
        or settings.private_runner_control_plane_auth_token is None
    ):
        raise PrivateRunnerControlPlaneError(
            "private runner control plane configuration is incomplete"
        )
    return HttpPrivateRunnerControlPlaneClient(
        base_url=settings.private_runner_control_plane_url,
        bearer_token=settings.private_runner_control_plane_auth_token,
        client=client,
    )


class PrivateRunnerAttestationIssuer:
    """Issue short-lived signed offers from server-held controls after existing lease checks."""

    def __init__(
        self,
        settings: Settings,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not settings.private_runner_control_plane_enabled:
            raise PrivateRunnerControlPlaneError("private runner control plane is disabled")
        key_bytes = settings.private_runner_dispatch_signing_key
        if not isinstance(key_bytes, bytes) or len(key_bytes) != 32:
            raise PrivateRunnerControlPlaneError(
                "private runner dispatch signing key is unavailable"
            )
        key = Ed25519PrivateKey.from_private_bytes(key_bytes)
        public_key = key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        key_id = dispatch_issuer_key_id(public_key)
        if settings.private_runner_dispatch_key_id != key_id:
            raise PrivateRunnerControlPlaneError(
                "private runner dispatch key identity does not match"
            )
        self._key = key
        self._clock = clock or (lambda: datetime.now(UTC))

    def issue(
        self,
        contract: ResourceExecutionContractV2,
        lease: ExecutionLease,
    ) -> SignedDispatchAttestation:
        if not isinstance(contract, ResourceExecutionContractV2) or not isinstance(
            lease, ExecutionLease
        ):
            raise PrivateRunnerControlPlaneError("private runner requires typed contract and lease")
        try:
            contract = ResourceExecutionContractV2.model_validate(contract.model_dump(mode="json"))
            lease = ExecutionLease.model_validate(lease.model_dump(mode="json"))
        except (ValidationError, ValueError):
            raise PrivateRunnerControlPlaneError(
                "private runner contract or lease is invalid"
            ) from None
        if (
            contract.provider is not ResourceProvider.SELF_HOSTED
            or contract.provider_resource_type is not ResourceType.SELF_HOSTED_LINUX
            or contract.runner_profile_id != GALOR_TWEAK_RUNNER_ID
        ):
            raise PrivateRunnerControlPlaneError("private runner contract identity is invalid")
        if not lease.execution_id:
            raise PrivateRunnerControlPlaneError(
                "private runner lease execution identity is invalid"
            )
        bindings = (
            (lease.contract_digest, contract.contract_digest),
            (lease.provider, contract.provider),
            (lease.runner_profile_id, contract.runner_profile_id),
            (lease.commands_digest, contract.commands_digest),
            (lease.approval_digest, contract.approval.approval_digest),
            (lease.policy_digest, contract.approval.policy_digest),
        )
        if any(observed != expected for observed, expected in bindings):
            raise PrivateRunnerControlPlaneError("private runner lease binding is invalid")
        now = self._clock()
        if (
            now.tzinfo is None
            or now.utcoffset() is None
            or now < contract.issued_at
            or now < lease.issued_at
        ):
            raise PrivateRunnerControlPlaneError("private runner attestation time is invalid")
        expiry = min(contract.expires_at, lease.expires_at, now + _MAX_ATTESTATION_LIFETIME)
        if expiry <= now:
            raise PrivateRunnerControlPlaneError("private runner lease is expired")
        try:
            nonce = (
                base64.urlsafe_b64encode(bytes.fromhex(lease.attempt_nonce))
                .decode("ascii")
                .rstrip("=")
            )
        except ValueError as exc:
            raise PrivateRunnerControlPlaneError("private runner lease nonce is invalid") from exc
        try:
            return SignedDispatchAttestation.issue(
                issuer_private_key=self._key,
                execution_id=lease.execution_id,
                lease_digest=lease.lease_digest,
                contract_digest=contract.contract_digest,
                commands_digest=contract.commands_digest,
                approval_digest=lease.approval_digest,
                policy_digest=lease.policy_digest,
                attempt_nonce=nonce,
                issued_at_ms=int(now.timestamp() * 1_000),
                expires_at_ms=int(expiry.timestamp() * 1_000),
            )
        except DispatchAttestationError as exc:
            raise PrivateRunnerControlPlaneError(
                "private runner attestation cannot be issued"
            ) from exc
