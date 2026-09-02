from __future__ import annotations

import base64
import binascii
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, StrictInt, StrictStr, model_validator

from .creator_contract import CreatorSchema, canonical_json, content_digest
from .runner_qualification import (
    LocalRunnerConnectionAuthorization,
    LocalRunnerConnectionDecision,
    RunnerQualificationDecision,
    SignedRunnerQualificationAttestation,
    runner_key_id,
)

_RUNNER_ID = "galor-tweak-runner-01"
_RUNNER_ROLE = "role-tweak-runner"
_REPOSITORY_ID = "github:islamismylifebey-web/lil-tweak"
_ENDPOINT = "https://runner-control.liltweak.galorweb.works"
_PROFILE_DIGEST = "e6d24dd720d661535a806e985153ef4801509e67b2a32b31ae9a302ce3298394"
_SHA256 = r"^[0-9a-f]{64}$"
_B64_NONCE = r"^[A-Za-z0-9_-]{43}$"
_B64_SIGNATURE = r"^[A-Za-z0-9_-]{86}$"
_POLL_DOMAIN = "lil-tweak.runner-request/poll/v1\n"
_MAX_POLL_AGE = timedelta(seconds=30)


class CloudflareRunnerQualificationError(RuntimeError):
    pass


class CloudflareRunnerPollRequest(CreatorSchema):
    schema_version: Literal["lil-tweak.runner-request/v1"] = "lil-tweak.runner-request/v1"
    runner_id: Literal["galor-tweak-runner-01"] = _RUNNER_ID
    operation: Literal["poll"] = "poll"
    request_nonce: StrictStr = Field(pattern=_B64_NONCE)
    issued_at_ms: StrictInt = Field(ge=0)
    payload: dict[str, object]

    @model_validator(mode="after")
    def empty_payload(self) -> Self:
        if self.payload:
            raise ValueError("runner poll payload must be empty")
        return self


class CloudflareRunnerPollObservation(CreatorSchema):
    schema_version: Literal["lil-tweak.cloudflare-runner-poll-observation/v1"] = (
        "lil-tweak.cloudflare-runner-poll-observation/v1"
    )
    endpoint: Literal["https://runner-control.liltweak.galorweb.works"] = _ENDPOINT
    request: CloudflareRunnerPollRequest
    signature: StrictStr = Field(pattern=_B64_SIGNATURE)
    worker_response_status: Literal[200, 404]
    worker_response_digest: StrictStr = Field(pattern=_SHA256)
    observed_at: datetime
    nonce_consumed: Literal[True] = True
    observation_digest: StrictStr = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def valid_digest(self) -> Self:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("runner poll observation time must be timezone-aware")
        expected = content_digest(self.model_dump(mode="json", exclude={"observation_digest"}))
        if self.observation_digest != expected:
            raise ValueError("runner poll observation digest mismatch")
        return self


class CloudflareRunnerQualificationProof(CreatorSchema):
    schema_version: Literal["lil-tweak.cloudflare-runner-qualification-proof/v1"] = (
        "lil-tweak.cloudflare-runner-qualification-proof/v1"
    )
    runner_id: Literal["galor-tweak-runner-01"] = _RUNNER_ID
    runner_role: Literal["role-tweak-runner"] = _RUNNER_ROLE
    repository_id: Literal["github:islamismylifebey-web/lil-tweak"] = _REPOSITORY_ID
    repository_commit: StrictStr = Field(pattern=r"^[0-9a-f]{40}$")
    repository_tree: StrictStr = Field(pattern=r"^[0-9a-f]{40}$")
    runner_key_id: StrictStr = Field(pattern=_SHA256)
    profile_spec_digest: StrictStr = Field(pattern=_SHA256)
    qualification_id: StrictStr
    qualification_evidence_digest: StrictStr = Field(pattern=_SHA256)
    qualification_verified_at: datetime
    authorization_id: StrictStr
    authorization_evidence_digest: StrictStr = Field(pattern=_SHA256)
    authorization_sequence: StrictInt = Field(ge=1)
    authorization_revocation_epoch: StrictInt = Field(default=1, ge=1)
    host_report_digest: StrictStr = Field(pattern=_SHA256)
    local_decision_digest: StrictStr = Field(pattern=_SHA256)
    cloudflare_poll_observation_digest: StrictStr = Field(pattern=_SHA256)
    cloudflare_poll_observed_at: datetime
    valid_until: datetime
    proof_digest: StrictStr = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_proof(self) -> Self:
        for value in (
            self.qualification_verified_at,
            self.cloudflare_poll_observed_at,
            self.valid_until,
        ):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("Cloudflare runner proof times must be timezone-aware")
        expected = content_digest(self.model_dump(mode="json", exclude={"proof_digest"}))
        if self.proof_digest != expected:
            raise ValueError("Cloudflare runner proof digest mismatch")
        return self

    def is_fresh(self, now: datetime) -> bool:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Cloudflare runner proof time must be timezone-aware")
        return self.cloudflare_poll_observed_at <= now < self.valid_until


class QualificationSource(Protocol):
    def verify(
        self, *, now: datetime
    ) -> tuple[RunnerQualificationDecision, SignedRunnerQualificationAttestation]: ...


class LocalConnectionSource(Protocol):
    def verify(
        self, *, qualification: RunnerQualificationDecision, now: datetime
    ) -> tuple[LocalRunnerConnectionDecision, LocalRunnerConnectionAuthorization]: ...


def _decode_signature(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise CloudflareRunnerQualificationError("runner poll signature is invalid") from exc
    if len(decoded) != 64:
        raise CloudflareRunnerQualificationError("runner poll signature is invalid")
    return decoded


class CloudflareRunnerQualificationVerifier:
    """Compose actual Gate 3, owner-authorized host probe, and signed Worker poll proof."""

    def __init__(
        self,
        *,
        qualification_source: QualificationSource,
        local_source: LocalConnectionSource,
        poll_observation: CloudflareRunnerPollObservation,
        runner_public_key: bytes,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(runner_public_key, bytes) or len(runner_public_key) != 32:
            raise ValueError("Cloudflare runner public key must contain exactly 32 bytes")
        self._qualification_source = qualification_source
        self._local_source = local_source
        self._poll = CloudflareRunnerPollObservation.model_validate(
            poll_observation.model_dump(mode="json")
        )
        self._runner_public_key = runner_public_key
        self._clock = clock or (lambda: datetime.now(UTC))
        self.contract_digest = content_digest(
            {
                "schema_version": "lil-tweak.cloudflare-runner-verifier-contract/v1",
                "runner_id": _RUNNER_ID,
                "repository_id": _REPOSITORY_ID,
                "profile_spec_digest": _PROFILE_DIGEST,
                "endpoint": _ENDPOINT,
                "runner_key_id": runner_key_id(runner_public_key),
            }
        )

    async def refresh(self) -> CloudflareRunnerQualificationProof:
        now = self._clock()
        qualification, attestation = self._qualification_source.verify(now=now)
        if (
            not qualification.qualified
            or qualification.failure_codes
            or qualification.connection_authorized
            or qualification.qualification_id != attestation.qualification_id
            or qualification.evidence_digest != attestation.evidence_digest
        ):
            raise CloudflareRunnerQualificationError("runner qualification decision failed")
        if (
            attestation.runner_id != _RUNNER_ID
            or attestation.repository_id != _REPOSITORY_ID
            or attestation.key_id != runner_key_id(self._runner_public_key)
        ):
            raise CloudflareRunnerQualificationError("runner qualification identity mismatch")

        local, authorization = self._local_source.verify(qualification=qualification, now=now)
        bindings = authorization.bindings
        if (
            not local.connection_authorized
            or local.failure_codes
            or local.authorization_id != authorization.authorization_id
            or local.authorization_digest != authorization.authorization_digest
            or local.report_digest != authorization.report_digest
        ):
            raise CloudflareRunnerQualificationError("local host probe decision failed")
        if (
            authorization.qualification_id != qualification.qualification_id
            or authorization.qualification_evidence_digest != qualification.evidence_digest
            or bindings.repository_id != _REPOSITORY_ID
            or bindings.repository_commit != attestation.repository_commit
            or bindings.repository_tree != attestation.repository_tree
            or bindings.resource_profile_digest != _PROFILE_DIGEST
        ):
            raise CloudflareRunnerQualificationError("local host profile binding mismatch")

        poll = self._poll
        issued_at = datetime.fromtimestamp(poll.request.issued_at_ms / 1_000, tz=UTC)
        if (
            issued_at > poll.observed_at
            or poll.observed_at > now
            or now - poll.observed_at > _MAX_POLL_AGE
            or poll.observed_at - issued_at > _MAX_POLL_AGE
        ):
            raise CloudflareRunnerQualificationError("signed runner poll is stale")
        message = (_POLL_DOMAIN + canonical_json(poll.request.model_dump(mode="json"))).encode(
            "utf-8"
        )
        try:
            Ed25519PublicKey.from_public_bytes(self._runner_public_key).verify(
                _decode_signature(poll.signature), message
            )
        except InvalidSignature as exc:
            raise CloudflareRunnerQualificationError(
                "signed runner poll signature is invalid"
            ) from exc
        valid_until = min(
            authorization.expires_at,
            poll.observed_at + _MAX_POLL_AGE,
        )
        values: dict[str, Any] = {
            "repository_commit": attestation.repository_commit,
            "repository_tree": attestation.repository_tree,
            "runner_key_id": attestation.key_id,
            "profile_spec_digest": _PROFILE_DIGEST,
            "qualification_id": qualification.qualification_id,
            "qualification_evidence_digest": qualification.evidence_digest,
            "qualification_verified_at": qualification.verified_at,
            "authorization_id": authorization.authorization_id,
            "authorization_evidence_digest": authorization.authorization_digest,
            "authorization_sequence": authorization.generation,
            "host_report_digest": authorization.report_digest,
            "local_decision_digest": local.decision_digest,
            "cloudflare_poll_observation_digest": poll.observation_digest,
            "cloudflare_poll_observed_at": poll.observed_at,
            "valid_until": valid_until,
        }
        draft = CloudflareRunnerQualificationProof.model_construct(**values, proof_digest="0" * 64)
        values["proof_digest"] = content_digest(
            draft.model_dump(mode="json", exclude={"proof_digest"})
        )
        return CloudflareRunnerQualificationProof(**values)
