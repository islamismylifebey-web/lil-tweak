from __future__ import annotations

import secrets
from datetime import datetime
from enum import StrEnum
from typing import Literal, Protocol, runtime_checkable

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator

from .workbench_contract import SAFE_ID, SHA256, WorkbenchSchema, content_digest


class ExternalCheckpointError(RuntimeError):
    """Base error for fail-closed external checkpoint operations."""


class ExternalCheckpointUnavailable(ExternalCheckpointError):
    """The independent checkpoint cannot currently authorize progress."""


class ExternalCheckpointMismatch(ExternalCheckpointError):
    """An external receipt does not bind the expected local evidence head."""


class ExternalCheckpointStatus(StrEnum):
    BLOCKED = "blocked"
    OPERATIONAL = "operational"
    FAILED = "failed"


class ExternalCheckpointCapability(WorkbenchSchema):
    schema_version: Literal["external-checkpoint-capability-v1"] = (
        "external-checkpoint-capability-v1"
    )
    provider_id: StrictStr = Field(pattern=SAFE_ID)
    configured: StrictBool
    reachable: StrictBool
    independently_retained: StrictBool
    append_authorized: StrictBool
    verified: StrictBool
    operational: StrictBool
    status: ExternalCheckpointStatus
    reason_code: StrictStr = Field(pattern=SAFE_ID)

    @model_validator(mode="after")
    def status_is_truthful(self) -> ExternalCheckpointCapability:
        prerequisites = (
            self.configured,
            self.reachable,
            self.independently_retained,
            self.append_authorized,
            self.verified,
        )
        if self.operational != all(prerequisites):
            raise ValueError("checkpoint operational status does not match its prerequisites")
        if self.operational != (self.status == ExternalCheckpointStatus.OPERATIONAL):
            raise ValueError("checkpoint status contradicts its operational flag")
        return self


class ExternalCheckpointAppend(WorkbenchSchema):
    """A purpose-bound request to retain the current local evidence head externally."""

    schema_version: Literal["external-checkpoint-append-v1"] = "external-checkpoint-append-v1"
    operation_id: StrictStr = Field(pattern=SAFE_ID)
    ledger_id: StrictStr = Field(pattern=SAFE_ID)
    task_id: StrictStr = Field(pattern=SAFE_ID)
    evidence_sequence: StrictInt = Field(ge=1)
    evidence_head_sha256: StrictStr = Field(pattern=SHA256)
    previous_receipt_digest: StrictStr | None = Field(default=None, pattern=SHA256)
    local_created_at: datetime

    @model_validator(mode="after")
    def timestamp_is_aware(self) -> ExternalCheckpointAppend:
        if self.local_created_at.tzinfo is None or self.local_created_at.utcoffset() is None:
            raise ValueError("checkpoint request timestamp must be timezone-aware")
        return self

    @property
    def request_digest(self) -> str:
        return content_digest(self)


class ExternalCheckpointExpectation(WorkbenchSchema):
    """The exact external head required before a security-sensitive gate may proceed."""

    schema_version: Literal["external-checkpoint-expectation-v1"] = (
        "external-checkpoint-expectation-v1"
    )
    ledger_id: StrictStr = Field(pattern=SAFE_ID)
    task_id: StrictStr = Field(pattern=SAFE_ID)
    evidence_sequence: StrictInt = Field(ge=1)
    evidence_head_sha256: StrictStr = Field(pattern=SHA256)
    minimum_external_sequence: StrictInt = Field(ge=1)
    expected_receipt_digest: StrictStr | None = Field(default=None, pattern=SHA256)


class ExternalCheckpointReceipt(WorkbenchSchema):
    """Provider-authenticated proof of independently retained evidence state.

    The provider proof is deliberately opaque here. A concrete client must authenticate it
    using trust material outside the application database before returning the receipt.
    """

    schema_version: Literal["external-checkpoint-receipt-v1"] = "external-checkpoint-receipt-v1"
    provider_id: StrictStr = Field(pattern=SAFE_ID)
    provider_key_id: StrictStr = Field(pattern=SAFE_ID)
    checkpoint_id: StrictStr = Field(pattern=SAFE_ID)
    ledger_id: StrictStr = Field(pattern=SAFE_ID)
    task_id: StrictStr = Field(pattern=SAFE_ID)
    operation_id: StrictStr = Field(pattern=SAFE_ID)
    request_digest: StrictStr = Field(pattern=SHA256)
    evidence_sequence: StrictInt = Field(ge=1)
    evidence_head_sha256: StrictStr = Field(pattern=SHA256)
    external_sequence: StrictInt = Field(ge=1)
    trusted_timestamp: datetime
    previous_receipt_digest: StrictStr | None = Field(default=None, pattern=SHA256)
    receipt_digest: StrictStr = Field(pattern=SHA256)
    provider_proof: StrictStr = Field(min_length=1, max_length=8_192)

    @model_validator(mode="after")
    def validate_receipt(self) -> ExternalCheckpointReceipt:
        if self.trusted_timestamp.tzinfo is None or self.trusted_timestamp.utcoffset() is None:
            raise ValueError("checkpoint trusted timestamp must be timezone-aware")
        expected = content_digest(
            self.model_dump(mode="json", exclude={"receipt_digest", "provider_proof"})
        )
        if not secrets.compare_digest(self.receipt_digest, expected):
            raise ValueError("external checkpoint receipt digest mismatch")
        return self


def assert_receipt_binding(
    receipt: ExternalCheckpointReceipt,
    expectation: ExternalCheckpointExpectation,
) -> None:
    """Reject a stale or differently bound receipt after provider-proof verification."""

    matches = (
        receipt.ledger_id == expectation.ledger_id
        and receipt.task_id == expectation.task_id
        and receipt.evidence_sequence == expectation.evidence_sequence
        and secrets.compare_digest(
            receipt.evidence_head_sha256,
            expectation.evidence_head_sha256,
        )
        and receipt.external_sequence >= expectation.minimum_external_sequence
    )
    if expectation.expected_receipt_digest is not None:
        matches = matches and secrets.compare_digest(
            receipt.receipt_digest,
            expectation.expected_receipt_digest,
        )
    if not matches:
        raise ExternalCheckpointMismatch(
            "external checkpoint does not match the required evidence head"
        )


@runtime_checkable
class ExternalCheckpointClient(Protocol):
    """Submit-only independent checkpoint boundary used by the control plane.

    Implementations must authenticate provider receipts with trust material that is not
    recoverable from the application database. They must never synthesize external sequence
    numbers or trusted timestamps locally.
    """

    @property
    def capability(self) -> ExternalCheckpointCapability: ...

    async def append(self, request: ExternalCheckpointAppend) -> ExternalCheckpointReceipt: ...

    async def assert_current(
        self,
        expectation: ExternalCheckpointExpectation,
    ) -> ExternalCheckpointReceipt: ...


class DisabledExternalCheckpointClient:
    """Truthful default: checkpoint-dependent operations remain blocked."""

    def __init__(self, *, reason_code: str = "not_configured") -> None:
        self._capability = ExternalCheckpointCapability(
            provider_id="disabled",
            configured=False,
            reachable=False,
            independently_retained=False,
            append_authorized=False,
            verified=False,
            operational=False,
            status=ExternalCheckpointStatus.BLOCKED,
            reason_code=reason_code,
        )

    @property
    def capability(self) -> ExternalCheckpointCapability:
        return self._capability

    async def append(self, request: ExternalCheckpointAppend) -> ExternalCheckpointReceipt:
        del request
        raise ExternalCheckpointUnavailable(
            f"external checkpoint unavailable: {self._capability.reason_code}"
        )

    async def assert_current(
        self,
        expectation: ExternalCheckpointExpectation,
    ) -> ExternalCheckpointReceipt:
        del expectation
        raise ExternalCheckpointUnavailable(
            f"external checkpoint unavailable: {self._capability.reason_code}"
        )
