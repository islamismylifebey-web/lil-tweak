from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from liltweak.external_checkpoint import (
    DisabledExternalCheckpointClient,
    ExternalCheckpointAppend,
    ExternalCheckpointCapability,
    ExternalCheckpointClient,
    ExternalCheckpointExpectation,
    ExternalCheckpointMismatch,
    ExternalCheckpointReceipt,
    ExternalCheckpointStatus,
    ExternalCheckpointUnavailable,
    assert_receipt_binding,
)
from liltweak.workbench_contract import content_digest

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def append_request() -> ExternalCheckpointAppend:
    return ExternalCheckpointAppend(
        operation_id="operation:one",
        ledger_id="ledger:one",
        task_id="task:one",
        evidence_sequence=7,
        evidence_head_sha256=DIGEST_A,
        previous_receipt_digest=DIGEST_B,
        local_created_at=datetime.now(UTC),
    )


def receipt_for(request: ExternalCheckpointAppend) -> ExternalCheckpointReceipt:
    payload = {
        "schema_version": "external-checkpoint-receipt-v1",
        "provider_id": "independent-ledger",
        "provider_key_id": "key:one",
        "checkpoint_id": "checkpoint:one",
        "ledger_id": request.ledger_id,
        "task_id": request.task_id,
        "operation_id": request.operation_id,
        "request_digest": request.request_digest,
        "evidence_sequence": request.evidence_sequence,
        "evidence_head_sha256": request.evidence_head_sha256,
        "external_sequence": 19,
        "trusted_timestamp": datetime.now(UTC),
        "previous_receipt_digest": request.previous_receipt_digest,
    }
    return ExternalCheckpointReceipt(
        **payload,
        receipt_digest=content_digest(payload),
        provider_proof="provider-authenticated-proof",
    )


def test_disabled_checkpoint_is_truthfully_blocked_and_satisfies_interface() -> None:
    client = DisabledExternalCheckpointClient()

    assert isinstance(client, ExternalCheckpointClient)
    assert client.capability == ExternalCheckpointCapability(
        provider_id="disabled",
        configured=False,
        reachable=False,
        independently_retained=False,
        append_authorized=False,
        verified=False,
        operational=False,
        status=ExternalCheckpointStatus.BLOCKED,
        reason_code="not_configured",
    )


async def test_disabled_checkpoint_fails_closed_for_append_and_verification() -> None:
    client = DisabledExternalCheckpointClient(reason_code="independent_backend_absent")
    request = append_request()
    expectation = ExternalCheckpointExpectation(
        ledger_id=request.ledger_id,
        task_id=request.task_id,
        evidence_sequence=request.evidence_sequence,
        evidence_head_sha256=request.evidence_head_sha256,
        minimum_external_sequence=1,
    )

    with pytest.raises(ExternalCheckpointUnavailable, match="independent_backend_absent"):
        await client.append(request)
    with pytest.raises(ExternalCheckpointUnavailable, match="independent_backend_absent"):
        await client.assert_current(expectation)


def test_capability_cannot_claim_operational_without_every_prerequisite() -> None:
    with pytest.raises(ValidationError, match="operational status"):
        ExternalCheckpointCapability(
            provider_id="provider",
            configured=True,
            reachable=True,
            independently_retained=False,
            append_authorized=True,
            verified=True,
            operational=True,
            status=ExternalCheckpointStatus.OPERATIONAL,
            reason_code="ready",
        )


def test_receipt_is_bound_to_exact_evidence_head_and_external_sequence() -> None:
    request = append_request()
    receipt = receipt_for(request)
    expectation = ExternalCheckpointExpectation(
        ledger_id=request.ledger_id,
        task_id=request.task_id,
        evidence_sequence=request.evidence_sequence,
        evidence_head_sha256=request.evidence_head_sha256,
        minimum_external_sequence=receipt.external_sequence,
        expected_receipt_digest=receipt.receipt_digest,
    )

    assert_receipt_binding(receipt, expectation)

    stale = expectation.model_copy(
        update={"minimum_external_sequence": receipt.external_sequence + 1}
    )
    with pytest.raises(ExternalCheckpointMismatch):
        assert_receipt_binding(receipt, stale)

    wrong_head = expectation.model_copy(update={"evidence_head_sha256": DIGEST_B})
    with pytest.raises(ExternalCheckpointMismatch):
        assert_receipt_binding(receipt, wrong_head)


def test_receipt_rejects_local_timestamp_and_digest_forgery() -> None:
    request = append_request()
    receipt = receipt_for(request)

    with pytest.raises(ValidationError, match="timezone-aware"):
        ExternalCheckpointAppend(
            **request.model_dump(exclude={"local_created_at"}),
            local_created_at=datetime.now(),
        )

    with pytest.raises(ValidationError, match="receipt digest mismatch"):
        ExternalCheckpointReceipt(
            **receipt.model_dump(exclude={"receipt_digest"}),
            receipt_digest=DIGEST_B,
        )
