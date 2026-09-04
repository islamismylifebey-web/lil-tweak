"""Exact approval and evidence validation for registry decisions."""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from .registry_types import (
    ApprovalRecord,
    DecisionRequest,
    EvidenceReference,
    ReasonCode,
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TRUSTED_LOCATORS = frozenset({"CORE_DB", "R2_IMMUTABLE", "GITHUB_EXACT_COMMIT"})
_TRUSTED_SOURCES = {
    "CORE_DB": "trusted-core",
    "R2_IMMUTABLE": "r2",
    "GITHUB_EXACT_COMMIT": "github",
}
_EVIDENCE_TYPES = frozenset(
    {
        "artifact",
        "build",
        "lint",
        "review",
        "security_scan",
        "tests",
        "verification",
    }
)


def _valid_utc(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() is not None
        and value.utcoffset() == timedelta(0)
    )


def validate_approval(
    record,
    request,
    target_digest,
    now,
    superseded_at=None,
) -> ReasonCode | None:
    """Return a stable failure code, or ``None`` for an exact valid approval."""

    try:
        if not isinstance(record, ApprovalRecord) or not isinstance(request, DecisionRequest):
            return ReasonCode.INTEGRITY_CHECK_FAILED
        record.validate()
        request.validate()
        if not isinstance(target_digest, str) or _SHA256_RE.fullmatch(target_digest) is None:
            return ReasonCode.INTEGRITY_CHECK_FAILED
        if not _valid_utc(now):
            return ReasonCode.INTEGRITY_CHECK_FAILED
        if superseded_at is not None and not _valid_utc(superseded_at):
            return ReasonCode.INTEGRITY_CHECK_FAILED
    except Exception:
        return ReasonCode.INTEGRITY_CHECK_FAILED

    if not record.authenticated:
        return ReasonCode.INACTIVE_PRINCIPAL
    if record.revoked_at is not None and record.revoked_at <= now:
        return ReasonCode.REVOKED_APPROVAL
    if record.issued_at > now or record.expires_at <= now:
        return ReasonCode.STALE_APPROVAL
    if record.target_digest != target_digest:
        return ReasonCode.WRONG_DIGEST_BINDING
    if (
        record.owner_id != request.owner_id
        or record.requester_id != request.requester_id
        or record.agent_id != request.agent_id
        or record.asset_id != request.asset_id
        or record.action_class is not request.action_class
        or record.operation_intent is not request.operation_intent
        or record.environment is not request.environment
    ):
        return ReasonCode.WRONG_DIGEST_BINDING
    if (
        superseded_at is not None
        and superseded_at > record.issued_at
        and superseded_at <= now
    ):
        return ReasonCode.STALE_APPROVAL
    return None


def validate_evidence(reference, request, target_digest) -> ReasonCode | None:
    """Validate the supplied trusted-reference record without claiming artifact existence."""

    try:
        if not isinstance(reference, EvidenceReference) or not isinstance(request, DecisionRequest):
            return ReasonCode.INTEGRITY_CHECK_FAILED
        reference.validate()
        request.validate()
        if not isinstance(target_digest, str) or _SHA256_RE.fullmatch(target_digest) is None:
            return ReasonCode.INTEGRITY_CHECK_FAILED
    except Exception:
        return ReasonCode.INTEGRITY_CHECK_FAILED

    if reference.digest_algorithm != "sha256":
        return ReasonCode.INTEGRITY_CHECK_FAILED
    if _SHA256_RE.fullmatch(reference.content_digest) is None:
        return ReasonCode.INTEGRITY_CHECK_FAILED
    if reference.locator_class not in _TRUSTED_LOCATORS:
        return ReasonCode.INTEGRITY_CHECK_FAILED
    if not reference.locator or len(reference.locator) > 2048:
        return ReasonCode.INTEGRITY_CHECK_FAILED
    if reference.evidence_type not in _EVIDENCE_TYPES:
        return ReasonCode.INTEGRITY_CHECK_FAILED
    if reference.source_system != _TRUSTED_SOURCES[reference.locator_class]:
        return ReasonCode.INTEGRITY_CHECK_FAILED
    if not _valid_utc(reference.created_at):
        return ReasonCode.INTEGRITY_CHECK_FAILED
    if not reference.asserted_safe:
        return ReasonCode.INTEGRITY_CHECK_FAILED
    if reference.owner_id != request.owner_id or reference.target_digest != target_digest:
        return ReasonCode.WRONG_DIGEST_BINDING
    if request.source_revision is not None:
        if reference.source_revision != request.source_revision:
            return ReasonCode.WRONG_DIGEST_BINDING
        if (
            reference.locator_class == "GITHUB_EXACT_COMMIT"
            and not reference.locator.endswith("@" + request.source_revision)
        ):
            return ReasonCode.WRONG_DIGEST_BINDING
    return None
