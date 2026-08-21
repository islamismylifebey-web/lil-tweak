from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictStr,
    field_validator,
    model_validator,
)
from pydantic_core import to_jsonable_python

SHA256 = r"^[0-9a-f]{64}$"
REVISION = r"^[0-9a-f]{40,64}$"
SAFE_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"


def canonical_json(value: object) -> str:
    return json.dumps(
        to_jsonable_python(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def content_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _aware(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


class MemorySchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class MemoryStatus(StrEnum):
    CANDIDATE = "candidate"
    PROMOTED = "promoted"
    QUARANTINED = "quarantined"
    INVALIDATED = "invalidated"


class MemoryDisposition(StrEnum):
    HOLD = "hold"
    REUSE = "reuse"
    QUARANTINE = "quarantine"
    INVALIDATE = "invalidate"


class MemoryProvenance(MemorySchema):
    repository_id: StrictStr = Field(pattern=SAFE_ID)
    source_revision: StrictStr = Field(pattern=REVISION)
    source_tree_digest: StrictStr = Field(pattern=SHA256)
    task_digest: StrictStr = Field(pattern=SHA256)
    context_manifest_digest: StrictStr = Field(pattern=SHA256)
    prompt_digest: StrictStr = Field(pattern=SHA256)
    model_policy_digest: StrictStr = Field(pattern=SHA256)
    tool_registry_digest: StrictStr = Field(pattern=SHA256)
    effective_model: StrictStr = Field(min_length=1, max_length=128)
    verifier_principal: StrictStr = Field(pattern=SAFE_ID)
    evidence_digests: tuple[StrictStr, ...] = Field(min_length=1, max_length=128)
    verified_at: datetime

    @field_validator(
        "source_tree_digest",
        "task_digest",
        "context_manifest_digest",
        "prompt_digest",
        "model_policy_digest",
        "tool_registry_digest",
        "evidence_digests",
    )
    @classmethod
    def digest_fields_are_lowercase_sha256(
        cls, value: str | tuple[str, ...]
    ) -> str | tuple[str, ...]:
        values = value if isinstance(value, tuple) else (value,)
        if any(
            not isinstance(item, str)
            or len(item) != 64
            or any(character not in "0123456789abcdef" for character in item)
            for item in values
        ):
            raise ValueError("memory provenance digests must be lowercase SHA-256")
        return value

    @field_validator("evidence_digests")
    @classmethod
    def evidence_is_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("evidence digests must be unique and sorted")
        return value

    @field_validator("verified_at")
    @classmethod
    def verified_time_is_aware(cls, value: datetime) -> datetime:
        return _aware(value, label="verified_at")


class MemoryRecord(MemorySchema):
    schema_version: Literal["memory-record-v1"] = "memory-record-v1"
    record_id: StrictStr = Field(pattern=SAFE_ID)
    kind: Literal["verified_outcome", "causal_claim", "procedure_guardrail"]
    statement: StrictStr = Field(min_length=1, max_length=4_000)
    outcome: Literal["verified_success", "verified_failure", "safety_constraint"]
    confidence: StrictFloat = Field(ge=0, le=1)
    reusable_when: tuple[StrictStr, ...] = Field(min_length=1, max_length=32)
    provenance: MemoryProvenance
    status: MemoryStatus = MemoryStatus.CANDIDATE
    retention_until: datetime
    promotion_grant_digest: StrictStr | None = Field(default=None, pattern=SHA256)
    quarantine_reasons: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=32)
    invalidation_reasons: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=32)
    record_digest: StrictStr = Field(pattern=SHA256)

    @field_validator("retention_until")
    @classmethod
    def retention_time_is_aware(cls, value: datetime) -> datetime:
        return _aware(value, label="retention_until")

    @field_validator("reusable_when", "quarantine_reasons", "invalidation_reasons")
    @classmethod
    def bounded_reasons_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item.strip() for item in value) or len(set(value)) != len(value):
            raise ValueError("memory conditions and reasons must be non-empty and unique")
        return value

    @model_validator(mode="after")
    def status_and_digest_are_bound(self) -> MemoryRecord:
        if self.retention_until <= self.provenance.verified_at:
            raise ValueError("memory retention must extend beyond verification")
        if self.status == MemoryStatus.CANDIDATE and (
            self.promotion_grant_digest or self.quarantine_reasons or self.invalidation_reasons
        ):
            raise ValueError("candidate memory cannot claim promotion or adverse disposition")
        if self.status == MemoryStatus.PROMOTED and (
            self.promotion_grant_digest is None
            or self.quarantine_reasons
            or self.invalidation_reasons
        ):
            raise ValueError("promoted memory requires one grant and no adverse disposition")
        if self.status == MemoryStatus.QUARANTINED and (
            not self.quarantine_reasons or self.promotion_grant_digest is not None
        ):
            raise ValueError("quarantined memory requires reasons and cannot remain promoted")
        if self.status == MemoryStatus.INVALIDATED and (
            not self.invalidation_reasons or self.promotion_grant_digest is not None
        ):
            raise ValueError("invalidated memory requires reasons and cannot remain promoted")
        unsigned = self.model_dump(mode="json", exclude={"record_digest"})
        if self.record_digest != content_digest(unsigned):
            raise ValueError("memory record digest mismatch")
        return self


class PromotionGrant(MemorySchema):
    schema_version: Literal["memory-promotion-grant-v1"] = "memory-promotion-grant-v1"
    principal_id: StrictStr = Field(pattern=SAFE_ID)
    authority_scope: Literal["memory:promote"] = "memory:promote"
    repository_id: StrictStr = Field(pattern=SAFE_ID)
    candidate_record_digest: StrictStr = Field(pattern=SHA256)
    authority_evidence_digest: StrictStr = Field(pattern=SHA256)
    issued_at: datetime
    expires_at: datetime
    grant_digest: StrictStr = Field(pattern=SHA256)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def grant_times_are_aware(cls, value: datetime) -> datetime:
        return _aware(value, label="promotion grant time")

    @model_validator(mode="after")
    def grant_is_bounded_and_bound(self) -> PromotionGrant:
        if self.expires_at <= self.issued_at:
            raise ValueError("promotion grant expiry must follow issuance")
        unsigned = self.model_dump(mode="json", exclude={"grant_digest"})
        if self.grant_digest != content_digest(unsigned):
            raise ValueError("promotion grant digest mismatch")
        return self


class MemoryReuseContext(MemorySchema):
    repository_id: StrictStr = Field(pattern=SAFE_ID)
    source_revision: StrictStr = Field(pattern=REVISION)
    source_tree_digest: StrictStr = Field(pattern=SHA256)
    active_model_policy_digest: StrictStr = Field(pattern=SHA256)
    active_tool_registry_digest: StrictStr = Field(pattern=SHA256)
    trusted_evidence_digests: tuple[StrictStr, ...] = Field(max_length=1_000)
    quarantined_evidence_digests: tuple[StrictStr, ...] = Field(max_length=1_000)
    revoked_verifier_principals: tuple[StrictStr, ...] = Field(max_length=1_000)
    assessed_at: datetime

    @field_validator(
        "trusted_evidence_digests",
        "quarantined_evidence_digests",
    )
    @classmethod
    def evidence_sets_are_sha256_and_sorted(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(SHA256, item) is None for item in value):
            raise ValueError("reuse-context evidence must be lowercase SHA-256")
        if tuple(sorted(set(value))) != value:
            raise ValueError("reuse-context sets must be unique and sorted")
        return value

    @field_validator("revoked_verifier_principals")
    @classmethod
    def revoked_principals_are_safe_and_sorted(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(SAFE_ID, item) is None for item in value):
            raise ValueError("revoked verifier principals must be safe identifiers")
        if tuple(sorted(set(value))) != value:
            raise ValueError("revoked verifier principals must be unique and sorted")
        return value

    @field_validator("assessed_at")
    @classmethod
    def assessment_time_is_aware(cls, value: datetime) -> datetime:
        return _aware(value, label="assessed_at")


class MemoryAssessment(MemorySchema):
    schema_version: Literal["memory-assessment-v1"] = "memory-assessment-v1"
    record_digest: StrictStr = Field(pattern=SHA256)
    disposition: MemoryDisposition
    reusable: StrictBool
    reasons: tuple[StrictStr, ...] = Field(min_length=1, max_length=32)
    assessed_at: datetime
    assessment_digest: StrictStr = Field(pattern=SHA256)

    @field_validator("assessed_at")
    @classmethod
    def assessment_time_is_aware(cls, value: datetime) -> datetime:
        return _aware(value, label="assessed_at")

    @field_validator("reasons")
    @classmethod
    def reasons_are_exact_and_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not reason.strip() for reason in value) or len(set(value)) != len(value):
            raise ValueError("memory assessment reasons must be non-empty and unique")
        return value

    @model_validator(mode="after")
    def decision_and_digest_are_bound(self) -> MemoryAssessment:
        if self.reusable != (self.disposition == MemoryDisposition.REUSE):
            raise ValueError("only a reuse disposition can be reusable")
        unsigned = self.model_dump(mode="json", exclude={"assessment_digest"})
        if self.assessment_digest != content_digest(unsigned):
            raise ValueError("memory assessment digest mismatch")
        return self


class MemoryTombstone(MemorySchema):
    schema_version: Literal["memory-tombstone-v1"] = "memory-tombstone-v1"
    record_id: StrictStr = Field(pattern=SAFE_ID)
    deleted_record_digest: StrictStr = Field(pattern=SHA256)
    deletion_authority_digest: StrictStr = Field(pattern=SHA256)
    deleted_at: datetime
    tombstone_digest: StrictStr = Field(pattern=SHA256)

    @field_validator("deleted_at")
    @classmethod
    def deletion_time_is_aware(cls, value: datetime) -> datetime:
        return _aware(value, label="deleted_at")

    @model_validator(mode="after")
    def tombstone_digest_is_bound(self) -> MemoryTombstone:
        unsigned = self.model_dump(mode="json", exclude={"tombstone_digest"})
        if self.tombstone_digest != content_digest(unsigned):
            raise ValueError("memory tombstone digest mismatch")
        return self


def create_memory_record(
    *,
    record_id: str,
    kind: str,
    statement: str,
    outcome: str,
    confidence: float,
    reusable_when: tuple[str, ...],
    provenance: MemoryProvenance,
    retention_until: datetime,
) -> MemoryRecord:
    values = {
        "schema_version": "memory-record-v1",
        "record_id": record_id,
        "kind": kind,
        "statement": statement,
        "outcome": outcome,
        "confidence": confidence,
        "reusable_when": reusable_when,
        "provenance": provenance,
        "status": MemoryStatus.CANDIDATE,
        "retention_until": retention_until,
        "promotion_grant_digest": None,
        "quarantine_reasons": (),
        "invalidation_reasons": (),
    }
    return MemoryRecord(**values, record_digest=content_digest(values))


def create_promotion_grant(
    *,
    principal_id: str,
    repository_id: str,
    candidate_record_digest: str,
    authority_evidence_digest: str,
    issued_at: datetime,
    expires_at: datetime,
) -> PromotionGrant:
    values = {
        "schema_version": "memory-promotion-grant-v1",
        "principal_id": principal_id,
        "authority_scope": "memory:promote",
        "repository_id": repository_id,
        "candidate_record_digest": candidate_record_digest,
        "authority_evidence_digest": authority_evidence_digest,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
    return PromotionGrant(**values, grant_digest=content_digest(values))


def _replace_record(record: MemoryRecord, **updates: object) -> MemoryRecord:
    values = record.model_dump(mode="python", exclude={"record_digest"})
    values.update(updates)
    return MemoryRecord(**values, record_digest=content_digest(values))


def promote_memory(
    record: MemoryRecord,
    grant: PromotionGrant,
    *,
    authorized_principals: frozenset[str],
    now: datetime,
) -> MemoryRecord:
    active_time = _aware(now, label="promotion time")
    if record.status != MemoryStatus.CANDIDATE:
        raise ValueError("only a clean candidate memory can be promoted")
    if grant.principal_id not in authorized_principals:
        raise ValueError("promotion principal is not authorized")
    if grant.repository_id != record.provenance.repository_id:
        raise ValueError("promotion grant is bound to another repository")
    if grant.candidate_record_digest != record.record_digest:
        raise ValueError("promotion grant is bound to another memory record")
    if not (grant.issued_at <= active_time < grant.expires_at):
        raise ValueError("promotion grant is not currently active")
    if active_time >= record.retention_until:
        raise ValueError("expired memory cannot be promoted")
    return _replace_record(
        record,
        status=MemoryStatus.PROMOTED,
        promotion_grant_digest=grant.grant_digest,
    )


def assess_memory(record: MemoryRecord, context: MemoryReuseContext) -> MemoryAssessment:
    invalidation_reasons: list[str] = []
    quarantine_reasons: list[str] = []
    provenance = record.provenance
    if context.assessed_at >= record.retention_until:
        invalidation_reasons.append("retention_expired")
    if context.repository_id != provenance.repository_id:
        invalidation_reasons.append("repository_changed")
    if context.source_revision != provenance.source_revision:
        invalidation_reasons.append("source_revision_changed")
    if context.source_tree_digest != provenance.source_tree_digest:
        invalidation_reasons.append("source_tree_changed")
    if context.active_model_policy_digest != provenance.model_policy_digest:
        invalidation_reasons.append("model_policy_changed")
    if context.active_tool_registry_digest != provenance.tool_registry_digest:
        invalidation_reasons.append("tool_registry_changed")
    if provenance.verifier_principal in context.revoked_verifier_principals:
        quarantine_reasons.append("verifier_revoked")
    trusted = set(context.trusted_evidence_digests)
    quarantined = set(context.quarantined_evidence_digests)
    if not set(provenance.evidence_digests).issubset(trusted):
        quarantine_reasons.append("evidence_not_trusted")
    if set(provenance.evidence_digests).intersection(quarantined):
        quarantine_reasons.append("evidence_quarantined")

    if record.status == MemoryStatus.INVALIDATED:
        invalidation_reasons.extend(record.invalidation_reasons)
    if invalidation_reasons:
        disposition = MemoryDisposition.INVALIDATE
        reasons = tuple(dict.fromkeys(invalidation_reasons))
    elif record.status == MemoryStatus.QUARANTINED:
        disposition = MemoryDisposition.QUARANTINE
        reasons = tuple(dict.fromkeys((*record.quarantine_reasons, *quarantine_reasons)))
    elif quarantine_reasons:
        disposition = MemoryDisposition.QUARANTINE
        reasons = tuple(dict.fromkeys(quarantine_reasons))
    elif record.status != MemoryStatus.PROMOTED:
        disposition = MemoryDisposition.HOLD
        reasons = ("promotion_required",)
    else:
        disposition = MemoryDisposition.REUSE
        reasons = ("all_provenance_and_authority_gates_satisfied",)
    values = {
        "schema_version": "memory-assessment-v1",
        "record_digest": record.record_digest,
        "disposition": disposition,
        "reusable": disposition == MemoryDisposition.REUSE,
        "reasons": reasons,
        "assessed_at": context.assessed_at,
    }
    return MemoryAssessment(**values, assessment_digest=content_digest(values))


def apply_memory_assessment(
    record: MemoryRecord,
    assessment: MemoryAssessment,
) -> MemoryRecord:
    if assessment.record_digest != record.record_digest:
        raise ValueError("memory assessment is bound to another record")
    if assessment.disposition == MemoryDisposition.INVALIDATE:
        return _replace_record(
            record,
            status=MemoryStatus.INVALIDATED,
            promotion_grant_digest=None,
            quarantine_reasons=(),
            invalidation_reasons=assessment.reasons,
        )
    if assessment.disposition == MemoryDisposition.QUARANTINE:
        return _replace_record(
            record,
            status=MemoryStatus.QUARANTINED,
            promotion_grant_digest=None,
            quarantine_reasons=assessment.reasons,
            invalidation_reasons=(),
        )
    return record


def create_memory_tombstone(
    record: MemoryRecord,
    *,
    deletion_authority_digest: str,
    deleted_at: datetime,
) -> MemoryTombstone:
    values = {
        "schema_version": "memory-tombstone-v1",
        "record_id": record.record_id,
        "deleted_record_digest": record.record_digest,
        "deletion_authority_digest": deletion_authority_digest,
        "deleted_at": _aware(deleted_at, label="deleted_at"),
    }
    return MemoryTombstone(**values, tombstone_digest=content_digest(values))
