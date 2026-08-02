from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from liltweak.memory_governance import (
    MemoryDisposition,
    MemoryProvenance,
    MemoryRecord,
    MemoryReuseContext,
    MemoryStatus,
    apply_memory_assessment,
    assess_memory,
    create_memory_record,
    create_memory_tombstone,
    create_promotion_grant,
    promote_memory,
)

NOW = datetime(2026, 8, 2, 12, tzinfo=UTC)


def provenance() -> MemoryProvenance:
    return MemoryProvenance(
        repository_id="repo:demo",
        source_revision="a" * 40,
        source_tree_digest="1" * 64,
        task_digest="2" * 64,
        context_manifest_digest="3" * 64,
        prompt_digest="4" * 64,
        model_policy_digest="5" * 64,
        tool_registry_digest="6" * 64,
        effective_model="gpt-5.6-sol",
        verifier_principal="verifier:independent",
        evidence_digests=("7" * 64, "8" * 64),
        verified_at=NOW,
    )


def candidate() -> MemoryRecord:
    return create_memory_record(
        record_id="memory:one",
        kind="causal_claim",
        statement="The bounded retry prevented duplicate application.",
        outcome="verified_success",
        confidence=0.9,
        reusable_when=("repository and policy bindings remain exact",),
        provenance=provenance(),
        retention_until=NOW + timedelta(days=90),
    )


def reuse_context(**updates) -> MemoryReuseContext:
    values = {
        "repository_id": "repo:demo",
        "source_revision": "a" * 40,
        "source_tree_digest": "1" * 64,
        "active_model_policy_digest": "5" * 64,
        "active_tool_registry_digest": "6" * 64,
        "trusted_evidence_digests": ("7" * 64, "8" * 64),
        "quarantined_evidence_digests": (),
        "revoked_verifier_principals": (),
        "assessed_at": NOW + timedelta(days=1),
    }
    values.update(updates)
    return MemoryReuseContext(**values)


def test_memory_digest_and_promotion_authority_fail_closed() -> None:
    record = candidate()
    assert record.status == MemoryStatus.CANDIDATE
    hold = assess_memory(record, reuse_context())
    assert hold.disposition == MemoryDisposition.HOLD
    assert hold.reusable is False
    assert hold.reasons == ("promotion_required",)

    grant = create_promotion_grant(
        principal_id="owner:memory-reviewer",
        repository_id="repo:demo",
        candidate_record_digest=record.record_digest,
        authority_evidence_digest="9" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=2),
    )
    with pytest.raises(ValueError, match="not authorized"):
        promote_memory(
            record,
            grant,
            authorized_principals=frozenset(),
            now=NOW + timedelta(minutes=1),
        )

    promoted = promote_memory(
        record,
        grant,
        authorized_principals=frozenset({"owner:memory-reviewer"}),
        now=NOW + timedelta(minutes=1),
    )
    assert promoted.status == MemoryStatus.PROMOTED
    assert promoted.promotion_grant_digest == grant.grant_digest
    allowed = assess_memory(promoted, reuse_context())
    assert allowed.disposition == MemoryDisposition.REUSE
    assert allowed.reusable is True

    tampered = promoted.model_dump(mode="json")
    tampered["statement"] = "A forged claim."
    with pytest.raises(ValidationError, match="memory record digest mismatch"):
        MemoryRecord.model_validate(tampered)


def test_revision_drift_quarantine_and_invalidation_are_provenance_bound() -> None:
    record = candidate()
    revision_drift = assess_memory(record, reuse_context(source_revision="b" * 40))
    assert revision_drift.disposition == MemoryDisposition.INVALIDATE
    assert "source_revision_changed" in revision_drift.reasons
    invalidated = apply_memory_assessment(record, revision_drift)
    assert invalidated.status == MemoryStatus.INVALIDATED
    assert invalidated.promotion_grant_digest is None

    untrusted = assess_memory(record, reuse_context(trusted_evidence_digests=("7" * 64,)))
    assert untrusted.disposition == MemoryDisposition.QUARANTINE
    assert untrusted.reasons == ("evidence_not_trusted",)
    quarantined = apply_memory_assessment(record, untrusted)
    assert quarantined.status == MemoryStatus.QUARANTINED
    assert assess_memory(quarantined, reuse_context()).disposition == MemoryDisposition.QUARANTINE


def test_retention_and_deletion_create_non_content_tombstones() -> None:
    record = candidate()
    expired = assess_memory(record, reuse_context(assessed_at=NOW + timedelta(days=91)))
    assert expired.disposition == MemoryDisposition.INVALIDATE
    assert "retention_expired" in expired.reasons

    tombstone = create_memory_tombstone(
        record,
        deletion_authority_digest="f" * 64,
        deleted_at=NOW + timedelta(days=2),
    )
    assert tombstone.deleted_record_digest == record.record_digest
    assert "statement" not in tombstone.model_dump()
    assert "bounded retry" not in tombstone.model_dump_json()
