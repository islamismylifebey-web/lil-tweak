from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from liltweak.training_readiness import (
    TRAINING_EXECUTION_AVAILABLE,
    ExclusionReason,
    TrainingCandidate,
    TrainingLineage,
    TrainingReadinessReport,
    TrainingSplit,
    create_contamination_index,
    create_training_authority,
    create_training_candidate,
    prepare_training_readiness,
    training_content_digest,
    training_shingle_digests,
)

NOW = datetime(2026, 8, 2, 12, tzinfo=UTC)


def authority(*, authorized: bool = True):
    return create_training_authority(
        authority_id="authority:owner",
        basis="owner_created",
        license_id="owner-controlled-v1",
        training_use_authorized=authorized,
        authority_evidence_digest="a" * 64,
        privacy_review_digest="b" * 64,
    )


def lineage(
    *,
    repository_id: str = "repo:ordinary",
    task_id: str = "task:ordinary",
    memory_digest: str = "c" * 64,
    observed_at: datetime = NOW,
) -> TrainingLineage:
    return TrainingLineage(
        repository_id=repository_id,
        source_revision="d" * 40,
        task_id=task_id,
        task_digest="e" * 64,
        memory_record_digest=memory_digest,
        context_manifest_digest="f" * 64,
        prompt_digest="1" * 64,
        model_policy_digest="2" * 64,
        evidence_digests=("3" * 64, "4" * 64),
        observed_at=observed_at,
    )


def candidate(
    candidate_id: str,
    instruction: str,
    response: str,
    *,
    candidate_lineage: TrainingLineage | None = None,
    authorized: bool = True,
) -> TrainingCandidate:
    return create_training_candidate(
        candidate_id=candidate_id,
        instruction=instruction,
        response=response,
        lineage=candidate_lineage or lineage(),
        authority=authority(authorized=authorized),
    )


def test_training_readiness_redacts_deduplicates_splits_and_propagates_deletion() -> None:
    secret_instruction = (
        "Contact owner@example.com and use sk-proj-abcdefghijklmnopqrstuvwxyz012345 only in test."
    )
    safe_response = "The safe result is recorded with exact evidence."
    contaminated_instruction = "Evaluation-only incident analysis must never enter training."
    contaminated_response = "Preserve the blinded holdout evidence."
    candidates = (
        candidate(
            "case:001",
            secret_instruction,
            safe_response,
            candidate_lineage=lineage(repository_id="repo:holdout", task_id="task:a"),
        ),
        candidate(
            "case:002",
            secret_instruction,
            safe_response,
            candidate_lineage=lineage(repository_id="repo:duplicate", task_id="task:b"),
        ),
        candidate(
            "case:003",
            "Unlicensed source.",
            "Must be excluded.",
            authorized=False,
        ),
        candidate(
            "case:004",
            "Deleted memory source.",
            "Must propagate deletion.",
            candidate_lineage=lineage(memory_digest="5" * 64),
        ),
        candidate(
            "case:005",
            contaminated_instruction,
            contaminated_response,
        ),
        candidate(
            "case:006",
            "Task holdout source.",
            "Keep this outside training.",
            candidate_lineage=lineage(task_id="task:holdout"),
        ),
        candidate(
            "case:007",
            "Future observation.",
            "Keep this in the temporal holdout.",
            candidate_lineage=lineage(
                task_id="task:future",
                observed_at=NOW + timedelta(days=2),
            ),
        ),
    )
    contamination = create_contamination_index(
        index_id="index:release-eval",
        forbidden_content_digests=(
            training_content_digest(contaminated_instruction, contaminated_response),
        ),
        holdout_repository_ids=("repo:holdout",),
        holdout_task_ids=("task:holdout",),
        deleted_memory_record_digests=("5" * 64,),
    )
    report = prepare_training_readiness(
        candidates,
        dataset_id="dataset:readiness",
        contamination_index=contamination,
        temporal_cutoff=NOW + timedelta(days=1),
    )
    repeated = prepare_training_readiness(
        candidates,
        dataset_id="dataset:readiness",
        contamination_index=contamination,
        temporal_cutoff=NOW + timedelta(days=1),
    )

    assert report.report_digest == repeated.report_digest
    assert report.source_candidate_count == 7
    assert report.ready_case_count == 3
    assert report.export_only is True
    assert report.training_execution_enabled is False
    assert TRAINING_EXECUTION_AVAILABLE is False
    assert report.ready_for_human_review is True

    prepared = {item.candidate_id: item for item in report.cases}
    assert prepared["case:001"].split == TrainingSplit.REPOSITORY_HOLDOUT
    assert prepared["case:006"].split == TrainingSplit.TASK_HOLDOUT
    assert prepared["case:007"].split == TrainingSplit.TEMPORAL_HOLDOUT
    assert prepared["case:001"].redaction_rule_ids == (
        "email-address",
        "openai-api-key",
    )
    serialized = report.model_dump_json()
    assert "owner@example.com" not in serialized
    assert "sk-proj-abcdefghijklmnopqrstuvwxyz012345" not in serialized
    assert "[REDACTED:email-address]" in serialized

    excluded = {item.candidate_id: item for item in report.exclusions}
    assert excluded["case:002"].reason == ExclusionReason.EXACT_DUPLICATE
    assert excluded["case:003"].reason == ExclusionReason.UNAUTHORIZED
    assert excluded["case:004"].reason == ExclusionReason.SOURCE_DELETED
    assert excluded["case:005"].reason == ExclusionReason.EVALUATION_CONTAMINATION


def test_shingle_contamination_and_all_lineage_digests_fail_closed() -> None:
    evaluation_instruction = "one two three four five six seven eight nine ten"
    evaluation_response = "holdout response remains isolated"
    forbidden_shingles = training_shingle_digests(
        evaluation_instruction,
        evaluation_response,
    )
    source = candidate(
        "case:shingle",
        "prefix one two three four five six seven eight nine ten suffix",
        evaluation_response,
    )
    index = create_contamination_index(
        index_id="index:shingles",
        forbidden_shingle_digests=forbidden_shingles,
    )
    report = prepare_training_readiness(
        (source,),
        dataset_id="dataset:shingles",
        contamination_index=index,
        temporal_cutoff=NOW + timedelta(days=1),
    )
    assert report.cases == ()
    assert report.exclusions[0].reason == ExclusionReason.EVALUATION_CONTAMINATION
    assert report.training_execution_enabled is False

    tampered_candidate = source.model_dump(mode="json")
    tampered_candidate["response"] = "forged output"
    with pytest.raises(ValidationError, match="candidate digest mismatch"):
        TrainingCandidate.model_validate(tampered_candidate)

    tampered_report = report.model_dump(mode="json")
    tampered_report["report_digest"] = "0" * 64
    with pytest.raises(ValidationError, match="readiness report digest mismatch"):
        TrainingReadinessReport.model_validate(tampered_report)


def test_holdout_precedes_train_during_exact_deduplication() -> None:
    shared_instruction = "Identical example content must remain isolated."
    shared_response = "The protected holdout copy is canonical."
    sources = (
        candidate(
            "case:001",
            shared_instruction,
            shared_response,
            candidate_lineage=lineage(repository_id="repo:train", task_id="task:train"),
        ),
        candidate(
            "case:999",
            shared_instruction,
            shared_response,
            candidate_lineage=lineage(
                repository_id="repo:reserved",
                task_id="task:reserved-copy",
            ),
        ),
    )
    index = create_contamination_index(
        index_id="index:holdout-precedence",
        holdout_repository_ids=("repo:reserved",),
    )

    report = prepare_training_readiness(
        sources,
        dataset_id="dataset:holdout-precedence",
        contamination_index=index,
        temporal_cutoff=NOW + timedelta(days=1),
    )

    assert tuple(item.candidate_id for item in report.cases) == ("case:999",)
    assert report.cases[0].split == TrainingSplit.REPOSITORY_HOLDOUT
    assert tuple(item.candidate_id for item in report.exclusions) == ("case:001",)
    assert report.exclusions[0].reason == ExclusionReason.EXACT_DUPLICATE
    assert report.exclusions[0].related_digest == report.cases[0].case_digest


def test_train_shingle_overlap_with_holdout_is_contamination() -> None:
    holdout = candidate(
        "case:holdout",
        "alpha beta gamma delta epsilon zeta eta theta protected suffix",
        "This response remains in evaluation.",
        candidate_lineage=lineage(task_id="task:reserved"),
    )
    overlapping_train = candidate(
        "case:train",
        "train prefix alpha beta gamma delta epsilon zeta eta theta train suffix",
        "This is a distinct response.",
        candidate_lineage=lineage(repository_id="repo:train", task_id="task:train"),
    )
    index = create_contamination_index(
        index_id="index:cross-split",
        holdout_task_ids=("task:reserved",),
    )

    report = prepare_training_readiness(
        (overlapping_train, holdout),
        dataset_id="dataset:cross-split",
        contamination_index=index,
        temporal_cutoff=NOW + timedelta(days=1),
    )

    assert tuple(item.candidate_id for item in report.cases) == ("case:holdout",)
    assert report.cases[0].split == TrainingSplit.TASK_HOLDOUT
    assert tuple(item.candidate_id for item in report.exclusions) == ("case:train",)
    assert report.exclusions[0].reason == ExclusionReason.EVALUATION_CONTAMINATION
    assert report.exclusions[0].related_digest in report.cases[0].shingle_digests
