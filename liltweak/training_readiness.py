from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)
from pydantic_core import to_jsonable_python

SHA256 = r"^[0-9a-f]{64}$"
REVISION = r"^[0-9a-f]{40,64}$"
SAFE_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
TRAINING_EXECUTION_AVAILABLE = False

_REDACTION_RULES = (
    (
        "private-key",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?"
            r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    ("openai-api-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    (
        "credential-assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
            r"password|secret)\b\s*[:=]\s*[\"']?[A-Za-z0-9_./+=-]{8,}"
        ),
    ),
    (
        "email-address",
        re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b"),
    ),
    (
        "phone-number",
        re.compile(r"(?<!\d)(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}(?!\d)"),
    ),
)


def canonical_json(value: object) -> str:
    return json.dumps(
        to_jsonable_python(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def content_digest(value: object) -> str:
    payload = value if isinstance(value, str) else canonical_json(value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _aware(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _unique_sorted(value: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    if tuple(sorted(set(value))) != value:
        raise ValueError(f"{label} must be unique and sorted")
    return value


class TrainingSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TrainingSplit(StrEnum):
    TRAIN = "train"
    REPOSITORY_HOLDOUT = "repository_holdout"
    TASK_HOLDOUT = "task_holdout"
    TEMPORAL_HOLDOUT = "temporal_holdout"


class ExclusionReason(StrEnum):
    UNAUTHORIZED = "training_use_not_authorized"
    SOURCE_DELETED = "source_memory_deleted"
    EXACT_DUPLICATE = "exact_duplicate"
    EVALUATION_CONTAMINATION = "evaluation_contamination"


class TrainingAuthority(TrainingSchema):
    schema_version: Literal["training-authority-v1"] = "training-authority-v1"
    authority_id: StrictStr = Field(pattern=SAFE_ID)
    basis: Literal["owner_created", "permissive_license", "contractual_permission"]
    license_id: StrictStr = Field(min_length=1, max_length=128)
    training_use_authorized: StrictBool
    authority_evidence_digest: StrictStr = Field(pattern=SHA256)
    privacy_review_digest: StrictStr = Field(pattern=SHA256)
    authority_digest: StrictStr = Field(pattern=SHA256)

    @model_validator(mode="after")
    def authority_digest_is_exact(self) -> TrainingAuthority:
        unsigned = self.model_dump(mode="json", exclude={"authority_digest"})
        if self.authority_digest != content_digest(unsigned):
            raise ValueError("training authority digest mismatch")
        return self


class TrainingLineage(TrainingSchema):
    repository_id: StrictStr = Field(pattern=SAFE_ID)
    source_revision: StrictStr = Field(pattern=REVISION)
    task_id: StrictStr = Field(pattern=SAFE_ID)
    task_digest: StrictStr = Field(pattern=SHA256)
    memory_record_digest: StrictStr = Field(pattern=SHA256)
    context_manifest_digest: StrictStr = Field(pattern=SHA256)
    prompt_digest: StrictStr = Field(pattern=SHA256)
    model_policy_digest: StrictStr = Field(pattern=SHA256)
    evidence_digests: tuple[StrictStr, ...] = Field(min_length=1, max_length=128)
    observed_at: datetime

    @field_validator("evidence_digests")
    @classmethod
    def evidence_is_unique_and_sorted(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(SHA256, item) is None for item in value):
            raise ValueError("training evidence must be lowercase SHA-256")
        return _unique_sorted(value, label="training evidence digests")

    @field_validator("observed_at")
    @classmethod
    def observed_time_is_aware(cls, value: datetime) -> datetime:
        return _aware(value, label="observed_at")


class TrainingCandidate(TrainingSchema):
    schema_version: Literal["training-candidate-v1"] = "training-candidate-v1"
    candidate_id: StrictStr = Field(pattern=SAFE_ID)
    instruction: StrictStr = Field(min_length=1, max_length=64_000)
    response: StrictStr = Field(min_length=1, max_length=64_000)
    lineage: TrainingLineage
    authority: TrainingAuthority
    candidate_digest: StrictStr = Field(pattern=SHA256)

    @model_validator(mode="after")
    def candidate_digest_is_exact(self) -> TrainingCandidate:
        unsigned = self.model_dump(mode="json", exclude={"candidate_digest"})
        if self.candidate_digest != content_digest(unsigned):
            raise ValueError("training candidate digest mismatch")
        return self


class RedactedText(TrainingSchema):
    text: StrictStr = Field(max_length=64_000)
    original_sha256: StrictStr = Field(pattern=SHA256)
    redacted_sha256: StrictStr = Field(pattern=SHA256)
    rule_ids: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=32)
    changed: StrictBool

    @model_validator(mode="after")
    def redacted_text_is_bound(self) -> RedactedText:
        if self.redacted_sha256 != content_digest(self.text):
            raise ValueError("redacted text digest mismatch")
        if self.changed != bool(self.rule_ids):
            raise ValueError("redaction change flag must match applied rules")
        if len(set(self.rule_ids)) != len(self.rule_ids):
            raise ValueError("redaction rules must be unique")
        return self


class ContaminationIndex(TrainingSchema):
    schema_version: Literal["contamination-index-v1"] = "contamination-index-v1"
    index_id: StrictStr = Field(pattern=SAFE_ID)
    forbidden_content_digests: tuple[StrictStr, ...] = Field(max_length=100_000)
    forbidden_shingle_digests: tuple[StrictStr, ...] = Field(max_length=1_000_000)
    holdout_repository_ids: tuple[StrictStr, ...] = Field(max_length=100_000)
    holdout_task_ids: tuple[StrictStr, ...] = Field(max_length=100_000)
    deleted_memory_record_digests: tuple[StrictStr, ...] = Field(max_length=100_000)
    index_digest: StrictStr = Field(pattern=SHA256)

    @field_validator(
        "forbidden_content_digests",
        "forbidden_shingle_digests",
        "holdout_repository_ids",
        "holdout_task_ids",
        "deleted_memory_record_digests",
    )
    @classmethod
    def index_sets_are_unique_and_sorted(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, label="contamination index sets")

    @field_validator(
        "forbidden_content_digests",
        "forbidden_shingle_digests",
        "deleted_memory_record_digests",
    )
    @classmethod
    def index_digests_are_sha256(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(SHA256, item) is None for item in value):
            raise ValueError("contamination digests must be lowercase SHA-256")
        return value

    @field_validator("holdout_repository_ids", "holdout_task_ids")
    @classmethod
    def holdout_ids_are_safe(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(SAFE_ID, item) is None for item in value):
            raise ValueError("holdout identifiers must be safe identifiers")
        return value

    @model_validator(mode="after")
    def index_digest_is_exact(self) -> ContaminationIndex:
        unsigned = self.model_dump(mode="json", exclude={"index_digest"})
        if self.index_digest != content_digest(unsigned):
            raise ValueError("contamination index digest mismatch")
        return self


class PreparedTrainingCase(TrainingSchema):
    schema_version: Literal["prepared-training-case-v1"] = "prepared-training-case-v1"
    candidate_id: StrictStr = Field(pattern=SAFE_ID)
    split: TrainingSplit
    instruction: StrictStr = Field(min_length=1, max_length=64_000)
    response: StrictStr = Field(min_length=1, max_length=64_000)
    content_digest: StrictStr = Field(pattern=SHA256)
    shingle_digests: tuple[StrictStr, ...] = Field(min_length=1, max_length=20_000)
    redaction_rule_ids: tuple[StrictStr, ...] = Field(max_length=64)
    source_candidate_digest: StrictStr = Field(pattern=SHA256)
    lineage: TrainingLineage
    authority_digest: StrictStr = Field(pattern=SHA256)
    case_digest: StrictStr = Field(pattern=SHA256)

    @field_validator("shingle_digests", "redaction_rule_ids")
    @classmethod
    def prepared_sets_are_unique_and_sorted(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _unique_sorted(value, label="prepared case sets")

    @model_validator(mode="after")
    def case_content_and_digest_are_exact(self) -> PreparedTrainingCase:
        if self.content_digest != _pair_digest(self.instruction, self.response):
            raise ValueError("prepared training content digest mismatch")
        if self.shingle_digests != _pair_shingles(self.instruction, self.response):
            raise ValueError("prepared training shingle digests mismatch")
        unsigned = self.model_dump(mode="json", exclude={"case_digest"})
        if self.case_digest != content_digest(unsigned):
            raise ValueError("prepared training case digest mismatch")
        return self


class TrainingExclusion(TrainingSchema):
    candidate_id: StrictStr = Field(pattern=SAFE_ID)
    source_candidate_digest: StrictStr = Field(pattern=SHA256)
    reason: ExclusionReason
    related_digest: StrictStr | None = Field(default=None, pattern=SHA256)
    exclusion_digest: StrictStr = Field(pattern=SHA256)

    @model_validator(mode="after")
    def exclusion_digest_is_exact(self) -> TrainingExclusion:
        unsigned = self.model_dump(mode="json", exclude={"exclusion_digest"})
        if self.exclusion_digest != content_digest(unsigned):
            raise ValueError("training exclusion digest mismatch")
        return self


class SplitCount(TrainingSchema):
    split: TrainingSplit
    count: StrictInt = Field(ge=0, le=1_000_000)


class TrainingReadinessReport(TrainingSchema):
    schema_version: Literal["training-readiness-v1"] = "training-readiness-v1"
    dataset_id: StrictStr = Field(pattern=SAFE_ID)
    source_candidate_count: StrictInt = Field(ge=0, le=1_000_000)
    ready_case_count: StrictInt = Field(ge=0, le=1_000_000)
    cases: tuple[PreparedTrainingCase, ...] = Field(max_length=1_000_000)
    exclusions: tuple[TrainingExclusion, ...] = Field(max_length=1_000_000)
    split_counts: tuple[SplitCount, ...] = Field(min_length=4, max_length=4)
    contamination_index_digest: StrictStr = Field(pattern=SHA256)
    temporal_cutoff: datetime
    export_only: Literal[True] = True
    training_execution_enabled: Literal[False] = False
    ready_for_human_review: StrictBool
    report_digest: StrictStr = Field(pattern=SHA256)

    @field_validator("temporal_cutoff")
    @classmethod
    def cutoff_is_aware(cls, value: datetime) -> datetime:
        return _aware(value, label="temporal_cutoff")

    @model_validator(mode="after")
    def counts_order_and_digest_are_exact(self) -> TrainingReadinessReport:
        if self.ready_case_count != len(self.cases):
            raise ValueError("ready case count does not match prepared cases")
        if self.source_candidate_count != len(self.cases) + len(self.exclusions):
            raise ValueError("source count does not reconcile with cases and exclusions")
        if tuple(item.candidate_id for item in self.cases) != tuple(
            sorted(item.candidate_id for item in self.cases)
        ):
            raise ValueError("prepared cases must be candidate-id sorted")
        if tuple(item.candidate_id for item in self.exclusions) != tuple(
            sorted(item.candidate_id for item in self.exclusions)
        ):
            raise ValueError("training exclusions must be candidate-id sorted")
        expected_splits = tuple(TrainingSplit)
        if tuple(item.split for item in self.split_counts) != expected_splits:
            raise ValueError("split counts must report every split in canonical order")
        actual = {split: 0 for split in TrainingSplit}
        for case in self.cases:
            actual[case.split] += 1
        if any(item.count != actual[item.split] for item in self.split_counts):
            raise ValueError("split counts do not match prepared cases")
        if self.ready_for_human_review != bool(self.cases):
            raise ValueError("human-review readiness must reflect prepared cases")
        unsigned = self.model_dump(mode="json", exclude={"report_digest"})
        if self.report_digest != content_digest(unsigned):
            raise ValueError("training readiness report digest mismatch")
        return self


def redact_training_text(text: str) -> RedactedText:
    redacted = text
    applied: list[str] = []
    for rule_id, pattern in _REDACTION_RULES:
        redacted, count = pattern.subn(f"[REDACTED:{rule_id}]", redacted)
        if count:
            applied.append(rule_id)
    return RedactedText(
        text=redacted,
        original_sha256=content_digest(text),
        redacted_sha256=content_digest(redacted),
        rule_ids=tuple(applied),
        changed=bool(applied),
    )


def _normalized(value: str) -> str:
    return " ".join(unicodedata.normalize("NFC", value).casefold().split())


def _pair_digest(instruction: str, response: str) -> str:
    return content_digest(
        {"instruction": _normalized(instruction), "response": _normalized(response)}
    )


def _pair_shingles(instruction: str, response: str) -> tuple[str, ...]:
    tokens = _normalized(f"{instruction} {response}").split()
    if not tokens:
        return (content_digest(""),)
    width = min(8, len(tokens))
    return tuple(
        sorted(
            {
                content_digest(" ".join(tokens[index : index + width]))
                for index in range(len(tokens) - width + 1)
            }
        )
    )


def training_content_digest(instruction: str, response: str) -> str:
    return _pair_digest(
        redact_training_text(instruction).text,
        redact_training_text(response).text,
    )


def training_shingle_digests(instruction: str, response: str) -> tuple[str, ...]:
    return _pair_shingles(
        redact_training_text(instruction).text,
        redact_training_text(response).text,
    )


def create_training_authority(
    *,
    authority_id: str,
    basis: str,
    license_id: str,
    training_use_authorized: bool,
    authority_evidence_digest: str,
    privacy_review_digest: str,
) -> TrainingAuthority:
    values = {
        "schema_version": "training-authority-v1",
        "authority_id": authority_id,
        "basis": basis,
        "license_id": license_id,
        "training_use_authorized": training_use_authorized,
        "authority_evidence_digest": authority_evidence_digest,
        "privacy_review_digest": privacy_review_digest,
    }
    return TrainingAuthority(**values, authority_digest=content_digest(values))


def create_training_candidate(
    *,
    candidate_id: str,
    instruction: str,
    response: str,
    lineage: TrainingLineage,
    authority: TrainingAuthority,
) -> TrainingCandidate:
    values = {
        "schema_version": "training-candidate-v1",
        "candidate_id": candidate_id,
        "instruction": instruction,
        "response": response,
        "lineage": lineage,
        "authority": authority,
    }
    return TrainingCandidate(**values, candidate_digest=content_digest(values))


def create_contamination_index(
    *,
    index_id: str,
    forbidden_content_digests: tuple[str, ...] = (),
    forbidden_shingle_digests: tuple[str, ...] = (),
    holdout_repository_ids: tuple[str, ...] = (),
    holdout_task_ids: tuple[str, ...] = (),
    deleted_memory_record_digests: tuple[str, ...] = (),
) -> ContaminationIndex:
    values = {
        "schema_version": "contamination-index-v1",
        "index_id": index_id,
        "forbidden_content_digests": tuple(sorted(set(forbidden_content_digests))),
        "forbidden_shingle_digests": tuple(sorted(set(forbidden_shingle_digests))),
        "holdout_repository_ids": tuple(sorted(set(holdout_repository_ids))),
        "holdout_task_ids": tuple(sorted(set(holdout_task_ids))),
        "deleted_memory_record_digests": tuple(sorted(set(deleted_memory_record_digests))),
    }
    return ContaminationIndex(**values, index_digest=content_digest(values))


def _split(lineage: TrainingLineage, index: ContaminationIndex, cutoff: datetime) -> TrainingSplit:
    if lineage.repository_id in index.holdout_repository_ids:
        return TrainingSplit.REPOSITORY_HOLDOUT
    if lineage.task_id in index.holdout_task_ids:
        return TrainingSplit.TASK_HOLDOUT
    if lineage.observed_at >= cutoff:
        return TrainingSplit.TEMPORAL_HOLDOUT
    repository_bucket = int(content_digest(lineage.repository_id)[:8], 16) % 10
    if repository_bucket == 0:
        return TrainingSplit.REPOSITORY_HOLDOUT
    task_bucket = int(content_digest(lineage.task_id)[:8], 16) % 10
    return TrainingSplit.TASK_HOLDOUT if task_bucket == 0 else TrainingSplit.TRAIN


_SPLIT_DEDUPLICATION_PRIORITY = {
    TrainingSplit.REPOSITORY_HOLDOUT: 0,
    TrainingSplit.TASK_HOLDOUT: 1,
    TrainingSplit.TEMPORAL_HOLDOUT: 2,
    TrainingSplit.TRAIN: 3,
}


def _exclusion(
    candidate: TrainingCandidate,
    reason: ExclusionReason,
    related_digest: str | None = None,
) -> TrainingExclusion:
    values = {
        "candidate_id": candidate.candidate_id,
        "source_candidate_digest": candidate.candidate_digest,
        "reason": reason,
        "related_digest": related_digest,
    }
    return TrainingExclusion(**values, exclusion_digest=content_digest(values))


def _prepared_case(
    candidate: TrainingCandidate,
    *,
    instruction: RedactedText,
    response: RedactedText,
    split: TrainingSplit,
) -> PreparedTrainingCase:
    rules = tuple(sorted(set((*instruction.rule_ids, *response.rule_ids))))
    values = {
        "schema_version": "prepared-training-case-v1",
        "candidate_id": candidate.candidate_id,
        "split": split,
        "instruction": instruction.text,
        "response": response.text,
        "content_digest": _pair_digest(instruction.text, response.text),
        "shingle_digests": _pair_shingles(instruction.text, response.text),
        "redaction_rule_ids": rules,
        "source_candidate_digest": candidate.candidate_digest,
        "lineage": candidate.lineage,
        "authority_digest": candidate.authority.authority_digest,
    }
    return PreparedTrainingCase(**values, case_digest=content_digest(values))


def prepare_training_readiness(
    candidates: tuple[TrainingCandidate, ...],
    *,
    dataset_id: str,
    contamination_index: ContaminationIndex,
    temporal_cutoff: datetime,
) -> TrainingReadinessReport:
    cutoff = _aware(temporal_cutoff, label="temporal_cutoff")
    candidate_ids = tuple(item.candidate_id for item in candidates)
    if len(set(candidate_ids)) != len(candidate_ids):
        raise ValueError("training candidate identifiers must be unique")
    eligible: list[tuple[TrainingCandidate, PreparedTrainingCase]] = []
    exclusions: list[TrainingExclusion] = []
    forbidden_content = set(contamination_index.forbidden_content_digests)
    forbidden_shingles = set(contamination_index.forbidden_shingle_digests)
    deleted_memory = set(contamination_index.deleted_memory_record_digests)
    for candidate in sorted(candidates, key=lambda item: item.candidate_id):
        if not candidate.authority.training_use_authorized:
            exclusions.append(_exclusion(candidate, ExclusionReason.UNAUTHORIZED))
            continue
        if candidate.lineage.memory_record_digest in deleted_memory:
            exclusions.append(
                _exclusion(
                    candidate,
                    ExclusionReason.SOURCE_DELETED,
                    candidate.lineage.memory_record_digest,
                )
            )
            continue
        instruction = redact_training_text(candidate.instruction)
        response = redact_training_text(candidate.response)
        prepared = _prepared_case(
            candidate,
            instruction=instruction,
            response=response,
            split=_split(candidate.lineage, contamination_index, cutoff),
        )
        if prepared.content_digest in forbidden_content or set(
            prepared.shingle_digests
        ).intersection(forbidden_shingles):
            related = (
                prepared.content_digest
                if prepared.content_digest in forbidden_content
                else sorted(set(prepared.shingle_digests).intersection(forbidden_shingles))[0]
            )
            exclusions.append(
                _exclusion(candidate, ExclusionReason.EVALUATION_CONTAMINATION, related)
            )
            continue
        eligible.append((candidate, prepared))

    # Deduplicate only after every split is known. A holdout must always win over a
    # train case with the same content, regardless of candidate-id ordering.
    retained_by_content: dict[str, tuple[TrainingCandidate, PreparedTrainingCase]] = {}
    for candidate, prepared in sorted(
        eligible,
        key=lambda item: (
            _SPLIT_DEDUPLICATION_PRIORITY[item[1].split],
            item[0].candidate_id,
        ),
    ):
        retained_pair = retained_by_content.get(prepared.content_digest)
        if retained_pair is not None:
            exclusions.append(
                _exclusion(
                    candidate,
                    ExclusionReason.EXACT_DUPLICATE,
                    retained_pair[1].case_digest,
                )
            )
            continue
        retained_by_content[prepared.content_digest] = (candidate, prepared)

    retained_pairs = tuple(retained_by_content.values())
    holdout_shingles = {
        digest
        for _, prepared in retained_pairs
        if prepared.split is not TrainingSplit.TRAIN
        for digest in prepared.shingle_digests
    }
    cases: list[PreparedTrainingCase] = []
    for candidate, prepared in retained_pairs:
        overlap = (
            set(prepared.shingle_digests).intersection(holdout_shingles)
            if prepared.split is TrainingSplit.TRAIN
            else set()
        )
        if overlap:
            exclusions.append(
                _exclusion(
                    candidate,
                    ExclusionReason.EVALUATION_CONTAMINATION,
                    sorted(overlap)[0],
                )
            )
            continue
        cases.append(prepared)

    cases.sort(key=lambda item: item.candidate_id)
    exclusions.sort(key=lambda item: item.candidate_id)

    counts = {split: 0 for split in TrainingSplit}
    for case in cases:
        counts[case.split] += 1
    split_counts = tuple(SplitCount(split=split, count=counts[split]) for split in TrainingSplit)
    values = {
        "schema_version": "training-readiness-v1",
        "dataset_id": dataset_id,
        "source_candidate_count": len(candidates),
        "ready_case_count": len(cases),
        "cases": tuple(cases),
        "exclusions": tuple(exclusions),
        "split_counts": split_counts,
        "contamination_index_digest": contamination_index.index_digest,
        "temporal_cutoff": cutoff,
        "export_only": True,
        "training_execution_enabled": False,
        "ready_for_human_review": bool(cases),
    }
    return TrainingReadinessReport(**values, report_digest=content_digest(values))
