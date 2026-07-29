from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import defaultdict
from enum import StrEnum
from pathlib import PurePosixPath

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from .repository import secret_rule_ids
from .store import canonical_json

MAX_EVIDENCE_ITEMS = 6
MAX_PACKET_BYTES = 48 * 1024
MAX_ANALYSIS_BYTES = 64 * 1024

_IDENTIFIER_PATTERN = r"^[A-Z][A-Z0-9_-]{0,31}$"
_CASE_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,63}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_UNSUPPORTED_EXECUTION_CLAIM = re.compile(
    r"(?i)(?:"
    r"\b(?:i|we)\s+(?:ran|executed|verified|deployed|modified|inspected|confirmed)\b"
    r"|\b(?:tests?|build|deployment)\s+(?:have\s+)?(?:passed|succeeded|completed)\b"
    r")"
)
_SENSITIVE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".npmrc",
    ".pypirc",
    "credentials.json",
    "service-account.json",
    "id_rsa",
    "id_ed25519",
}


class EngineeringContractError(ValueError):
    """A packet or analysis failed deterministic engineering-contract validation."""

    def __init__(self, message: str, *, codes: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.codes = codes


class EngineeringSchema(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        str_strip_whitespace=False,
        allow_inf_nan=False,
    )


class EvidenceKind(StrEnum):
    OBSERVATION = "observation"
    SOURCE_EXCERPT = "source_excerpt"
    TEST_RESULT = "test_result"
    CONSTRAINT = "constraint"
    DISTRACTOR = "distractor"


class EngineeringMechanism(StrEnum):
    ATOMICITY_VIOLATION = "atomicity_violation"
    TENANT_SCOPE_VIOLATION = "tenant_scope_violation"
    TEMPORAL_LEAKAGE = "temporal_leakage"
    INPUT_VALIDATION_FAILURE = "input_validation_failure"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    STATE_MACHINE_VIOLATION = "state_machine_violation"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    OTHER = "other"


def _contains_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _validate_identifier(value: str, *, label: str) -> str:
    if re.fullmatch(_IDENTIFIER_PATTERN, value) is None:
        raise ValueError(f"{label} must be a bounded uppercase identifier")
    return value


def _validate_path(value: str) -> str:
    if (
        not value
        or len(value) > 512
        or value.startswith(("/", "\\"))
        or "\\" in value
        or _contains_control(value)
        or unicodedata.normalize("NFC", value) != value
    ):
        raise ValueError("evidence path must be normalized repository-relative UTF-8 text")
    parts = PurePosixPath(value).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("evidence path must not contain empty, dot, or parent components")
    for part in parts:
        folded = part.casefold()
        if folded in _SENSITIVE_NAMES or (
            folded.startswith(".env.") and folded not in {".env.example", ".env.sample"}
        ):
            raise ValueError("sensitive paths are not permitted in engineering evidence")
    return value


class EngineeringEvidenceItem(EngineeringSchema):
    id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    kind: EvidenceKind = Field(strict=False)
    path: StrictStr | None = Field(default=None, max_length=512)
    symbol: StrictStr | None = Field(default=None, min_length=1, max_length=256)
    line_start: StrictInt | None = Field(default=None, ge=1, le=1_000_000)
    line_end: StrictInt | None = Field(default=None, ge=1, le=1_000_000)
    content: StrictStr = Field(min_length=1, max_length=12_000)
    sha256: StrictStr = Field(pattern=_SHA256_PATTERN)

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        return _validate_identifier(value, label="evidence id")

    @field_validator("path")
    @classmethod
    def valid_path(cls, value: str | None) -> str | None:
        return None if value is None else _validate_path(value)

    @field_validator("symbol")
    @classmethod
    def valid_symbol(cls, value: str | None) -> str | None:
        if value is not None and _contains_control(value):
            raise ValueError("evidence symbol cannot contain control characters")
        return value

    @model_validator(mode="after")
    def valid_source_binding(self) -> EngineeringEvidenceItem:
        if (self.line_start is None) != (self.line_end is None):
            raise ValueError("line_start and line_end must be supplied together")
        if self.line_start is not None:
            if self.path is None:
                raise ValueError("line-bound evidence requires a path")
            if self.line_end is not None and self.line_end < self.line_start:
                raise ValueError("line_end cannot precede line_start")
        digest = hashlib.sha256(self.content.encode("utf-8")).hexdigest()
        if digest != self.sha256:
            raise ValueError("evidence content digest mismatch")
        return self


class EngineeringInvariant(EngineeringSchema):
    id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    statement: StrictStr = Field(min_length=1, max_length=1_000)

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        return _validate_identifier(value, label="invariant id")


class EngineeringEvidencePacket(EngineeringSchema):
    schema_version: StrictStr = Field(default="1.0", pattern=r"^1\.0$")
    case_id: StrictStr = Field(pattern=_CASE_ID_PATTERN)
    objective: StrictStr = Field(min_length=1, max_length=2_000)
    evidence_items: list[EngineeringEvidenceItem] = Field(
        min_length=2,
        max_length=MAX_EVIDENCE_ITEMS,
    )
    required_invariants: list[EngineeringInvariant] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def validate_packet(self) -> EngineeringEvidencePacket:
        evidence_ids = [item.id for item in self.evidence_items]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence ids must be unique")
        invariant_ids = [item.id for item in self.required_invariants]
        if len(invariant_ids) != len(set(invariant_ids)):
            raise ValueError("invariant ids must be unique")

        path_spellings: dict[str, str] = {}
        for item in self.evidence_items:
            if item.path is None:
                continue
            comparison = unicodedata.normalize("NFC", item.path).casefold()
            existing = path_spellings.setdefault(comparison, item.path)
            if existing != item.path:
                raise ValueError("case or Unicode-colliding evidence paths are not permitted")

        serialized = self.model_dump_json().encode("utf-8")
        if len(serialized) > MAX_PACKET_BYTES:
            raise ValueError("engineering evidence packet exceeds the 48 KiB limit")
        if secret_rule_ids(serialized):
            raise ValueError("engineering evidence packet contains credential-like material")
        return self

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            canonical_json(self.model_dump(mode="json")).encode("utf-8")
        ).hexdigest()


class EvidenceTrace(EngineeringSchema):
    evidence_id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    interpretation: StrictStr = Field(min_length=1, max_length=1_500)


class EngineeringHypothesis(EngineeringSchema):
    id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    statement: StrictStr = Field(min_length=1, max_length=2_000)
    mechanism: EngineeringMechanism = Field(strict=False)
    confidence: StrictFloat = Field(ge=0.0, le=1.0)
    evidence_ids: list[StrictStr] = Field(min_length=1, max_length=MAX_EVIDENCE_ITEMS)
    contradicting_evidence_ids: list[StrictStr] = Field(
        default_factory=list,
        max_length=MAX_EVIDENCE_ITEMS,
    )
    falsification: StrictStr = Field(min_length=1, max_length=1_500)


class EngineeringChange(EngineeringSchema):
    path: StrictStr = Field(min_length=1, max_length=512)
    symbol: StrictStr | None = Field(default=None, min_length=1, max_length=256)
    change: StrictStr = Field(min_length=1, max_length=2_000)
    evidence_ids: list[StrictStr] = Field(min_length=1, max_length=MAX_EVIDENCE_ITEMS)


class RejectedAlternative(EngineeringSchema):
    hypothesis_id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    reason: StrictStr = Field(min_length=1, max_length=1_500)
    evidence_ids: list[StrictStr] = Field(min_length=1, max_length=MAX_EVIDENCE_ITEMS)


class EngineeringProofTest(EngineeringSchema):
    name: StrictStr = Field(min_length=1, max_length=256)
    setup: StrictStr = Field(min_length=1, max_length=1_500)
    action: StrictStr = Field(min_length=1, max_length=1_500)
    expected: StrictStr = Field(min_length=1, max_length=1_500)
    invariant_ids: list[StrictStr] = Field(min_length=1, max_length=8)
    evidence_ids: list[StrictStr] = Field(min_length=1, max_length=MAX_EVIDENCE_ITEMS)


class EngineeringAnalysis(EngineeringSchema):
    schema_version: StrictStr = Field(default="1.0", pattern=r"^1\.0$")
    case_id: StrictStr = Field(pattern=_CASE_ID_PATTERN)
    objective: StrictStr = Field(min_length=1, max_length=2_000)
    trace: list[EvidenceTrace] = Field(min_length=1, max_length=MAX_EVIDENCE_ITEMS)
    hypotheses: list[EngineeringHypothesis] = Field(min_length=2, max_length=4)
    selected_hypothesis_id: StrictStr = Field(pattern=_IDENTIFIER_PATTERN)
    causal_chain: list[StrictStr] = Field(min_length=2, max_length=8)
    minimal_changes: list[EngineeringChange] = Field(
        default_factory=list,
        max_length=6,
        description=(
            "Supported root-cause repairs. Must be empty when insufficient_evidence is true."
        ),
    )
    rejected_alternatives: list[RejectedAlternative] = Field(default_factory=list, max_length=3)
    proof_tests: list[EngineeringProofTest] = Field(
        default_factory=list,
        max_length=8,
        description=(
            "Falsifying regression tests for a supported repair. May be empty only when "
            "insufficient_evidence is true."
        ),
    )
    insufficient_evidence: StrictBool = Field(
        description=(
            "True only when the packet cannot support any root-cause repair. If a repair is "
            "proposed, this must be false."
        )
    )
    missing_evidence: list[StrictStr] = Field(
        default_factory=list,
        max_length=6,
        description=(
            "Discriminating observations required before a repair can be selected. Populate "
            "only when insufficient_evidence is true; otherwise return an empty list."
        ),
    )
    execution_claimed: StrictBool = Field(
        description="Always false in this no-tools, no-execution reasoning trial."
    )
    confidence: StrictFloat = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def bounded_analysis(self) -> EngineeringAnalysis:
        if len(self.model_dump_json().encode("utf-8")) > MAX_ANALYSIS_BYTES:
            raise ValueError("engineering analysis exceeds the 64 KiB limit")
        return self

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            canonical_json(self.model_dump(mode="json")).encode("utf-8")
        ).hexdigest()


class EngineeringValidationReport(EngineeringSchema):
    valid: StrictBool
    packet_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    analysis_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    evidence_citation_count: StrictInt = Field(ge=0)
    hypothesis_count: StrictInt = Field(ge=0)
    change_count: StrictInt = Field(ge=0)
    proof_test_count: StrictInt = Field(ge=0)
    covered_invariant_ids: list[StrictStr]


def _duplicates(values: list[str]) -> bool:
    return len(values) != len(set(values))


def _all_analysis_text(analysis: EngineeringAnalysis) -> str:
    return analysis.model_dump_json()


def validate_engineering_analysis(
    packet: EngineeringEvidencePacket,
    analysis: EngineeringAnalysis,
) -> EngineeringValidationReport:
    errors: list[str] = []
    evidence_ids = {item.id for item in packet.evidence_items}
    invariant_ids = {item.id for item in packet.required_invariants}
    paths = {item.path for item in packet.evidence_items if item.path is not None}
    symbols_by_path: dict[str, set[str]] = defaultdict(set)
    for item in packet.evidence_items:
        if item.path is not None and item.symbol is not None:
            symbols_by_path[item.path].add(item.symbol)

    if analysis.case_id != packet.case_id:
        errors.append("case_id_mismatch")
    if analysis.objective != packet.objective:
        errors.append("objective_mismatch")

    trace_ids = [item.evidence_id for item in analysis.trace]
    if _duplicates(trace_ids):
        errors.append("duplicate_trace_citation")
    if not set(trace_ids) <= evidence_ids:
        errors.append("unknown_trace_citation")

    hypothesis_ids = [item.id for item in analysis.hypotheses]
    if _duplicates(hypothesis_ids):
        errors.append("duplicate_hypothesis_id")
    selected = next(
        (item for item in analysis.hypotheses if item.id == analysis.selected_hypothesis_id),
        None,
    )
    if selected is None:
        errors.append("selected_hypothesis_missing")

    all_citations: list[str] = list(trace_ids)
    for hypothesis in analysis.hypotheses:
        citations = [*hypothesis.evidence_ids, *hypothesis.contradicting_evidence_ids]
        all_citations.extend(citations)
        if _duplicates(hypothesis.evidence_ids) or _duplicates(
            hypothesis.contradicting_evidence_ids
        ):
            errors.append("duplicate_hypothesis_citation")
        if not set(citations) <= evidence_ids:
            errors.append("unknown_hypothesis_citation")
    if selected is not None:
        if len(set(selected.evidence_ids)) < 2 and not analysis.insufficient_evidence:
            errors.append("selected_hypothesis_under_supported")
        if not set(selected.evidence_ids) <= set(trace_ids):
            errors.append("selected_evidence_not_traced")

    rejected_ids = [item.hypothesis_id for item in analysis.rejected_alternatives]
    if _duplicates(rejected_ids):
        errors.append("duplicate_rejected_hypothesis")
    for alternative in analysis.rejected_alternatives:
        all_citations.extend(alternative.evidence_ids)
        if alternative.hypothesis_id not in set(hypothesis_ids):
            errors.append("unknown_rejected_hypothesis")
        if alternative.hypothesis_id == analysis.selected_hypothesis_id:
            errors.append("selected_hypothesis_rejected")
        if not set(alternative.evidence_ids) <= evidence_ids:
            errors.append("unknown_alternative_citation")

    for change in analysis.minimal_changes:
        all_citations.extend(change.evidence_ids)
        try:
            path = _validate_path(change.path)
        except ValueError:
            errors.append("invalid_change_path")
            continue
        if path not in paths:
            errors.append("unknown_change_path")
        if change.symbol is not None and change.symbol not in symbols_by_path.get(path, set()):
            errors.append("unknown_change_symbol")
        if not set(change.evidence_ids) <= evidence_ids:
            errors.append("unknown_change_citation")

    covered_invariants: set[str] = set()
    for proof in analysis.proof_tests:
        all_citations.extend(proof.evidence_ids)
        if _duplicates(proof.invariant_ids):
            errors.append("duplicate_test_invariant")
        if not set(proof.invariant_ids) <= invariant_ids:
            errors.append("unknown_test_invariant")
        if not set(proof.evidence_ids) <= evidence_ids:
            errors.append("unknown_test_citation")
        covered_invariants.update(proof.invariant_ids)

    if analysis.insufficient_evidence:
        if analysis.minimal_changes:
            errors.append("insufficient_evidence_with_changes")
        if not analysis.missing_evidence:
            errors.append("missing_discriminating_evidence")
    else:
        if analysis.missing_evidence:
            errors.append("unexpected_missing_evidence")
        if not analysis.minimal_changes:
            errors.append("missing_minimal_change")
        if not analysis.proof_tests:
            errors.append("missing_proof_tests")
        if not invariant_ids <= covered_invariants:
            errors.append("required_invariant_not_covered")
        if len(analysis.rejected_alternatives) < 1:
            errors.append("missing_rejected_alternative")

    analysis_text = _all_analysis_text(analysis)
    if analysis.execution_claimed or _UNSUPPORTED_EXECUTION_CLAIM.search(analysis_text):
        errors.append("unsupported_execution_claim")
    if secret_rule_ids(analysis_text.encode("utf-8")):
        errors.append("credential_like_analysis")
    if not set(all_citations) <= evidence_ids:
        errors.append("unknown_evidence_citation")

    if errors:
        codes = tuple(sorted(set(errors)))
        raise EngineeringContractError(
            "engineering analysis rejected: " + ",".join(codes),
            codes=codes,
        )

    return EngineeringValidationReport(
        valid=True,
        packet_digest=packet.digest,
        analysis_digest=analysis.digest,
        evidence_citation_count=len(all_citations),
        hypothesis_count=len(analysis.hypotheses),
        change_count=len(analysis.minimal_changes),
        proof_test_count=len(analysis.proof_tests),
        covered_invariant_ids=sorted(covered_invariants),
    )
