"""Deterministic contracts for Lil' Tueeq Engineering IQ evaluation.

The reasoning model may attempt a challenge, but it never owns challenge secrecy,
source binding, evidence verification, budgets, dimension proof, provenance, or verdict.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
from types import MappingProxyType
from typing import Mapping


_MAX_TOKEN = 128
_MAX_TEXT = 4_000
_MAX_ITEMS = 256
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class EngineeringDimension(StrEnum):
    ARCHITECTURE_RECONSTRUCTION = "architecture_reconstruction"
    CAUSAL_DEBUGGING = "causal_debugging"
    INVARIANT_DISCOVERY = "invariant_discovery"
    SYSTEM_DESIGN = "system_design"
    CONCURRENCY_REASONING = "concurrency_reasoning"
    SECURITY_REASONING = "security_reasoning"
    RECOVERY_REASONING = "recovery_reasoning"
    PERFORMANCE_REASONING = "performance_reasoning"
    TRANSFER_LEARNING = "transfer_learning"
    SELF_CRITIQUE = "self_critique"
    EVIDENCE_DISCIPLINE = "evidence_discipline"
    IMPLEMENTATION_ACCURACY = "implementation_accuracy"


class Verdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INCOMPLETE = "incomplete"


def _token(value: object, code: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise ValueError(code)
    return value


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(code)
    return value


def _revision(value: object, code: str) -> str:
    if not isinstance(value, str) or not _REVISION.fullmatch(value):
        raise ValueError(code)
    return value


def _tuple_tokens(values: object, code: str) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) > _MAX_ITEMS:
        raise ValueError(code)
    normalized = tuple(_token(item, code) for item in values)
    if len(set(normalized)) != len(normalized):
        raise ValueError(code)
    return normalized


def _changed_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or chr(92) in value:
        raise ValueError("engineering_iq_changed_path_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ValueError("engineering_iq_changed_path_invalid")
    normalized = path.as_posix()
    if normalized != value or normalized.startswith("/"):
        raise ValueError("engineering_iq_changed_path_invalid")
    return normalized


@dataclass(frozen=True, slots=True)
class ChallengeBudget:
    max_attempts: int
    max_wall_seconds: int
    max_changed_files: int

    def __post_init__(self) -> None:
        for value in (self.max_attempts, self.max_wall_seconds, self.max_changed_files):
            if type(value) is not int or value < 1:
                raise ValueError("engineering_iq_budget_invalid")
        if (
            self.max_attempts > 100
            or self.max_wall_seconds > 86_400
            or self.max_changed_files > 10_000
        ):
            raise ValueError("engineering_iq_budget_invalid")


@dataclass(frozen=True, slots=True)
class PublicEngineeringChallenge:
    challenge_id: str
    title: str
    dimensions: tuple[EngineeringDimension, ...]
    public_brief: str
    required_evidence: tuple[str, ...]
    budget: ChallengeBudget


@dataclass(frozen=True, slots=True)
class EngineeringChallenge:
    challenge_id: str
    title: str
    dimensions: tuple[EngineeringDimension, ...]
    public_brief: str
    required_evidence: tuple[str, ...]
    hidden_check_ids: tuple[str, ...]
    budget: ChallengeBudget
    dimension_check_ids: Mapping[EngineeringDimension, tuple[str, ...]] | None = None

    def __post_init__(self) -> None:
        _token(self.challenge_id, "engineering_iq_challenge_invalid")
        if not isinstance(self.title, str) or not self.title or len(self.title) > 512:
            raise ValueError("engineering_iq_challenge_invalid")
        if (
            not isinstance(self.public_brief, str)
            or not self.public_brief
            or len(self.public_brief) > _MAX_TEXT
        ):
            raise ValueError("engineering_iq_challenge_invalid")
        if not isinstance(self.dimensions, tuple) or not self.dimensions:
            raise ValueError("engineering_iq_challenge_incomplete")
        if any(not isinstance(item, EngineeringDimension) for item in self.dimensions):
            raise ValueError("engineering_iq_dimension_invalid")
        if len(set(self.dimensions)) != len(self.dimensions):
            raise ValueError("engineering_iq_dimension_duplicate")
        object.__setattr__(
            self,
            "required_evidence",
            _tuple_tokens(self.required_evidence, "engineering_iq_evidence_invalid"),
        )
        object.__setattr__(
            self,
            "hidden_check_ids",
            _tuple_tokens(self.hidden_check_ids, "engineering_iq_hidden_check_invalid"),
        )
        if not self.required_evidence or not self.hidden_check_ids:
            raise ValueError("engineering_iq_challenge_incomplete")
        if not isinstance(self.budget, ChallengeBudget):
            raise ValueError("engineering_iq_budget_invalid")

        if self.dimension_check_ids is None:
            frozen = MappingProxyType({})
        else:
            if not isinstance(self.dimension_check_ids, Mapping):
                raise ValueError("engineering_iq_dimension_binding_invalid")
            normalized: dict[EngineeringDimension, tuple[str, ...]] = {}
            for dimension, checks in self.dimension_check_ids.items():
                if not isinstance(dimension, EngineeringDimension):
                    raise ValueError("engineering_iq_dimension_binding_invalid")
                bound = _tuple_tokens(checks, "engineering_iq_dimension_binding_invalid")
                if not bound:
                    raise ValueError("engineering_iq_dimension_binding_invalid")
                normalized[dimension] = bound
            frozen = MappingProxyType(normalized)
        object.__setattr__(self, "dimension_check_ids", frozen)

    def public_view(self) -> PublicEngineeringChallenge:
        return PublicEngineeringChallenge(
            challenge_id=self.challenge_id,
            title=self.title,
            dimensions=self.dimensions,
            public_brief=self.public_brief,
            required_evidence=self.required_evidence,
            budget=self.budget,
        )


def challenge_digest(challenge: EngineeringChallenge) -> str:
    if not isinstance(challenge, EngineeringChallenge):
        raise ValueError("engineering_iq_challenge_invalid")
    material = {
        "challenge_id": challenge.challenge_id,
        "title": challenge.title,
        "dimensions": [item.value for item in challenge.dimensions],
        "public_brief": challenge.public_brief,
        "required_evidence": list(challenge.required_evidence),
        "hidden_check_ids": list(challenge.hidden_check_ids),
        "budget": {
            "max_attempts": challenge.budget.max_attempts,
            "max_wall_seconds": challenge.budget.max_wall_seconds,
            "max_changed_files": challenge.budget.max_changed_files,
        },
        "dimension_check_ids": {
            dimension.value: list(challenge.dimension_check_ids[dimension])
            for dimension in sorted(challenge.dimension_check_ids, key=lambda item: item.value)
        },
    }
    encoded = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class CheckResult:
    check_id: str
    passed: bool
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _token(self.check_id, "engineering_iq_check_invalid")
        if type(self.passed) is not bool:
            raise ValueError("engineering_iq_check_invalid")
        object.__setattr__(
            self,
            "evidence_refs",
            _tuple_tokens(self.evidence_refs, "engineering_iq_evidence_ref_invalid"),
        )


@dataclass(frozen=True, slots=True)
class VerifiedEvidence:
    evidence_ref: str
    evidence_sha256: str
    challenge_digest: str
    run_id: str
    source_revision: str

    def __post_init__(self) -> None:
        _token(self.evidence_ref, "engineering_iq_evidence_registry_invalid")
        _digest(self.evidence_sha256, "engineering_iq_evidence_digest_invalid")
        _digest(self.challenge_digest, "engineering_iq_evidence_registry_invalid")
        _token(self.run_id, "engineering_iq_run_id_invalid")
        _revision(self.source_revision, "engineering_iq_evidence_registry_invalid")


@dataclass(frozen=True, slots=True)
class EngineeringIQResult:
    challenge_id: str
    challenge_digest: str
    run_id: str
    source_revision: str
    attempts_used: int
    changed_files: tuple[str, ...]
    check_results: tuple[CheckResult, ...]
    claimed_verdict: Verdict | None = None

    def __post_init__(self) -> None:
        _token(self.challenge_id, "engineering_iq_result_invalid")
        _digest(self.challenge_digest, "engineering_iq_challenge_digest_invalid")
        _token(self.run_id, "engineering_iq_run_id_invalid")
        _revision(self.source_revision, "engineering_iq_result_invalid")
        if type(self.attempts_used) is not int or self.attempts_used < 0:
            raise ValueError("engineering_iq_attempt_count_invalid")
        if not isinstance(self.changed_files, tuple) or len(self.changed_files) > 10_000:
            raise ValueError("engineering_iq_changed_path_invalid")
        normalized_paths = tuple(_changed_path(path) for path in self.changed_files)
        if len(set(normalized_paths)) != len(normalized_paths):
            raise ValueError("engineering_iq_changed_path_duplicate")
        object.__setattr__(self, "changed_files", normalized_paths)
        if not isinstance(self.check_results, tuple) or len(self.check_results) > _MAX_ITEMS:
            raise ValueError("engineering_iq_check_invalid")
        if any(not isinstance(item, CheckResult) for item in self.check_results):
            raise ValueError("engineering_iq_check_invalid")
        if self.claimed_verdict is not None and not isinstance(self.claimed_verdict, Verdict):
            raise ValueError("engineering_iq_claimed_verdict_invalid")


@dataclass(frozen=True, slots=True)
class AuthoritativeScore:
    verdict: Verdict
    passed_checks: int
    total_checks: int
    dimension_coverage: Mapping[EngineeringDimension, bool]
    evidence_digests: Mapping[str, str]
    challenge_digest: str
    run_id: str
    source_revision: str
    score_digest: str


def _validate_dimension_bindings(challenge: EngineeringChallenge) -> None:
    mapping = challenge.dimension_check_ids
    if set(mapping) != set(challenge.dimensions):
        raise ValueError("engineering_iq_dimension_unbound")
    hidden = set(challenge.hidden_check_ids)
    for dimension in challenge.dimensions:
        bound = mapping.get(dimension, ())
        if not bound or not set(bound).issubset(hidden):
            raise ValueError("engineering_iq_dimension_unbound")


def _verified_registry(
    values: object,
    *,
    digest: str,
    run_id: str,
    source_revision: str,
) -> Mapping[str, VerifiedEvidence]:
    if not isinstance(values, tuple) or len(values) > _MAX_ITEMS:
        raise ValueError("engineering_iq_evidence_registry_invalid")
    registry: dict[str, VerifiedEvidence] = {}
    for item in values:
        if not isinstance(item, VerifiedEvidence):
            raise ValueError("engineering_iq_evidence_registry_invalid")
        if item.evidence_ref in registry:
            raise ValueError("engineering_iq_evidence_duplicate")
        if (
            item.challenge_digest != digest
            or item.run_id != run_id
            or item.source_revision != source_revision
        ):
            raise ValueError("engineering_iq_evidence_binding_mismatch")
        registry[item.evidence_ref] = item
    return MappingProxyType(registry)


def score(
    challenge: EngineeringChallenge,
    result: EngineeringIQResult,
    *,
    expected_source_revision: str,
    expected_run_id: str,
    elapsed_wall_seconds: int | float,
    verified_evidence: tuple[VerifiedEvidence, ...],
) -> AuthoritativeScore:
    if not isinstance(challenge, EngineeringChallenge) or not isinstance(result, EngineeringIQResult):
        raise ValueError("engineering_iq_input_invalid")
    _revision(expected_source_revision, "engineering_iq_source_binding_mismatch")
    _token(expected_run_id, "engineering_iq_run_id_invalid")

    digest = challenge_digest(challenge)
    if result.challenge_id != challenge.challenge_id:
        raise ValueError("engineering_iq_challenge_binding_mismatch")
    if result.challenge_digest != digest:
        raise ValueError("engineering_iq_challenge_digest_mismatch")
    if result.run_id != expected_run_id:
        raise ValueError("engineering_iq_run_binding_mismatch")
    if result.source_revision != expected_source_revision:
        raise ValueError("engineering_iq_source_binding_mismatch")
    if (
        isinstance(elapsed_wall_seconds, bool)
        or not isinstance(elapsed_wall_seconds, (int, float))
        or not math.isfinite(elapsed_wall_seconds)
        or elapsed_wall_seconds < 0
    ):
        raise ValueError("engineering_iq_wall_time_invalid")
    if elapsed_wall_seconds > challenge.budget.max_wall_seconds:
        raise ValueError("engineering_iq_wall_time_exceeded")

    verified = _verified_registry(
        verified_evidence,
        digest=digest,
        run_id=expected_run_id,
        source_revision=expected_source_revision,
    )
    _validate_dimension_bindings(challenge)

    if result.attempts_used < 1 or result.attempts_used > challenge.budget.max_attempts:
        return _fail(
            challenge,
            result,
            evidence=verified,
            challenge_digest_value=digest,
            run_id=expected_run_id,
            source_revision=expected_source_revision,
        )
    if len(result.changed_files) > challenge.budget.max_changed_files:
        return _fail(
            challenge,
            result,
            evidence=verified,
            challenge_digest_value=digest,
            run_id=expected_run_id,
            source_revision=expected_source_revision,
        )

    by_id = {item.check_id: item for item in result.check_results}
    if len(by_id) != len(result.check_results):
        raise ValueError("engineering_iq_duplicate_check_result")
    if set(by_id) != set(challenge.hidden_check_ids):
        return _fail(
            challenge,
            result,
            evidence=verified,
            challenge_digest_value=digest,
            run_id=expected_run_id,
            source_revision=expected_source_revision,
        )

    claimed_evidence = {ref for item in result.check_results for ref in item.evidence_refs}
    if not claimed_evidence.issubset(verified):
        raise ValueError("engineering_iq_evidence_unverified")
    if any(required not in verified for required in challenge.required_evidence):
        return _fail(
            challenge,
            result,
            evidence=verified,
            challenge_digest_value=digest,
            run_id=expected_run_id,
            source_revision=expected_source_revision,
        )
    if any(required not in claimed_evidence for required in challenge.required_evidence):
        return _fail(
            challenge,
            result,
            evidence=verified,
            challenge_digest_value=digest,
            run_id=expected_run_id,
            source_revision=expected_source_revision,
        )

    passed = sum(1 for item in result.check_results if item.passed)
    verdict = Verdict.PASS if passed == len(challenge.hidden_check_ids) else Verdict.FAIL
    coverage = {
        dimension: all(
            by_id[check_id].passed
            for check_id in challenge.dimension_check_ids[dimension]
        )
        for dimension in challenge.dimensions
    }
    return _make_score(
        verdict=verdict,
        passed=passed,
        total=len(challenge.hidden_check_ids),
        coverage=coverage,
        evidence=verified,
        challenge_digest_value=digest,
        run_id=expected_run_id,
        source_revision=expected_source_revision,
    )


def _make_score(
    *,
    verdict: Verdict,
    passed: int,
    total: int,
    coverage: Mapping[EngineeringDimension, bool],
    evidence: Mapping[str, VerifiedEvidence],
    challenge_digest_value: str,
    run_id: str,
    source_revision: str,
) -> AuthoritativeScore:
    coverage_dict = {dimension: bool(coverage[dimension]) for dimension in sorted(coverage, key=lambda item: item.value)}
    evidence_dict = {ref: evidence[ref].evidence_sha256 for ref in sorted(evidence)}
    material = {
        "verdict": verdict.value,
        "passed_checks": passed,
        "total_checks": total,
        "dimension_coverage": {dimension.value: coverage_dict[dimension] for dimension in coverage_dict},
        "evidence_digests": evidence_dict,
        "challenge_digest": challenge_digest_value,
        "run_id": run_id,
        "source_revision": source_revision,
    }
    receipt = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return AuthoritativeScore(
        verdict=verdict,
        passed_checks=passed,
        total_checks=total,
        dimension_coverage=MappingProxyType(coverage_dict),
        evidence_digests=MappingProxyType(evidence_dict),
        challenge_digest=challenge_digest_value,
        run_id=run_id,
        source_revision=source_revision,
        score_digest=receipt,
    )


def _fail(
    challenge: EngineeringChallenge,
    result: EngineeringIQResult,
    *,
    evidence: Mapping[str, VerifiedEvidence],
    challenge_digest_value: str,
    run_id: str,
    source_revision: str,
) -> AuthoritativeScore:
    passed = sum(1 for item in result.check_results if item.passed)
    return _make_score(
        verdict=Verdict.FAIL,
        passed=passed,
        total=len(challenge.hidden_check_ids),
        coverage={dimension: False for dimension in challenge.dimensions},
        evidence=evidence,
        challenge_digest_value=challenge_digest_value,
        run_id=run_id,
        source_revision=source_revision,
    )
