"""Deterministic contracts for Lil' Tueeq Engineering IQ evaluation.

The reasoning model may attempt a challenge, but it never owns challenge secrecy,
source binding, evidence verification, budgets, or the authoritative verdict.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Mapping


_MAX_TOKEN = 128
_MAX_TEXT = 4_000
_MAX_ITEMS = 256


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
    if not isinstance(value, str) or not value or len(value) > _MAX_TOKEN:
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
    if not isinstance(value, str) or not value or len(value) > 512 or "\" in value:
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
        if self.max_attempts > 100 or self.max_wall_seconds > 86_400 or self.max_changed_files > 10_000:
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

    def __post_init__(self) -> None:
        _token(self.challenge_id, "engineering_iq_challenge_invalid")
        if not isinstance(self.title, str) or not self.title or len(self.title) > 512:
            raise ValueError("engineering_iq_challenge_invalid")
        if not isinstance(self.public_brief, str) or not self.public_brief or len(self.public_brief) > _MAX_TEXT:
            raise ValueError("engineering_iq_challenge_invalid")
        if not isinstance(self.dimensions, tuple) or not self.dimensions:
            raise ValueError("engineering_iq_challenge_incomplete")
        if len(self.dimensions) > len(EngineeringDimension):
            raise ValueError("engineering_iq_dimension_duplicate")
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

    def public_view(self) -> PublicEngineeringChallenge:
        return PublicEngineeringChallenge(
            challenge_id=self.challenge_id,
            title=self.title,
            dimensions=self.dimensions,
            public_brief=self.public_brief,
            required_evidence=self.required_evidence,
            budget=self.budget,
        )


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
class EngineeringIQResult:
    challenge_id: str
    source_revision: str
    attempts_used: int
    changed_files: tuple[str, ...]
    check_results: tuple[CheckResult, ...]
    claimed_verdict: Verdict | None = None

    def __post_init__(self) -> None:
        _token(self.challenge_id, "engineering_iq_result_invalid")
        if (
            not isinstance(self.source_revision, str)
            or len(self.source_revision) not in (40, 64)
            or any(char not in "0123456789abcdef" for char in self.source_revision)
        ):
            raise ValueError("engineering_iq_result_invalid")
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


def score(
    challenge: EngineeringChallenge,
    result: EngineeringIQResult,
    *,
    expected_source_revision: str,
    elapsed_wall_seconds: int | float,
    verified_evidence_refs: frozenset[str],
) -> AuthoritativeScore:
    if not isinstance(challenge, EngineeringChallenge) or not isinstance(result, EngineeringIQResult):
        raise ValueError("engineering_iq_input_invalid")
    if result.challenge_id != challenge.challenge_id:
        raise ValueError("engineering_iq_challenge_binding_mismatch")
    if result.source_revision != expected_source_revision:
        raise ValueError("engineering_iq_source_binding_mismatch")
    if isinstance(elapsed_wall_seconds, bool) or not isinstance(elapsed_wall_seconds, (int, float)) or elapsed_wall_seconds < 0:
        raise ValueError("engineering_iq_wall_time_invalid")
    if elapsed_wall_seconds > challenge.budget.max_wall_seconds:
        raise ValueError("engineering_iq_wall_time_exceeded")
    if not isinstance(verified_evidence_refs, frozenset) or any(
        not isinstance(item, str) or not item for item in verified_evidence_refs
    ):
        raise ValueError("engineering_iq_evidence_unverified")
    if result.attempts_used < 1 or result.attempts_used > challenge.budget.max_attempts:
        return _fail(challenge, result)
    if len(result.changed_files) > challenge.budget.max_changed_files:
        return _fail(challenge, result)

    by_id = {item.check_id: item for item in result.check_results}
    if len(by_id) != len(result.check_results):
        raise ValueError("engineering_iq_duplicate_check_result")
    if set(by_id) != set(challenge.hidden_check_ids):
        return _fail(challenge, result)

    claimed_evidence = {ref for item in result.check_results for ref in item.evidence_refs}
    if not claimed_evidence.issubset(verified_evidence_refs):
        raise ValueError("engineering_iq_evidence_unverified")
    if any(required not in verified_evidence_refs for required in challenge.required_evidence):
        return _fail(challenge, result)
    if any(required not in claimed_evidence for required in challenge.required_evidence):
        return _fail(challenge, result)

    passed = sum(1 for item in result.check_results if item.passed)
    verdict = Verdict.PASS if passed == len(challenge.hidden_check_ids) else Verdict.FAIL
    coverage = MappingProxyType(
        {dimension: verdict is Verdict.PASS for dimension in challenge.dimensions}
    )
    return AuthoritativeScore(verdict, passed, len(challenge.hidden_check_ids), coverage)


def _fail(
    challenge: EngineeringChallenge,
    result: EngineeringIQResult,
) -> AuthoritativeScore:
    passed = sum(1 for item in result.check_results if item.passed)
    return AuthoritativeScore(
        Verdict.FAIL,
        passed,
        len(challenge.hidden_check_ids),
        MappingProxyType({dimension: False for dimension in challenge.dimensions}),
    )
