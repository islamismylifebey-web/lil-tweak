"""Deterministic contracts for Lil' Tueeq Engineering IQ evaluation.

This module does not call a model and does not let an agent grade itself.
It defines the challenge, evidence, and scoring boundaries used by Test World.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping


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


@dataclass(frozen=True, slots=True)
class ChallengeBudget:
    max_attempts: int
    max_wall_seconds: int
    max_changed_files: int

    def __post_init__(self) -> None:
        for value in (self.max_attempts, self.max_wall_seconds, self.max_changed_files):
            if type(value) is not int or value < 1:
                raise ValueError("engineering_iq_budget_invalid")


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
        if not self.challenge_id or not self.title or not self.public_brief:
            raise ValueError("engineering_iq_challenge_invalid")
        if not self.dimensions or not self.required_evidence or not self.hidden_check_ids:
            raise ValueError("engineering_iq_challenge_incomplete")
        if len(set(self.hidden_check_ids)) != len(self.hidden_check_ids):
            raise ValueError("engineering_iq_hidden_check_duplicate")


@dataclass(frozen=True, slots=True)
class CheckResult:
    check_id: str
    passed: bool
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.check_id or type(self.passed) is not bool:
            raise ValueError("engineering_iq_check_invalid")


@dataclass(frozen=True, slots=True)
class EngineeringIQResult:
    challenge_id: str
    source_revision: str
    attempts_used: int
    changed_files: tuple[str, ...]
    check_results: tuple[CheckResult, ...]
    claimed_verdict: Verdict | None = None

    def __post_init__(self) -> None:
        if not self.challenge_id or not self.source_revision:
            raise ValueError("engineering_iq_result_invalid")
        if type(self.attempts_used) is not int or self.attempts_used < 0:
            raise ValueError("engineering_iq_attempt_count_invalid")


@dataclass(frozen=True, slots=True)
class AuthoritativeScore:
    verdict: Verdict
    passed_checks: int
    total_checks: int
    dimension_coverage: Mapping[EngineeringDimension, bool]


def score(
    challenge: EngineeringChallenge,
    result: EngineeringIQResult,
) -> AuthoritativeScore:
    if result.challenge_id != challenge.challenge_id:
        raise ValueError("engineering_iq_challenge_binding_mismatch")
    if result.attempts_used > challenge.budget.max_attempts:
        return _fail(challenge, result)
    if len(set(result.changed_files)) > challenge.budget.max_changed_files:
        return _fail(challenge, result)

    by_id = {item.check_id: item for item in result.check_results}
    if len(by_id) != len(result.check_results):
        raise ValueError("engineering_iq_duplicate_check_result")
    if set(by_id) != set(challenge.hidden_check_ids):
        return _fail(challenge, result)

    evidence = {ref for item in result.check_results for ref in item.evidence_refs}
    if any(required not in evidence for required in challenge.required_evidence):
        return _fail(challenge, result)

    passed = sum(1 for item in result.check_results if item.passed)
    verdict = Verdict.PASS if passed == len(challenge.hidden_check_ids) else Verdict.FAIL
    coverage = {dimension: verdict is Verdict.PASS for dimension in challenge.dimensions}
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
        {dimension: False for dimension in challenge.dimensions},
    )
