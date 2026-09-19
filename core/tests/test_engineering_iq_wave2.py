import math
import unittest

from core.lil_tweak.engineering_iq import (
    ChallengeBudget,
    CheckResult,
    EngineeringChallenge,
    EngineeringDimension,
    EngineeringIQResult,
    Verdict,
    score,
)


class EngineeringIQSecondWaveTests(unittest.TestCase):
    def result(self):
        return EngineeringIQResult(
            challenge_id="wave2",
            source_revision="a" * 40,
            attempts_used=1,
            changed_files=("fix.py",),
            check_results=(
                CheckResult("cause", True, ("proof",)),
                CheckResult("repair", True),
            ),
            claimed_verdict=Verdict.PASS,
        )

    def challenge(self, **overrides):
        values = dict(
            challenge_id="wave2",
            title="Second-wave evaluator assault",
            dimensions=(EngineeringDimension.CAUSAL_DEBUGGING,),
            public_brief="Diagnose and repair.",
            required_evidence=("proof",),
            hidden_check_ids=("cause", "repair"),
            budget=ChallengeBudget(2, 10, 3),
        )
        values.update(overrides)
        return EngineeringChallenge(**values)

    def grade(self, challenge=None, *, elapsed=1, verified=frozenset({"proof"})):
        return score(
            challenge or self.challenge(),
            self.result(),
            expected_source_revision="a" * 40,
            elapsed_wall_seconds=elapsed,
            verified_evidence_refs=verified,
        )

    def test_nan_wall_clock_cannot_bypass_budget(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_wall_time_invalid"):
            self.grade(elapsed=float("nan"))

    def test_positive_infinity_is_invalid_not_merely_over_budget(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_wall_time_invalid"):
            self.grade(elapsed=float("inf"))

    def test_negative_infinity_is_invalid(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_wall_time_invalid"):
            self.grade(elapsed=float("-inf"))

    def test_verified_evidence_registry_is_count_bounded(self):
        huge = frozenset(f"proof-{index}" for index in range(300))
        with self.assertRaisesRegex(ValueError, "engineering_iq_evidence_registry_invalid"):
            self.grade(verified=huge)

    def test_verified_evidence_registry_tokens_are_bounded(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_evidence_registry_invalid"):
            self.grade(verified=frozenset({"x" * 1000, "proof"}))

    def test_hidden_check_tokens_reject_whitespace_and_control_characters(self):
        for bad in (" cause", "cause ", "cause\n", "cause\t", "cause check"):
            with self.subTest(bad=repr(bad)):
                with self.assertRaisesRegex(ValueError, "engineering_iq_hidden_check_invalid"):
                    self.challenge(hidden_check_ids=(bad, "repair"))

    def test_evidence_tokens_reject_whitespace_and_control_characters(self):
        for bad in (" proof", "proof ", "proof\n", "proof\t", "proof name"):
            with self.subTest(bad=repr(bad)):
                with self.assertRaisesRegex(ValueError, "engineering_iq_evidence_invalid"):
                    self.challenge(required_evidence=(bad,))

    def test_dimension_cannot_be_claimed_without_a_private_check_binding(self):
        challenge = self.challenge(
            dimensions=(
                EngineeringDimension.CAUSAL_DEBUGGING,
                EngineeringDimension.SECURITY_REASONING,
            ),
        )
        with self.assertRaisesRegex(ValueError, "engineering_iq_dimension_unbound"):
            self.grade(challenge)

    def test_dimension_coverage_is_derived_from_its_own_bound_checks(self):
        challenge = self.challenge(
            dimensions=(
                EngineeringDimension.CAUSAL_DEBUGGING,
                EngineeringDimension.SECURITY_REASONING,
            ),
            hidden_check_ids=("cause", "repair", "security"),
            dimension_check_ids={
                EngineeringDimension.CAUSAL_DEBUGGING: ("cause", "repair"),
                EngineeringDimension.SECURITY_REASONING: ("security",),
            },
        )
        result = EngineeringIQResult(
            challenge_id="wave2",
            source_revision="a" * 40,
            attempts_used=1,
            changed_files=("fix.py",),
            check_results=(
                CheckResult("cause", True, ("proof",)),
                CheckResult("repair", True),
                CheckResult("security", False),
            ),
            claimed_verdict=Verdict.PASS,
        )
        scored = score(
            challenge,
            result,
            expected_source_revision="a" * 40,
            elapsed_wall_seconds=1,
            verified_evidence_refs=frozenset({"proof"}),
        )
        self.assertTrue(scored.dimension_coverage[EngineeringDimension.CAUSAL_DEBUGGING])
        self.assertFalse(scored.dimension_coverage[EngineeringDimension.SECURITY_REASONING])
        self.assertEqual(scored.verdict, Verdict.FAIL)


if __name__ == "__main__":
    unittest.main()
