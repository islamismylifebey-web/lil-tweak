import unittest
from types import MappingProxyType

from core.lil_tweak.engineering_iq import (
    ChallengeBudget,
    CheckResult,
    EngineeringChallenge,
    EngineeringDimension,
    EngineeringIQResult,
    Verdict,
    score,
)


class EngineeringIQAdversarialTests(unittest.TestCase):
    def challenge(self):
        return EngineeringChallenge(
            challenge_id="attack-001",
            title="Adversarial evaluator attack",
            dimensions=(
                EngineeringDimension.CAUSAL_DEBUGGING,
                EngineeringDimension.EVIDENCE_DISCIPLINE,
            ),
            public_brief="Repair the system under hidden verification.",
            required_evidence=("root-cause-proof", "regression-proof"),
            hidden_check_ids=("cause", "repair"),
            budget=ChallengeBudget(
                max_attempts=2,
                max_wall_seconds=10,
                max_changed_files=2,
            ),
            dimension_check_ids={
                EngineeringDimension.CAUSAL_DEBUGGING: ("cause", "repair"),
                EngineeringDimension.EVIDENCE_DISCIPLINE: ("cause",),
            },
        )

    def clean_result(self, **overrides):
        values = dict(
            challenge_id="attack-001",
            source_revision="a" * 40,
            attempts_used=1,
            changed_files=("a.py",),
            check_results=(
                CheckResult("cause", True, ("root-cause-proof",)),
                CheckResult("repair", True, ("regression-proof",)),
            ),
            claimed_verdict=Verdict.PASS,
        )
        values.update(overrides)
        return EngineeringIQResult(**values)

    def grade(self, result, *, source="a" * 40, elapsed=1, verified=None):
        return score(
            self.challenge(),
            result,
            expected_source_revision=source,
            elapsed_wall_seconds=elapsed,
            verified_evidence_refs=(
                frozenset({"root-cause-proof", "regression-proof"})
                if verified is None else verified
            ),
        )

    def test_zero_attempt_result_cannot_pass(self):
        self.assertEqual(
            self.grade(self.clean_result(attempts_used=0)).verdict,
            Verdict.FAIL,
        )

    def test_wrong_source_revision_cannot_pass(self):
        challenge = self.challenge()
        result = self.clean_result(source_revision="b" * 40)
        with self.assertRaisesRegex(ValueError, "engineering_iq_source_binding_mismatch"):
            score(
                challenge,
                result,
                expected_source_revision="a" * 40,
                elapsed_wall_seconds=1,
                verified_evidence_refs=frozenset({"root-cause-proof", "regression-proof"}),
            )

    def test_elapsed_wall_clock_is_enforced(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_wall_time_exceeded"):
            self.grade(self.clean_result(), elapsed=11)

    def test_negative_elapsed_wall_clock_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_wall_time_invalid"):
            self.grade(self.clean_result(), elapsed=-1)

    def test_fake_evidence_names_do_not_count_without_authoritative_registry(self):
        result = self.clean_result()
        with self.assertRaisesRegex(ValueError, "engineering_iq_evidence_unverified"):
            self.grade(result, verified=frozenset())

    def test_only_authoritatively_verified_evidence_counts(self):
        result = self.clean_result()
        scored = self.grade(result)
        self.assertEqual(scored.verdict, Verdict.PASS)

    def test_hidden_checks_are_not_present_in_public_challenge_view(self):
        public = self.challenge().public_view()
        self.assertFalse(hasattr(public, "hidden_check_ids"))
        self.assertEqual(public.challenge_id, "attack-001")

    def test_score_dimension_coverage_is_immutable(self):
        scored = self.grade(self.clean_result())
        with self.assertRaises(TypeError):
            scored.dimension_coverage[EngineeringDimension.CAUSAL_DEBUGGING] = False

    def test_empty_hidden_check_identifier_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_hidden_check_invalid"):
            EngineeringChallenge(
                challenge_id="bad",
                title="bad",
                dimensions=(EngineeringDimension.CAUSAL_DEBUGGING,),
                public_brief="bad",
                required_evidence=("proof",),
                hidden_check_ids=("",),
                budget=ChallengeBudget(1, 1, 1),
            )

    def test_duplicate_dimensions_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_dimension_duplicate"):
            EngineeringChallenge(
                challenge_id="bad",
                title="bad",
                dimensions=(
                    EngineeringDimension.CAUSAL_DEBUGGING,
                    EngineeringDimension.CAUSAL_DEBUGGING,
                ),
                public_brief="bad",
                required_evidence=("proof",),
                hidden_check_ids=("check",),
                budget=ChallengeBudget(1, 1, 1),
            )

    def test_non_dimension_value_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_dimension_invalid"):
            EngineeringChallenge(
                challenge_id="bad",
                title="bad",
                dimensions=("causal_debugging",),
                public_brief="bad",
                required_evidence=("proof",),
                hidden_check_ids=("check",),
                budget=ChallengeBudget(1, 1, 1),
            )

    def test_path_traversal_changed_file_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_changed_path_invalid"):
            self.grade(self.clean_result(changed_files=("../escape.py",)))

    def test_absolute_changed_file_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_changed_path_invalid"):
            self.grade(self.clean_result(changed_files=("/tmp/escape.py",)))

    def test_duplicate_changed_file_entries_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_changed_path_duplicate"):
            self.grade(self.clean_result(changed_files=("a.py", "a.py")))

    def test_unknown_claimed_verdict_type_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_claimed_verdict_invalid"):
            EngineeringIQResult(
                challenge_id="attack-001",
                source_revision="a" * 40,
                attempts_used=1,
                changed_files=("a.py",),
                check_results=(
                    CheckResult("cause", True, ("root-cause-proof",)),
                    CheckResult("repair", True, ("regression-proof",)),
                ),
                claimed_verdict="pass",
            )


if __name__ == "__main__":
    unittest.main()
