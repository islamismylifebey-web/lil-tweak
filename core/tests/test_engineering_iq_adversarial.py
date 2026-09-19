import unittest

from core.lil_tweak.engineering_iq import (
    ChallengeBudget,
    CheckResult,
    EngineeringChallenge,
    EngineeringDimension,
    EngineeringIQResult,
    VerifiedEvidence,
    Verdict,
    challenge_digest,
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
            budget=ChallengeBudget(2, 10, 2),
            dimension_check_ids={
                EngineeringDimension.CAUSAL_DEBUGGING: ("cause", "repair"),
                EngineeringDimension.EVIDENCE_DISCIPLINE: ("cause",),
            },
        )

    def clean_result(self, **overrides):
        challenge = self.challenge()
        values = dict(
            challenge_id="attack-001",
            challenge_digest=challenge_digest(challenge),
            run_id="run-1",
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

    def evidence(self, refs=("root-cause-proof", "regression-proof")):
        challenge = self.challenge()
        digest = challenge_digest(challenge)
        return tuple(VerifiedEvidence(ref, "3" * 64, digest, "run-1", "a" * 40) for ref in refs)

    def grade(self, result, *, source="a" * 40, elapsed=1, evidence=None):
        return score(
            self.challenge(),
            result,
            expected_source_revision=source,
            expected_run_id="run-1",
            elapsed_wall_seconds=elapsed,
            verified_evidence=self.evidence() if evidence is None else evidence,
        )

    def test_zero_attempt_result_cannot_pass(self):
        self.assertEqual(self.grade(self.clean_result(attempts_used=0)).verdict, Verdict.FAIL)

    def test_wrong_source_revision_cannot_pass(self):
        result = self.clean_result(source_revision="b" * 40)
        with self.assertRaisesRegex(ValueError, "engineering_iq_source_binding_mismatch"):
            self.grade(result)

    def test_elapsed_wall_clock_is_enforced(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_wall_time_exceeded"):
            self.grade(self.clean_result(), elapsed=11)

    def test_negative_elapsed_wall_clock_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_wall_time_invalid"):
            self.grade(self.clean_result(), elapsed=-1)

    def test_fake_evidence_names_do_not_count_without_authoritative_registry(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_evidence_unverified"):
            self.grade(self.clean_result(), evidence=())

    def test_only_authoritatively_verified_evidence_counts(self):
        self.assertEqual(self.grade(self.clean_result()).verdict, Verdict.PASS)

    def test_hidden_checks_are_not_present_in_public_challenge_view(self):
        public = self.challenge().public_view()
        self.assertFalse(hasattr(public, "hidden_check_ids"))
        self.assertFalse(hasattr(public, "dimension_check_ids"))
        self.assertEqual(public.challenge_id, "attack-001")

    def test_score_dimension_coverage_is_immutable(self):
        scored = self.grade(self.clean_result())
        with self.assertRaises(TypeError):
            scored.dimension_coverage[EngineeringDimension.CAUSAL_DEBUGGING] = False

    def test_empty_hidden_check_identifier_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_hidden_check_invalid"):
            EngineeringChallenge(
                challenge_id="bad", title="bad",
                dimensions=(EngineeringDimension.CAUSAL_DEBUGGING,),
                public_brief="bad", required_evidence=("proof",),
                hidden_check_ids=("",), budget=ChallengeBudget(1, 1, 1),
            )

    def test_duplicate_dimensions_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_dimension_duplicate"):
            EngineeringChallenge(
                challenge_id="bad", title="bad",
                dimensions=(EngineeringDimension.CAUSAL_DEBUGGING, EngineeringDimension.CAUSAL_DEBUGGING),
                public_brief="bad", required_evidence=("proof",),
                hidden_check_ids=("check",), budget=ChallengeBudget(1, 1, 1),
            )

    def test_non_dimension_value_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_dimension_invalid"):
            EngineeringChallenge(
                challenge_id="bad", title="bad", dimensions=("causal_debugging",),
                public_brief="bad", required_evidence=("proof",),
                hidden_check_ids=("check",), budget=ChallengeBudget(1, 1, 1),
            )

    def test_path_traversal_changed_file_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_changed_path_invalid"):
            self.clean_result(changed_files=("../escape.py",))

    def test_absolute_changed_file_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_changed_path_invalid"):
            self.clean_result(changed_files=("/tmp/escape.py",))

    def test_duplicate_changed_file_entries_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_changed_path_duplicate"):
            self.clean_result(changed_files=("a.py", "a.py"))

    def test_unknown_claimed_verdict_type_is_rejected(self):
        challenge = self.challenge()
        with self.assertRaisesRegex(ValueError, "engineering_iq_claimed_verdict_invalid"):
            EngineeringIQResult(
                challenge_id="attack-001",
                challenge_digest=challenge_digest(challenge),
                run_id="run-1",
                source_revision="a" * 40,
                attempts_used=1,
                changed_files=("a.py",),
                check_results=(CheckResult("cause", True), CheckResult("repair", True)),
                claimed_verdict="pass",
            )


if __name__ == "__main__":
    unittest.main()
