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


class EngineeringIQContractTests(unittest.TestCase):
    def challenge(self):
        return EngineeringChallenge(
            challenge_id="unfamiliar-system-001",
            title="Reconstruct and repair an unfamiliar system",
            dimensions=(
                EngineeringDimension.ARCHITECTURE_RECONSTRUCTION,
                EngineeringDimension.CAUSAL_DEBUGGING,
                EngineeringDimension.EVIDENCE_DISCIPLINE,
            ),
            public_brief="Find the causal defect and prove the smallest correct repair.",
            required_evidence=("root-cause-proof", "regression-proof"),
            hidden_check_ids=("architecture", "cause", "repair", "regression"),
            budget=ChallengeBudget(max_attempts=3, max_wall_seconds=1800, max_changed_files=8),
        )

    def result(self, *, claimed=Verdict.PASS, attempts=1, changed=("a.py",), checks=None):
        checks = checks or (
            CheckResult("architecture", True, ("root-cause-proof",)),
            CheckResult("cause", True),
            CheckResult("repair", True),
            CheckResult("regression", True, ("regression-proof",)),
        )
        return EngineeringIQResult(
            challenge_id="unfamiliar-system-001",
            source_revision="a" * 40,
            attempts_used=attempts,
            changed_files=changed,
            check_results=checks,
            claimed_verdict=claimed,
        )

    def grade(self, result):
        return score(
            self.challenge(),
            result,
            expected_source_revision="a" * 40,
            elapsed_wall_seconds=1,
            verified_evidence_refs=frozenset({"root-cause-proof", "regression-proof"}),
        )

    def test_agent_cannot_self_grade_a_failure_into_a_pass(self):
        checks = (
            CheckResult("architecture", True, ("root-cause-proof",)),
            CheckResult("cause", False),
            CheckResult("repair", True),
            CheckResult("regression", True, ("regression-proof",)),
        )
        self.assertEqual(self.grade(self.result(claimed=Verdict.PASS, checks=checks)).verdict, Verdict.FAIL)

    def test_hidden_check_omission_fails_closed(self):
        checks = (
            CheckResult("architecture", True, ("root-cause-proof",)),
            CheckResult("cause", True),
            CheckResult("repair", True, ("regression-proof",)),
        )
        self.assertEqual(self.grade(self.result(checks=checks)).verdict, Verdict.FAIL)

    def test_required_evidence_is_mandatory(self):
        checks = (
            CheckResult("architecture", True),
            CheckResult("cause", True),
            CheckResult("repair", True),
            CheckResult("regression", True),
        )
        self.assertEqual(self.grade(self.result(checks=checks)).verdict, Verdict.FAIL)

    def test_attempt_budget_is_authoritative(self):
        self.assertEqual(self.grade(self.result(attempts=4)).verdict, Verdict.FAIL)

    def test_changed_file_budget_is_authoritative(self):
        files = tuple(f"f{index}.py" for index in range(9))
        self.assertEqual(self.grade(self.result(changed=files)).verdict, Verdict.FAIL)

    def test_clean_complete_result_passes(self):
        scored = self.grade(self.result())
        self.assertEqual(scored.verdict, Verdict.PASS)
        self.assertEqual(scored.passed_checks, 4)
        self.assertEqual(scored.total_checks, 4)

    def test_duplicate_check_results_are_rejected(self):
        checks = (
            CheckResult("architecture", True, ("root-cause-proof",)),
            CheckResult("architecture", True),
            CheckResult("repair", True),
            CheckResult("regression", True, ("regression-proof",)),
        )
        with self.assertRaisesRegex(ValueError, "engineering_iq_duplicate_check_result"):
            self.grade(self.result(checks=checks))


if __name__ == "__main__":
    unittest.main()
