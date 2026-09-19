import unittest

from core.lil_tweak.engineering_iq import (
    AuthoritativeScore,
    ChallengeBudget,
    CheckResult,
    EngineeringChallenge,
    EngineeringDimension,
    EngineeringIQResult,
    VerifiedEvidence,
    Verdict,
    challenge_digest,
    score,
    verify_score,
)


class EngineeringIQReceiptCompletenessTests(unittest.TestCase):
    def challenge(self):
        return EngineeringChallenge(
            challenge_id="receipt-001",
            title="Complete receipt",
            dimensions=(EngineeringDimension.CAUSAL_DEBUGGING,),
            public_brief="Repair it.",
            required_evidence=("proof",),
            hidden_check_ids=("cause", "repair"),
            budget=ChallengeBudget(3, 20, 3),
            dimension_check_ids={EngineeringDimension.CAUSAL_DEBUGGING: ("cause", "repair")},
        )

    def evidence(self, challenge, sha="b" * 64):
        return (
            VerifiedEvidence("proof", sha, challenge_digest(challenge), "run-1", "a" * 40),
        )

    def result(self, challenge, *, attempts=1, checks=None, files=("fix.py",)):
        return EngineeringIQResult(
            challenge_id=challenge.challenge_id,
            challenge_digest=challenge_digest(challenge),
            run_id="run-1",
            source_revision="a" * 40,
            attempts_used=attempts,
            changed_files=files,
            check_results=checks or (
                CheckResult("cause", True, ("proof",)),
                CheckResult("repair", True),
            ),
            claimed_verdict=Verdict.PASS,
        )

    def grade(self, *, attempts=1, elapsed=1, checks=None, files=("fix.py",), evidence_sha="b" * 64):
        challenge = self.challenge()
        return score(
            challenge,
            self.result(challenge, attempts=attempts, checks=checks, files=files),
            expected_source_revision="a" * 40,
            expected_run_id="run-1",
            elapsed_wall_seconds=elapsed,
            verified_evidence=self.evidence(challenge, evidence_sha),
        )

    def test_receipt_changes_when_attempt_count_changes(self):
        self.assertNotEqual(
            self.grade(attempts=1).score_digest,
            self.grade(attempts=2).score_digest,
        )

    def test_receipt_changes_when_elapsed_time_changes(self):
        self.assertNotEqual(
            self.grade(elapsed=1).score_digest,
            self.grade(elapsed=2).score_digest,
        )

    def test_receipt_changes_when_changed_files_change(self):
        self.assertNotEqual(
            self.grade(files=("fix.py",)).score_digest,
            self.grade(files=("fix.py", "helper.py")).score_digest,
        )

    def test_receipt_changes_when_exact_check_pattern_changes(self):
        first = (
            CheckResult("cause", False, ("proof",)),
            CheckResult("repair", True),
        )
        second = (
            CheckResult("cause", True, ("proof",)),
            CheckResult("repair", False),
        )
        self.assertNotEqual(
            self.grade(checks=first).score_digest,
            self.grade(checks=second).score_digest,
        )

    def test_receipt_changes_when_evidence_bytes_change(self):
        self.assertNotEqual(
            self.grade(evidence_sha="b" * 64).score_digest,
            self.grade(evidence_sha="c" * 64).score_digest,
        )

    def test_score_exposes_immutable_exact_check_results(self):
        scored = self.grade()
        self.assertEqual(dict(scored.check_results), {"cause": True, "repair": True})
        with self.assertRaises(TypeError):
            scored.check_results["cause"] = False

    def test_score_exposes_budget_consumption(self):
        scored = self.grade(attempts=2, elapsed=3)
        self.assertEqual(scored.attempts_used, 2)
        self.assertEqual(scored.elapsed_wall_seconds, 3)

    def test_score_exposes_immutable_changed_files(self):
        scored = self.grade(files=("fix.py", "helper.py"))
        self.assertEqual(scored.changed_files, ("fix.py", "helper.py"))

    def test_verify_score_accepts_authoritative_receipt(self):
        self.assertTrue(verify_score(self.grade()))

    def test_verify_score_rejects_post_construction_tampering(self):
        scored = self.grade()
        object.__setattr__(scored, "passed_checks", 0)
        with self.assertRaisesRegex(ValueError, "engineering_iq_score_digest_mismatch"):
            verify_score(scored)


if __name__ == "__main__":
    unittest.main()
