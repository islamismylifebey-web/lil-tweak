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


class EngineeringIQReplayAttackTests(unittest.TestCase):
    def challenge(self, *, budget=ChallengeBudget(2, 10, 2)):
        return EngineeringChallenge(
            challenge_id="replay-001",
            title="Replay-resistant challenge",
            dimensions=(EngineeringDimension.CAUSAL_DEBUGGING,),
            public_brief="Find and repair the cause.",
            required_evidence=("proof",),
            hidden_check_ids=("cause", "repair"),
            budget=budget,
            dimension_check_ids={
                EngineeringDimension.CAUSAL_DEBUGGING: ("cause", "repair"),
            },
        )

    def result(self, challenge, *, run_id="run-1", digest=None):
        return EngineeringIQResult(
            challenge_id=challenge.challenge_id,
            challenge_digest=digest or challenge_digest(challenge),
            run_id=run_id,
            source_revision="a" * 40,
            attempts_used=1,
            changed_files=("fix.py",),
            check_results=(
                CheckResult("cause", True, ("proof",)),
                CheckResult("repair", True),
            ),
            claimed_verdict=Verdict.PASS,
        )

    def evidence(self, challenge, *, run_id="run-1", source="a" * 40, digest=None):
        return (
            VerifiedEvidence(
                evidence_ref="proof",
                challenge_digest=digest or challenge_digest(challenge),
                run_id=run_id,
                source_revision=source,
            ),
        )

    def grade(self, challenge, result, evidence):
        return score(
            challenge,
            result,
            expected_source_revision="a" * 40,
            expected_run_id="run-1",
            elapsed_wall_seconds=1,
            verified_evidence=evidence,
        )

    def test_challenge_digest_changes_when_private_budget_changes(self):
        self.assertNotEqual(
            challenge_digest(self.challenge()),
            challenge_digest(self.challenge(budget=ChallengeBudget(1, 10, 2))),
        )

    def test_result_from_different_challenge_digest_is_rejected(self):
        challenge = self.challenge()
        result = self.result(challenge, digest="0" * 64)
        with self.assertRaisesRegex(ValueError, "engineering_iq_challenge_digest_mismatch"):
            self.grade(challenge, result, self.evidence(challenge))

    def test_result_from_different_run_is_rejected(self):
        challenge = self.challenge()
        result = self.result(challenge, run_id="run-2")
        with self.assertRaisesRegex(ValueError, "engineering_iq_run_binding_mismatch"):
            self.grade(challenge, result, self.evidence(challenge))

    def test_evidence_from_different_run_is_rejected(self):
        challenge = self.challenge()
        with self.assertRaisesRegex(ValueError, "engineering_iq_evidence_binding_mismatch"):
            self.grade(challenge, self.result(challenge), self.evidence(challenge, run_id="run-2"))

    def test_evidence_from_different_source_is_rejected(self):
        challenge = self.challenge()
        with self.assertRaisesRegex(ValueError, "engineering_iq_evidence_binding_mismatch"):
            self.grade(challenge, self.result(challenge), self.evidence(challenge, source="b" * 40))

    def test_evidence_from_different_challenge_is_rejected(self):
        challenge = self.challenge()
        with self.assertRaisesRegex(ValueError, "engineering_iq_evidence_binding_mismatch"):
            self.grade(
                challenge,
                self.result(challenge),
                self.evidence(challenge, digest="f" * 64),
            )

    def test_duplicate_evidence_reference_records_are_rejected(self):
        challenge = self.challenge()
        item = self.evidence(challenge)[0]
        with self.assertRaisesRegex(ValueError, "engineering_iq_evidence_duplicate"):
            self.grade(challenge, self.result(challenge), (item, item))

    def test_run_id_is_protocol_bounded(self):
        challenge = self.challenge()
        with self.assertRaisesRegex(ValueError, "engineering_iq_run_id_invalid"):
            self.result(challenge, run_id="bad run")

    def test_digest_is_private_configuration_sensitive(self):
        first = self.challenge()
        second = EngineeringChallenge(
            challenge_id="replay-001",
            title=first.title,
            dimensions=first.dimensions,
            public_brief=first.public_brief,
            required_evidence=first.required_evidence,
            hidden_check_ids=("cause", "repair", "extra"),
            budget=first.budget,
            dimension_check_ids={
                EngineeringDimension.CAUSAL_DEBUGGING: ("cause", "repair", "extra"),
            },
        )
        self.assertNotEqual(challenge_digest(first), challenge_digest(second))


if __name__ == "__main__":
    unittest.main()
