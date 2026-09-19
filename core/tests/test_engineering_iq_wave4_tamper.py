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


class EngineeringIQTamperTests(unittest.TestCase):
    def challenge(self, **overrides):
        values = dict(
            challenge_id="tamper-001",
            title="Tamper-verifiable benchmark",
            dimensions=(EngineeringDimension.SECURITY_REASONING,),
            public_brief="Prove the repair.",
            required_evidence=("proof",),
            hidden_check_ids=("security",),
            budget=ChallengeBudget(1, 10, 1),
            dimension_check_ids={EngineeringDimension.SECURITY_REASONING: ("security",)},
        )
        values.update(overrides)
        return EngineeringChallenge(**values)

    def result(self, challenge=None):
        challenge = challenge or self.challenge()
        return EngineeringIQResult(
            challenge_id=challenge.challenge_id,
            challenge_digest=challenge_digest(challenge),
            run_id="run-1",
            source_revision="a" * 40,
            attempts_used=1,
            changed_files=("fix.py",),
            check_results=(CheckResult("security", True, ("proof",)),),
            claimed_verdict=Verdict.PASS,
        )

    def evidence(self, challenge=None, *, sha="b" * 64):
        challenge = challenge or self.challenge()
        return (
            VerifiedEvidence(
                evidence_ref="proof",
                evidence_sha256=sha,
                challenge_digest=challenge_digest(challenge),
                run_id="run-1",
                source_revision="a" * 40,
            ),
        )

    def grade(self, challenge=None):
        challenge = challenge or self.challenge()
        return score(
            challenge,
            self.result(challenge),
            expected_source_revision="a" * 40,
            expected_run_id="run-1",
            elapsed_wall_seconds=1,
            verified_evidence=self.evidence(challenge),
        )

    def test_verified_evidence_requires_content_sha256(self):
        with self.assertRaisesRegex(ValueError, "engineering_iq_evidence_digest_invalid"):
            self.evidence(sha="not-a-digest")

    def test_authoritative_score_carries_challenge_binding(self):
        scored = self.grade()
        self.assertEqual(scored.challenge_digest, challenge_digest(self.challenge()))

    def test_authoritative_score_carries_run_binding(self):
        self.assertEqual(self.grade().run_id, "run-1")

    def test_authoritative_score_carries_source_binding(self):
        self.assertEqual(self.grade().source_revision, "a" * 40)

    def test_authoritative_score_has_tamper_digest(self):
        scored = self.grade()
        self.assertRegex(scored.score_digest, r"^[0-9a-f]{64}$")

    def test_challenge_digest_is_stable_under_dimension_map_insertion_order(self):
        first = EngineeringChallenge(
            challenge_id="order",
            title="order",
            dimensions=(EngineeringDimension.CAUSAL_DEBUGGING, EngineeringDimension.SECURITY_REASONING),
            public_brief="order",
            required_evidence=("proof",),
            hidden_check_ids=("cause", "security"),
            budget=ChallengeBudget(1, 10, 1),
            dimension_check_ids={
                EngineeringDimension.CAUSAL_DEBUGGING: ("cause",),
                EngineeringDimension.SECURITY_REASONING: ("security",),
            },
        )
        second = EngineeringChallenge(
            challenge_id="order",
            title="order",
            dimensions=(EngineeringDimension.CAUSAL_DEBUGGING, EngineeringDimension.SECURITY_REASONING),
            public_brief="order",
            required_evidence=("proof",),
            hidden_check_ids=("cause", "security"),
            budget=ChallengeBudget(1, 10, 1),
            dimension_check_ids={
                EngineeringDimension.SECURITY_REASONING: ("security",),
                EngineeringDimension.CAUSAL_DEBUGGING: ("cause",),
            },
        )
        self.assertEqual(challenge_digest(first), challenge_digest(second))

    def test_challenge_digest_changes_when_dimension_binding_changes(self):
        first = EngineeringChallenge(
            challenge_id="binding",
            title="binding",
            dimensions=(EngineeringDimension.CAUSAL_DEBUGGING,),
            public_brief="binding",
            required_evidence=("proof",),
            hidden_check_ids=("cause", "repair"),
            budget=ChallengeBudget(1, 10, 1),
            dimension_check_ids={EngineeringDimension.CAUSAL_DEBUGGING: ("cause",)},
        )
        second = EngineeringChallenge(
            challenge_id="binding",
            title="binding",
            dimensions=(EngineeringDimension.CAUSAL_DEBUGGING,),
            public_brief="binding",
            required_evidence=("proof",),
            hidden_check_ids=("cause", "repair"),
            budget=ChallengeBudget(1, 10, 1),
            dimension_check_ids={EngineeringDimension.CAUSAL_DEBUGGING: ("repair",)},
        )
        self.assertNotEqual(challenge_digest(first), challenge_digest(second))

    def test_challenge_copies_private_mapping_before_digesting(self):
        mapping = {EngineeringDimension.SECURITY_REASONING: ("security",)}
        challenge = EngineeringChallenge(
            challenge_id="copy",
            title="copy",
            dimensions=(EngineeringDimension.SECURITY_REASONING,),
            public_brief="copy",
            required_evidence=("proof",),
            hidden_check_ids=("security",),
            budget=ChallengeBudget(1, 10, 1),
            dimension_check_ids=mapping,
        )
        before = challenge_digest(challenge)
        mapping[EngineeringDimension.SECURITY_REASONING] = ("other",)
        self.assertEqual(challenge_digest(challenge), before)


if __name__ == "__main__":
    unittest.main()
