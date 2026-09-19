import random
import unittest
from dataclasses import replace

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
    verify_score,
)


SEEDS = (7, 101, 20260918)


class EngineeringIQFuzzTests(unittest.TestCase):
    def challenge(self):
        return EngineeringChallenge(
            challenge_id="fuzz-001",
            title="Fuzz evaluator",
            dimensions=(
                EngineeringDimension.CAUSAL_DEBUGGING,
                EngineeringDimension.SECURITY_REASONING,
            ),
            public_brief="Diagnose, repair, and prove.",
            required_evidence=("root-proof", "security-proof"),
            hidden_check_ids=("cause", "repair", "security"),
            budget=ChallengeBudget(3, 100, 5),
            dimension_check_ids={
                EngineeringDimension.CAUSAL_DEBUGGING: ("cause", "repair"),
                EngineeringDimension.SECURITY_REASONING: ("security",),
            },
        )

    def evidence(self, challenge=None):
        challenge = challenge or self.challenge()
        digest = challenge_digest(challenge)
        return (
            VerifiedEvidence("root-proof", "1" * 64, digest, "run-1", "a" * 40),
            VerifiedEvidence("security-proof", "2" * 64, digest, "run-1", "a" * 40),
        )

    def result(self, challenge=None):
        challenge = challenge or self.challenge()
        return EngineeringIQResult(
            challenge_id=challenge.challenge_id,
            challenge_digest=challenge_digest(challenge),
            run_id="run-1",
            source_revision="a" * 40,
            attempts_used=1,
            changed_files=("src/fix.py",),
            check_results=(
                CheckResult("cause", True, ("root-proof",)),
                CheckResult("repair", True),
                CheckResult("security", True, ("security-proof",)),
            ),
            claimed_verdict=Verdict.PASS,
        )

    def grade(self, challenge=None, result=None, evidence=None):
        challenge = challenge or self.challenge()
        return score(
            challenge,
            result or self.result(challenge),
            expected_source_revision="a" * 40,
            expected_run_id="run-1",
            elapsed_wall_seconds=1,
            verified_evidence=self.evidence(challenge) if evidence is None else evidence,
        )

    def test_seeded_bad_protocol_tokens_fail_closed(self):
        alphabet = [" ", "\n", "\t", "/", "\\", "\x00", "é", "💥"]
        for seed in SEEDS:
            rng = random.Random(seed)
            for index in range(100):
                bad = "ok" + rng.choice(alphabet) + str(index)
                with self.subTest(seed=seed, bad=repr(bad)):
                    with self.assertRaises(ValueError):
                        EngineeringChallenge(
                            challenge_id=bad,
                            title="x",
                            dimensions=(EngineeringDimension.CAUSAL_DEBUGGING,),
                            public_brief="x",
                            required_evidence=("proof",),
                            hidden_check_ids=("check",),
                            budget=ChallengeBudget(1, 1, 1),
                            dimension_check_ids={
                                EngineeringDimension.CAUSAL_DEBUGGING: ("check",)
                            },
                        )

    def test_seeded_bad_changed_paths_fail_closed(self):
        families = (
            "../x.py", "./x.py", "/x.py", "a/../x.py", "a/./x.py",
            "a\\x.py", "a//x.py", "", "..", ".",
        )
        for seed in SEEDS:
            rng = random.Random(seed)
            values = list(families)
            rng.shuffle(values)
            for bad in values:
                with self.subTest(seed=seed, bad=repr(bad)):
                    with self.assertRaisesRegex(ValueError, "engineering_iq_changed_path_invalid"):
                        replace(self.result(), changed_files=(bad,))

    def test_dimension_tuple_order_does_not_change_challenge_identity(self):
        first = self.challenge()
        second = EngineeringChallenge(
            challenge_id=first.challenge_id,
            title=first.title,
            dimensions=tuple(reversed(first.dimensions)),
            public_brief=first.public_brief,
            required_evidence=first.required_evidence,
            hidden_check_ids=first.hidden_check_ids,
            budget=first.budget,
            dimension_check_ids={
                EngineeringDimension.SECURITY_REASONING: ("security",),
                EngineeringDimension.CAUSAL_DEBUGGING: ("cause", "repair"),
            },
        )
        self.assertEqual(challenge_digest(first), challenge_digest(second))

    def test_required_evidence_order_does_not_change_challenge_identity(self):
        first = self.challenge()
        second = EngineeringChallenge(
            challenge_id=first.challenge_id,
            title=first.title,
            dimensions=first.dimensions,
            public_brief=first.public_brief,
            required_evidence=tuple(reversed(first.required_evidence)),
            hidden_check_ids=first.hidden_check_ids,
            budget=first.budget,
            dimension_check_ids=first.dimension_check_ids,
        )
        self.assertEqual(challenge_digest(first), challenge_digest(second))

    def test_hidden_check_order_does_not_change_challenge_identity(self):
        first = self.challenge()
        second = EngineeringChallenge(
            challenge_id=first.challenge_id,
            title=first.title,
            dimensions=first.dimensions,
            public_brief=first.public_brief,
            required_evidence=first.required_evidence,
            hidden_check_ids=tuple(reversed(first.hidden_check_ids)),
            budget=first.budget,
            dimension_check_ids=first.dimension_check_ids,
        )
        self.assertEqual(challenge_digest(first), challenge_digest(second))

    def test_random_single_private_mutations_change_digest(self):
        base = self.challenge()
        original = challenge_digest(base)
        variants = (
            replace(base, title="Fuzz evaluator changed"),
            replace(base, public_brief="Different brief."),
            replace(base, budget=ChallengeBudget(2, 100, 5)),
            replace(base, hidden_check_ids=("cause", "repair", "security", "extra"),
                    dimension_check_ids={
                        EngineeringDimension.CAUSAL_DEBUGGING: ("cause", "repair"),
                        EngineeringDimension.SECURITY_REASONING: ("security", "extra"),
                    }),
            replace(base, required_evidence=("root-proof", "security-proof", "extra-proof")),
        )
        for variant in variants:
            with self.subTest(variant=variant.title):
                self.assertNotEqual(original, challenge_digest(variant))

    def test_every_receipt_scalar_tamper_is_detected(self):
        original = self.grade()
        mutations = (
            ("passed_checks", 0),
            ("total_checks", 999),
            ("attempts_used", 2),
            ("elapsed_wall_seconds", 2.0),
            ("changed_files", ("src/other.py",)),
            ("challenge_digest", "f" * 64),
            ("run_id", "run-2"),
            ("source_revision", "b" * 40),
            ("score_digest", "0" * 64),
        )
        for field, value in mutations:
            tampered = replace(original, **{field: value})
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "engineering_iq_score_digest_mismatch"):
                    verify_score(tampered)

    def test_every_check_result_flip_changes_receipt(self):
        base = self.challenge()
        original = self.result(base)
        baseline = self.grade(base, original).score_digest
        for index in range(len(original.check_results)):
            checks = list(original.check_results)
            item = checks[index]
            checks[index] = replace(item, passed=not item.passed)
            changed = replace(original, check_results=tuple(checks))
            with self.subTest(check=item.check_id):
                self.assertNotEqual(baseline, self.grade(base, changed).score_digest)

    def test_every_evidence_content_mutation_changes_receipt(self):
        challenge = self.challenge()
        baseline = self.grade(challenge).score_digest
        evidence = list(self.evidence(challenge))
        for index in range(len(evidence)):
            changed = evidence.copy()
            item = changed[index]
            changed[index] = replace(item, evidence_sha256=("f" if item.evidence_sha256[0] != "f" else "e") * 64)
            with self.subTest(ref=item.evidence_ref):
                self.assertNotEqual(
                    baseline,
                    self.grade(challenge, evidence=tuple(changed)).score_digest,
                )


if __name__ == "__main__":
    unittest.main()
