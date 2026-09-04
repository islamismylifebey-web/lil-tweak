import re
import unittest

from core.lil_tweak.test_world import (
    MemoryTestWorldStore,
    TestCheck,
    TestWorldConflict,
)


OWNER = "0123456789abcdef0123456789abcdef"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class TestWorldApprovedInvariantTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryTestWorldStore(clock=lambda: 1786636800.0)
        self.checks = (
            TestCheck("unit", ("python3", "-m", "unittest"), 60),
            TestCheck("lint", ("npm", "run", "lint"), 120),
        )

    def world(self, idem="world", checks=None):
        return self.store.create_world(
            OWNER,
            idempotency_key=idem,
            name="Durable repair",
            objective="Repair only the failing behavior",
            repository_url="https://github.com/example/project.git",
            commit="a" * 40,
            checks=checks or self.checks,
            max_attempts=3,
        )

    def test_world_and_judge_fingerprints_are_stable_and_distinct_contracts(self):
        world = self.world()
        retry = self.world()
        changed_judge = self.world(
            idem="changed",
            checks=(TestCheck("unit", ("python3", "-m", "unittest", "-v"), 60),),
        )

        self.assertRegex(world.fingerprint, HEX64)
        self.assertRegex(world.judge_version, HEX64)
        self.assertEqual(world.fingerprint, retry.fingerprint)
        self.assertEqual(world.judge_version, retry.judge_version)
        self.assertNotEqual(world.fingerprint, changed_judge.fingerprint)
        self.assertNotEqual(world.judge_version, changed_judge.judge_version)

    def test_attempt_snapshots_world_and_judge_versions(self):
        world = self.world()
        attempt = self.store.enqueue_attempt(world.id, OWNER, idempotency_key="attempt")
        self.assertEqual(attempt.world_fingerprint, world.fingerprint)
        self.assertEqual(attempt.judge_version, world.judge_version)

    def test_pass_is_rejected_without_complete_matching_judge_proof(self):
        world = self.world()
        attempt = self.store.enqueue_attempt(world.id, OWNER, idempotency_key="attempt")
        lease = self.store.claim_attempt(attempt.id, "worker", lease_seconds=60, now=100.0)

        with self.assertRaises(TestWorldConflict):
            self.store.complete_attempt(
                lease,
                passed=True,
                feedback=({"check": "unit", "passed": True},),
                cumulative_patch="patch",
                now=101.0,
            )

        with self.assertRaises(TestWorldConflict):
            self.store.complete_attempt(
                lease,
                passed=True,
                feedback=(
                    {"check": "unit", "passed": True},
                    {"check": "not-lint", "passed": True},
                ),
                cumulative_patch="patch",
                now=101.0,
            )

        completed = self.store.complete_attempt(
            lease,
            passed=True,
            feedback=(
                {"check": "unit", "passed": True},
                {"check": "lint", "passed": True},
            ),
            cumulative_patch="patch",
            duration_ms=1200,
            judge_duration_ms=300,
            now=102.0,
        )
        self.assertEqual(completed.outcome, "pass")
        self.assertEqual(completed.duration_ms, 1200)
        self.assertEqual(completed.judge_duration_ms, 300)

    def test_failed_attempt_records_bounded_resource_evidence(self):
        world = self.world(checks=(TestCheck("unit", ("python3", "-m", "unittest"), 60),))
        attempt = self.store.enqueue_attempt(world.id, OWNER, idempotency_key="attempt")
        lease = self.store.claim_attempt(attempt.id, "worker", lease_seconds=60, now=100.0)
        completed = self.store.complete_attempt(
            lease,
            passed=False,
            feedback=({
                "check": "unit",
                "passed": False,
                "exitCode": 1,
                "timedOut": False,
                "truncated": False,
                "stdout": "one failure",
                "stderr": "",
            },),
            cumulative_patch="patch",
            model_calls=2,
            input_tokens=100,
            output_tokens=25,
            total_tokens=125,
            duration_ms=1500,
            judge_duration_ms=400,
            now=102.0,
        )
        self.assertEqual(completed.model_calls, 2)
        self.assertEqual(completed.total_tokens, 125)
        self.assertEqual(completed.duration_ms, 1500)
        self.assertEqual(completed.judge_duration_ms, 400)
        self.assertEqual(completed.feedback[0]["exitCode"], 1)
        self.assertFalse(completed.feedback[0]["timedOut"])


if __name__ == "__main__":
    unittest.main()
