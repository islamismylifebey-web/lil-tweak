import unittest

from core.lil_tweak.test_world import (
    AttemptStatus,
    MemoryTestWorldStore,
    TestCheck,
    TestWorldConflict,
    TestWorldLimitReached,
    WorldStatus,
)


OWNER = "0123456789abcdef0123456789abcdef"
SOURCE_URL = "https://github.com/example/project.git"
SOURCE_COMMIT = "a" * 40


class DurableTestWorldStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryTestWorldStore(clock=lambda: 1_786_636_800.0)
        self.checks = (
            TestCheck("unit tests", ("python3", "-m", "unittest"), 60),
            TestCheck("typecheck", ("npm", "run", "typecheck"), 120),
        )

    def create_world(self, *, idem="world-1", objective="Repair the failing behavior", max_attempts=3):
        return self.store.create_world(
            OWNER,
            idempotency_key=idem,
            name="Practice failure recovery",
            objective=objective,
            repository_url=SOURCE_URL,
            commit=SOURCE_COMMIT,
            checks=self.checks,
            max_attempts=max_attempts,
        )

    def test_world_creation_is_idempotent_but_conflicting_reuse_is_rejected(self):
        created = self.create_world()
        retried = self.create_world()

        self.assertEqual(created.id, retried.id)
        self.assertEqual(created.status, WorldStatus.READY)
        self.assertEqual(created.max_attempts, 3)
        self.assertEqual(created.checks, self.checks)

        with self.assertRaises(TestWorldConflict):
            self.create_world(objective="A different challenge")

    def test_attempt_is_queued_claimed_and_failed_with_authoritative_feedback(self):
        world = self.create_world()
        attempt = self.store.enqueue_attempt(
            world.id,
            OWNER,
            idempotency_key="attempt-1",
        )
        self.assertEqual(attempt.number, 1)
        self.assertEqual(attempt.status, AttemptStatus.QUEUED)
        self.assertEqual(self.store.get_world(world.id, OWNER).status, WorldStatus.RUNNING)

        lease = self.store.claim_attempt(
            attempt.id,
            worker_id="worker-a",
            lease_seconds=30,
            now=100.0,
        )
        self.assertIsNotNone(lease)
        running = self.store.get_attempt(attempt.id, OWNER)
        self.assertEqual(running.status, AttemptStatus.RUNNING)
        self.assertEqual(lease.generation, 1)

        completed = self.store.complete_attempt(
            lease,
            passed=False,
            feedback=(
                {
                    "check": "unit tests",
                    "passed": False,
                    "exitCode": 1,
                    "timedOut": False,
                    "truncated": False,
                    "stdout": "1 failure",
                    "stderr": "",
                },
            ),
            cumulative_patch="--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-old\n+new\n",
            plan="Inspect and repair",
            summary="One check still fails",
            tests="unit tests failed",
            model_calls=2,
            input_tokens=100,
            output_tokens=50,
            total_tokens=150,
            now=110.0,
        )

        self.assertEqual(completed.status, AttemptStatus.FAILED)
        self.assertEqual(completed.outcome, "fail")
        self.assertEqual(self.store.get_world(world.id, OWNER).status, WorldStatus.FAILED)
        self.assertEqual(completed.feedback[0]["check"], "unit tests")
        self.assertEqual(completed.cumulative_patch.startswith("--- a/"), True)

    def test_retry_uses_monotonic_attempt_numbers_and_pass_closes_world(self):
        world = self.create_world()
        first = self.store.enqueue_attempt(world.id, OWNER, idempotency_key="attempt-1")
        first_lease = self.store.claim_attempt(first.id, "worker-a", lease_seconds=30, now=100.0)
        self.store.complete_attempt(
            first_lease,
            passed=False,
            feedback=({"check": "unit tests", "passed": False},),
            cumulative_patch="first patch",
            now=110.0,
        )

        second = self.store.enqueue_attempt(world.id, OWNER, idempotency_key="attempt-2")
        self.assertEqual(second.number, 2)
        self.assertEqual(second.previous_attempt_id, first.id)
        second_lease = self.store.claim_attempt(second.id, "worker-b", lease_seconds=30, now=120.0)
        passed = self.store.complete_attempt(
            second_lease,
            passed=True,
            feedback=({"check": "unit tests", "passed": True},),
            cumulative_patch="second patch",
            now=130.0,
        )

        self.assertEqual(passed.status, AttemptStatus.PASSED)
        self.assertEqual(self.store.get_world(world.id, OWNER).status, WorldStatus.PASSED)
        with self.assertRaises(TestWorldLimitReached):
            self.store.enqueue_attempt(world.id, OWNER, idempotency_key="attempt-3")

    def test_failed_final_attempt_exhausts_world(self):
        world = self.create_world(max_attempts=2)
        for number in (1, 2):
            attempt = self.store.enqueue_attempt(
                world.id,
                OWNER,
                idempotency_key=f"attempt-{number}",
            )
            lease = self.store.claim_attempt(
                attempt.id,
                f"worker-{number}",
                lease_seconds=30,
                now=100.0 + number,
            )
            self.store.complete_attempt(
                lease,
                passed=False,
                feedback=({"check": "unit tests", "passed": False},),
                cumulative_patch=f"patch-{number}",
                now=110.0 + number,
            )

        self.assertEqual(self.store.get_world(world.id, OWNER).status, WorldStatus.EXHAUSTED)
        with self.assertRaises(TestWorldLimitReached):
            self.store.enqueue_attempt(world.id, OWNER, idempotency_key="attempt-3")

    def test_only_one_attempt_can_be_active_for_a_world(self):
        world = self.create_world()
        first = self.store.enqueue_attempt(world.id, OWNER, idempotency_key="attempt-1")
        retried = self.store.enqueue_attempt(world.id, OWNER, idempotency_key="attempt-1")
        self.assertEqual(retried.id, first.id)
        with self.assertRaises(TestWorldConflict):
            self.store.enqueue_attempt(world.id, OWNER, idempotency_key="attempt-2")

    def test_expired_running_lease_is_reconciled_to_queued_and_generation_fenced(self):
        world = self.create_world()
        attempt = self.store.enqueue_attempt(world.id, OWNER, idempotency_key="attempt-1")
        lease = self.store.claim_attempt(attempt.id, "worker-a", lease_seconds=10, now=100.0)

        reconciled = self.store.reconcile_active_attempts(now=111.0, limit=10)
        self.assertEqual([item.id for item in reconciled], [attempt.id])
        self.assertEqual(self.store.get_attempt(attempt.id, OWNER).status, AttemptStatus.QUEUED)

        replacement = self.store.claim_attempt(attempt.id, "worker-b", lease_seconds=10, now=112.0)
        self.assertEqual(replacement.generation, lease.generation + 1)
        with self.assertRaises(TestWorldConflict):
            self.store.complete_attempt(
                lease,
                passed=True,
                feedback=(),
                cumulative_patch="stale",
                now=113.0,
            )


if __name__ == "__main__":
    unittest.main()
