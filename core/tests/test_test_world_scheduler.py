import threading
import unittest
from concurrent.futures import Future
from contextlib import contextmanager

from core.lil_tweak.test_world import MemoryTestWorldStore, TestCheck
from core.lil_tweak.test_world_scheduler import TestWorldScheduler


OWNER = "0123456789abcdef0123456789abcdef"


class ImmediateExecutor:
    def submit(self, fn, *args):
        future = Future()
        try:
            future.set_result(fn(*args))
        except BaseException as error:
            future.set_exception(error)
        return future

    def shutdown(self, wait=True, cancel_futures=False):
        pass


class Runner:
    def __init__(self):
        self.calls = []

    def run_attempt(self, attempt_id, owner_id, *, lease=None):
        self.calls.append((attempt_id, owner_id, lease))
        return "done"


class TestWorldSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryTestWorldStore(clock=lambda: 100.0)
        world = self.store.create_world(
            OWNER,
            idempotency_key="world",
            name="Scheduler",
            objective="Run durably",
            repository_url="https://github.com/example/project.git",
            commit="a" * 40,
            checks=(TestCheck("unit", ("python3", "-m", "unittest"), 60),),
            max_attempts=2,
        )
        self.attempt = self.store.enqueue_attempt(world.id, OWNER, idempotency_key="attempt")
        self.runner = Runner()
        self.guard_entries = 0

        @contextmanager
        def guard():
            self.guard_entries += 1
            yield

        self.scheduler = TestWorldScheduler(
            self.store,
            self.runner,
            worker_id="world-worker",
            lease_seconds=30,
            poll_interval=0.05,
            clock=lambda: 100.0,
            execution_guard=guard,
            executor=ImmediateExecutor(),
        )

    def test_poll_claims_generation_and_executes_under_shared_guard(self):
        admitted = self.scheduler.poll_once()
        self.assertEqual(admitted, 1)
        self.assertEqual(len(self.runner.calls), 1)
        attempt_id, owner_id, lease = self.runner.calls[0]
        self.assertEqual((attempt_id, owner_id), (self.attempt.id, OWNER))
        self.assertEqual(lease.generation, 1)
        self.assertEqual(lease.worker_id, "world-worker")
        self.assertEqual(self.guard_entries, 1)

    def test_notify_is_safe_and_shutdown_is_idempotent(self):
        self.scheduler.notify(self.attempt.id, OWNER)
        self.scheduler.shutdown()
        self.scheduler.shutdown()

    def test_reconciles_expired_running_attempt_before_admission(self):
        lease = self.store.claim_attempt(
            self.attempt.id,
            "dead-worker",
            lease_seconds=1,
            now=50.0,
        )
        self.assertIsNotNone(lease)
        scheduler = TestWorldScheduler(
            self.store,
            self.runner,
            worker_id="replacement",
            lease_seconds=30,
            poll_interval=0.05,
            clock=lambda: 100.0,
            execution_guard=lambda: _NoopContext(),
            executor=ImmediateExecutor(),
        )
        self.assertEqual(scheduler.poll_once(), 1)
        self.assertEqual(self.runner.calls[-1][2].generation, 2)


class _NoopContext:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


if __name__ == "__main__":
    unittest.main()
