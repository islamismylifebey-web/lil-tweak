"""Offline waves 5/6/8/9: real SQLite, real child-process death, no providers.

This certifies only the named recovery-history boundary, not the production
PostgreSQL store, power-loss durability, or irreversible external actions.
"""
from __future__ import annotations

from dataclasses import replace
import multiprocessing
from pathlib import Path
import signal
import sqlite3
import tempfile
import unittest

from core.lil_tweak.failure_recovery import (
    FailureCode,
    FailureRecoveryController,
    FailureSignal,
    RecoveryContext,
    RecoveryOutcome,
    RecoveryOutcomeStatus,
    SQLiteRecoveryHistoryStore,
)


def make_decision(index=0, revision=1, owner="stress-owner"):
    context = RecoveryContext(
        owner_id=owner, task_id=f"task-{index}", dag_run_id=f"run-{revision}-{index}",
        node_id="execute", source_revision=f"{revision:040x}", attempt=1,
        plan_digest="a" * 64, candidate_digest="b" * 64, contract_digest="c" * 64,
    )
    return FailureRecoveryController().decide(
        FailureSignal(code=FailureCode.TEST_FAILURE, failed_checks=("unit_test",)), context
    )


def failed_outcome():
    return RecoveryOutcome(status=RecoveryOutcomeStatus.FAILED, progress=False,
                           remaining_failed_checks=("unit_test",))


class CrashConnection:
    """Pause at a real SQL/commit boundary so the parent can send SIGKILL."""
    def __init__(self, connection, phase, pipe):
        self.connection, self.phase, self.pipe = connection, phase, pipe

    def park(self, phase):
        if phase == self.phase:
            self.pipe.send(phase)
            self.pipe.recv()
            raise AssertionError("a parked crash worker must be killed, not resumed")

    def execute(self, sql, *args):
        if sql == "BEGIN IMMEDIATE":
            self.park("before_begin")
        result = self.connection.execute(sql, *args)
        if sql == "BEGIN IMMEDIATE":
            self.park("after_begin")
        if sql.lstrip().startswith("INSERT INTO recovery_history"):
            self.park("after_insert")
        return result

    def commit(self):
        self.park("before_commit")
        result = self.connection.commit()
        self.park("after_commit")
        return result

    def __getattr__(self, name):
        return getattr(self.connection, name)


def crash_worker(path, phase, operation, pipe):
    store = SQLiteRecoveryHistoryStore(path)
    store._connection = CrashConnection(store._connection, phase, pipe)
    decision = make_decision()
    if operation == "decision":
        store.append_decision(decision)
    else:
        store.append_outcome(decision, failed_outcome())
    raise AssertionError("requested crash boundary was not reached")


def race_worker(path, index, mode, gate, pipe):
    try:
        store = SQLiteRecoveryHistoryStore(path)
        pipe.send("ready")
        if not gate.wait(20):
            raise TimeoutError("start gate expired")
        decision = make_decision(index if mode == "distinct" else 0)
        try:
            entry = (store.append_outcome(decision, failed_outcome()) if mode == "outcome"
                     else store.append_decision(decision))
            result = ("written", entry.sequence)
        except ValueError as error:
            result = ("rejected", str(error))
        finally:
            store.close()
        pipe.send(result)
    except BaseException as error:
        pipe.send(("unexpected", type(error).__name__))
        raise
    finally:
        pipe.close()


class RecoveryPersistenceStress(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "history.sqlite3"
        SQLiteRecoveryHistoryStore(self.path).close()

    def open_store(self):
        store = SQLiteRecoveryHistoryStore(self.path)
        self.addCleanup(store.close)
        return store

    def seed(self, outcome=False):
        store = SQLiteRecoveryHistoryStore(self.path)
        try:
            decision = make_decision()
            store.append_decision(decision, failed_checks=("unit_test",))
            if outcome:
                store.append_outcome(decision, failed_outcome())
            return decision
        finally:
            store.close()

    def mutate(self, statement, parameters=()):
        with sqlite3.connect(self.path) as connection:
            connection.execute(statement, parameters)

    def assert_database_healthy(self):
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchall(), [("ok",)])
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def assert_corruption_blocks_authority(self, decision):
        store = self.open_store()
        for operation in (
            lambda: store.list(decision.owner_id),
            lambda: store.contains_decision(decision),
            lambda: store.append_outcome(decision, failed_outcome()),
            lambda: store.append_decision(make_decision(99)),
        ):
            with self.assertRaisesRegex(ValueError, "^recovery_history_corrupt$"):
                operation()
        # Rejection must not turn into automatic repair, deletion, or new history.
        self.assert_database_healthy()

    def test_corrupt_progress_is_not_coerced_to_true(self):
        decision = self.seed(outcome=True)
        self.mutate("UPDATE recovery_history SET progress=2 WHERE sequence=2")
        self.assert_corruption_blocks_authority(decision)

    def test_fractional_attempt_is_not_truncated(self):
        decision = self.seed()
        self.mutate("UPDATE recovery_history SET attempt=1.5")
        self.assert_corruption_blocks_authority(decision)

    def test_fractional_sequence_is_not_truncated(self):
        decision = self.seed()
        self.mutate("UPDATE recovery_history SET sequence=1.5")
        self.assert_corruption_blocks_authority(decision)

    def test_json_string_cannot_masquerade_as_check_array(self):
        decision = self.seed()
        self.mutate("UPDATE recovery_history SET remaining_failed_checks=?", ('"unit_test"',))
        self.assert_corruption_blocks_authority(decision)

    def test_json_object_cannot_masquerade_as_check_array(self):
        decision = self.seed()
        self.mutate("UPDATE recovery_history SET remaining_failed_checks=?", ('{"unit_test":true}',))
        self.assert_corruption_blocks_authority(decision)

    def test_success_without_progress_is_corrupt(self):
        decision = self.seed(outcome=True)
        self.mutate("UPDATE recovery_history SET outcome_status='succeeded', progress=0 WHERE sequence=2")
        self.assert_corruption_blocks_authority(decision)

    def test_outcome_without_progress_value_is_corrupt(self):
        decision = self.seed(outcome=True)
        self.mutate("UPDATE recovery_history SET progress=NULL WHERE sequence=2")
        self.assert_corruption_blocks_authority(decision)

    def test_decision_cannot_contain_outcome_evidence(self):
        decision = self.seed()
        self.mutate("UPDATE recovery_history SET resulting_candidate_digest=?", ("d" * 64,))
        self.assert_corruption_blocks_authority(decision)

    def test_outcome_cannot_change_its_issued_action(self):
        decision = self.seed(outcome=True)
        self.mutate("UPDATE recovery_history SET action='block' WHERE sequence=2")
        self.assert_corruption_blocks_authority(decision)

    def test_missing_decision_is_not_hidden_by_well_typed_outcome(self):
        decision = self.seed(outcome=True)
        self.mutate("DELETE FROM recovery_history WHERE sequence=1")
        self.assert_corruption_blocks_authority(decision)

    def test_duplicate_outcome_row_is_corrupt(self):
        decision = self.seed(outcome=True)
        self.mutate("""INSERT INTO recovery_history SELECT owner_id, 3, task_id, node_id,
            attempt, fingerprint, action, decision_digest, target_resource_id,
            outcome_status, progress, remaining_failed_checks, resulting_plan_digest,
            resulting_candidate_digest, resulting_resource_id
            FROM recovery_history WHERE sequence=2""")
        self.assert_corruption_blocks_authority(decision)

    def test_ten_thousand_failed_checks_are_rejected_before_persistence(self):
        store = self.open_store()
        decision = make_decision()
        checks = tuple(f"check-{index}" for index in range(10_000))
        with self.assertRaises(ValueError):
            store.append_decision(decision, failed_checks=checks)
        self.assertEqual(store.list("stress-owner"), [])

    def test_oversized_persisted_check_array_blocks_authority(self):
        decision = self.seed()
        payload = "[" + ",".join(f'"check-{index}"' for index in range(10_000)) + "]"
        self.mutate("UPDATE recovery_history SET remaining_failed_checks=?", (payload,))
        self.assert_corruption_blocks_authority(decision)

    def test_corruption_in_one_owner_does_not_rewrite_another_owner(self):
        self.seed(outcome=True)
        store = self.open_store()
        other = make_decision(owner="other-owner")
        store.append_decision(other)
        self.mutate("UPDATE recovery_history SET progress=2 WHERE owner_id='stress-owner' AND sequence=2")
        self.assertTrue(store.contains_decision(other))
        self.assertEqual(len(store.list("other-owner")), 1)

    def kill_at(self, phase, operation):
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe()
        process = context.Process(target=crash_worker, args=(str(self.path), phase, operation, child))
        process.start()
        child.close()
        try:
            self.assertTrue(parent.poll(20), f"worker never reached {phase}")
            self.assertEqual(parent.recv(), phase)
            process.kill()
            process.join(10)
            self.assertEqual(process.exitcode, -signal.SIGKILL)
        finally:
            if process.is_alive():
                process.kill()
                process.join(10)
            parent.close()
            process.close()

    def test_hard_kill_decision_write_has_no_partial_commit(self):
        # Each phase gets a separate real database and a fresh process.
        for phase in ("before_begin", "after_begin", "after_insert", "before_commit", "after_commit"):
            with self.subTest(phase=phase):
                self.path = Path(self.directory.name) / f"{phase}.sqlite3"
                SQLiteRecoveryHistoryStore(self.path).close()
                self.kill_at(phase, "decision")
                store = SQLiteRecoveryHistoryStore(self.path)
                try:
                    self.assertEqual(len(store.list("stress-owner")), int(phase == "after_commit"))
                    if phase == "after_commit":
                        with self.assertRaisesRegex(ValueError, "recovery_decision_already_issued"):
                            store.append_decision(make_decision())
                    else:
                        self.assertEqual(store.append_decision(make_decision()).sequence, 1)
                    self.assertEqual(len(store.list("stress-owner")), 1)
                finally:
                    store.close()
                self.assert_database_healthy()

    def test_hard_kill_outcome_write_replays_without_duplicate(self):
        for phase in ("after_insert", "before_commit", "after_commit"):
            with self.subTest(phase=phase):
                self.path = Path(self.directory.name) / f"outcome-{phase}.sqlite3"
                decision = self.seed()
                self.kill_at(phase, "outcome")
                store = SQLiteRecoveryHistoryStore(self.path)
                try:
                    self.assertEqual(len(store.list("stress-owner")), 2 if phase == "after_commit" else 1)
                    if phase == "after_commit":
                        with self.assertRaisesRegex(ValueError, "recovery_outcome_already_recorded"):
                            store.append_outcome(decision, failed_outcome())
                    else:
                        self.assertEqual(store.append_outcome(decision, failed_outcome()).sequence, 2)
                    self.assertEqual([entry.sequence for entry in store.list("stress-owner")], [1, 2])
                finally:
                    store.close()
                self.assert_database_healthy()

    def race(self, mode):
        context = multiprocessing.get_context("spawn")
        gate = context.Event()
        workers = []
        try:
            for index in range(8):
                parent, child = context.Pipe()
                process = context.Process(target=race_worker, args=(str(self.path), index, mode, gate, child))
                process.start()
                child.close()
                workers.append((process, parent))
            for _, pipe in workers:
                self.assertTrue(pipe.poll(20), "race worker did not initialize")
                self.assertEqual(pipe.recv(), "ready")
            gate.set()
            results = []
            for process, pipe in workers:
                self.assertTrue(pipe.poll(40), "race worker did not finish")
                results.append(pipe.recv())
                process.join(10)
                self.assertEqual(process.exitcode, 0)
            return results
        finally:
            gate.set()
            for process, pipe in workers:
                if process.is_alive():
                    process.kill()
                    process.join(10)
                pipe.close()
                process.close()

    def test_eight_processes_record_one_identical_decision(self):
        results = self.race("decision")
        self.assertEqual(results.count(("written", 1)), 1)
        self.assertEqual(results.count(("rejected", "recovery_decision_already_issued")), 7)
        self.assertEqual(len(self.open_store().list("stress-owner")), 1)
        self.assert_database_healthy()

    def test_eight_processes_record_one_identical_outcome(self):
        self.seed()
        results = self.race("outcome")
        self.assertEqual(results.count(("written", 2)), 1)
        self.assertEqual(results.count(("rejected", "recovery_outcome_already_recorded")), 7)
        self.assertEqual(len(self.open_store().list("stress-owner")), 2)
        self.assert_database_healthy()

    def test_eight_processes_keep_distinct_decision_sequence_exact(self):
        results = self.race("distinct")
        self.assertEqual(sorted(results), [("written", number) for number in range(1, 9)])
        self.assertEqual([item.sequence for item in self.open_store().list("stress-owner")], list(range(1, 9)))
        self.assert_database_healthy()

    def test_sixty_source_revisions_and_six_hundred_decisions_survive_reopen(self):
        expected = []
        first = None
        for revision in range(1, 61):
            store = SQLiteRecoveryHistoryStore(self.path)
            try:
                for index in range(10):
                    decision = make_decision(index, revision)
                    first = first or decision
                    issued = store.append_decision(decision, failed_checks=("unit_test",))
                    completed = store.append_outcome(decision, failed_outcome())
                    expected.extend([issued, completed])
            finally:
                store.close()
            store = SQLiteRecoveryHistoryStore(self.path)
            try:
                self.assertEqual(store.list("stress-owner"), expected)
                with self.assertRaisesRegex(ValueError, "recovery_decision_already_issued"):
                    store.append_decision(first)
                with self.assertRaisesRegex(ValueError, "recovery_outcome_already_recorded"):
                    store.append_outcome(first, failed_outcome())
                self.assertEqual(len(store.list("stress-owner")), revision * 20)
            finally:
                store.close()
        self.assertEqual(len(expected), 1200)
        self.assertEqual(len({item.decision_digest for item in expected}), 600)
        self.assert_database_healthy()


if __name__ == "__main__":
    unittest.main()
