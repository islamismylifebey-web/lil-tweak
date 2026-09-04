"""Owner-isolated, append-only recovery history."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import RLock
from typing import Protocol

from .contracts import (
    RecoveryAction,
    RecoveryDecision,
    RecoveryHistoryEntry,
    RecoveryOutcome,
    RecoveryOutcomeStatus,
)


class RecoveryHistoryStore(Protocol):
    def append_decision(self, decision: RecoveryDecision) -> RecoveryHistoryEntry: ...

    def append_outcome(
        self, decision: RecoveryDecision, outcome: RecoveryOutcome
    ) -> RecoveryHistoryEntry: ...

    def contains_decision(self, decision: RecoveryDecision) -> bool: ...

    def list(self, owner_id: str) -> list[RecoveryHistoryEntry]: ...

    def for_fingerprint(
        self, owner_id: str, fingerprint: str
    ) -> list[RecoveryHistoryEntry]: ...


class InMemoryRecoveryHistoryStore:
    """Thread-safe append-only history for tests and bounded local operation."""

    def __init__(self) -> None:
        self._entries: dict[str, list[RecoveryHistoryEntry]] = {}
        self._lock = RLock()

    def append_decision(self, decision: RecoveryDecision) -> RecoveryHistoryEntry:
        with self._lock:
            if self.contains_decision(decision):
                raise ValueError("recovery_decision_already_issued")
            entry = _decision_entry(decision, self._next_sequence(decision.owner_id))
            self._entries.setdefault(decision.owner_id, []).append(entry)
            return entry

    def append_outcome(
        self, decision: RecoveryDecision, outcome: RecoveryOutcome
    ) -> RecoveryHistoryEntry:
        with self._lock:
            self._require_issued(decision)
            if self._has_outcome(decision):
                raise ValueError("recovery_outcome_already_recorded")
            entry = _outcome_entry(
                decision, outcome, self._next_sequence(decision.owner_id)
            )
            self._entries.setdefault(decision.owner_id, []).append(entry)
            return entry

    def contains_decision(self, decision: RecoveryDecision) -> bool:
        with self._lock:
            return any(
                entry.decision_digest == decision.decision_digest
                and entry.fingerprint == decision.fingerprint
                and entry.task_id == decision.task_id
                and entry.node_id == decision.node_id
                and entry.attempt == decision.attempt
                and entry.outcome_status is None
                for entry in self._entries.get(decision.owner_id, ())
            )

    def list(self, owner_id: str) -> list[RecoveryHistoryEntry]:
        with self._lock:
            return list(self._entries.get(owner_id, ()))

    def for_fingerprint(
        self, owner_id: str, fingerprint: str
    ) -> list[RecoveryHistoryEntry]:
        return [
            entry
            for entry in self.list(owner_id)
            if entry.fingerprint == fingerprint
        ]

    def _next_sequence(self, owner_id: str) -> int:
        return len(self._entries.get(owner_id, ())) + 1

    def _require_issued(self, decision: RecoveryDecision) -> None:
        if not self.contains_decision(decision):
            raise ValueError("recovery_decision_not_issued")

    def _has_outcome(self, decision: RecoveryDecision) -> bool:
        return any(
            entry.decision_digest == decision.decision_digest
            and entry.outcome_status is not None
            for entry in self._entries.get(decision.owner_id, ())
        )


class SQLiteRecoveryHistoryStore:
    """Durable append-only history with per-owner monotonic sequencing."""

    def __init__(self, path: str | Path) -> None:
        value = str(path)
        if value != ":memory:":
            Path(value).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(value, check_same_thread=False, timeout=30)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._lock = RLock()
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS recovery_history (
                    owner_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    task_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    attempt INTEGER NOT NULL,
                    fingerprint TEXT NOT NULL,
                    action TEXT NOT NULL,
                    decision_digest TEXT NOT NULL,
                    outcome_status TEXT,
                    progress INTEGER,
                    remaining_failed_checks TEXT NOT NULL,
                    resulting_plan_digest TEXT,
                    resulting_candidate_digest TEXT,
                    resulting_resource_id TEXT,
                    PRIMARY KEY (owner_id, sequence)
                )
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS recovery_history_fingerprint
                ON recovery_history(owner_id, fingerprint, sequence)
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS recovery_history_decision
                ON recovery_history(owner_id, decision_digest, sequence)
                """
            )

    def append_decision(self, decision: RecoveryDecision) -> RecoveryHistoryEntry:
        with self._lock:
            self._begin_immediate()
            try:
                if self.contains_decision(decision):
                    raise ValueError("recovery_decision_already_issued")
                entry = _decision_entry(decision, self._next_sequence(decision.owner_id))
                self._insert(entry)
                self._connection.commit()
                return entry
            except Exception:
                self._connection.rollback()
                raise

    def append_outcome(
        self, decision: RecoveryDecision, outcome: RecoveryOutcome
    ) -> RecoveryHistoryEntry:
        with self._lock:
            self._begin_immediate()
            try:
                if not self.contains_decision(decision):
                    raise ValueError("recovery_decision_not_issued")
                if self._has_outcome(decision):
                    raise ValueError("recovery_outcome_already_recorded")
                entry = _outcome_entry(
                    decision, outcome, self._next_sequence(decision.owner_id)
                )
                self._insert(entry)
                self._connection.commit()
                return entry
            except Exception:
                self._connection.rollback()
                raise

    def contains_decision(self, decision: RecoveryDecision) -> bool:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT 1
                FROM recovery_history
                WHERE owner_id = ? AND decision_digest = ? AND fingerprint = ?
                  AND task_id = ? AND node_id = ? AND attempt = ?
                  AND outcome_status IS NULL
                LIMIT 1
                """,
                (
                    decision.owner_id,
                    decision.decision_digest,
                    decision.fingerprint,
                    decision.task_id,
                    decision.node_id,
                    decision.attempt,
                ),
            ).fetchone()
            return row is not None

    def list(self, owner_id: str) -> list[RecoveryHistoryEntry]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT owner_id, sequence, task_id, node_id, attempt,
                       fingerprint, action, decision_digest, outcome_status,
                       progress, remaining_failed_checks, resulting_plan_digest,
                       resulting_candidate_digest, resulting_resource_id
                FROM recovery_history
                WHERE owner_id = ?
                ORDER BY sequence ASC
                """,
                (owner_id,),
            ).fetchall()
        return [self._decode(row) for row in rows]

    def for_fingerprint(
        self, owner_id: str, fingerprint: str
    ) -> list[RecoveryHistoryEntry]:
        return [
            entry
            for entry in self.list(owner_id)
            if entry.fingerprint == fingerprint
        ]

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _begin_immediate(self) -> None:
        self._connection.execute("BEGIN IMMEDIATE")

    def _next_sequence(self, owner_id: str) -> int:
        row = self._connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM recovery_history WHERE owner_id = ?",
            (owner_id,),
        ).fetchone()
        return int(row[0])

    def _has_outcome(self, decision: RecoveryDecision) -> bool:
        row = self._connection.execute(
            """
            SELECT 1 FROM recovery_history
            WHERE owner_id = ? AND decision_digest = ?
              AND outcome_status IS NOT NULL
            LIMIT 1
            """,
            (decision.owner_id, decision.decision_digest),
        ).fetchone()
        return row is not None

    def _insert(self, entry: RecoveryHistoryEntry) -> None:
        self._connection.execute(
            """
            INSERT INTO recovery_history (
                owner_id, sequence, task_id, node_id, attempt, fingerprint,
                action, decision_digest, outcome_status, progress,
                remaining_failed_checks, resulting_plan_digest,
                resulting_candidate_digest, resulting_resource_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.owner_id,
                entry.sequence,
                entry.task_id,
                entry.node_id,
                entry.attempt,
                entry.fingerprint,
                entry.action.value,
                entry.decision_digest,
                entry.outcome_status.value if entry.outcome_status else None,
                None if entry.progress is None else int(entry.progress),
                json.dumps(list(entry.remaining_failed_checks), separators=(",", ":")),
                entry.resulting_plan_digest,
                entry.resulting_candidate_digest,
                entry.resulting_resource_id,
            ),
        )

    @staticmethod
    def _decode(row: tuple[object, ...]) -> RecoveryHistoryEntry:
        outcome = RecoveryOutcomeStatus(str(row[8])) if row[8] is not None else None
        progress = None if row[9] is None else bool(row[9])
        checks = tuple(json.loads(str(row[10])))
        return RecoveryHistoryEntry(
            owner_id=str(row[0]),
            sequence=int(row[1]),
            task_id=str(row[2]),
            node_id=str(row[3]),
            attempt=int(row[4]),
            fingerprint=str(row[5]),
            action=RecoveryAction(str(row[6])),
            decision_digest=str(row[7]),
            outcome_status=outcome,
            progress=progress,
            remaining_failed_checks=checks,
            resulting_plan_digest=str(row[11]) if row[11] is not None else None,
            resulting_candidate_digest=str(row[12]) if row[12] is not None else None,
            resulting_resource_id=str(row[13]) if row[13] is not None else None,
        )


def _decision_entry(
    decision: RecoveryDecision, sequence: int
) -> RecoveryHistoryEntry:
    return RecoveryHistoryEntry(
        owner_id=decision.owner_id,
        sequence=sequence,
        task_id=decision.task_id,
        node_id=decision.node_id,
        attempt=decision.attempt,
        fingerprint=decision.fingerprint,
        action=decision.action,
        decision_digest=decision.decision_digest,
    )


def _outcome_entry(
    decision: RecoveryDecision,
    outcome: RecoveryOutcome,
    sequence: int,
) -> RecoveryHistoryEntry:
    return RecoveryHistoryEntry(
        owner_id=decision.owner_id,
        sequence=sequence,
        task_id=decision.task_id,
        node_id=decision.node_id,
        attempt=decision.attempt,
        fingerprint=decision.fingerprint,
        action=decision.action,
        decision_digest=decision.decision_digest,
        outcome_status=outcome.status,
        progress=outcome.progress,
        remaining_failed_checks=outcome.remaining_failed_checks,
        resulting_plan_digest=outcome.resulting_plan_digest,
        resulting_candidate_digest=outcome.resulting_candidate_digest,
        resulting_resource_id=outcome.resulting_resource_id,
    )
