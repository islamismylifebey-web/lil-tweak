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
    def append_decision(
        self,
        decision: RecoveryDecision,
        *,
        failed_checks: tuple[str, ...] = (),
    ) -> RecoveryHistoryEntry: ...

    def append_outcome(
        self, decision: RecoveryDecision, outcome: RecoveryOutcome
    ) -> RecoveryHistoryEntry: ...

    def contains_decision(self, decision: RecoveryDecision) -> bool: ...

    def list(self, owner_id: str) -> list[RecoveryHistoryEntry]: ...

    def for_fingerprint(
        self, owner_id: str, fingerprint: str
    ) -> list[RecoveryHistoryEntry]: ...


class InMemoryRecoveryHistoryStore:
    def __init__(self) -> None:
        self._entries: dict[str, list[RecoveryHistoryEntry]] = {}
        self._lock = RLock()

    def append_decision(
        self,
        decision: RecoveryDecision,
        *,
        failed_checks: tuple[str, ...] = (),
    ) -> RecoveryHistoryEntry:
        with self._lock:
            if self.contains_decision(decision):
                raise ValueError("recovery_decision_already_issued")
            entry = _entry(
                decision,
                self._next(decision.owner_id),
                initial_failed_checks=failed_checks,
            )
            self._entries.setdefault(decision.owner_id, []).append(entry)
            return entry

    def append_outcome(
        self, decision: RecoveryDecision, outcome: RecoveryOutcome
    ) -> RecoveryHistoryEntry:
        with self._lock:
            if not self.contains_decision(decision):
                raise ValueError("recovery_decision_not_issued")
            if self._has_outcome(decision):
                raise ValueError("recovery_outcome_already_recorded")
            entry = _entry(decision, self._next(decision.owner_id), outcome=outcome)
            self._entries.setdefault(decision.owner_id, []).append(entry)
            return entry

    def contains_decision(self, decision: RecoveryDecision) -> bool:
        with self._lock:
            return any(
                item.decision_digest == decision.decision_digest
                and item.fingerprint == decision.fingerprint
                and item.task_id == decision.task_id
                and item.node_id == decision.node_id
                and item.attempt == decision.attempt
                and item.target_resource_id == decision.target_resource_id
                and item.outcome_status is None
                for item in self._entries.get(decision.owner_id, ())
            )

    def list(self, owner_id: str) -> list[RecoveryHistoryEntry]:
        with self._lock:
            return list(self._entries.get(owner_id, ()))

    def for_fingerprint(
        self, owner_id: str, fingerprint: str
    ) -> list[RecoveryHistoryEntry]:
        return [item for item in self.list(owner_id) if item.fingerprint == fingerprint]

    def _next(self, owner_id: str) -> int:
        return len(self._entries.get(owner_id, ())) + 1

    def _has_outcome(self, decision: RecoveryDecision) -> bool:
        return any(
            item.decision_digest == decision.decision_digest
            and item.outcome_status is not None
            for item in self._entries.get(decision.owner_id, ())
        )


class SQLiteRecoveryHistoryStore:
    def __init__(self, path: str | Path) -> None:
        value = str(path)
        if value != ":memory:":
            Path(value).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(value, check_same_thread=False, timeout=30)
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._lock = RLock()
        with self._connection:
            self._connection.execute(
                """CREATE TABLE IF NOT EXISTS recovery_history (
                owner_id TEXT NOT NULL, sequence INTEGER NOT NULL, task_id TEXT NOT NULL,
                node_id TEXT NOT NULL, attempt INTEGER NOT NULL, fingerprint TEXT NOT NULL,
                action TEXT NOT NULL, decision_digest TEXT NOT NULL, target_resource_id TEXT,
                outcome_status TEXT, progress INTEGER, remaining_failed_checks TEXT NOT NULL,
                resulting_plan_digest TEXT, resulting_candidate_digest TEXT,
                resulting_resource_id TEXT, PRIMARY KEY (owner_id, sequence))"""
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS recovery_history_fingerprint ON recovery_history(owner_id, fingerprint, sequence)"
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS recovery_history_decision ON recovery_history(owner_id, decision_digest, sequence)"
            )

    def append_decision(
        self,
        decision: RecoveryDecision,
        *,
        failed_checks: tuple[str, ...] = (),
    ) -> RecoveryHistoryEntry:
        return self._append(decision, None, initial_failed_checks=failed_checks)

    def append_outcome(
        self, decision: RecoveryDecision, outcome: RecoveryOutcome
    ) -> RecoveryHistoryEntry:
        return self._append(decision, outcome)

    def _append(
        self,
        decision: RecoveryDecision,
        outcome: RecoveryOutcome | None,
        *,
        initial_failed_checks: tuple[str, ...] = (),
    ) -> RecoveryHistoryEntry:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                if outcome is None and self.contains_decision(decision):
                    raise ValueError("recovery_decision_already_issued")
                if outcome is not None:
                    if not self.contains_decision(decision):
                        raise ValueError("recovery_decision_not_issued")
                    if self._has_outcome(decision):
                        raise ValueError("recovery_outcome_already_recorded")
                row = self._connection.execute(
                    "SELECT COALESCE(MAX(sequence), 0) + 1 FROM recovery_history WHERE owner_id = ?",
                    (decision.owner_id,),
                ).fetchone()
                entry = _entry(
                    decision,
                    int(row[0]),
                    outcome=outcome,
                    initial_failed_checks=initial_failed_checks,
                )
                self._connection.execute(
                    """INSERT INTO recovery_history (
                    owner_id, sequence, task_id, node_id, attempt, fingerprint, action,
                    decision_digest, target_resource_id, outcome_status, progress,
                    remaining_failed_checks, resulting_plan_digest,
                    resulting_candidate_digest, resulting_resource_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    _encode(entry),
                )
                self._connection.commit()
                return entry
            except Exception:
                self._connection.rollback()
                raise

    def contains_decision(self, decision: RecoveryDecision) -> bool:
        with self._lock:
            row = self._connection.execute(
                """SELECT target_resource_id FROM recovery_history
                WHERE owner_id = ? AND decision_digest = ? AND fingerprint = ?
                AND task_id = ? AND node_id = ? AND attempt = ?
                AND outcome_status IS NULL LIMIT 1""",
                (
                    decision.owner_id,
                    decision.decision_digest,
                    decision.fingerprint,
                    decision.task_id,
                    decision.node_id,
                    decision.attempt,
                ),
            ).fetchone()
            return row is not None and row[0] == decision.target_resource_id

    def list(self, owner_id: str) -> list[RecoveryHistoryEntry]:
        with self._lock:
            rows = self._connection.execute(
                """SELECT owner_id, sequence, task_id, node_id, attempt, fingerprint,
                action, decision_digest, target_resource_id, outcome_status, progress,
                remaining_failed_checks, resulting_plan_digest,
                resulting_candidate_digest, resulting_resource_id
                FROM recovery_history WHERE owner_id = ? ORDER BY sequence""",
                (owner_id,),
            ).fetchall()
        return [_decode(row) for row in rows]

    def for_fingerprint(
        self, owner_id: str, fingerprint: str
    ) -> list[RecoveryHistoryEntry]:
        return [item for item in self.list(owner_id) if item.fingerprint == fingerprint]

    def _has_outcome(self, decision: RecoveryDecision) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM recovery_history WHERE owner_id = ? AND decision_digest = ? AND outcome_status IS NOT NULL LIMIT 1",
            (decision.owner_id, decision.decision_digest),
        ).fetchone()
        return row is not None

    def close(self) -> None:
        with self._lock:
            self._connection.close()


def _entry(
    decision: RecoveryDecision,
    sequence: int,
    outcome: RecoveryOutcome | None = None,
    *,
    initial_failed_checks: tuple[str, ...] = (),
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
        target_resource_id=decision.target_resource_id,
        outcome_status=outcome.status if outcome else None,
        progress=outcome.progress if outcome else None,
        remaining_failed_checks=(
            outcome.remaining_failed_checks if outcome else initial_failed_checks
        ),
        resulting_plan_digest=outcome.resulting_plan_digest if outcome else None,
        resulting_candidate_digest=outcome.resulting_candidate_digest if outcome else None,
        resulting_resource_id=outcome.resulting_resource_id if outcome else None,
    )


def _encode(entry: RecoveryHistoryEntry) -> tuple[object, ...]:
    return (
        entry.owner_id,
        entry.sequence,
        entry.task_id,
        entry.node_id,
        entry.attempt,
        entry.fingerprint,
        entry.action.value,
        entry.decision_digest,
        entry.target_resource_id,
        entry.outcome_status.value if entry.outcome_status else None,
        None if entry.progress is None else int(entry.progress),
        json.dumps(list(entry.remaining_failed_checks), separators=(",", ":")),
        entry.resulting_plan_digest,
        entry.resulting_candidate_digest,
        entry.resulting_resource_id,
    )


def _decode(row: tuple[object, ...]) -> RecoveryHistoryEntry:
    return RecoveryHistoryEntry(
        owner_id=str(row[0]),
        sequence=int(row[1]),
        task_id=str(row[2]),
        node_id=str(row[3]),
        attempt=int(row[4]),
        fingerprint=str(row[5]),
        action=RecoveryAction(str(row[6])),
        decision_digest=str(row[7]),
        target_resource_id=str(row[8]) if row[8] is not None else None,
        outcome_status=(
            RecoveryOutcomeStatus(str(row[9])) if row[9] is not None else None
        ),
        progress=None if row[10] is None else bool(row[10]),
        remaining_failed_checks=tuple(json.loads(str(row[11]))),
        resulting_plan_digest=str(row[12]) if row[12] is not None else None,
        resulting_candidate_digest=str(row[13]) if row[13] is not None else None,
        resulting_resource_id=str(row[14]) if row[14] is not None else None,
    )
