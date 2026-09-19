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


_CORRUPT = "recovery_history_corrupt"


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
                entries = self._validated_entries(decision.owner_id)
                issued = _matching_decisions(entries, decision)
                recorded_outcomes = _matching_outcomes(entries, decision)

                if outcome is None and issued:
                    raise ValueError("recovery_decision_already_issued")
                if outcome is not None:
                    if not issued:
                        raise ValueError("recovery_decision_not_issued")
                    if recorded_outcomes:
                        raise ValueError("recovery_outcome_already_recorded")

                entry = _entry(
                    decision,
                    len(entries) + 1,
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
            entries = self._validated_entries(decision.owner_id)
            return bool(_matching_decisions(entries, decision))

    def list(self, owner_id: str) -> list[RecoveryHistoryEntry]:
        with self._lock:
            return list(self._validated_entries(owner_id))

    def for_fingerprint(
        self, owner_id: str, fingerprint: str
    ) -> list[RecoveryHistoryEntry]:
        return [item for item in self.list(owner_id) if item.fingerprint == fingerprint]

    def _has_outcome(self, decision: RecoveryDecision) -> bool:
        with self._lock:
            entries = self._validated_entries(decision.owner_id)
            return bool(_matching_outcomes(entries, decision))

    def _validated_entries(self, owner_id: str) -> list[RecoveryHistoryEntry]:
        rows = self._connection.execute(
            """SELECT owner_id, sequence, task_id, node_id, attempt, fingerprint,
            action, decision_digest, target_resource_id, outcome_status, progress,
            remaining_failed_checks, resulting_plan_digest,
            resulting_candidate_digest, resulting_resource_id
            FROM recovery_history WHERE owner_id = ? ORDER BY sequence""",
            (owner_id,),
        ).fetchall()
        try:
            entries = [_decode(row) for row in rows]
            _validate_lineage(owner_id, entries)
            return entries
        except (TypeError, ValueError, json.JSONDecodeError, OverflowError):
            raise ValueError(_CORRUPT) from None

    def close(self) -> None:
        with self._lock:
            self._connection.close()


def _matching_decisions(
    entries: list[RecoveryHistoryEntry], decision: RecoveryDecision
) -> list[RecoveryHistoryEntry]:
    return [
        item
        for item in entries
        if item.decision_digest == decision.decision_digest
        and item.fingerprint == decision.fingerprint
        and item.task_id == decision.task_id
        and item.node_id == decision.node_id
        and item.attempt == decision.attempt
        and item.target_resource_id == decision.target_resource_id
        and item.outcome_status is None
    ]


def _matching_outcomes(
    entries: list[RecoveryHistoryEntry], decision: RecoveryDecision
) -> list[RecoveryHistoryEntry]:
    return [
        item
        for item in entries
        if item.decision_digest == decision.decision_digest
        and item.outcome_status is not None
    ]


def _validate_lineage(owner_id: str, entries: list[RecoveryHistoryEntry]) -> None:
    if [entry.sequence for entry in entries] != list(range(1, len(entries) + 1)):
        raise ValueError(_CORRUPT)

    issued: dict[str, RecoveryHistoryEntry] = {}
    completed: set[str] = set()

    for entry in entries:
        if entry.owner_id != owner_id:
            raise ValueError(_CORRUPT)

        if entry.outcome_status is None:
            if (
                entry.progress is not None
                or entry.resulting_plan_digest is not None
                or entry.resulting_candidate_digest is not None
                or entry.resulting_resource_id is not None
            ):
                raise ValueError(_CORRUPT)
            if entry.decision_digest in issued or entry.decision_digest in completed:
                raise ValueError(_CORRUPT)
            issued[entry.decision_digest] = entry
            continue

        if entry.progress is None:
            raise ValueError(_CORRUPT)
        if entry.outcome_status is RecoveryOutcomeStatus.SUCCEEDED and entry.progress is not True:
            raise ValueError(_CORRUPT)
        if entry.decision_digest in completed:
            raise ValueError(_CORRUPT)

        decision = issued.get(entry.decision_digest)
        if decision is None:
            raise ValueError(_CORRUPT)
        if (
            entry.task_id != decision.task_id
            or entry.node_id != decision.node_id
            or entry.attempt != decision.attempt
            or entry.fingerprint != decision.fingerprint
            or entry.action is not decision.action
            or entry.target_resource_id != decision.target_resource_id
        ):
            raise ValueError(_CORRUPT)
        completed.add(entry.decision_digest)


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
    if len(row) != 15:
        raise ValueError(_CORRUPT)

    owner_id, sequence, task_id, node_id, attempt, fingerprint, action_value, decision_digest, target_resource_id, outcome_value, progress_raw, checks_raw, plan_digest, candidate_digest, resource_id = row

    if type(sequence) is not int or type(attempt) is not int:
        raise ValueError(_CORRUPT)
    if progress_raw is not None and (type(progress_raw) is not int or progress_raw not in (0, 1)):
        raise ValueError(_CORRUPT)
    if not isinstance(checks_raw, str):
        raise ValueError(_CORRUPT)

    checks = json.loads(checks_raw)
    if not isinstance(checks, list) or any(not isinstance(item, str) for item in checks):
        raise ValueError(_CORRUPT)

    for value in (owner_id, task_id, node_id, fingerprint, action_value, decision_digest):
        if not isinstance(value, str):
            raise ValueError(_CORRUPT)
    for value in (target_resource_id, outcome_value, plan_digest, candidate_digest, resource_id):
        if value is not None and not isinstance(value, str):
            raise ValueError(_CORRUPT)

    action = RecoveryAction(action_value)
    outcome_status = (
        RecoveryOutcomeStatus(outcome_value) if outcome_value is not None else None
    )

    return RecoveryHistoryEntry(
        owner_id=owner_id,
        sequence=sequence,
        task_id=task_id,
        node_id=node_id,
        attempt=attempt,
        fingerprint=fingerprint,
        action=action,
        decision_digest=decision_digest,
        target_resource_id=target_resource_id,
        outcome_status=outcome_status,
        progress=None if progress_raw is None else progress_raw == 1,
        remaining_failed_checks=tuple(checks),
        resulting_plan_digest=plan_digest,
        resulting_candidate_digest=candidate_digest,
        resulting_resource_id=resource_id,
    )
