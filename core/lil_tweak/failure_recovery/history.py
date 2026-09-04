"""Owner-isolated, append-only recovery history."""

from __future__ import annotations

from collections.abc import Protocol
from threading import RLock

from .contracts import RecoveryDecision, RecoveryHistoryEntry, RecoveryOutcome


class RecoveryHistoryStore(Protocol):
    def append_decision(self, decision: RecoveryDecision) -> RecoveryHistoryEntry: ...

    def append_outcome(
        self, decision: RecoveryDecision, outcome: RecoveryOutcome
    ) -> RecoveryHistoryEntry: ...

    def list(self, owner_id: str) -> list[RecoveryHistoryEntry]: ...

    def for_fingerprint(
        self, owner_id: str, fingerprint: str
    ) -> list[RecoveryHistoryEntry]: ...


class InMemoryRecoveryHistoryStore:
    """Thread-safe evidence store used until a durable DAG adapter is installed."""

    def __init__(self) -> None:
        self._entries: dict[str, list[RecoveryHistoryEntry]] = {}
        self._lock = RLock()

    def append_decision(self, decision: RecoveryDecision) -> RecoveryHistoryEntry:
        with self._lock:
            entry = RecoveryHistoryEntry(
                owner_id=decision.owner_id,
                sequence=self._next_sequence(decision.owner_id),
                task_id=decision.task_id,
                fingerprint=decision.fingerprint,
                action=decision.action,
                decision_digest=decision.decision_digest,
            )
            self._entries.setdefault(decision.owner_id, []).append(entry)
            return entry

    def append_outcome(
        self, decision: RecoveryDecision, outcome: RecoveryOutcome
    ) -> RecoveryHistoryEntry:
        with self._lock:
            entry = RecoveryHistoryEntry(
                owner_id=decision.owner_id,
                sequence=self._next_sequence(decision.owner_id),
                task_id=decision.task_id,
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
            self._entries.setdefault(decision.owner_id, []).append(entry)
            return entry

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
