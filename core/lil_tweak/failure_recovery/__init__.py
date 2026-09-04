"""Deterministic, fail-closed engineering failure recovery authority."""

from .classifier import FailureClassifier
from .contracts import (
    HANDOFF_SCHEMA_VERSION,
    SCHEMA_VERSION,
    ClassifiedFailure,
    EvidenceRef,
    FailureClass,
    FailureCode,
    FailureSignal,
    RecoveryAction,
    RecoveryBudgets,
    RecoveryContext,
    RecoveryDecision,
    RecoveryDisposition,
    RecoveryHistoryEntry,
    RecoveryOutcome,
    RecoveryOutcomeStatus,
    ResourceRecoveryDecision,
)
from .controller import FailureRecoveryController
from .fingerprints import canonical_digest, canonical_json, failure_fingerprint
from .history import (
    InMemoryRecoveryHistoryStore,
    RecoveryHistoryStore,
    SQLiteRecoveryHistoryStore,
)
from .orchestrator_bridge import RecoveryAwareEngineeringOrchestrator
from .policy import PolicyDecision, RecoveryPolicy

__all__ = [
    "HANDOFF_SCHEMA_VERSION",
    "SCHEMA_VERSION",
    "ClassifiedFailure",
    "EvidenceRef",
    "FailureClass",
    "FailureClassifier",
    "FailureCode",
    "FailureRecoveryController",
    "FailureSignal",
    "InMemoryRecoveryHistoryStore",
    "PolicyDecision",
    "RecoveryAction",
    "RecoveryAwareEngineeringOrchestrator",
    "RecoveryBudgets",
    "RecoveryContext",
    "RecoveryDecision",
    "RecoveryDisposition",
    "RecoveryHistoryEntry",
    "RecoveryHistoryStore",
    "RecoveryOutcome",
    "RecoveryOutcomeStatus",
    "RecoveryPolicy",
    "ResourceRecoveryDecision",
    "SQLiteRecoveryHistoryStore",
    "canonical_digest",
    "canonical_json",
    "failure_fingerprint",
]
