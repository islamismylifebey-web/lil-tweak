"""Authoritative coordinator for classification and bounded recovery decisions."""

from __future__ import annotations

import hmac
from typing import Any

from .classifier import FailureClassifier
from .contracts import (
    HANDOFF_SCHEMA_VERSION,
    SCHEMA_VERSION,
    FailureCode,
    FailureSignal,
    RecoveryBudgets,
    RecoveryContext,
    RecoveryDecision,
    RecoveryHistoryEntry,
    RecoveryOutcome,
    ResourceRecoveryDecision,
)
from .fingerprints import decision_digest, failure_fingerprint
from .history import InMemoryRecoveryHistoryStore, RecoveryHistoryStore
from .policy import PolicyDecision, RecoveryPolicy


_EXCEPTION_CODES: dict[str, tuple[FailureCode, bool]] = {
    "agent_deadline_exceeded": (FailureCode.TIMEOUT, True),
    "agent_round_limit": (FailureCode.RESOURCE_EXHAUSTION, False),
    "agent_tool_capacity": (FailureCode.RESOURCE_EXHAUSTION, False),
    "agent_protocol_error": (FailureCode.COMMAND_FAILED, False),
    "admission_unavailable": (FailureCode.RUNNER_UNAVAILABLE, True),
    "stale_lease": (FailureCode.LEASE_REJECTED, False),
    "patch_reconciliation_required": (FailureCode.RECOVERY_EVIDENCE_INVALID, False),
}


class FailureRecoveryController:
    """Classify and authorize recovery transitions without executing them."""

    def __init__(
        self,
        *,
        history: RecoveryHistoryStore | None = None,
        budgets: RecoveryBudgets | None = None,
        classifier: FailureClassifier | None = None,
        policy: RecoveryPolicy | None = None,
    ) -> None:
        self.history = history or InMemoryRecoveryHistoryStore()
        self.budgets = budgets or RecoveryBudgets()
        self.classifier = classifier or FailureClassifier()
        self.policy = policy or RecoveryPolicy()

    def decide(
        self,
        signal: FailureSignal,
        context: RecoveryContext,
        *,
        resource_decision: ResourceRecoveryDecision | None = None,
    ) -> RecoveryDecision:
        classified = self.classifier.classify(signal, context)
        fingerprint = failure_fingerprint(signal, context)
        policy_decision = self.policy.decide(
            classified,
            signal,
            context,
            self.history.list(context.owner_id),
            self.budgets,
            fingerprint=fingerprint,
            resource_decision=resource_decision,
        )
        reason_codes = tuple(sorted(set(policy_decision.reason_codes)))
        material = self._decision_material(
            context=context,
            fingerprint=fingerprint,
            failure_class=classified.failure_class.value,
            failure_code=classified.code.value,
            policy_decision=policy_decision,
            reason_codes=reason_codes,
        )
        decision = RecoveryDecision(
            schema_version=SCHEMA_VERSION,
            owner_id=context.owner_id,
            task_id=context.task_id,
            dag_run_id=context.dag_run_id,
            node_id=context.node_id,
            source_revision=context.source_revision,
            plan_digest=context.plan_digest,
            candidate_digest=context.candidate_digest,
            contract_digest=context.contract_digest,
            execution_id=context.execution_id,
            lease_id=context.lease_id,
            resource_id=context.resource_id,
            attempt=context.attempt,
            failure_class=classified.failure_class,
            failure_code=classified.code,
            fingerprint=fingerprint,
            disposition=policy_decision.disposition,
            action=policy_decision.action,
            allowed=policy_decision.allowed,
            requires_reauthorization=policy_decision.requires_reauthorization,
            requires_fresh_lease=policy_decision.requires_fresh_lease,
            reason_codes=reason_codes,
            decision_digest=decision_digest(material),
        )
        self.history.append_decision(decision)
        return decision

    def record_outcome(
        self,
        decision: RecoveryDecision,
        context: RecoveryContext,
        outcome: RecoveryOutcome,
    ) -> RecoveryHistoryEntry:
        expected = (
            decision.owner_id,
            decision.task_id,
            decision.dag_run_id,
            decision.node_id,
            decision.source_revision,
            decision.plan_digest,
            decision.candidate_digest,
            decision.contract_digest,
            decision.execution_id,
            decision.lease_id,
            decision.resource_id,
            decision.attempt,
        )
        actual = (
            context.owner_id,
            context.task_id,
            context.dag_run_id,
            context.node_id,
            context.source_revision,
            context.plan_digest,
            context.candidate_digest,
            context.contract_digest,
            context.execution_id,
            context.lease_id,
            context.resource_id,
            context.attempt,
        )
        if expected != actual:
            raise ValueError("recovery_decision_binding_mismatch")
        self._require_issued(decision)
        return self.history.append_outcome(decision, outcome)

    def dag_handoff(self, decision: RecoveryDecision) -> dict[str, object]:
        self._require_issued(decision)
        return {
            "schemaVersion": HANDOFF_SCHEMA_VERSION,
            "decisionDigest": decision.decision_digest,
            "taskId": decision.task_id,
            "dagRunId": decision.dag_run_id,
            "nodeId": decision.node_id,
            "sourceRevision": decision.source_revision,
            "planDigest": decision.plan_digest,
            "candidateDigest": decision.candidate_digest,
            "contractDigest": decision.contract_digest,
            "failureFingerprint": decision.fingerprint,
            "failureCode": decision.failure_code.value,
            "disposition": decision.disposition.value,
            "action": decision.action.value,
            "allowed": decision.allowed,
            "requiresReauthorization": decision.requires_reauthorization,
            "requiresFreshLease": decision.requires_fresh_lease,
            "reasonCodes": list(decision.reason_codes),
            "mayExecute": False,
            "mayAuthorize": False,
            "maySelectProvider": False,
        }

    def _require_issued(self, decision: RecoveryDecision) -> None:
        if not self.history.contains_decision(decision):
            raise ValueError("recovery_decision_not_issued")
        expected = decision_digest(self._material_from_decision(decision))
        if not hmac.compare_digest(expected, decision.decision_digest):
            raise ValueError("recovery_decision_digest_mismatch")

    @staticmethod
    def _decision_material(
        *,
        context: RecoveryContext,
        fingerprint: str,
        failure_class: str,
        failure_code: str,
        policy_decision: PolicyDecision,
        reason_codes: tuple[str, ...],
    ) -> dict[str, Any]:
        return {
            "ownerId": context.owner_id,
            "taskId": context.task_id,
            "dagRunId": context.dag_run_id,
            "nodeId": context.node_id,
            "sourceRevision": context.source_revision,
            "planDigest": context.plan_digest,
            "candidateDigest": context.candidate_digest,
            "contractDigest": context.contract_digest,
            "executionId": context.execution_id,
            "leaseId": context.lease_id,
            "resourceId": context.resource_id,
            "attempt": context.attempt,
            "failureClass": failure_class,
            "failureCode": failure_code,
            "fingerprint": fingerprint,
            "disposition": policy_decision.disposition.value,
            "action": policy_decision.action.value,
            "allowed": policy_decision.allowed,
            "requiresReauthorization": policy_decision.requires_reauthorization,
            "requiresFreshLease": policy_decision.requires_fresh_lease,
            "reasonCodes": reason_codes,
        }

    @staticmethod
    def _material_from_decision(decision: RecoveryDecision) -> dict[str, Any]:
        return {
            "ownerId": decision.owner_id,
            "taskId": decision.task_id,
            "dagRunId": decision.dag_run_id,
            "nodeId": decision.node_id,
            "sourceRevision": decision.source_revision,
            "planDigest": decision.plan_digest,
            "candidateDigest": decision.candidate_digest,
            "contractDigest": decision.contract_digest,
            "executionId": decision.execution_id,
            "leaseId": decision.lease_id,
            "resourceId": decision.resource_id,
            "attempt": decision.attempt,
            "failureClass": decision.failure_class.value,
            "failureCode": decision.failure_code.value,
            "fingerprint": decision.fingerprint,
            "disposition": decision.disposition.value,
            "action": decision.action.value,
            "allowed": decision.allowed,
            "requiresReauthorization": decision.requires_reauthorization,
            "requiresFreshLease": decision.requires_fresh_lease,
            "reasonCodes": decision.reason_codes,
        }

    @staticmethod
    def signal_from_exception(error: BaseException) -> FailureSignal:
        raw_code = getattr(error, "code", None)
        if isinstance(raw_code, str) and raw_code in _EXCEPTION_CODES:
            code, transient = _EXCEPTION_CODES[raw_code]
            return FailureSignal(
                code=code,
                exception_type=type(error).__name__,
                transient=transient,
                integrity_failure=code is FailureCode.RECOVERY_EVIDENCE_INVALID,
            )
        if isinstance(error, TimeoutError):
            return FailureSignal(
                code=FailureCode.TIMEOUT,
                exception_type=type(error).__name__,
                transient=True,
            )
        return FailureSignal(
            code=FailureCode.UNKNOWN_FAILURE,
            exception_type=type(error).__name__,
        )
