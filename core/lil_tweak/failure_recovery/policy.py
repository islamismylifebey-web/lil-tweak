"""Server-owned recovery policy and retry-budget enforcement."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .contracts import (
    ClassifiedFailure,
    FailureCode,
    FailureSignal,
    RecoveryAction,
    RecoveryBudgets,
    RecoveryContext,
    RecoveryDisposition,
    RecoveryHistoryEntry,
    RecoveryOutcomeStatus,
    ResourceRecoveryDecision,
)


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    disposition: RecoveryDisposition
    action: RecoveryAction
    allowed: bool
    requires_reauthorization: bool
    requires_fresh_lease: bool
    reason_codes: tuple[str, ...]


class RecoveryPolicy:
    """Choose the narrowest allowed recovery action; ambiguity always blocks."""

    def decide(
        self,
        classified: ClassifiedFailure,
        signal: FailureSignal,
        context: RecoveryContext,
        history: list[RecoveryHistoryEntry],
        budgets: RecoveryBudgets,
        *,
        fingerprint: str,
        resource_decision: ResourceRecoveryDecision | None = None,
    ) -> PolicyDecision:
        base = PolicyDecision(
            disposition=classified.disposition,
            action=classified.preferred_action,
            allowed=classified.preferred_action
            not in {RecoveryAction.BLOCK, RecoveryAction.ESCALATE},
            requires_reauthorization=classified.requires_reauthorization,
            requires_fresh_lease=classified.requires_fresh_lease,
            reason_codes=classified.reason_codes,
        )

        if signal.partial_mutation and not (
            classified.automatic_recovery_prohibited
            or classified.code
            in {
                FailureCode.ROLLBACK_FAILED,
                FailureCode.RECOVERY_EVIDENCE_INVALID,
                FailureCode.SECURITY_CHECK_FAILURE,
            }
        ):
            base = PolicyDecision(
                disposition=RecoveryDisposition.ROLLBACK_REQUIRED,
                action=RecoveryAction.ROLLBACK,
                allowed=True,
                requires_reauthorization=False,
                requires_fresh_lease=False,
                reason_codes=("partial_mutation_requires_rollback",),
            )

        if context.new_authority_required:
            return self._blocked(
                "new_authority_requires_approval",
                disposition=RecoveryDisposition.APPROVAL_REQUIRED,
                action=RecoveryAction.ESCALATE,
                requires_reauthorization=True,
            )

        if base.action is RecoveryAction.REROUTE_RESOURCE:
            resource_failure = self._validate_resource(resource_decision)
            if resource_failure is not None:
                return self._blocked(resource_failure, requires_fresh_lease=True)
            base = replace(base, requires_fresh_lease=True)

        if base.action in {RecoveryAction.BLOCK, RecoveryAction.ESCALATE}:
            return base

        fingerprint_history = [
            entry for entry in history if entry.fingerprint == fingerprint
        ]
        mission_history = [
            entry for entry in history if entry.task_id == context.task_id
        ]
        fingerprint_decisions = [
            entry for entry in fingerprint_history if entry.outcome_status is None
        ]
        fingerprint_outcomes = [
            entry for entry in fingerprint_history if entry.outcome_status is not None
        ]
        mission_decisions = [
            entry for entry in mission_history if entry.outcome_status is None
        ]

        if fingerprint_outcomes:
            latest = fingerprint_outcomes[-1]
            if (
                latest.action is base.action
                and latest.outcome_status is RecoveryOutcomeStatus.FAILED
                and latest.progress is False
            ):
                return self._blocked("recovery_strategy_no_progress")

        if len(fingerprint_decisions) >= budgets.max_fingerprint_retries:
            return self._blocked("fingerprint_retry_budget_exhausted")

        action_limit = budgets.limit_for(base.action)
        if base.action is RecoveryAction.RETRY_STEP:
            prior_same_action = [
                entry for entry in fingerprint_decisions if entry.action is base.action
            ]
        else:
            prior_same_action = [
                entry for entry in mission_decisions if entry.action is base.action
            ]
        if action_limit <= 0 or len(prior_same_action) >= action_limit:
            return self._blocked(self._budget_reason(base.action))

        return base

    @staticmethod
    def _validate_resource(
        resource: ResourceRecoveryDecision | None,
    ) -> str | None:
        if resource is None:
            return "alternate_resource_unavailable"
        gates = (
            (resource.qualified, "alternate_resource_not_qualified"),
            (resource.healthy, "alternate_resource_unhealthy"),
            (resource.authorized, "alternate_resource_unauthorized"),
            (resource.cost_approved, "alternate_resource_cost_not_approved"),
            (resource.fresh_lease, "alternate_resource_lease_not_fresh"),
            (resource.source_bound, "alternate_resource_source_mismatch"),
        )
        return next((reason for passed, reason in gates if not passed), None)

    @staticmethod
    def _budget_reason(action: RecoveryAction) -> str:
        return {
            RecoveryAction.RETRY_STEP: "node_retry_budget_exhausted",
            RecoveryAction.REPLAN: "mission_replan_budget_exhausted",
            RecoveryAction.REPAIR_CANDIDATE: "candidate_repair_budget_exhausted",
            RecoveryAction.REROUTE_RESOURCE: "resource_reroute_budget_exhausted",
            RecoveryAction.REQUALIFY_RESOURCE: "resource_requalification_budget_exhausted",
            RecoveryAction.ROLLBACK: "rollback_budget_exhausted",
            RecoveryAction.ESCALATE: "approval_required",
            RecoveryAction.BLOCK: "recovery_blocked",
        }[action]

    @staticmethod
    def _blocked(
        reason: str,
        *,
        disposition: RecoveryDisposition = RecoveryDisposition.NON_RECOVERABLE,
        action: RecoveryAction = RecoveryAction.BLOCK,
        requires_reauthorization: bool = False,
        requires_fresh_lease: bool = False,
    ) -> PolicyDecision:
        return PolicyDecision(
            disposition=disposition,
            action=action,
            allowed=False,
            requires_reauthorization=requires_reauthorization,
            requires_fresh_lease=requires_fresh_lease,
            reason_codes=(reason,),
        )
