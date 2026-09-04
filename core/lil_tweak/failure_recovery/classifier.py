"""Conservative failure taxonomy for bounded recovery."""

from __future__ import annotations

from .contracts import (
    ClassifiedFailure,
    FailureClass,
    FailureCode,
    FailureSignal,
    RecoveryAction,
    RecoveryContext,
    RecoveryDisposition,
)


_INPUT_CONTRACT = frozenset(
    {
        FailureCode.INVALID_REQUEST,
        FailureCode.MISSING_CONTRACT,
        FailureCode.CONFLICTING_CONTRACT,
        FailureCode.STALE_CONTRACT,
        FailureCode.MISSING_APPROVAL,
        FailureCode.STALE_APPROVAL,
        FailureCode.WRONG_DIGEST_BINDING,
    }
)
_PLANNING = frozenset(
    {
        FailureCode.PLAN_INCOMPLETE,
        FailureCode.PLAN_INVALID,
        FailureCode.PLAN_CONTRACT_VIOLATION,
        FailureCode.PLAN_SCOPE_EXCESSIVE,
        FailureCode.PLAN_CRITIC_FAILURE,
    }
)
_REPOSITORY = frozenset(
    {
        FailureCode.STALE_SOURCE,
        FailureCode.SOURCE_CHANGED,
        FailureCode.REPOSITORY_UNAVAILABLE,
        FailureCode.MAPPER_INCOMPLETE,
        FailureCode.DEPENDENCY_UNCERTAIN,
        FailureCode.REPOSITORY_INTEGRITY_FAILURE,
    }
)
_EXECUTION = frozenset(
    {
        FailureCode.COMMAND_FAILED,
        FailureCode.TIMEOUT,
        FailureCode.PROCESS_CRASH,
        FailureCode.RESOURCE_EXHAUSTION,
        FailureCode.SANDBOX_FAILURE,
        FailureCode.RUNNER_UNAVAILABLE,
        FailureCode.RUNNER_UNQUALIFIED,
        FailureCode.LEASE_REJECTED,
        FailureCode.LEASE_EXPIRED,
        FailureCode.LEASE_REPLAYED,
        FailureCode.CANCELLATION,
        FailureCode.CLEANUP_FAILURE,
    }
)
_VERIFICATION = frozenset(
    {
        FailureCode.TEST_FAILURE,
        FailureCode.LINT_FAILURE,
        FailureCode.FORMAT_FAILURE,
        FailureCode.TYPECHECK_FAILURE,
        FailureCode.BUILD_FAILURE,
        FailureCode.SECURITY_CHECK_FAILURE,
        FailureCode.DETERMINISTIC_VERIFICATION_FAILURE,
        FailureCode.INDEPENDENT_VERIFICATION_FAILURE,
        FailureCode.FALSE_COMPLETION_CLAIM,
    }
)
_INFRASTRUCTURE = frozenset(
    {
        FailureCode.PROVIDER_UNHEALTHY,
        FailureCode.PROVIDER_TIMEOUT,
        FailureCode.PROVIDER_CAPACITY_EXHAUSTED,
        FailureCode.PROVIDER_COST_GATE,
        FailureCode.PROVIDER_AUTH_FAILURE,
        FailureCode.CONTROL_PLANE_FAILURE,
    }
)
_RECOVERY = frozenset(
    {
        FailureCode.ROLLBACK_FAILED,
        FailureCode.REPAIR_REPEATED,
        FailureCode.REPAIR_BUDGET_EXHAUSTED,
        FailureCode.RECOVERY_EVIDENCE_INVALID,
        FailureCode.RECOVERY_STRATEGY_INVALID,
        FailureCode.RECOVERY_STRATEGY_NO_PROGRESS,
    }
)


class FailureClassifier:
    """Map typed failure evidence to one conservative recovery disposition."""

    def classify(
        self, signal: FailureSignal, context: RecoveryContext
    ) -> ClassifiedFailure:
        del context
        if not isinstance(signal.code, FailureCode):
            return self._unknown()
        code = signal.code
        failure_class = self._failure_class(code)

        if signal.integrity_failure or code in {
            FailureCode.REPOSITORY_INTEGRITY_FAILURE,
            FailureCode.RECOVERY_EVIDENCE_INVALID,
        }:
            return self._block(failure_class, code, "integrity_failure")
        if signal.security_sensitive or code in {
            FailureCode.SECURITY_CHECK_FAILURE,
            FailureCode.FALSE_COMPLETION_CLAIM,
            FailureCode.LEASE_REPLAYED,
            FailureCode.PROVIDER_AUTH_FAILURE,
        }:
            return self._block(failure_class, code, code.value)
        if code in {
            FailureCode.CANCELLATION,
            FailureCode.ROLLBACK_FAILED,
            FailureCode.REPAIR_BUDGET_EXHAUSTED,
            FailureCode.REPAIR_REPEATED,
            FailureCode.RECOVERY_STRATEGY_INVALID,
            FailureCode.RECOVERY_STRATEGY_NO_PROGRESS,
        }:
            return self._block(failure_class, code, code.value)
        if code is FailureCode.WRONG_DIGEST_BINDING:
            return ClassifiedFailure(
                failure_class,
                code,
                RecoveryDisposition.NON_RECOVERABLE,
                RecoveryAction.BLOCK,
                (code.value,),
                automatic_recovery_prohibited=True,
                requires_reauthorization=True,
            )
        if code in {FailureCode.MISSING_APPROVAL, FailureCode.STALE_APPROVAL}:
            return ClassifiedFailure(
                failure_class,
                code,
                RecoveryDisposition.APPROVAL_REQUIRED,
                RecoveryAction.ESCALATE,
                (code.value,),
                requires_reauthorization=True,
            )
        if code in {
            FailureCode.STALE_SOURCE,
            FailureCode.SOURCE_CHANGED,
            FailureCode.STALE_CONTRACT,
            FailureCode.CONFLICTING_CONTRACT,
            FailureCode.PLAN_CONTRACT_VIOLATION,
        }:
            return ClassifiedFailure(
                failure_class,
                code,
                RecoveryDisposition.HUMAN_ESCALATION_REQUIRED,
                RecoveryAction.ESCALATE,
                (code.value,),
                requires_reauthorization=True,
            )
        if code in _PLANNING or code in {
            FailureCode.MAPPER_INCOMPLETE,
            FailureCode.DEPENDENCY_UNCERTAIN,
        }:
            return ClassifiedFailure(
                failure_class,
                code,
                RecoveryDisposition.REPLAN_REQUIRED,
                RecoveryAction.REPLAN,
                (code.value,),
            )
        if code in {
            FailureCode.TEST_FAILURE,
            FailureCode.LINT_FAILURE,
            FailureCode.FORMAT_FAILURE,
            FailureCode.TYPECHECK_FAILURE,
            FailureCode.BUILD_FAILURE,
            FailureCode.DETERMINISTIC_VERIFICATION_FAILURE,
            FailureCode.INDEPENDENT_VERIFICATION_FAILURE,
            FailureCode.COMMAND_FAILED,
        }:
            return ClassifiedFailure(
                failure_class,
                code,
                RecoveryDisposition.REPLAN_REQUIRED,
                RecoveryAction.REPAIR_CANDIDATE,
                (code.value,),
            )
        if code in {FailureCode.RUNNER_UNQUALIFIED}:
            return ClassifiedFailure(
                failure_class,
                code,
                RecoveryDisposition.RESOURCE_REROUTE_ALLOWED,
                RecoveryAction.REQUALIFY_RESOURCE,
                (code.value,),
                requires_fresh_lease=True,
            )
        if code in {
            FailureCode.RUNNER_UNAVAILABLE,
            FailureCode.PROVIDER_UNHEALTHY,
            FailureCode.PROVIDER_TIMEOUT,
            FailureCode.PROVIDER_CAPACITY_EXHAUSTED,
            FailureCode.RESOURCE_EXHAUSTION,
            FailureCode.CONTROL_PLANE_FAILURE,
        }:
            return ClassifiedFailure(
                failure_class,
                code,
                RecoveryDisposition.RESOURCE_REROUTE_ALLOWED,
                RecoveryAction.REROUTE_RESOURCE,
                (code.value,),
                requires_fresh_lease=True,
            )
        if code in {FailureCode.PROVIDER_COST_GATE}:
            return ClassifiedFailure(
                failure_class,
                code,
                RecoveryDisposition.APPROVAL_REQUIRED,
                RecoveryAction.ESCALATE,
                (code.value,),
                requires_reauthorization=True,
            )
        if code in {FailureCode.LEASE_EXPIRED, FailureCode.LEASE_REJECTED}:
            return ClassifiedFailure(
                failure_class,
                code,
                RecoveryDisposition.NON_RECOVERABLE,
                RecoveryAction.BLOCK,
                (code.value,),
                automatic_recovery_prohibited=True,
                requires_fresh_lease=True,
            )
        if code in {
            FailureCode.TIMEOUT,
            FailureCode.PROCESS_CRASH,
            FailureCode.SANDBOX_FAILURE,
            FailureCode.REPOSITORY_UNAVAILABLE,
        } and signal.transient:
            return ClassifiedFailure(
                failure_class,
                code,
                RecoveryDisposition.RETRYABLE,
                RecoveryAction.RETRY_STEP,
                (code.value,),
            )
        if code is FailureCode.CLEANUP_FAILURE:
            return ClassifiedFailure(
                failure_class,
                code,
                RecoveryDisposition.ROLLBACK_REQUIRED,
                RecoveryAction.ROLLBACK,
                (code.value,),
            )
        return self._block(failure_class, code, code.value)

    @staticmethod
    def _failure_class(code: FailureCode) -> FailureClass:
        if code in _INPUT_CONTRACT:
            return FailureClass.INPUT_CONTRACT
        if code in _PLANNING:
            return FailureClass.PLANNING
        if code in _REPOSITORY:
            return FailureClass.REPOSITORY_CONTEXT
        if code in _EXECUTION:
            return FailureClass.EXECUTION
        if code in _VERIFICATION:
            return FailureClass.VERIFICATION
        if code in _INFRASTRUCTURE:
            return FailureClass.INFRASTRUCTURE_PROVIDER
        if code in _RECOVERY:
            return FailureClass.RECOVERY
        return FailureClass.UNKNOWN

    @staticmethod
    def _block(
        failure_class: FailureClass, code: FailureCode, reason: str
    ) -> ClassifiedFailure:
        return ClassifiedFailure(
            failure_class,
            code,
            RecoveryDisposition.NON_RECOVERABLE,
            RecoveryAction.BLOCK,
            (reason,),
            automatic_recovery_prohibited=True,
        )

    @staticmethod
    def _unknown() -> ClassifiedFailure:
        return ClassifiedFailure(
            FailureClass.UNKNOWN,
            FailureCode.UNKNOWN_FAILURE,
            RecoveryDisposition.NON_RECOVERABLE,
            RecoveryAction.BLOCK,
            (FailureCode.UNKNOWN_FAILURE.value,),
            automatic_recovery_prohibited=True,
        )
