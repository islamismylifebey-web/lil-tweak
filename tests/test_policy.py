from __future__ import annotations

from collections.abc import Callable

from liltweak.models import ActionProposal, Environment, RiskLevel, TaskCreate
from liltweak.policy import PolicyEngine


def test_development_preparation_does_not_require_approval(
    make_task: Callable[..., TaskCreate],
) -> None:
    decision = PolicyEngine().evaluate(
        make_task(),
        ActionProposal(operation="prepare_patch", environment=Environment.DEVELOPMENT),
    )
    assert decision.allowed_to_prepare
    assert not decision.allowed_to_execute
    assert not decision.approval_required


def test_production_requires_approval(make_task: Callable[..., TaskCreate]) -> None:
    decision = PolicyEngine().evaluate(
        make_task(environment=Environment.PRODUCTION),
        ActionProposal(operation="deploy", environment=Environment.PRODUCTION),
    )
    assert decision.approval_required
    assert not decision.allowed_to_execute
    assert decision.risk_level == RiskLevel.HIGH


def test_prohibited_operation_is_denied(make_task: Callable[..., TaskCreate]) -> None:
    decision = PolicyEngine().evaluate(
        make_task(prohibited_actions=["delete_database"]),
        ActionProposal(operation="delete_database", environment=Environment.DEVELOPMENT),
    )
    assert not decision.allowed_to_prepare
    assert not decision.allowed_to_execute
    assert decision.risk_level == RiskLevel.CRITICAL


def test_disabling_security_is_critical(make_task: Callable[..., TaskCreate]) -> None:
    decision = PolicyEngine().evaluate(
        make_task(),
        ActionProposal(
            operation="change_security",
            environment=Environment.DEVELOPMENT,
            disables_security=True,
        ),
    )
    assert decision.approval_required
    assert decision.risk_level == RiskLevel.CRITICAL
