from __future__ import annotations

from .models import (
    ActionProposal,
    Environment,
    PolicyDecision,
    RiskLevel,
    TaskCreate,
)

SENSITIVE_FLAGS: tuple[tuple[str, str], ...] = (
    ("destructive", "destructive action"),
    ("changes_billing", "billing change"),
    ("changes_permissions", "permission change"),
    ("changes_live_credentials", "live credential change"),
    ("changes_public_dns", "public DNS change"),
    ("changes_production_database", "production database change"),
    ("enables_money_movement", "money movement"),
    ("disables_security", "security control change"),
)


class PolicyEngine:
    def evaluate(self, task: TaskCreate, proposal: ActionProposal) -> PolicyDecision:
        reasons: list[str] = []
        approval_required = proposal.environment == Environment.PRODUCTION
        if approval_required:
            reasons.append("production action")

        for attribute, label in SENSITIVE_FLAGS:
            if getattr(proposal, attribute):
                approval_required = True
                reasons.append(label)

        if proposal.operation in task.prohibited_actions:
            return PolicyDecision(
                allowed_to_prepare=False,
                allowed_to_execute=False,
                approval_required=False,
                reasons=["operation is explicitly prohibited by the task"],
                risk_level=RiskLevel.CRITICAL,
            )

        risk = RiskLevel.LOW
        if approval_required:
            risk = RiskLevel.HIGH
        if proposal.destructive or proposal.disables_security or proposal.enables_money_movement:
            risk = RiskLevel.CRITICAL

        # Phase 3 has no execution runner. Model output cannot change this fact.
        return PolicyDecision(
            allowed_to_prepare=True,
            allowed_to_execute=False,
            approval_required=approval_required,
            reasons=reasons or ["Phase 3 inspection, recovery, and preparation only"],
            risk_level=risk,
        )
