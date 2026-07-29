from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from .models import (
    ActionProposal,
    ApprovalDecisionRequest,
    ApprovalRecord,
    ApprovalStatus,
    Environment,
)
from .store import SQLiteStore, canonical_json


class ApprovalError(ValueError):
    pass


def action_digest(job_id: str, proposal: ActionProposal) -> str:
    value = {"job_id": job_id, "proposal": proposal.model_dump(mode="json")}
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


class ApprovalService:
    def __init__(self, store: SQLiteStore, owner_id: str) -> None:
        self._store = store
        self._owner_id = owner_id

    def build(self, job_id: str, proposal: ActionProposal, created_by: str) -> ApprovalRecord:
        lifetime = timedelta(minutes=30)
        if proposal.environment != Environment.PRODUCTION:
            lifetime = timedelta(hours=24)
        return ApprovalRecord(
            id=f"apr_{secrets.token_urlsafe(18)}",
            job_id=job_id,
            action_digest=action_digest(job_id, proposal),
            proposal=proposal,
            purpose=proposal.purpose,
            status=ApprovalStatus.PENDING,
            created_by=created_by,
            expires_at=datetime.now(UTC) + lifetime,
        )

    def create(self, job_id: str, proposal: ActionProposal, created_by: str) -> ApprovalRecord:
        approval = self.build(job_id, proposal, created_by)
        self._store.save_approval(approval)
        return approval

    def get(self, approval_id: str) -> ApprovalRecord:
        approval = self._store.get_approval(approval_id)
        if approval.status in {
            ApprovalStatus.PENDING,
            ApprovalStatus.APPROVED,
        } and approval.expires_at <= datetime.now(UTC):
            approval.status = ApprovalStatus.EXPIRED
            self._store.save_approval(approval)
        return approval

    def decide(
        self,
        approval_id: str,
        request: ApprovalDecisionRequest,
        authenticated_identity: str,
    ) -> ApprovalRecord:
        if not secrets.compare_digest(authenticated_identity, self._owner_id):
            raise ApprovalError("this approval requires the authenticated owner")
        try:
            return self._store.decide_approval(
                approval_id,
                expected_digest=request.action_digest,
                approved=request.decision == "approve",
                decided_by=authenticated_identity,
                now=datetime.now(UTC),
            )
        except ValueError as exc:
            raise ApprovalError(str(exc)) from exc

    def consume(
        self,
        approval_id: str,
        *,
        expected_digest: str,
        expected_purpose: str,
        authenticated_identity: str,
    ) -> ApprovalRecord:
        if not secrets.compare_digest(authenticated_identity, self._owner_id):
            raise ApprovalError("this action requires the authenticated owner")
        approval = self.get(approval_id)
        if approval.status != ApprovalStatus.APPROVED:
            raise ApprovalError("approval is not approved and unused")
        if not secrets.compare_digest(approval.action_digest, expected_digest):
            raise ApprovalError("approval no longer matches the proposed action")
        if not secrets.compare_digest(approval.purpose, expected_purpose):
            raise ApprovalError("approval purpose does not match the proposed action")
        try:
            return self._store.consume_approval(
                approval_id,
                consumed_by=authenticated_identity,
                now=datetime.now(UTC),
            )
        except ValueError as exc:
            raise ApprovalError(str(exc)) from exc
