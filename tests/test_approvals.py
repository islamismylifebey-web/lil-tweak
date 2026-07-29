from __future__ import annotations

from collections.abc import Callable

import pytest

from liltweak.approvals import ApprovalError
from liltweak.models import (
    ApprovalDecisionRequest,
    ApprovalStatus,
    Environment,
    JobStatus,
    TaskCreate,
)
from liltweak.service import LilTweakService


@pytest.mark.asyncio
async def test_production_plan_creates_exact_approval(
    service: LilTweakService, make_task: Callable[..., TaskCreate]
) -> None:
    job = service.create_job(make_task(environment=Environment.PRODUCTION), "approval-key-0001")
    job = await service.analyze_job(job.id)
    assert job.status == JobStatus.AWAITING_APPROVAL
    assert job.approval_id
    approval = service.approvals.get(job.approval_id)
    assert approval.status == ApprovalStatus.PENDING


@pytest.mark.asyncio
async def test_only_owner_can_decide(
    service: LilTweakService, make_task: Callable[..., TaskCreate]
) -> None:
    job = service.create_job(make_task(environment=Environment.PRODUCTION), "approval-key-0002")
    job = await service.analyze_job(job.id)
    approval = service.approvals.get(job.approval_id or "")
    with pytest.raises(ApprovalError):
        service.decide_approval(
            approval.id,
            ApprovalDecisionRequest(
                decision="approve",
                action_digest=approval.action_digest,
            ),
            "developer",
        )


@pytest.mark.asyncio
async def test_approval_is_one_use(
    service: LilTweakService, make_task: Callable[..., TaskCreate]
) -> None:
    job = service.create_job(make_task(environment=Environment.PRODUCTION), "approval-key-0003")
    job = await service.analyze_job(job.id)
    approval = service.approvals.get(job.approval_id or "")
    request = ApprovalDecisionRequest(
        decision="approve",
        action_digest=approval.action_digest,
    )
    approved_job = service.decide_approval(approval.id, request, "owner")
    assert approved_job.status == JobStatus.APPROVED
    with pytest.raises(ApprovalError):
        service.decide_approval(approval.id, request, "owner")


@pytest.mark.asyncio
async def test_digest_mismatch_is_rejected(
    service: LilTweakService, make_task: Callable[..., TaskCreate]
) -> None:
    job = service.create_job(make_task(environment=Environment.PRODUCTION), "approval-key-0004")
    job = await service.analyze_job(job.id)
    approval = service.approvals.get(job.approval_id or "")
    with pytest.raises(ApprovalError):
        service.decide_approval(
            approval.id,
            ApprovalDecisionRequest(
                decision="approve",
                action_digest="0" * 64,
            ),
            "owner",
        )
