from __future__ import annotations

from collections.abc import Callable

import pytest

from liltweak.agent import DeterministicPlanner, PlanningProviderError
from liltweak.costs import BudgetExceededError, CostGuard
from liltweak.models import JobStatus, TaskCreate
from liltweak.service import (
    EmergencyStopError,
    LilTweakService,
    RunnerUnavailableError,
    SensitiveInputError,
)
from liltweak.store import IdempotencyConflictError, SQLiteStore


class FailingPlanner:
    async def plan(self, _task: TaskCreate, _inspection_context=None):
        raise PlanningProviderError("provider unavailable")


class PaidPlanner:
    paid_provider = True

    async def plan(self, task: TaskCreate, inspection_context=None):
        return await DeterministicPlanner().plan(task, inspection_context)


def test_job_creation_is_idempotent(
    service: LilTweakService, make_task: Callable[..., TaskCreate]
) -> None:
    first = service.create_job(make_task(), "idempotency-key-0001")
    second = service.create_job(make_task(), "idempotency-key-0001")
    assert first.id == second.id


def test_job_input_with_credential_material_is_rejected_before_storage(
    service: LilTweakService, make_task: Callable[..., TaskCreate]
) -> None:
    fake_credential = "sk-" + "proj-" + ("S" * 32)
    with pytest.raises(SensitiveInputError, match="references, not secrets"):
        service.create_job(
            make_task(objective=f"Repair the connector using {fake_credential}"),
            "idempotency-sensitive-input-0001",
        )
    assert service.store.list_active_jobs() == []


def test_idempotency_key_rejects_changed_input(
    service: LilTweakService, make_task: Callable[..., TaskCreate]
) -> None:
    service.create_job(make_task(), "idempotency-key-0002")
    with pytest.raises(IdempotencyConflictError):
        service.create_job(make_task(objective="A different request."), "idempotency-key-0002")


@pytest.mark.asyncio
async def test_analysis_produces_plan_without_claiming_execution(
    service: LilTweakService, make_task: Callable[..., TaskCreate]
) -> None:
    job = service.create_job(make_task(), "idempotency-key-0003")
    analyzed = await service.analyze_job(job.id)
    assert analyzed.status == JobStatus.PLAN_READY
    assert analyzed.plan is not None
    assert "No execution runner is connected in Phase 3." in analyzed.plan.blockers
    assert service.evidence.verify(job.id)


@pytest.mark.asyncio
async def test_execution_is_blocked_without_runner(
    service: LilTweakService, make_task: Callable[..., TaskCreate]
) -> None:
    job = service.create_job(make_task(), "idempotency-key-0004")
    await service.analyze_job(job.id)
    with pytest.raises(RunnerUnavailableError):
        service.request_execution(job.id)
    assert service.get_job(job.id).status == JobStatus.BLOCKED


def test_cancel_is_idempotent(
    service: LilTweakService, make_task: Callable[..., TaskCreate]
) -> None:
    job = service.create_job(make_task(), "idempotency-key-0005")
    canceled = service.cancel_job(job.id, "owner")
    again = service.cancel_job(job.id, "owner")
    assert canceled.status == JobStatus.CANCELED
    assert again.status == JobStatus.CANCELED


def test_emergency_stop_cancels_active_jobs(
    service: LilTweakService, make_task: Callable[..., TaskCreate]
) -> None:
    job = service.create_job(make_task(), "idempotency-key-0006")
    canceled = service.emergency_stop("owner")
    assert canceled == [job.id]
    assert service.get_job(job.id).status == JobStatus.CANCELED
    with pytest.raises(EmergencyStopError):
        service.create_job(make_task(task_id="task-2"), "idempotency-key-0007")


@pytest.mark.asyncio
async def test_provider_failure_is_recorded_as_failed(
    make_task: Callable[..., TaskCreate],
) -> None:
    service = LilTweakService(
        store=SQLiteStore(":memory:"),
        planner=FailingPlanner(),
        cost_guard=CostGuard(monthly_limit_usd=250, job_default_limit_usd=5),
    )
    job = service.create_job(make_task(), "idempotency-key-0008")
    with pytest.raises(PlanningProviderError):
        await service.analyze_job(job.id)
    assert service.get_job(job.id).status == JobStatus.FAILED
    assert service.evidence.verify(job.id)


@pytest.mark.asyncio
async def test_paid_planning_reserves_monthly_budget_before_provider_call(
    make_task: Callable[..., TaskCreate],
) -> None:
    service = LilTweakService(
        store=SQLiteStore(":memory:"),
        planner=PaidPlanner(),
        cost_guard=CostGuard(
            monthly_limit_usd=1,
            job_default_limit_usd=5,
            planning_reservation_usd=1,
        ),
    )
    first = service.create_job(
        make_task(task_id="paid-task-1"),
        "paid-reservation-0001",
    )
    analyzed = await service.analyze_job(first.id)
    assert analyzed.budget_reserved_usd == 1
    assert analyzed.estimated_cost_usd == 1
    assert analyzed.actual_cost_usd == 0
    assert service.store.month_to_date_cost() == 1

    second = service.create_job(
        make_task(task_id="paid-task-2"),
        "paid-reservation-0002",
    )
    with pytest.raises(BudgetExceededError, match="monthly"):
        await service.analyze_job(second.id)
    assert service.get_job(second.id).status == JobStatus.BLOCKED
