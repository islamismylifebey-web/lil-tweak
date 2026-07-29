from __future__ import annotations

from collections.abc import Callable

import pytest

from liltweak.agent import DeterministicPlanner
from liltweak.costs import CostGuard
from liltweak.models import Environment, TaskCreate
from liltweak.service import LilTweakService
from liltweak.store import SQLiteStore


@pytest.fixture
def service() -> LilTweakService:
    return LilTweakService(
        store=SQLiteStore(":memory:"),
        planner=DeterministicPlanner(),
        cost_guard=CostGuard(monthly_limit_usd=250, job_default_limit_usd=5),
    )


@pytest.fixture
def make_task() -> Callable[..., TaskCreate]:
    def factory(**changes: object) -> TaskCreate:
        values: dict[str, object] = {
            "task_id": "task-1",
            "requested_by": "owner",
            "organization_id": "org-1",
            "project_id": "project-1",
            "environment": Environment.DEVELOPMENT,
            "objective": "Prepare a safe repair plan.",
            "execution_permission": False,
        }
        values.update(changes)
        return TaskCreate.model_validate(values)

    return factory
