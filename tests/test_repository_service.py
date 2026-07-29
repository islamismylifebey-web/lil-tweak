from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from liltweak.agent import DeterministicPlanner
from liltweak.api import create_app
from liltweak.config import Settings
from liltweak.costs import CostGuard
from liltweak.models import JobStatus, PlanResult, RepositoryRef, TaskCreate
from liltweak.repository import RepositoryAccessError, RepositoryInspector
from liltweak.service import LilTweakService, RunnerUnavailableError
from liltweak.store import SQLiteStore
from tests.repository_helpers import initialize_repository


class CapturingPlanner:
    def __init__(self) -> None:
        self.context: dict[str, Any] | None = None

    async def plan(
        self,
        task: TaskCreate,
        inspection_context: dict[str, Any] | None = None,
    ) -> PlanResult:
        self.context = inspection_context
        return await DeterministicPlanner().plan(task, inspection_context)


def repository_task(*, repository_id: str = "fixture", execution: bool = False) -> TaskCreate:
    return TaskCreate(
        task_id="repository-task",
        requested_by="owner",
        organization_id="owner",
        project_id="lil-tweak",
        repository=RepositoryRef(
            provider="local",
            repository_id=repository_id,
            revision="WORKTREE",
        ),
        objective="Prepare a safe repair plan without changing the repository.",
        execution_permission=execution,
    )


def build_service(workspace: Path, planner=None) -> LilTweakService:
    return LilTweakService(
        store=SQLiteStore(":memory:"),
        planner=planner or DeterministicPlanner(),
        cost_guard=CostGuard(monthly_limit_usd=250, job_default_limit_usd=5),
        repository_inspector=RepositoryInspector(
            workspace,
            repository_mappings={"local:fixture": "repository"},
        ),
    )


@pytest.mark.asyncio
async def test_analyze_performs_real_inspection_before_planning(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    fake_secret = "sk-" + "proj-" + ("Q" * 32)
    (repository / "src" / "secret.txt").write_text(fake_secret, encoding="utf-8")
    planner = CapturingPlanner()
    service = build_service(workspace, planner)
    job = service.create_job(repository_task(), "repository-idempotency-0001")

    analyzed = await service.analyze_job(job.id)

    assert analyzed.status == JobStatus.PLAN_READY
    assert analyzed.inspection is not None
    assert analyzed.inspection.read_only_verified is True
    assert planner.context is not None
    serialized_context = json.dumps(planner.context)
    assert fake_secret not in serialized_context
    assert "secret.txt" not in serialized_context
    assert service.evidence.verify(job.id)
    event_types = [item.event_type for item in service.evidence.list(job.id)]
    assert event_types.index("repository_inspected") < event_types.index("plan_created")


def test_unknown_registry_id_is_blocked_with_evidence(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    initialize_repository(workspace)
    service = build_service(workspace)
    job = service.create_job(
        repository_task(repository_id="not-registered"),
        "repository-idempotency-0002",
    )

    with pytest.raises(RepositoryAccessError):
        service.inspect_job(job.id)

    assert service.get_job(job.id).status == JobStatus.BLOCKED
    assert service.evidence.verify(job.id)


@pytest.mark.asyncio
async def test_execution_remains_blocked_even_when_task_requests_it(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    initialize_repository(workspace)
    service = build_service(workspace)
    job = service.create_job(
        repository_task(execution=True),
        "repository-idempotency-0003",
    )
    analyzed = await service.analyze_job(job.id)

    with pytest.raises(RunnerUnavailableError):
        service.request_execution(analyzed.id)

    assert service.get_job(job.id).status == JobStatus.BLOCKED
    assert service.health().execution_connected is False


@pytest.mark.asyncio
async def test_inspection_api_is_authenticated_and_redacted(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    fake_secret = "sk-" + "proj-" + ("R" * 32)
    (repository / "src" / "credential.txt").write_text(fake_secret, encoding="utf-8")
    service = build_service(workspace)
    settings = Settings(
        environment="test",
        database_path=Path(":memory:"),
        dev_api_key="test-secret",
        auth_disabled=False,
        model="gpt-5.6-luna",
        monthly_budget_usd=250,
        job_hard_limit_usd=5,
        workspace_root=workspace,
        repository_mappings={"local:fixture": "repository"},
    )
    app = create_app(service=service, settings=settings)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        unauthenticated = await client.get("/v1/jobs/unknown/inspection")
        assert unauthenticated.status_code == 401
        auth = {"Authorization": "Bearer test-secret"}
        created = await client.post(
            "/v1/jobs",
            headers={**auth, "Idempotency-Key": "repository-api-key-0001"},
            json=repository_task().model_dump(mode="json"),
        )
        assert created.status_code == 202
        job_id = created.json()["id"]
        inspected = await client.post(f"/v1/jobs/{job_id}/inspect", headers=auth)
        assert inspected.status_code == 200
        assert inspected.json()["status"] == "ANALYZED"
        response = await client.get(f"/v1/jobs/{job_id}/inspection", headers=auth)
        assert response.status_code == 200
        body = response.text
        assert fake_secret not in body
        assert "openai-api-key" in body
        analyzed = await client.post(f"/v1/jobs/{job_id}/analyze", headers=auth)
        assert analyzed.status_code == 200
        assert analyzed.json()["status"] == "PLAN_READY"


def test_health_reports_phase_three_and_registry_state(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    initialize_repository(workspace)
    health = build_service(workspace).health()

    assert health.phase == 3
    assert health.repository_inspection_enabled is True
    assert health.execution_connected is False
