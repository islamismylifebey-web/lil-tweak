from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from liltweak.agent import DeterministicPlanner
from liltweak.api import create_app
from liltweak.config import Settings
from liltweak.costs import CostGuard
from liltweak.service import LilTweakService
from liltweak.store import SQLiteStore


def build_app():
    settings = Settings(
        environment="test",
        database_path=Path(":memory:"),
        dev_api_key="test-secret",
        auth_disabled=False,
        model="gpt-5.6-luna",
        monthly_budget_usd=250,
        job_hard_limit_usd=5,
    )
    service = LilTweakService(
        store=SQLiteStore(":memory:"),
        planner=DeterministicPlanner(),
        cost_guard=CostGuard(monthly_limit_usd=250, job_default_limit_usd=5),
        owner_id=settings.owner_id,
    )
    return create_app(service=service, settings=settings)


def task_payload() -> dict:
    return {
        "task_id": "api-task",
        "requested_by": "owner",
        "organization_id": "org",
        "project_id": "project",
        "environment": "development",
        "objective": "Prepare a repair plan.",
        "execution_permission": False,
    }


@pytest.mark.asyncio
async def test_health_is_public_and_truthful() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=build_app()), base_url="http://test"
    ) as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["execution_connected"] is False


@pytest.mark.asyncio
async def test_jobs_require_authentication() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=build_app()), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/jobs",
            headers={"Idempotency-Key": "api-idempotency-0001"},
            json=task_payload(),
        )
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_job_api_rejects_credential_material_without_echoing_it() -> None:
    fake_credential = "sk-" + "proj-" + ("S" * 32)
    payload = task_payload()
    payload["objective"] = f"Repair the connector using {fake_credential}"
    async with AsyncClient(
        transport=ASGITransport(app=build_app()), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/jobs",
            headers={
                "Authorization": "Bearer test-secret",
                "Idempotency-Key": "api-sensitive-input-0001",
            },
            json=payload,
        )
        assert response.status_code == 422
        assert fake_credential not in response.text


@pytest.mark.asyncio
async def test_validation_errors_never_echo_credential_values() -> None:
    fake_credential = "sk-" + "proj-" + ("V" * 32)
    payload = task_payload()
    payload["unexpected"] = fake_credential
    async with AsyncClient(
        transport=ASGITransport(app=build_app()), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/jobs",
            headers={
                "Authorization": "Bearer test-secret",
                "Idempotency-Key": "api-validation-redaction-0001",
            },
            json=payload,
        )
        assert response.status_code == 422
        assert fake_credential not in response.text
        assert response.json() == {"detail": "Request validation failed."}


@pytest.mark.asyncio
async def test_oversized_idempotency_key_is_rejected_without_storage() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=build_app()), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/jobs",
            headers={
                "Authorization": "Bearer test-secret",
                "Idempotency-Key": "x" * 129,
            },
            json=task_payload(),
        )
        assert response.status_code == 422


@pytest.mark.asyncio
async def test_job_analysis_and_evidence_api() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=build_app()), base_url="http://test"
    ) as client:
        headers = {
            "Authorization": "Bearer test-secret",
            "Idempotency-Key": "api-idempotency-0002",
        }
        created = await client.post("/v1/jobs", headers=headers, json=task_payload())
        assert created.status_code == 202
        job_id = created.json()["id"]

        analyzed = await client.post(
            f"/v1/jobs/{job_id}/analyze",
            headers={"Authorization": "Bearer test-secret"},
        )
        assert analyzed.status_code == 200
        assert analyzed.json()["status"] == "PLAN_READY"

        evidence = await client.get(
            f"/v1/jobs/{job_id}/evidence",
            headers={"Authorization": "Bearer test-secret"},
        )
        assert evidence.status_code == 200
        assert len(evidence.json()) >= 5


@pytest.mark.asyncio
async def test_execute_route_reports_real_runner_state() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=build_app()), base_url="http://test"
    ) as client:
        auth = {"Authorization": "Bearer test-secret"}
        created = await client.post(
            "/v1/jobs",
            headers={**auth, "Idempotency-Key": "api-idempotency-0003"},
            json=task_payload(),
        )
        job_id = created.json()["id"]
        await client.post(f"/v1/jobs/{job_id}/analyze", headers=auth)
        executed = await client.post(f"/v1/jobs/{job_id}/execute", headers=auth)
        assert executed.status_code == 409
        status_response = await client.get(f"/v1/jobs/{job_id}", headers=auth)
        assert status_response.json()["status"] == "BLOCKED"


@pytest.mark.asyncio
async def test_duplicate_approval_decision_returns_controlled_conflict() -> None:
    payload = task_payload()
    payload["environment"] = "production"
    async with AsyncClient(
        transport=ASGITransport(app=build_app()), base_url="http://test"
    ) as client:
        auth = {"Authorization": "Bearer test-secret"}
        created = await client.post(
            "/v1/jobs",
            headers={**auth, "Idempotency-Key": "api-approval-conflict-0001"},
            json=payload,
        )
        analyzed = await client.post(
            f"/v1/jobs/{created.json()['id']}/analyze",
            headers=auth,
        )
        approval_id = analyzed.json()["approval_id"]
        approval = await client.get(f"/v1/approvals/{approval_id}", headers=auth)
        decision = {
            "decision": "approve",
            "action_digest": approval.json()["action_digest"],
        }
        first = await client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=auth,
            json=decision,
        )
        second = await client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=auth,
            json=decision,
        )
        assert first.status_code == 200
        assert second.status_code == 409


@pytest.mark.asyncio
async def test_cancel_attribution_uses_authenticated_owner_not_request_body() -> None:
    app = build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        auth = {"Authorization": "Bearer test-secret"}
        created = await client.post(
            "/v1/jobs",
            headers={**auth, "Idempotency-Key": "api-cancel-attribution-0001"},
            json=task_payload(),
        )
        job_id = created.json()["id"]
        canceled = await client.post(
            f"/v1/jobs/{job_id}/cancel",
            headers=auth,
            json={"requested_by": "spoofed-user"},
        )
        assert canceled.status_code == 200
        evidence = await client.get(f"/v1/jobs/{job_id}/evidence", headers=auth)
        assert "spoofed-user" not in evidence.text
        assert "maurice-pennington-bey" in evidence.text
