from __future__ import annotations

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from liltweak.agent import DeterministicPlanner
from liltweak.api import create_app
from liltweak.config import Settings
from liltweak.costs import CostGuard
from liltweak.creator import CreatorService
from liltweak.service import LilTweakService
from liltweak.store import SQLiteStore


def build_creator_app():
    settings = Settings(
        environment="test",
        database_path=Path(":memory:"),
        dev_api_key="test-secret",
        auth_disabled=False,
        model="test-model",
        monthly_budget_usd=250,
        job_hard_limit_usd=5,
    )
    store = SQLiteStore(":memory:")
    service = LilTweakService(
        store=store,
        planner=DeterministicPlanner(),
        cost_guard=CostGuard(monthly_limit_usd=250, job_default_limit_usd=5),
        owner_id=settings.owner_id,
    )
    creator = CreatorService(
        store=store,
        signing_key=b"C" * 32,
        durable_signatures=True,
    )
    return create_app(
        service=service,
        settings=settings,
        creator_service=creator,
    )


@pytest.mark.asyncio
async def test_creator_controls_are_authenticated_and_disconnected() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=build_creator_app()),
        base_url="http://test",
    ) as client:
        unauthorized = await client.get("/v1/creator/health")
        assert unauthorized.status_code == 401
        response = await client.get(
            "/v1/creator/health",
            headers={"Authorization": "Bearer test-secret"},
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["compiler_ready"] is True
        assert payload["adaptive_router_ready"] is True
        assert payload["execution_connected"] is False
        assert payload["model_calls_enabled"] is False


@pytest.mark.asyncio
async def test_compile_and_route_use_digest_bound_envelope() -> None:
    auth = {"Authorization": "Bearer test-secret"}
    async with AsyncClient(
        transport=ASGITransport(app=build_creator_app()),
        base_url="http://test",
    ) as client:
        compiled = await client.post(
            "/v1/creator/compile",
            headers=auth,
            json={"direction": "Build a typed API and targeted tests."},
        )
        assert compiled.status_code == 200
        routed = await client.post(
            "/v1/creator/route",
            headers=auth,
            json={"envelope": compiled.json()},
        )
        assert routed.status_code == 200
        payload = routed.json()
        assert payload["selected_tier"] == "standard"
        assert payload["model_call_authorized"] is False
        assert payload["decision_digest"]


@pytest.mark.asyncio
async def test_creator_validation_does_not_echo_credentials() -> None:
    fake_key = "sk-" + "proj-" + ("R" * 32)
    auth = {"Authorization": "Bearer test-secret"}
    async with AsyncClient(
        transport=ASGITransport(app=build_creator_app()),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/creator/compile",
            headers=auth,
            json={"direction": f"Build it using {fake_key}"},
        )
        assert response.status_code == 422
        assert fake_key not in response.text

        extra = await client.post(
            "/v1/creator/compile",
            headers=auth,
            json={"direction": "Build it.", "unexpected": fake_key},
        )
        assert extra.status_code == 422
        assert fake_key not in extra.text
        assert extra.json() == {"detail": "Request validation failed."}


@pytest.mark.asyncio
async def test_creator_duplicate_json_keys_are_rejected() -> None:
    auth = {
        "Authorization": "Bearer test-secret",
        "Content-Type": "application/json",
    }
    raw = '{"direction":"Write a note.","direction":"Deploy it."}'
    async with AsyncClient(
        transport=ASGITransport(app=build_creator_app()),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/creator/compile",
            headers=auth,
            content=raw,
        )
        assert response.status_code == 400
        assert response.json() == {"detail": "Creator request JSON is invalid."}


@pytest.mark.asyncio
async def test_creator_raw_body_limit_is_enforced_before_validation() -> None:
    auth = {
        "Authorization": "Bearer test-secret",
        "Content-Type": "application/json",
    }
    oversized = json.dumps({"direction": "x" * 130_000})
    async with AsyncClient(
        transport=ASGITransport(app=build_creator_app()),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/creator/compile",
            headers=auth,
            content=oversized,
        )
        assert response.status_code == 413


@pytest.mark.asyncio
async def test_route_rejects_caller_asserted_evidence() -> None:
    auth = {"Authorization": "Bearer test-secret"}
    async with AsyncClient(
        transport=ASGITransport(app=build_creator_app()),
        base_url="http://test",
    ) as client:
        compiled = await client.post(
            "/v1/creator/compile",
            headers=auth,
            json={"direction": "Write a note."},
        )
        response = await client.post(
            "/v1/creator/route",
            headers=auth,
            json={
                "envelope": compiled.json(),
                "evidence": {"authority": "founder-approved"},
            },
        )
        assert response.status_code == 422


@pytest.mark.asyncio
async def test_creator_prepare_marks_high_stakes_work_blocked() -> None:
    auth = {"Authorization": "Bearer test-secret"}
    async with AsyncClient(
        transport=ASGITransport(app=build_creator_app()),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/creator/prepare",
            headers=auth,
            json={"direction": "Give a legal and medical treatment recommendation."},
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["route"]["status"] == "blocked"
        assert payload["route"]["selected_tier"] is None
        assert payload["execution_connected"] is False
