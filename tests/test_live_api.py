from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from liltweak.agent import DeterministicPlanner
from liltweak.api import create_app
from liltweak.config import Settings
from liltweak.costs import CostGuard
from liltweak.creator import CreatorService
from liltweak.live_contract import CreatorWorkOrder, LiveModelUsage
from liltweak.live_model import (
    LiveCreatorController,
    ProviderWorkOrder,
)
from liltweak.service import LilTweakService
from liltweak.store import SQLiteStore

SIGNING_KEY = b"A" * 32


class ApiFixtureProvider:
    def __init__(self) -> None:
        self.calls = 0

    async def create_work_order(self, proposal, envelope) -> ProviderWorkOrder:
        del proposal, envelope
        self.calls += 1
        return ProviderWorkOrder(
            work_order=CreatorWorkOrder(
                functional_gap="The requested typed endpoint is absent.",
                confirmed_facts=("A signed brief was supplied.",),
                unknowns=("No repository bodies were supplied.",),
                hypotheses=("A narrow endpoint is sufficient.",),
                smallest_intervention=("Add the endpoint.",),
                verification_checks=("Exercise the endpoint with a regression test.",),
                stop_conditions=("Stop before execution without a separate approval.",),
                execution_required=True,
            ),
            usage=LiveModelUsage(
                requests=1,
                input_tokens=700,
                output_tokens=180,
                total_tokens=880,
            ),
            response_id="resp_api_fixture",
        )


def build_live_api(*, durable: bool = True):
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
        signing_key=SIGNING_KEY if durable else None,
        durable_signatures=durable,
    )
    provider = ApiFixtureProvider()
    live = None
    if durable:
        live = LiveCreatorController(
            creator=creator,
            store=store,
            signing_key=SIGNING_KEY,
            provider=provider,
            enabled=True,
            owner_id=settings.owner_id,
            monthly_limit_usd=1.0,
            per_call_limit_usd=0.10,
        )
    return (
        create_app(
            service=service,
            settings=settings,
            creator_service=creator,
            live_controller=live,
        ),
        provider,
    )


@pytest.mark.asyncio
async def test_live_api_requires_durable_controls() -> None:
    app, _provider = build_live_api(durable=False)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        compiled = await client.post(
            "/v1/creator/compile",
            headers={"Authorization": "Bearer test-secret"},
            json={"direction": "Build a typed API."},
        )
        routed = await client.post(
            "/v1/creator/route",
            headers={"Authorization": "Bearer test-secret"},
            json={"envelope": compiled.json()},
        )
        response = await client.post(
            "/v1/creator/live/proposals",
            headers={"Authorization": "Bearer test-secret"},
            json={"envelope": compiled.json(), "route": routed.json()},
        )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_live_api_exact_approval_and_one_call_flow() -> None:
    app, provider = build_live_api()
    auth = {"Authorization": "Bearer test-secret"}
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        health = await client.get("/v1/creator/health", headers=auth)
        assert health.status_code == 200
        assert health.json()["model_calls_enabled"] is True
        assert health.json()["hosted_sandbox_probe_ready"] is False
        assert health.json()["source_execution_connected"] is False

        compiled = await client.post(
            "/v1/creator/compile",
            headers=auth,
            json={"direction": "Build a typed API and regression tests."},
        )
        routed = await client.post(
            "/v1/creator/route",
            headers=auth,
            json={"envelope": compiled.json()},
        )
        proposal_response = await client.post(
            "/v1/creator/live/proposals",
            headers=auth,
            json={
                "envelope": compiled.json(),
                "route": routed.json(),
            },
        )
        assert proposal_response.status_code == 202
        proposal_record = proposal_response.json()
        proposal = proposal_record["proposal"]
        assert proposal_record["status"] == "pending_approval"
        assert proposal["model_call_authorized"] is False
        assert proposal["spend_authorized"] is False

        wrong = await client.post(
            f"/v1/creator/live/proposals/{proposal['id']}/decision",
            headers=auth,
            json={"decision": "approve", "proposal_digest": "0" * 64},
        )
        assert wrong.status_code == 409
        assert provider.calls == 0

        decision = await client.post(
            f"/v1/creator/live/proposals/{proposal['id']}/decision",
            headers=auth,
            json={
                "decision": "approve",
                "proposal_digest": proposal["proposal_digest"],
            },
        )
        assert decision.status_code == 200
        approval = decision.json()["approval"]
        assert approval is not None

        run_body = {
            "proposal_id": proposal["id"],
            "approval_id": approval["id"],
            "envelope": compiled.json(),
            "route": routed.json(),
        }
        result = await client.post(
            "/v1/creator/live/runs",
            headers=auth,
            json=run_body,
        )
        assert result.status_code == 200
        payload = result.json()
        assert payload["model_call_observed"] is True
        assert payload["tools_observed"] is False
        assert payload["completion_claim_allowed"] is False
        assert payload["execution_connected"] is False
        assert payload["estimated_actual_cost_usd"] <= payload["reserved_cost_usd"]
        assert provider.calls == 1

        replay = await client.post(
            "/v1/creator/live/runs",
            headers=auth,
            json=run_body,
        )
        assert replay.status_code == 409
        assert provider.calls == 1

        stored = await client.get(
            f"/v1/creator/live/results/{proposal['id']}",
            headers=auth,
        )
        assert stored.status_code == 200
        assert stored.json()["proposal_digest"] == proposal["proposal_digest"]
