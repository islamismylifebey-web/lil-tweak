from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

import main as runtime
from liltweak.agent import DeterministicPlanner, OpenAIPlanner
from liltweak.api import build_default_service, create_app
from liltweak.config import Settings
from liltweak.reasoning_policy import FoundationModel, ReasoningProfileUnavailable


def configured_settings(tmp_path: Path, *, intent_enabled: bool = False) -> Settings:
    return Settings(
        environment="test",
        database_path=tmp_path / "runtime-model-policy.db",
        dev_api_key=None,
        auth_disabled=True,
        model=FoundationModel.SOL.value,
        monthly_budget_usd=10,
        job_hard_limit_usd=1,
        creator_signing_key=b"C" * 32,
        live_model_enabled=intent_enabled,
    )


def test_live_smoke_defaults_to_primary_and_rejects_luna(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LILTWEAK_MODEL", raising=False)
    assert runtime._live_smoke_model_id() == FoundationModel.SOL.value

    monkeypatch.setenv("LILTWEAK_MODEL", FoundationModel.LUNA.value)
    with pytest.raises(ReasoningProfileUnavailable, match="canonical primary"):
        runtime._live_smoke_model_id()


def test_openai_planner_rejects_non_primary_engineering_model() -> None:
    planner = OpenAIPlanner(FoundationModel.SOL.value)
    assert planner.model_id == FoundationModel.SOL.value
    reasoning = planner._agent.model_settings.reasoning
    assert reasoning is not None
    assert reasoning.mode == "standard"
    assert reasoning.effort == "high"
    assert reasoning.context == "all_turns"
    assert reasoning.summary == "auto"
    assert planner._agent.tools == []
    assert planner._agent.handoffs == []
    with pytest.raises(ReasoningProfileUnavailable, match="canonical primary"):
        OpenAIPlanner(FoundationModel.TERRA.value)


def test_default_service_is_offline_even_with_model_intent(tmp_path: Path) -> None:
    service = build_default_service(configured_settings(tmp_path, intent_enabled=True))
    assert isinstance(service.planner, DeterministicPlanner)
    assert service.planner.paid_provider is False


@pytest.mark.asyncio
async def test_environment_intent_cannot_auto_connect_legacy_creator(
    tmp_path: Path,
) -> None:
    app = create_app(settings=configured_settings(tmp_path, intent_enabled=True))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        health = await client.get("/v1/creator/health")
        assert health.status_code == 200
        assert health.json()["model_calls_enabled"] is False

        compiled = await client.post(
            "/v1/creator/compile",
            json={"direction": "Build a typed API and deterministic regression tests."},
        )
        routed = await client.post(
            "/v1/creator/route",
            json={"envelope": compiled.json()},
        )
        response = await client.post(
            "/v1/creator/live/proposals",
            json={"envelope": compiled.json(), "route": routed.json()},
        )
        assert response.status_code == 503
        assert response.json() == {"detail": "durable live Creator controls are not configured"}
