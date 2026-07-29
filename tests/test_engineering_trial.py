from __future__ import annotations

import pytest

from evals.run_engineering_trial import load_cases, run_offline
from liltweak.engineering_model import EngineeringModelError, TweakEngineeringModel


def test_hidden_expectations_never_enter_packet() -> None:
    for packet, expectations in load_cases():
        serialized = packet.model_dump_json()
        assert "expectations" not in serialized
        assert expectations.mechanism not in serialized


def test_offline_trial_rejects_generic_baseline_without_model_calls() -> None:
    result = run_offline(load_cases())
    assert result["passed"]
    assert result["call_count"] == 0
    assert result["case_count"] == 3
    assert all(item["baseline_rejected"] for item in result["cases"])


def test_engineering_model_has_no_tools_or_handoffs() -> None:
    model = TweakEngineeringModel("test-model")
    assert model.identity == "lil-tweak-engineering-v1"
    assert model.foundation_model_id == "test-model"
    assert model._agent.tools == []
    assert model._agent.handoffs == []
    assert model.call_count == 0


@pytest.mark.asyncio
async def test_provider_failure_is_one_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model = TweakEngineeringModel("test-model")
    packet, _expectations = load_cases()[0]

    async def fail(*_args, **_kwargs):
        raise RuntimeError("provider detail that must not escape")

    monkeypatch.setattr("liltweak.engineering_model.Runner.run", fail)
    with pytest.raises(EngineeringModelError, match="unavailable"):
        await model.reason(packet)
    assert model.call_count == 1
