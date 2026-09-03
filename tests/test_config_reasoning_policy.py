from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from liltweak.config import Settings


def settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        database_path=tmp_path / "data.db",
        dev_api_key=None,
        auth_disabled=True,
        model="gpt-5.6-sol",
        monthly_budget_usd=10,
        job_hard_limit_usd=1,
    )


def test_engineering_defaults_are_sol_standard_high_ordinary(tmp_path: Path) -> None:
    configured = settings(tmp_path)

    assert configured.model == "gpt-5.6-sol"
    assert configured.workbench_model == "gpt-5.6-sol"
    assert configured.workbench_reasoning_profile == "ordinary"
    assert configured.workbench_reasoning_mode == "standard"
    assert configured.workbench_reasoning_tier == "high"
    assert configured.workbench_input_token_limit == 144_000
    assert configured.workbench_output_token_limit == 25_772
    assert configured.workbench_cost_ceiling_usd == 1.50


def test_environment_loads_workbench_token_capacity_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("LILTWEAK_WORKBENCH_INPUT_TOKEN_LIMIT", raising=False)
    monkeypatch.delenv("LILTWEAK_WORKBENCH_OUTPUT_TOKEN_LIMIT", raising=False)

    configured = Settings.from_env()

    assert configured.workbench_input_token_limit == 144_000
    assert configured.workbench_output_token_limit == 25_772


def test_requested_workbench_token_capacity_is_accepted(tmp_path: Path) -> None:
    configured = replace(
        settings(tmp_path),
        workbench_input_token_limit=144_000,
        workbench_output_token_limit=25_772,
    )

    assert configured.workbench_input_token_limit == 144_000
    assert configured.workbench_output_token_limit == 25_772


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    (
        ("workbench_input_token_limit", 200_001, "INPUT_TOKEN_LIMIT"),
        ("workbench_output_token_limit", 32_001, "OUTPUT_TOKEN_LIMIT"),
    ),
)
def test_workbench_token_absolute_maximums_remain_enforced(
    tmp_path: Path,
    field_name: str,
    value: int,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        replace(settings(tmp_path), **{field_name: value})


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    (
        ("workbench_input_token_limit", 255, "INPUT_TOKEN_LIMIT"),
        ("workbench_output_token_limit", 1_023, "OUTPUT_TOKEN_LIMIT"),
    ),
)
def test_workbench_token_minimums_remain_enforced(
    tmp_path: Path,
    field_name: str,
    value: int,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        replace(settings(tmp_path), **{field_name: value})


def test_token_capacity_change_preserves_unrelated_workbench_defaults(tmp_path: Path) -> None:
    configured = settings(tmp_path)

    assert configured.workbench_model_enabled is False
    assert configured.workbench_model == "gpt-5.6-sol"
    assert configured.workbench_reasoning_profile == "ordinary"
    assert configured.workbench_reasoning_mode == "standard"
    assert configured.workbench_reasoning_tier == "high"
    assert configured.workbench_cost_ceiling_usd == 1.50
    assert configured.workbench_monthly_limit_usd == 5.0
    assert configured.workbench_runner_enabled is False
    assert configured.repository_execution_enabled is False


def test_named_reasoning_profile_prevents_scattered_model_mode_drift(tmp_path: Path) -> None:
    configured = settings(tmp_path)

    with pytest.raises(ValueError, match="must match"):
        replace(configured, workbench_model="gpt-5.6-terra")
    with pytest.raises(ValueError, match="must match"):
        replace(configured, workbench_reasoning_tier="max")
    apex = replace(
        configured,
        workbench_reasoning_profile="apex",
        workbench_reasoning_mode="pro",
        workbench_reasoning_tier="max",
    )
    assert apex.workbench_model == "gpt-5.6-sol"
    assert apex.workbench_reasoning_profile == "apex"


def test_environment_rejects_non_primary_engineering_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LILTWEAK_MODEL", "gpt-5.6-luna")
    with pytest.raises(ValueError, match="canonical primary"):
        Settings.from_env()


def test_galor_runner_activation_requires_complete_server_configuration(tmp_path: Path) -> None:
    configured = settings(tmp_path)
    with pytest.raises(ValueError, match="AUTH_TOKEN"):
        replace(
            configured,
            workbench_runner_enabled=True,
            workbench_runner_gateway_url="https://galor.invalid/runner",
            workbench_runner_contract_json="{}",
            workbench_runner_expected_contract_digest="a" * 64,
            workbench_runner_qualification_digest="b" * 64,
            workbench_runner_authorization_digest="c" * 64,
            workbench_runner_signing_keys_json='{"key":"value"}',
        )
