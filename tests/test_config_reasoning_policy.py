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
