from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from liltweak.api import create_app
from liltweak.config import Settings
from liltweak.workbench_contract import (
    CapabilityState,
    CapabilityStatus,
    WorkbenchCapability,
    default_workbench_capabilities,
)


def enabled_settings(tmp_path: Path) -> Settings:
    return replace(
        Settings(
            environment="development",
            database_path=tmp_path / "data.db",
            dev_api_key="owner-secret",
            auth_disabled=False,
            model="gpt-5.6-luna",
            monthly_budget_usd=10,
            job_hard_limit_usd=1,
        ),
        workbench_enabled=True,
        workspace_root=tmp_path / "repositories",
        artifact_root=tmp_path / "artifacts",
        execution_runtime_root=tmp_path / "runtime-root",
        workbench_workspace_root=tmp_path / "workbench-tasks",
    )


def test_capability_contract_defaults_every_gate_to_blocked() -> None:
    statuses = default_workbench_capabilities()
    assert tuple(item.capability for item in statuses) == tuple(WorkbenchCapability)
    assert all(item.state == CapabilityState.BLOCKED for item in statuses)
    assert all(item.operational is False for item in statuses)
    assert all(item.blockers for item in statuses)

    with pytest.raises(ValidationError, match="requires every gate"):
        CapabilityStatus(
            capability=WorkbenchCapability.MODEL,
            state=CapabilityState.OPERATIONAL,
            operational=True,
            blockers=(),
        )


def test_private_health_reports_independent_exact_capability_blockers(
    tmp_path: Path,
) -> None:
    client = TestClient(
        create_app(settings=enabled_settings(tmp_path)),
        base_url="http://127.0.0.1",
    )
    login = client.post("/v1/workbench/session", json={"owner_key": "owner-secret"})
    assert login.status_code == 200

    response = client.get("/v1/workbench/health")
    assert response.status_code == 200
    payload = response.json()
    statuses = {item["capability"]: item for item in payload["capabilities"]}
    assert tuple(statuses) == tuple(capability.value for capability in WorkbenchCapability)
    assert all(status["state"] == "blocked" for status in statuses.values())
    assert all(status["operational"] is False for status in statuses.values())
    assert all(status["blockers"] for status in statuses.values())

    assert statuses["model"]["configured"] is False
    assert statuses["runner"]["connected"] is False
    assert "anti-rollback" in statuses["checkpoint"]["blockers"][0]
    assert "release publisher" in statuses["publisher"]["blockers"][0]
    assert "real-browser" in statuses["browser"]["blockers"][0]
    assert "disabled and deferred" in statuses["gcp"]["blockers"][0]
