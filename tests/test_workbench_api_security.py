from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from liltweak.api import create_app
from liltweak.config import Settings
from liltweak.workbench_api import mount_workbench
from liltweak.workbench_contract import (
    EvidenceKind,
    TaskImport,
    WorkbenchState,
    WorkbenchTask,
)
from liltweak.workbench_store import WorkbenchStore


def settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="development",
        database_path=tmp_path / "data.db",
        dev_api_key="owner-secret",
        auth_disabled=False,
        model="gpt-5.6-luna",
        monthly_budget_usd=10,
        job_hard_limit_usd=1,
    )


def test_owner_session_cookie_and_csrf_fail_closed(tmp_path: Path) -> None:
    app = FastAPI()
    mount_workbench(
        app,
        controller=object(),  # Login and dependency checks do not call the controller.
        settings=settings(tmp_path),
        session_signing_key=b"s" * 32,
    )
    client = TestClient(app)
    assert client.get("/v1/workbench/session").status_code == 401
    assert client.post("/v1/workbench/session", json={"owner_key": "wrong"}).status_code == 401

    login = client.post("/v1/workbench/session", json={"owner_key": "owner-secret"})
    assert login.status_code == 200
    cookie = login.headers["set-cookie"].casefold()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "owner-secret" not in login.text

    secure_client = TestClient(app, base_url="https://testserver")
    secure_login = secure_client.post("/v1/workbench/session", json={"owner_key": "owner-secret"})
    assert secure_login.status_code == 200
    assert "secure" in secure_login.headers["set-cookie"].casefold()

    no_csrf = client.post("/v1/workbench/emergency-stop", json={})
    assert no_csrf.status_code == 403


def test_rate_limit_and_event_stream_are_real_backend_actions(tmp_path: Path) -> None:
    configured = replace(settings(tmp_path), workbench_rate_limit_per_minute=10)
    store = WorkbenchStore(tmp_path / "events.db")
    imported = TaskImport(
        title="events",
        direction="observe events",
        source_snapshot_digest="a" * 64,
    )
    task = WorkbenchTask(
        id="task:events",
        imported=imported,
        task_digest=imported.task_digest,
        state=WorkbenchState.RECEIVED,
    )
    store.create_task(task)
    store.append_evidence(
        task.id,
        kind=EvidenceKind.TASK,
        event_type="task_received",
        payload={"task_digest": task.task_digest},
    )
    app = FastAPI()
    mount_workbench(
        app,
        controller=SimpleNamespace(store=store),
        settings=configured,
        session_signing_key=b"s" * 32,
    )
    client = TestClient(app)
    assert (
        client.post("/v1/workbench/session", json={"owner_key": "owner-secret"}).status_code == 200
    )
    stream = client.get("/v1/workbench/tasks/task:events/events?once=true")
    assert stream.status_code == 200
    assert stream.headers["content-type"].startswith("text/event-stream")
    assert "event: task_received" in stream.text
    for _ in range(9):
        assert client.get("/v1/workbench/session").status_code == 200
    assert client.get("/v1/workbench/session").status_code == 409


def test_bodyless_workbench_actions_reach_csrf_and_controller(tmp_path: Path) -> None:
    configured = replace(
        settings(tmp_path),
        workbench_enabled=True,
        workspace_root=tmp_path / "repositories",
        artifact_root=tmp_path / "artifacts",
        execution_runtime_root=tmp_path / "runtime-root",
        workbench_workspace_root=tmp_path / "workbench-tasks",
    )
    client = TestClient(create_app(settings=configured))
    login = client.post("/v1/workbench/session", json={"owner_key": "owner-secret"})
    assert login.status_code == 200

    assert client.post("/v1/workbench/emergency-stop").status_code == 403
    stopped = client.post(
        "/v1/workbench/emergency-stop",
        headers={"X-CSRF-Token": login.json()["csrf_token"]},
    )
    assert stopped.status_code == 200
    assert stopped.json() == {"emergency_stopped": True, "canceled_tasks": []}


def test_emergency_reset_requires_fresh_owner_reauthentication(tmp_path: Path) -> None:
    configured = replace(
        settings(tmp_path),
        workbench_enabled=True,
        workspace_root=tmp_path / "repositories",
        artifact_root=tmp_path / "artifacts",
        execution_runtime_root=tmp_path / "runtime-root",
        workbench_workspace_root=tmp_path / "workbench-tasks",
    )
    client = TestClient(create_app(settings=configured))
    login = client.post("/v1/workbench/session", json={"owner_key": "owner-secret"})
    csrf = login.json()["csrf_token"]
    headers = {"X-CSRF-Token": csrf}
    assert client.post("/v1/workbench/emergency-stop", headers=headers).status_code == 200

    denied = client.post(
        "/v1/workbench/emergency-stop/reset",
        headers=headers,
        json={"owner_key": "wrong"},
    )
    assert denied.status_code == 401
    assert client.get("/v1/workbench/health").json()["emergency_stopped"] is True

    reset = client.post(
        "/v1/workbench/emergency-stop/reset",
        headers=headers,
        json={"owner_key": "owner-secret"},
    )
    assert reset.status_code == 200
    assert reset.json() == {"emergency_stopped": False, "canceled_tasks": []}
    assert client.get("/v1/workbench/health").json()["emergency_stopped"] is False
