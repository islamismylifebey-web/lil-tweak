from __future__ import annotations

import json
import stat
from pathlib import Path, PureWindowsPath

import pytest
from fastapi.testclient import TestClient

from liltweak.api import create_app
from liltweak.config import Settings
from liltweak.creator import CreatorService
from liltweak.store import SQLiteStore
from liltweak.workbench import WorkbenchController, WorkbenchError
from liltweak.workbench_agent import ModelPlanResult
from liltweak.workbench_contract import (
    CommandRequest,
    StepPhase,
    TaskImport,
    ToolKind,
    ToolRequest,
    WorkbenchPlan,
    WorkbenchState,
)
from liltweak.workbench_executor import (
    BoundedToolExecutor,
    DisconnectedProcessTransport,
    TaskWorkspaceManager,
)
from liltweak.workbench_policy import ToolPolicyBroker
from liltweak.workbench_repository import WorkbenchRepositoryRegistry
from liltweak.workbench_store import WorkbenchStore
from tests.repository_helpers import initialize_repository

REPOSITORY_ID = "local:fixture"


class CapturingModel:
    connected = True
    provider_name = "capturing-fake"
    model_name = "capturing-fake-model"
    reasoning_tier = "high"

    def __init__(self) -> None:
        self.inspection_summaries: list[str] = []

    async def plan(
        self,
        *,
        task: TaskImport,
        inspection_summary: str,
        **_: object,
    ) -> ModelPlanResult:
        self.inspection_summaries.append(inspection_summary)
        plan = WorkbenchPlan(
            summary="Run bounded repository checks.",
            reasoning="Test the imported source and independently verify its formatting.",
            source_snapshot_digest=task.source_snapshot_digest,
            steps=(
                ToolRequest(
                    tool_id="test-1",
                    kind=ToolKind.COMMAND,
                    phase=StepPhase.TEST,
                    purpose="test",
                    command=CommandRequest(executable="pytest", args=("-q",)),
                ),
                ToolRequest(
                    tool_id="verify-1",
                    kind=ToolKind.COMMAND,
                    phase=StepPhase.VERIFICATION,
                    purpose="verify",
                    command=CommandRequest(executable="ruff", args=("check", ".")),
                ),
            ),
            rollback_steps=("Restore the recovery snapshot.",),
        )
        return ModelPlanResult(
            plan,
            self.provider_name,
            self.model_name,
            self.reasoning_tier,
            None,
            10,
            20,
        )


def _controller(
    tmp_path: Path,
) -> tuple[WorkbenchController, CapturingModel, Path, WorkbenchRepositoryRegistry]:
    source_root = tmp_path / "registered"
    source_root.mkdir()
    repository, _head = initialize_repository(source_root)
    registry = WorkbenchRepositoryRegistry(
        source_root,
        {REPOSITORY_ID: repository.name},
    )
    workspaces = TaskWorkspaceManager(tmp_path / "workbench-tasks")
    model = CapturingModel()
    database = tmp_path / "controller.db"
    creator = CreatorService(
        store=SQLiteStore(database),
        signing_key=b"c" * 32,
        durable_signatures=True,
    )
    control = WorkbenchController(
        creator=creator,
        store=WorkbenchStore(database),
        model=model,
        executor=BoundedToolExecutor(workspaces, DisconnectedProcessTransport()),
        workspaces=workspaces,
        policy=ToolPolicyBroker(),
        owner_id="owner",
        authorized_repositories=frozenset({REPOSITORY_ID}),
        repository_registry=registry,
    )
    return control, model, repository, registry


def _git_free_tree(root: Path) -> dict[str, tuple[str, bytes, bool]]:
    payload: dict[str, tuple[str, bytes, bool]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        if path.is_dir():
            payload[relative.as_posix()] = ("directory", b"", False)
        else:
            metadata = path.lstat()
            payload[relative.as_posix()] = (
                "file",
                path.read_bytes(),
                bool(metadata.st_mode & stat.S_IXUSR),
            )
    return payload


def _all_strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _all_strings(key)
            yield from _all_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _all_strings(item)


def _assert_no_absolute_paths(response) -> None:
    for value in _all_strings(response.json()):
        assert not Path(value).is_absolute(), value
        assert not PureWindowsPath(value).is_absolute(), value


def test_controller_binds_and_materializes_the_exact_registered_source(
    tmp_path: Path,
) -> None:
    control, _model, repository, registry = _controller(tmp_path)
    (repository / "owner-note.txt").write_text("untracked owner work\n", encoding="utf-8")
    expected_tree = _git_free_tree(repository)
    expected_inspection = registry.inspect(
        REPOSITORY_ID,
        direction="Inspect the FastAPI app and its tests.",
    )

    task = control.receive_repository_task(
        repository_id=REPOSITORY_ID,
        title="Inspect fixture",
        direction="Inspect the FastAPI app and its tests.",
    )

    task_root = control.workspaces.task_root(task.id)
    assert task.imported.repository_id == REPOSITORY_ID
    assert task.imported.repository_fingerprint == expected_inspection.source_fingerprint
    assert task.imported.source_snapshot_digest == control.workspaces.tree_digest(task_root)
    assert len(task.imported.repository_fingerprint) == 64
    assert len(task.imported.source_snapshot_digest) == 64
    assert _git_free_tree(task_root) == expected_tree
    assert not (task_root / ".git").exists()
    receipt = control.store.list_evidence(task.id)[0]
    assert receipt.payload["repository_fingerprint"] == expected_inspection.source_fingerprint
    assert receipt.payload["source_snapshot_digest"] == task.imported.source_snapshot_digest


@pytest.mark.parametrize("boundary", ["inspect", "analyze"])
@pytest.mark.asyncio
async def test_repository_change_before_inspection_or_analysis_fails_closed(
    tmp_path: Path,
    boundary: str,
) -> None:
    control, model, repository, _registry = _controller(tmp_path)
    task = control.receive_repository_task(
        repository_id=REPOSITORY_ID,
        title="Bound source",
        direction="Inspect the FastAPI app and its tests.",
    )
    if boundary == "analyze":
        assert control.inspect(task.id).state == WorkbenchState.ANALYZED

    (repository / "src" / "app.py").write_text(
        "from fastapi import FastAPI\n\napp = FastAPI(title='changed')\n",
        encoding="utf-8",
    )

    with pytest.raises(WorkbenchError, match="registered repository changed"):
        if boundary == "inspect":
            control.inspect(task.id)
        else:
            await control.analyze(task.id)

    current = control.store.get_task(task.id)
    assert current.state == (
        WorkbenchState.BLOCKED if boundary == "inspect" else WorkbenchState.ANALYZED
    )
    assert current.plan is None
    assert model.inspection_summaries == []


@pytest.mark.asyncio
async def test_planning_model_receives_relative_source_paths_and_screened_excerpts(
    tmp_path: Path,
) -> None:
    control, model, repository, _registry = _controller(tmp_path)
    task = control.receive_repository_task(
        repository_id=REPOSITORY_ID,
        title="Plan fixture repair",
        direction="Inspect the FastAPI app initialization and its tests.",
    )
    assert control.inspect(task.id).state == WorkbenchState.ANALYZED

    planned, _approval = await control.analyze(task.id)

    assert planned.state == WorkbenchState.AWAITING_APPROVAL
    assert len(model.inspection_summaries) == 1
    context = json.loads(model.inspection_summaries[0])
    assert context["file_count"] >= 1
    assert any(item["path"] == "src/app.py" for item in context["files"])
    app_excerpt = next(item for item in context["excerpts"] if item["path"] == "src/app.py")
    assert "FastAPI" in app_excerpt["text"]
    assert str(repository.resolve()) not in model.inspection_summaries[0]
    assert all(not Path(item["path"]).is_absolute() for item in context["files"])


def test_repository_api_routes_require_owner_session_csrf_and_hide_host_paths(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "registered"
    source_root.mkdir()
    repository, _head = initialize_repository(source_root)
    workbench_root = tmp_path / "workbench-tasks"
    configured = Settings(
        environment="development",
        database_path=tmp_path / "api.db",
        dev_api_key="owner-secret",
        auth_disabled=False,
        model="test-model",
        monthly_budget_usd=10,
        job_hard_limit_usd=1,
        workspace_root=source_root,
        repository_mappings={REPOSITORY_ID: repository.name},
        artifact_root=tmp_path / "artifacts",
        execution_runtime_root=tmp_path / "runtime-root",
        workbench_enabled=True,
        workbench_workspace_root=workbench_root,
    )
    client = TestClient(create_app(settings=configured))
    inspection_body = {"direction": "Inspect the FastAPI app and its tests."}
    task_body = {
        "title": "Inspect fixture",
        "direction": "Inspect the FastAPI app and its tests.",
    }

    assert client.get("/v1/workbench/repositories").status_code == 401
    assert (
        client.post(
            f"/v1/workbench/repositories/{REPOSITORY_ID}/inspect",
            json=inspection_body,
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/v1/workbench/repositories/{REPOSITORY_ID}/tasks",
            json=task_body,
        ).status_code
        == 403
    )

    login = client.post("/v1/workbench/session", json={"owner_key": "owner-secret"})
    assert login.status_code == 200
    csrf = login.json()["csrf_token"]

    repository_list = client.get("/v1/workbench/repositories")
    assert repository_list.status_code == 200
    assert repository_list.json() == {"repository_ids": [REPOSITORY_ID]}
    assert (
        client.post(
            f"/v1/workbench/repositories/{REPOSITORY_ID}/inspect",
            json=inspection_body,
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/v1/workbench/repositories/{REPOSITORY_ID}/tasks",
            json=task_body,
        ).status_code
        == 403
    )

    headers = {"X-CSRF-Token": csrf}
    legacy_import = client.post(
        "/v1/workbench/tasks",
        json={
            "title": "caller-controlled import",
            "direction": "bypass repository onboarding",
            "source_snapshot_digest": "a" * 64,
        },
        headers=headers,
    )
    assert legacy_import.status_code == 405
    inspection = client.post(
        f"/v1/workbench/repositories/{REPOSITORY_ID}/inspect",
        json=inspection_body,
        headers=headers,
    )
    assert inspection.status_code == 200
    assert inspection.json()["repository_id"] == REPOSITORY_ID
    secret_rejected = client.post(
        f"/v1/workbench/repositories/{REPOSITORY_ID}/tasks",
        json={
            "title": "sk-proj-" + "Q" * 32,
            "direction": "Inspect the FastAPI app and its tests.",
        },
        headers=headers,
    )
    assert secret_rejected.status_code == 409
    assert client.get("/v1/workbench/tasks").json() == []
    created = client.post(
        f"/v1/workbench/repositories/{REPOSITORY_ID}/tasks",
        json=task_body,
        headers=headers,
    )
    assert created.status_code == 202
    assert created.json()["imported"]["repository_id"] == REPOSITORY_ID

    for response in (repository_list, inspection, created):
        _assert_no_absolute_paths(response)
        assert str(tmp_path.resolve()) not in response.text
