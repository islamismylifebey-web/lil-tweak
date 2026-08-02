from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from liltweak.api import create_app
from liltweak.config import Settings
from liltweak.planning_chat import (
    PlanningChatError,
    PlanningChatService,
    PlanningConversationCreate,
    PlanningConversationStore,
    PlanningModelOutput,
    PlanningTurnRequest,
)
from liltweak.project_workspace import (
    AttachmentCreate,
    ProjectCreate,
    ProjectUpdate,
    ProjectWorkspaceStore,
    new_board_item,
    new_milestone,
    new_note,
    new_requirement,
)
from liltweak.reasoning_contract import ReasoningRole
from liltweak.reasoning_policy import FoundationModel, ReasoningProfileName
from liltweak.reasoning_provider import (
    ProviderCallEvidence,
    ProviderCallResult,
    ProviderFailureKind,
    ReasoningProviderError,
)


class FakePlanningProvider:
    def __init__(self, failure: ProviderFailureKind | None = None) -> None:
        self.failure = failure
        self.calls: list[ReasoningProfileName] = []

    def profile_is_qualified(self, profile_name: ReasoningProfileName) -> bool:
        return profile_name in {
            ReasoningProfileName.ORDINARY,
            ReasoningProfileName.TERRA_DEGRADED_READ_ONLY,
        }

    async def call(self, **values: object) -> ProviderCallResult:
        profile = values["profile_name"]
        assert isinstance(profile, ReasoningProfileName)
        self.calls.append(profile)
        if profile == ReasoningProfileName.ORDINARY and self.failure is not None:
            raise ReasoningProviderError(self.failure, "synthetic provider failure")
        model = (
            FoundationModel.TERRA.value
            if profile == ReasoningProfileName.TERRA_DEGRADED_READ_ONLY
            else FoundationModel.SOL.value
        )
        instructions = values["instructions"]
        input_text = values["input_text"]
        assert isinstance(instructions, str)
        assert isinstance(input_text, str)
        output = PlanningModelOutput(
            answer="Use one bounded milestone.",
            conversation_summary="The owner is planning one bounded milestone.",
            stable_facts=("Execution remains disconnected.",),
        )
        evidence = ProviderCallEvidence(
            call_id=str(values["call_id"]),
            role=ReasoningRole.PLANNER,
            profile_name=profile,
            profile_version="1.0.0",
            requested_model=model,
            effective_model=model,
            request_mode="standard",
            reasoning_effort="high",
            prompt_digest=hashlib.sha256(instructions.encode()).hexdigest(),
            input_digest=hashlib.sha256(input_text.encode()).hexdigest(),
            provider_input_digest=hashlib.sha256(input_text.encode()).hexdigest(),
            response_id_digest="a" * 64,
            output_item_digests=("b" * 64,),
            parsed_output_digest=hashlib.sha256(output.model_dump_json().encode()).hexdigest(),
            provider_counted_input_tokens=100,
            input_tokens=100,
            cached_input_tokens=20,
            output_tokens=30,
            reasoning_tokens=10,
            total_tokens=130,
            store_disabled=True,
            sensitive_tracing_disabled=True,
            tools_supplied=False,
            continuation_items_preserved=False,
            status="completed",
        )
        return ProviderCallResult(output=output, evidence=evidence, replay_items=())


def settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        database_path=tmp_path / "liltweak.db",
        dev_api_key="owner-secret",
        auth_disabled=False,
        model="gpt-5.6-sol",
        monthly_budget_usd=10,
        job_hard_limit_usd=1,
        workbench_enabled=True,
        workbench_workspace_root=tmp_path / "tasks",
    )


def test_project_workspace_is_complete_and_zero_token(tmp_path: Path) -> None:
    store = ProjectWorkspaceStore(tmp_path / "workspace.db")
    created = store.create(ProjectCreate(name="Private agent", description="Local only"))
    updated = store.update(
        created.id,
        ProjectUpdate(
            name=created.name,
            description=created.description,
            status="active",
            requirements=(new_requirement("No public deployment"),),
            milestones=(new_milestone("Local acceptance", target_date="2026-08-03"),),
            board=(new_board_item("Qualify browser", detail="Use real Chromium"),),
            notes=(new_note("Runner remains disconnected."),),
        ),
    )
    content = b"bounded attachment"
    attached = store.attach(
        created.id,
        AttachmentCreate(
            filename="requirements.txt",
            media_type="text/plain",
            content_base64=base64.b64encode(content).decode(),
        ),
    )
    assert updated.model_call == "NO MODEL CALL"
    assert attached.model_tokens == 0
    assert attached.attachments[0].sha256 == hashlib.sha256(content).hexdigest()
    assert store.list(query="browser", status="active") == (attached,)
    exported = store.export(created.id)
    imported = store.import_project(exported)
    assert imported.id != created.id
    assert imported.attachments == attached.attachments
    assert store.export(imported.id).attachment_content == exported.attachment_content


@pytest.mark.asyncio
async def test_planning_chat_records_model_usage_and_never_grants_tools(tmp_path: Path) -> None:
    provider = FakePlanningProvider()
    service = PlanningChatService(
        provider=provider,
        store=PlanningConversationStore(tmp_path / "planning.db"),
    )
    assert service.output_token_ceiling == 1_024
    assert service.timeout_seconds == 60
    conversation = service.store.create(PlanningConversationCreate(title="Activation"))
    result = await service.turn(conversation.id, PlanningTurnRequest(message="Plan one step."))
    assert provider.calls == [ReasoningProfileName.ORDINARY]
    assert result.current_model == FoundationModel.SOL.value
    assert result.reasoning_effort == "high"
    assert result.tool_authority == "NONE"
    assert result.execution == "DISCONNECTED"
    assert result.usage.input_tokens == 100
    assert result.usage.cached_input_tokens == 20
    assert result.usage.estimated_cost_usd > 0
    assert result.conversation.messages[-1].role == "assistant"
    records = service.store.list_usage(conversation.id)
    assert len(records) == 1
    assert records[0].current_model == FoundationModel.SOL.value
    assert records[0].usage == result.usage
    assert records[0].response_id_digest == "a" * 64


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [ProviderFailureKind.RATE_LIMIT, ProviderFailureKind.TIMEOUT, ProviderFailureKind.SERVICE],
)
async def test_planning_fallback_is_limited_to_transient_failures(
    tmp_path: Path, failure: ProviderFailureKind
) -> None:
    provider = FakePlanningProvider(failure)
    service = PlanningChatService(
        provider=provider,
        store=PlanningConversationStore(tmp_path / "planning.db"),
    )
    conversation = service.store.create(PlanningConversationCreate(title="Fallback"))
    result = await service.turn(conversation.id, PlanningTurnRequest(message="Continue safely."))
    assert provider.calls == [
        ReasoningProfileName.ORDINARY,
        ReasoningProfileName.TERRA_DEGRADED_READ_ONLY,
    ]
    assert result.fallback_used is True
    assert result.fallback_reason == failure.value
    assert result.current_model == FoundationModel.TERRA.value


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        ProviderFailureKind.AUTHENTICATION,
        ProviderFailureKind.QUOTA,
        ProviderFailureKind.INVALID_REQUEST,
        ProviderFailureKind.BLOCKED_PROFILE,
        ProviderFailureKind.ENTITLEMENT,
    ],
)
async def test_planning_never_falls_back_for_policy_or_account_failures(
    tmp_path: Path, failure: ProviderFailureKind
) -> None:
    provider = FakePlanningProvider(failure)
    service = PlanningChatService(
        provider=provider,
        store=PlanningConversationStore(tmp_path / "planning.db"),
    )
    conversation = service.store.create(PlanningConversationCreate(title="No fallback"))
    with pytest.raises(PlanningChatError):
        await service.turn(conversation.id, PlanningTurnRequest(message="Do not mask failure."))
    assert provider.calls == [ReasoningProfileName.ORDINARY]


def test_authenticated_project_api_and_operational_states(tmp_path: Path) -> None:
    provider = FakePlanningProvider()
    planning = PlanningChatService(
        provider=provider,
        store=PlanningConversationStore(tmp_path / "planning.db"),
    )
    app = create_app(
        settings=settings(tmp_path),
        planning_chat_service=planning,
        project_workspace_store=ProjectWorkspaceStore(tmp_path / "projects.db"),
    )
    client = TestClient(app)
    login = client.post("/v1/workbench/session", json={"owner_key": "owner-secret"})
    assert login.status_code == 200
    csrf = login.json()["csrf_token"]
    created = client.post(
        "/v1/workbench/projects",
        json={"name": "Local project", "description": "Zero token workspace"},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201
    assert created.json()["model_call"] == "NO MODEL CALL"
    assert created.json()["model_tokens"] == 0
    project_id = created.json()["id"]
    updated = client.put(
        f"/v1/workbench/projects/{project_id}",
        json={
            "name": "Local project",
            "description": "Zero token workspace",
            "status": "active",
            "requirements": [
                {
                    "id": "requirement:" + "a" * 32,
                    "text": "Browser-compatible JSON array",
                    "status": "active",
                }
            ],
            "milestones": [],
            "board": [],
            "notes": [
                {
                    "id": "note:" + "b" * 32,
                    "text": "Browser-compatible timestamp",
                    "created_at": "2026-08-02T21:00:00.000Z",
                }
            ],
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert updated.status_code == 200
    assert updated.json()["requirements"][0]["text"] == "Browser-compatible JSON array"
    assert updated.json()["notes"][0]["text"] == "Browser-compatible timestamp"
    status = client.get("/v1/workbench/operational-status").json()
    assert status["backend"]["state"] == "CONNECTED"
    assert status["runner"]["state"] == "DISCONNECTED"
    assert status["execution"]["state"] == "DISCONNECTED"
    assert status["browser"]["state"] == "DISCONNECTED"
    page = client.get("/workbench")
    assert "Project Workspace" in page.text
    assert "NO MODEL CALL · ZERO TOKENS" in page.text
    assert "Planning Chat" in page.text
    assert "Engineering Mode" in page.text


def test_planning_conversation_timestamp_is_utc(tmp_path: Path) -> None:
    store = PlanningConversationStore(tmp_path / "planning.db")
    conversation = store.create(PlanningConversationCreate(title="Timestamp"))
    assert conversation.created_at.tzinfo == UTC
    assert conversation.created_at <= datetime.now(UTC)
