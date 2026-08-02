from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from liltweak.api import create_app
from liltweak.config import Settings
from liltweak.reasoning_contract import (
    EvidenceMode,
    OutcomeStatus,
    ProviderHealthState,
    ProviderQualification,
    ProviderQualificationState,
    ProviderUsage,
    QualificationScenario,
    ReasoningRole,
)
from liltweak.reasoning_policy import ReasoningProfileName
from liltweak.reasoning_prompts import PROMPT_DEFINITIONS, PromptName
from liltweak.reasoning_provider import ProviderCallEvidence, ProviderCallResult
from liltweak.workbench_agent import CanonicalWorkbenchModelAdapter, WorkbenchModelError
from liltweak.workbench_contract import (
    CommandRequest,
    StepPhase,
    TaskImport,
    ToolKind,
    ToolRequest,
    WorkbenchPlan,
)

SHA = "a" * 64
SECRET = "sk-proj-" + "Q" * 32


def plan() -> WorkbenchPlan:
    return WorkbenchPlan(
        summary="Bounded canonical Workbench plan",
        reasoning="Request a test and an independent verification command.",
        source_snapshot_digest=SHA,
        steps=(
            ToolRequest(
                tool_id="test-1",
                kind=ToolKind.COMMAND,
                phase=StepPhase.TEST,
                purpose="Run focused tests",
                command=CommandRequest(executable="pytest", args=("-q",)),
            ),
            ToolRequest(
                tool_id="verify-1",
                kind=ToolKind.COMMAND,
                phase=StepPhase.VERIFICATION,
                purpose="Run independent static verification",
                command=CommandRequest(executable="ruff", args=("check", ".")),
            ),
        ),
        rollback_steps=("Restore the recovery snapshot.",),
    )


def plan_digest(value: WorkbenchPlan) -> str:
    return hashlib.sha256(
        json.dumps(
            value.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def live_qualification() -> ProviderQualification:
    return ProviderQualification(
        schema_version="1.0.0",
        status=OutcomeStatus.PASSED,
        status_reasons=(),
        qualification_id="qualification:test-only-complete-live-record",
        provider="openai-responses",
        configured=True,
        connected=True,
        requested_model="gpt-5.6-sol",
        effective_model="gpt-5.6-sol",
        profile_name=ReasoningProfileName.ORDINARY.value,
        profile_version="1.0.0",
        request_mode="standard",
        reasoning_effort="high",
        health_state=ProviderHealthState.HEALTHY,
        qualification_state=ProviderQualificationState.LIVE_QUALIFIED,
        evidence_mode=EvidenceMode.LIVE,
        strict_schema_qualified=True,
        refusal_qualified=True,
        incomplete_qualified=True,
        continuation_qualified=True,
        compaction_qualified=True,
        timeout_qualified=True,
        cancellation_qualified=True,
        concurrency_qualified=True,
        usage_reconciliation_qualified=True,
        caching_telemetry_qualified=True,
        store_disabled=True,
        sensitive_tracing_disabled=True,
        approved_data_controls="Synthetic test record; never production qualification evidence.",
        scenarios=(
            QualificationScenario(
                status=OutcomeStatus.PASSED,
                status_reasons=(),
                scenario_id="test-only-complete-live-suite",
                live=True,
                response_id_digest="f" * 64,
                evidence_digest="e" * 64,
            ),
        ),
        usage=ProviderUsage(
            requests=1,
            input_tokens=200,
            cached_input_tokens=0,
            output_tokens=100,
            reasoning_tokens=25,
            total_tokens=300,
            estimated_cost_usd=0.01,
        ),
        qualified_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


class SpyAdmission:
    def __init__(self) -> None:
        self.claims: list[dict[str, object]] = []
        self.finishes: list[dict[str, object]] = []

    async def claim(self, **values: object) -> str:
        self.claims.append(values)
        return "model-admission:canonical"

    async def finish(self, **values: object) -> None:
        self.finishes.append(values)


class FakeCanonicalProvider:
    def __init__(self, *, qualified: bool = True, wrong_effort: bool = False) -> None:
        self.qualification = live_qualification() if qualified else None
        self.wrong_effort = wrong_effort
        self.calls: list[dict[str, object]] = []

    def qualification_for_profile(
        self, profile_name: ReasoningProfileName
    ) -> ProviderQualification | None:
        if profile_name == ReasoningProfileName.ORDINARY:
            return self.qualification
        return None

    async def call(self, **values: object) -> ProviderCallResult:
        self.calls.append(values)
        instructions = values["instructions"]
        input_text = values["input_text"]
        assert isinstance(instructions, str)
        assert isinstance(input_text, str)
        evidence = ProviderCallEvidence(
            call_id=str(values["call_id"]),
            role=ReasoningRole.PLANNER,
            profile_name=ReasoningProfileName.ORDINARY,
            profile_version="1.0.0",
            requested_model="gpt-5.6-sol",
            effective_model="gpt-5.6-sol",
            request_mode="standard",
            reasoning_effort="max" if self.wrong_effort else "high",
            prompt_digest=hashlib.sha256(instructions.encode()).hexdigest(),
            input_digest=hashlib.sha256(input_text.encode()).hexdigest(),
            provider_input_digest=hashlib.sha256(input_text.encode()).hexdigest(),
            response_id_digest="b" * 64,
            output_item_digests=("c" * 64,),
            parsed_output_digest=plan_digest(plan()),
            provider_counted_input_tokens=200,
            input_tokens=200,
            cached_input_tokens=0,
            output_tokens=100,
            reasoning_tokens=25,
            total_tokens=300,
            store_disabled=True,
            sensitive_tracing_disabled=True,
            tools_supplied=False,
            continuation_items_preserved=False,
            status="completed",
        )
        return ProviderCallResult(output=plan(), evidence=evidence, replay_items=())


class NameOnlyQualificationProvider(FakeCanonicalProvider):
    def profile_is_qualified(self, profile_name: ReasoningProfileName) -> bool:
        return profile_name == ReasoningProfileName.ORDINARY

    def qualification_for_profile(
        self, profile_name: ReasoningProfileName
    ) -> ProviderQualification | None:
        return None


class BlockingCanonicalProvider(FakeCanonicalProvider):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def call(self, **values: object) -> ProviderCallResult:
        self.calls.append(values)
        self.started.set()
        await self.release.wait()
        return await super().call(**values)


def imported_task(*, title: str = "Safe task") -> TaskImport:
    return TaskImport(
        title=title,
        direction="Produce the bounded plan.",
        source_snapshot_digest=SHA,
    )


@pytest.mark.asyncio
async def test_bridge_uses_canonical_prompt_profile_and_provider_evidence() -> None:
    provider = FakeCanonicalProvider()
    admission = SpyAdmission()
    adapter = CanonicalWorkbenchModelAdapter(
        provider=provider,  # type: ignore[arg-type]
        admission=admission,
    )

    result = await adapter.plan(
        task=imported_task(),
        creator_brief_digest="d" * 64,
        creator_route_digest="e" * 64,
        inspection_summary="Controller-supplied inspection evidence.",
    )

    assert result.plan == plan()
    assert result.provider == "openai-responses"
    assert result.model == "gpt-5.6-sol"
    assert result.reasoning_profile == "ordinary"
    assert result.reasoning_mode == "standard"
    assert result.reasoning_tier == "high"
    assert result.response_id is None
    assert result.response_id_hash == "b" * 64
    assert len(provider.calls) == 1
    call = provider.calls[0]
    assert call["role"] == ReasoningRole.PLANNER
    assert call["profile_name"] == ReasoningProfileName.ORDINARY
    assert call["output_type"] is WorkbenchPlan
    assert call["instructions"] == PROMPT_DEFINITIONS[PromptName.WORKBENCH_PLAN].instructions
    assert "expected_status" not in str(call["input_text"])
    assert admission.claims[0]["model"] == "gpt-5.6-sol"
    assert admission.finishes == [
        {
            "admission_id": "model-admission:canonical",
            "succeeded": True,
            "input_tokens": 200,
            "output_tokens": 100,
            "response_id_hash": "b" * 64,
        }
    ]


@pytest.mark.asyncio
async def test_unqualified_or_mismatched_bridge_fails_closed() -> None:
    unqualified_provider = FakeCanonicalProvider(qualified=False)
    admission = SpyAdmission()
    adapter = CanonicalWorkbenchModelAdapter(
        provider=unqualified_provider,  # type: ignore[arg-type]
        admission=admission,
    )
    assert adapter.connected is False
    assert adapter.qualification_verified is False
    with pytest.raises(WorkbenchModelError, match="no injected complete live qualification"):
        await adapter.plan(
            task=imported_task(),
            creator_brief_digest="d" * 64,
            creator_route_digest="e" * 64,
            inspection_summary="Safe evidence.",
        )
    assert admission.claims == []
    assert unqualified_provider.calls == []

    name_only_provider = NameOnlyQualificationProvider()
    name_only = CanonicalWorkbenchModelAdapter(
        provider=name_only_provider,  # type: ignore[arg-type]
        admission=SpyAdmission(),
    )
    assert name_only.connected is False
    assert name_only.qualification_verified is False

    mismatched_provider = FakeCanonicalProvider(wrong_effort=True)
    mismatched_admission = SpyAdmission()
    mismatched = CanonicalWorkbenchModelAdapter(
        provider=mismatched_provider,  # type: ignore[arg-type]
        admission=mismatched_admission,
    )
    with pytest.raises(WorkbenchModelError, match="failed closed"):
        await mismatched.plan(
            task=imported_task(),
            creator_brief_digest="d" * 64,
            creator_route_digest="e" * 64,
            inspection_summary="Safe evidence.",
        )
    assert mismatched_admission.finishes[0]["succeeded"] is False
    assert mismatched_admission.finishes[0]["input_tokens"] == 200
    assert mismatched_admission.finishes[0]["response_id_hash"] == "b" * 64


@pytest.mark.asyncio
async def test_bridge_rejects_secret_shaped_input_before_cost_admission() -> None:
    provider = FakeCanonicalProvider()
    admission = SpyAdmission()
    adapter = CanonicalWorkbenchModelAdapter(
        provider=provider,  # type: ignore[arg-type]
        admission=admission,
    )

    with pytest.raises(WorkbenchModelError, match="input was rejected"):
        await adapter.plan(
            task=imported_task(title=SECRET),
            creator_brief_digest="d" * 64,
            creator_route_digest="e" * 64,
            inspection_summary="Safe evidence.",
        )
    assert admission.claims == []
    assert provider.calls == []


@pytest.mark.asyncio
async def test_bridge_uses_a_separate_pre_admission_byte_ceiling() -> None:
    provider = FakeCanonicalProvider()
    admission = SpyAdmission()
    adapter = CanonicalWorkbenchModelAdapter(
        provider=provider,  # type: ignore[arg-type]
        admission=admission,
        maximum_input_bytes=32,
    )

    with pytest.raises(WorkbenchModelError, match="byte ceiling"):
        await adapter.plan(
            task=imported_task(),
            creator_brief_digest="d" * 64,
            creator_route_digest="e" * 64,
            inspection_summary="Safe evidence.",
        )
    assert admission.claims == []
    assert provider.calls == []


@pytest.mark.asyncio
async def test_bridge_finalizes_cost_admission_when_provider_call_is_canceled() -> None:
    provider = BlockingCanonicalProvider()
    admission = SpyAdmission()
    adapter = CanonicalWorkbenchModelAdapter(
        provider=provider,  # type: ignore[arg-type]
        admission=admission,
    )
    pending = asyncio.create_task(
        adapter.plan(
            task=imported_task(),
            creator_brief_digest="d" * 64,
            creator_route_digest="e" * 64,
            inspection_summary="Safe evidence.",
        )
    )
    await provider.started.wait()
    pending.cancel()

    with pytest.raises(WorkbenchModelError, match="canceled"):
        await pending
    assert len(admission.claims) == 1
    assert admission.finishes == [
        {
            "admission_id": "model-admission:canonical",
            "succeeded": False,
            "input_tokens": 0,
            "output_tokens": 0,
            "response_id_hash": None,
        }
    ]


def enabled_settings(tmp_path: Path) -> Settings:
    return replace(
        Settings(
            environment="development",
            database_path=tmp_path / "data.db",
            dev_api_key="owner-secret",
            auth_disabled=False,
            model="gpt-5.6-sol",
            monthly_budget_usd=10,
            job_hard_limit_usd=1,
        ),
        workbench_enabled=True,
        workbench_model_enabled=True,
        workspace_root=tmp_path / "repositories",
        artifact_root=tmp_path / "artifacts",
        execution_runtime_root=tmp_path / "runtime-root",
        workbench_workspace_root=tmp_path / "workbench-tasks",
    )


def model_capability(client: TestClient) -> dict[str, object]:
    login = client.post("/v1/workbench/session", json={"owner_key": "owner-secret"})
    assert login.status_code == 200
    health = client.get("/v1/workbench/health")
    assert health.status_code == 200
    return next(item for item in health.json()["capabilities"] if item["capability"] == "model")


def test_app_factory_flag_cannot_self_assert_provider_qualification(tmp_path: Path) -> None:
    configured = enabled_settings(tmp_path)
    client = TestClient(create_app(settings=configured), base_url="http://127.0.0.1")
    capability = model_capability(client)
    assert capability["configured"] is False
    assert capability["connected"] is False
    assert capability["qualified"] is False
    assert capability["operational"] is False


def test_app_factory_uses_only_explicitly_injected_qualified_provider(tmp_path: Path) -> None:
    configured = enabled_settings(tmp_path)
    provider = FakeCanonicalProvider()
    client = TestClient(
        create_app(
            settings=configured,
            workbench_reasoning_provider=provider,  # type: ignore[arg-type]
        ),
        base_url="http://127.0.0.1",
    )
    capability = model_capability(client)
    assert capability["configured"] is True
    assert capability["connected"] is True
    assert capability["authorized"] is True
    assert capability["healthy"] is True
    assert capability["qualified"] is True
    assert capability["operational"] is True
