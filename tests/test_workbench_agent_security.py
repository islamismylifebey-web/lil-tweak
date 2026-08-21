from __future__ import annotations

from types import SimpleNamespace

import pytest

from liltweak.workbench_agent import OpenAIWorkbenchModelAdapter, WorkbenchModelError
from liltweak.workbench_contract import (
    CommandRequest,
    StepPhase,
    TaskImport,
    ToolKind,
    ToolRequest,
    WorkbenchPlan,
)

DIGEST = "a" * 64
SECRET = "sk-proj-" + "Q" * 32


class SpyAdmission:
    def __init__(self) -> None:
        self.claims = 0
        self.finishes: list[dict[str, object]] = []

    async def claim(self, **_: object) -> str:
        self.claims += 1
        return "admission:one"

    async def finish(self, **values: object) -> None:
        self.finishes.append(values)


class FakeProviderTokenCounter:
    async def count(self, **values: object) -> int:
        provider_input = values["provider_input"]
        assert isinstance(provider_input, str)
        return 20_001 if len(provider_input) > 12_000 else 500


def plan(*, summary: str = "Safe bounded plan") -> WorkbenchPlan:
    return WorkbenchPlan(
        summary=summary,
        reasoning="Run a test and an independent verification command.",
        source_snapshot_digest=DIGEST,
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


def adapter(admission: SpyAdmission) -> OpenAIWorkbenchModelAdapter:
    return OpenAIWorkbenchModelAdapter(
        model="gpt-5.6-sol",
        reasoning_tier="high",
        admission=admission,
        enabled=True,
        token_counter=FakeProviderTokenCounter(),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("location", ["title", "direction", "inspection"])
async def test_secret_shaped_provider_input_is_rejected_before_admission(
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    admission = SpyAdmission()
    calls = 0

    async def forbidden_run(*_: object, **__: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("provider must not be called")

    monkeypatch.setattr("liltweak.workbench_agent.Runner.run", forbidden_run)
    task = TaskImport(
        title=SECRET if location == "title" else "Safe title",
        direction=SECRET if location == "direction" else "Make the bounded change",
        source_snapshot_digest=DIGEST,
    )
    with pytest.raises(WorkbenchModelError, match="rejected"):
        await adapter(admission).plan(
            task=task,
            creator_brief_digest="b" * 64,
            creator_route_digest="c" * 64,
            inspection_summary=SECRET if location == "inspection" else "safe summary",
        )
    assert admission.claims == 0
    assert calls == 0


@pytest.mark.asyncio
async def test_oversized_prompt_is_rejected_before_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admission = SpyAdmission()

    async def forbidden_run(*_: object, **__: object) -> object:
        raise AssertionError("provider must not be called")

    monkeypatch.setattr("liltweak.workbench_agent.Runner.run", forbidden_run)
    with pytest.raises(WorkbenchModelError, match="safe token bound"):
        await adapter(admission).plan(
            task=TaskImport(
                title="Safe title",
                direction="Make the bounded change",
                source_snapshot_digest=DIGEST,
            ),
            creator_brief_digest="b" * 64,
            creator_route_digest="c" * 64,
            inspection_summary="x" * 20_000,
        )
    assert admission.claims == 0


@pytest.mark.asyncio
async def test_safe_prompt_calls_provider_once_and_records_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admission = SpyAdmission()
    calls = 0

    async def fake_run(*_: object, **__: object) -> object:
        nonlocal calls
        calls += 1
        return SimpleNamespace(
            final_output=plan(),
            last_response_id="response-safe",
            context_wrapper=SimpleNamespace(
                usage=SimpleNamespace(input_tokens=200, output_tokens=100)
            ),
        )

    monkeypatch.setattr("liltweak.workbench_agent.Runner.run", fake_run)
    result = await adapter(admission).plan(
        task=TaskImport(
            title="Safe title",
            direction="Make the bounded change",
            source_snapshot_digest=DIGEST,
        ),
        creator_brief_digest="b" * 64,
        creator_route_digest="c" * 64,
        inspection_summary="safe summary",
    )
    assert result.plan == plan()
    assert calls == 1
    assert admission.claims == 1
    assert admission.finishes[0]["input_tokens"] == 200
    assert admission.finishes[0]["output_tokens"] == 100


@pytest.mark.asyncio
async def test_post_provider_rejection_preserves_observed_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admission = SpyAdmission()

    async def fake_run(*_: object, **__: object) -> object:
        return SimpleNamespace(
            final_output=plan(summary=f"password={SECRET}"),
            last_response_id="response-rejected",
            context_wrapper=SimpleNamespace(
                usage=SimpleNamespace(input_tokens=321, output_tokens=123)
            ),
        )

    monkeypatch.setattr("liltweak.workbench_agent.Runner.run", fake_run)
    with pytest.raises(WorkbenchModelError, match="failed closed"):
        await adapter(admission).plan(
            task=TaskImport(
                title="Safe title",
                direction="Make the bounded change",
                source_snapshot_digest=DIGEST,
            ),
            creator_brief_digest="b" * 64,
            creator_route_digest="c" * 64,
            inspection_summary="safe summary",
        )
    assert admission.finishes[0]["succeeded"] is False
    assert admission.finishes[0]["input_tokens"] == 321
    assert admission.finishes[0]["output_tokens"] == 123
