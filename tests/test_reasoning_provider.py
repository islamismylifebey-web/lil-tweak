from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from pydantic import BaseModel, ConfigDict, StrictStr

from liltweak.reasoning_contract import ReasoningRole
from liltweak.reasoning_policy import (
    ReasoningEffort,
    ReasoningProfileName,
    ReasoningRequestMode,
)
from liltweak.reasoning_provider import (
    OpenAIResponsesReasoningProvider,
    ProviderFailureKind,
    ReasoningProviderError,
)


class Output(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    answer: StrictStr


class Item:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def model_dump(self, *, mode: str, **_: object) -> dict[str, object]:
        assert mode == "json"
        return self.payload


def completed_response(**updates: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "id": "resp_123",
        "error": None,
        "status": "completed",
        "model": "gpt-5.6-sol",
        "output": [
            Item(
                {
                    "type": "reasoning",
                    "id": "reasoning_1",
                    "status": "completed",
                    "encrypted_content": "opaque",
                }
            ),
            Item(
                {
                    "type": "message",
                    "id": "message_1",
                    "content": [{"type": "output_text", "text": '{"answer":"grounded"}'}],
                }
            ),
        ],
        "output_parsed": Output(answer="grounded"),
        "usage": SimpleNamespace(
            input_tokens=100,
            output_tokens=40,
            total_tokens=140,
            input_tokens_details=SimpleNamespace(cached_tokens=10),
            output_tokens_details=SimpleNamespace(reasoning_tokens=20),
        ),
    }
    values.update(updates)
    return SimpleNamespace(**values)


class FakeInputTokens:
    def __init__(self, *, count: int = 120, delay: float = 0) -> None:
        self._count = count
        self.delay = delay
        self.kwargs: dict[str, object] | None = None

    async def count(self, **kwargs: object) -> SimpleNamespace:
        self.kwargs = kwargs
        if self.delay:
            await asyncio.sleep(self.delay)
        return SimpleNamespace(input_tokens=self._count)


class FakeResponses:
    def __init__(self, response: SimpleNamespace, *, delay: float = 0) -> None:
        self.input_tokens = FakeInputTokens()
        self.response = response
        self.delay = delay
        self.kwargs: dict[str, object] | None = None

    async def parse(self, **kwargs: object) -> SimpleNamespace:
        self.kwargs = kwargs
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.response


class FakeClient:
    def __init__(self, response: SimpleNamespace, *, delay: float = 0) -> None:
        self.responses = FakeResponses(response, delay=delay)


async def call(
    client: FakeClient,
    **updates: object,
):
    provider = OpenAIResponsesReasoningProvider(client=client)  # type: ignore[arg-type]
    arguments: dict[str, object] = {
        "call_id": "call:one",
        "role": ReasoningRole.ANALYST,
        "profile_name": ReasoningProfileName.ORDINARY,
        "instructions": "Analyze only the supplied evidence and return the exact schema.",
        "input_text": "Evidence: the failing assertion is at tests/test_widget.py:12.",
        "output_type": Output,
        "input_token_ceiling": 1_000,
        "output_token_ceiling": 256,
        "timeout_seconds": 1,
        "qualification_call": True,
    }
    arguments.update(updates)
    return await provider.call(**arguments)  # type: ignore[arg-type]


async def test_explicit_responses_boundary_counts_tokens_and_disables_tools_storage() -> None:
    client = FakeClient(completed_response())

    result = await call(client)

    assert result.output == Output(answer="grounded")
    assert result.evidence.effective_model == "gpt-5.6-sol"
    assert result.evidence.provider_counted_input_tokens == 120
    assert result.evidence.cached_input_tokens == 10
    assert result.evidence.reasoning_tokens == 20
    assert len(result.replay_items) == 2
    assert "status" not in result.replay_items[0]
    count_args = client.responses.input_tokens.kwargs
    parse_args = client.responses.kwargs
    assert count_args is not None and parse_args is not None
    assert count_args["text"]["format"]["strict"] is True  # type: ignore[index]
    assert parse_args["store"] is False
    assert parse_args["tools"] == []
    assert parse_args["parallel_tool_calls"] is False
    assert parse_args["reasoning"] == {
        "mode": "standard",
        "effort": "high",
        "context": "all_turns",
        "summary": "auto",
    }


async def test_unqualified_production_profile_and_sensitive_input_fail_before_api() -> None:
    client = FakeClient(completed_response())
    with pytest.raises(ReasoningProviderError) as blocked:
        await call(client, qualification_call=False)
    assert blocked.value.kind == ProviderFailureKind.BLOCKED_PROFILE

    with pytest.raises(ReasoningProviderError) as sensitive:
        await call(client, input_text="api_key=sk-test-abcdefghijklmnopqrstuvwxyz")
    assert sensitive.value.kind == ProviderFailureKind.SENSITIVE_INPUT
    assert client.responses.kwargs is None


@pytest.mark.parametrize(
    ("response", "kind"),
    (
        (completed_response(status="incomplete"), ProviderFailureKind.INCOMPLETE),
        (completed_response(model="gpt-5.6-terra"), ProviderFailureKind.MODEL_MISMATCH),
        (
            completed_response(output_parsed={"unknown": "field"}),
            ProviderFailureKind.MALFORMED_OUTPUT,
        ),
        (
            completed_response(
                output=[
                    Item(
                        {
                            "type": "message",
                            "content": [{"type": "refusal", "refusal": "cannot comply"}],
                        }
                    )
                ]
            ),
            ProviderFailureKind.REFUSAL,
        ),
    ),
)
async def test_provider_status_schema_refusal_and_model_mismatch_fail_closed(
    response: SimpleNamespace,
    kind: ProviderFailureKind,
) -> None:
    with pytest.raises(ReasoningProviderError) as failure:
        await call(FakeClient(response))
    assert failure.value.kind == kind


async def test_provider_token_ceiling_timeout_and_cancellation_are_distinct() -> None:
    client = FakeClient(completed_response())
    client.responses.input_tokens._count = 1_001
    with pytest.raises(ReasoningProviderError) as excessive:
        await call(client)
    assert excessive.value.kind == ProviderFailureKind.USAGE_INVALID

    with pytest.raises(ReasoningProviderError) as timeout:
        await call(FakeClient(completed_response(), delay=0.05), timeout_seconds=0.01)
    assert timeout.value.kind == ProviderFailureKind.TIMEOUT

    task = asyncio.create_task(call(FakeClient(completed_response(), delay=1)))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(ReasoningProviderError) as canceled:
        await task
    assert canceled.value.kind == ProviderFailureKind.CANCELED


async def test_continuation_replays_every_prior_output_item() -> None:
    client = FakeClient(completed_response())
    prior = (
        {"type": "reasoning", "id": "r1", "encrypted_content": "opaque"},
        {
            "type": "message",
            "id": "m1",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "prior"}],
        },
    )

    result = await call(client, replay_items=prior)

    assert result.evidence.continuation_items_preserved is True
    sent = client.responses.kwargs["input"]  # type: ignore[index]
    assert sent[:2] == list(prior)
    assert sent[2]["role"] == "user"


async def test_benchmark_variant_override_is_qualification_only_and_recorded() -> None:
    client = FakeClient(completed_response())
    result = await call(
        client,
        qualification_request_mode=ReasoningRequestMode.PRO,
        qualification_effort=ReasoningEffort.MAX,
    )
    assert result.evidence.request_mode == "pro"
    assert result.evidence.reasoning_effort == "max"
    assert client.responses.kwargs["reasoning"]["mode"] == "pro"  # type: ignore[index]

    with pytest.raises(ReasoningProviderError) as blocked:
        await call(
            FakeClient(completed_response()),
            qualification_call=False,
            qualification_request_mode=ReasoningRequestMode.PRO,
            qualification_effort=ReasoningEffort.MAX,
        )
    assert blocked.value.kind == ProviderFailureKind.BLOCKED_PROFILE
