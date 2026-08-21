from __future__ import annotations

import asyncio
import hashlib
import json
from types import SimpleNamespace

import pytest
from pydantic import BaseModel, ConfigDict, StrictStr

from liltweak.reasoning_contract import ReasoningRole
from liltweak.reasoning_policy import ReasoningProfileName
from liltweak.reasoning_provider import (
    OpenAIResponsesReasoningProvider,
    ProviderFailureKind,
    ReasoningProviderError,
)


class Output(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    answer: StrictStr


class OutputItem:
    def model_dump(self, *, mode: str, **_: object) -> dict[str, object]:
        assert mode == "json"
        return {
            "type": "message",
            "id": "message_1",
            "content": [{"type": "output_text", "text": '{"answer":"grounded"}'}],
        }


def completed_response() -> SimpleNamespace:
    return SimpleNamespace(
        id="response_hardening",
        error=None,
        status="completed",
        model="gpt-5.6-sol",
        output=[OutputItem()],
        output_parsed=Output(answer="grounded"),
        usage=SimpleNamespace(
            input_tokens=20,
            output_tokens=10,
            total_tokens=30,
            input_tokens_details=SimpleNamespace(cached_tokens=0),
            output_tokens_details=SimpleNamespace(reasoning_tokens=5),
        ),
    )


class DelayedResponses:
    def __init__(self, *, count_delay: float = 0, parse_delay: float = 0) -> None:
        self.input_tokens = self
        self.count_delay = count_delay
        self.parse_delay = parse_delay
        self.count_calls = 0
        self.parse_input: object = None
        self.response = completed_response()

    async def count(self, **_: object) -> SimpleNamespace:
        self.count_calls += 1
        await asyncio.sleep(self.count_delay)
        return SimpleNamespace(input_tokens=20)

    async def parse(self, **values: object) -> SimpleNamespace:
        self.parse_input = values["input"]
        await asyncio.sleep(self.parse_delay)
        return self.response


async def provider_call(responses: DelayedResponses, **updates: object):
    provider = OpenAIResponsesReasoningProvider(
        client=SimpleNamespace(responses=responses)  # type: ignore[arg-type]
    )
    arguments: dict[str, object] = {
        "call_id": "call:provider-hardening",
        "role": ReasoningRole.ANALYST,
        "profile_name": ReasoningProfileName.ORDINARY,
        "instructions": "Use only supplied evidence and return the exact schema.",
        "input_text": "Evidence: one bounded observation.",
        "output_type": Output,
        "input_token_ceiling": 1_000,
        "output_token_ceiling": 256,
        "timeout_seconds": 1,
        "qualification_call": True,
    }
    arguments.update(updates)
    return await provider.call(**arguments)  # type: ignore[arg-type]


async def test_one_wall_clock_deadline_covers_count_and_parse() -> None:
    responses = DelayedResponses(count_delay=0.04, parse_delay=0.04)

    with pytest.raises(ReasoningProviderError) as failure:
        await provider_call(responses, timeout_seconds=0.06)

    assert failure.value.kind == ProviderFailureKind.TIMEOUT


async def test_replayed_provider_input_is_secret_scanned_before_api() -> None:
    responses = DelayedResponses()
    secret = "sk-" + "proj-" + "Q" * 32

    with pytest.raises(ReasoningProviderError) as failure:
        await provider_call(
            responses,
            replay_items=(
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": secret}],
                },
            ),
        )

    assert failure.value.kind == ProviderFailureKind.SENSITIVE_INPUT
    assert responses.count_calls == 0


async def test_continuation_evidence_binds_every_transmitted_input_item() -> None:
    responses = DelayedResponses()
    prior = ({"type": "reasoning", "id": "reasoning_1", "encrypted_content": "opaque"},)

    result = await provider_call(responses, replay_items=prior)

    expected_input = [
        *prior,
        {"role": "user", "content": "Evidence: one bounded observation."},
    ]
    expected_digest = hashlib.sha256(
        json.dumps(
            expected_input,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    ).hexdigest()
    assert responses.parse_input == expected_input
    assert result.evidence.provider_input_digest == expected_digest
    assert result.evidence.input_digest != expected_digest


async def test_rejected_billable_response_preserves_sanitized_cost_evidence() -> None:
    responses = DelayedResponses()
    responses.response.status = "incomplete"

    with pytest.raises(ReasoningProviderError) as failure:
        await provider_call(responses)

    assert failure.value.kind == ProviderFailureKind.INCOMPLETE
    assert failure.value.input_tokens == 20
    assert failure.value.output_tokens == 10
    assert failure.value.response_id_digest == hashlib.sha256(b"response_hardening").hexdigest()


async def test_provider_cancellation_remains_task_cancellation() -> None:
    responses = DelayedResponses(parse_delay=1)
    task = asyncio.create_task(provider_call(responses))
    await asyncio.sleep(0)
    task.cancel()

    with pytest.raises(ReasoningProviderError) as failure:
        await task

    assert isinstance(failure.value, asyncio.CancelledError)
    assert failure.value.kind == ProviderFailureKind.CANCELED
    assert task.cancelled()
