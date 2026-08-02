from __future__ import annotations

import pytest

from liltweak.hosted_sandbox import (
    HostedSandboxProbeError,
    OpenAIHostedSandboxProbe,
)
from liltweak.live_contract import LiveModelUsage
from liltweak.model_catalog import MODEL_CATALOG
from liltweak.reasoning_policy import FoundationModel, ReasoningEffort


@pytest.mark.asyncio
async def test_hosted_probe_requires_explicit_approval_before_provider_use() -> None:
    probe = OpenAIHostedSandboxProbe()
    with pytest.raises(HostedSandboxProbeError, match="approval"):
        await probe.run(approved=False)


def test_hosted_probe_extracts_observations_without_secret_named_fields() -> None:
    output = {
        "output": [
            {
                "stdout": "safe-digest",
                "environment": "must-not-be-read",
                "nested": {"value": "observed"},
            }
        ],
        "credentials": "must-not-be-read",
    }
    collected = OpenAIHostedSandboxProbe._collect_text(output)
    assert "safe-digest" in collected
    assert "observed" in collected
    assert "must-not-be-read" not in collected


def test_hosted_probe_recognizes_only_shell_output_items() -> None:
    assert OpenAIHostedSandboxProbe._raw_type({"type": "shell_call_output"}) == (
        "shell_call_output"
    )
    assert OpenAIHostedSandboxProbe._raw_type({"type": "message"}) == "message"


def test_hosted_probe_uses_diagnostic_policy_and_catalog_prices() -> None:
    probe = OpenAIHostedSandboxProbe()
    usage = LiveModelUsage(
        requests=1,
        input_tokens=1_000,
        output_tokens=100,
        total_tokens=1_100,
    )
    band = MODEL_CATALOG.price_band(FoundationModel.LUNA, input_tokens=1_000)

    assert probe.MODEL_ID == FoundationModel.LUNA
    assert FoundationModel.LUNA.value == probe.MODEL
    assert ReasoningEffort.LOW.value == probe.REASONING_EFFORT
    expected = (
        usage.input_tokens * float(band.input_per_million_usd)
        + usage.output_tokens * float(band.output_per_million_usd)
    ) / 1_000_000
    assert probe._token_cost_usd(usage) == pytest.approx(expected)
