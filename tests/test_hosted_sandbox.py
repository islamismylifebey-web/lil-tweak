from __future__ import annotations

import pytest

from liltweak.hosted_sandbox import (
    HostedSandboxProbeError,
    OpenAIHostedSandboxProbe,
)


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
