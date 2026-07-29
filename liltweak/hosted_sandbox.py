from __future__ import annotations

import hashlib
import math
import secrets
from collections.abc import Mapping, Sequence

from agents import Agent, ModelSettings, RunConfig, Runner, ShellTool
from agents.items import ToolCallOutputItem
from pydantic import Field, StrictStr

from .creator_contract import CreatorSchema
from .live_contract import HostedSandboxProbeResult, LiveModelUsage


class HostedSandboxProbeError(RuntimeError):
    pass


class _ProbeSummary(CreatorSchema):
    observed_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


class OpenAIHostedSandboxProbe:
    MODEL = "gpt-5.6-luna"
    INPUT_PRICE_PER_MILLION_USD = 1.0
    OUTPUT_PRICE_PER_MILLION_USD = 6.0
    CONTAINER_MINIMUM_USD = 0.03
    APPROVED_COST_CEILING_USD = 0.04

    async def run(self, *, approved: bool) -> HostedSandboxProbeResult:
        if not approved:
            raise HostedSandboxProbeError("hosted sandbox probe requires explicit cost approval")
        challenge = secrets.token_hex(24)
        expected = hashlib.sha256(challenge.encode("ascii")).hexdigest()
        exact_command = (
            f"python -c \"import hashlib; print(hashlib.sha256(b'{challenge}').hexdigest())\""
        )
        shell = ShellTool(
            environment={
                "type": "container_auto",
                "memory_limit": "1g",
                "network_policy": {"type": "disabled"},
            }
        )
        agent: Agent = Agent(
            name="Lil Tweak Hosted Sandbox Boundary Probe",
            model=self.MODEL,
            instructions=(
                "This is a synthetic isolation probe. Use the hosted shell exactly once. "
                "Run only the exact command supplied by the user. Do not access the network, "
                "files, environment variables, credentials, package managers, or any other "
                "resource. After the tool returns, copy only its 64-character digest into the "
                "strict output schema. Never fabricate a shell result."
            ),
            tools=[shell],
            handoffs=[],
            model_settings=ModelSettings(
                tool_choice="shell",
                max_tokens=512,
                reasoning={"effort": "low"},
                include_usage=True,
                store=False,
                parallel_tool_calls=False,
            ),
            output_type=_ProbeSummary,
        )
        try:
            result = await Runner.run(
                agent,
                input=f"Run exactly this command and no other command:\n{exact_command}",
                max_turns=2,
                run_config=RunConfig(
                    tracing_disabled=True,
                    trace_include_sensitive_data=False,
                    workflow_name="Lil Tweak Network-Disabled Hosted Sandbox Probe",
                ),
            )
        except Exception as exc:
            raise HostedSandboxProbeError("hosted sandbox probe is unavailable") from exc

        shell_outputs = [
            item.output
            for item in result.new_items
            if isinstance(item, ToolCallOutputItem)
            and self._raw_type(item.raw_item) == "shell_call_output"
        ]
        observed_text = "\n".join(
            value for output in shell_outputs for value in self._collect_text(output)
        )
        usage = result.context_wrapper.usage
        bounded_usage = LiveModelUsage(
            requests=usage.requests,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            total_tokens=usage.total_tokens,
        )
        token_cost = (
            math.ceil(
                (
                    bounded_usage.input_tokens * self.INPUT_PRICE_PER_MILLION_USD
                    + bounded_usage.output_tokens * self.OUTPUT_PRICE_PER_MILLION_USD
                )
                / 1_000_000
                * 1_000_000
            )
            / 1_000_000
        )
        actual_cost = math.ceil((self.CONTAINER_MINIMUM_USD + token_cost) * 1_000_000) / 1_000_000
        verified = (
            len(shell_outputs) == 1
            and observed_text.count(expected) == 1
            and bounded_usage.requests <= 2
            and actual_cost <= self.APPROVED_COST_CEILING_USD
        )
        return HostedSandboxProbeResult(
            model=self.MODEL,
            challenge_digest=expected,
            observed_output_digest=hashlib.sha256(observed_text.encode("utf-8")).hexdigest(),
            shell_call_count=len(shell_outputs),
            usage=bounded_usage,
            approved_cost_ceiling_usd=self.APPROVED_COST_CEILING_USD,
            estimated_actual_cost_usd=actual_cost,
            verified=verified,
        )

    @staticmethod
    def _raw_type(value: object) -> str | None:
        raw_type = value.get("type") if isinstance(value, Mapping) else getattr(value, "type", None)
        return str(raw_type) if raw_type is not None else None

    @classmethod
    def _collect_text(cls, value: object) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, bytes):
            return [value.decode("utf-8", errors="replace")]
        if isinstance(value, Mapping):
            return [
                text
                for key, item in value.items()
                if str(key).casefold() not in {"environment", "env", "credentials", "secrets"}
                for text in cls._collect_text(item)
            ]
        if isinstance(value, Sequence):
            return [text for item in value for text in cls._collect_text(item)]
        if hasattr(value, "model_dump"):
            return cls._collect_text(value.model_dump(mode="json"))
        return []
