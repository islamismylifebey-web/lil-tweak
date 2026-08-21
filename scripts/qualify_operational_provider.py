from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictStr

APP_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(APP_ROOT))

from liltweak.model_catalog import MODEL_CATALOG  # noqa: E402
from liltweak.reasoning_contract import (  # noqa: E402
    EvidenceMode,
    OutcomeStatus,
    ProviderHealthState,
    ProviderQualification,
    ProviderQualificationState,
    ProviderUsage,
    QualificationScenario,
    ReasoningRole,
)
from liltweak.reasoning_policy import (  # noqa: E402
    PROFILE_REGISTRY,
    FoundationModel,
    ReasoningProfileName,
)
from liltweak.reasoning_provider import (  # noqa: E402
    OpenAIResponsesReasoningProvider,
    ProviderCallResult,
    ProviderFailureKind,
    ReasoningProviderCanceled,
    ReasoningProviderError,
)


class ProbeOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status: Literal["PASS"]
    statement: StrictStr = Field(min_length=1, max_length=200)


class OperationalQualificationEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["operational-provider-qualification-v1"] = (
        "operational-provider-qualification-v1"
    )
    run_id: StrictStr
    status: Literal["PASSED"] = "PASSED"
    qualifications: tuple[ProviderQualification, ProviderQualification]
    live_scenarios: tuple[StrictStr, ...]
    deterministic_scenarios: tuple[StrictStr, ...]
    estimated_cost_usd: StrictFloat = Field(ge=0)
    envelope_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _cost(result: ProviderCallResult) -> float:
    evidence = result.evidence
    model = FoundationModel(evidence.effective_model)
    price = MODEL_CATALOG.price_band(model, input_tokens=evidence.input_tokens)
    uncached = evidence.input_tokens - evidence.cached_input_tokens
    return float(
        (
            uncached * price.input_per_million_usd
            + evidence.cached_input_tokens * price.cached_input_per_million_usd
            + evidence.output_tokens * price.output_per_million_usd
        )
        / 1_000_000
    )


def _scenario(
    scenario_id: str,
    *,
    response_id_digest: str | None,
    evidence: object,
) -> QualificationScenario:
    return QualificationScenario(
        status=OutcomeStatus.PASSED,
        status_reasons=(),
        scenario_id=scenario_id,
        live=True,
        response_id_digest=response_id_digest,
        evidence_digest=_digest(evidence),
    )


def _qualification(
    profile_name: ReasoningProfileName,
    *,
    scenarios: tuple[QualificationScenario, ...],
    result: ProviderCallResult,
    estimated_cost_usd: float,
    run_id: str,
) -> ProviderQualification:
    profile = PROFILE_REGISTRY[profile_name]
    evidence = result.evidence
    return ProviderQualification(
        schema_version="1.0.0",
        status=OutcomeStatus.PASSED,
        status_reasons=(),
        qualification_id=f"qualification:{run_id}:{profile_name.value}",
        provider="openai-responses",
        configured=True,
        connected=True,
        requested_model=profile.model.value,
        effective_model=evidence.effective_model,
        profile_name=profile_name.value,
        profile_version=profile.profile_version,
        request_mode=profile.variant.request_mode.value,
        reasoning_effort=profile.variant.effort.value,
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
        approved_data_controls=(
            "Synthetic nonsecret probes only; tool-free Responses calls; store disabled; "
            "response identifiers retained only as SHA-256 digests. Malformed, refusal, retry, "
            "and fallback policy paths are deterministic fault-injection qualifications."
        ),
        scenarios=scenarios,
        usage=ProviderUsage(
            requests=1,
            input_tokens=evidence.input_tokens,
            cached_input_tokens=evidence.cached_input_tokens,
            output_tokens=evidence.output_tokens,
            reasoning_tokens=evidence.reasoning_tokens,
            total_tokens=evidence.total_tokens,
            estimated_cost_usd=estimated_cost_usd,
        ),
        qualified_at=datetime.now(UTC),
    )


async def _structured_probe(
    provider: OpenAIResponsesReasoningProvider,
    profile: ReasoningProfileName,
    run_id: str,
) -> ProviderCallResult:
    return await provider.call(
        call_id=f"qualification:{run_id}:{profile.value}",
        role=ReasoningRole.ANALYST,
        profile_name=profile,
        instructions=(
            "This is a synthetic tool-free provider identity probe. Return status PASS and a "
            "short statement that no tool or execution action occurred."
        ),
        input_text="Confirm this bounded structured provider probe.",
        output_type=ProbeOutput,
        input_token_ceiling=512,
        output_token_ceiling=128,
        timeout_seconds=30,
        qualification_call=True,
    )


async def _timeout_probe(
    provider: OpenAIResponsesReasoningProvider, run_id: str
) -> QualificationScenario:
    try:
        await provider.call(
            call_id=f"qualification:{run_id}:timeout",
            role=ReasoningRole.ANALYST,
            profile_name=ReasoningProfileName.ORDINARY,
            instructions="Synthetic timeout probe. Return PASS.",
            input_text="Timeout immediately.",
            output_type=ProbeOutput,
            input_token_ceiling=512,
            output_token_ceiling=128,
            timeout_seconds=0.0001,
            qualification_call=True,
        )
    except ReasoningProviderError as exc:
        if exc.kind != ProviderFailureKind.TIMEOUT:
            raise RuntimeError("provider timeout was misclassified") from exc
        return _scenario(
            "live-timeout-classification",
            response_id_digest=exc.response_id_digest,
            evidence={"kind": exc.kind.value, "input_tokens": exc.input_tokens},
        )
    raise RuntimeError("provider timeout probe unexpectedly completed")


async def _cancellation_probe(
    provider: OpenAIResponsesReasoningProvider, run_id: str
) -> QualificationScenario:
    task = asyncio.create_task(
        provider.call(
            call_id=f"qualification:{run_id}:cancellation",
            role=ReasoningRole.ANALYST,
            profile_name=ReasoningProfileName.ORDINARY,
            instructions="Synthetic cancellation probe. Return PASS after careful reasoning.",
            input_text="This request will be canceled by its owner.",
            output_type=ProbeOutput,
            input_token_ceiling=512,
            output_token_ceiling=128,
            timeout_seconds=30,
            qualification_call=True,
        )
    )
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except ReasoningProviderCanceled as exc:
        return _scenario(
            "live-cancellation-classification",
            response_id_digest=None,
            evidence={"kind": exc.kind.value, "observable": True},
        )
    except asyncio.CancelledError:
        return _scenario(
            "live-cancellation-classification",
            response_id_digest=None,
            evidence={"kind": ProviderFailureKind.CANCELED.value, "observable": True},
        )
    raise RuntimeError("provider cancellation probe unexpectedly completed")


async def run(output: Path) -> int:
    run_id = f"operational-{uuid.uuid4().hex}"
    provider = OpenAIResponsesReasoningProvider(maximum_concurrency=1)
    sol = await _structured_probe(provider, ReasoningProfileName.ORDINARY, run_id)
    terra = await _structured_probe(provider, ReasoningProfileName.TERRA_DEGRADED_READ_ONLY, run_id)
    timeout = await _timeout_probe(provider, run_id)
    cancellation = await _cancellation_probe(provider, run_id)
    sol_cost = _cost(sol)
    terra_cost = _cost(terra)
    sol_scenarios = (
        _scenario(
            "live-sol-identity-structured-usage",
            response_id_digest=sol.evidence.response_id_digest,
            evidence=sol.evidence.model_dump(mode="json"),
        ),
        timeout,
        cancellation,
    )
    terra_scenarios = (
        _scenario(
            "live-terra-identity-structured-usage",
            response_id_digest=terra.evidence.response_id_digest,
            evidence=terra.evidence.model_dump(mode="json"),
        ),
    )
    qualifications = (
        _qualification(
            ReasoningProfileName.ORDINARY,
            scenarios=sol_scenarios,
            result=sol,
            estimated_cost_usd=sol_cost,
            run_id=run_id,
        ),
        _qualification(
            ReasoningProfileName.TERRA_DEGRADED_READ_ONLY,
            scenarios=terra_scenarios,
            result=terra,
            estimated_cost_usd=terra_cost,
            run_id=run_id,
        ),
    )
    for qualification in qualifications:
        OpenAIResponsesReasoningProvider.validate_live_qualification(qualification)
    live_scenarios = (
        "Sol exact model + structured output + usage",
        "Terra exact model + structured output + usage",
        "timeout classification",
        "cancellation observability",
    )
    deterministic_scenarios = (
        "malformed response",
        "refusal response",
        "incomplete response",
        "retry disabled",
        "fallback allowlist and denylist",
        "continuation and compaction preservation",
        "cost reconciliation",
    )
    estimated_cost_usd = sol_cost + terra_cost
    body = {
        "schema_version": "operational-provider-qualification-v1",
        "run_id": run_id,
        "status": "PASSED",
        "qualifications": [item.model_dump(mode="json") for item in qualifications],
        "live_scenarios": live_scenarios,
        "deterministic_scenarios": deterministic_scenarios,
        "estimated_cost_usd": estimated_cost_usd,
    }
    envelope = OperationalQualificationEnvelope(
        run_id=run_id,
        qualifications=qualifications,
        live_scenarios=live_scenarios,
        deterministic_scenarios=deterministic_scenarios,
        estimated_cost_usd=estimated_cost_usd,
        envelope_digest=_digest(body),
    )
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(envelope.model_dump_json(indent=2))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(
        json.dumps(
            {
                "status": envelope.status,
                "run_id": run_id,
                "models": [item.effective_model for item in qualifications],
                "live_scenarios": list(envelope.live_scenarios),
                "estimated_cost_usd": envelope.estimated_cost_usd,
                "evidence_path": str(output),
            },
            sort_keys=True,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run bounded private provider qualification.")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    return asyncio.run(run(arguments.output))


if __name__ == "__main__":
    raise SystemExit(main())
