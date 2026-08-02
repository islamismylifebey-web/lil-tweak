from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from liltweak.operational_qualification import (
    OperationalQualificationError,
    load_operational_qualifications,
)
from liltweak.reasoning_contract import (
    EvidenceMode,
    OutcomeStatus,
    ProviderHealthState,
    ProviderQualification,
    ProviderQualificationState,
    ProviderUsage,
    QualificationScenario,
)


def qualification(profile: str, model: str) -> ProviderQualification:
    return ProviderQualification(
        schema_version="1.0.0",
        status=OutcomeStatus.PASSED,
        status_reasons=(),
        qualification_id=f"qualification:test:{profile}",
        provider="openai-responses",
        configured=True,
        connected=True,
        requested_model=model,
        effective_model=model,
        profile_name=profile,
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
        approved_data_controls="Synthetic test evidence.",
        scenarios=(
            QualificationScenario(
                status=OutcomeStatus.PASSED,
                status_reasons=(),
                scenario_id=f"live-{profile}",
                live=True,
                response_id_digest="a" * 64,
                evidence_digest="b" * 64,
            ),
        ),
        usage=ProviderUsage(
            requests=1,
            input_tokens=1,
            cached_input_tokens=0,
            output_tokens=1,
            reasoning_tokens=0,
            total_tokens=2,
            estimated_cost_usd=0.001,
        ),
        qualified_at=datetime.now(UTC),
    )


def write_envelope(path: Path) -> None:
    body = {
        "schema_version": "operational-provider-qualification-v1",
        "run_id": "test-run",
        "status": "PASSED",
        "qualifications": [
            qualification("ordinary", "gpt-5.6-sol").model_dump(mode="json"),
            qualification("terra_degraded_read_only", "gpt-5.6-terra").model_dump(mode="json"),
        ],
        "live_scenarios": ["identity"],
        "deterministic_scenarios": ["fallback"],
        "estimated_cost_usd": 0.002,
    }
    body["envelope_digest"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    path.write_text(json.dumps(body), encoding="utf-8")


def test_qualification_loader_validates_digest_and_profiles(tmp_path: Path) -> None:
    path = tmp_path / "qualification.json"
    write_envelope(path)
    loaded = load_operational_qualifications(path)
    assert [item.profile_name for item in loaded] == ["ordinary", "terra_degraded_read_only"]
    payload = json.loads(path.read_text())
    payload["estimated_cost_usd"] = 9.0
    path.write_text(json.dumps(payload))
    with pytest.raises(OperationalQualificationError, match="digest mismatch"):
        load_operational_qualifications(path)
