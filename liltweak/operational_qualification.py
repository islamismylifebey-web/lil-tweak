from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, StrictFloat, StrictStr

from .reasoning_contract import ProviderQualification
from .reasoning_provider import OpenAIResponsesReasoningProvider


class OperationalQualificationError(RuntimeError):
    pass


class OperationalQualificationEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["operational-provider-qualification-v1"]
    run_id: StrictStr
    status: Literal["PASSED"]
    qualifications: tuple[ProviderQualification, ProviderQualification]
    live_scenarios: tuple[StrictStr, ...]
    deterministic_scenarios: tuple[StrictStr, ...]
    estimated_cost_usd: StrictFloat
    envelope_digest: StrictStr


def load_operational_qualifications(path: Path) -> tuple[ProviderQualification, ...]:
    try:
        envelope = OperationalQualificationEnvelope.model_validate_json(
            path.read_text(encoding="utf-8")
        )
    except (OSError, ValueError) as exc:
        raise OperationalQualificationError("provider qualification evidence is invalid") from exc
    body = envelope.model_dump(mode="json", exclude={"envelope_digest"})
    expected = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    if expected != envelope.envelope_digest:
        raise OperationalQualificationError("provider qualification evidence digest mismatch")
    profile_names: list[str] = []
    for qualification in envelope.qualifications:
        profile = OpenAIResponsesReasoningProvider.validate_live_qualification(qualification)
        profile_names.append(profile.value)
    if profile_names != ["ordinary", "terra_degraded_read_only"]:
        raise OperationalQualificationError("provider qualification profiles are incomplete")
    return envelope.qualifications
