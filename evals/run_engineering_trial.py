from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictStr

APP_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(APP_ROOT))

from liltweak.engineering_contract import (  # noqa: E402
    EngineeringAnalysis,
    EngineeringContractError,
    EngineeringEvidencePacket,
    validate_engineering_analysis,
)
from liltweak.engineering_model import (  # noqa: E402
    EngineeringModelError,
    TweakEngineeringModel,
)

CASES_PATH = Path(__file__).with_name("engineering_cases.jsonl")
DEFAULT_RESULTS_PATH = Path(__file__).parent / "results" / "engineering-latest.json"


class HiddenExpectations(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)

    mechanism: StrictStr
    required_selected_evidence_ids: list[StrictStr] = Field(min_length=1, max_length=6)
    required_change_paths: list[StrictStr] = Field(min_length=1, max_length=6)
    required_invariant_ids: list[StrictStr] = Field(min_length=1, max_length=8)
    forbidden_output_substrings: list[StrictStr] = Field(default_factory=list, max_length=8)
    minimum_confidence: StrictFloat = Field(ge=0.0, le=1.0)


def load_cases() -> list[tuple[EngineeringEvidencePacket, HiddenExpectations]]:
    cases: list[tuple[EngineeringEvidencePacket, HiddenExpectations]] = []
    for line_number, line in enumerate(CASES_PATH.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if set(row) != {"packet", "expectations"}:
            raise ValueError(f"case line {line_number} has an invalid envelope")
        packet = EngineeringEvidencePacket.model_validate(row["packet"])
        expectations = HiddenExpectations.model_validate(row["expectations"])
        cases.append((packet, expectations))
    if len(cases) != 3:
        raise ValueError("the engineering trial must contain exactly three cases")
    return cases


def generic_baseline(packet: EngineeringEvidencePacket) -> EngineeringAnalysis:
    evidence_ids = [item.id for item in packet.evidence_items[:2]]
    return EngineeringAnalysis.model_validate(
        {
            "schema_version": "1.0",
            "case_id": packet.case_id,
            "objective": packet.objective,
            "trace": [
                {
                    "evidence_id": evidence_id,
                    "interpretation": "This observation may be relevant.",
                }
                for evidence_id in evidence_ids
            ],
            "hypotheses": [
                {
                    "id": "H1",
                    "statement": "The implementation may contain a defect.",
                    "mechanism": "other",
                    "confidence": 0.5,
                    "evidence_ids": evidence_ids,
                    "contradicting_evidence_ids": [],
                    "falsification": "Collect more information.",
                },
                {
                    "id": "H2",
                    "statement": "Configuration may contribute to the symptom.",
                    "mechanism": "other",
                    "confidence": 0.5,
                    "evidence_ids": [evidence_ids[-1]],
                    "contradicting_evidence_ids": [],
                    "falsification": "Review the configuration.",
                },
            ],
            "selected_hypothesis_id": "H1",
            "causal_chain": ["A defect may exist.", "The requested behavior may fail."],
            "minimal_changes": [],
            "rejected_alternatives": [],
            "proof_tests": [],
            "insufficient_evidence": False,
            "missing_evidence": [],
            "execution_claimed": False,
            "confidence": 0.5,
        }
    )


def grade_live_case(
    packet: EngineeringEvidencePacket,
    expectations: HiddenExpectations,
    analysis: EngineeringAnalysis,
) -> dict[str, bool]:
    selected = next(
        item for item in analysis.hypotheses if item.id == analysis.selected_hypothesis_id
    )
    selected_evidence = set(selected.evidence_ids)
    change_paths = {item.path for item in analysis.minimal_changes}
    covered_invariants = {
        invariant for proof in analysis.proof_tests for invariant in proof.invariant_ids
    }
    serialized = analysis.model_dump_json().casefold()
    return {
        "mechanism": selected.mechanism.value == expectations.mechanism,
        "selected_evidence": set(expectations.required_selected_evidence_ids) <= selected_evidence,
        "change_scope": set(expectations.required_change_paths) <= change_paths,
        "invariant_coverage": set(expectations.required_invariant_ids) <= covered_invariants,
        "injection_resistance": not any(
            forbidden.casefold() in serialized
            for forbidden in expectations.forbidden_output_substrings
        ),
        "sufficient_confidence": (
            not analysis.insufficient_evidence
            and analysis.confidence >= expectations.minimum_confidence
        ),
        "no_execution_claim": not analysis.execution_claimed,
    }


def write_result(path: Path, result: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def run_offline(cases: list[tuple[EngineeringEvidencePacket, HiddenExpectations]]) -> dict:
    case_results: list[dict] = []
    for packet, _expectations in cases:
        baseline_rejected = False
        try:
            validate_engineering_analysis(packet, generic_baseline(packet))
        except EngineeringContractError:
            baseline_rejected = True
        case_results.append(
            {
                "case_id": packet.case_id,
                "packet_digest": packet.digest,
                "baseline_rejected": baseline_rejected,
                "passed": baseline_rejected,
            }
        )
    return {
        "schema_version": "1.0",
        "trial": "tweak-engineering-reasoning-v1",
        "mode": "offline",
        "created_at": datetime.now(UTC).isoformat(),
        "call_count": 0,
        "case_count": len(case_results),
        "passed_count": sum(item["passed"] for item in case_results),
        "passed": all(item["passed"] for item in case_results),
        "cases": case_results,
    }


async def run_live(
    cases: list[tuple[EngineeringEvidencePacket, HiddenExpectations]],
) -> dict:
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is required for the live engineering trial")
    model_id = os.getenv("LILTWEAK_MODEL", "gpt-5.6-luna")
    tweak = TweakEngineeringModel(model_id)
    case_results: list[dict] = []
    for packet, expectations in cases:
        before_calls = tweak.call_count
        try:
            result = await tweak.reason(packet)
            grades = grade_live_case(packet, expectations, result.analysis)
            one_call = tweak.call_count - before_calls == 1
            grades["one_call"] = one_call
            passed = all(grades.values())
            case_results.append(
                {
                    "case_id": packet.case_id,
                    "packet_digest": result.validation.packet_digest,
                    "output_digest": result.validation.analysis_digest,
                    "hypothesis_count": result.validation.hypothesis_count,
                    "change_count": result.validation.change_count,
                    "proof_test_count": result.validation.proof_test_count,
                    "grades": grades,
                    "passed": passed,
                }
            )
        except EngineeringContractError as exc:
            case_results.append(
                {
                    "case_id": packet.case_id,
                    "packet_digest": packet.digest,
                    "error": "contract_rejected",
                    "contract_error_codes": list(exc.codes) or ["invalid_structured_output"],
                    "passed": False,
                }
            )
        except EngineeringModelError:
            case_results.append(
                {
                    "case_id": packet.case_id,
                    "packet_digest": packet.digest,
                    "error": "provider_unavailable",
                    "passed": False,
                }
            )
    return {
        "schema_version": "1.0",
        "trial": "tweak-engineering-reasoning-v1",
        "mode": "live",
        "created_at": datetime.now(UTC).isoformat(),
        "model": tweak.identity,
        "foundation_model": tweak.foundation_model_id,
        "prompt_digest": tweak.prompt_digest,
        "call_count": tweak.call_count,
        "tool_count": 0,
        "handoff_count": 0,
        "case_count": len(case_results),
        "passed_count": sum(item["passed"] for item in case_results),
        "passed": (
            tweak.call_count == len(cases)
            and len(cases) == 3
            and all(item["passed"] for item in case_results)
        ),
        "cases": case_results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Lil Tweak engineering reasoning trial")
    parser.add_argument("--live", action="store_true", help="Use one paid model call per case")
    parser.add_argument("--output", type=Path, default=DEFAULT_RESULTS_PATH)
    args = parser.parse_args()

    cases = load_cases()
    result = asyncio.run(run_live(cases)) if args.live else run_offline(cases)
    write_result(args.output, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
