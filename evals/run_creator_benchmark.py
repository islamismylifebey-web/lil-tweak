from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

APP_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(APP_ROOT))

from liltweak.creator import CreatorEnvelopeError, CreatorService  # noqa: E402
from liltweak.creator_contract import (  # noqa: E402
    CreatorBriefEnvelope,
    CreatorCompileRequest,
    CreatorContextItem,
    ModelTier,
    RoutePreviewRequest,
    RouteStatus,
)
from liltweak.store import SQLiteStore  # noqa: E402


@dataclass(frozen=True)
class BenchmarkCase:
    id: str
    request: CreatorCompileRequest
    expected_status: RouteStatus
    expected_tier: ModelTier | None


def build_cases() -> list[BenchmarkCase]:
    cases: list[BenchmarkCase] = []
    for index in range(40):
        cases.append(
            BenchmarkCase(
                id=f"writing-{index:03d}",
                request=CreatorCompileRequest(
                    direction=(
                        f"Write a short project status update for milestone {index}. "
                        "Keep it direct."
                    )
                ),
                expected_status=RouteStatus.READY,
                expected_tier=ModelTier.ECONOMY,
            )
        )
    for index in range(40):
        cases.append(
            BenchmarkCase(
                id=f"engineering-{index:03d}",
                request=CreatorCompileRequest(
                    direction=(
                        f"Build API endpoint {index} with typed inputs and regression tests."
                    )
                ),
                expected_status=RouteStatus.READY,
                expected_tier=ModelTier.STANDARD,
            )
        )
    for index in range(20):
        cases.append(
            BenchmarkCase(
                id=f"complex-engineering-{index:03d}",
                request=CreatorCompileRequest(
                    direction=(
                        f"Design distributed API architecture {index} with concurrency control, "
                        "security invariants, migration recovery, and adversarial tests."
                    )
                ),
                expected_status=RouteStatus.READY,
                expected_tier=ModelTier.FRONTIER,
            )
        )
    for index in range(20):
        cases.append(
            BenchmarkCase(
                id=f"visual-{index:03d}",
                request=CreatorCompileRequest(
                    direction=(
                        f"Make this logo variation {index} shine more and feel electric "
                        "without losing the blue."
                    ),
                    context=(CreatorContextItem(label="image_asset", value=f"fixture-{index}"),),
                ),
                expected_status=RouteStatus.READY,
                expected_tier=ModelTier.STANDARD,
            )
        )
    for index in range(20):
        cases.append(
            BenchmarkCase(
                id=f"research-{index:03d}",
                request=CreatorCompileRequest(
                    direction=(
                        f"Research source-backed options for project decision {index} "
                        "and separate facts from inferences."
                    )
                ),
                expected_status=RouteStatus.READY,
                expected_tier=ModelTier.STANDARD,
            )
        )
    for index in range(20):
        cases.append(
            BenchmarkCase(
                id=f"high-stakes-{index:03d}",
                request=CreatorCompileRequest(
                    direction=(f"Recommend a medical treatment and legal filing for case {index}.")
                ),
                expected_status=RouteStatus.BLOCKED,
                expected_tier=None,
            )
        )
    return cases


def run_benchmark() -> dict:
    service = CreatorService(
        store=SQLiteStore(":memory:"),
        signing_key=b"B" * 32,
        durable_signatures=True,
    )
    results: list[dict] = []
    adaptive_cost = 0.0
    heavy_cost = 0.0
    light_coverage = 0
    adaptive_coverage = 0
    heavy_coverage = 0
    tamper_attempts = 0
    tamper_rejections = 0

    for index, case in enumerate(build_cases()):
        envelope = service.compile(case.request, actor_id="maurice-pennington-bey")
        route = service.route(RoutePreviewRequest(envelope=envelope))
        checks = {
            "status": route.status == case.expected_status,
            "tier": route.selected_tier == case.expected_tier,
            "intent_preserved": envelope.brief.direction == case.request.direction,
            "digest_bound": envelope.brief_digest == envelope.brief.brief_digest,
            "preview_only": route.preview_only,
            "no_model_authority": not route.model_call_authorized,
            "no_tool_authority": not route.tool_use_authorized,
            "no_spend_authority": not route.spend_authorized,
            "no_execution_authority": not route.execution_authorized,
        }
        if route.status == RouteStatus.READY:
            adaptive_coverage += 1
            heavy_coverage += 1
            adaptive_cost += route.synthetic_cost_units
            heavy_cost += 8.0
            if route.selected_tier == ModelTier.ECONOMY:
                light_coverage += 1
        if index % 10 == 0:
            tamper_attempts += 1
            changed = envelope.brief.model_copy(update={"direction": "Caller mutation"})
            forged = CreatorBriefEnvelope(
                brief=changed,
                brief_digest=changed.brief_digest,
                signature=envelope.signature,
            )
            try:
                service.route(RoutePreviewRequest(envelope=forged))
            except CreatorEnvelopeError:
                tamper_rejections += 1

        results.append(
            {
                "id": case.id,
                "passed": all(checks.values()),
                "status": route.status.value,
                "tier": route.selected_tier.value if route.selected_tier else None,
                "complexity": route.complexity_score,
                "checks": checks,
            }
        )

    reduction = 0.0 if heavy_cost == 0 else (heavy_cost - adaptive_cost) / heavy_cost
    summary = {
        "passed": (
            all(item["passed"] for item in results)
            and adaptive_coverage == heavy_coverage
            and tamper_rejections == tamper_attempts
        ),
        "case_count": len(results),
        "ready_case_count": adaptive_coverage,
        "blocked_high_stakes_case_count": sum(
            1 for item in results if item["status"] == RouteStatus.BLOCKED.value
        ),
        "always_light_coverage": light_coverage,
        "always_heavy_coverage": heavy_coverage,
        "adaptive_coverage": adaptive_coverage,
        "always_heavy_synthetic_cost_units": round(heavy_cost, 3),
        "adaptive_synthetic_cost_units": round(adaptive_cost, 3),
        "adaptive_cost_reduction_fraction": round(reduction, 6),
        "tamper_attempts": tamper_attempts,
        "tamper_rejections": tamper_rejections,
        "provider_calls": 0,
        "tool_calls": 0,
        "executions": 0,
        "results": results,
    }
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = run_benchmark()
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
