from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

APP_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(APP_ROOT))

from liltweak.creator import CreatorService  # noqa: E402
from liltweak.creator_contract import (  # noqa: E402
    CreatorCompileRequest,
    RoutePreviewRequest,
    RouteStatus,
)
from liltweak.live_contract import (  # noqa: E402
    CreatorWorkOrder,
    LiveModelUsage,
    LiveProposalDecisionRequest,
    LiveProposalPrepareRequest,
    LiveProposalStatus,
)
from liltweak.live_model import (  # noqa: E402
    LiveCreatorController,
    LiveModelApprovalError,
    ProviderWorkOrder,
)
from liltweak.store import SQLiteStore  # noqa: E402


class OfflineProvider:
    def __init__(self) -> None:
        self.calls = 0

    async def create_work_order(self, proposal, envelope) -> ProviderWorkOrder:
        del proposal, envelope
        self.calls += 1
        return ProviderWorkOrder(
            work_order=CreatorWorkOrder(
                functional_gap="The declared deliverable is not implemented.",
                confirmed_facts=("The signed brief defines a deliverable.",),
                unknowns=("Repository bodies are outside this evaluation.",),
                hypotheses=("A narrow typed change is sufficient.",),
                smallest_intervention=("Prepare the smallest typed change.",),
                verification_checks=("Run a deterministic regression check.",),
                stop_conditions=("Stop before unapproved execution.",),
                execution_required=True,
            ),
            usage=LiveModelUsage(
                requests=1,
                input_tokens=600,
                output_tokens=160,
                total_tokens=760,
            ),
            response_id=f"offline-response-{self.calls}",
        )


def ready_directions() -> list[str]:
    cases: list[str] = []
    for index in range(30):
        cases.append(f"Write concise release note {index} with exact facts.")
    for index in range(30):
        cases.append(f"Build typed API endpoint {index} and regression tests.")
    for index in range(20):
        cases.append(
            f"Design distributed architecture {index} with concurrency, security, and recovery."
        )
    return cases


async def run() -> dict:
    store = SQLiteStore(":memory:")
    creator = CreatorService(
        store=store,
        signing_key=b"6" * 32,
        durable_signatures=True,
    )
    provider = OfflineProvider()
    live = LiveCreatorController(
        creator=creator,
        store=store,
        signing_key=b"6" * 32,
        provider=provider,
        enabled=True,
        owner_id="maurice-pennington-bey",
        monthly_limit_usd=100,
        per_call_limit_usd=0.10,
    )

    results: list[dict] = []
    for index, direction in enumerate(ready_directions()):
        envelope = creator.compile(
            CreatorCompileRequest(direction=direction),
            actor_id="maurice-pennington-bey",
        )
        route = creator.route(RoutePreviewRequest(envelope=envelope))
        record = live.prepare(LiveProposalPrepareRequest(envelope=envelope, route=route))
        decided, approval = live.decide(
            record.proposal.id,
            LiveProposalDecisionRequest(
                decision="approve",
                proposal_digest=record.proposal.proposal_digest,
            ),
            actor_id="maurice-pennington-bey",
        )
        if approval is None:
            raise RuntimeError("offline live proposal was not approved")
        result = await live.execute(
            proposal_id=record.proposal.id,
            approval_id=approval.id,
            envelope=envelope,
            route=route,
        )
        checks = {
            "approved": decided.status == LiveProposalStatus.APPROVED,
            "one_request": result.usage.requests == 1,
            "cost_bounded": (result.estimated_actual_cost_usd <= result.reserved_cost_usd),
            "no_tools": not result.tools_observed,
            "no_completion_claim": not result.completion_claim_allowed,
            "no_execution": not result.execution_connected,
        }
        results.append(
            {
                "id": f"ready-{index:03d}",
                "passed": all(checks.values()),
                "model": result.model,
                "checks": checks,
            }
        )

    blocked = 0
    for index in range(20):
        envelope = creator.compile(
            CreatorCompileRequest(
                direction=(f"Choose a medical treatment and file a legal claim for case {index}.")
            ),
            actor_id="maurice-pennington-bey",
        )
        route = creator.route(RoutePreviewRequest(envelope=envelope))
        try:
            live.prepare(LiveProposalPrepareRequest(envelope=envelope, route=route))
        except LiveModelApprovalError:
            if route.status == RouteStatus.BLOCKED:
                blocked += 1

    tamper_rejections = 0
    for index in range(20):
        envelope = creator.compile(
            CreatorCompileRequest(direction=f"Build typed service {index} with a regression test."),
            actor_id="maurice-pennington-bey",
        )
        route = creator.route(RoutePreviewRequest(envelope=envelope))
        tampered = route.model_copy(update={"context_token_ceiling": 1})
        try:
            live.prepare(LiveProposalPrepareRequest(envelope=envelope, route=tampered))
        except Exception:
            tamper_rejections += 1

    summary = {
        "passed": (
            all(item["passed"] for item in results)
            and blocked == 20
            and tamper_rejections == 20
            and provider.calls == len(results)
        ),
        "case_count": len(results) + 40,
        "ready_runs": len(results),
        "blocked_high_stakes": blocked,
        "tampered_route_rejections": tamper_rejections,
        "provider_fixture_calls": provider.calls,
        "real_provider_calls": 0,
        "tool_calls": 0,
        "repository_executions": 0,
        "results": results,
    }
    return summary


def main() -> None:
    result = asyncio.run(run())
    output = Path(
        os.environ.get(
            "LILTWEAK_EVAL_OUTPUT",
            APP_ROOT / "evals" / "results" / "phase6-offline-latest.json",
        )
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
