from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import sys
from pathlib import Path

APP_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(APP_ROOT))

from liltweak.creator import CreatorService  # noqa: E402
from liltweak.creator_contract import CreatorCompileRequest, RoutePreviewRequest  # noqa: E402
from liltweak.hosted_sandbox import OpenAIHostedSandboxProbe  # noqa: E402
from liltweak.live_contract import (  # noqa: E402
    LiveProposalDecisionRequest,
    LiveProposalPrepareRequest,
)
from liltweak.live_model import (  # noqa: E402
    LiveCreatorController,
    OpenAICreatorModelProvider,
)
from liltweak.store import SQLiteStore  # noqa: E402


async def run(
    *,
    approved_model_ceiling_usd: float,
    approved_sandbox_ceiling_usd: float,
) -> dict:
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is required for the Phase 6 live evaluation")
    if approved_model_ceiling_usd != 0.05:
        raise RuntimeError("the live model evaluation ceiling must be exactly $0.05")
    if approved_sandbox_ceiling_usd not in {0.0, 0.04}:
        raise RuntimeError("the hosted sandbox ceiling must be exactly $0.00 or $0.04")
    signing_key = secrets.token_bytes(32)
    store = SQLiteStore(":memory:")
    creator = CreatorService(
        store=store,
        signing_key=signing_key,
        durable_signatures=False,
    )
    live = LiveCreatorController(
        creator=creator,
        store=store,
        signing_key=signing_key,
        provider=OpenAICreatorModelProvider(),
        enabled=True,
        owner_id="maurice-pennington-bey",
        monthly_limit_usd=0.05,
        per_call_limit_usd=approved_model_ceiling_usd,
        input_token_limit=6_000,
        output_token_limit=1_024,
    )
    envelope = creator.compile(
        CreatorCompileRequest(
            direction=(
                "Analyze a synthetic Python API defect: duplicate requests can create two "
                "records. Produce the smallest evidence-backed work order and falsifying "
                "regression checks. Do not claim execution."
            )
        ),
        actor_id="maurice-pennington-bey",
    )
    route = creator.route(RoutePreviewRequest(envelope=envelope))
    proposal_record = live.prepare(LiveProposalPrepareRequest(envelope=envelope, route=route))
    proposal = proposal_record.proposal
    if proposal.cost_ceiling_usd > approved_model_ceiling_usd:
        raise RuntimeError("generated live proposal exceeds the approved evaluation ceiling")
    _decided, approval = live.decide(
        proposal.id,
        LiveProposalDecisionRequest(
            decision="approve",
            proposal_digest=proposal.proposal_digest,
        ),
        actor_id="maurice-pennington-bey",
    )
    if approval is None:
        raise RuntimeError("live evaluation approval was not created")
    work_order_result = await live.execute(
        proposal_id=proposal.id,
        approval_id=approval.id,
        envelope=envelope,
        route=route,
    )

    sandbox_result = None
    if approved_sandbox_ceiling_usd:
        sandbox = OpenAIHostedSandboxProbe()
        if approved_sandbox_ceiling_usd < sandbox.APPROVED_COST_CEILING_USD:
            raise RuntimeError("hosted sandbox probe exceeds the approved evaluation ceiling")
        sandbox_result = await sandbox.run(approved=True)
    passed = (
        work_order_result.usage.requests == 1
        and work_order_result.estimated_actual_cost_usd <= work_order_result.reserved_cost_usd
        and not work_order_result.tools_observed
        and not work_order_result.completion_claim_allowed
        and not work_order_result.execution_connected
        and (
            sandbox_result is None
            or (
                sandbox_result.verified
                and not sandbox_result.real_source_uploaded
                and not sandbox_result.repository_execution_connected
            )
        )
    )
    summary = {
        "passed": passed,
        "live_work_order": {
            "model": work_order_result.model,
            "work_order_digest": work_order_result.work_order.work_order_digest,
            "proposal_digest": work_order_result.proposal_digest,
            "usage": work_order_result.usage.model_dump(mode="json"),
            "reserved_cost_usd": work_order_result.reserved_cost_usd,
            "estimated_actual_cost_usd": (work_order_result.estimated_actual_cost_usd),
            "tools_observed": work_order_result.tools_observed,
            "completion_claim_allowed": (work_order_result.completion_claim_allowed),
            "execution_connected": work_order_result.execution_connected,
        },
        "hosted_sandbox_probe": (
            sandbox_result.model_dump(mode="json")
            if sandbox_result is not None
            else {"status": "not_run", "reason": "no additional sandbox spend approved"}
        ),
        "approved_combined_ceiling_usd": (
            approved_model_ceiling_usd + approved_sandbox_ceiling_usd
        ),
        "real_source_uploaded": False,
        "repository_execution_connected": False,
        "phase6_complete": sandbox_result is not None and sandbox_result.verified,
    }
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--approve-model-ceiling-usd", type=float, required=True)
    parser.add_argument("--approve-sandbox-ceiling-usd", type=float, required=True)
    args = parser.parse_args()
    result = asyncio.run(
        run(
            approved_model_ceiling_usd=args.approve_model_ceiling_usd,
            approved_sandbox_ceiling_usd=args.approve_sandbox_ceiling_usd,
        )
    )
    output = APP_ROOT / "evals" / "results" / "phase6-live-latest.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
