from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from liltweak.costs import BudgetExceededError
from liltweak.creator import CreatorService
from liltweak.creator_contract import (
    CreatorCompileRequest,
    ModelTier,
    RoutePreviewRequest,
)
from liltweak.live_contract import (
    CreatorWorkOrder,
    LiveModelUsage,
    LiveProposalDecisionRequest,
    LiveProposalPrepareRequest,
    LiveProposalStatus,
)
from liltweak.live_model import (
    LiveCreatorController,
    LiveModelApprovalError,
    LiveModelDisabledError,
    LiveModelProviderError,
    ProviderWorkOrder,
)
from liltweak.store import SQLiteStore, StoreStateConflictError

SIGNING_KEY = b"L" * 32


class FixtureProvider:
    def __init__(
        self,
        *,
        input_tokens: int = 800,
        output_tokens: int = 200,
        fail: bool = False,
    ) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.fail = fail
        self.calls = 0

    async def create_work_order(self, proposal, envelope) -> ProviderWorkOrder:
        del envelope
        self.calls += 1
        if self.fail:
            raise LiveModelProviderError("fixture provider failed")
        return ProviderWorkOrder(
            work_order=CreatorWorkOrder(
                functional_gap="The requested API behavior does not yet exist.",
                confirmed_facts=("A signed Creator brief was supplied.",),
                unknowns=("The target repository contents were not supplied.",),
                hypotheses=("A bounded API layer is the smallest useful intervention.",),
                smallest_intervention=(
                    "Add a typed API contract.",
                    "Add deterministic regression tests.",
                ),
                verification_checks=(
                    "The targeted tests pass.",
                    "No execution claim is made without observations.",
                ),
                stop_conditions=(
                    "Stop if the repository fingerprint changes.",
                    "Stop if exact approval is unavailable.",
                ),
                execution_required=True,
            ),
            usage=LiveModelUsage(
                requests=1,
                input_tokens=self.input_tokens,
                output_tokens=self.output_tokens,
                total_tokens=self.input_tokens + self.output_tokens,
            ),
            response_id="resp_fixture_123",
        )


def build_live_controller(
    path: Path | str = ":memory:",
    *,
    enabled: bool = True,
    provider: FixtureProvider | None = None,
    monthly_limit_usd: float = 5.0,
):
    store = SQLiteStore(path)
    creator = CreatorService(
        store=store,
        signing_key=SIGNING_KEY,
        durable_signatures=True,
    )
    provider = provider or FixtureProvider()
    controller = LiveCreatorController(
        creator=creator,
        store=store,
        signing_key=SIGNING_KEY,
        provider=provider,
        enabled=enabled,
        owner_id="owner",
        monthly_limit_usd=monthly_limit_usd,
        per_call_limit_usd=0.10,
    )
    envelope = creator.compile(
        CreatorCompileRequest(direction="Build a typed API and deterministic regression tests."),
        actor_id="owner",
    )
    route = creator.route(RoutePreviewRequest(envelope=envelope))
    return store, creator, controller, provider, envelope, route


def prepare_and_approve(controller, envelope, route):
    record = controller.prepare(LiveProposalPrepareRequest(envelope=envelope, route=route))
    decided, approval = controller.decide(
        record.proposal.id,
        LiveProposalDecisionRequest(
            decision="approve",
            proposal_digest=record.proposal.proposal_digest,
        ),
        actor_id="owner",
    )
    assert approval is not None
    assert decided.status == LiveProposalStatus.APPROVED
    return decided, approval


def test_live_proposal_is_least_cost_route_bound_and_non_authoritative() -> None:
    _store, _creator, controller, _provider, envelope, route = build_live_controller()
    record = controller.prepare(LiveProposalPrepareRequest(envelope=envelope, route=route))
    proposal = record.proposal
    assert route.selected_tier == ModelTier.STANDARD
    assert proposal.model == "gpt-5.6-terra"
    assert proposal.reasoning_effort == route.reasoning_effort
    assert proposal.cost_ceiling_usd <= 0.10
    assert proposal.max_turns == 1
    assert proposal.model_call_authorized is False
    assert proposal.spend_authorized is False
    assert proposal.tool_use_authorized is False
    assert proposal.execution_authorized is False


def test_live_controller_refuses_truncation_prone_output_budget() -> None:
    store = SQLiteStore(":memory:")
    creator = CreatorService(
        store=store,
        signing_key=SIGNING_KEY,
        durable_signatures=True,
    )
    with pytest.raises(ValueError, match="output token"):
        LiveCreatorController(
            creator=creator,
            store=store,
            signing_key=SIGNING_KEY,
            provider=FixtureProvider(),
            enabled=True,
            owner_id="owner",
            output_token_limit=1_023,
        )


def test_live_proposal_rejects_tampered_route() -> None:
    _store, _creator, controller, _provider, envelope, route = build_live_controller()
    tampered = route.model_copy(update={"context_token_ceiling": 1})
    with pytest.raises(Exception, match="route"):
        controller.prepare(LiveProposalPrepareRequest(envelope=envelope, route=tampered))


def test_live_approval_requires_exact_digest_and_founder() -> None:
    _store, _creator, controller, _provider, envelope, route = build_live_controller()
    record = controller.prepare(LiveProposalPrepareRequest(envelope=envelope, route=route))
    with pytest.raises(LiveModelApprovalError):
        controller.decide(
            record.proposal.id,
            LiveProposalDecisionRequest(
                decision="approve",
                proposal_digest="0" * 64,
            ),
            actor_id="owner",
        )
    with pytest.raises(LiveModelApprovalError):
        controller.decide(
            record.proposal.id,
            LiveProposalDecisionRequest(
                decision="approve",
                proposal_digest=record.proposal.proposal_digest,
            ),
            actor_id="caller-asserted-founder",
        )


@pytest.mark.asyncio
async def test_live_model_call_is_one_attempt_and_usage_reconciled() -> None:
    store, _creator, controller, provider, envelope, route = build_live_controller()
    record, approval = prepare_and_approve(controller, envelope, route)
    result = await controller.execute(
        proposal_id=record.proposal.id,
        approval_id=approval.id,
        envelope=envelope,
        route=route,
    )
    assert provider.calls == 1
    assert result.usage.requests == 1
    assert result.estimated_actual_cost_usd <= result.reserved_cost_usd
    assert result.model_call_observed is True
    assert result.tools_observed is False
    assert result.completion_claim_allowed is False
    assert result.execution_connected is False
    assert controller.get_proposal(record.proposal.id).status == LiveProposalStatus.SUCCEEDED
    assert controller.get_result(record.proposal.id).result_digest == result.result_digest
    assert store.creator_live_month_to_date_reserved("owner") == pytest.approx(
        result.reserved_cost_usd
    )
    with pytest.raises(StoreStateConflictError):
        await controller.execute(
            proposal_id=record.proposal.id,
            approval_id=approval.id,
            envelope=envelope,
            route=route,
        )
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_disabled_live_model_does_not_consume_approval() -> None:
    _store, _creator, controller, provider, envelope, route = build_live_controller(enabled=False)
    record, approval = prepare_and_approve(controller, envelope, route)
    with pytest.raises(LiveModelDisabledError):
        await controller.execute(
            proposal_id=record.proposal.id,
            approval_id=approval.id,
            envelope=envelope,
            route=route,
        )
    assert provider.calls == 0
    assert controller.get_proposal(record.proposal.id).status == LiveProposalStatus.APPROVED


@pytest.mark.asyncio
async def test_provider_failure_is_recorded_and_never_retried() -> None:
    provider = FixtureProvider(fail=True)
    _store, _creator, controller, _provider, envelope, route = build_live_controller(
        provider=provider
    )
    record, approval = prepare_and_approve(controller, envelope, route)
    with pytest.raises(LiveModelProviderError):
        await controller.execute(
            proposal_id=record.proposal.id,
            approval_id=approval.id,
            envelope=envelope,
            route=route,
        )
    failed = controller.get_proposal(record.proposal.id)
    assert failed.status == LiveProposalStatus.FAILED
    assert failed.failure_code == "provider_or_validation_failure"
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_usage_overrun_fails_closed_after_one_call() -> None:
    provider = FixtureProvider(input_tokens=12_001)
    _store, _creator, controller, _provider, envelope, route = build_live_controller(
        provider=provider
    )
    record, approval = prepare_and_approve(controller, envelope, route)
    with pytest.raises(LiveModelProviderError, match="input usage"):
        await controller.execute(
            proposal_id=record.proposal.id,
            approval_id=approval.id,
            envelope=envelope,
            route=route,
        )
    assert controller.get_proposal(record.proposal.id).status == LiveProposalStatus.FAILED
    assert provider.calls == 1


def test_live_approval_decision_is_atomic_across_connections(tmp_path: Path) -> None:
    database = tmp_path / "live.db"
    _store, _creator, controller, _provider, envelope, route = build_live_controller(database)
    record = controller.prepare(LiveProposalPrepareRequest(envelope=envelope, route=route))
    digest = record.proposal.proposal_digest
    controllers = [
        controller,
        *[build_live_controller(database)[2] for _ in range(7)],
    ]
    barrier = Barrier(len(controllers))

    def decide(candidate: LiveCreatorController) -> str:
        barrier.wait()
        try:
            decided, _approval = candidate.decide(
                record.proposal.id,
                LiveProposalDecisionRequest(
                    decision="approve",
                    proposal_digest=digest,
                ),
                actor_id="owner",
            )
            return decided.status.value
        except StoreStateConflictError:
            return "conflict"

    with ThreadPoolExecutor(max_workers=len(controllers)) as pool:
        outcomes = list(pool.map(decide, controllers))
    assert outcomes.count(LiveProposalStatus.APPROVED.value) == 1
    assert outcomes.count("conflict") == len(controllers) - 1


def test_live_monthly_admission_is_atomic_across_connections(tmp_path: Path) -> None:
    database = tmp_path / "live-budget.db"
    shared_provider = FixtureProvider()
    builds = [
        build_live_controller(
            database,
            provider=shared_provider,
            monthly_limit_usd=0.05,
        )
        for _ in range(2)
    ]
    runs = []
    for _store, _creator, controller, _provider, envelope, route in builds:
        record, approval = prepare_and_approve(controller, envelope, route)
        runs.append((controller, record, approval, envelope, route))
    barrier = Barrier(len(runs))

    def execute(candidate) -> str:
        controller, record, approval, envelope, route = candidate
        barrier.wait()
        try:
            asyncio.run(
                controller.execute(
                    proposal_id=record.proposal.id,
                    approval_id=approval.id,
                    envelope=envelope,
                    route=route,
                )
            )
            return "succeeded"
        except BudgetExceededError as exc:
            assert "budget" in str(exc)
            return "budget_blocked"

    with ThreadPoolExecutor(max_workers=len(runs)) as pool:
        outcomes = list(pool.map(execute, runs))
    assert outcomes.count("succeeded") == 1
    assert outcomes.count("budget_blocked") == 1
    assert shared_provider.calls == 1


def test_async_runtime_has_no_implicit_retry() -> None:
    _store, _creator, controller, provider, envelope, route = build_live_controller()
    record, approval = prepare_and_approve(controller, envelope, route)
    result = asyncio.run(
        controller.execute(
            proposal_id=record.proposal.id,
            approval_id=approval.id,
            envelope=envelope,
            route=route,
        )
    )
    assert result.usage.requests == 1
    assert provider.calls == 1
