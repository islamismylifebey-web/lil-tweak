from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier

import pytest

from liltweak.creator import CreatorService, outcome_digest_for_fixture
from liltweak.creator_contract import (
    CommandKind,
    CreatorCompileRequest,
    RoutePreviewRequest,
    RuntimeOutcome,
    SandboxCommand,
    SandboxResult,
)
from liltweak.creator_runtime import (
    CreatorRuntimeController,
    DisconnectedSandboxExecutor,
    ExecutionApprovalError,
    SandboxUnavailableError,
    observation,
)
from liltweak.store import SQLiteStore

SIGNING_KEY = b"X" * 32


class FixtureExecutor:
    connected = True

    def __init__(self, *, fail_test: bool = False, network_used: bool = False) -> None:
        self.fail_test = fail_test
        self.network_used = network_used
        self.calls = 0

    async def execute(self, plan) -> SandboxResult:
        self.calls += 1
        observations = []
        for command in plan.commands:
            exit_code = 1 if self.fail_test and command.kind == CommandKind.TEST else 0
            observations.append(
                observation(
                    command.command_id,
                    exit_code=exit_code,
                    stdout_label=f"{command.command_id}:{exit_code}",
                )
            )
        return SandboxResult(
            plan_digest=plan.plan_digest,
            session_id="fixture-sandbox",
            source_before_digest=plan.repository_fingerprint,
            source_after_digest=outcome_digest_for_fixture("source-after"),
            observations=tuple(observations),
            artifact_digests=(outcome_digest_for_fixture("patch"),),
            artifact_bytes=128,
            credential_finding_count=0,
            network_used=self.network_used,
            sandbox_isolated=True,
        )


def build_runtime(path: Path | str = ":memory:"):
    store = SQLiteStore(path)
    creator = CreatorService(
        store=store,
        signing_key=SIGNING_KEY,
        durable_signatures=True,
    )
    runtime = CreatorRuntimeController(
        creator=creator,
        store=store,
        signing_key=SIGNING_KEY,
    )
    envelope = creator.compile(
        CreatorCompileRequest(direction="Build an API and run regression tests."),
        actor_id="owner",
    )
    route = creator.route(RoutePreviewRequest(envelope=envelope))
    plan = runtime.prepare_plan(
        envelope=envelope,
        route=route,
        repository_fingerprint=outcome_digest_for_fixture("source-before"),
        workspace_mount_digest=outcome_digest_for_fixture("mount"),
        commands=(
            SandboxCommand(
                command_id="baseline",
                kind=CommandKind.BASELINE,
                argv=("pytest", "-q"),
                timeout_seconds=300,
            ),
            SandboxCommand(
                command_id="targeted",
                kind=CommandKind.TEST,
                argv=("pytest", "-q", "tests/test_target.py"),
                timeout_seconds=300,
            ),
        ),
        allowed_write_paths=("src", "tests"),
    )
    return store, runtime, plan


def test_execution_plan_is_bounded_and_does_not_grant_itself_authority() -> None:
    _store, _runtime, plan = build_runtime()
    assert plan.execution_authorized is False
    assert plan.network_allowed is False
    assert plan.secrets_in_manifest is False
    assert plan.wall_clock_seconds == 900
    assert plan.allowed_write_paths == ("src", "tests")
    assert plan.plan_digest


@pytest.mark.asyncio
async def test_disconnected_runner_fails_without_execution() -> None:
    _store, runtime, plan = build_runtime()
    approval = runtime.authority.approve(plan, approved_by="owner")
    with pytest.raises(SandboxUnavailableError):
        await runtime.execute(plan, approval, DisconnectedSandboxExecutor())


@pytest.mark.asyncio
async def test_verified_runtime_success_requires_all_observed_checks() -> None:
    _store, runtime, plan = build_runtime()
    approval = runtime.authority.approve(plan, approved_by="owner")
    executor = FixtureExecutor()
    outcome = await runtime.execute(plan, approval, executor)
    assert isinstance(outcome, RuntimeOutcome)
    assert executor.calls == 1
    assert outcome.outcome == "verified_success"
    assert outcome.verification.verified is True
    assert outcome.verification.completion_claim_allowed is True
    assert outcome.verification.required_check_count == 2
    assert outcome.verification.passed_required_check_count == 2


@pytest.mark.asyncio
async def test_failed_check_blocks_completion_claim() -> None:
    _store, runtime, plan = build_runtime()
    approval = runtime.authority.approve(plan, approved_by="owner")
    outcome = await runtime.execute(plan, approval, FixtureExecutor(fail_test=True))
    assert outcome.outcome == "verified_failure"
    assert outcome.verification.verified is False
    assert outcome.verification.completion_claim_allowed is False
    assert "required_check_failed:targeted" in outcome.verification.failure_codes


@pytest.mark.asyncio
async def test_unapproved_network_use_fails_verification() -> None:
    _store, runtime, plan = build_runtime()
    approval = runtime.authority.approve(plan, approved_by="owner")
    outcome = await runtime.execute(plan, approval, FixtureExecutor(network_used=True))
    assert outcome.verification.verified is False
    assert "unexpected_network_use" in outcome.verification.failure_codes


@pytest.mark.asyncio
async def test_execution_approval_is_exact_digest_and_one_attempt() -> None:
    _store, runtime, plan = build_runtime()
    approval = runtime.authority.approve(plan, approved_by="owner")
    await runtime.execute(plan, approval, FixtureExecutor())
    with pytest.raises(ExecutionApprovalError):
        await runtime.execute(plan, approval, FixtureExecutor())


@pytest.mark.asyncio
async def test_changed_plan_rejects_prior_approval() -> None:
    _store, runtime, plan = build_runtime()
    approval = runtime.authority.approve(plan, approved_by="owner")
    changed = plan.model_copy(update={"memory_megabytes": 4_096})
    with pytest.raises(ExecutionApprovalError):
        await runtime.execute(changed, approval, FixtureExecutor())


def test_execution_approval_consumption_is_atomic_across_connections(
    tmp_path: Path,
) -> None:
    database = tmp_path / "runtime.db"
    first_store, runtime, plan = build_runtime(database)
    approval = runtime.authority.approve(plan, approved_by="owner")
    stores = [first_store, *[SQLiteStore(database) for _ in range(15)]]
    barrier = Barrier(len(stores))
    consumed_at = (approval.created_at + timedelta(seconds=1)).isoformat()

    def consume(store: SQLiteStore) -> bool:
        barrier.wait()
        return store.consume_creator_execution_approval(
            approval_id=approval.id,
            plan_digest=plan.plan_digest,
            signature=approval.signature,
            consumed_at=consumed_at,
        )

    with ThreadPoolExecutor(max_workers=len(stores)) as pool:
        outcomes = list(pool.map(consume, stores))
    assert outcomes.count(True) == 1
    assert outcomes.count(False) == len(stores) - 1


def test_runtime_does_not_depend_on_event_loop_side_effects() -> None:
    _store, runtime, plan = build_runtime()
    approval = runtime.authority.approve(plan, approved_by="owner")
    result = asyncio.run(runtime.execute(plan, approval, FixtureExecutor()))
    assert result.verification.verified is True
