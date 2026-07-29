from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from httpx import ASGITransport, AsyncClient

from liltweak.agent import DeterministicPlanner
from liltweak.api import create_app
from liltweak.config import Settings
from liltweak.costs import CostGuard
from liltweak.creator import CreatorService
from liltweak.creator_contract import (
    CommandKind,
    CreatorCompileRequest,
    RoutePreviewRequest,
    SandboxCommand,
    content_digest,
)
from liltweak.execution_contract import (
    ExecutionDecisionRequest,
    ExecutionPrepareRequest,
    ExecutionRecipe,
    ExecutionStatus,
    ProcessObservation,
    RunnerAttestation,
    SandboxExecutionEvidence,
    SandboxProfile,
)
from liltweak.execution_plane import (
    ExecutionRecipeRegistry,
    RepositoryExecutionApprovalError,
    RepositoryExecutionController,
    RepositoryExecutionDisabledError,
    RepositoryExecutionError,
    RepositoryExecutionProviderError,
)
from liltweak.models import Environment, RepositoryRef, TaskCreate
from liltweak.repository import RepositoryInspector
from liltweak.service import LilTweakService
from liltweak.source_snapshot import RepositorySnapshotBuilder
from liltweak.store import SQLiteStore, StoreStateConflictError
from tests.repository_helpers import initialize_repository

SIGNING_KEY = b"7" * 32
IMAGE = "registry.invalid/liltweak-python@sha256:" + ("b" * 64)
RUNTIME_DIGEST = hashlib.sha256(b"bubblewrap").hexdigest()
LIMITER_DIGEST = hashlib.sha256(b"prlimit").hexdigest()


class FixtureExecutor:
    connected = True

    def __init__(
        self,
        *,
        reverse_observations: bool = False,
        source_changed: bool = False,
        profile_drift: bool = False,
        output_bytes: int | None = None,
        attempt_nonce_mismatch: bool = False,
        on_execute: Callable[[], None] | None = None,
    ) -> None:
        self.reverse_observations = reverse_observations
        self.source_changed = source_changed
        self.profile_drift = profile_drift
        self.output_bytes = output_bytes
        self.attempt_nonce_mismatch = attempt_nonce_mismatch
        self.on_execute = on_execute
        self.calls = 0
        self.profile_calls = 0

    def profile_for(self, recipe: ExecutionRecipe) -> SandboxProfile:
        self.profile_calls += 1
        return SandboxProfile(
            runtime_sha256=(
                hashlib.sha256(b"drifted-runtime").hexdigest()
                if self.profile_drift and self.profile_calls > 1
                else RUNTIME_DIGEST
            ),
            limiter_sha256=LIMITER_DIGEST,
            image_ref=recipe.image_ref,
            container_user=recipe.container_user,
        )

    async def execute(self, *, plan, recipe, reference) -> SandboxExecutionEvidence:
        del reference
        self.calls += 1
        observations = [
            ProcessObservation(
                command_id=command.command_id,
                exit_code=0,
                stdout_digest=hashlib.sha256(command.command_id.encode()).hexdigest(),
                stderr_digest=hashlib.sha256(b"").hexdigest(),
                stdout_bytes=(
                    self.output_bytes if self.output_bytes is not None else len(command.command_id)
                ),
                stderr_bytes=0,
                duration_ms=5,
            )
            for command in recipe.commands
        ]
        if self.reverse_observations:
            observations.reverse()
        profile = self.profile_for(recipe)
        evidence = SandboxExecutionEvidence(
            plan_digest=plan.plan_digest,
            session_id="fixture-phase7-sandbox",
            source_before_digest=plan.source.tree_digest,
            source_after_digest=(
                hashlib.sha256(b"changed").hexdigest()
                if self.source_changed
                else plan.source.tree_digest
            ),
            observations=tuple(observations),
            attestation=RunnerAttestation(
                attempt_nonce=(
                    hashlib.sha256(b"wrong-attempt-nonce").hexdigest()
                    if self.attempt_nonce_mismatch
                    else plan.attempt_nonce
                ),
                runtime_sha256=profile.runtime_sha256,
                limiter_sha256=profile.limiter_sha256,
                sandbox_profile_digest=profile.profile_digest,
                image_ref=profile.image_ref,
                cleanup_verified=True,
            ),
        )
        if self.on_execute is not None:
            self.on_execute()
        return evidence


class DisconnectedFixtureExecutor(FixtureExecutor):
    connected = False


def trusted_recipe() -> ExecutionRecipe:
    return ExecutionRecipe(
        recipe_id="python-verify",
        image_ref=IMAGE,
        commands=(
            SandboxCommand(
                command_id="lint",
                kind=CommandKind.LINT,
                argv=("ruff", "check", "."),
                timeout_seconds=60,
            ),
            SandboxCommand(
                command_id="tests",
                kind=CommandKind.TEST,
                argv=("pytest", "-q"),
                timeout_seconds=60,
            ),
        ),
        output_byte_limit=1_024,
    )


def build_controller(
    tmp_path: Path,
    *,
    executor: FixtureExecutor | None = None,
    database: Path | str = ":memory:",
):
    repository, commit = initialize_repository(tmp_path)
    reference = RepositoryRef(
        provider="local",
        repository_id="fixture",
        revision=commit,
    )
    inspector = RepositoryInspector(
        tmp_path,
        repository_mappings={"local:fixture": repository.name},
    )
    store = SQLiteStore(database)
    service = LilTweakService(
        store=store,
        planner=DeterministicPlanner(),
        cost_guard=CostGuard(monthly_limit_usd=250, job_default_limit_usd=5),
        repository_inspector=inspector,
        owner_id="owner",
        evidence_signing_key=SIGNING_KEY,
    )
    task = TaskCreate(
        task_id="phase7-task",
        requested_by="owner",
        organization_id="org-1",
        project_id="project-1",
        repository=reference,
        environment=Environment.DEVELOPMENT,
        objective="Run the trusted offline verification recipe.",
        execution_permission=False,
    )
    job = service.create_job(task, "phase7-job-idempotency")
    job = service.inspect_job(job.id)
    creator = CreatorService(
        store=store,
        signing_key=SIGNING_KEY,
        durable_signatures=True,
    )
    fixture_executor = executor or FixtureExecutor()
    controller = RepositoryExecutionController(
        service=service,
        creator=creator,
        store=store,
        inspector=inspector,
        snapshot_builder=RepositorySnapshotBuilder(inspector),
        executor=fixture_executor,
        recipes=ExecutionRecipeRegistry({"python-verify": trusted_recipe()}),
        signing_key=SIGNING_KEY,
        owner_id="owner",
        enabled=True,
    )
    envelope = creator.compile(
        CreatorCompileRequest(
            direction="Run the exact offline lint and test recipe on this repository."
        ),
        actor_id="owner",
    )
    route = creator.route(RoutePreviewRequest(envelope=envelope))
    request = ExecutionPrepareRequest(
        job_id=job.id,
        recipe_id="python-verify",
        expected_repository_fingerprint=job.inspection.repository_fingerprint,
        envelope=envelope,
        route=route,
    )
    return store, service, controller, fixture_executor, request


@pytest.mark.asyncio
async def test_repository_execution_requires_exact_approval_and_verifies_once(
    tmp_path: Path,
) -> None:
    _store, _service, controller, executor, request = build_controller(tmp_path)
    pending = controller.prepare(request, idempotency_key="phase7-prepare-key")
    duplicate = controller.prepare(request, idempotency_key="phase7-prepare-key")
    assert duplicate.plan.id == pending.plan.id
    assert pending.status == ExecutionStatus.PENDING_APPROVAL
    assert pending.plan.source_read_only is True
    assert pending.plan.network_allowed is False
    assert pending.plan.execution_authorized is False

    decision = controller.decide(
        pending.plan.id,
        ExecutionDecisionRequest(
            decision="approve",
            plan_digest=pending.plan.plan_digest,
        ),
        actor_id="owner",
    )
    assert decision.approval is not None
    completed = await controller.run(
        pending.plan.id,
        approval_id=decision.approval.id,
    )
    assert completed.status == ExecutionStatus.SUCCEEDED
    assert completed.attempt_count == 1
    assert executor.calls == 1
    result = controller.get_result(pending.plan.id)
    assert result.verification.verified is True
    assert result.verification.completion_claim_allowed is True

    with pytest.raises(RepositoryExecutionApprovalError, match="approved state"):
        await controller.run(pending.plan.id, approval_id=decision.approval.id)
    assert executor.calls == 1


@pytest.mark.asyncio
async def test_repository_execution_result_signature_is_verified_on_read(
    tmp_path: Path,
) -> None:
    store, _service, controller, _executor, request = build_controller(tmp_path)
    pending = controller.prepare(request, idempotency_key="phase7-result-integrity-key")
    decision = controller.decide(
        pending.plan.id,
        ExecutionDecisionRequest(
            decision="approve",
            plan_digest=pending.plan.plan_digest,
        ),
        actor_id="owner",
    )
    await controller.run(pending.plan.id, approval_id=decision.approval.id)
    row = store._connection.execute(
        """
        SELECT result_json
        FROM creator_repository_execution_results
        WHERE execution_id = ?
        """,
        (pending.plan.id,),
    ).fetchone()
    payload = json.loads(row["result_json"])
    payload["verifier_signature"] = "0" * 64
    store._connection.execute(
        """
        UPDATE creator_repository_execution_results
        SET verifier_signature = ?, result_json = ?
        WHERE execution_id = ?
        """,
        ("0" * 64, json.dumps(payload), pending.plan.id),
    )
    store._connection.commit()
    with pytest.raises(RepositoryExecutionError, match="integrity"):
        controller.get_result(pending.plan.id)


@pytest.mark.asyncio
async def test_store_rejects_semantically_contradictory_outcome(
    tmp_path: Path,
) -> None:
    store, _service, controller, _executor, request = build_controller(tmp_path)
    pending = controller.prepare(request, idempotency_key="phase7-outcome-semantics-key")
    decision = controller.decide(
        pending.plan.id,
        ExecutionDecisionRequest(
            decision="approve",
            plan_digest=pending.plan.plan_digest,
        ),
        actor_id="owner",
    )
    await controller.run(pending.plan.id, approval_id=decision.approval.id)
    valid = controller.get_result(pending.plan.id)
    changed = valid.model_copy(update={"status": "verified_failure"})
    contradictory = changed.model_copy(
        update={
            "outcome_digest": content_digest(
                changed.model_dump(
                    mode="json",
                    exclude={"outcome_digest", "verifier_signature"},
                )
            )
        }
    )
    with pytest.raises(ValueError, match="contradicts"):
        store.complete_repository_execution(
            contradictory,
            now=valid.created_at,
        )


def test_prepare_retry_returns_original_plan_after_source_drift(tmp_path: Path) -> None:
    _store, service, controller, _executor, request = build_controller(tmp_path)
    pending = controller.prepare(request, idempotency_key="phase7-drift-retry-key")
    reference = service.get_job(request.job_id).task.repository
    repository = controller.inspector.registered_path(reference)
    (repository / "src" / "app.py").write_text("drifted = True\n", encoding="utf-8")

    duplicate = controller.prepare(request, idempotency_key="phase7-drift-retry-key")
    assert duplicate.plan.id == pending.plan.id
    with pytest.raises(RepositoryExecutionError, match="eligible"):
        controller.prepare(request, idempotency_key="phase7-drift-new-key")


@pytest.mark.asyncio
async def test_untrusted_observation_order_or_source_change_fails_closed(
    tmp_path: Path,
) -> None:
    executor = FixtureExecutor(reverse_observations=True, source_changed=True)
    _store, _service, controller, _executor, request = build_controller(
        tmp_path,
        executor=executor,
    )
    pending = controller.prepare(request, idempotency_key="phase7-failure-key")
    decision = controller.decide(
        pending.plan.id,
        ExecutionDecisionRequest(
            decision="approve",
            plan_digest=pending.plan.plan_digest,
        ),
        actor_id="owner",
    )
    completed = await controller.run(
        pending.plan.id,
        approval_id=decision.approval.id,
    )
    assert completed.status == ExecutionStatus.FAILED
    result = controller.get_result(pending.plan.id)
    assert result.verification.completion_claim_allowed is False
    assert "source_after_mismatch" in result.verification.failure_codes
    assert "command_observation_order_mismatch" in result.verification.failure_codes


@pytest.mark.asyncio
async def test_disconnected_runner_does_not_consume_approval(tmp_path: Path) -> None:
    executor = DisconnectedFixtureExecutor()
    _store, _service, controller, _executor, request = build_controller(
        tmp_path,
        executor=executor,
    )
    pending = controller.prepare(request, idempotency_key="phase7-disconnected-key")
    decision = controller.decide(
        pending.plan.id,
        ExecutionDecisionRequest(
            decision="approve",
            plan_digest=pending.plan.plan_digest,
        ),
        actor_id="owner",
    )
    with pytest.raises(RepositoryExecutionDisabledError):
        await controller.run(pending.plan.id, approval_id=decision.approval.id)
    assert controller.get(pending.plan.id).attempt_count == 0


@pytest.mark.asyncio
async def test_profile_drift_after_approval_consumes_attempt_and_fails(
    tmp_path: Path,
) -> None:
    executor = FixtureExecutor(profile_drift=True)
    _store, _service, controller, _executor, request = build_controller(
        tmp_path,
        executor=executor,
    )
    pending = controller.prepare(request, idempotency_key="phase7-profile-drift-key")
    decision = controller.decide(
        pending.plan.id,
        ExecutionDecisionRequest(
            decision="approve",
            plan_digest=pending.plan.plan_digest,
        ),
        actor_id="owner",
    )
    with pytest.raises(RepositoryExecutionProviderError):
        await controller.run(pending.plan.id, approval_id=decision.approval.id)
    failed = controller.get(pending.plan.id)
    assert failed.status == ExecutionStatus.FAILED
    assert failed.attempt_count == 1
    assert executor.calls == 0


@pytest.mark.asyncio
async def test_post_claim_recipe_failure_cannot_leave_execution_running(
    tmp_path: Path,
) -> None:
    _store, _service, controller, _executor, request = build_controller(tmp_path)
    pending = controller.prepare(request, idempotency_key="phase7-recipe-drift-key")
    decision = controller.decide(
        pending.plan.id,
        ExecutionDecisionRequest(
            decision="approve",
            plan_digest=pending.plan.plan_digest,
        ),
        actor_id="owner",
    )
    replacement = trusted_recipe().model_copy(update={"recipe_id": "replacement"})
    controller.recipes = ExecutionRecipeRegistry({"replacement": replacement})
    with pytest.raises(RepositoryExecutionProviderError):
        await controller.run(pending.plan.id, approval_id=decision.approval.id)
    failed = controller.get(pending.plan.id)
    assert failed.status == ExecutionStatus.FAILED
    assert failed.attempt_count == 1


@pytest.mark.asyncio
async def test_output_overflow_fails_verification_even_if_runner_denies_it(
    tmp_path: Path,
) -> None:
    executor = FixtureExecutor(output_bytes=1_025)
    _store, _service, controller, _executor, request = build_controller(
        tmp_path,
        executor=executor,
    )
    pending = controller.prepare(request, idempotency_key="phase7-output-overflow-key")
    decision = controller.decide(
        pending.plan.id,
        ExecutionDecisionRequest(
            decision="approve",
            plan_digest=pending.plan.plan_digest,
        ),
        actor_id="owner",
    )
    completed = await controller.run(
        pending.plan.id,
        approval_id=decision.approval.id,
    )
    assert completed.status == ExecutionStatus.FAILED
    result = controller.get_result(pending.plan.id)
    assert "command_stream_output_exceeded:lint" in result.verification.failure_codes
    assert "aggregate_command_output_exceeded" in result.verification.failure_codes


@pytest.mark.asyncio
async def test_cancellation_between_verification_and_completion_blocks_success(
    tmp_path: Path,
) -> None:
    store, _service, controller, _executor, request = build_controller(tmp_path)
    pending = controller.prepare(request, idempotency_key="phase7-cancel-race-key")
    decision = controller.decide(
        pending.plan.id,
        ExecutionDecisionRequest(
            decision="approve",
            plan_digest=pending.plan.plan_digest,
        ),
        actor_id="owner",
    )
    original_verify = controller.verifier.verify

    def verify_then_cancel(**kwargs):
        verification = original_verify(**kwargs)
        store.set_job_cancel_requested(pending.plan.job_id)
        return verification

    controller.verifier.verify = verify_then_cancel
    completed = await controller.run(
        pending.plan.id,
        approval_id=decision.approval.id,
    )
    assert completed.status == ExecutionStatus.CANCELED
    assert completed.failure_code == "job_canceled"


@pytest.mark.asyncio
async def test_attempt_nonce_mismatch_fails_verification(tmp_path: Path) -> None:
    executor = FixtureExecutor(attempt_nonce_mismatch=True)
    _store, _service, controller, _executor, request = build_controller(
        tmp_path,
        executor=executor,
    )
    pending = controller.prepare(request, idempotency_key="phase7-nonce-mismatch-key")
    decision = controller.decide(
        pending.plan.id,
        ExecutionDecisionRequest(
            decision="approve",
            plan_digest=pending.plan.plan_digest,
        ),
        actor_id="owner",
    )
    completed = await controller.run(
        pending.plan.id,
        approval_id=decision.approval.id,
    )
    assert completed.status == ExecutionStatus.FAILED
    assert (
        "attempt_nonce_mismatch"
        in controller.get_result(pending.plan.id).verification.failure_codes
    )


@pytest.mark.asyncio
async def test_verifier_failure_after_claim_cannot_leave_execution_running(
    tmp_path: Path,
) -> None:
    _store, _service, controller, _executor, request = build_controller(tmp_path)
    pending = controller.prepare(request, idempotency_key="phase7-verifier-failure-key")
    decision = controller.decide(
        pending.plan.id,
        ExecutionDecisionRequest(
            decision="approve",
            plan_digest=pending.plan.plan_digest,
        ),
        actor_id="owner",
    )

    def fail_verification(**_kwargs):
        raise RuntimeError("simulated verifier failure")

    controller.verifier.verify = fail_verification
    with pytest.raises(RepositoryExecutionProviderError):
        await controller.run(pending.plan.id, approval_id=decision.approval.id)
    failed = controller.get(pending.plan.id)
    assert failed.status == ExecutionStatus.FAILED
    assert failed.attempt_count == 1


@pytest.mark.asyncio
async def test_completion_failure_after_claim_cannot_leave_execution_running(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _service, controller, _executor, request = build_controller(tmp_path)
    pending = controller.prepare(request, idempotency_key="phase7-completion-failure-key")
    decision = controller.decide(
        pending.plan.id,
        ExecutionDecisionRequest(
            decision="approve",
            plan_digest=pending.plan.plan_digest,
        ),
        actor_id="owner",
    )

    def fail_completion(*_args, **_kwargs):
        raise RuntimeError("simulated completion failure")

    monkeypatch.setattr(store, "complete_repository_execution", fail_completion)
    with pytest.raises(RepositoryExecutionProviderError):
        await controller.run(pending.plan.id, approval_id=decision.approval.id)
    failed = controller.get(pending.plan.id)
    assert failed.status == ExecutionStatus.FAILED
    assert failed.attempt_count == 1


def test_repository_execution_claim_is_atomic_across_workers(tmp_path: Path) -> None:
    database = tmp_path / "state" / "phase7.db"
    store, _service, controller, _executor, request = build_controller(
        tmp_path / "workspace",
        database=database,
    )
    pending = controller.prepare(request, idempotency_key="phase7-race-key")
    decision = controller.decide(
        pending.plan.id,
        ExecutionDecisionRequest(
            decision="approve",
            plan_digest=pending.plan.plan_digest,
        ),
        actor_id="owner",
    )
    signature = controller._sign_plan(pending.plan.plan_digest)
    stores = [store, *[SQLiteStore(database) for _ in range(15)]]
    barrier = Barrier(len(stores))

    def claim(candidate: SQLiteStore) -> bool:
        barrier.wait()
        try:
            candidate.claim_repository_execution(
                execution_id=pending.plan.id,
                approval_id=decision.approval.id,
                plan_digest=pending.plan.plan_digest,
                approval_signature=signature,
                now=pending.plan.created_at,
            )
            return True
        except StoreStateConflictError:
            return False

    with ThreadPoolExecutor(max_workers=len(stores)) as pool:
        outcomes = list(pool.map(claim, stores))
    assert outcomes.count(True) == 1
    assert outcomes.count(False) == len(stores) - 1


def test_pending_expiry_and_approved_cancellation_reconcile_truthfully(
    tmp_path: Path,
) -> None:
    store, _service, controller, _executor, request = build_controller(tmp_path)
    expiring = controller.prepare(request, idempotency_key="phase7-expiry-key")
    expired = store.reconcile_repository_execution(
        expiring.plan.id,
        now=expiring.plan.expires_at,
    )
    assert expired.status == ExecutionStatus.EXPIRED
    assert expired.failure_code == "plan_expired"

    approved = controller.prepare(request, idempotency_key="phase7-cancel-state-key")
    controller.decide(
        approved.plan.id,
        ExecutionDecisionRequest(
            decision="approve",
            plan_digest=approved.plan.plan_digest,
        ),
        actor_id="owner",
    )
    store.set_job_cancel_requested(approved.plan.job_id)
    canceled = controller.get(approved.plan.id)
    assert canceled.status == ExecutionStatus.CANCELED
    assert canceled.failure_code == "job_canceled"


@pytest.mark.asyncio
@pytest.mark.parametrize("terminal_state", ["expired", "canceled"])
async def test_terminal_execution_run_stops_before_snapshot_or_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal_state: str,
) -> None:
    store, _service, controller, executor, request = build_controller(tmp_path)
    pending = controller.prepare(
        request,
        idempotency_key=f"phase7-terminal-{terminal_state}-key",
    )
    approval_id = "no-approval"
    if terminal_state == "expired":
        store.reconcile_repository_execution(
            pending.plan.id,
            now=pending.plan.expires_at,
        )
    else:
        decision = controller.decide(
            pending.plan.id,
            ExecutionDecisionRequest(
                decision="approve",
                plan_digest=pending.plan.plan_digest,
            ),
            actor_id="owner",
        )
        approval_id = decision.approval.id
        store.set_job_cancel_requested(pending.plan.job_id)

    snapshot_calls = 0

    def fail_if_snapshot_called(_reference):
        nonlocal snapshot_calls
        snapshot_calls += 1
        raise AssertionError("terminal execution must not rebuild a snapshot")

    monkeypatch.setattr(
        controller.snapshot_builder,
        "prepare_manifest",
        fail_if_snapshot_called,
    )
    with pytest.raises(RepositoryExecutionApprovalError, match="approved state"):
        await controller.run(pending.plan.id, approval_id=approval_id)
    assert snapshot_calls == 0
    assert executor.calls == 0
    assert executor.profile_calls == 1


@pytest.mark.asyncio
async def test_repository_execution_api_is_authenticated_and_caller_cannot_add_commands(
    tmp_path: Path,
) -> None:
    _store, service, controller, executor, request = build_controller(tmp_path)
    settings = Settings(
        environment="test",
        database_path=Path(":memory:"),
        dev_api_key="phase7-api-secret",
        auth_disabled=False,
        model="test-model",
        monthly_budget_usd=250,
        job_hard_limit_usd=5,
        owner_id="owner",
        artifact_root=tmp_path / "api-artifacts",
        creator_signing_key=SIGNING_KEY,
        repository_execution_enabled=True,
        execution_runtime_root=tmp_path / "api-runtime",
        execution_image_ref=IMAGE,
        workspace_root=tmp_path / "api-workspace",
    )
    app = create_app(
        service=service,
        settings=settings,
        creator_service=controller.creator,
        execution_controller=controller,
    )
    auth = {"Authorization": "Bearer phase7-api-secret"}
    body = request.model_dump(mode="json")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        unauthorized = await client.post(
            "/v1/creator/executions",
            headers={"Idempotency-Key": "phase7-api-key-unauthorized"},
            json=body,
        )
        assert unauthorized.status_code == 401

        caller_commands = dict(body)
        caller_commands["commands"] = [["sh", "-c", "anything"]]
        rejected = await client.post(
            "/v1/creator/executions",
            headers={**auth, "Idempotency-Key": "phase7-api-key-rejected"},
            json=caller_commands,
        )
        assert rejected.status_code == 422

        prepared = await client.post(
            "/v1/creator/executions",
            headers={**auth, "Idempotency-Key": "phase7-api-key-approved"},
            json=body,
        )
        assert prepared.status_code == 202
        pending = prepared.json()
        decision = await client.post(
            f"/v1/creator/executions/{pending['plan']['id']}/decision",
            headers=auth,
            json={
                "decision": "approve",
                "plan_digest": pending["plan"]["plan_digest"],
            },
        )
        assert decision.status_code == 200
        approval_id = decision.json()["approval"]["id"]
        completed = await client.post(
            f"/v1/creator/executions/{pending['plan']['id']}/run",
            headers=auth,
            json={"approval_id": approval_id},
        )
        assert completed.status_code == 200
        assert completed.json()["status"] == "succeeded"
        result = await client.get(
            f"/v1/creator/executions/{pending['plan']['id']}/result",
            headers=auth,
        )
        assert result.status_code == 200
        assert result.json()["verification"]["verified"] is True
        assert executor.calls == 1


@pytest.mark.asyncio
async def test_repository_execution_api_obeys_configuration_kill_switch(
    tmp_path: Path,
) -> None:
    _store, service, controller, _executor, request = build_controller(tmp_path)
    pending = controller.prepare(request, idempotency_key="phase7-kill-switch-existing")
    settings = Settings(
        environment="test",
        database_path=Path(":memory:"),
        dev_api_key="phase7-api-secret",
        auth_disabled=False,
        model="test-model",
        monthly_budget_usd=250,
        job_hard_limit_usd=5,
        owner_id="owner",
        repository_execution_enabled=False,
    )
    app = create_app(
        service=service,
        settings=settings,
        creator_service=controller.creator,
        execution_controller=controller,
    )
    auth = {"Authorization": "Bearer phase7-api-secret"}
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        health = await client.get("/v1/creator/health", headers=auth)
        readable = await client.get(
            f"/v1/creator/executions/{pending.plan.id}",
            headers=auth,
        )
        blocked = await client.post(
            "/v1/creator/executions",
            headers={**auth, "Idempotency-Key": "phase7-kill-switch-block"},
            json=request.model_dump(mode="json"),
        )
    assert health.json()["execution_connected"] is False
    assert readable.status_code == 200
    assert blocked.status_code == 503


@pytest.mark.asyncio
async def test_repository_execution_api_returns_controlled_conflict_for_source_drift(
    tmp_path: Path,
) -> None:
    _store, service, controller, _executor, request = build_controller(tmp_path)
    settings = Settings(
        environment="test",
        database_path=Path(":memory:"),
        dev_api_key="phase7-api-secret",
        auth_disabled=False,
        model="test-model",
        monthly_budget_usd=250,
        job_hard_limit_usd=5,
        owner_id="owner",
        artifact_root=tmp_path / "drift-api-artifacts",
        creator_signing_key=SIGNING_KEY,
        repository_execution_enabled=True,
        execution_runtime_root=tmp_path / "drift-api-runtime",
        execution_image_ref=IMAGE,
        workspace_root=tmp_path / "drift-api-workspace",
    )
    reference = service.get_job(request.job_id).task.repository
    repository = controller.inspector.registered_path(reference)
    (repository / "src" / "app.py").write_text("drifted = True\n", encoding="utf-8")
    app = create_app(
        service=service,
        settings=settings,
        creator_service=controller.creator,
        execution_controller=controller,
    )
    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/v1/creator/executions",
            headers={
                "Authorization": "Bearer phase7-api-secret",
                "Idempotency-Key": "phase7-source-drift-api",
            },
            json=request.model_dump(mode="json"),
        )
    assert response.status_code == 409
    assert response.json() == {
        "detail": "registered source is not eligible for repository verification"
    }
