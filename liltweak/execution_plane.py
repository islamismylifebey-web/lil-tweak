from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Literal, Protocol

from .creator import CreatorEnvelopeError, CreatorService
from .creator_contract import RoutePreviewRequest, RouteStatus, content_digest
from .execution_contract import (
    ExecutionDecisionRequest,
    ExecutionDecisionResponse,
    ExecutionOutcomeRecord,
    ExecutionPrepareRequest,
    ExecutionRecipe,
    ExecutionRecord,
    ExecutionStatus,
    ExecutionVerification,
    RepositoryExecutionApproval,
    RepositoryExecutionPlan,
    SandboxExecutionEvidence,
    SandboxProfile,
)
from .models import RepositoryRef
from .repository import RepositoryInspector
from .service import LilTweakService
from .source_snapshot import RepositorySnapshotBuilder, SourceSnapshotError
from .store import SQLiteStore, StoreStateConflictError


class RepositoryExecutionError(RuntimeError):
    pass


class RepositoryExecutionDisabledError(RepositoryExecutionError):
    pass


class RepositoryExecutionApprovalError(RepositoryExecutionError):
    pass


class RepositoryExecutionProviderError(RepositoryExecutionError):
    pass


class RepositorySandboxExecutor(Protocol):
    @property
    def connected(self) -> bool: ...

    def profile_for(self, recipe: ExecutionRecipe) -> SandboxProfile: ...

    async def execute(
        self,
        *,
        plan: RepositoryExecutionPlan,
        recipe: ExecutionRecipe,
        reference: RepositoryRef,
    ) -> SandboxExecutionEvidence: ...


class ExecutionRecipeRegistry:
    def __init__(self, recipes: Mapping[str, ExecutionRecipe]) -> None:
        if not recipes:
            raise ValueError("at least one trusted execution recipe is required")
        copied = dict(recipes)
        for key, recipe in copied.items():
            if key != recipe.recipe_id:
                raise ValueError("execution recipe registry key does not match its recipe")
        self._recipes = MappingProxyType(copied)

    def get(self, recipe_id: str) -> ExecutionRecipe:
        try:
            return self._recipes[recipe_id]
        except KeyError as exc:
            raise RepositoryExecutionError("trusted execution recipe is not registered") from exc


class RepositoryVerificationGate:
    def verify(
        self,
        *,
        plan: RepositoryExecutionPlan,
        evidence: SandboxExecutionEvidence,
        profile: SandboxProfile,
        canceled: bool,
        emergency_stopped: bool,
    ) -> ExecutionVerification:
        failures: list[str] = []
        if evidence.plan_digest != plan.plan_digest:
            failures.append("plan_digest_mismatch")
        if evidence.source_before_digest != plan.source.tree_digest:
            failures.append("source_before_mismatch")
        if evidence.source_after_digest != plan.source.tree_digest:
            failures.append("source_after_mismatch")
        if evidence.source_after_digest != evidence.source_before_digest:
            failures.append("source_changed_during_execution")
        attestation = evidence.attestation
        if attestation.attempt_nonce != plan.attempt_nonce:
            failures.append("attempt_nonce_mismatch")
        if profile.profile_digest != plan.sandbox_profile_digest:
            failures.append("approved_sandbox_profile_mismatch")
        if attestation.sandbox_profile_digest != profile.profile_digest:
            failures.append("sandbox_profile_mismatch")
        if attestation.runtime_sha256 != profile.runtime_sha256:
            failures.append("sandbox_runtime_mismatch")
        if attestation.limiter_sha256 != profile.limiter_sha256:
            failures.append("sandbox_limiter_mismatch")
        if attestation.image_ref != plan.image_ref:
            failures.append("sandbox_image_mismatch")
        if not attestation.cleanup_verified:
            failures.append("sandbox_cleanup_unverified")
        if evidence.artifact_count or evidence.artifact_bytes:
            failures.append("unexpected_execution_artifact")
        if canceled:
            failures.append("job_canceled")
        if emergency_stopped:
            failures.append("emergency_stop_active")

        expected_ids = [command.command_id for command in plan.commands]
        observed_ids = [observation.command_id for observation in evidence.observations]
        if observed_ids != expected_ids:
            failures.append("command_observation_order_mismatch")
        if len(observed_ids) != len(set(observed_ids)):
            failures.append("duplicate_command_observation")

        observations = {item.command_id: item for item in evidence.observations}
        required = [command for command in plan.commands if command.required]
        if not required:
            failures.append("no_required_checks")
        passed = 0
        aggregate_duration_ms = 0
        aggregate_output_bytes = 0
        evidence_digests: list[str] = [attestation.attestation_digest]
        for command in plan.commands:
            observed = observations.get(command.command_id)
            if observed is None:
                if command.required:
                    failures.append(f"missing_required_check:{command.command_id}")
                continue
            evidence_digests.extend((observed.stdout_digest, observed.stderr_digest))
            aggregate_duration_ms += observed.duration_ms
            aggregate_output_bytes += observed.stdout_bytes + observed.stderr_bytes
            if observed.duration_ms > command.timeout_seconds * 1_000 + 1_000:
                failures.append(f"command_duration_exceeded:{command.command_id}")
            if (
                observed.stdout_bytes > plan.output_byte_limit
                or observed.stderr_bytes > plan.output_byte_limit
            ):
                failures.append(f"command_stream_output_exceeded:{command.command_id}")
            if observed.timed_out:
                failures.append(f"command_timed_out:{command.command_id}")
            if observed.output_limit_exceeded:
                failures.append(f"command_output_limit_exceeded:{command.command_id}")
            if command.required:
                if observed.exit_code == 0 and not observed.timed_out:
                    passed += 1
                else:
                    failures.append(f"required_check_failed:{command.command_id}")
        if aggregate_duration_ms > plan.wall_clock_seconds * 1_000 + 1_000:
            failures.append("aggregate_command_duration_exceeded")
        if aggregate_output_bytes > plan.output_byte_limit:
            failures.append("aggregate_command_output_exceeded")
        verified = not failures and passed == len(required)
        return ExecutionVerification(
            verified=verified,
            completion_claim_allowed=verified,
            required_check_count=len(required),
            passed_required_check_count=passed,
            evidence_digests=tuple(dict.fromkeys(evidence_digests)),
            failure_codes=tuple(dict.fromkeys(failures)),
        )


class RepositoryExecutionController:
    def __init__(
        self,
        *,
        service: LilTweakService,
        creator: CreatorService,
        store: SQLiteStore,
        inspector: RepositoryInspector,
        snapshot_builder: RepositorySnapshotBuilder,
        executor: RepositorySandboxExecutor,
        recipes: ExecutionRecipeRegistry,
        signing_key: bytes,
        owner_id: str,
        enabled: bool = False,
    ) -> None:
        if len(signing_key) != 32:
            raise ValueError("repository execution signing key must contain exactly 32 bytes")
        self.service = service
        self.creator = creator
        self.store = store
        self.inspector = inspector
        self.snapshot_builder = snapshot_builder
        self.executor = executor
        self.recipes = recipes
        self._key = signing_key
        self.owner_id = owner_id
        self.enabled = enabled
        self.verifier = RepositoryVerificationGate()

    @property
    def connected(self) -> bool:
        return self.enabled and self.executor.connected

    def prepare(
        self,
        request: ExecutionPrepareRequest,
        *,
        idempotency_key: str,
    ) -> ExecutionRecord:
        self._require_enabled()
        route = request.route
        submitted_digest = content_digest(
            route.model_dump(mode="json", exclude={"decision_digest"})
        )
        if not self._digests_match(route.decision_digest, submitted_digest):
            raise CreatorEnvelopeError("route decision digest is invalid")
        verified_route = self.creator.route(RoutePreviewRequest(envelope=request.envelope))
        if not self._digests_match(route.decision_digest, verified_route.decision_digest):
            raise CreatorEnvelopeError("route decision is not bound to the signed brief")
        if verified_route.status != RouteStatus.READY:
            raise RepositoryExecutionError("creator route is not ready for repository execution")

        job = self.service.get_job(request.job_id)
        reference = job.task.repository
        inspection = job.inspection
        if reference is None or inspection is None:
            raise RepositoryExecutionError("repository execution requires an inspected job")
        if (
            inspection.repository_fingerprint != request.expected_repository_fingerprint
            or not inspection.complete
            or not inspection.read_only_verified
        ):
            raise RepositoryExecutionError("job inspection is incomplete or no longer matches")
        request_hash = content_digest(request.model_dump(mode="json"))
        existing = self.store.get_repository_execution_by_idempotency(
            organization_id=job.task.organization_id,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
        )
        if existing is not None:
            return existing
        recipe = self.recipes.get(request.recipe_id)
        try:
            profile = self.executor.profile_for(recipe)
        except Exception as exc:
            raise RepositoryExecutionDisabledError(
                "repository isolation profile is unavailable"
            ) from exc
        try:
            source = self.snapshot_builder.prepare_manifest(reference)
        except SourceSnapshotError as exc:
            raise RepositoryExecutionError(
                "registered source is not eligible for repository verification"
            ) from exc
        if source.repository_fingerprint != request.expected_repository_fingerprint:
            raise RepositoryExecutionError("registered source changed after job inspection")

        created_at = datetime.now(UTC)
        execution_id = f"repo_exec_{uuid.uuid4().hex}"
        workspace_mount_digest = content_digest(
            {
                "source_manifest_digest": source.manifest_digest,
                "sandbox_profile_digest": profile.profile_digest,
                "recipe_digest": recipe.recipe_digest,
            }
        )
        expires_at = created_at + timedelta(minutes=15)
        attempt_nonce = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        unsigned = RepositoryExecutionPlan.model_construct(
            id=execution_id,
            job_id=job.id,
            organization_id=job.task.organization_id,
            project_id=job.task.project_id,
            brief_digest=request.envelope.brief_digest,
            route_digest=verified_route.decision_digest,
            recipe_id=recipe.recipe_id,
            recipe_digest=recipe.recipe_digest,
            source=source,
            sandbox_profile_digest=profile.profile_digest,
            workspace_mount_digest=workspace_mount_digest,
            image_ref=recipe.image_ref,
            commands=recipe.commands,
            wall_clock_seconds=recipe.wall_clock_seconds,
            memory_megabytes=recipe.memory_megabytes,
            cpu_count=recipe.cpu_count,
            pid_limit=recipe.pid_limit,
            file_size_limit_bytes=recipe.file_size_limit_bytes,
            output_byte_limit=recipe.output_byte_limit,
            created_at=created_at,
            expires_at=expires_at,
            attempt_nonce=attempt_nonce,
            plan_digest="0" * 64,
        )
        plan = RepositoryExecutionPlan(
            id=execution_id,
            job_id=job.id,
            organization_id=job.task.organization_id,
            project_id=job.task.project_id,
            brief_digest=request.envelope.brief_digest,
            route_digest=verified_route.decision_digest,
            recipe_id=recipe.recipe_id,
            recipe_digest=recipe.recipe_digest,
            source=source,
            sandbox_profile_digest=profile.profile_digest,
            workspace_mount_digest=workspace_mount_digest,
            image_ref=recipe.image_ref,
            commands=recipe.commands,
            wall_clock_seconds=recipe.wall_clock_seconds,
            memory_megabytes=recipe.memory_megabytes,
            cpu_count=recipe.cpu_count,
            pid_limit=recipe.pid_limit,
            file_size_limit_bytes=recipe.file_size_limit_bytes,
            output_byte_limit=recipe.output_byte_limit,
            created_at=created_at,
            expires_at=expires_at,
            attempt_nonce=attempt_nonce,
            plan_digest=content_digest(unsigned.model_dump(mode="json", exclude={"plan_digest"})),
        )
        record = ExecutionRecord(plan=plan, status=ExecutionStatus.PENDING_APPROVAL)
        return self.store.publish_repository_execution(
            record,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
        )

    def get(self, execution_id: str) -> ExecutionRecord:
        return self.store.reconcile_repository_execution(
            execution_id,
            now=datetime.now(UTC),
        )

    def decide(
        self,
        execution_id: str,
        request: ExecutionDecisionRequest,
        *,
        actor_id: str,
    ) -> ExecutionDecisionResponse:
        self._require_enabled()
        if actor_id != self.owner_id:
            raise RepositoryExecutionApprovalError(
                "only the configured Founder may decide repository execution"
            )
        record = self.store.reconcile_repository_execution(
            execution_id,
            now=datetime.now(UTC),
        )
        approval = None
        if request.decision == "approve":
            if request.plan_digest != record.plan.plan_digest:
                raise RepositoryExecutionApprovalError(
                    "repository execution approval digest does not match"
                )
            created_at = datetime.now(UTC)
            approval = RepositoryExecutionApproval(
                id=f"repo_exec_approval_{uuid.uuid4().hex}",
                execution_id=record.plan.id,
                job_id=record.plan.job_id,
                plan_digest=record.plan.plan_digest,
                approved_by=actor_id,
                signature=self._sign_plan(record.plan.plan_digest),
                created_at=created_at,
                expires_at=min(record.plan.expires_at, created_at + timedelta(minutes=15)),
            )
        decided, approval = self.store.decide_repository_execution(
            execution_id=execution_id,
            plan_digest=request.plan_digest,
            decision=request.decision,
            approval=approval,
            now=datetime.now(UTC),
        )
        return ExecutionDecisionResponse(record=decided, approval=approval)

    async def run(
        self,
        execution_id: str,
        *,
        approval_id: str,
    ) -> ExecutionRecord:
        self._require_enabled()
        record = self.store.reconcile_repository_execution(
            execution_id,
            now=datetime.now(UTC),
        )
        if record.status != ExecutionStatus.APPROVED:
            raise RepositoryExecutionApprovalError(
                "repository execution is not in an approved state"
            )
        if not self.executor.connected:
            raise RepositoryExecutionDisabledError(
                "repository isolation is not independently qualified and connected"
            )
        if record.approval_id != approval_id:
            raise RepositoryExecutionApprovalError(
                "repository execution approval does not match the plan"
            )
        reference = self.service.get_job(record.plan.job_id).task.repository
        if reference is None:
            raise RepositoryExecutionError("repository execution job lost its source binding")
        try:
            current = await asyncio.to_thread(
                self.snapshot_builder.prepare_manifest,
                reference,
            )
        except SourceSnapshotError as exc:
            raise RepositoryExecutionError(
                "registered source no longer matches the approved execution"
            ) from exc
        if current.model_dump(mode="json") != record.plan.source.model_dump(mode="json"):
            raise RepositoryExecutionError("registered source changed after execution approval")
        approval = self._approval_from_store(record, approval_id)
        self.store.claim_repository_execution(
            execution_id=execution_id,
            approval_id=approval_id,
            plan_digest=record.plan.plan_digest,
            approval_signature=approval.signature,
            now=datetime.now(UTC),
        )
        try:
            recipe = self.recipes.get(record.plan.recipe_id)
            profile = self.executor.profile_for(recipe)
            if (
                recipe.recipe_digest != record.plan.recipe_digest
                or recipe.commands != record.plan.commands
                or recipe.image_ref != record.plan.image_ref
                or profile.profile_digest != record.plan.sandbox_profile_digest
            ):
                raise RepositoryExecutionError("trusted execution inputs changed after approval")
            evidence = await self.executor.execute(
                plan=record.plan,
                recipe=recipe,
                reference=reference,
            )
            verification = self.verifier.verify(
                plan=record.plan,
                evidence=evidence,
                profile=profile,
                canceled=self.store.is_job_cancel_requested(record.plan.job_id),
                emergency_stopped=self.store.is_emergency_stopped(),
            )
            outcome = self._signed_outcome(record.plan, evidence, verification)
            return self.store.complete_repository_execution(
                outcome,
                now=datetime.now(UTC),
            )
        except asyncio.CancelledError:
            self._fail_claimed_attempt(execution_id)
            raise
        except Exception as exc:
            self._fail_claimed_attempt(execution_id)
            raise RepositoryExecutionProviderError(
                "repository sandbox attempt failed and will not be retried"
            ) from exc

    def get_result(self, execution_id: str) -> ExecutionOutcomeRecord:
        record = self.store.get_repository_execution(execution_id)
        outcome = self.store.get_repository_execution_result(execution_id)
        expected_signature = hmac.new(
            self._key,
            f"phase7-execution-outcome-v1:{outcome.outcome_digest}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        if (
            outcome.execution_id != execution_id
            or outcome.plan_digest != record.plan.plan_digest
            or record.result_digest != outcome.outcome_digest
            or not secrets.compare_digest(outcome.verifier_signature, expected_signature)
        ):
            raise RepositoryExecutionError(
                "repository execution result integrity verification failed"
            )
        return outcome

    def _approval_from_store(
        self,
        record: ExecutionRecord,
        approval_id: str,
    ) -> RepositoryExecutionApproval:
        # The public store API intentionally returns no approval row. Recreate only the
        # deterministic signature input; the atomic store claim verifies the persisted row.
        signature = self._sign_plan(record.plan.plan_digest)
        return RepositoryExecutionApproval(
            id=approval_id,
            execution_id=record.plan.id,
            job_id=record.plan.job_id,
            plan_digest=record.plan.plan_digest,
            approved_by=self.owner_id,
            signature=signature,
            created_at=record.plan.created_at,
            expires_at=record.plan.expires_at,
        )

    def _fail_claimed_attempt(self, execution_id: str) -> None:
        try:
            self.store.fail_repository_execution(
                execution_id,
                failure_code="sandbox_attempt_failed",
                now=datetime.now(UTC),
            )
        except StoreStateConflictError:
            # A concurrent terminal transition is never overwritten.
            return

    def _signed_outcome(
        self,
        plan: RepositoryExecutionPlan,
        evidence: SandboxExecutionEvidence,
        verification: ExecutionVerification,
    ) -> ExecutionOutcomeRecord:
        created_at = datetime.now(UTC)
        status: Literal["verified_success", "verified_failure"] = (
            "verified_success" if verification.verified else "verified_failure"
        )
        unsigned = ExecutionOutcomeRecord.model_construct(
            execution_id=plan.id,
            plan_digest=plan.plan_digest,
            status=status,
            evidence=evidence,
            verification=verification,
            created_at=created_at,
            outcome_digest="0" * 64,
            verifier_signature="0" * 64,
        )
        digest = content_digest(
            unsigned.model_dump(
                mode="json",
                exclude={"outcome_digest", "verifier_signature"},
            )
        )
        signature = hmac.new(
            self._key,
            f"phase7-execution-outcome-v1:{digest}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return ExecutionOutcomeRecord(
            execution_id=plan.id,
            plan_digest=plan.plan_digest,
            status=status,
            evidence=evidence,
            verification=verification,
            created_at=created_at,
            outcome_digest=digest,
            verifier_signature=signature,
        )

    def _sign_plan(self, plan_digest: str) -> str:
        return hmac.new(
            self._key,
            f"phase7-execution-plan-v1:{plan_digest}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def _require_enabled(self) -> None:
        if not self.enabled:
            raise RepositoryExecutionDisabledError(
                "repository execution is disabled by server configuration"
            )

    @staticmethod
    def _digests_match(first: object, second: object) -> bool:
        return (
            isinstance(first, str)
            and isinstance(second, str)
            and first.isascii()
            and second.isascii()
            and secrets.compare_digest(first, second)
        )
