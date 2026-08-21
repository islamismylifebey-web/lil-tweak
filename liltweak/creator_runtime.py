from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Protocol

from .creator import CreatorEnvelopeError, CreatorService
from .creator_contract import (
    CommandObservation,
    CreatorBriefEnvelope,
    ExecutionApproval,
    ExecutionPlan,
    RouteDecision,
    RoutePreviewRequest,
    RouteStatus,
    RuntimeOutcome,
    SandboxCommand,
    SandboxResult,
    VerificationReport,
    content_digest,
)
from .store import SQLiteStore


class SandboxUnavailableError(RuntimeError):
    pass


class ExecutionApprovalError(RuntimeError):
    pass


def _digests_match(first: object, second: object) -> bool:
    return (
        isinstance(first, str)
        and isinstance(second, str)
        and first.isascii()
        and second.isascii()
        and secrets.compare_digest(first, second)
    )


class SandboxExecutor(Protocol):
    connected: bool

    async def execute(self, plan: ExecutionPlan) -> SandboxResult: ...


class DisconnectedSandboxExecutor:
    connected = False

    async def execute(self, plan: ExecutionPlan) -> SandboxResult:
        del plan
        raise SandboxUnavailableError("isolated execution runner is not connected")


class VerificationGate:
    def verify(self, plan: ExecutionPlan, result: SandboxResult) -> VerificationReport:
        failures: list[str] = []
        if result.plan_digest != plan.plan_digest:
            failures.append("plan_digest_mismatch")
        if result.source_before_digest != plan.repository_fingerprint:
            failures.append("source_before_mismatch")
        if not result.sandbox_isolated:
            failures.append("sandbox_isolation_unverified")
        if result.network_used and not plan.network_allowed:
            failures.append("unexpected_network_use")
        if result.credential_finding_count:
            failures.append("credential_material_detected")
        if result.artifact_bytes > plan.artifact_byte_limit:
            failures.append("artifact_limit_exceeded")

        observation_ids = [item.command_id for item in result.observations]
        if len(observation_ids) != len(set(observation_ids)):
            failures.append("duplicate_command_observation")
        observations = {item.command_id: item for item in result.observations}
        required = [item for item in plan.commands if item.required]
        passed = 0
        evidence_digests: list[str] = []
        for command in required:
            observed = observations.get(command.command_id)
            if observed is None:
                failures.append(f"missing_required_check:{command.command_id}")
                continue
            evidence_digests.extend((observed.stdout_digest, observed.stderr_digest))
            if observed.exit_code == 0:
                passed += 1
            else:
                failures.append(f"required_check_failed:{command.command_id}")

        verified = not failures and passed == len(required)
        return VerificationReport(
            plan_digest=plan.plan_digest,
            verified=verified,
            required_check_count=len(required),
            passed_required_check_count=passed,
            evidence_digests=tuple(dict.fromkeys(evidence_digests)),
            failure_codes=tuple(dict.fromkeys(failures)),
            completion_claim_allowed=verified,
        )


class ExecutionAuthority:
    """Trusted control-plane approval issuer. It is not part of the public API."""

    def __init__(self, *, store: SQLiteStore, signing_key: bytes) -> None:
        if len(signing_key) != 32:
            raise ValueError("execution signing key must contain exactly 32 bytes")
        self._store = store
        self._key = signing_key

    def approve(
        self,
        plan: ExecutionPlan,
        *,
        approved_by: str,
        ttl_minutes: int = 15,
    ) -> ExecutionApproval:
        if ttl_minutes < 1 or ttl_minutes > 60:
            raise ValueError("execution approval TTL must be between 1 and 60 minutes")
        created_at = datetime.now(UTC)
        digest = plan.plan_digest
        signature = self._sign(digest)
        approval = ExecutionApproval(
            id=f"exec_approval_{uuid.uuid4().hex}",
            plan_digest=digest,
            approved_by=approved_by,
            signature=signature,
            created_at=created_at,
            expires_at=created_at + timedelta(minutes=ttl_minutes),
        )
        self._store.publish_creator_execution_approval(
            approval_id=approval.id,
            plan_digest=approval.plan_digest,
            signature=approval.signature,
            approved_by=approval.approved_by,
            expires_at=approval.expires_at.isoformat(),
            created_at=approval.created_at.isoformat(),
        )
        return approval

    def verify(self, approval: ExecutionApproval, plan: ExecutionPlan) -> None:
        if approval.plan_digest != plan.plan_digest:
            raise ExecutionApprovalError("execution approval is bound to another plan")
        if datetime.now(UTC) >= approval.expires_at:
            raise ExecutionApprovalError("execution approval has expired")
        expected = self._sign(approval.plan_digest)
        if not secrets.compare_digest(expected, approval.signature):
            raise ExecutionApprovalError("execution approval signature is invalid")

    def _sign(self, digest: str) -> str:
        return hmac.new(
            self._key,
            f"creator-execution-plan-v1:{digest}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()


class CreatorRuntimeController:
    def __init__(
        self,
        *,
        creator: CreatorService,
        store: SQLiteStore,
        signing_key: bytes,
    ) -> None:
        self.creator = creator
        self.store = store
        self.authority = ExecutionAuthority(store=store, signing_key=signing_key)
        self.verifier = VerificationGate()

    def prepare_plan(
        self,
        *,
        envelope: CreatorBriefEnvelope,
        route: RouteDecision,
        repository_fingerprint: str,
        workspace_mount_digest: str,
        commands: tuple[SandboxCommand, ...],
        allowed_write_paths: tuple[str, ...] = (),
        wall_clock_seconds: int = 900,
        memory_megabytes: int = 2_048,
        cpu_count: int = 2,
        artifact_byte_limit: int = 50_000_000,
    ) -> ExecutionPlan:
        submitted_digest = content_digest(
            route.model_dump(mode="json", exclude={"decision_digest"})
        )
        if not _digests_match(route.decision_digest, submitted_digest):
            raise CreatorEnvelopeError("route decision digest is invalid")
        verified_route = self.creator.route(RoutePreviewRequest(envelope=envelope))
        if not _digests_match(route.decision_digest, verified_route.decision_digest):
            raise CreatorEnvelopeError("route decision is not bound to the signed brief")
        if verified_route.status != RouteStatus.READY:
            raise SandboxUnavailableError("creator route is not ready for execution preparation")
        return ExecutionPlan(
            id=f"exec_plan_{uuid.uuid4().hex}",
            brief_digest=envelope.brief_digest,
            route_digest=verified_route.decision_digest,
            repository_fingerprint=repository_fingerprint,
            workspace_mount_digest=workspace_mount_digest,
            commands=commands,
            allowed_write_paths=allowed_write_paths,
            wall_clock_seconds=wall_clock_seconds,
            memory_megabytes=memory_megabytes,
            cpu_count=cpu_count,
            artifact_byte_limit=artifact_byte_limit,
        )

    async def execute(
        self,
        plan: ExecutionPlan,
        approval: ExecutionApproval,
        executor: SandboxExecutor,
    ) -> RuntimeOutcome:
        self.authority.verify(approval, plan)
        consumed = self.store.consume_creator_execution_approval(
            approval_id=approval.id,
            plan_digest=plan.plan_digest,
            signature=approval.signature,
            consumed_at=datetime.now(UTC).isoformat(),
        )
        if not consumed:
            raise ExecutionApprovalError("execution approval is unavailable or already consumed")
        if not executor.connected:
            raise SandboxUnavailableError("isolated execution runner is not connected")
        result = await executor.execute(plan)
        verification = self.verifier.verify(plan, result)
        return RuntimeOutcome(
            plan=plan,
            result=result,
            verification=verification,
            outcome="verified_success" if verification.verified else "verified_failure",
        )


def observation(
    command_id: str,
    *,
    exit_code: int,
    stdout_label: str,
    stderr_label: str = "",
    duration_ms: int = 1,
) -> CommandObservation:
    """Create digest-only fixture observations for offline tests and evals."""
    return CommandObservation(
        command_id=command_id,
        exit_code=exit_code,
        stdout_digest=hashlib.sha256(stdout_label.encode("utf-8")).hexdigest(),
        stderr_digest=hashlib.sha256(stderr_label.encode("utf-8")).hexdigest(),
        duration_ms=duration_ms,
    )
