from __future__ import annotations

import asyncio
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from threading import RLock

from .agent import Planner
from .approvals import ApprovalError, ApprovalService, action_digest
from .costs import BudgetExceededError, CostGuard
from .evidence import EvidenceLedger
from .models import (
    ActionProposal,
    ApprovalDecisionRequest,
    ApprovalStatus,
    ArtifactKind,
    ChangePreparation,
    ChangePreparationStatus,
    Environment,
    HealthResponse,
    JobRecord,
    JobStatus,
    RecoveryCreateRequest,
    RecoveryPackage,
    RecoveryStatus,
    RepositoryInspection,
    TaskCreate,
)
from .policy import PolicyEngine
from .recovery import (
    RecoveryBlockedError,
    RecoveryCapture,
    RecoveryError,
    RecoveryUnavailableError,
)
from .repository import (
    RepositoryAccessError,
    RepositoryInspectionError,
    RepositoryInspector,
    secret_rule_ids,
)
from .states import TERMINAL_STATES, require_transition
from .store import (
    EmergencyStopActiveError,
    SQLiteStore,
    StoreStateConflictError,
    canonical_json,
)


class EmergencyStopError(RuntimeError):
    pass


class RunnerUnavailableError(RuntimeError):
    pass


class InspectionUnavailableError(RuntimeError):
    pass


class SensitiveInputError(ValueError):
    pass


def _validate_idempotency_key(idempotency_key: str) -> None:
    if not 16 <= len(idempotency_key) <= 128 or any(
        ord(character) < 32 or ord(character) == 127 for character in idempotency_key
    ):
        raise SensitiveInputError("idempotency key must contain 16 to 128 non-control characters")
    try:
        encoded = idempotency_key.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SensitiveInputError("idempotency key is not valid UTF-8 text") from exc
    if secret_rule_ids(encoded):
        raise SensitiveInputError(
            "idempotency key contains credential-like material; use an opaque random identifier"
        )


def _validate_actor_label(value: str) -> None:
    if not 1 <= len(value) <= 128 or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise SensitiveInputError(
            "request actor label must contain 1 to 128 non-control characters"
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SensitiveInputError("request actor label is not valid UTF-8 text") from exc
    if secret_rule_ids(encoded):
        raise SensitiveInputError(
            "request actor label contains credential-like material; submit identity only"
        )


class LilTweakService:
    def __init__(
        self,
        store: SQLiteStore,
        planner: Planner,
        cost_guard: CostGuard,
        repository_inspector: RepositoryInspector | None = None,
        recovery_capture: RecoveryCapture | None = None,
        owner_id: str = "owner",
        evidence_signing_key: bytes | None = None,
    ) -> None:
        self.store = store
        self.planner = planner
        self.cost_guard = cost_guard
        self.repository_inspector = repository_inspector
        self.recovery_capture = recovery_capture
        self.owner_id = owner_id
        self.policy = PolicyEngine()
        self.evidence = EvidenceLedger(store, evidence_signing_key)
        self.approvals = ApprovalService(store, owner_id)
        self._preparation_lock = RLock()

    def health(self) -> HealthResponse:
        return HealthResponse(
            status="ready",
            phase=3,
            execution_connected=False,
            repository_inspection_enabled=bool(
                self.repository_inspector and self.repository_inspector.enabled
            ),
            recovery_preparation_enabled=self.recovery_capture is not None,
            durable_evidence_integrity=self.evidence.durable_integrity,
            emergency_stopped=self.store.is_emergency_stopped(),
        )

    def create_job(self, task: TaskCreate, idempotency_key: str) -> JobRecord:
        _validate_idempotency_key(idempotency_key)
        if self.store.is_emergency_stopped():
            raise EmergencyStopError("Lil Tweak is emergency-stopped")
        if secret_rule_ids(task.model_dump_json().encode()):
            raise SensitiveInputError(
                "task input contains credential-like material; submit references, not secrets"
            )
        self.cost_guard.validate_job_budget(task.budget)
        request_hash = hashlib.sha256(
            canonical_json(task.model_dump(mode="json")).encode()
        ).hexdigest()
        job = JobRecord(
            id=f"job_{secrets.token_urlsafe(18)}",
            task=task,
            status=JobStatus.RECEIVED,
        )
        try:
            job, created = self.store.create_job_idempotently(
                job,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
            )
        except EmergencyStopActiveError as exc:
            raise EmergencyStopError(str(exc)) from exc
        if not created:
            return job
        self.evidence.append(
            job.id,
            "job_received",
            {
                "task_id": task.task_id,
                "organization_id": task.organization_id,
                "project_id": task.project_id,
                "environment": task.environment.value,
                "execution_permission": task.execution_permission,
                "request_hash": request_hash,
            },
        )
        return job

    def get_job(self, job_id: str) -> JobRecord:
        return self.store.get_job(job_id)

    def _transition(self, job: JobRecord, target: JobStatus, reason: str) -> JobRecord:
        require_transition(job.status, target)
        old = job.status
        old_updated_at = job.updated_at
        job.status = target
        job.updated_at = datetime.now(UTC)
        if not self.store.compare_and_save_job(
            job,
            expected_status=old,
            expected_updated_at=old_updated_at,
        ):
            current = self.get_job(job.id)
            raise RepositoryAccessError(
                f"job state changed concurrently; current state is {current.status.value}"
            )
        self.evidence.append(
            job.id,
            "state_transition",
            {"from": old.value, "to": target.value, "reason": reason},
        )
        return job

    def _transition_if_status(
        self,
        job_id: str,
        expected: JobStatus,
        target: JobStatus,
        reason: str,
    ) -> JobRecord:
        current = self.get_job(job_id)
        if current.status != expected:
            return current
        try:
            return self._transition(current, target, reason)
        except RepositoryAccessError:
            return self.get_job(job_id)

    def _save_job_update(self, job: JobRecord, expected_updated_at: datetime) -> None:
        if not self.store.compare_and_save_job(
            job,
            expected_status=job.status,
            expected_updated_at=expected_updated_at,
        ):
            current = self.get_job(job.id)
            raise RepositoryAccessError(
                f"job changed concurrently; current state is {current.status.value}"
            )

    @staticmethod
    def _plan_digest(job: JobRecord) -> str:
        if job.plan is None:
            raise RecoveryUnavailableError("a structured plan is required")
        return hashlib.sha256(canonical_json(job.plan.model_dump(mode="json")).encode()).hexdigest()

    @staticmethod
    def _require_operation_allowed(job: JobRecord, operation: str) -> None:
        if operation in job.task.prohibited_actions:
            raise RecoveryBlockedError(
                "operation_prohibited",
                f"{operation} is explicitly prohibited by the task policy",
            )

    @staticmethod
    def _require_complete_inspection(
        inspection: RepositoryInspection,
        *,
        purpose: str,
    ) -> None:
        git_incomplete = inspection.git.is_repository and (
            not inspection.git.metadata_complete
            or inspection.git.status_truncated
            or inspection.git.head_revision is None
            or inspection.git.recovery_snapshot_digest is None
        )
        if not inspection.complete or not inspection.read_only_verified or git_incomplete:
            raise RecoveryBlockedError(
                "inspection_incomplete",
                f"a complete verified inspection is required for {purpose}",
            )

    def inspect_job(self, job_id: str) -> JobRecord:
        if self.store.is_emergency_stopped():
            raise EmergencyStopError("Lil Tweak is emergency-stopped")
        job = self.get_job(job_id)
        if job.status == JobStatus.ANALYZED and job.inspection is not None:
            return job
        if job.status != JobStatus.RECEIVED:
            raise RepositoryAccessError("job is not ready for repository inspection")
        if job.task.repository is None:
            self._transition(job, JobStatus.BLOCKED, "repository reference is required")
            raise RepositoryAccessError("job has no repository reference")
        if self.repository_inspector is None or not self.repository_inspector.enabled:
            self._transition(job, JobStatus.BLOCKED, "repository registry is not configured")
            raise RepositoryAccessError("repository registry is not configured")

        self._transition(job, JobStatus.INSPECTING, "bounded repository inspection started")
        self.evidence.append(
            job.id,
            "repository_inspection_started",
            {
                "provider": job.task.repository.provider,
                "repository_id": job.task.repository.repository_id,
                "requested_revision": job.task.repository.revision,
                "allowed_path_count": len(job.task.repository.allowed_paths),
            },
        )
        try:
            inspection = self.repository_inspector.inspect(job.task.repository)
        except RepositoryAccessError:
            self._transition(
                job,
                JobStatus.BLOCKED,
                "repository access boundary blocked inspection",
            )
            raise
        except RepositoryInspectionError:
            self._transition(job, JobStatus.FAILED, "repository inspection failed")
            raise
        except Exception as exc:
            self._transition(job, JobStatus.FAILED, "repository inspection failed")
            raise RepositoryInspectionError("repository inspection failed") from exc

        job.inspection = inspection
        old_updated_at = job.updated_at
        job.updated_at = datetime.now(UTC)
        if not self.store.compare_and_save_job(
            job,
            expected_status=JobStatus.INSPECTING,
            expected_updated_at=old_updated_at,
        ):
            return self.get_job(job.id)
        inspection_digest = hashlib.sha256(
            canonical_json(inspection.model_dump(mode="json")).encode()
        ).hexdigest()
        self.evidence.append(
            job.id,
            "repository_inspected",
            {
                "inspection_digest": inspection_digest,
                "repository_fingerprint": inspection.repository_fingerprint,
                "resolved_revision": inspection.git.resolved_revision,
                "file_count": inspection.file_count,
                "secret_finding_count": len(inspection.secret_findings),
                "limits_reached": inspection.limits_reached,
                "read_only_verified": inspection.read_only_verified,
            },
        )
        if not inspection.read_only_verified:
            self._transition(job, JobStatus.BLOCKED, "repository changed during inspection")
            raise RepositoryAccessError("repository changed during inspection")
        return self._transition(job, JobStatus.ANALYZED, "repository inspection completed")

    def get_inspection(self, job_id: str) -> RepositoryInspection:
        job = self.get_job(job_id)
        if job.inspection is None:
            raise InspectionUnavailableError("repository inspection is not available")
        return job.inspection

    async def analyze_job(self, job_id: str) -> JobRecord:
        if self.store.is_emergency_stopped():
            raise EmergencyStopError("Lil Tweak is emergency-stopped")
        job = self.get_job(job_id)
        if job.status == JobStatus.RECEIVED:
            if job.task.repository is not None:
                job = await asyncio.to_thread(self.inspect_job, job_id)
            else:
                self._transition(job, JobStatus.INSPECTING, "analysis started")
                job = self._transition(job, JobStatus.ANALYZED, "no repository was supplied")
        if job.status != JobStatus.ANALYZED:
            raise RepositoryAccessError("job is not ready for planning")
        if not self.store.claim_planning(job.id):
            raise RepositoryAccessError(
                "planning was already claimed; automatic retry is blocked to prevent "
                "duplicate provider charges"
            )

        inspection_context = None
        if job.inspection is not None and self.repository_inspector is not None:
            inspection_context = self.repository_inspector.planning_context(job.inspection)
        paid_provider = bool(getattr(self.planner, "paid_provider", False))
        try:
            reservation = 0.0
            if paid_provider:
                reservation = self.cost_guard.planning_reservation(job.task.budget)
                try:
                    self.store.reserve_budget(
                        job_id=job.id,
                        organization_id=job.task.organization_id,
                        amount_usd=reservation,
                        monthly_limit_usd=self.cost_guard.monthly_limit_usd,
                    )
                except ValueError as exc:
                    raise BudgetExceededError(str(exc)) from exc
                job.budget_reserved_usd = reservation
                job.estimated_cost_usd = reservation
                old_updated_at = job.updated_at
                job.updated_at = datetime.now(UTC)
                if not self.store.compare_and_save_job(
                    job,
                    expected_status=JobStatus.ANALYZED,
                    expected_updated_at=old_updated_at,
                ):
                    return self.get_job(job.id)
                self.evidence.append(
                    job.id,
                    "planning_budget_reserved",
                    {
                        "reserved_usd": reservation,
                        "monthly_limit_usd": self.cost_guard.monthly_limit_usd,
                        "pricing_basis": "conservative_admission_reservation",
                    },
                )
            current = self.get_job(job.id)
            if current.status != JobStatus.ANALYZED:
                return current
            if self.store.is_emergency_stopped():
                self._transition_if_status(
                    job.id,
                    JobStatus.ANALYZED,
                    JobStatus.CANCELED,
                    "emergency stop observed before planning provider call",
                )
                raise EmergencyStopError("Lil Tweak is emergency-stopped")
            job = current
            plan = await self.planner.plan(job.task, inspection_context)
            if secret_rule_ids(plan.model_dump_json().encode()):
                raise SensitiveInputError(
                    "planning output contained credential-like material and was discarded"
                )
            if paid_provider:
                plan = plan.model_copy(update={"estimated_cost_usd": reservation})
            else:
                self.cost_guard.require_within_job_limit(
                    plan.estimated_cost_usd,
                    job.task.budget,
                )
        except asyncio.CancelledError:
            self._transition_if_status(
                job.id,
                JobStatus.ANALYZED,
                JobStatus.FAILED,
                "planning request was canceled before completion",
            )
            raise
        except BudgetExceededError:
            self._transition_if_status(
                job.id,
                JobStatus.ANALYZED,
                JobStatus.BLOCKED,
                "cost limit reached",
            )
            raise
        except Exception:
            self._transition_if_status(
                job.id,
                JobStatus.ANALYZED,
                JobStatus.FAILED,
                "planning failed",
            )
            raise

        current = self.get_job(job.id)
        if current.status != JobStatus.ANALYZED:
            return current
        if self.store.is_emergency_stopped():
            return self._transition_if_status(
                job.id,
                JobStatus.ANALYZED,
                JobStatus.CANCELED,
                "planning result discarded after emergency stop",
            )
        job = current
        job.plan = plan
        job.estimated_cost_usd = plan.estimated_cost_usd
        old_updated_at = job.updated_at
        job.updated_at = datetime.now(UTC)
        if not self.store.compare_and_save_job(
            job,
            expected_status=JobStatus.ANALYZED,
            expected_updated_at=old_updated_at,
        ):
            return self.get_job(job.id)
        self.evidence.append(
            job.id,
            "plan_created",
            {
                "plan_digest": hashlib.sha256(
                    canonical_json(plan.model_dump(mode="json")).encode()
                ).hexdigest(),
                "estimated_cost_usd": plan.estimated_cost_usd,
            },
        )
        try:
            job = self._transition(job, JobStatus.PLAN_READY, "structured plan is ready")
        except RepositoryAccessError:
            return self.get_job(job.id)

        proposal = self._proposal_from(job)
        decision = self.policy.evaluate(job.task, proposal)
        self.evidence.append(
            job.id,
            "policy_decision",
            decision.model_dump(mode="json"),
        )
        if not decision.allowed_to_prepare:
            return self._transition(
                job,
                JobStatus.BLOCKED,
                "technical change preparation is prohibited by task policy",
            )
        if decision.approval_required:
            approval = self.approvals.build(job.id, proposal, self.owner_id)
            old_updated_at = job.updated_at
            job.approval_id = approval.id
            job.status = JobStatus.AWAITING_APPROVAL
            job.updated_at = datetime.now(UTC)
            try:
                job, published = self.store.publish_technical_approval(
                    job,
                    expected_updated_at=old_updated_at,
                    approval=approval,
                )
            except StoreStateConflictError:
                return self.get_job(job.id)
            if not published:
                return job
            self.evidence.append(
                job.id,
                "state_transition",
                {
                    "from": JobStatus.PLAN_READY.value,
                    "to": JobStatus.AWAITING_APPROVAL.value,
                    "reason": "exact approval required",
                },
            )
        return job

    def _proposal_from(self, job: JobRecord) -> ActionProposal:
        return ActionProposal(
            operation="prepare_technical_change",
            purpose="technical_change_review_v1",
            environment=job.task.environment,
            repository_id=job.task.repository.repository_id if job.task.repository else None,
            plan_digest=self._plan_digest(job),
            source_fingerprint=(job.inspection.repository_fingerprint if job.inspection else None),
            source_snapshot_digest=(
                job.inspection.git.recovery_snapshot_digest if job.inspection else None
            ),
            base_revision=job.inspection.git.head_revision if job.inspection else None,
            estimated_cost_usd=job.estimated_cost_usd,
            rollback_plan=[
                "Preserve the pre-change revision and restore it if verification fails."
            ],
        )

    def decide_approval(
        self,
        approval_id: str,
        request: ApprovalDecisionRequest,
        authenticated_identity: str,
    ) -> JobRecord:
        with self._preparation_lock:
            if self.store.is_emergency_stopped():
                raise EmergencyStopError("Lil Tweak is emergency-stopped")
            if not secrets.compare_digest(authenticated_identity, self.owner_id):
                raise ApprovalError("this approval requires the authenticated owner")
            pending = self.approvals.get(approval_id)
            if pending.status == ApprovalStatus.INVALIDATED:
                raise ApprovalError("approval belongs to a canceled or terminal job")
            if pending.status != ApprovalStatus.PENDING:
                raise ApprovalError("approval is not pending")
            job = self.get_job(pending.job_id)
            if job.status in TERMINAL_STATES or self.store.is_job_cancel_requested(job.id):
                raise ApprovalError("approval belongs to a canceled or terminal job")
            if pending.purpose == "recovery_capture_v1":
                package = job.recovery_package
                if (
                    package is None
                    or package.approval_id != pending.id
                    or package.action_digest != pending.action_digest
                    or package.status != RecoveryStatus.AWAITING_APPROVAL
                ):
                    raise ApprovalError("recovery approval is stale or has no matching package")
            elif pending.purpose == "technical_change_review_v1":
                if (
                    job.approval_id != pending.id
                    or job.status != JobStatus.AWAITING_APPROVAL
                    or not secrets.compare_digest(
                        pending.action_digest,
                        action_digest(job.id, self._proposal_from(job)),
                    )
                ):
                    raise ApprovalError("technical approval is stale or no longer matches the plan")
            else:
                raise ApprovalError("approval purpose is not supported")

            linked_digest = (
                action_digest(job.id, self._proposal_from(job))
                if pending.purpose == "technical_change_review_v1"
                else pending.action_digest
            )
            try:
                job, approval, decided = self.store.decide_linked_approval(
                    approval_id,
                    expected_digest=request.action_digest,
                    expected_linked_digest=linked_digest,
                    expected_job_updated_at=job.updated_at,
                    approved=request.decision == "approve",
                    decided_by=authenticated_identity,
                    now=datetime.now(UTC),
                )
            except EmergencyStopActiveError as exc:
                raise EmergencyStopError(str(exc)) from exc
            except StoreStateConflictError as exc:
                raise ApprovalError(str(exc)) from exc

            if pending.purpose == "technical_change_review_v1":
                reason = (
                    "owner approved exact action"
                    if approval.status == ApprovalStatus.APPROVED
                    else "approval expired"
                    if approval.status == ApprovalStatus.EXPIRED
                    else "owner rejected exact action"
                )
                self.evidence.append(
                    job.id,
                    "state_transition",
                    {
                        "from": JobStatus.AWAITING_APPROVAL.value,
                        "to": job.status.value,
                        "reason": reason,
                    },
                )

            self.evidence.append(
                job.id,
                "approval_decided",
                {
                    "approval_id": approval.id,
                    "status": approval.status.value,
                    "action_digest": approval.action_digest,
                    "decided_by": approval.decided_by,
                },
            )
            if not decided:
                raise ApprovalError("approval expired before decision")
            return job

    def create_recovery_request(
        self,
        job_id: str,
        request: RecoveryCreateRequest,
        idempotency_key: str,
        authenticated_identity: str,
    ) -> RecoveryPackage:
        _validate_idempotency_key(idempotency_key)
        if self.store.is_emergency_stopped():
            raise EmergencyStopError("Lil Tweak is emergency-stopped")
        if not secrets.compare_digest(authenticated_identity, self.owner_id):
            raise RecoveryUnavailableError("recovery preparation requires the authenticated owner")
        if self.recovery_capture is None or self.repository_inspector is None:
            raise RecoveryUnavailableError("encrypted recovery preparation is not configured")
        job = self.get_job(job_id)
        if job.task.repository is None or job.inspection is None or job.plan is None:
            raise RecoveryUnavailableError("repository inspection and planning are required")
        self._require_operation_allowed(job, "prepare_recovery_package")
        if job.status not in {
            JobStatus.PLAN_READY,
            JobStatus.AWAITING_APPROVAL,
            JobStatus.APPROVED,
        }:
            raise RecoveryUnavailableError("job is not ready for recovery preparation")
        request_hash = hashlib.sha256(
            canonical_json(
                {
                    "job_id": job.id,
                    "request": request.model_dump(mode="json"),
                }
            ).encode()
        ).hexdigest()
        scope = f"recovery:{job.id}"
        inspection = job.inspection
        if not secrets.compare_digest(
            request.expected_repository_fingerprint,
            inspection.repository_fingerprint,
        ):
            raise RecoveryBlockedError(
                "fingerprint_mismatch",
                "expected repository fingerprint does not match the inspected source",
            )
        if (
            not inspection.complete
            or not inspection.read_only_verified
            or not inspection.git.is_repository
            or not inspection.git.metadata_complete
            or inspection.git.status_truncated
            or inspection.git.head_revision is None
            or inspection.git.recovery_snapshot_digest is None
        ):
            raise RecoveryBlockedError(
                "inspection_incomplete",
                "complete Git inspection is required for recovery preparation",
            )
        if inspection.git.conflicted_paths:
            raise RecoveryBlockedError(
                "unmerged_index",
                "unresolved Git conflicts block safe recovery preparation",
            )

        planned: list[ArtifactKind] = []
        if inspection.recovery.patch_recommended:
            planned.extend([ArtifactKind.STAGED_PATCH, ArtifactKind.UNSTAGED_PATCH])
        if inspection.recovery.untracked_archive_recommended:
            planned.append(ArtifactKind.UNTRACKED_ARCHIVE)
        exclusions: list[str] = []
        warnings: list[str] = []
        if inspection.git.ignored_paths:
            warnings.append(
                "Git-ignored non-index files are included in the approved recovery scope."
            )
        complete_for_scope = True
        if inspection.recovery.bundle_recommended:
            if not request.accept_incomplete_history:
                raise RecoveryBlockedError(
                    "ahead_commits_require_history_recovery",
                    "local commits require a later encrypted Git-history recovery artifact",
                )
            exclusions.append("local_commits_ahead_of_upstream")
            warnings.append("Local commits ahead of upstream are not captured by Phase 3.")
            complete_for_scope = False
        if not planned:
            raise RecoveryUnavailableError("no safely capturable working-tree changes were found")

        package_id = f"rcv_{secrets.token_urlsafe(18)}"
        proposal = ActionProposal(
            operation="prepare_recovery_package",
            purpose="recovery_capture_v1",
            environment=job.task.environment,
            repository_id=job.task.repository.repository_id,
            recovery_package_id=package_id,
            source_fingerprint=inspection.repository_fingerprint,
            source_snapshot_digest=inspection.git.recovery_snapshot_digest,
            base_revision=inspection.git.head_revision,
            artifact_kinds=planned,
            retention_hours=request.retention_hours,
            exclusions=exclusions,
            files=list(job.task.repository.allowed_paths),
            rollback_plan=[
                "Quarantine every unpublished artifact if validation fails.",
                "Perform any future restoration only in a disposable clone.",
            ],
        )
        approval = self.approvals.build(job.id, proposal, self.owner_id)
        package = RecoveryPackage(
            id=package_id,
            job_id=job.id,
            status=RecoveryStatus.AWAITING_APPROVAL,
            repository_id=job.task.repository.repository_id,
            source_fingerprint=inspection.repository_fingerprint,
            source_snapshot_digest=inspection.git.recovery_snapshot_digest,
            capture_scope=(
                "allowed_paths_tracked_and_all_non_index_files"
                if job.task.repository.allowed_paths
                else "tracked_and_all_non_index_files"
            ),
            base_head=inspection.git.head_revision,
            allowed_paths=list(job.task.repository.allowed_paths),
            planned_artifacts=planned,
            complete_for_scope=complete_for_scope,
            exclusions=exclusions,
            warnings=warnings,
            approval_id=approval.id,
            action_digest=approval.action_digest,
            retention_expires_at=datetime.now(UTC) + timedelta(hours=request.retention_hours),
        )
        old_updated_at = job.updated_at
        job.recovery_package = package
        job.updated_at = datetime.now(UTC)
        try:
            published_job, created = self.store.publish_recovery_request_idempotently(
                job,
                approval,
                operation_scope=scope,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                expected_status=job.status,
                expected_updated_at=old_updated_at,
            )
        except EmergencyStopActiveError as exc:
            raise EmergencyStopError(str(exc)) from exc
        except StoreStateConflictError as exc:
            raise RecoveryUnavailableError(str(exc)) from exc
        published_package = published_job.recovery_package
        if published_package is None:
            raise RecoveryUnavailableError("idempotent recovery record is unavailable")
        if not created:
            return published_package
        self.evidence.append(
            job.id,
            "recovery_approval_requested",
            {
                "recovery_package_id": published_package.id,
                "approval_id": published_package.approval_id,
                "action_digest": published_package.action_digest,
                "source_fingerprint": published_package.source_fingerprint,
                "source_snapshot_digest": published_package.source_snapshot_digest,
                "capture_scope": published_package.capture_scope,
                "planned_artifacts": [item.value for item in planned],
                "complete_for_scope": complete_for_scope,
                "retention_hours": request.retention_hours,
            },
        )
        return published_package

    def get_recovery(self, job_id: str) -> RecoveryPackage:
        package = self.get_job(job_id).recovery_package
        if package is None:
            raise RecoveryUnavailableError("recovery package is not available")
        return package

    def prepare_recovery(
        self,
        job_id: str,
        authenticated_identity: str,
    ) -> RecoveryPackage:
        if self.store.is_emergency_stopped():
            raise EmergencyStopError("Lil Tweak is emergency-stopped")
        if self.recovery_capture is None:
            raise RecoveryUnavailableError("encrypted recovery preparation is not configured")
        with self._preparation_lock:
            job = self.get_job(job_id)
            package = job.recovery_package
            if package is None or package.status != RecoveryStatus.APPROVED:
                raise RecoveryUnavailableError("recovery package is not approved and ready")
            if package.retention_expires_at <= datetime.now(UTC):
                package.status = RecoveryStatus.BLOCKED
                package.blocker_codes = sorted(
                    set([*package.blocker_codes, "recovery_request_expired"])
                )
                package.updated_at = datetime.now(UTC)
                job.recovery_package = package
                old_updated_at = job.updated_at
                job.updated_at = datetime.now(UTC)
                self._save_job_update(job, old_updated_at)
                raise RecoveryUnavailableError("recovery request expired before capture")
            self.approvals.consume(
                package.approval_id,
                expected_digest=package.action_digest,
                expected_purpose="recovery_capture_v1",
                authenticated_identity=authenticated_identity,
            )
            package.status = RecoveryStatus.CAPTURING
            package.updated_at = datetime.now(UTC)
            job.recovery_package = package
            old_updated_at = job.updated_at
            job.updated_at = datetime.now(UTC)
            self._save_job_update(job, old_updated_at)
            self.evidence.append(
                job.id,
                "recovery_capture_started",
                {
                    "recovery_package_id": package.id,
                    "approval_id": package.approval_id,
                    "action_digest": package.action_digest,
                },
            )
            try:
                package = self.recovery_capture.capture(
                    job,
                    package,
                    stop_requested=lambda: (
                        self.store.is_emergency_stopped()
                        or self.store.is_job_cancel_requested(job.id)
                    ),
                )
            except RecoveryBlockedError as exc:
                package.status = RecoveryStatus.BLOCKED
                package.blocker_codes = sorted(set([*package.blocker_codes, exc.code]))
                package.updated_at = datetime.now(UTC)
                current_job = self.get_job(job.id)
                current_job.recovery_package = package
                old_updated_at = current_job.updated_at
                current_job.updated_at = datetime.now(UTC)
                self._save_job_update(current_job, old_updated_at)
                self.evidence.append(
                    job.id,
                    "recovery_capture_blocked",
                    {
                        "recovery_package_id": package.id,
                        "blocker_code": exc.code,
                    },
                )
                raise
            except Exception as exc:
                package.status = RecoveryStatus.FAILED
                package.blocker_codes = sorted(set([*package.blocker_codes, "capture_failed"]))
                package.updated_at = datetime.now(UTC)
                current_job = self.get_job(job.id)
                current_job.recovery_package = package
                old_updated_at = current_job.updated_at
                current_job.updated_at = datetime.now(UTC)
                self._save_job_update(current_job, old_updated_at)
                self.evidence.append(
                    job.id,
                    "recovery_capture_failed",
                    {"recovery_package_id": package.id},
                )
                if isinstance(exc, RecoveryError):
                    raise
                raise RecoveryError("recovery capture failed safely") from exc

            package.updated_at = datetime.now(UTC)
            current_job = self.get_job(job.id)
            current_job.recovery_package = package
            old_updated_at = current_job.updated_at
            current_job.updated_at = datetime.now(UTC)
            self._save_job_update(current_job, old_updated_at)
            self.evidence.append(
                job.id,
                "recovery_capture_completed",
                {
                    "recovery_package_id": package.id,
                    "status": package.status.value,
                    "manifest_digest": package.manifest_digest,
                    "artifact_count": len(package.artifacts),
                    "artifact_digests": [
                        {
                            "id": item.id,
                            "kind": item.kind.value,
                            "sha256": item.plaintext_sha256,
                            "bytes": item.plaintext_bytes,
                        }
                        for item in package.artifacts
                    ],
                    "source_fingerprint": package.after_fingerprint,
                    "source_writes_performed": False,
                },
            )
            return package

    def prepare_change(
        self,
        job_id: str,
        authenticated_identity: str,
    ) -> ChangePreparation:
        if self.store.is_emergency_stopped():
            raise EmergencyStopError("Lil Tweak is emergency-stopped")
        if not secrets.compare_digest(authenticated_identity, self.owner_id):
            raise RecoveryUnavailableError("change preparation requires the authenticated owner")
        if self.repository_inspector is None:
            raise RecoveryUnavailableError("repository inspection is not configured")
        job = self.get_job(job_id)
        if job.status in TERMINAL_STATES:
            raise RecoveryUnavailableError("terminal jobs cannot prepare changes")
        if job.task.repository is None or job.inspection is None or job.plan is None:
            raise RecoveryUnavailableError("repository inspection and planning are required")
        self._require_operation_allowed(job, "prepare_technical_change")
        self._require_complete_inspection(
            job.inspection,
            purpose="change preparation",
        )
        if job.inspection.recovery.dirty_worktree and (
            job.recovery_package is None or job.recovery_package.status != RecoveryStatus.READY
        ):
            raise RecoveryUnavailableError(
                "verified complete recovery is required before change preparation"
            )
        fresh = self.repository_inspector.inspect(job.task.repository)
        self._require_complete_inspection(
            fresh,
            purpose="change preparation",
        )
        if fresh.repository_fingerprint != job.inspection.repository_fingerprint:
            if job.change_preparation is not None:
                job.change_preparation.status = ChangePreparationStatus.STALE
                old_updated_at = job.updated_at
                job.updated_at = datetime.now(UTC)
                self._save_job_update(job, old_updated_at)
            raise RecoveryBlockedError(
                "stale_source_fingerprint",
                "repository changed before change preparation",
            )
        proposal = self._proposal_from(job)
        policy = self.policy.evaluate(job.task, proposal)
        if not policy.allowed_to_prepare:
            raise RecoveryBlockedError(
                "operation_prohibited",
                "technical change preparation is prohibited by task policy",
            )
        if policy.approval_required:
            if job.approval_id is None or job.status != JobStatus.APPROVED:
                raise RecoveryUnavailableError(
                    "current exact technical approval is required before change preparation"
                )
            approval = self.approvals.get(job.approval_id)
            expected_digest = action_digest(job.id, proposal)
            if (
                approval.status != ApprovalStatus.APPROVED
                or approval.purpose != "technical_change_review_v1"
                or not secrets.compare_digest(approval.action_digest, expected_digest)
            ):
                raise RecoveryBlockedError(
                    "stale_technical_approval",
                    "technical approval no longer matches the plan and source snapshot",
                )
        if job.change_preparation is not None:
            return job.change_preparation
        plan_digest = self._plan_digest(job)
        recovery_ready = (
            job.recovery_package is not None and job.recovery_package.status == RecoveryStatus.READY
        )
        rollback_plan = [
            (
                "Use only the verified recovery package in a disposable clone."
                if recovery_ready
                else "Begin any future implementation from the exact base revision in a "
                "disposable clone."
            ),
            "Do not apply any candidate change to the registered source in Phase 3.",
        ]
        payload = {
            "job_id": job.id,
            "repository_id": job.task.repository.repository_id,
            "source_fingerprint": fresh.repository_fingerprint,
            "source_snapshot_digest": fresh.git.recovery_snapshot_digest,
            "plan_digest": plan_digest,
            "base_head": fresh.git.head_revision,
            "recovery_package_id": (
                job.recovery_package.id if recovery_ready and job.recovery_package else None
            ),
            "objective": job.plan.objective,
            "proposed_steps": job.plan.proposed_plan,
            "files_and_systems": job.plan.files_and_systems,
            "tests_required": job.plan.tests_required,
            "rollback_plan": rollback_plan,
            "risk_flags": {
                "production": job.task.environment == Environment.PRODUCTION,
                "credential_findings_present": bool(fresh.secret_findings),
                "source_is_dirty": fresh.recovery.dirty_worktree,
            },
            "source_writes_performed": False,
            "execution_ready": False,
        }
        digest = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
        preparation = ChangePreparation(
            id=f"chg_{secrets.token_urlsafe(18)}",
            status=ChangePreparationStatus.READY_FOR_REVIEW,
            preparation_digest=digest,
            **payload,
        )
        job.change_preparation = preparation
        old_updated_at = job.updated_at
        job.updated_at = datetime.now(UTC)
        self._save_job_update(job, old_updated_at)
        self.evidence.append(
            job.id,
            "change_preparation_created",
            {
                "change_preparation_id": preparation.id,
                "preparation_digest": digest,
                "source_fingerprint": preparation.source_fingerprint,
                "recovery_package_id": preparation.recovery_package_id,
                "source_writes_performed": False,
                "execution_ready": False,
            },
        )
        return preparation

    def cancel_job(self, job_id: str, requested_by: str) -> JobRecord:
        _validate_actor_label(requested_by)
        self.get_job(job_id)
        # Publish the stop signal before waiting for an in-process capture lock.
        # The atomic cancellation below owns the final job/approval transition.
        self.store.set_job_cancel_requested(job_id)
        with self._preparation_lock:
            job, previous_status, invalidated = self.store.cancel_job_atomically(
                job_id,
                requested_by=requested_by,
                now=datetime.now(UTC),
            )
            if previous_status is None:
                return job
            self.evidence.append(
                job.id,
                "state_transition",
                {
                    "from": previous_status.value,
                    "to": JobStatus.CANCELED.value,
                    "reason": f"canceled by {requested_by}",
                },
            )
            if invalidated:
                self.evidence.append(
                    job.id,
                    "approvals_invalidated",
                    {
                        "approval_ids": invalidated,
                        "invalidated_by": requested_by,
                        "reason": "job_canceled",
                    },
                )
            return job

    def request_execution(self, job_id: str) -> JobRecord:
        job = self.get_job(job_id)
        if job.status not in {JobStatus.PLAN_READY, JobStatus.APPROVED}:
            raise RunnerUnavailableError("job is not ready for execution")
        self._transition(job, JobStatus.BLOCKED, "no isolated execution runner is connected")
        raise RunnerUnavailableError("no isolated execution runner is connected")

    def emergency_stop(self, requested_by: str) -> list[str]:
        _validate_actor_label(requested_by)
        with self._preparation_lock:
            results = self.store.emergency_stop_and_cancel_jobs(
                requested_by=requested_by,
                now=datetime.now(UTC),
            )
            for job, previous_status, invalidated in results:
                self.evidence.append(
                    job.id,
                    "state_transition",
                    {
                        "from": previous_status.value,
                        "to": JobStatus.CANCELED.value,
                        "reason": f"emergency-stopped by {requested_by}",
                    },
                )
                if invalidated:
                    self.evidence.append(
                        job.id,
                        "approvals_invalidated",
                        {
                            "approval_ids": invalidated,
                            "invalidated_by": requested_by,
                            "reason": "emergency_stop",
                        },
                    )
            return [job.id for job, _previous, _invalidated in results]
