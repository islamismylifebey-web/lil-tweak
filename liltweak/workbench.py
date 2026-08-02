from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta

from .creator import CreatorService
from .creator_contract import (
    CreatorCompileRequest,
    CreatorContextItem,
    RiskDomain,
    RoutePreviewRequest,
    RouteStatus,
)
from .workbench_agent import ModelPlanResult, WorkbenchModelAdapter
from .workbench_contract import (
    ApprovalDecision,
    CandidateSubmission,
    EvidenceKind,
    NetworkMode,
    StepPhase,
    SubmissionStatus,
    TaskImport,
    ToolKind,
    WorkbenchApproval,
    WorkbenchHealth,
    WorkbenchState,
    WorkbenchTask,
    content_digest,
    utc_now,
)
from .workbench_executor import BoundedToolExecutor, TaskWorkspaceManager
from .workbench_policy import ToolPolicyBroker
from .workbench_store import WorkbenchConflict, WorkbenchStore


class WorkbenchError(RuntimeError):
    pass


class WorkbenchController:
    def __init__(
        self,
        *,
        creator: CreatorService,
        store: WorkbenchStore,
        model: WorkbenchModelAdapter,
        executor: BoundedToolExecutor,
        workspaces: TaskWorkspaceManager,
        policy: ToolPolicyBroker,
        owner_id: str,
        approval_ttl_minutes: int = 15,
        cost_ceiling_usd: float = 0.10,
        authorized_repositories: frozenset[str] = frozenset(),
    ) -> None:
        self.creator = creator
        self.store = store
        self.model = model
        self.executor = executor
        self.workspaces = workspaces
        self.policy = policy
        self.owner_id = owner_id
        self.approval_ttl_minutes = approval_ttl_minutes
        self.cost_ceiling_usd = cost_ceiling_usd
        self.authorized_repositories = authorized_repositories

    def receive(self, imported: TaskImport) -> WorkbenchTask:
        if self.store.is_emergency_stopped():
            raise WorkbenchError("emergency stop is active")
        if (
            imported.repository_id is not None
            and imported.repository_id not in self.authorized_repositories
        ):
            raise WorkbenchError("repository identity is not in the server-owned registry")
        request = self._creator_request(imported)
        if imported.examination is None:
            envelope = self.creator.compile(request, actor_id=self.owner_id)
        else:
            envelope = self.creator.compile_for_trusted_harness(
                request,
                actor_id=self.owner_id,
                enforced_risk_domains=(RiskDomain.CREDENTIALS, RiskDomain.PRODUCTION),
            )
        route = self.creator.route(RoutePreviewRequest(envelope=envelope))
        if route.status == RouteStatus.NEEDS_INPUT:
            raise WorkbenchError("Creator route is not ready; material input is missing")
        if route.status == RouteStatus.BLOCKED:
            if imported.examination is None:
                raise WorkbenchError("Creator route requires a trusted harness")
            if "qualified domain review recorded by the trusted harness" in (
                envelope.brief.trusted_prerequisites
            ):
                raise WorkbenchError("GCP examination direction requires qualified domain review")
        task = WorkbenchTask(
            id=f"task:{uuid.uuid4().hex}",
            imported=imported,
            task_digest=imported.task_digest,
            state=WorkbenchState.RECEIVED,
            creator_brief_digest=envelope.brief_digest,
            creator_route_digest=route.decision_digest,
        )
        self.store.create_task(task)
        self.store.append_evidence(
            task.id,
            kind=EvidenceKind.TASK,
            event_type="task_received",
            payload={
                "task_digest": task.task_digest,
                "source_snapshot_digest": imported.source_snapshot_digest,
                "mode": imported.mode.value,
                "creator_route_status": route.status.value,
                "trusted_prerequisites_pending": list(envelope.brief.trusted_prerequisites),
            },
        )
        return task

    def inspect(self, task_id: str) -> WorkbenchTask:
        if self.store.is_emergency_stopped():
            raise WorkbenchError("emergency stop is active")
        task = self.store.get_task(task_id)
        if task.state not in {WorkbenchState.RECEIVED, WorkbenchState.BLOCKED}:
            raise WorkbenchError("task is not ready for inspection")
        self.store.transition(task_id, WorkbenchState.INSPECTING)
        try:
            guard = self.workspaces.guard(task_id)
            file_count, total_bytes = guard.inventory()
            digest = self.workspaces.tree_digest(guard.root)
            if digest != task.imported.source_snapshot_digest:
                raise WorkbenchError("workspace source does not match the imported snapshot")
            self.store.append_evidence(
                task_id,
                kind=EvidenceKind.SOURCE,
                event_type="source_inspected",
                payload={
                    "source_snapshot_digest": digest,
                    "file_count": file_count,
                    "total_bytes": total_bytes,
                    "read_only_observation": True,
                },
            )
            if task.imported.examination is not None:
                envelope = self.creator.compile_for_trusted_harness(
                    self._creator_request(task.imported),
                    actor_id=self.owner_id,
                    enforced_risk_domains=(RiskDomain.CREDENTIALS, RiskDomain.PRODUCTION),
                )
                if envelope.brief.brief_digest != task.creator_brief_digest:
                    raise WorkbenchError("Creator brief changed before source inspection")
                satisfied = envelope.brief.trusted_prerequisites
                envelope = self.creator.satisfy_trusted_prerequisites(
                    envelope,
                    satisfied_prerequisites=satisfied,
                )
                route = self.creator.route(RoutePreviewRequest(envelope=envelope))
                if route.status != RouteStatus.READY:
                    raise WorkbenchError("Creator route remained blocked after trusted inspection")
                task = self.store.set_creator_bindings(
                    task_id,
                    brief_digest=envelope.brief_digest,
                    route_digest=route.decision_digest,
                )
                self.store.append_evidence(
                    task_id,
                    kind=EvidenceKind.CONTROL,
                    event_type="trusted_prerequisites_satisfied",
                    payload={
                        "source_snapshot_digest": digest,
                        "examination_config_digest": (task.imported.examination.config_digest),
                        "satisfied_prerequisites": list(satisfied),
                        "creator_brief_digest": envelope.brief_digest,
                        "creator_route_digest": route.decision_digest,
                    },
                )
            return self.store.transition(task_id, WorkbenchState.ANALYZED)
        except Exception as exc:
            current = self.store.get_task(task_id)
            if current.state == WorkbenchState.INSPECTING:
                self.store.transition(
                    task_id,
                    WorkbenchState.BLOCKED,
                    blocked_reason=str(exc),
                )
            raise

    @staticmethod
    def _creator_request(imported: TaskImport) -> CreatorCompileRequest:
        return CreatorCompileRequest(
            direction=imported.direction,
            context=(
                CreatorContextItem(
                    label="workbench_source_snapshot",
                    value=imported.source_snapshot_digest,
                ),
            ),
            desired_output="One bounded, testable engineering plan",
        )

    async def analyze(self, task_id: str) -> tuple[WorkbenchTask, WorkbenchApproval]:
        if self.store.is_emergency_stopped():
            raise WorkbenchError("emergency stop is active")
        task = self.store.get_task(task_id)
        if task.state != WorkbenchState.ANALYZED:
            raise WorkbenchError("task is not ready for planning")
        if not task.creator_brief_digest or not task.creator_route_digest:
            raise WorkbenchError("Creator control-plane bindings are missing")
        source_evidence = self.store.list_evidence(task_id)
        summary = next(
            (
                canonical_summary(record.payload)
                for record in reversed(source_evidence)
                if record.event_type == "source_inspected"
            ),
            "No source inspection evidence is available.",
        )
        result = await self.model.plan(
            task=task.imported,
            creator_brief_digest=task.creator_brief_digest,
            creator_route_digest=task.creator_route_digest,
            inspection_summary=summary,
        )
        if self.store.is_emergency_stopped():
            raise WorkbenchError("emergency stop activated during planning")
        self._validate_plan(task, result)
        task = self.store.transition(task_id, WorkbenchState.PLAN_READY, plan=result.plan)
        self.store.append_evidence(
            task_id,
            kind=EvidenceKind.MODEL,
            event_type="model_plan_received",
            payload={
                "provider": result.provider,
                "model": result.model,
                "reasoning_tier": result.reasoning_tier,
                "response_id_hash": (
                    hashlib.sha256(result.response_id.encode()).hexdigest()
                    if result.response_id
                    else None
                ),
                "input_tokens": result.input_tokens,
                "output_tokens": result.output_tokens,
                "claim_only": True,
            },
        )
        self.store.append_evidence(
            task_id,
            kind=EvidenceKind.PLAN,
            event_type="plan_bound",
            payload={
                "plan_digest": result.plan.plan_digest,
                "source_snapshot_digest": result.plan.source_snapshot_digest,
                "tool_digests": [step.request_digest for step in result.plan.steps],
            },
        )
        task = self.store.transition(task_id, WorkbenchState.AWAITING_APPROVAL)
        approval = self._new_approval(task)
        self.store.publish_approval(approval)
        self.store.append_evidence(
            task_id,
            kind=EvidenceKind.APPROVAL,
            event_type="approval_requested",
            payload={
                "approval_id": approval.id,
                "approval_digest": approval.approval_digest,
                "expires_at": approval.expires_at.isoformat(),
            },
        )
        return task, approval

    def decide(self, task_id: str, approval_id: str, decision: ApprovalDecision) -> WorkbenchTask:
        if self.store.is_emergency_stopped() and decision.decision == "approve":
            raise WorkbenchError("emergency stop prevents approval")
        task = self.store.get_task(task_id)
        if task.state != WorkbenchState.AWAITING_APPROVAL:
            raise WorkbenchError("task is not awaiting approval")
        approval = self.store.decide_approval(
            approval_id,
            task_id=task_id,
            decision=decision.decision,
            approval_digest=decision.approval_digest,
            actor_id=self.owner_id,
        )
        self.store.append_evidence(
            task_id,
            kind=EvidenceKind.APPROVAL,
            event_type="approval_decided",
            payload={"approval_id": approval.id, "decision": decision.decision},
        )
        if decision.decision == "approve":
            return self.store.transition(task_id, WorkbenchState.APPROVED)
        if decision.decision == "request_revision":
            return self.store.transition(task_id, WorkbenchState.ANALYZED)
        return self.store.transition(task_id, WorkbenchState.CANCELED)

    async def execute(self, task_id: str, approval_id: str) -> WorkbenchTask:
        task = self.store.get_task(task_id)
        if task.state != WorkbenchState.APPROVED or task.plan is None:
            raise WorkbenchError("task is not approved for execution")
        if self.store.is_emergency_stopped():
            raise WorkbenchError("emergency stop is active")
        approval = self.store.get_approval(approval_id)
        if approval.purpose != "execute":
            raise WorkbenchError("rollback approval cannot authorize plan execution")
        attempt = task.active_attempt + 1
        tool_digests = tuple(step.request_digest for step in task.plan.steps)
        current_source_digest = self.workspaces.tree_digest(self.workspaces.task_root(task_id))
        if current_source_digest != task.imported.source_snapshot_digest:
            raise WorkbenchError("source changed after approval")
        snapshot, snapshot_digest = self.workspaces.snapshot(task_id, attempt)
        if snapshot_digest != task.imported.source_snapshot_digest:
            raise WorkbenchError("recovery snapshot does not match the approved source")
        try:
            self.store.consume_approval(
                approval_id,
                task=task,
                expected_attempt=attempt,
                tool_digests=tool_digests,
            )
        except Exception:
            self.workspaces.discard_snapshot(snapshot)
            raise
        self.store.append_evidence(
            task_id,
            kind=EvidenceKind.RECOVERY,
            event_type="recovery_snapshot_created",
            payload={
                "attempt": attempt,
                "snapshot_digest": snapshot_digest,
                "storage_path_disclosed": False,
            },
        )
        task = self.store.transition(task_id, WorkbenchState.EXECUTING, increment_attempt=True)
        try:
            entered_testing = False
            required_failures: list[str] = []
            for step in task.plan.steps:
                if self.store.is_emergency_stopped():
                    self.executor.cancel(task_id)
                    raise WorkbenchError("emergency stop activated during execution")
                self.policy.authorize(task, step)
                if step.phase in {StepPhase.TEST, StepPhase.VERIFICATION} and not entered_testing:
                    task = self.store.transition(task_id, WorkbenchState.TESTING)
                    entered_testing = True
                proposed = self.store.append_evidence(
                    task_id,
                    kind=EvidenceKind.PROPOSED,
                    event_type="tool_request_authorized",
                    payload={
                        "tool_id": step.tool_id,
                        "request_digest": step.request_digest,
                        "phase": step.phase.value,
                    },
                )
                run = await self.executor.execute(
                    task_id=task_id,
                    attempt=attempt,
                    request=step,
                    evidence_id=proposed.id,
                )
                self.store.save_run(run)
                evidence_kind = (
                    EvidenceKind.TEST
                    if step.phase in {StepPhase.TEST, StepPhase.VERIFICATION}
                    else EvidenceKind.EXECUTED
                )
                self.store.append_evidence(
                    task_id,
                    kind=evidence_kind,
                    event_type="tool_executed",
                    payload={
                        "run_id": run.id,
                        "tool_id": run.tool_id,
                        "request_digest": run.request_digest,
                        "success": run.success,
                        "exit_code": run.exit_code,
                        "timed_out": run.timed_out,
                        "canceled": run.canceled,
                        "output_digest": run.output_digest,
                        "network_status": run.network_status.value,
                    },
                )
                if step.required and not run.success:
                    required_failures.append(step.tool_id)
                    break
            if required_failures:
                self.store.append_evidence(
                    task_id,
                    kind=EvidenceKind.VERIFIED,
                    event_type="verification_failed",
                    payload={"required_failures": required_failures, "verified": False},
                )
                return self.store.transition(
                    task_id,
                    WorkbenchState.FAILED,
                    blocked_reason=f"required tool failed: {required_failures[0]}",
                )
            if not entered_testing:
                raise WorkbenchError("execution never entered the required testing phase")
            runs = self.store.list_runs(task_id)
            current = [run for run in runs if run.attempt == attempt]
            test_ids = {
                step.tool_id
                for step in task.plan.steps
                if step.required and step.phase in {StepPhase.TEST, StepPhase.VERIFICATION}
            }
            passed_ids = {run.tool_id for run in current if run.success}
            if not test_ids or not test_ids.issubset(passed_ids):
                raise WorkbenchError("required test and verification evidence is incomplete")
            task = self.store.transition(task_id, WorkbenchState.VERIFIED)
            self.store.append_evidence(
                task_id,
                kind=EvidenceKind.VERIFIED,
                event_type="verification_satisfied",
                payload={
                    "verified": True,
                    "test_tool_ids": sorted(test_ids),
                    "run_ids": [run.id for run in current],
                    "independent_examiner_verification": False,
                },
            )
            return self.store.transition(task_id, WorkbenchState.COMPLETED)
        except Exception as exc:
            current = self.store.get_task(task_id)
            if current.state in {WorkbenchState.EXECUTING, WorkbenchState.TESTING}:
                self.store.transition(task_id, WorkbenchState.FAILED, blocked_reason=str(exc))
            raise

    def cancel(self, task_id: str) -> WorkbenchTask:
        task = self.store.get_task(task_id)
        self.executor.cancel(task_id)
        if task.state in {
            WorkbenchState.RECEIVED,
            WorkbenchState.INSPECTING,
            WorkbenchState.ANALYZED,
            WorkbenchState.BLOCKED,
            WorkbenchState.PLAN_READY,
            WorkbenchState.AWAITING_APPROVAL,
            WorkbenchState.APPROVED,
            WorkbenchState.EXECUTING,
            WorkbenchState.TESTING,
        }:
            canceled = self.store.transition(task_id, WorkbenchState.CANCELED)
        else:
            raise WorkbenchError("task cannot be canceled from its current state")
        self.store.append_evidence(
            task_id,
            kind=EvidenceKind.CONTROL,
            event_type="task_canceled",
            payload={"actor": self.owner_id},
        )
        return canceled

    def emergency_stop(self) -> list[str]:
        self.store.emergency_stop(True)
        canceled: list[str] = []
        for task in self.store.list_tasks(limit=200):
            if task.state in {
                WorkbenchState.RECEIVED,
                WorkbenchState.INSPECTING,
                WorkbenchState.ANALYZED,
                WorkbenchState.PLAN_READY,
                WorkbenchState.AWAITING_APPROVAL,
                WorkbenchState.APPROVED,
                WorkbenchState.EXECUTING,
                WorkbenchState.TESTING,
                WorkbenchState.BLOCKED,
            }:
                self.executor.cancel(task.id)
                try:
                    self.store.transition(task.id, WorkbenchState.CANCELED)
                    canceled.append(task.id)
                except WorkbenchConflict:
                    pass
                self.store.append_evidence(
                    task.id,
                    kind=EvidenceKind.CONTROL,
                    event_type="emergency_stop",
                    payload={"actor": self.owner_id},
                )
        return canceled

    def request_rollback(self, task_id: str) -> tuple[WorkbenchTask, WorkbenchApproval]:
        task = self.store.get_task(task_id)
        if task.state != WorkbenchState.FAILED or task.plan is None:
            raise WorkbenchError("rollback requires a failed attempted task")
        snapshot = self.workspaces.root / "_recovery" / f"{task.id}-{task.active_attempt}"
        if not snapshot.is_dir():
            raise WorkbenchError("recovery snapshot is unavailable")
        snapshot_digest = self.workspaces.tree_digest(snapshot)
        task = self.store.transition(task_id, WorkbenchState.ANALYZED)
        task = self.store.transition(task_id, WorkbenchState.PLAN_READY, plan=task.plan)
        task = self.store.transition(task_id, WorkbenchState.AWAITING_APPROVAL)
        approval = self._new_approval(
            task,
            purpose="rollback",
            tool_digests=(snapshot_digest,),
            attempt=task.active_attempt,
        )
        self.store.publish_approval(approval)
        self.store.append_evidence(
            task_id,
            kind=EvidenceKind.APPROVAL,
            event_type="rollback_approval_requested",
            payload={
                "approval_id": approval.id,
                "approval_digest": approval.approval_digest,
                "snapshot_digest": snapshot_digest,
            },
        )
        return task, approval

    def rollback(self, task_id: str, approval_id: str) -> WorkbenchTask:
        task = self.store.get_task(task_id)
        if task.state != WorkbenchState.APPROVED or task.plan is None:
            raise WorkbenchError("rollback is not approved")
        approval = self.store.get_approval(approval_id)
        if approval.purpose != "rollback":
            raise WorkbenchError("execution approval cannot authorize rollback")
        snapshot = self.workspaces.root / "_recovery" / f"{task.id}-{task.active_attempt}"
        if not snapshot.is_dir():
            raise WorkbenchError("recovery snapshot is unavailable")
        snapshot_digest = self.workspaces.tree_digest(snapshot)
        self.store.consume_approval(
            approval_id,
            task=task,
            expected_attempt=task.active_attempt,
            tool_digests=(snapshot_digest,),
        )
        after_digest = self.workspaces.rollback(task_id, snapshot)
        if after_digest != task.imported.source_snapshot_digest:
            raise WorkbenchError("post-rollback source verification failed")
        self.store.append_evidence(
            task_id,
            kind=EvidenceKind.RECOVERY,
            event_type="rollback_verified",
            payload={
                "attempt": task.active_attempt,
                "source_snapshot_digest": after_digest,
                "approval_id": approval_id,
            },
        )
        return self.store.transition(task_id, WorkbenchState.ROLLED_BACK)

    def retry_eligible_step(self, task_id: str) -> WorkbenchTask:
        task = self.store.get_task(task_id)
        if task.state != WorkbenchState.ROLLED_BACK:
            raise WorkbenchError(
                "retry requires an approved rollback with verified original source"
            )
        current_digest = self.workspaces.tree_digest(self.workspaces.task_root(task_id))
        if current_digest != task.imported.source_snapshot_digest:
            raise WorkbenchError("retry source does not match the immutable task snapshot")
        revised = self.store.transition(task_id, WorkbenchState.ANALYZED)
        self.store.append_evidence(
            task_id,
            kind=EvidenceKind.CONTROL,
            event_type="revision_requested_after_rollback",
            payload={
                "source_snapshot_digest": current_digest,
                "next_step": "produce a revised plan and obtain a new exact approval",
            },
        )
        return revised

    def generate_submission(self, task_id: str) -> CandidateSubmission:
        task = self.store.get_task(task_id)
        if task.state not in {
            WorkbenchState.COMPLETED,
            WorkbenchState.FAILED,
            WorkbenchState.BLOCKED,
        }:
            raise WorkbenchError("submission requires a terminal execution result")
        runs = self.store.list_runs(task_id)
        evidence = self.store.list_evidence(task_id)
        status = (
            SubmissionStatus.COMPLETE
            if task.state == WorkbenchState.COMPLETED
            else SubmissionStatus.BLOCKED
            if task.state == WorkbenchState.BLOCKED
            else SubmissionStatus.FAILED
        )
        resources = list(task.plan.expected_artifacts if task.plan else ())
        if task.imported.examination is not None:
            resources.extend(
                [
                    f"project={task.imported.examination.authorized_project}",
                    f"region={task.imported.examination.region}",
                    f"zone={task.imported.examination.zone}",
                ]
            )
        verification = tuple(
            f"{run.executable or run.tool_id} exit={run.exit_code} evidence={run.evidence_id}"
            for run in runs
            if run.tool_id
        )
        values = {
            "id": f"submission:{uuid.uuid4().hex}",
            "task_id": task_id,
            "status": status,
            "summary": (
                "The approved task completed with recorded tests and verification evidence."
                if status == SubmissionStatus.COMPLETE
                else (
                    f"The task ended {status.value.lower()}: "
                    f"{task.blocked_reason or 'see evidence'}."
                )
            ),
            "resources": tuple(resources),
            "verification": verification,
            "reasoning": (
                " ".join(task.plan.reasoning.split()[:150])
                if task.plan
                else "No approved plan was executed."
            ),
            "evidence": tuple(f"{item.id}: {item.event_type}" for item in evidence),
            "known_issues": ()
            if status == SubmissionStatus.COMPLETE
            else (task.blocked_reason or "Task did not complete.",),
            "locked": False,
            "created_at": utc_now(),
        }
        digest = content_digest({key: value for key, value in values.items() if key != "locked"})
        submission = CandidateSubmission(**values, submission_digest=digest)
        self.store.save_submission(submission)
        self.store.append_evidence(
            task_id,
            kind=EvidenceKind.SUBMISSION,
            event_type="submission_generated",
            payload={"submission_id": submission.id, "submission_digest": digest},
        )
        return submission

    def lock_submission(self, task_id: str) -> CandidateSubmission:
        locked = self.store.lock_submission(task_id)
        self.store.append_evidence(
            task_id,
            kind=EvidenceKind.SUBMISSION,
            event_type="submission_locked",
            payload={"submission_id": locked.id, "submission_digest": locked.submission_digest},
        )
        return locked

    def reopen_submission(self, task_id: str) -> CandidateSubmission:
        reopened = self.store.reopen_submission(task_id)
        self.store.append_evidence(
            task_id,
            kind=EvidenceKind.SUBMISSION,
            event_type="submission_reopened",
            payload={
                "submission_id": reopened.id,
                "submission_digest": reopened.submission_digest,
                "actor": self.owner_id,
            },
        )
        return reopened

    def health(self, task_id: str | None = None) -> WorkbenchHealth:
        task = self.store.get_task(task_id) if task_id else None
        exam = task.imported.examination if task else None
        missing: list[str] = []
        if not self.model.connected:
            missing.append("live Lil Tweak model adapter is disabled")
        if not self.executor.connected:
            missing.append("qualified bounded command runner is disconnected")
        if self.store.is_emergency_stopped():
            missing.append("emergency stop is active")
        return WorkbenchHealth(
            provider=self.model.provider_name,
            model=self.model.model_name,
            reasoning_tier=self.model.reasoning_tier,
            runner_connected=self.executor.connected,
            repository=task.imported.repository_id if task else None,
            project=exam.authorized_project if exam else None,
            identity=exam.candidate_service_account if exam else None,
            network=(
                NetworkMode.TASK_SCOPED
                if exam is not None and self.executor.connected
                else NetworkMode.DENIED
            ),
            execution_permission=(
                self.executor.connected
                and not self.store.is_emergency_stopped()
                and task is not None
                and task.state == WorkbenchState.APPROVED
            ),
            cost_ceiling_usd=self.cost_ceiling_usd,
            emergency_stopped=self.store.is_emergency_stopped(),
            missing_prerequisites=tuple(missing),
        )

    def _validate_plan(self, task: WorkbenchTask, result: ModelPlanResult) -> None:
        if result.plan.source_snapshot_digest != task.imported.source_snapshot_digest:
            raise WorkbenchError("model plan is bound to another source snapshot")
        for step in result.plan.steps:
            self.policy.authorize(task, step)
        if task.imported.examination is not None:
            estimated_cloud_cost = sum(
                step.command.estimated_cost_usd
                for step in result.plan.steps
                if step.command is not None
            )
            if estimated_cloud_cost > task.imported.examination.spending_ceiling_usd:
                raise WorkbenchError("plan exceeds the examination spending ceiling")
            for step in result.plan.steps:
                if (
                    step.kind == ToolKind.COMMAND
                    and step.command is not None
                    and step.command.executable in {"gcloud", "kubectl"}
                ):
                    self.policy.gcp.validate(step.command, task.imported.examination)

    def _new_approval(
        self,
        task: WorkbenchTask,
        *,
        purpose: str = "execute",
        tool_digests: tuple[str, ...] | None = None,
        attempt: int | None = None,
    ) -> WorkbenchApproval:
        if task.plan is None or task.plan_digest is None:
            raise WorkbenchError("approval requires an immutable plan")
        exam = task.imported.examination
        attempt = task.active_attempt + 1 if attempt is None else attempt
        tool_digests = (
            tuple(step.request_digest for step in task.plan.steps)
            if tool_digests is None
            else tool_digests
        )
        bindings = {
            "task_id": task.id,
            "purpose": purpose,
            "plan_digest": task.plan_digest,
            "source_snapshot_digest": task.imported.source_snapshot_digest,
            "project": exam.authorized_project if exam else None,
            "candidate_identity": exam.candidate_service_account if exam else None,
            "execution_attempt": attempt,
            "approved_tool_digests": tool_digests,
        }
        now = utc_now()
        return WorkbenchApproval(
            id=f"approval:{uuid.uuid4().hex}",
            **bindings,
            approval_digest=content_digest(bindings),
            status="pending",
            created_at=now,
            expires_at=now + timedelta(minutes=self.approval_ttl_minutes),
        )


def canonical_summary(payload: dict[str, object]) -> str:
    return "\n".join(f"{key}={payload[key]}" for key in sorted(payload))
