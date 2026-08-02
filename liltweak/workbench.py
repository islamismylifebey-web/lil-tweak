from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable
from datetime import timedelta
from typing import cast

from .canonical_lifecycle import CapabilityName
from .context_manifest import ContextManifest, ContextPolicy, build_context_manifest
from .creator import CreatorService
from .creator_contract import (
    CreatorCompileRequest,
    CreatorContextItem,
    RiskDomain,
    RoutePreviewRequest,
    RouteStatus,
)
from .repository import secret_rule_ids
from .workbench_agent import ModelPlanResult, WorkbenchModelAdapter
from .workbench_capabilities import build_capability_statuses
from .workbench_contract import (
    ApprovalDecision,
    ApprovalPurpose,
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
from .workbench_repository import (
    WorkbenchRepositoryError,
    WorkbenchRepositoryInspection,
    WorkbenchRepositoryRegistry,
)
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
        repository_registry: WorkbenchRepositoryRegistry | None = None,
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
        self.repository_registry = repository_registry
        input_ceiling = getattr(model, "input_token_ceiling", 12_000)
        output_ceiling = getattr(model, "output_token_ceiling", 4_096)
        if (
            not isinstance(input_ceiling, int)
            or isinstance(input_ceiling, bool)
            or not isinstance(output_ceiling, int)
            or isinstance(output_ceiling, bool)
        ):
            raise ValueError("Workbench model token ceilings are invalid")
        self.context_policy = ContextPolicy(
            input_token_ceiling=input_ceiling,
            reserved_output_tokens=output_ceiling,
        )

    def receive(self, imported: TaskImport, *, task_id: str | None = None) -> WorkbenchTask:
        if self.store.is_emergency_stopped():
            raise WorkbenchError("emergency stop is active")
        ingress = json.dumps(
            {"title": imported.title, "direction": imported.direction},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if secret_rule_ids(ingress):
            raise WorkbenchError("task input contains secret-shaped material")
        if (
            imported.repository_id is not None
            and imported.repository_id not in self.authorized_repositories
        ):
            raise WorkbenchError("repository identity is not in the server-owned registry")
        if (
            imported.repository_id is not None
            and self.repository_registry is not None
            and imported.repository_fingerprint is None
        ):
            raise WorkbenchError("repository tasks require a server-generated source binding")
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
            id=task_id or f"task:{uuid.uuid4().hex}",
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
                "repository_fingerprint": imported.repository_fingerprint,
                "mode": imported.mode.value,
                "creator_route_status": route.status.value,
                "trusted_prerequisites_pending": list(envelope.brief.trusted_prerequisites),
            },
        )
        return task

    def receive_repository_task(
        self,
        *,
        repository_id: str,
        title: str,
        direction: str,
    ) -> WorkbenchTask:
        if self.repository_registry is None:
            raise WorkbenchError("local repository onboarding is not configured")
        inspection = self.repository_registry.inspect(repository_id, direction=direction)
        if not inspection.candidate_commands:
            raise WorkbenchError("repository has no server-discovered bounded acceptance command")
        task_id = f"task:{uuid.uuid4().hex}"
        destination = self.workspaces.task_root(task_id)
        try:
            self.repository_registry.materialize(
                repository_id,
                expected_source_fingerprint=inspection.source_fingerprint,
                destination=destination,
            )
            source_digest = self.workspaces.tree_digest(destination)
            imported = TaskImport(
                title=title,
                direction=direction,
                repository_id=repository_id,
                repository_fingerprint=inspection.source_fingerprint,
                source_snapshot_digest=source_digest,
                requires_changes=True,
                acceptance_commands=inspection.candidate_commands,
            )
            return self.receive(imported, task_id=task_id)
        except Exception:
            self.workspaces.discard_task_workspace(task_id)
            raise

    def inspect_repository(
        self,
        repository_id: str,
        *,
        direction: str = "",
    ) -> WorkbenchRepositoryInspection:
        if self.repository_registry is None:
            raise WorkbenchError("local repository onboarding is not configured")
        return self.repository_registry.inspect(repository_id, direction=direction)

    @property
    def repository_ids(self) -> tuple[str, ...]:
        if self.repository_registry is None:
            return ()
        return self.repository_registry.repository_ids

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
            repository_facts: dict[str, object] = {}
            if task.imported.repository_id is not None:
                inspection = self._inspect_bound_repository(task)
                repository_facts = {
                    "repository_fingerprint": inspection.source_fingerprint,
                    "branch": inspection.git.branch,
                    "head": inspection.git.head,
                    "dirty": inspection.git.dirty,
                    "languages": inspection.languages,
                    "framework_clues": list(inspection.framework_clues),
                    "screened_file_count": inspection.screened_file_count,
                }
            self.store.append_evidence(
                task_id,
                kind=EvidenceKind.SOURCE,
                event_type="source_inspected",
                payload={
                    "source_snapshot_digest": digest,
                    "file_count": file_count,
                    "total_bytes": total_bytes,
                    "read_only_observation": True,
                    **repository_facts,
                },
            )
            examination = task.imported.examination
            if examination is not None:
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
                        "examination_config_digest": examination.config_digest,
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

    def _planning_context(
        self,
        task: WorkbenchTask,
    ) -> tuple[str, ContextManifest, str, str | None, str]:
        """Build a bounded manifest from the materialized source, never the owner path."""

        workspace = self.workspaces.task_root(task.id)
        before_digest = self.workspaces.tree_digest(workspace)
        if before_digest != task.imported.source_snapshot_digest:
            raise WorkbenchError("workspace source changed before context assembly")

        git_facts: dict[str, object] | None = None
        source_revision = task.imported.source_snapshot_digest
        if task.imported.repository_id is not None:
            inspection = self._inspect_bound_repository(task)
            source_revision = inspection.git.head
            git_facts = {
                "branch": inspection.git.branch,
                "head": inspection.git.head,
                "dirty": inspection.git.dirty,
                "staged_count": inspection.git.staged_count,
                "modified_count": inspection.git.modified_count,
                "untracked_count": inspection.git.untracked_count,
                "status_digest": inspection.git.status_digest,
            }

        context_repository_id = task.imported.repository_id or (
            f"workbench:{hashlib.sha256(task.id.encode()).hexdigest()[:32]}"
        )
        try:
            manifest = build_context_manifest(
                workspace,
                repository_id=context_repository_id,
                source_revision=source_revision,
                objective=task.imported.direction,
                policy=self.context_policy,
            )
        except ValueError as exc:
            raise WorkbenchError("deterministic context assembly failed closed") from exc

        after_digest = self.workspaces.tree_digest(workspace)
        if after_digest != before_digest or after_digest != task.imported.source_snapshot_digest:
            raise WorkbenchError("workspace source changed during context assembly")
        if manifest.scan_truncated:
            raise WorkbenchError("deterministic context assembly was truncated")
        prohibited_reasons = {
            "credential_shaped_content",
            "hardlink",
            "sensitive_path",
        }
        observed_prohibited = sorted(
            {
                reason
                for item in manifest.files
                for reason in item.policy_reasons
                if reason in prohibited_reasons
            }
        )
        if observed_prohibited:
            raise WorkbenchError(
                "deterministic context assembly rejected unsafe workspace content: "
                + ",".join(observed_prohibited)
            )

        selected_paths = {item.path for item in manifest.excerpts}
        exclusion_counts: dict[str, int] = {}
        for item in manifest.files:
            for reason in item.policy_reasons:
                exclusion_counts[reason] = exclusion_counts.get(reason, 0) + 1
        planning_payload = {
            "schema_version": "workbench-planning-context-v2",
            "source_binding": {
                "workspace_tree_digest": before_digest,
                "context_source_tree_digest": manifest.source_tree_digest,
                "context_manifest_digest": manifest.manifest_digest,
                "source_revision": manifest.source_revision,
            },
            "context_manifest": {
                "schema_version": manifest.schema_version,
                "objective_sha256": manifest.objective_sha256,
                "policy": manifest.policy.model_dump(mode="json"),
                "selected_files": [
                    {
                        "path": item.path,
                        "category": item.category.value,
                        "sha256": item.sha256,
                        "byte_count": item.byte_count,
                    }
                    for item in manifest.files
                    if item.path in selected_paths
                ],
                "excerpts": [item.model_dump(mode="json") for item in manifest.excerpts],
                "instructions": [item.model_dump(mode="json") for item in manifest.instructions],
                "project_signals": [
                    item.model_dump(mode="json") for item in manifest.project_signals
                ],
                "diagnostics": [item.model_dump(mode="json") for item in manifest.diagnostics],
                "exclusion_counts": dict(sorted(exclusion_counts.items())),
                "scan_blockers": list(manifest.scan_blockers),
                "source_tree_digest": manifest.source_tree_digest,
                "token_budget": manifest.token_budget.model_dump(mode="json"),
                "manifest_digest": manifest.manifest_digest,
            },
            "trusted_git_facts": git_facts,
            "trusted_acceptance": {
                "commands": list(task.imported.acceptance_commands),
                "commands_digest": content_digest(task.imported.acceptance_commands),
            },
        }
        summary = json.dumps(
            planning_payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        return (
            summary,
            manifest,
            before_digest,
            str(git_facts["status_digest"]) if git_facts is not None else None,
            content_digest(task.imported.acceptance_commands),
        )

    async def analyze(self, task_id: str) -> tuple[WorkbenchTask, WorkbenchApproval]:
        if self.store.is_emergency_stopped():
            raise WorkbenchError("emergency stop is active")
        task = self.store.get_task(task_id)
        if task.state != WorkbenchState.ANALYZED:
            raise WorkbenchError("task is not ready for planning")
        if not self.store.canonical.capability(CapabilityName.MODEL).operational:
            raise WorkbenchError("canonical model capability is not operational")
        if not task.creator_brief_digest or not task.creator_route_digest:
            raise WorkbenchError("Creator control-plane bindings are missing")
        (
            summary,
            context_manifest,
            workspace_tree_digest,
            git_status_digest,
            acceptance_commands_digest,
        ) = self._planning_context(task)
        planning_context_digest = hashlib.sha256(summary.encode()).hexdigest()
        self.store.append_evidence(
            task_id,
            kind=EvidenceKind.SOURCE,
            event_type="context_manifest_built",
            payload={
                "context_manifest_digest": context_manifest.manifest_digest,
                "context_source_tree_digest": context_manifest.source_tree_digest,
                "workspace_tree_digest": workspace_tree_digest,
                "source_snapshot_digest": task.imported.source_snapshot_digest,
                "source_revision": context_manifest.source_revision,
                "context_policy_digest": content_digest(context_manifest.policy),
                "planning_context_digest": planning_context_digest,
                "selected_context_utf8_bytes": (
                    context_manifest.token_budget.selected_context_utf8_bytes
                ),
                "context_token_upper_bound": (
                    context_manifest.token_budget.conservative_context_token_upper_bound
                ),
                "git_status_digest": git_status_digest,
                "acceptance_commands_digest": acceptance_commands_digest,
                "read_only_observation": True,
            },
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
                "reasoning_mode": result.reasoning_mode,
                "reasoning_profile": result.reasoning_profile,
                "response_id_hash": result.response_id_hash
                or (
                    hashlib.sha256(result.response_id.encode()).hexdigest()
                    if result.response_id
                    else None
                ),
                "input_tokens": result.input_tokens,
                "output_tokens": result.output_tokens,
                "provider_input_digest": result.provider_input_digest,
                "model_input_digest": result.input_digest,
                "planning_context_digest": planning_context_digest,
                "context_manifest_digest": context_manifest.manifest_digest,
                "context_source_tree_digest": context_manifest.source_tree_digest,
                "workspace_tree_digest": workspace_tree_digest,
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
                "context_manifest_digest": context_manifest.manifest_digest,
                "context_source_tree_digest": context_manifest.source_tree_digest,
                "planning_context_digest": planning_context_digest,
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
            payload={
                "approval_id": approval.id,
                "approval_digest": approval.approval_digest,
                "decision": decision.decision,
                "actor_id": self.owner_id,
                "decided_at": approval.decided_at.isoformat() if approval.decided_at else None,
            },
        )
        if decision.decision == "approve":
            return self.store.get_task(task_id)
        if decision.decision == "request_revision":
            raise WorkbenchError("canonical lifecycle requires a new task for a revised exact plan")
        return self.store.get_task(task_id)

    def reissue_expired_approval(
        self,
        task_id: str,
        approval_id: str,
    ) -> WorkbenchApproval:
        task = self.store.get_task(task_id)
        approval = self.store.get_approval(approval_id)
        if approval.task_id != task_id or approval.status != "expired":
            raise WorkbenchError("only an expired approval for this task can be reissued")
        if task.state not in {
            WorkbenchState.AWAITING_APPROVAL,
            WorkbenchState.APPROVED,
        }:
            raise WorkbenchError("task is not waiting on an expired approval")
        if task.state == WorkbenchState.APPROVED:
            task = self.store.transition(task_id, WorkbenchState.AWAITING_APPROVAL)
        replacement = self._new_approval(
            task,
            purpose=approval.purpose,
            tool_digests=approval.approved_tool_digests,
            attempt=approval.execution_attempt,
        )
        self.store.publish_approval(replacement)
        self.store.append_evidence(
            task_id,
            kind=EvidenceKind.APPROVAL,
            event_type="approval_reissued",
            payload={
                "expired_approval_id": approval.id,
                "replacement_approval_id": replacement.id,
                "replacement_approval_digest": replacement.approval_digest,
                "purpose": replacement.purpose.value,
                "actor_id": self.owner_id,
            },
        )
        return replacement

    async def execute(self, task_id: str, approval_id: str) -> WorkbenchTask:
        task = self.store.get_task(task_id)
        if task.state != WorkbenchState.APPROVED or task.plan is None:
            raise WorkbenchError("task is not approved for execution")
        plan = task.plan
        if self.store.is_emergency_stopped():
            raise WorkbenchError("emergency stop is active")
        if not self.executor.connected:
            raise WorkbenchError("qualified bounded command runner is disconnected")
        if task.imported.repository_id is not None:
            self._inspect_bound_repository(task)
        approval = self.store.get_approval(approval_id)
        if approval.purpose != ApprovalPurpose.EXECUTE:
            raise WorkbenchError("rollback approval cannot authorize plan execution")
        attempt = task.active_attempt + 1
        tool_digests = tuple(step.request_digest for step in plan.steps)
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
                expected_purpose=ApprovalPurpose.EXECUTE,
                expected_owner_id=self.owner_id,
                policy_digest=self.policy.policy_digest,
                runner_grant_digest=self.executor.authorization_digest,
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
        task = self.store.get_task(task_id)
        if task.state != WorkbenchState.EXECUTING or task.active_attempt != attempt:
            raise WorkbenchError("canonical dispatch did not enter the exact execution attempt")
        try:
            entered_testing = False
            required_failures: list[str] = []
            for step in plan.steps:
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
                self.store.assert_active_dispatch_authority(
                    task_id,
                    expected_attempt=attempt,
                    request=step,
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
            current_runs = [run for run in runs if run.attempt == attempt]
            test_ids = {
                step.tool_id
                for step in plan.steps
                if step.required and step.phase == StepPhase.TEST
            }
            verification_ids = {
                step.tool_id
                for step in plan.steps
                if step.required and step.phase == StepPhase.VERIFICATION
            }
            passed_ids = {run.tool_id for run in current_runs if run.success}
            if (
                not test_ids
                or not verification_ids
                or not test_ids.issubset(passed_ids)
                or not verification_ids.issubset(passed_ids)
            ):
                raise WorkbenchError("required test and verification evidence is incomplete")
            removed_transients = self.workspaces.discard_server_transients(task_id, snapshot)
            verified_artifacts = self.workspaces.expected_artifacts(
                task_id,
                plan.expected_artifacts,
            )
            final_tree_digest = self.workspaces.tree_digest(self.workspaces.task_root(task_id))
            patch_name, patch_digest, changed_paths = self.workspaces.generate_patch(
                task_id,
                attempt,
                snapshot,
            )
            if task.imported.requires_changes and not changed_paths:
                raise WorkbenchError("repository task required a source change but produced none")
            completion = self.store.append_evidence(
                task_id,
                kind=EvidenceKind.EXECUTED,
                event_type="execution_completed",
                payload={
                    "attempt": attempt,
                    "source_snapshot_digest": snapshot_digest,
                    "final_tree_digest": final_tree_digest,
                    "patch_name": patch_name,
                    "patch_digest": patch_digest,
                    "changed_paths": list(changed_paths),
                    "removed_server_transients": list(removed_transients),
                    "verified_artifacts": list(verified_artifacts),
                    "test_tool_ids": sorted(test_ids),
                    "verification_tool_ids": sorted(verification_ids),
                    "runner_provider": self.executor.provider_name,
                    "runner_grant_digest": self.executor.authorization_digest,
                },
            )
            task = self.store.transition(task_id, WorkbenchState.VERIFIED)
            independent_examiner_verification = False
            self.store.append_evidence(
                task_id,
                kind=EvidenceKind.VERIFIED,
                event_type="local_verification_satisfied",
                payload={
                    "verified": True,
                    "test_tool_ids": sorted(test_ids),
                    "verification_tool_ids": sorted(verification_ids),
                    "run_ids": [run.id for run in current_runs],
                    "completion_evidence_id": completion.id,
                    "final_tree_digest": final_tree_digest,
                    "patch_digest": patch_digest,
                    "independent_examiner_verification": independent_examiner_verification,
                    "completion_claim_allowed": independent_examiner_verification,
                },
            )
            if not independent_examiner_verification:
                return task
            return self.store.transition(task_id, WorkbenchState.COMPLETED)
        except Exception as exc:
            current_task = self.store.get_task(task_id)
            if current_task.state in {WorkbenchState.EXECUTING, WorkbenchState.TESTING}:
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
        self.store.emergency_stop(True, actor_id=self.owner_id)
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

    def reset_emergency_stop(self) -> None:
        if self.executor.connected:
            raise WorkbenchError(
                "emergency reset requires a disconnected runner with no possible active process"
            )
        nonterminal = {
            WorkbenchState.RECEIVED,
            WorkbenchState.INSPECTING,
            WorkbenchState.ANALYZED,
            WorkbenchState.PLAN_READY,
            WorkbenchState.AWAITING_APPROVAL,
            WorkbenchState.APPROVED,
            WorkbenchState.EXECUTING,
            WorkbenchState.TESTING,
            WorkbenchState.VERIFIED,
        }
        if any(task.state in nonterminal for task in self.store.list_tasks(limit=200)):
            raise WorkbenchError("emergency reset requires every task to be terminal")
        self.store.emergency_stop(False, actor_id=self.owner_id)

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
            purpose=ApprovalPurpose.ROLLBACK,
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
        if approval.purpose != ApprovalPurpose.ROLLBACK:
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
            expected_purpose=ApprovalPurpose.ROLLBACK,
            expected_owner_id=self.owner_id,
            policy_digest=self.policy.policy_digest,
            runner_grant_digest=None,
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
        raise WorkbenchError(
            "rolled-back tasks are terminal; import the verified source as a new task revision"
        )

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
        completion = next(
            (item for item in reversed(evidence) if item.event_type == "execution_completed"),
            None,
        )
        if status == SubmissionStatus.COMPLETE and completion is None:
            raise WorkbenchError("completed task is missing final execution evidence")
        if completion is not None:
            self._verify_completion_artifacts(task, completion.payload)
        resources: list[str] = []
        if completion is not None:
            resources.extend(
                [
                    f"final_tree_sha256={completion.payload['final_tree_digest']}",
                    (
                        f"patch={completion.payload['patch_name']} "
                        f"sha256={completion.payload['patch_digest']}"
                    ),
                ]
            )
            verified_artifacts = cast(
                Iterable[object],
                completion.payload.get("verified_artifacts", []),
            )
            resources.extend(
                (
                    f"artifact={item['path']} sha256={item['sha256']} "
                    f"bytes={item['bytes']} executable={str(item['executable']).lower()}"
                )
                for item in verified_artifacts
                if isinstance(item, dict)
            )
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
        task = self.store.get_task(task_id)
        if task.state == WorkbenchState.COMPLETED:
            evidence = self.store.list_evidence(task_id)
            completion = next(
                (item for item in reversed(evidence) if item.event_type == "execution_completed"),
                None,
            )
            if completion is None:
                raise WorkbenchError("completed task is missing final execution evidence")
            self._verify_completion_artifacts(task, completion.payload)
        return self.store.lock_submission(task_id, actor_id=self.owner_id)

    def reopen_submission(self, task_id: str) -> CandidateSubmission:
        return self.store.reopen_submission(task_id, actor_id=self.owner_id)

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
        evidence_integrity = (
            "durable_hmac" if self.store.durable_evidence_integrity else "ephemeral_hmac"
        )
        if task is not None:
            try:
                self.store.list_evidence(task.id)
            except WorkbenchConflict:
                evidence_integrity = "invalid"
                missing.append("evidence integrity verification failed")
        return WorkbenchHealth(
            provider=self.model.provider_name,
            model=self.model.model_name,
            reasoning_tier=self.model.reasoning_tier,
            model_connected=self.model.connected,
            model_status=("connected" if self.model.connected else "disabled"),
            runner_provider=self.executor.provider_name,
            runner_qualification=self.executor.qualification_status,
            runner_connection=("connected" if self.executor.connected else "disconnected"),
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
            evidence_integrity=evidence_integrity,
            missing_prerequisites=tuple(missing),
            capabilities=build_capability_statuses(
                model=self.model,
                runner=self.executor,
            ),
        )

    def _validate_plan(self, task: WorkbenchTask, result: ModelPlanResult) -> None:
        if result.plan.source_snapshot_digest != task.imported.source_snapshot_digest:
            raise WorkbenchError("model plan is bound to another source snapshot")
        for step in result.plan.steps:
            self.policy.authorize(task, step)
        if task.imported.repository_id is not None:
            planned_commands = {
                " ".join((step.command.executable, *step.command.args))
                for step in result.plan.steps
                if step.required
                and step.command is not None
                and step.phase in {StepPhase.TEST, StepPhase.VERIFICATION}
            }
            if not planned_commands.intersection(task.imported.acceptance_commands):
                raise WorkbenchError(
                    "plan omits every server-discovered repository acceptance command"
                )
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

    def _inspect_bound_repository(
        self,
        task: WorkbenchTask,
    ) -> WorkbenchRepositoryInspection:
        if (
            self.repository_registry is None
            or task.imported.repository_id is None
            or task.imported.repository_fingerprint is None
        ):
            raise WorkbenchError("server-owned repository binding is incomplete")
        try:
            inspection = self.repository_registry.inspect(
                task.imported.repository_id,
                direction=task.imported.direction,
            )
        except WorkbenchRepositoryError as exc:
            raise WorkbenchError("registered repository inspection failed closed") from exc
        if inspection.source_fingerprint != task.imported.repository_fingerprint:
            raise WorkbenchError("registered repository changed after task import")
        return inspection

    def _new_approval(
        self,
        task: WorkbenchTask,
        *,
        purpose: ApprovalPurpose = ApprovalPurpose.EXECUTE,
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
            "task_digest": task.task_digest,
            "purpose": purpose.value,
            "plan_digest": task.plan_digest,
            "source_snapshot_digest": task.imported.source_snapshot_digest,
            "repository_id": task.imported.repository_id,
            "examination_digest": exam.config_digest if exam else None,
            "project": exam.authorized_project if exam else None,
            "candidate_identity": exam.candidate_service_account if exam else None,
            "execution_attempt": attempt,
            "approved_tool_digests": tool_digests,
            "policy_digest": self.policy.policy_digest,
            "runner_grant_digest": (
                self.executor.authorization_digest if purpose == ApprovalPurpose.EXECUTE else None
            ),
            "network_mode": self._plan_network_mode(task, purpose).value,
            "nonce": f"nonce:{uuid.uuid4().hex}",
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

    @staticmethod
    def _plan_network_mode(task: WorkbenchTask, purpose: ApprovalPurpose) -> NetworkMode:
        if purpose != ApprovalPurpose.EXECUTE or task.plan is None:
            return NetworkMode.DENIED
        if any(
            step.command is not None and step.command.network == NetworkMode.TASK_SCOPED
            for step in task.plan.steps
        ):
            return NetworkMode.TASK_SCOPED
        return NetworkMode.DENIED

    def export_patch(self, task_id: str) -> str:
        task = self.store.get_task(task_id)
        if task.state not in {WorkbenchState.VERIFIED, WorkbenchState.COMPLETED}:
            raise WorkbenchError("patch export requires verified execution")
        evidence = self.store.list_evidence(task_id)
        completion = next(
            (item for item in reversed(evidence) if item.event_type == "execution_completed"),
            None,
        )
        if completion is None:
            raise WorkbenchError("verified task is missing authenticated patch evidence")
        self._verify_completion_artifacts(task, completion.payload)
        return self.workspaces.read_patch(
            task_id,
            str(completion.payload["patch_name"]),
            str(completion.payload["patch_digest"]),
        )

    def _verify_completion_artifacts(
        self,
        task: WorkbenchTask,
        payload: dict[str, object],
    ) -> None:
        required = {
            "attempt",
            "final_tree_digest",
            "patch_name",
            "patch_digest",
            "verified_artifacts",
        }
        if not required.issubset(payload):
            raise WorkbenchError("authenticated completion manifest is incomplete")
        if payload["attempt"] != task.active_attempt:
            raise WorkbenchError("authenticated patch attempt does not match the task")
        final_digest = self.workspaces.tree_digest(self.workspaces.task_root(task.id))
        if final_digest != payload["final_tree_digest"]:
            raise WorkbenchError("completed source tree changed after verification")
        self.workspaces.read_patch(
            task.id,
            str(payload["patch_name"]),
            str(payload["patch_digest"]),
        )
        self.workspaces.verify_artifacts(task.id, payload["verified_artifacts"])


def canonical_summary(payload: dict[str, object]) -> str:
    return "\n".join(f"{key}={payload[key]}" for key in sorted(payload))
