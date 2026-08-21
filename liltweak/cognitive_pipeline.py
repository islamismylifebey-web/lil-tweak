from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, model_validator

from .cognitive_contract import CognitiveFinalization
from .reasoning_contract import (
    CandidateCritique,
    CandidateManifest,
    CheckResult,
    CognitiveState,
    ContextManifest,
    EngineeringPlan,
    OutcomeStatus,
    PlanCritique,
    ReasoningRole,
    Sha256,
    TaskIntake,
    ToolAuthority,
    VerificationDecision,
)
from .reasoning_policy import ReasoningProfileName, profile_for_role
from .reasoning_prompts import (
    PROMPT_OUTPUT_TYPES,
    PromptName,
    render_prompt,
)

COGNITIVE_PIPELINE_VERSION: Final[Literal["1.0.0"]] = "1.0.0"
type TerminalCognitiveState = Literal[
    CognitiveState.COGNITIVE_READY,
    CognitiveState.NO_CHANGE_PROPOSED,
    CognitiveState.BLOCKED,
    CognitiveState.FAILED,
]


class CognitiveSchema(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class CognitiveCallRequest(CognitiveSchema):
    schema_version: Literal["1.0.0"]
    call_id: StrictStr = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    role: ReasoningRole
    profile_name: ReasoningProfileName
    prompt_name: PromptName
    prompt_version: Literal["1.1.0"]
    instructions: StrictStr
    instructions_digest: Sha256
    input_text: StrictStr
    input_digest: Sha256
    provider_bound_prompt_digest: Sha256
    output_schema_name: StrictStr
    output_schema_digest: Sha256
    tool_authority: Literal[ToolAuthority.NONE]
    tools: tuple[StrictStr, ...]
    previous_response_id: Literal[None]
    fresh_context: StrictBool

    @model_validator(mode="after")
    def validate_no_tools(self) -> CognitiveCallRequest:
        if self.tools:
            raise ValueError("cognitive reasoning calls cannot receive tools")
        if self.role in {ReasoningRole.CRITIC, ReasoningRole.VERIFIER} and not self.fresh_context:
            raise ValueError("critic and verifier calls require a fresh context")
        return self


@dataclass(frozen=True)
class CognitiveProviderResult[TOutput: BaseModel]:
    output: TOutput
    response_id: str


class CognitiveProvider(Protocol):
    async def call[TOutput: BaseModel](
        self,
        *,
        request: CognitiveCallRequest,
        output_type: type[TOutput],
    ) -> CognitiveProviderResult[TOutput]: ...


class DeterministicCandidateChecker(Protocol):
    async def check(
        self,
        *,
        task: TaskIntake,
        context: ContextManifest,
        plan: EngineeringPlan,
        candidate: CandidateManifest,
    ) -> tuple[CheckResult, ...]: ...


class CognitiveEvent(CognitiveSchema):
    sequence: StrictInt = Field(ge=1)
    attempt: StrictInt = Field(ge=1, le=3)
    previous_state: CognitiveState
    state: CognitiveState
    detail: StrictStr = Field(min_length=1, max_length=1_000)
    call_id: StrictStr | None
    response_id_digest: Sha256 | None


class CognitivePipelineResult(CognitiveSchema):
    schema_version: Literal["1.0.0"]
    run_id: StrictStr = Field(pattern=r"^cognitive_[A-Za-z0-9][A-Za-z0-9._:-]{0,117}$")
    task_id: StrictStr
    state: Literal[
        CognitiveState.COGNITIVE_READY,
        CognitiveState.NO_CHANGE_PROPOSED,
        CognitiveState.BLOCKED,
        CognitiveState.FAILED,
    ]
    events: tuple[CognitiveEvent, ...]
    call_ids: tuple[StrictStr, ...]
    response_ids: tuple[StrictStr, ...]
    full_repairs: StrictInt = Field(ge=0, le=2)
    plan_digest: Sha256 | None
    candidate_digest: Sha256 | None
    verification_digest: Sha256 | None
    finalization_digest: Sha256 | None
    blocked_reason: StrictStr | None
    task_completion_claimed: Literal[False]

    @model_validator(mode="after")
    def validate_result(self) -> CognitivePipelineResult:
        if len(self.call_ids) != len(set(self.call_ids)):
            raise ValueError("cognitive call ids must be unique")
        if len(self.response_ids) != len(set(self.response_ids)):
            raise ValueError("cognitive response ids must be unique")
        if len(self.call_ids) != len(self.response_ids):
            raise ValueError("every cognitive call must have exactly one response id")
        if self.state in {CognitiveState.BLOCKED, CognitiveState.FAILED}:
            if not self.blocked_reason:
                raise ValueError("blocked or failed cognitive result requires a reason")
        elif self.blocked_reason is not None:
            raise ValueError("ready cognitive result cannot carry a blocked reason")
        return self


class CognitivePipelineError(RuntimeError):
    pass


_ALLOWED_TRANSITIONS: dict[CognitiveState, frozenset[CognitiveState]] = {
    CognitiveState.REQUESTED: frozenset(
        {CognitiveState.CONTRACT_READY, CognitiveState.BLOCKED, CognitiveState.FAILED}
    ),
    CognitiveState.CONTRACT_READY: frozenset(
        {CognitiveState.CONTEXT_READY, CognitiveState.BLOCKED, CognitiveState.FAILED}
    ),
    CognitiveState.CONTEXT_READY: frozenset(
        {CognitiveState.PLAN_PROPOSED, CognitiveState.BLOCKED, CognitiveState.FAILED}
    ),
    CognitiveState.PLAN_PROPOSED: frozenset(
        {
            CognitiveState.PLAN_CRITIQUED,
            CognitiveState.CONTEXT_READY,
            CognitiveState.BLOCKED,
            CognitiveState.FAILED,
        }
    ),
    CognitiveState.PLAN_CRITIQUED: frozenset(
        {
            CognitiveState.PLAN_VERIFIED,
            CognitiveState.CONTEXT_READY,
            CognitiveState.BLOCKED,
            CognitiveState.FAILED,
        }
    ),
    CognitiveState.PLAN_VERIFIED: frozenset(
        {
            CognitiveState.CANDIDATE_GENERATED,
            CognitiveState.BLOCKED,
            CognitiveState.FAILED,
        }
    ),
    CognitiveState.CANDIDATE_GENERATED: frozenset(
        {
            CognitiveState.CANDIDATE_CRITIQUED,
            CognitiveState.NO_CHANGE_PROPOSED,
            CognitiveState.CONTEXT_READY,
            CognitiveState.BLOCKED,
            CognitiveState.FAILED,
        }
    ),
    CognitiveState.CANDIDATE_CRITIQUED: frozenset(
        {
            CognitiveState.DETERMINISTIC_CHECKED,
            CognitiveState.CONTEXT_READY,
            CognitiveState.BLOCKED,
            CognitiveState.FAILED,
        }
    ),
    CognitiveState.DETERMINISTIC_CHECKED: frozenset(
        {
            CognitiveState.INDEPENDENTLY_VERIFIED,
            CognitiveState.CONTEXT_READY,
            CognitiveState.BLOCKED,
            CognitiveState.FAILED,
        }
    ),
    CognitiveState.INDEPENDENTLY_VERIFIED: frozenset(
        {
            CognitiveState.COGNITIVE_READY,
            CognitiveState.CONTEXT_READY,
            CognitiveState.BLOCKED,
            CognitiveState.FAILED,
        }
    ),
    CognitiveState.COGNITIVE_READY: frozenset(),
    CognitiveState.NO_CHANGE_PROPOSED: frozenset(),
    CognitiveState.BLOCKED: frozenset(),
    CognitiveState.FAILED: frozenset(),
}


class CognitivePipelineController:
    def __init__(
        self,
        *,
        provider: CognitiveProvider,
        checker: DeterministicCandidateChecker,
        maximum_full_repairs: int = 2,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        if maximum_full_repairs < 0 or maximum_full_repairs > 2:
            raise ValueError("maximum full repairs must be between zero and two")
        self._provider = provider
        self._checker = checker
        self._maximum_full_repairs = maximum_full_repairs
        self._id_factory = id_factory or (lambda: uuid.uuid4().hex)

    async def run(
        self,
        *,
        task: TaskIntake,
        context: ContextManifest,
    ) -> CognitivePipelineResult:
        run_id = f"cognitive_{self._id_factory()}"
        state = CognitiveState.REQUESTED
        events: list[CognitiveEvent] = []
        call_ids: list[str] = []
        response_ids: list[str] = []
        failure_fingerprints: set[str] = set()
        full_repairs = 0
        attempt = 1
        plan_digest: str | None = None
        candidate_digest: str | None = None
        verification_digest: str | None = None
        finalization_digest: str | None = None

        def transition(
            target: CognitiveState,
            detail: str,
            *,
            call_id: str | None = None,
            response_id: str | None = None,
        ) -> None:
            nonlocal state
            if target not in _ALLOWED_TRANSITIONS[state]:
                raise CognitivePipelineError(
                    f"illegal cognitive transition: {state.value} -> {target.value}"
                )
            events.append(
                CognitiveEvent(
                    sequence=len(events) + 1,
                    attempt=attempt,
                    previous_state=state,
                    state=target,
                    detail=detail,
                    call_id=call_id,
                    response_id_digest=(
                        hashlib.sha256(response_id.encode("utf-8")).hexdigest()
                        if response_id
                        else None
                    ),
                )
            )
            state = target

        def finish(
            target: TerminalCognitiveState,
            reason: str | None,
        ) -> CognitivePipelineResult:
            if state != target:
                transition(target, reason or "cognitive pipeline reached its terminal state")
            return CognitivePipelineResult(
                schema_version=COGNITIVE_PIPELINE_VERSION,
                run_id=run_id,
                task_id=task.task_id,
                state=target,
                events=tuple(events),
                call_ids=tuple(call_ids),
                response_ids=tuple(response_ids),
                full_repairs=full_repairs,
                plan_digest=plan_digest,
                candidate_digest=candidate_digest,
                verification_digest=verification_digest,
                finalization_digest=finalization_digest,
                blocked_reason=reason,
                task_completion_claimed=False,
            )

        def request_repair(stage: str, status: OutcomeStatus, material: object) -> bool:
            nonlocal full_repairs, attempt
            fingerprint = _digest_value(
                {"stage": stage, "status": status.value, "material": material}
            )
            if status != OutcomeStatus.FAILED:
                return False
            if fingerprint in failure_fingerprints:
                return False
            if full_repairs >= self._maximum_full_repairs:
                return False
            failure_fingerprints.add(fingerprint)
            full_repairs += 1
            attempt += 1
            transition(
                CognitiveState.CONTEXT_READY,
                f"bounded full repair {full_repairs} requested after {stage}",
            )
            return True

        if task.status != OutcomeStatus.PASSED:
            return finish(CognitiveState.BLOCKED, "task intake is not ready")
        transition(CognitiveState.CONTRACT_READY, "strict task contract accepted")
        if (
            context.status != OutcomeStatus.PASSED
            or context.task_id != task.task_id
            or context.source_binding != task.source_binding
        ):
            return finish(CognitiveState.BLOCKED, "context manifest is not ready or task-bound")
        transition(CognitiveState.CONTEXT_READY, "task-bound context manifest accepted")

        while True:
            try:
                plan, plan_call, plan_response = await self._call(
                    prompt_name=PromptName.ENGINEERING_PLAN,
                    payload=_payload(task=task, context=context, attempt=attempt),
                    output_type=EngineeringPlan,
                    fresh_context=False,
                    call_ids=call_ids,
                    response_ids=response_ids,
                )
                plan_digest = _digest_model(plan)
                if plan.task_id != task.task_id or plan.source_binding != task.source_binding:
                    raise CognitivePipelineError("planner output is not task/source bound")
                transition(
                    CognitiveState.PLAN_PROPOSED,
                    "planner returned a strict engineering plan",
                    call_id=plan_call,
                    response_id=plan_response,
                )
                if plan.status != OutcomeStatus.PASSED:
                    if request_repair("plan", plan.status, plan.status_reasons):
                        continue
                    return finish(CognitiveState.BLOCKED, "planner did not produce a passing plan")

                plan_critique, critique_call, critique_response = await self._call(
                    prompt_name=PromptName.PLAN_CRITIQUE,
                    payload=_payload(
                        task=task,
                        context=context,
                        plan=plan,
                        attempt=attempt,
                    ),
                    output_type=PlanCritique,
                    fresh_context=True,
                    call_ids=call_ids,
                    response_ids=response_ids,
                )
                if (
                    plan_critique.task_id != task.task_id
                    or plan_critique.plan_digest != plan_digest
                    or plan_critique.source_binding != task.source_binding
                ):
                    raise CognitivePipelineError("plan critique binding changed")
                transition(
                    CognitiveState.PLAN_CRITIQUED,
                    "fresh critic reviewed the plan",
                    call_id=critique_call,
                    response_id=critique_response,
                )
                plan_findings = tuple(
                    finding.statement
                    for finding in plan_critique.findings
                    if finding.repair_required
                )
                if plan_critique.status != OutcomeStatus.PASSED or plan_findings:
                    effective_status = (
                        OutcomeStatus.FAILED
                        if plan_findings and plan_critique.status == OutcomeStatus.PASSED
                        else plan_critique.status
                    )
                    if request_repair(
                        "plan_critique",
                        effective_status,
                        (*plan_critique.status_reasons, *plan_findings),
                    ):
                        continue
                    return finish(CognitiveState.BLOCKED, "plan critique did not pass")
                transition(CognitiveState.PLAN_VERIFIED, "critic found no required plan repair")

                candidate, candidate_call, candidate_response = await self._call(
                    prompt_name=PromptName.CANDIDATE_MANIFEST,
                    payload=_payload(
                        task=task,
                        context=context,
                        plan=plan,
                        attempt=attempt,
                    ),
                    output_type=CandidateManifest,
                    fresh_context=False,
                    call_ids=call_ids,
                    response_ids=response_ids,
                )
                candidate_digest = _digest_model(candidate)
                if (
                    candidate.task_id != task.task_id
                    or candidate.plan_digest != plan_digest
                    or candidate.source_binding != task.source_binding
                ):
                    raise CognitivePipelineError("candidate binding changed")
                transition(
                    CognitiveState.CANDIDATE_GENERATED,
                    "implementer returned a non-executed candidate manifest",
                    call_id=candidate_call,
                    response_id=candidate_response,
                )
                if candidate.status == OutcomeStatus.NOT_APPLICABLE:
                    return finish(CognitiveState.NO_CHANGE_PROPOSED, None)
                if candidate.status != OutcomeStatus.PASSED:
                    if request_repair("candidate", candidate.status, candidate.status_reasons):
                        continue
                    return finish(CognitiveState.BLOCKED, "candidate generation did not pass")
                if not candidate.changes:
                    return finish(CognitiveState.NO_CHANGE_PROPOSED, None)

                (
                    candidate_critique,
                    candidate_critique_call,
                    candidate_critique_response,
                ) = await self._call(
                    prompt_name=PromptName.CANDIDATE_CRITIQUE,
                    payload=_payload(
                        task=task,
                        context=context,
                        plan=plan,
                        candidate=candidate,
                        attempt=attempt,
                    ),
                    output_type=CandidateCritique,
                    fresh_context=True,
                    call_ids=call_ids,
                    response_ids=response_ids,
                )
                if (
                    candidate_critique.task_id != task.task_id
                    or candidate_critique.plan_digest != plan_digest
                    or candidate_critique.candidate_digest != candidate_digest
                    or candidate_critique.source_binding != task.source_binding
                ):
                    raise CognitivePipelineError("candidate critique binding changed")
                transition(
                    CognitiveState.CANDIDATE_CRITIQUED,
                    "fresh critic reviewed the candidate",
                    call_id=candidate_critique_call,
                    response_id=candidate_critique_response,
                )
                candidate_findings = tuple(
                    finding.statement
                    for finding in candidate_critique.findings
                    if finding.repair_required
                )
                if candidate_critique.status != OutcomeStatus.PASSED or candidate_findings:
                    effective_status = (
                        OutcomeStatus.FAILED
                        if candidate_findings and candidate_critique.status == OutcomeStatus.PASSED
                        else candidate_critique.status
                    )
                    if request_repair(
                        "candidate_critique",
                        effective_status,
                        (*candidate_critique.status_reasons, *candidate_findings),
                    ):
                        continue
                    return finish(CognitiveState.BLOCKED, "candidate critique did not pass")

                checks = await self._checker.check(
                    task=task,
                    context=context,
                    plan=plan,
                    candidate=candidate,
                )
                transition(
                    CognitiveState.DETERMINISTIC_CHECKED,
                    "controller-owned deterministic candidate checks completed",
                )
                failed_checks = tuple(
                    (check.check_id, check.status.value, check.status_reasons)
                    for check in checks
                    if check.status != OutcomeStatus.PASSED
                )
                if not checks or failed_checks:
                    if request_repair(
                        "deterministic_checks",
                        OutcomeStatus.FAILED,
                        failed_checks or ("no deterministic checks",),
                    ):
                        continue
                    return finish(CognitiveState.BLOCKED, "deterministic checks did not pass")

                verification, verification_call, verification_response = await self._call(
                    prompt_name=PromptName.VERIFICATION_DECISION,
                    payload=_payload(
                        task=task,
                        context=context,
                        plan=plan,
                        candidate=candidate,
                        checks=checks,
                        attempt=attempt,
                    ),
                    output_type=VerificationDecision,
                    fresh_context=True,
                    call_ids=call_ids,
                    response_ids=response_ids,
                )
                verification_digest = _digest_model(verification)
                if (
                    verification.task_id != task.task_id
                    or verification.plan_digest != plan_digest
                    or verification.candidate_digest != candidate_digest
                    or verification.source_binding != task.source_binding
                ):
                    raise CognitivePipelineError("verification binding changed")
                transition(
                    CognitiveState.INDEPENDENTLY_VERIFIED,
                    "fresh verifier returned a strict decision",
                    call_id=verification_call,
                    response_id=verification_response,
                )
                if verification.status != OutcomeStatus.PASSED or verification.unresolved_findings:
                    effective_status = (
                        OutcomeStatus.FAILED
                        if verification.unresolved_findings
                        and verification.status == OutcomeStatus.PASSED
                        else verification.status
                    )
                    if request_repair(
                        "verification",
                        effective_status,
                        (
                            *verification.status_reasons,
                            *(item.statement for item in verification.unresolved_findings),
                        ),
                    ):
                        continue
                    return finish(CognitiveState.BLOCKED, "independent verification did not pass")

                finalization, final_call, final_response = await self._call(
                    prompt_name=PromptName.COGNITIVE_FINALIZATION,
                    payload=_payload(
                        task=task,
                        context=context,
                        plan=plan,
                        candidate=candidate,
                        checks=checks,
                        verification=verification,
                        attempt=attempt,
                    ),
                    output_type=CognitiveFinalization,
                    fresh_context=True,
                    call_ids=call_ids,
                    response_ids=response_ids,
                )
                finalization_digest = _digest_model(finalization)
                if (
                    finalization.task_id != task.task_id
                    or finalization.plan_digest != plan_digest
                    or finalization.candidate_digest != candidate_digest
                    or finalization.verification_digest != verification_digest
                ):
                    raise CognitivePipelineError("cognitive finalization binding changed")
                if (
                    finalization.status != OutcomeStatus.PASSED
                    or finalization.recommended_state != CognitiveState.COGNITIVE_READY
                    or finalization.task_completion_claimed
                ):
                    target: TerminalCognitiveState = (
                        CognitiveState.FAILED
                        if finalization.status == OutcomeStatus.FAILED
                        else CognitiveState.BLOCKED
                    )
                    return finish(target, "final cognitive synthesis did not establish readiness")
                transition(
                    CognitiveState.COGNITIVE_READY,
                    "finalizer established cognitive readiness without task completion",
                    call_id=final_call,
                    response_id=final_response,
                )
                return finish(CognitiveState.COGNITIVE_READY, None)
            except CognitivePipelineError as exc:
                return finish(CognitiveState.FAILED, str(exc))
            except Exception:
                return finish(CognitiveState.FAILED, "cognitive provider or checker failed closed")

    async def _call[TOutput: BaseModel](
        self,
        *,
        prompt_name: PromptName,
        payload: str,
        output_type: type[TOutput],
        fresh_context: bool,
        call_ids: list[str],
        response_ids: list[str],
    ) -> tuple[TOutput, str, str]:
        if PROMPT_OUTPUT_TYPES[prompt_name] is not output_type:
            raise CognitivePipelineError("prompt output schema binding changed")
        rendered = render_prompt(prompt_name, payload)
        profile = profile_for_role(rendered.role)
        call_id = f"call_{self._id_factory()}"
        if call_id in call_ids:
            raise CognitivePipelineError("cognitive provider call id was reused")
        request = CognitiveCallRequest(
            schema_version=COGNITIVE_PIPELINE_VERSION,
            call_id=call_id,
            role=rendered.role,
            profile_name=profile.name,
            prompt_name=prompt_name,
            prompt_version=rendered.prompt_version,
            instructions=rendered.instructions,
            instructions_digest=rendered.instructions_digest,
            input_text=rendered.input_payload,
            input_digest=rendered.input_digest,
            provider_bound_prompt_digest=rendered.provider_bound_prompt_digest,
            output_schema_name=rendered.output_schema_name,
            output_schema_digest=rendered.output_schema_digest,
            tool_authority=ToolAuthority.NONE,
            tools=(),
            previous_response_id=None,
            fresh_context=fresh_context,
        )
        result = await self._provider.call(request=request, output_type=output_type)
        if not isinstance(result.output, output_type):
            raise CognitivePipelineError("provider returned the wrong strict role contract")
        if (
            not result.response_id
            or len(result.response_id) > 512
            or result.response_id in response_ids
        ):
            raise CognitivePipelineError("provider response id is missing or reused")
        call_ids.append(call_id)
        response_ids.append(result.response_id)
        return result.output, call_id, result.response_id


def _digest_value(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _digest_model(value: BaseModel) -> str:
    return _digest_value(value.model_dump(mode="json"))


def _payload(**values: object) -> str:
    serializable = {
        key: value.model_dump(mode="json") if isinstance(value, BaseModel) else value
        for key, value in values.items()
    }
    return json.dumps(
        serializable,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
