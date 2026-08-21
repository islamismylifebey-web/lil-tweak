from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import BaseModel

from liltweak.cognitive_contract import CognitiveFinalization
from liltweak.cognitive_pipeline import (
    CognitiveCallRequest,
    CognitivePipelineController,
    CognitiveProviderResult,
)
from liltweak.reasoning_contract import (
    CandidateChange,
    CandidateCritique,
    CandidateManifest,
    ChangeKind,
    CheckResult,
    CognitiveState,
    ContextManifest,
    EngineeringPlan,
    OutcomeStatus,
    PlanCritique,
    ReasoningRole,
    SourceBinding,
    TaskIntake,
    VerificationDecision,
)

SHA = "a" * 64


def digest_model(value: BaseModel) -> str:
    encoded = json.dumps(
        value.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def source() -> SourceBinding:
    return SourceBinding(
        repository_id="repo",
        branch="main",
        base_commit=SHA,
        source_tree_digest=SHA,
        worktree_digest=SHA,
        source_fingerprint=SHA,
    )


def task_and_context() -> tuple[TaskIntake, ContextManifest]:
    binding = source()
    task = TaskIntake.model_construct(
        task_id="task",
        source_binding=binding,
        status=OutcomeStatus.PASSED,
        status_reasons=(),
    )
    context = ContextManifest.model_construct(
        task_id="task",
        source_binding=binding,
        status=OutcomeStatus.PASSED,
        status_reasons=(),
    )
    return task, context


def passing_artifacts() -> tuple[BaseModel, ...]:
    binding = source()
    plan = EngineeringPlan.model_construct(
        task_id="task",
        source_binding=binding,
        status=OutcomeStatus.PASSED,
        status_reasons=(),
    )
    plan_digest = digest_model(plan)
    plan_critique = PlanCritique.model_construct(
        task_id="task",
        plan_digest=plan_digest,
        source_binding=binding,
        findings=(),
        status=OutcomeStatus.PASSED,
        status_reasons=(),
    )
    change = CandidateChange(
        path="liltweak/example.py",
        kind=ChangeKind.MODIFY,
        symbols=("example",),
        summary="Change the bounded example.",
        content_digest=SHA,
    )
    candidate = CandidateManifest.model_construct(
        task_id="task",
        plan_digest=plan_digest,
        source_binding=binding,
        changes=(change,),
        status=OutcomeStatus.PASSED,
        status_reasons=(),
    )
    candidate_digest = digest_model(candidate)
    candidate_critique = CandidateCritique.model_construct(
        task_id="task",
        plan_digest=plan_digest,
        candidate_digest=candidate_digest,
        source_binding=binding,
        findings=(),
        status=OutcomeStatus.PASSED,
        status_reasons=(),
    )
    verification = VerificationDecision.model_construct(
        task_id="task",
        plan_digest=plan_digest,
        candidate_digest=candidate_digest,
        source_binding=binding,
        unresolved_findings=(),
        status=OutcomeStatus.PASSED,
        status_reasons=(),
    )
    verification_digest = digest_model(verification)
    finalization = CognitiveFinalization.model_construct(
        task_id="task",
        plan_digest=plan_digest,
        candidate_digest=candidate_digest,
        verification_digest=verification_digest,
        recommended_state=CognitiveState.COGNITIVE_READY,
        task_completion_claimed=False,
        status=OutcomeStatus.PASSED,
        status_reasons=(),
    )
    return (
        plan,
        plan_critique,
        candidate,
        candidate_critique,
        verification,
        finalization,
    )


class FakeProvider:
    def __init__(self, outputs: tuple[BaseModel, ...], response_ids: tuple[str, ...] = ()) -> None:
        self._outputs: Iterator[BaseModel] = iter(outputs)
        self._response_ids = iter(response_ids)
        self.requests: list[CognitiveCallRequest] = []

    async def call(
        self,
        *,
        request: CognitiveCallRequest,
        output_type: type[BaseModel],
    ) -> CognitiveProviderResult[Any]:
        output = next(self._outputs)
        assert isinstance(output, output_type)
        self.requests.append(request)
        try:
            response_id = next(self._response_ids)
        except StopIteration:
            response_id = f"response_{len(self.requests)}"
        return CognitiveProviderResult(output=output, response_id=response_id)


class PassingChecker:
    async def check(self, **_kwargs: object) -> tuple[CheckResult, ...]:
        return (
            CheckResult(
                check_id="unit-tests",
                command_or_check="Focused unit tests",
                exit_code=0,
                output_digest=SHA,
                evidence_ids=(),
                status=OutcomeStatus.PASSED,
                status_reasons=(),
            ),
        )


def id_factory() -> Iterator[str]:
    index = 0
    while True:
        index += 1
        yield str(index)


@pytest.mark.asyncio
async def test_pipeline_uses_distinct_role_calls_fresh_reviewers_and_no_tools() -> None:
    task, context = task_and_context()
    provider = FakeProvider(passing_artifacts())
    ids = id_factory()
    controller = CognitivePipelineController(
        provider=provider,
        checker=PassingChecker(),
        id_factory=lambda: next(ids),
    )

    result = await controller.run(task=task, context=context)

    assert result.state == CognitiveState.COGNITIVE_READY
    assert result.task_completion_claimed is False
    assert result.full_repairs == 0
    assert len(result.call_ids) == len(result.response_ids) == 6
    assert len(set(result.response_ids)) == 6
    assert [request.role for request in provider.requests] == [
        ReasoningRole.PLANNER,
        ReasoningRole.CRITIC,
        ReasoningRole.IMPLEMENTER,
        ReasoningRole.CRITIC,
        ReasoningRole.VERIFIER,
        ReasoningRole.FINALIZER,
    ]
    assert all(request.tools == () for request in provider.requests)
    assert all(request.previous_response_id is None for request in provider.requests)
    assert all(
        request.fresh_context
        for request in provider.requests
        if request.role in {ReasoningRole.CRITIC, ReasoningRole.VERIFIER}
    )
    assert all(event.state.value != "COMPLETED" for event in result.events)


def failed_plan(reason: str) -> EngineeringPlan:
    return EngineeringPlan.model_construct(
        task_id="task",
        source_binding=source(),
        status=OutcomeStatus.FAILED,
        status_reasons=(reason,),
    )


@pytest.mark.asyncio
async def test_pipeline_caps_full_repairs_at_two() -> None:
    task, context = task_and_context()
    provider = FakeProvider(
        (
            failed_plan("first material failure"),
            failed_plan("second material failure"),
            failed_plan("third material failure"),
        )
    )
    ids = id_factory()
    controller = CognitivePipelineController(
        provider=provider,
        checker=PassingChecker(),
        id_factory=lambda: next(ids),
    )

    result = await controller.run(task=task, context=context)

    assert result.state == CognitiveState.BLOCKED
    assert result.full_repairs == 2
    assert len(provider.requests) == 3
    assert result.blocked_reason == "planner did not produce a passing plan"


@pytest.mark.asyncio
async def test_recurring_material_failure_blocks_without_unbounded_retry() -> None:
    task, context = task_and_context()
    provider = FakeProvider(
        (
            failed_plan("same material failure"),
            failed_plan("same material failure"),
        )
    )
    ids = id_factory()
    controller = CognitivePipelineController(
        provider=provider,
        checker=PassingChecker(),
        id_factory=lambda: next(ids),
    )

    result = await controller.run(task=task, context=context)

    assert result.state == CognitiveState.BLOCKED
    assert result.full_repairs == 1
    assert len(provider.requests) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status",
    (OutcomeStatus.UNKNOWN, OutcomeStatus.BLOCKED, OutcomeStatus.FAILED),
)
async def test_empty_nonpassing_candidate_never_becomes_no_change(
    status: OutcomeStatus,
) -> None:
    task, context = task_and_context()
    plan, critique, *_ = passing_artifacts()
    candidate = CandidateManifest.model_construct(
        task_id="task",
        plan_digest=digest_model(plan),
        source_binding=source(),
        changes=(),
        status=status,
        status_reasons=("candidate did not pass",),
    )
    provider = FakeProvider((plan, critique, candidate))
    ids = id_factory()
    controller = CognitivePipelineController(
        provider=provider,
        checker=PassingChecker(),
        maximum_full_repairs=0,
        id_factory=lambda: next(ids),
    )

    result = await controller.run(task=task, context=context)

    assert result.state == CognitiveState.BLOCKED
    assert result.blocked_reason == "candidate generation did not pass"
    assert result.state != CognitiveState.NO_CHANGE_PROPOSED


@pytest.mark.asyncio
async def test_duplicate_provider_response_id_fails_closed() -> None:
    task, context = task_and_context()
    provider = FakeProvider(passing_artifacts(), response_ids=("duplicate", "duplicate"))
    ids = id_factory()
    controller = CognitivePipelineController(
        provider=provider,
        checker=PassingChecker(),
        id_factory=lambda: next(ids),
    )

    result = await controller.run(task=task, context=context)

    assert result.state == CognitiveState.FAILED
    assert result.blocked_reason == "provider response id is missing or reused"
    assert result.call_ids == ("call_2",)
    assert result.response_ids == ("duplicate",)


@pytest.mark.asyncio
async def test_changed_plan_binding_fails_closed_before_critique() -> None:
    task, context = task_and_context()
    changed = source().model_copy(update={"source_tree_digest": "b" * 64})
    plan = EngineeringPlan.model_construct(
        task_id="task",
        source_binding=changed,
        status=OutcomeStatus.PASSED,
        status_reasons=(),
    )
    provider = FakeProvider((plan,))
    ids = id_factory()
    controller = CognitivePipelineController(
        provider=provider,
        checker=PassingChecker(),
        id_factory=lambda: next(ids),
    )

    result = await controller.run(task=task, context=context)

    assert result.state == CognitiveState.FAILED
    assert result.blocked_reason == "planner output is not task/source bound"
    assert len(provider.requests) == 1
