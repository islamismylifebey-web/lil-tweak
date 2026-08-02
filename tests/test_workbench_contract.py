from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from liltweak.workbench_contract import (
    CommandRequest,
    FileRequest,
    GcpExamConfig,
    StepPhase,
    TaskImport,
    ToolKind,
    ToolRequest,
    WorkbenchMode,
    WorkbenchPlan,
    content_digest,
    utc_now,
)

DIGEST = "a" * 64


def command(tool_id: str, phase: StepPhase) -> ToolRequest:
    return ToolRequest(
        tool_id=tool_id,
        kind=ToolKind.COMMAND,
        phase=phase,
        purpose="bounded test",
        command=CommandRequest(executable="pytest", args=("-q",)),
    )


def test_gcp_zone_must_match_region() -> None:
    with pytest.raises(ValidationError, match="zone must belong"):
        GcpExamConfig(
            examination_id="exam-1",
            authorized_project="valid-project-1",
            candidate_service_account="candidate@valid-project-1.iam.gserviceaccount.com",
            region="us-central1",
            zone="us-east1-b",
            spending_ceiling_usd=1,
            current_task_number=1,
        )


def test_gcp_task_requires_exam_binding() -> None:
    with pytest.raises(ValidationError, match="require an examination"):
        TaskImport(
            mode=WorkbenchMode.GCP_QUALIFICATION,
            title="task",
            direction="perform the task",
            source_snapshot_digest=DIGEST,
        )


def test_plan_requires_test_and_verification() -> None:
    with pytest.raises(ValidationError, match="verification"):
        WorkbenchPlan(
            summary="plan",
            reasoning="reason",
            source_snapshot_digest=DIGEST,
            steps=(command("test-1", StepPhase.TEST),),
            rollback_steps=("restore snapshot",),
        )


def test_file_only_phases_cannot_claim_test_or_verification() -> None:
    steps = tuple(
        ToolRequest(
            tool_id=f"file-{phase.value}",
            kind=ToolKind.READ_FILE,
            phase=phase,
            purpose="not an executed check",
            file=FileRequest(path="result.txt"),
        )
        for phase in (StepPhase.TEST, StepPhase.VERIFICATION)
    )
    with pytest.raises(ValidationError, match="required command test"):
        WorkbenchPlan(
            summary="file-only plan",
            reasoning="File operations alone do not prove an executed test.",
            source_snapshot_digest=DIGEST,
            steps=steps,
            rollback_steps=("restore snapshot",),
        )


def test_plan_digest_changes_with_any_exact_argument() -> None:
    first = WorkbenchPlan(
        summary="plan",
        reasoning="reason",
        source_snapshot_digest=DIGEST,
        steps=(
            command("test-1", StepPhase.TEST),
            command("verify-1", StepPhase.VERIFICATION),
        ),
        rollback_steps=("restore snapshot",),
    )
    second_step = command("verify-1", StepPhase.VERIFICATION).model_copy(
        update={"purpose": "different purpose"}
    )
    second = first.model_copy(update={"steps": (first.steps[0], second_step)})
    assert first.plan_digest != content_digest(second)


def test_approval_expiry_test_clock_is_timezone_aware() -> None:
    assert utc_now().tzinfo is not None
    assert utc_now() + timedelta(minutes=1) > utc_now()
