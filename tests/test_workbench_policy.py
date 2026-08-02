from __future__ import annotations

import pytest

from liltweak.workbench_contract import (
    CommandRequest,
    GcpExamConfig,
    NetworkMode,
    StepPhase,
    TaskImport,
    ToolKind,
    ToolRequest,
    WorkbenchMode,
    WorkbenchState,
    WorkbenchTask,
)
from liltweak.workbench_policy import ToolPolicyBroker, ToolPolicyError

DIGEST = "a" * 64


def exam() -> GcpExamConfig:
    return GcpExamConfig(
        examination_id="exam-1",
        authorized_project="valid-project-1",
        candidate_service_account="candidate@valid-project-1.iam.gserviceaccount.com",
        region="us-central1",
        zone="us-central1-a",
        spending_ceiling_usd=5,
        current_task_number=1,
    )


def task() -> WorkbenchTask:
    imported = TaskImport(
        mode=WorkbenchMode.GCP_QUALIFICATION,
        title="task",
        direction="one immutable task",
        source_snapshot_digest=DIGEST,
        examination=exam(),
    )
    return WorkbenchTask(
        id="task:1",
        imported=imported,
        task_digest=imported.task_digest,
        state=WorkbenchState.ANALYZED,
    )


def tool(*args: str) -> ToolRequest:
    return ToolRequest(
        tool_id="gcp-1",
        kind=ToolKind.COMMAND,
        phase=StepPhase.VERIFICATION,
        purpose="verify",
        command=CommandRequest(
            executable="gcloud",
            args=args,
            network=NetworkMode.TASK_SCOPED,
        ),
    )


def bound_args(*extra: str) -> tuple[str, ...]:
    return (
        "compute",
        "instances",
        "list",
        "--project",
        "valid-project-1",
        "--impersonate-service-account",
        "candidate@valid-project-1.iam.gserviceaccount.com",
        "--region",
        "us-central1",
        *extra,
    )


def test_exact_project_identity_and_region_are_allowed() -> None:
    assert ToolPolicyBroker().authorize(task(), tool(*bound_args())).allowed is True


@pytest.mark.parametrize(
    "args",
    [
        bound_args("--key-file=key.json"),
        (
            "projects",
            "delete",
            "valid-project-1",
            "--project",
            "valid-project-1",
            "--impersonate-service-account",
            "candidate@valid-project-1.iam.gserviceaccount.com",
        ),
        (
            "billing",
            "budgets",
            "create",
            "--project",
            "valid-project-1",
            "--impersonate-service-account",
            "candidate@valid-project-1.iam.gserviceaccount.com",
        ),
        (
            "projects",
            "add-iam-policy-binding",
            "valid-project-1",
            "--member=user:test@example.com",
            "--role=roles/owner",
            "--project",
            "valid-project-1",
            "--impersonate-service-account",
            "candidate@valid-project-1.iam.gserviceaccount.com",
        ),
    ],
)
def test_examiner_protected_gcp_operations_are_denied(args: tuple[str, ...]) -> None:
    with pytest.raises(ToolPolicyError):
        ToolPolicyBroker().authorize(task(), tool(*args))


def test_wrong_project_is_denied() -> None:
    args = list(bound_args())
    args[args.index("valid-project-1")] = "other-project-1"
    with pytest.raises(ToolPolicyError, match="project"):
        ToolPolicyBroker().authorize(task(), tool(*args))


def test_shell_and_interpreter_strings_are_denied() -> None:
    broker = ToolPolicyBroker()
    engineering = task().model_copy(
        update={
            "imported": TaskImport(
                title="engineering",
                direction="task",
                source_snapshot_digest=DIGEST,
            )
        }
    )
    for executable, args in (("bash", ("-c", "id")), ("python", ("-c", "print(1)"))):
        request = ToolRequest(
            tool_id="unsafe-1",
            kind=ToolKind.COMMAND,
            phase=StepPhase.TEST,
            purpose="unsafe",
            command=CommandRequest(executable=executable, args=args),
        )
        with pytest.raises(ToolPolicyError):
            broker.authorize(engineering, request)


def test_credential_shaped_command_arguments_are_denied() -> None:
    request = ToolRequest(
        tool_id="unsafe-credential",
        kind=ToolKind.COMMAND,
        phase=StepPhase.TEST,
        purpose="unsafe",
        command=CommandRequest(
            executable="curl",
            args=("-H", "Authorization: Bearer secret-token"),
            network=NetworkMode.TASK_SCOPED,
        ),
    )
    engineering = TaskImport(
        title="engineering",
        direction="task",
        source_snapshot_digest=DIGEST,
    )
    bound = WorkbenchTask(
        id="task:credential",
        imported=engineering,
        task_digest=engineering.task_digest,
        state=WorkbenchState.ANALYZED,
    )
    with pytest.raises(ToolPolicyError, match="credential"):
        ToolPolicyBroker().authorize(bound, request)
