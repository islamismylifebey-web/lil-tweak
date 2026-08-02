from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

from liltweak.workbench_contract import (
    CommandRequest,
    FileRequest,
    NetworkMode,
    StepPhase,
    ToolKind,
    ToolRequest,
)
from liltweak.workbench_executor import (
    BoundedToolExecutor,
    ProcessResult,
    QualifiedProcessTransport,
    TaskWorkspaceManager,
)


class FakeTransport:
    connected = True

    async def run(self, **kwargs: object) -> ProcessResult:
        cancel_event = kwargs["cancel_event"]
        assert isinstance(cancel_event, asyncio.Event)
        return ProcessResult(0, b"ok", b"", False, False)


class FailedTransport:
    connected = True

    def __init__(self, result: ProcessResult) -> None:
        self.result = result

    async def run(self, **_: object) -> ProcessResult:
        return self.result


def test_qualified_transport_rejects_unpinned_or_shell_prefix() -> None:
    with pytest.raises(ValueError, match="pinned"):
        QualifiedProcessTransport(
            sandbox_prefix=("bwrap",),
            qualification_digest="not-a-digest",
            network_namespace_enforced=True,
        )
    with pytest.raises(ValueError, match="shell"):
        QualifiedProcessTransport(
            sandbox_prefix=("bash", "-c"),
            qualification_digest="a" * 64,
            network_namespace_enforced=True,
        )


@pytest.mark.asyncio
async def test_atomic_file_write_and_structured_command(tmp_path: Path) -> None:
    workspaces = TaskWorkspaceManager(tmp_path / "tasks")
    executor = BoundedToolExecutor(workspaces, FakeTransport())
    task_id = "task:one"
    workspaces.task_root(task_id)

    write = ToolRequest(
        tool_id="write-1",
        kind=ToolKind.WRITE_FILE,
        phase=StepPhase.MUTATION,
        purpose="write",
        file=FileRequest(path="src/example.py", content="print('ok')\n"),
    )
    write_run = await executor.execute(
        task_id=task_id, attempt=1, request=write, evidence_id="evidence:one"
    )
    assert write_run.success is True
    assert (workspaces.task_root(task_id) / "src/example.py").read_text() == "print('ok')\n"

    command = ToolRequest(
        tool_id="test-1",
        kind=ToolKind.COMMAND,
        phase=StepPhase.TEST,
        purpose="test",
        command=CommandRequest(executable="pytest", args=("-q",), network=NetworkMode.DENIED),
    )
    command_run = await executor.execute(
        task_id=task_id, attempt=1, request=command, evidence_id="evidence:two"
    )
    assert command_run.success is True
    assert command_run.args == ("-q",)


@pytest.mark.asyncio
async def test_conditional_patch_rejects_changed_source(tmp_path: Path) -> None:
    workspaces = TaskWorkspaceManager(tmp_path / "tasks")
    executor = BoundedToolExecutor(workspaces, FakeTransport())
    task_id = "task:one"
    target = workspaces.task_root(task_id) / "file.txt"
    target.write_text("changed", encoding="utf-8")
    request = ToolRequest(
        tool_id="patch-1",
        kind=ToolKind.APPLY_PATCH,
        phase=StepPhase.MUTATION,
        purpose="patch",
        file=FileRequest(
            path="file.txt",
            content="replacement",
            expected_sha256=hashlib.sha256(b"original").hexdigest(),
        ),
    )
    run = await executor.execute(
        task_id=task_id, attempt=1, request=request, evidence_id="evidence:one"
    )
    assert run.success is False
    assert "changed since" in run.redacted_output


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (ProcessResult(None, b"", b"timeout", True, False), "timeout"),
        (ProcessResult(None, b"", b"canceled", False, True), "canceled"),
        (ProcessResult(125, b"", b"[OUTPUT LIMIT REACHED]", False, False), "OUTPUT LIMIT"),
    ],
)
async def test_timeout_cancel_and_output_limit_never_report_success(
    tmp_path: Path,
    result: ProcessResult,
    expected: str,
) -> None:
    workspaces = TaskWorkspaceManager(tmp_path / "tasks")
    executor = BoundedToolExecutor(workspaces, FailedTransport(result))
    request = ToolRequest(
        tool_id="bounded-run",
        kind=ToolKind.COMMAND,
        phase=StepPhase.TEST,
        purpose="bounded failure",
        command=CommandRequest(executable="pytest", args=("-q",)),
    )
    run = await executor.execute(
        task_id="task:bounded",
        attempt=1,
        request=request,
        evidence_id="evidence:bounded",
    )
    assert run.success is False
    assert expected.casefold() in run.redacted_output.casefold()


@pytest.mark.asyncio
async def test_output_is_redacted_before_run_record_persistence(tmp_path: Path) -> None:
    workspaces = TaskWorkspaceManager(tmp_path / "tasks")
    transport = FailedTransport(
        ProcessResult(1, b"token=secret-value-123456789", b"", False, False)
    )
    executor = BoundedToolExecutor(workspaces, transport)
    request = ToolRequest(
        tool_id="redact-run",
        kind=ToolKind.COMMAND,
        phase=StepPhase.TEST,
        purpose="redaction",
        command=CommandRequest(executable="pytest", args=("-q",)),
    )
    run = await executor.execute(
        task_id="task:redact",
        attempt=1,
        request=request,
        evidence_id="evidence:redact",
    )
    assert "secret-value" not in run.redacted_output
    assert "[REDACTED]" in run.redacted_output
