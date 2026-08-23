from __future__ import annotations

import shutil
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from liltweak.creator_contract import CommandKind, SandboxCommand
from liltweak.execution_contract import ExecutionRecipe
from liltweak.isolated_runner import (
    BubblewrapSandboxExecutor,
    IsolationUnavailableError,
    _OutputBudget,
)
from liltweak.source_snapshot import RepositorySnapshotBuilder

IMAGE = "registry.invalid/liltweak-python@sha256:" + ("c" * 64)


def recipe() -> ExecutionRecipe:
    return ExecutionRecipe(
        recipe_id="python-verify",
        image_ref=IMAGE,
        commands=(
            SandboxCommand(
                command_id="tests",
                kind=CommandKind.TEST,
                argv=("pytest", "-q"),
                timeout_seconds=60,
            ),
        ),
    )


def runner(tmp_path: Path) -> BubblewrapSandboxExecutor:
    runtime_root = tmp_path / "runtime-root"
    runtime_root.mkdir()
    runtime_path, limiter_path = trusted_executables(tmp_path)
    return BubblewrapSandboxExecutor(
        snapshot_builder=Mock(spec=RepositorySnapshotBuilder),
        runtime_root=runtime_root,
        image_ref=IMAGE,
        runtime_path=runtime_path,
        limiter_path=limiter_path,
    )


def trusted_executables(tmp_path: Path) -> tuple[Path, Path]:
    paths = (tmp_path / "bwrap", tmp_path / "prlimit")
    for path in paths:
        shutil.copyfile(sys.executable, path)
        path.chmod(0o700)
    return paths


def test_bubblewrap_invocation_has_fail_closed_profile(tmp_path: Path) -> None:
    executor = runner(tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    command = executor._sandbox_command(
        recipe=recipe(),
        source=source,
        argv=("pytest", "-q"),
    )
    assert "--unshare-all" in command
    assert "--share-net" not in command
    assert "--clearenv" in command
    assert (
        command[command.index("--cap-drop")],
        command[command.index("--cap-drop") + 1],
    ) == ("--cap-drop", "ALL")
    source_index = command.index(str(source))
    assert command[source_index - 1] == "--ro-bind"
    assert command[source_index + 1] == "/workspace/source"
    assert "OPENAI_API_KEY" not in command
    assert "HTTP_PROXY" not in command
    assert command[-2:] == ("pytest", "-q")
    profile = executor.profile_for(recipe())
    assert profile.network_namespace_isolated is True
    assert profile.source_read_only is True
    assert profile.profile_digest


@pytest.mark.asyncio
async def test_binary_presence_does_not_mark_runner_connected(tmp_path: Path) -> None:
    executor = runner(tmp_path)
    assert executor.connected is False
    observed = await executor.probe(recipe())
    assert observed is False
    assert executor.connected is False


@pytest.mark.asyncio
async def test_output_budget_is_shared_across_commands(tmp_path: Path) -> None:
    executor = runner(tmp_path)
    budget = _OutputBudget(limit=10)
    first = await executor._run_command(
        command_id="first",
        command=(sys.executable, "-c", "print('1234567', end='')"),
        timeout_seconds=5,
        output_budget=budget,
    )
    second = await executor._run_command(
        command_id="second",
        command=(sys.executable, "-c", "print('abcdefg', end='')"),
        timeout_seconds=5,
        output_budget=budget,
    )
    assert first.stdout_bytes == 7
    assert first.output_limit_exceeded is False
    assert second.stdout_bytes == 3
    assert second.output_limit_exceeded is True
    assert budget.retained == budget.limit


def test_host_root_cannot_be_used_as_runtime_bundle(tmp_path: Path) -> None:
    runtime_path, limiter_path = trusted_executables(tmp_path)
    with pytest.raises(IsolationUnavailableError, match="dedicated pinned directory"):
        BubblewrapSandboxExecutor(
            snapshot_builder=Mock(spec=RepositorySnapshotBuilder),
            runtime_root=Path("/"),
            image_ref=IMAGE,
            runtime_path=runtime_path,
            limiter_path=limiter_path,
        )


def test_runtime_bundle_symlink_is_rejected(tmp_path: Path) -> None:
    runtime_root = tmp_path / "runtime-root"
    runtime_root.mkdir()
    linked_root = tmp_path / "linked-runtime-root"
    linked_root.symlink_to(runtime_root, target_is_directory=True)
    with pytest.raises(IsolationUnavailableError, match="symbolic link"):
        BubblewrapSandboxExecutor(
            snapshot_builder=Mock(spec=RepositorySnapshotBuilder),
            runtime_root=linked_root,
            image_ref=IMAGE,
        )
