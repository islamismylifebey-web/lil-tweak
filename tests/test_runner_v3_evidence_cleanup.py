from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from liltweak.providers.github.runner_v3_contracts import (
    RunnerV3Action,
    RunnerV3JobManifest,
    RunnerV3Outcome,
    RunnerV3WorkspaceMode,
)
from liltweak.providers.github.runner_v3_executor import RunnerV3Executor

NOW = datetime(2026, 9, 2, 19, 0, tzinfo=UTC)


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    (repository / "liltweak").mkdir(parents=True)
    (repository / "scripts").mkdir()
    (repository / "liltweak" / "__init__.py").write_text("", encoding="utf-8")
    (repository / "scripts" / "tool.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.name", "Runner V3 Test")
    _git(repository, "config", "user.email", "runner-v3-test@invalid")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "fixture")
    return repository


def test_runtime_scratch_is_removed_and_never_uploaded_as_evidence(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    output = tmp_path / "evidence"
    source_commit = _git(repository, "rev-parse", "HEAD")
    source_tree = _git(repository, "rev-parse", "HEAD^{tree}")
    manifest = RunnerV3JobManifest.issue(
        execution_id="execution_runner_v3_cleanup",
        attempt_nonce="1" * 64,
        repository_id="github:islamismylifebey-web/lil-tweak",
        source_commit=source_commit,
        source_tree=source_tree,
        contract_digest="c" * 64,
        lease_digest="d" * 64,
        commands_digest="a" * 64,
        approval_digest="b" * 64,
        policy_digest="9" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        cpu_ceiling=2,
        memory_mb_ceiling=2_048,
        disk_mb_ceiling=4_096,
        timeout_seconds=60,
        output_byte_limit=128_000,
        workspace_mode=RunnerV3WorkspaceMode.READ_ONLY,
        source_write_authorized=False,
        actions=(
            RunnerV3Action.INSPECT_SOURCE,
            RunnerV3Action.COMPILE_PYTHON,
            RunnerV3Action.GIT_DIFF,
        ),
        patch=None,
    )

    receipt = RunnerV3Executor(
        clock=lambda: NOW + timedelta(minutes=1),
        poll_interval_seconds=0.01,
    ).execute(
        manifest,
        workspace=repository,
        output_directory=output,
        cancellation_requested=lambda: False,
    )

    assert receipt.outcome is RunnerV3Outcome.SUCCEEDED
    assert {path.name for path in output.iterdir()} == {
        "runner-v3-receipt.json",
        "steps",
    }
    assert not list(tmp_path.glob(".runner-v3-runtime-*"))
