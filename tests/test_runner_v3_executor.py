from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from liltweak.creator_contract import canonical_json, content_digest
from liltweak.providers.github.runner_v3_contracts import (
    RunnerV3Action,
    RunnerV3JobManifest,
    RunnerV3Outcome,
    RunnerV3Patch,
    RunnerV3Receipt,
    RunnerV3WorkspaceMode,
)
from liltweak.providers.github.runner_v3_executor import (
    RunnerV3ExecutionError,
    RunnerV3Executor,
)
from scripts.runner_v3 import main as runner_v3_main

NOW = datetime(2026, 9, 2, 18, 0, tzinfo=UTC)


def _git(repository: Path, *arguments: str, check: bool = True) -> str:
    result = subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=False,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(f"git {' '.join(arguments)} failed: {result.stdout}\n{result.stderr}")
    return result.stdout.strip()


def _write(repository: Path, relative: str, content: str) -> None:
    target = repository / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _repository(
    tmp_path: Path,
    *,
    sample_test: str = (
        "from liltweak.value import VALUE\n\ndef test_value() -> None:\n    assert VALUE == 1\n"
    ),
) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    _write(repository, "liltweak/__init__.py", "")
    _write(repository, "liltweak/value.py", "VALUE = 1\n")
    _write(repository, "scripts/tool.py", "VALUE = 1\n")
    _write(repository, "docs/note.txt", "before\n")
    _write(repository, "README.md", "# Fixture\n")
    _write(repository, "tests/test_sample.py", sample_test)
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.name", "Runner V3 Test")
    _git(repository, "config", "user.email", "runner-v3-test@invalid")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "fixture")
    return repository


def _manifest(
    repository: Path,
    *,
    actions: tuple[RunnerV3Action, ...] = (
        RunnerV3Action.INSPECT_SOURCE,
        RunnerV3Action.GIT_DIFF,
    ),
    workspace_mode: RunnerV3WorkspaceMode = RunnerV3WorkspaceMode.READ_ONLY,
    source_write_authorized: bool = False,
    patch: RunnerV3Patch | None = None,
    source_commit: str | None = None,
    source_tree: str | None = None,
    timeout_seconds: int = 30,
    output_byte_limit: int = 128_000,
    issued_at: datetime = NOW,
) -> RunnerV3JobManifest:
    return RunnerV3JobManifest.issue(
        execution_id="execution_runner_v3_executor",
        attempt_nonce="1" * 64,
        repository_id="github:islamismylifebey-web/lil-tweak",
        source_commit=source_commit or _git(repository, "rev-parse", "HEAD"),
        source_tree=source_tree or _git(repository, "rev-parse", "HEAD^{tree}"),
        contract_digest="c" * 64,
        lease_digest="d" * 64,
        commands_digest="a" * 64,
        approval_digest="b" * 64,
        policy_digest="9" * 64,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=10),
        cpu_ceiling=2,
        memory_mb_ceiling=2_048,
        disk_mb_ceiling=4_096,
        timeout_seconds=timeout_seconds,
        output_byte_limit=output_byte_limit,
        workspace_mode=workspace_mode,
        source_write_authorized=source_write_authorized,
        actions=actions,
        patch=patch,
    )


def _patch(
    repository: Path,
    changes: dict[str, str],
    *,
    authorized_paths: tuple[str, ...] | None = None,
) -> RunnerV3Patch:
    originals = {
        relative: (repository / relative).read_text(encoding="utf-8") for relative in changes
    }
    for relative, content in changes.items():
        _write(repository, relative, content)
    patch_text = _git(
        repository,
        "diff",
        "--binary",
        "--full-index",
        "--",
        *changes,
    )
    for relative, content in originals.items():
        _write(repository, relative, content)
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == ""
    return RunnerV3Patch.issue(
        text=f"{patch_text}\n",
        authorized_paths=authorized_paths or tuple(changes),
    )


def _executor() -> RunnerV3Executor:
    return RunnerV3Executor(
        clock=lambda: NOW + timedelta(minutes=1),
        poll_interval_seconds=0.01,
    )


def test_clean_read_only_execution_writes_canonical_evidence(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    output = tmp_path / "evidence"
    manifest = _manifest(
        repository,
        actions=(
            RunnerV3Action.INSPECT_SOURCE,
            RunnerV3Action.COMPILE_PYTHON,
            RunnerV3Action.PYTEST,
            RunnerV3Action.GIT_DIFF,
        ),
    )

    receipt = _executor().execute(
        manifest,
        workspace=repository,
        output_directory=output,
        cancellation_requested=lambda: False,
    )

    assert receipt.outcome is RunnerV3Outcome.SUCCEEDED
    assert receipt.workspace_changed is False
    assert receipt.changed_paths == ()
    assert receipt.candidate_patch_digest is None
    assert tuple(step.action for step in receipt.steps) == manifest.actions
    assert all(step.outcome is RunnerV3Outcome.SUCCEEDED for step in receipt.steps)
    assert receipt.host_capacity.cpu_count >= 1
    assert receipt.host_capacity.memory_mb >= 128
    assert receipt.host_capacity.free_disk_mb >= 1
    persisted = RunnerV3Receipt.model_validate_json(
        (output / "runner-v3-receipt.json").read_text(encoding="utf-8")
    )
    assert persisted == receipt
    assert receipt.receipt_digest == content_digest(
        receipt.model_dump(mode="json", exclude={"receipt_digest"})
    )
    for index, action in enumerate(manifest.actions):
        prefix = output / "steps" / f"{index:02d}-{action.value}"
        assert prefix.with_suffix(".json").is_file()
        assert prefix.with_suffix(".stdout").is_file()
        assert prefix.with_suffix(".stderr").is_file()
    assert not (output / "candidate.patch").exists()
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == ""


@pytest.mark.parametrize("binding", ("commit", "tree"))
def test_source_mismatch_fails_before_any_action(
    tmp_path: Path,
    binding: str,
) -> None:
    repository = _repository(tmp_path)
    output = tmp_path / "evidence"
    values = {"source_commit": "0" * 40} if binding == "commit" else {"source_tree": "0" * 40}
    manifest = _manifest(repository, **values)

    with pytest.raises(RunnerV3ExecutionError, match="source"):
        _executor().execute(
            manifest,
            workspace=repository,
            output_directory=output,
            cancellation_requested=lambda: False,
        )

    assert not output.exists()


def test_authorized_ephemeral_patch_emits_exact_candidate(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    output = tmp_path / "evidence"
    patch = _patch(repository, {"docs/note.txt": "after\n"})
    manifest = _manifest(
        repository,
        actions=(RunnerV3Action.INSPECT_SOURCE, RunnerV3Action.GIT_DIFF),
        workspace_mode=RunnerV3WorkspaceMode.EPHEMERAL_PATCH,
        source_write_authorized=True,
        patch=patch,
    )

    receipt = _executor().execute(
        manifest,
        workspace=repository,
        output_directory=output,
        cancellation_requested=lambda: False,
    )

    assert receipt.outcome is RunnerV3Outcome.SUCCEEDED
    assert receipt.workspace_changed is True
    assert receipt.changed_paths == ("docs/note.txt",)
    assert receipt.candidate_patch_digest == patch.patch_digest
    assert (output / "candidate.patch").read_text(encoding="utf-8") == patch.text
    assert (repository / "docs/note.txt").read_text(encoding="utf-8") == "after\n"


def test_patch_rejects_touched_paths_outside_exact_allowlist(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    patch = _patch(
        repository,
        {
            "docs/note.txt": "after\n",
            "liltweak/value.py": "VALUE = 2\n",
        },
        authorized_paths=("docs/note.txt",),
    )
    manifest = _manifest(
        repository,
        workspace_mode=RunnerV3WorkspaceMode.EPHEMERAL_PATCH,
        source_write_authorized=True,
        patch=patch,
    )

    with pytest.raises(RunnerV3ExecutionError, match="authorized paths"):
        _executor().execute(
            manifest,
            workspace=repository,
            output_directory=tmp_path / "evidence",
            cancellation_requested=lambda: False,
        )


def test_patch_rejects_symlink_or_gitlink_modes(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    patch_text = """diff --git a/liltweak/link.py b/liltweak/link.py
new file mode 120000
index 0000000..257cc56
--- /dev/null
+++ b/liltweak/link.py
@@ -0,0 +1 @@
+value.py
"""
    patch = RunnerV3Patch.issue(
        text=patch_text,
        authorized_paths=("liltweak/link.py",),
    )
    manifest = _manifest(
        repository,
        workspace_mode=RunnerV3WorkspaceMode.EPHEMERAL_PATCH,
        source_write_authorized=True,
        patch=patch,
    )

    with pytest.raises(RunnerV3ExecutionError, match=r"symlink|gitlink"):
        _executor().execute(
            manifest,
            workspace=repository,
            output_directory=tmp_path / "evidence",
            cancellation_requested=lambda: False,
        )


def test_executor_revalidates_forged_manifest_digest(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    manifest = _manifest(repository).model_copy(update={"manifest_digest": "0" * 64})

    with pytest.raises(RunnerV3ExecutionError, match=r"digest|schema"):
        _executor().execute(
            manifest,
            workspace=repository,
            output_directory=tmp_path / "evidence",
            cancellation_requested=lambda: False,
        )


def test_executor_requires_source_inspection_as_first_action(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    manifest = _manifest(
        repository,
        actions=(RunnerV3Action.GIT_DIFF, RunnerV3Action.INSPECT_SOURCE),
    )

    with pytest.raises(RunnerV3ExecutionError, match=r"inspect_source.*first"):
        _executor().execute(
            manifest,
            workspace=repository,
            output_directory=tmp_path / "evidence",
            cancellation_requested=lambda: False,
        )


def test_failing_step_short_circuits_later_actions(tmp_path: Path) -> None:
    repository = _repository(
        tmp_path,
        sample_test="def test_failure() -> None:\n    assert False\n",
    )
    output = tmp_path / "evidence"
    manifest = _manifest(
        repository,
        actions=(
            RunnerV3Action.INSPECT_SOURCE,
            RunnerV3Action.PYTEST,
            RunnerV3Action.COMPILE_PYTHON,
            RunnerV3Action.GIT_DIFF,
        ),
    )

    receipt = _executor().execute(
        manifest,
        workspace=repository,
        output_directory=output,
        cancellation_requested=lambda: False,
    )

    assert receipt.outcome is RunnerV3Outcome.FAILED
    assert tuple(step.action for step in receipt.steps) == (
        RunnerV3Action.INSPECT_SOURCE,
        RunnerV3Action.PYTEST,
    )
    assert receipt.steps[-1].exit_code != 0
    assert not (output / "steps/02-compile_python.json").exists()


def test_global_timeout_kills_the_process_group(tmp_path: Path) -> None:
    repository = _repository(
        tmp_path,
        sample_test=("import time\n\ndef test_slow() -> None:\n    time.sleep(10)\n"),
    )
    manifest = _manifest(
        repository,
        actions=(RunnerV3Action.INSPECT_SOURCE, RunnerV3Action.PYTEST),
        timeout_seconds=1,
    )

    receipt = _executor().execute(
        manifest,
        workspace=repository,
        output_directory=tmp_path / "evidence",
        cancellation_requested=lambda: False,
    )

    assert receipt.outcome is RunnerV3Outcome.FAILED
    assert receipt.steps[-1].action is RunnerV3Action.PYTEST
    assert receipt.steps[-1].exit_code == 124


def test_cancellation_kills_the_process_group(tmp_path: Path) -> None:
    repository = _repository(
        tmp_path,
        sample_test=("import time\n\ndef test_slow() -> None:\n    time.sleep(10)\n"),
    )
    manifest = _manifest(
        repository,
        actions=(RunnerV3Action.INSPECT_SOURCE, RunnerV3Action.PYTEST),
        timeout_seconds=30,
    )
    started = time.monotonic()

    receipt = _executor().execute(
        manifest,
        workspace=repository,
        output_directory=tmp_path / "evidence",
        cancellation_requested=lambda: time.monotonic() - started > 0.15,
    )

    assert receipt.outcome is RunnerV3Outcome.CANCELLED
    assert receipt.steps[-1].exit_code == 130


def test_output_overflow_terminates_and_marks_step_truncated(tmp_path: Path) -> None:
    repository = _repository(
        tmp_path,
        sample_test=("def test_noisy() -> None:\n    print('x' * 100_000)\n    assert False\n"),
    )
    manifest = _manifest(
        repository,
        actions=(RunnerV3Action.INSPECT_SOURCE, RunnerV3Action.PYTEST),
        output_byte_limit=1_024,
    )

    receipt = _executor().execute(
        manifest,
        workspace=repository,
        output_directory=tmp_path / "evidence",
        cancellation_requested=lambda: False,
    )

    assert receipt.outcome is RunnerV3Outcome.FAILED
    assert receipt.steps[-1].exit_code == 70
    assert receipt.steps[-1].output_truncated is True


def test_read_only_workspace_mutation_is_detected_and_evidenced(
    tmp_path: Path,
) -> None:
    repository = _repository(
        tmp_path,
        sample_test=(
            "from pathlib import Path\n\n"
            "def test_mutation() -> None:\n"
            "    Path('liltweak/value.py').write_text('VALUE = 9\\n')\n"
        ),
    )
    output = tmp_path / "evidence"
    manifest = _manifest(
        repository,
        actions=(
            RunnerV3Action.INSPECT_SOURCE,
            RunnerV3Action.PYTEST,
            RunnerV3Action.GIT_DIFF,
        ),
    )

    receipt = _executor().execute(
        manifest,
        workspace=repository,
        output_directory=output,
        cancellation_requested=lambda: False,
    )

    assert receipt.outcome is RunnerV3Outcome.FAILED
    assert receipt.workspace_changed is True
    assert receipt.changed_paths == ("liltweak/value.py",)
    assert receipt.candidate_patch_digest is not None
    assert (output / "candidate.patch").is_file()


def test_child_process_does_not_inherit_provider_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-leak")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak")
    repository = _repository(
        tmp_path,
        sample_test=(
            "import os\n\n"
            "def test_secrets_absent() -> None:\n"
            "    assert os.getenv('OPENAI_API_KEY') in (None, '')\n"
            "    assert os.getenv('GITHUB_TOKEN') in (None, '')\n"
            "    assert os.getenv('AWS_SECRET_ACCESS_KEY') in (None, '')\n"
        ),
    )
    manifest = _manifest(
        repository,
        actions=(RunnerV3Action.INSPECT_SOURCE, RunnerV3Action.PYTEST),
    )

    receipt = _executor().execute(
        manifest,
        workspace=repository,
        output_directory=tmp_path / "evidence",
        cancellation_requested=lambda: False,
    )

    assert receipt.outcome is RunnerV3Outcome.SUCCEEDED


def test_output_directory_must_be_outside_workspace(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    manifest = _manifest(repository)

    with pytest.raises(RunnerV3ExecutionError, match="outside"):
        _executor().execute(
            manifest,
            workspace=repository,
            output_directory=repository / ".runner-v3-evidence",
            cancellation_requested=lambda: False,
        )


def test_cli_loads_manifest_and_writes_receipt(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = _repository(tmp_path)
    output = tmp_path / "cli-evidence"
    issued_at = datetime.now(UTC)
    manifest = _manifest(repository, issued_at=issued_at)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        f"{canonical_json(manifest.model_dump(mode='json'))}\n",
        encoding="utf-8",
    )

    status = runner_v3_main(
        [
            "--manifest",
            str(manifest_path),
            "--workspace",
            str(repository),
            "--output-directory",
            str(output),
        ]
    )

    assert status == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["outcome"] == "succeeded"
    assert summary["receipt_digest"]
    assert (output / "runner-v3-receipt.json").is_file()
    assert not any(key in os.environ for key in ("RUNNER_V3_MANIFEST_JSON", "RUNNER_V3_PATCH_TEXT"))
