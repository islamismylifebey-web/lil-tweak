from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from liltweak.artifacts import EncryptedArtifactStore
from liltweak.recovery import RecoveryBlockedError, RecoveryCapture
from liltweak.repository import RepositoryInspector
from liltweak.store import SQLiteStore
from tests.repository_helpers import initialize_repository, run_git


def _capture(workspace: Path, artifact_root: Path) -> RecoveryCapture:
    store = SQLiteStore(":memory:")
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )
    artifact_store = EncryptedArtifactStore(
        root=artifact_root,
        workspace_root=workspace,
        master_key=b"P" * 32,
        store=store,
    )
    return RecoveryCapture(
        inspector=inspector,
        artifact_store=artifact_store,
    )


def _apply(repository: Path, patch: bytes, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(repository), "apply", *arguments, "-"],
        input=patch,
        check=True,
        capture_output=True,
    )


def _status(repository: Path) -> bytes:
    return subprocess.run(
        [
            "git",
            "--no-optional-locks",
            "-C",
            str(repository),
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
        ],
        check=True,
        capture_output=True,
    ).stdout


def test_capture_remains_command_free_if_filter_is_added_after_boundary_check(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    (repository / ".gitattributes").write_text(
        "src/app.py filter=hostile diff=hostile\n",
        encoding="utf-8",
    )
    run_git(repository, "add", ".gitattributes")
    run_git(repository, "commit", "-q", "-m", "Add hostile attribute fixture")
    head = run_git(repository, "rev-parse", "HEAD")

    sentinel = tmp_path / "filter-executed"
    filter_program = tmp_path / "hostile-filter.sh"
    filter_program.write_text(
        f"#!/bin/sh\ntouch '{sentinel}'\ncat\n",
        encoding="utf-8",
    )
    filter_program.chmod(0o755)
    capture = _capture(workspace, tmp_path / "artifacts")
    capture._validate_git_boundary(repository)

    run_git(repository, "config", "filter.hostile.clean", str(filter_program))
    run_git(repository, "config", "diff.hostile.textconv", str(filter_program))
    changed = b"from fastapi import FastAPI\n\napp = FastAPI(title='raw bytes')\n"
    (repository / "src" / "app.py").write_bytes(changed)

    staged, unstaged = capture._capture_tracked_patches(
        repository,
        head,
        ["--"],
    )

    assert staged == b""
    assert b"+app = FastAPI(title='raw bytes')" in unstaged
    assert not sentinel.exists()


@pytest.mark.skipif(os.name != "posix", reason="mode recovery requires POSIX file modes")
def test_python_patches_restore_renames_deletes_modes_and_no_final_newline(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    (repository / "docs").mkdir()
    (repository / "scripts").mkdir()
    (repository / "docs" / "old name.txt").write_text(
        "before rename\n",
        encoding="utf-8",
    )
    executable = repository / "scripts" / "run.sh"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    run_git(repository, "add", ".")
    run_git(repository, "commit", "-q", "-m", "Add patch edge cases")
    head = run_git(repository, "rev-parse", "HEAD")

    run_git(repository, "mv", "docs/old name.txt", "docs/renamed ü.txt")
    (repository / "docs" / "renamed ü.txt").write_bytes(b"after rename without newline")
    run_git(repository, "rm", "-q", "tests/test_app.py")
    executable.chmod(0o755)
    run_git(repository, "add", "scripts/run.sh")
    executable.chmod(0o644)
    (repository / "empty.txt").write_bytes(b"")
    run_git(repository, "add", "empty.txt")

    capture = _capture(workspace, tmp_path / "artifacts")
    staged, unstaged = capture._capture_tracked_patches(
        repository,
        head,
        ["--"],
    )

    restored = tmp_path / "restored"
    subprocess.run(
        ["git", "clone", "--quiet", "--no-hardlinks", str(repository), str(restored)],
        check=True,
        capture_output=True,
    )
    _apply(restored, staged, "--index", "--binary")
    _apply(restored, unstaged, "--binary")

    assert _status(restored) == _status(repository)
    assert (restored / "docs" / "renamed ü.txt").read_bytes() == (
        repository / "docs" / "renamed ü.txt"
    ).read_bytes()
    assert not (restored / "docs" / "old name.txt").exists()
    assert not (restored / "tests" / "test_app.py").exists()
    assert (restored / "empty.txt").is_file()
    assert stat_mode(restored / "scripts" / "run.sh") == stat_mode(executable)


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_sensitive_rename_checks_both_source_and_destination(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    (repository / ".env").write_text("FIXTURE_VALUE=not-a-secret\n", encoding="utf-8")
    run_git(repository, "add", ".env")
    run_git(repository, "commit", "-q", "-m", "Add sensitive path fixture")
    head = run_git(repository, "rev-parse", "HEAD")
    run_git(repository, "mv", ".env", "safe-name.txt")
    capture = _capture(workspace, tmp_path / "artifacts")

    with pytest.raises(RecoveryBlockedError) as blocked:
        capture._capture_tracked_patches(repository, head, ["--"])

    assert blocked.value.code == "sensitive_path"


def test_non_utf8_tracked_change_is_blocked_as_binary(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    (repository / "src" / "app.py").write_bytes(b"not utf-8: \xff\xfe\n")
    capture = _capture(workspace, tmp_path / "artifacts")

    with pytest.raises(RecoveryBlockedError) as blocked:
        capture._capture_tracked_patches(repository, head, ["--"])

    assert blocked.value.code == "binary_change_not_supported"


def test_ignored_files_are_included_in_untracked_scope_and_sensitive_ones_block(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    (repository / ".gitignore").write_text(
        ".env.local\nignored-note.txt\n",
        encoding="utf-8",
    )
    run_git(repository, "add", ".gitignore")
    run_git(repository, "commit", "-q", "-m", "Add ignored recovery fixtures")
    (repository / "ignored-note.txt").write_text("include me\n", encoding="utf-8")
    (repository / ".env.local").write_text(
        "FIXTURE_VALUE=not-a-secret\n",
        encoding="utf-8",
    )
    capture = _capture(workspace, tmp_path / "artifacts")

    inventory = capture._untracked_inventory(repository, ["--"])

    assert inventory == [".env.local", "ignored-note.txt"]
    with pytest.raises(RecoveryBlockedError) as blocked:
        capture._build_untracked_archive(repository, inventory)
    assert blocked.value.code == "sensitive_path"


def test_promisor_configuration_blocks_object_capture(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    run_git(repository, "config", "remote.origin.promisor", "true")
    capture = _capture(workspace, tmp_path / "artifacts")

    with pytest.raises(RecoveryBlockedError) as blocked:
        capture._validate_git_boundary(repository)

    assert blocked.value.code == "partial_clone_not_supported"


def test_capture_rejects_cross_set_casefold_collision(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    (repository / "A.txt").write_text("tracked\n", encoding="utf-8")
    run_git(repository, "add", "A.txt")
    run_git(repository, "commit", "-q", "-m", "Add collision fixture")
    head = run_git(repository, "rev-parse", "HEAD")
    (repository / "a.txt").write_text("untracked\n", encoding="utf-8")
    capture = _capture(workspace, tmp_path / "artifacts")

    with pytest.raises(RecoveryBlockedError) as blocked:
        capture._capture_tracked_patches(repository, head, ["--"])

    assert blocked.value.code == "path_collision"


def test_capture_rejects_skip_worktree_deletion_semantics(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    run_git(repository, "update-index", "--skip-worktree", "src/app.py")
    (repository / "src" / "app.py").unlink()
    capture = _capture(workspace, tmp_path / "artifacts")

    with pytest.raises(RecoveryBlockedError) as blocked:
        capture._capture_tracked_patches(repository, head, ["--"])

    assert blocked.value.code == "unsupported_index_flags"
