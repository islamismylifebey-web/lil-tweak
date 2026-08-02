from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from liltweak.workbench_executor import BoundedToolExecutor, ProcessResult, TaskWorkspaceManager
from liltweak.workbench_security import SecurityBoundaryError


def _write(root: Path, relative: str, data: bytes, *, mode: int = 0o644) -> Path:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    target.chmod(mode)
    return target


def _tree_state(root: Path) -> dict[str, tuple[int, bytes]]:
    return {
        path.relative_to(root).as_posix(): (
            0o755 if path.stat().st_mode & 0o111 else 0o644,
            path.read_bytes(),
        )
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _apply_binary_patch(root: Path, patch: bytes) -> None:
    git = shutil.which("git", path="/usr/local/bin:/usr/bin:/bin")
    assert git is not None
    result = subprocess.run(
        (
            str(Path(git).resolve()),
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "core.hooksPath=/dev/null",
            "apply",
            "--binary",
            "-",
        ),
        cwd=root,
        env={
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "LANG": "C",
            "LC_ALL": "C",
        },
        input=patch,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


def test_patch_round_trip_preserves_text_binary_empty_and_executable_changes(
    tmp_path: Path,
) -> None:
    workspaces = TaskWorkspaceManager(tmp_path / "tasks")
    task_id = "task:patch-round-trip"
    source = workspaces.task_root(task_id)
    baseline = {
        "delete-with-newline.txt": b"delete me\n",
        "delete-without-newline.txt": b"delete me",
        "empty-delete.txt": b"",
        "modify-with-newline.txt": b"before\n",
        "modify-without-newline.txt": b"before",
        "mode-only.sh": b"#!/bin/sh\nexit 0\n",
    }
    for relative, data in baseline.items():
        _write(source, relative, data)
    snapshot, _snapshot_digest = workspaces.snapshot(task_id, 1)

    for relative in (
        "delete-with-newline.txt",
        "delete-without-newline.txt",
        "empty-delete.txt",
    ):
        (source / relative).unlink()
    _write(source, "add-with-newline.txt", b"added\n")
    _write(source, "add-without-newline.txt", b"added")
    _write(source, "empty-add.txt", b"")
    _write(source, "binary-add.bin", b"\x00\x01\x02\x7f\x80\xffbinary\n")
    _write(source, "modify-with-newline.txt", b"after\n")
    _write(source, "modify-without-newline.txt", b"after")
    (source / "mode-only.sh").chmod(0o755)

    artifact_name, patch_digest, changed_paths = workspaces.generate_patch(task_id, 1, snapshot)
    patch = workspaces.read_patch(task_id, artifact_name, patch_digest).encode("ascii")

    assert changed_paths == tuple(
        sorted(
            {
                "add-with-newline.txt",
                "add-without-newline.txt",
                "binary-add.bin",
                "delete-with-newline.txt",
                "delete-without-newline.txt",
                "empty-add.txt",
                "empty-delete.txt",
                "mode-only.sh",
                "modify-with-newline.txt",
                "modify-without-newline.txt",
            }
        )
    )
    assert hashlib.sha256(patch).hexdigest() == patch_digest
    assert b"GIT binary patch" in patch
    assert b"\\ No newline at end of file" in patch
    assert b"old mode 100644\nnew mode 100755" in patch

    applied = tmp_path / "applied"
    shutil.copytree(snapshot, applied)
    _apply_binary_patch(applied, patch)
    assert _tree_state(applied) == _tree_state(source)


def test_transient_cleanup_removes_new_cache_entries_but_preserves_baseline(
    tmp_path: Path,
) -> None:
    workspaces = TaskWorkspaceManager(tmp_path / "tasks")
    task_id = "task:transient-cleanup"
    source = workspaces.task_root(task_id)
    baseline_pytest = _write(source, ".pytest_cache/CACHEDIR.TAG", b"baseline-pytest\n")
    baseline_bytecode = _write(
        source,
        "package/__pycache__/baseline.cpython-312.pyc",
        b"baseline-bytecode",
    )
    snapshot, _snapshot_digest = workspaces.snapshot(task_id, 1)

    generated_in_baseline_pytest = _write(
        source,
        ".pytest_cache/v/cache/nodeids",
        b"[]\n",
    )
    generated_in_baseline_pycache = _write(
        source,
        "package/__pycache__/generated.cpython-312.pyc",
        b"generated-bytecode",
    )
    new_pytest_cache = _write(
        source,
        "nested/.pytest_cache/v/cache/lastfailed",
        b"{}\n",
    ).parents[2]
    new_pycache = _write(
        source,
        "new_package/__pycache__/generated.cpython-312.pyc",
        b"generated-bytecode",
    ).parent

    workspaces.discard_server_transients(task_id, snapshot)

    assert baseline_pytest.read_bytes() == b"baseline-pytest\n"
    assert baseline_bytecode.read_bytes() == b"baseline-bytecode"
    assert not generated_in_baseline_pytest.exists()
    assert not generated_in_baseline_pycache.exists()
    assert not new_pytest_cache.exists()
    assert not new_pycache.exists()


@pytest.mark.parametrize("git_control_path", [".git/config", "nested/.GiT/config"])
def test_patch_generation_rejects_git_control_paths(
    tmp_path: Path,
    git_control_path: str,
) -> None:
    workspaces = TaskWorkspaceManager(tmp_path / "tasks")
    task_id = "task:git-control-path"
    source = workspaces.task_root(task_id)
    _write(source, "safe.txt", b"baseline\n")
    snapshot, _snapshot_digest = workspaces.snapshot(task_id, 1)
    _write(source, git_control_path, b"prohibited\n")

    with pytest.raises(SecurityBoundaryError, match="Git control directory"):
        workspaces.generate_patch(task_id, 1, snapshot)


class _MetadataTransport:
    connected = True

    async def run(self, **_: object) -> ProcessResult:
        raise AssertionError("incomplete transport must never be dispatched")


@pytest.mark.parametrize(
    "metadata",
    [
        {},
        {"qualification_status": "qualified"},
        {"authorization_digest": "a" * 64},
        {"qualification_status": "unqualified", "authorization_digest": "a" * 64},
        {"qualification_status": "qualified", "authorization_digest": "a" * 63},
        {"qualification_status": "qualified", "authorization_digest": "A" * 64},
    ],
)
def test_connected_transport_requires_explicit_qualification_and_64hex_grant(
    tmp_path: Path,
    metadata: dict[str, str],
) -> None:
    transport = _MetadataTransport()
    for name, value in metadata.items():
        setattr(transport, name, value)
    executor = BoundedToolExecutor(TaskWorkspaceManager(tmp_path / "tasks"), transport)

    assert executor.connected is False

    transport.qualification_status = "qualified"
    transport.authorization_digest = "a" * 64
    assert executor.connected is False
    test_executor = BoundedToolExecutor(
        TaskWorkspaceManager(tmp_path / "test-tasks"),
        transport,
        allow_test_transport=True,
    )
    assert test_executor.connected is True
