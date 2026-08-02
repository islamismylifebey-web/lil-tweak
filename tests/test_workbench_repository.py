from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

import liltweak.workbench_repository as repository_module
from liltweak.workbench_repository import (
    WorkbenchRepositoryError,
    WorkbenchRepositoryRegistry,
)


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _initialize_repository(root: Path, name: str = "project") -> Path:
    repository = root / name
    (repository / "src").mkdir(parents=True)
    (repository / "web").mkdir()
    (repository / "tests").mkdir()
    (repository / "src" / "calculator.py").write_text(
        "def total(values: list[int]) -> int:\n    return sum(values) + 1\n",
        encoding="utf-8",
    )
    (repository / "tests" / "test_calculator.py").write_text(
        "from src.calculator import total\n\n\ndef test_total():\n    assert total([1, 2]) == 3\n",
        encoding="utf-8",
    )
    (repository / "web" / "app.js").write_text(
        "export function label(value) { return `Total: ${value}`; }\n",
        encoding="utf-8",
    )
    (repository / "package.json").write_text(
        json.dumps(
            {
                "name": "fixture-interface",
                "scripts": {"test": "node --test"},
                "dependencies": {"react": "1.0.0"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (repository / "pyproject.toml").write_text(
        (
            "[project]\n"
            'name = "fixture-backend"\n'
            'version = "0.1.0"\n'
            'dependencies = ["fastapi>=0.100"]\n'
        ),
        encoding="utf-8",
    )
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Fixture Owner")
    _git(repository, "config", "user.email", "fixture@example.invalid")
    _git(repository, "add", ".")
    _git(repository, "commit", "-q", "-m", "Initial fixture")
    return repository


def _worktree_payload(repository: Path) -> dict[str, tuple[bytes, bool]]:
    payload: dict[str, tuple[bytes, bool]] = {}
    for path in sorted(repository.rglob("*")):
        if ".git" in path.relative_to(repository).parts or not path.is_file():
            continue
        metadata = path.lstat()
        payload[path.relative_to(repository).as_posix()] = (
            path.read_bytes(),
            bool(metadata.st_mode & stat.S_IXUSR),
        )
    return payload


def _git_control_payload(repository: Path) -> dict[str, tuple[bytes, int]]:
    payload: dict[str, tuple[bytes, int]] = {}
    for name in ("HEAD", "config", "index"):
        path = repository / ".git" / name
        metadata = path.lstat()
        payload[name] = (path.read_bytes(), metadata.st_mtime_ns)
    return payload


def test_real_inspection_materializes_git_free_copy_and_preserves_source(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "registered"
    source_root.mkdir()
    repository = _initialize_repository(source_root)
    (repository / "owner-note.txt").write_text("untracked owner work\n", encoding="utf-8")
    before_files = _worktree_payload(repository)
    before_git = _git_control_payload(repository)
    registry = WorkbenchRepositoryRegistry(
        source_root,
        {"repo_8d8314f6": "project"},
    )

    inspection = registry.inspect(
        "repo_8d8314f6",
        direction="Find why calculator total adds one and repair the backend defect.",
    )

    assert inspection.repository_id == "repo_8d8314f6"
    assert inspection.git.head == _git(repository, "rev-parse", "HEAD")
    assert inspection.git.dirty is True
    assert inspection.git.untracked_count == 1
    assert inspection.languages["Python"] == 2
    assert inspection.languages["JavaScript"] == 1
    assert set(inspection.framework_clues) == {"FastAPI", "React"}
    assert any(item.path == "src/calculator.py" for item in inspection.files)
    assert any(item.path == "src/calculator.py" for item in inspection.excerpts)
    assert all(len(item.sha256) == 64 for item in inspection.files)
    serialized_context = json.dumps(registry.planning_context(inspection))
    assert str(source_root) not in serialized_context
    assert str(repository) not in serialized_context

    task_root = tmp_path / "tasks"
    task_root.mkdir()
    destination = task_root / "task-one"
    materialized = registry.materialize(
        "repo_8d8314f6",
        expected_source_fingerprint=inspection.source_fingerprint,
        destination=destination,
    )

    assert materialized.repository_id == inspection.repository_id
    assert materialized.source_fingerprint == inspection.source_fingerprint
    assert materialized.git_metadata_included is False
    assert materialized.source_writes_performed is False
    assert not (destination / ".git").exists()
    assert _worktree_payload(destination) == before_files
    assert _worktree_payload(repository) == before_files
    assert _git_control_payload(repository) == before_git
    assert registry.inspect("repo_8d8314f6").source_fingerprint == inspection.source_fingerprint


def test_git_calls_are_structured_and_never_use_a_shell(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "registered"
    source_root.mkdir()
    _initialize_repository(source_root)
    registry = WorkbenchRepositoryRegistry(source_root, {"repo_structured": "project"})
    real_run = subprocess.run
    observed: list[tuple[object, object]] = []

    def capture_run(command, **kwargs):
        observed.append((command, kwargs.get("shell")))
        return real_run(command, **kwargs)

    monkeypatch.setattr(repository_module.subprocess, "run", capture_run)
    registry.inspect("repo_structured", direction="Inspect calculator total behavior.")

    assert observed
    assert all(isinstance(command, list) for command, _shell in observed)
    assert all(shell is False for _command, shell in observed)
    assert all(Path(command[0]).name == "git" for command, _shell in observed)


def test_secret_paths_and_content_never_enter_planning_context(tmp_path: Path) -> None:
    source_root = tmp_path / "registered"
    source_root.mkdir()
    repository = _initialize_repository(source_root)
    (repository / ".env").write_text("PRIVATE_SETTING=not-for-models\n", encoding="utf-8")
    secret = "sk-" + "proj-" + ("Q" * 32)
    (repository / "src" / "leak.txt").write_text(secret, encoding="utf-8")
    registry = WorkbenchRepositoryRegistry(source_root, {"repo_private": "project"})

    inspection = registry.inspect("repo_private", direction="Inspect calculator total behavior.")
    context = json.dumps(registry.planning_context(inspection))

    assert inspection.screened_file_count == 2
    assert "openai-api-key" in inspection.secret_rule_ids
    assert ".env" not in context
    assert "leak.txt" not in context
    assert "not-for-models" not in context
    assert secret not in context
    task_parent = tmp_path / "tasks"
    task_parent.mkdir()
    with pytest.raises(WorkbenchRepositoryError, match="secret-like"):
        registry.materialize(
            "repo_private",
            expected_source_fingerprint=inspection.source_fingerprint,
            destination=task_parent / "task-private",
        )


def test_materialization_rejects_source_changed_after_inspection(tmp_path: Path) -> None:
    source_root = tmp_path / "registered"
    source_root.mkdir()
    repository = _initialize_repository(source_root)
    registry = WorkbenchRepositoryRegistry(source_root, {"repo_concurrent": "project"})
    inspection = registry.inspect("repo_concurrent", direction="Inspect calculator total.")
    (repository / "src" / "calculator.py").write_text(
        "def total(values: list[int]) -> int:\n    return sum(values)\n",
        encoding="utf-8",
    )
    task_parent = tmp_path / "tasks"
    task_parent.mkdir()
    destination = task_parent / "task-concurrent"

    with pytest.raises(WorkbenchRepositoryError, match="changed after inspection"):
        registry.materialize(
            "repo_concurrent",
            expected_source_fingerprint=inspection.source_fingerprint,
            destination=destination,
        )

    assert not destination.exists()


def test_registry_rejects_traversal_symlink_missing_git_hardlink_and_special_file(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "registered"
    source_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(WorkbenchRepositoryError, match="mapping"):
        WorkbenchRepositoryRegistry(source_root, {"repo_escape": "../outside"})

    repository = _initialize_repository(source_root, "real")
    (source_root / "linked").symlink_to(repository, target_is_directory=True)
    linked = WorkbenchRepositoryRegistry(source_root, {"repo_link": "linked"})
    with pytest.raises(WorkbenchRepositoryError, match="symlink"):
        linked.inspect("repo_link")

    plain = source_root / "plain"
    plain.mkdir()
    missing = WorkbenchRepositoryRegistry(source_root, {"repo_plain": "plain"})
    with pytest.raises(WorkbenchRepositoryError, match="Git"):
        missing.inspect("repo_plain")

    hardlink_source = repository / "src" / "calculator.py"
    os.link(hardlink_source, repository / "src" / "calculator-copy.py")
    hardlinked = WorkbenchRepositoryRegistry(source_root, {"repo_hardlink": "real"})
    with pytest.raises(WorkbenchRepositoryError, match="hardlinked"):
        hardlinked.inspect("repo_hardlink")
    (repository / "src" / "calculator-copy.py").unlink()

    fifo = repository / "unsafe.pipe"
    os.mkfifo(fifo)
    special = WorkbenchRepositoryRegistry(source_root, {"repo_special": "real"})
    with pytest.raises(WorkbenchRepositoryError, match="special"):
        special.inspect("repo_special")


def test_file_hashes_are_content_bound_and_excerpts_are_bounded(tmp_path: Path) -> None:
    source_root = tmp_path / "registered"
    source_root.mkdir()
    repository = _initialize_repository(source_root)
    long_body = "\n".join(f"def calculator_rule_{index}(): return {index}" for index in range(200))
    (repository / "src" / "rules.py").write_text(long_body + "\n", encoding="utf-8")
    registry = WorkbenchRepositoryRegistry(source_root, {"repo_bounded": "project"})

    inspection = registry.inspect(
        "repo_bounded",
        direction="Explain calculator_rule_150 and calculator behavior.",
    )
    fact = next(item for item in inspection.files if item.path == "src/rules.py")

    assert fact.sha256 == hashlib.sha256((long_body + "\n").encode()).hexdigest()
    assert len(inspection.excerpts) <= registry.limits.max_excerpt_files
    assert sum(len(item.text) for item in inspection.excerpts) <= (
        registry.limits.max_excerpt_characters
    )
    assert all(
        item.last_line - item.first_line + 1 <= registry.limits.max_excerpt_lines
        for item in inspection.excerpts
    )
