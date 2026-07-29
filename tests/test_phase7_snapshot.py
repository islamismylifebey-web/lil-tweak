from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from liltweak.creator import outcome_digest_for_fixture
from liltweak.creator_contract import CommandKind, SandboxCommand
from liltweak.execution_contract import ExecutionRecipe
from liltweak.models import RepositoryRef
from liltweak.repository import RepositoryInspector, is_sensitive_path
from liltweak.source_snapshot import RepositorySnapshotBuilder, SourceSnapshotError
from tests.repository_helpers import initialize_repository, run_git

IMAGE = "registry.invalid/liltweak-python@sha256:" + ("a" * 64)


def recipe(**changes: object) -> ExecutionRecipe:
    values: dict[str, object] = {
        "recipe_id": "python-verify",
        "image_ref": IMAGE,
        "commands": (
            SandboxCommand(
                command_id="tests",
                kind=CommandKind.TEST,
                argv=("pytest", "-q"),
                timeout_seconds=60,
            ),
        ),
    }
    values.update(changes)
    return ExecutionRecipe.model_validate(values)


def builder_for(workspace: Path, commit: str) -> tuple[RepositorySnapshotBuilder, RepositoryRef]:
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )
    reference = RepositoryRef(
        provider="local",
        repository_id="fixture",
        revision=commit,
    )
    return RepositorySnapshotBuilder(inspector), reference


def make_tree_writable(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_dir() and not path.is_symlink():
            os.chmod(path, 0o700)
        elif not path.is_symlink():
            os.chmod(path, 0o600)
    os.chmod(root, 0o700)


def test_execution_recipe_rejects_shell_and_interpreter_evaluation() -> None:
    with pytest.raises(ValueError, match="safe bare executable"):
        recipe(
            commands=(
                SandboxCommand(
                    command_id="shell",
                    kind=CommandKind.TEST,
                    argv=("sh", "-c", "pytest"),
                    timeout_seconds=10,
                ),
            )
        )
    with pytest.raises(ValueError, match="interpreter evaluation"):
        recipe(
            commands=(
                SandboxCommand(
                    command_id="python-eval",
                    kind=CommandKind.TEST,
                    argv=("python", "-c", "print('unsafe')"),
                    timeout_seconds=10,
                ),
            )
        )
    with pytest.raises(ValueError, match="safe bare executable"):
        recipe(
            commands=(
                SandboxCommand(
                    command_id="package-install",
                    kind=CommandKind.TEST,
                    argv=("pip", "install", "anything"),
                    timeout_seconds=10,
                ),
            )
        )
    with pytest.raises(ValueError, match="cannot modify source"):
        recipe(
            commands=(
                SandboxCommand(
                    command_id="ruff-fix",
                    kind=CommandKind.LINT,
                    argv=("ruff", "check", "--fix", "."),
                    timeout_seconds=10,
                ),
            )
        )


def test_execution_recipe_digest_is_deterministic_and_bounded() -> None:
    first = recipe()
    second = recipe()
    assert first.recipe_digest == second.recipe_digest
    assert first.network_allowed is False
    assert first.source_write_allowed is False
    assert first.deployment_allowed is False
    assert outcome_digest_for_fixture("not-the-recipe") != first.recipe_digest


def test_process_observation_rejects_contradictory_success_and_signal() -> None:
    from liltweak.execution_contract import ProcessObservation

    with pytest.raises(ValueError, match="exactly one"):
        ProcessObservation(
            command_id="contradictory",
            exit_code=0,
            signal=9,
            stdout_digest="0" * 64,
            stderr_digest="0" * 64,
            stdout_bytes=0,
            stderr_bytes=0,
            duration_ms=1,
        )


def test_committed_tree_snapshot_is_deterministic_and_git_free(tmp_path: Path) -> None:
    _repository, commit = initialize_repository(tmp_path)
    builder, reference = builder_for(tmp_path, commit)
    first = builder.prepare_manifest(reference)
    second = builder.prepare_manifest(reference)
    assert first == second
    assert first.resolved_revision == commit
    assert first.file_count == 4
    assert first.credential_finding_count == 0

    destination = tmp_path / "materialized"
    observed = builder.materialize(reference, first, destination)
    assert observed == first
    assert not (destination / ".git").exists()
    assert (destination / "src" / "app.py").is_file()
    assert stat.S_IMODE((destination / "src" / "app.py").stat().st_mode) == 0o444
    make_tree_writable(destination)


def test_snapshot_rejects_dirty_ignored_and_secret_state(tmp_path: Path) -> None:
    repository, commit = initialize_repository(tmp_path)
    builder, reference = builder_for(tmp_path, commit)
    (repository / "untracked.txt").write_text("untracked", encoding="utf-8")
    with pytest.raises(SourceSnapshotError, match="clean, exact"):
        builder.prepare_manifest(reference)
    (repository / "untracked.txt").unlink()

    fake_key = "sk-" + "proj-" + ("R" * 32)
    (repository / "src" / "secret.py").write_text(fake_key, encoding="utf-8")
    run_git(repository, "add", "src/secret.py")
    run_git(repository, "commit", "-q", "-m", "credential fixture")
    secret_commit = run_git(repository, "rev-parse", "HEAD")
    _builder, secret_reference = builder_for(tmp_path, secret_commit)
    with pytest.raises(SourceSnapshotError, match="credential-shaped"):
        _builder.prepare_manifest(secret_reference)


@pytest.mark.parametrize(
    "filename",
    [".ENV", ".Env.production", "CREDENTIALS.JSON"],
)
def test_snapshot_rejects_mixed_case_sensitive_filenames(
    tmp_path: Path,
    filename: str,
) -> None:
    repository, _commit = initialize_repository(tmp_path)
    (repository / filename).write_text("not-a-credential\n", encoding="utf-8")
    run_git(repository, "add", filename)
    run_git(repository, "commit", "-q", "-m", "mixed-case sensitive filename")
    commit = run_git(repository, "rev-parse", "HEAD")
    builder, reference = builder_for(tmp_path, commit)

    assert is_sensitive_path(filename)
    with pytest.raises(SourceSnapshotError, match=r"sensitive|credential"):
        builder.prepare_manifest(reference)


def test_snapshot_allows_mixed_case_env_example_policy(tmp_path: Path) -> None:
    repository, _commit = initialize_repository(tmp_path)
    filename = ".ENV.EXAMPLE"
    (repository / filename).write_text("EXAMPLE_VALUE=\n", encoding="utf-8")
    run_git(repository, "add", filename)
    run_git(repository, "commit", "-q", "-m", "mixed-case environment example")
    commit = run_git(repository, "rev-parse", "HEAD")
    builder, reference = builder_for(tmp_path, commit)

    assert not is_sensitive_path(filename)
    assert builder.prepare_manifest(reference).file_count == 5


def test_snapshot_rejects_symlinks_and_source_drift(tmp_path: Path) -> None:
    repository, commit = initialize_repository(tmp_path)
    builder, reference = builder_for(tmp_path, commit)
    approved = builder.prepare_manifest(reference)
    (repository / "src" / "app.py").write_text("changed = True\n", encoding="utf-8")
    with pytest.raises(SourceSnapshotError, match="no longer matches"):
        builder.materialize(reference, approved, tmp_path / "stale")

    run_git(repository, "reset", "--hard", commit)
    (repository / "linked.py").symlink_to("src/app.py")
    run_git(repository, "add", "linked.py")
    run_git(repository, "commit", "-q", "-m", "symlink fixture")
    symlink_commit = run_git(repository, "rev-parse", "HEAD")
    _builder, symlink_reference = builder_for(tmp_path, symlink_commit)
    with pytest.raises(SourceSnapshotError, match="clean, exact"):
        _builder.prepare_manifest(symlink_reference)


def test_snapshot_path_validation_rejects_git_and_casefolded_ancestors() -> None:
    with pytest.raises(SourceSnapshotError, match="unsafe"):
        RepositorySnapshotBuilder._validate_path(
            ".GIT/config",
            set(),
            set(),
            set(),
        )

    collisions: set[str] = set()
    file_keys: set[str] = set()
    ancestor_keys: set[str] = set()
    RepositorySnapshotBuilder._validate_path(
        "Foo",
        collisions,
        file_keys,
        ancestor_keys,
    )
    with pytest.raises(SourceSnapshotError, match="ancestor"):
        RepositorySnapshotBuilder._validate_path(
            "foo/bar.py",
            collisions,
            file_keys,
            ancestor_keys,
        )


def test_git_snapshot_reader_stops_at_the_output_limit(tmp_path: Path) -> None:
    _repository, commit = initialize_repository(tmp_path)
    builder, _reference = builder_for(tmp_path, commit)
    noisy_git = tmp_path / "noisy-git"
    noisy_git.write_text(
        f"#!{sys.executable}\nimport os\nos.write(1, b'x' * 1_000_000)\n",
        encoding="utf-8",
    )
    noisy_git.chmod(0o700)
    builder.git_binary = str(noisy_git)
    with pytest.raises(SourceSnapshotError, match="output exceeded"):
        builder._git(
            tmp_path,
            "ls-tree",
            output_limit=1_024,
        )
