from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from liltweak.models import RepositoryRef
from liltweak.repository import (
    InspectionLimits,
    RepositoryAccessError,
    RepositoryInspector,
)
from tests.repository_helpers import initialize_repository, repository_oracle, run_git


def reference(
    *,
    repository_id: str = "fixture",
    revision: str = "WORKTREE",
    allowed_paths: list[str] | None = None,
) -> RepositoryRef:
    return RepositoryRef(
        provider="local",
        repository_id=repository_id,
        revision=revision,
        allowed_paths=allowed_paths or [],
    )


def test_repository_reference_rejects_unsafe_scope() -> None:
    for unsafe in ["/etc", "../outside", "src/../outside", "src\\outside", ".", "src//app"]:
        with pytest.raises(ValidationError):
            reference(allowed_paths=[unsafe])
    with pytest.raises(ValidationError):
        RepositoryRef(
            provider="unsupported",
            repository_id="fixture",
            revision="WORKTREE",
        )


def test_inspection_detects_git_stack_risks_and_preserves_repository(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    (repository / "src" / "app.py").write_text(
        "from fastapi import FastAPI\n\napp = FastAPI(title='changed')\n",
        encoding="utf-8",
    )
    (repository / "tests" / "test_staged.py").write_text(
        "def test_staged():\n    assert True\n",
        encoding="utf-8",
    )
    run_git(repository, "add", "tests/test_staged.py")
    fake_secret = "sk-" + "proj-" + ("Z" * 32)
    (repository / "src" / "credential.txt").write_text(fake_secret, encoding="utf-8")

    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )
    before = repository_oracle(repository)
    report = inspector.inspect(reference())
    after = repository_oracle(repository)

    assert before == after
    assert report.read_only_verified is True
    assert report.git.is_repository is True
    assert report.git.modified_paths == ["src/app.py"]
    assert report.git.staged_paths == ["tests/test_staged.py"]
    assert "src/credential.txt" in report.git.untracked_paths
    assert "FastAPI" in report.frameworks
    assert any(item.language == "Python" for item in report.languages)
    assert report.recovery.patch_recommended is True
    assert report.recovery.untracked_archive_recommended is True
    assert any(item.rule_id == "openai-api-key" for item in report.secret_findings)
    assert fake_secret not in report.model_dump_json()
    assert fake_secret not in json.dumps(inspector.planning_context(report))


def test_allowed_paths_narrow_detection_scope(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    (repository / "web").mkdir()
    (repository / "web" / "package.json").write_text(
        json.dumps({"dependencies": {"next": "1", "react": "1"}}),
        encoding="utf-8",
    )
    report = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    ).inspect(reference(allowed_paths=["src"]))

    assert report.allowed_paths == ["src"]
    assert {item.language for item in report.languages} == {"Python"}
    assert "Next.js" not in report.frameworks
    assert report.dependency_manifests == []


def test_registry_is_opaque_and_confined(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={
            "local:outside": "../outside",
            "local:absolute": str(outside),
        },
    )
    with pytest.raises(RepositoryAccessError):
        inspector.inspect(reference(repository_id="outside"))
    with pytest.raises(RepositoryAccessError):
        inspector.inspect(reference(repository_id="absolute"))
    with pytest.raises(RepositoryAccessError):
        inspector.inspect(reference(repository_id="../outside"))


def test_symlink_repository_and_allowed_path_are_blocked(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "linked").symlink_to(repository, target_is_directory=True)
    (repository / "escape").symlink_to(outside, target_is_directory=True)

    linked_inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:linked": "linked"},
    )
    with pytest.raises(RepositoryAccessError):
        linked_inspector.inspect(reference(repository_id="linked"))

    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )
    with pytest.raises(RepositoryAccessError):
        inspector.inspect(reference(allowed_paths=["escape"]))


def test_exact_revision_must_match_worktree_head(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, first_head = initialize_repository(workspace)
    (repository / "README.md").write_text("second\n", encoding="utf-8")
    run_git(repository, "add", "README.md")
    run_git(repository, "commit", "-q", "-m", "Second")
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )
    with pytest.raises(RepositoryAccessError, match="does not match"):
        inspector.inspect(reference(revision=first_head))


def test_git_hooks_and_fsmonitor_are_not_executed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    sentinel = tmp_path / "executed"
    monitor = repository / "monitor.sh"
    monitor.write_text(f"#!/bin/sh\ntouch '{sentinel}'\n", encoding="utf-8")
    monitor.chmod(0o755)
    run_git(repository, "config", "core.fsmonitor", str(monitor))
    hook = repository / ".git" / "hooks" / "post-index-change"
    hook.write_text(f"#!/bin/sh\ntouch '{sentinel}'\n", encoding="utf-8")
    hook.chmod(0o755)

    report = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    ).inspect(reference())

    assert report.read_only_verified is True
    assert not sentinel.exists()


def test_sensitive_filename_is_reported_without_reading_value(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    private_fixture = "-".join(("not", "a", "standard", "token", "but", "still", "private"))
    (repository / ".env.local").write_text(
        f"PRIVATE_VALUE={private_fixture}\n",
        encoding="utf-8",
    )
    report = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    ).inspect(reference())

    assert any(item.rule_id == "sensitive-filename" for item in report.secret_findings)
    assert private_fixture not in report.model_dump_json()


def test_remote_credentials_are_never_returned(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    embedded_secret = "remote-password-value"
    run_git(
        repository,
        "remote",
        "add",
        "origin",
        f"https://user:{embedded_secret}@github.com/owner/repository.git?token=private",
    )
    report = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    ).inspect(reference())

    assert report.git.remotes[0].host == "github.com"
    assert report.git.remotes[0].provider == "github"
    assert embedded_secret not in report.model_dump_json()
    assert "token=private" not in report.model_dump_json()


def test_rename_delete_and_detached_head_are_reported(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    run_git(repository, "mv", "tests/test_app.py", "tests/test_renamed.py")
    (repository / "src" / "app.py").unlink()
    run_git(repository, "checkout", "--detach", "-q")
    report = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    ).inspect(reference(revision=head))

    assert report.git.detached_head is True
    assert "tests/test_renamed.py" in report.git.renamed_paths
    assert "tests/test_app.py" in report.git.renamed_paths
    assert "tests/test_app.py" in report.git.staged_paths
    assert "tests/test_renamed.py" in report.git.staged_paths
    assert "src/app.py" in report.git.deleted_paths


def test_snapshot_detects_same_size_change_with_restored_mtime(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )
    before = inspector.inspect(reference())
    target = repository / "src" / "app.py"
    metadata = target.stat()
    original = target.read_bytes()
    changed = original.replace(b"FastAPI", b"LastAPI")
    assert len(changed) == len(original)
    target.write_bytes(changed)
    os.utime(
        target,
        ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
    )

    after = inspector.inspect(reference())

    assert "src/app.py" in after.git.modified_paths
    assert after.git.recovery_snapshot_digest != before.git.recovery_snapshot_digest
    assert after.repository_fingerprint != before.repository_fingerprint


def test_ignored_files_are_included_in_snapshot_and_recovery_scope(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    (repository / ".gitignore").write_text("private.tmp\n", encoding="utf-8")
    ignored = repository / "private.tmp"
    ignored.write_text("first", encoding="utf-8")
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )
    first = inspector.inspect(reference())
    metadata = ignored.stat()
    ignored.write_text("other", encoding="utf-8")
    os.utime(ignored, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    second = inspector.inspect(reference())

    assert "private.tmp" in first.git.untracked_paths
    assert "private.tmp" in first.git.ignored_paths
    assert first.git.ignored_paths_included is True
    assert first.recovery.untracked_archive_recommended is True
    assert second.git.recovery_snapshot_digest != first.git.recovery_snapshot_digest


def test_sensitive_rename_reports_both_source_and_destination(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    sensitive = repository / ".env"
    sensitive.write_text("NON_SECRET_FIXTURE=value\n", encoding="utf-8")
    run_git(repository, "add", ".env")
    run_git(repository, "commit", "-q", "-m", "Add sensitive-name fixture")
    run_git(repository, "mv", ".env", "safe-name.txt")

    report = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    ).inspect(reference())

    assert {".env", "safe-name.txt"}.issubset(report.git.staged_paths)
    assert {".env", "safe-name.txt"}.issubset(report.git.renamed_paths)


def test_allowed_path_cannot_hide_cross_scope_sensitive_rename(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    (repository / ".env").write_text("MODE=demo\n", encoding="utf-8")
    run_git(repository, "add", ".env")
    run_git(repository, "commit", "-q", "-m", "Add scoped rename fixture")
    run_git(repository, "mv", ".env", "safe.txt")
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )

    with pytest.raises(RepositoryAccessError, match="cross-scope rename"):
        inspector.inspect(reference(allowed_paths=["safe.txt"]))


def test_full_inventory_rejects_cross_set_casefold_collision(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    (repository / "A.txt").write_text("tracked\n", encoding="utf-8")
    run_git(repository, "add", "A.txt")
    run_git(repository, "commit", "-q", "-m", "Add collision fixture")
    (repository / "a.txt").write_text("untracked\n", encoding="utf-8")
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )

    with pytest.raises(RepositoryAccessError, match="case-fold path collision"):
        inspector.inspect(reference())


def test_critical_git_metadata_symlink_and_hardlink_are_blocked(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )
    index_copy = workspace / "index-copy"
    os.link(repository / ".git" / "index", index_copy)
    with pytest.raises(RepositoryAccessError, match="hard-linked"):
        inspector.inspect(reference())
    index_copy.unlink()

    config = repository / ".git" / "config"
    config_copy = workspace / "config-copy"
    config.rename(config_copy)
    config.symlink_to(config_copy)
    with pytest.raises(RepositoryAccessError, match="symlinks"):
        inspector.inspect(reference())


def test_git_common_directory_and_promisor_markers_are_blocked(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )
    (repository / ".git" / "commondir").write_text("../outside\n", encoding="utf-8")
    with pytest.raises(RepositoryAccessError, match="indirection"):
        inspector.inspect(reference())
    (repository / ".git" / "commondir").unlink()

    marker = repository / ".git" / "objects" / "pack" / "fixture.promisor"
    marker.parent.mkdir(exist_ok=True)
    marker.write_bytes(b"")
    with pytest.raises(RepositoryAccessError, match="promisor"):
        inspector.inspect(reference())


def test_untracked_nested_repository_cannot_be_silently_snapshotted(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    nested = repository / "nested"
    nested.mkdir()
    run_git(nested, "init", "-q")
    (nested / "private.txt").write_text("nested bytes\n", encoding="utf-8")
    report = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    ).inspect(reference())

    assert report.complete is False
    assert report.git.metadata_complete is False
    assert report.git.recovery_snapshot_digest is None


def test_partial_clone_and_promisor_controls_are_blocked(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    run_git(repository, "config", "remote.origin.promisor", "true")
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )

    with pytest.raises(RepositoryAccessError, match="unsupported"):
        inspector.inspect(reference())
    run_git(repository, "config", "--unset", "remote.origin.promisor")
    run_git(repository, "config", "extensions.worktreeConfig", "true")
    with pytest.raises(RepositoryAccessError, match="unsupported"):
        inspector.inspect(reference())


def test_snapshot_byte_limit_marks_inspection_incomplete(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    initialize_repository(workspace)
    report = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
        limits=InspectionLimits(max_total_bytes=1),
    ).inspect(reference())

    assert report.complete is False
    assert report.git.metadata_complete is False
    assert report.git.recovery_snapshot_digest is None
    assert "recovery_snapshot_incomplete" in report.limits_reached


@pytest.mark.parametrize("index_flag", ["--skip-worktree", "--assume-unchanged"])
def test_unsupported_index_flags_are_rejected(
    tmp_path: Path,
    index_flag: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    run_git(repository, "update-index", index_flag, "src/app.py")
    if index_flag == "--skip-worktree":
        (repository / "src" / "app.py").unlink()
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )

    with pytest.raises(RepositoryAccessError, match="index flags"):
        inspector.inspect(reference())


def test_sparse_checkout_configuration_is_rejected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    run_git(repository, "config", "core.sparseCheckout", "true")
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )

    with pytest.raises(RepositoryAccessError, match="unsupported"):
        inspector.inspect(reference())


def test_git_status_output_limit_marks_inspection_incomplete(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    for index in range(20):
        (repository / f"untracked-file-{index}.txt").write_text("x", encoding="utf-8")
    report = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
        limits=InspectionLimits(max_git_output_bytes=64),
    ).inspect(reference())

    assert report.git.status_truncated is True
    assert report.git.metadata_complete is False
    assert report.complete is False
    assert "git_status_output" in report.limits_reached


def test_external_git_pointer_is_blocked(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    repository = workspace / "repository"
    repository.mkdir(parents=True)
    external_git = tmp_path / "external.git"
    external_git.mkdir()
    (repository / ".git").write_text(f"gitdir: {external_git}\n", encoding="utf-8")
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )

    with pytest.raises(RepositoryAccessError, match="Git pointer escapes"):
        inspector.inspect(reference())


def test_non_git_worktree_can_be_inspected_without_false_git_claim(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    repository = workspace / "repository"
    repository.mkdir(parents=True)
    (repository / "app.py").write_text("print('safe')\n", encoding="utf-8")
    report = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    ).inspect(reference())

    assert report.git.is_repository is False
    assert report.git.head_revision is None
    assert report.complete is True


def test_limits_are_reported_truthfully(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    for index in range(5):
        (repository / f"extra-{index}.txt").write_text("content", encoding="utf-8")
    report = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
        limits=InspectionLimits(max_files=2),
    ).inspect(reference())

    assert "file_count" in report.limits_reached
    assert report.file_count == 2


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="platform lacks O_NOFOLLOW")
def test_repository_symlink_is_listed_but_never_followed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    target = tmp_path / "private.txt"
    target.write_text("outside", encoding="utf-8")
    (repository / "outside-link").symlink_to(target)
    report = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    ).inspect(reference())

    assert any(
        item.path == "outside-link" and item.detail == "escapes repository"
        for item in report.symlinks
    )
