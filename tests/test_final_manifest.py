from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts import generate_final_manifest


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ("git", *arguments),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_manifest_uses_git_objects_and_verifies_the_committed_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Manifest Test")
    _git(repository, "config", "user.email", "manifest@example.invalid")
    (repository / "alpha.txt").write_text("alpha\n", encoding="utf-8")
    executable = repository / "run.sh"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    _git(repository, "add", "alpha.txt", "run.sh")

    output = repository / "FINAL_FILE_MANIFEST.json"
    monkeypatch.setattr(generate_final_manifest, "ROOT", repository)
    monkeypatch.setattr(generate_final_manifest, "OUTPUT", output)

    generated = generate_final_manifest.generate()
    files = generated["files"]
    assert isinstance(files, list)
    assert [entry["relative_path"] for entry in files] == ["alpha.txt", "run.sh"]
    assert [entry["git_mode"] for entry in files] == ["100644", "100755"]
    assert generated["source_scope"] == generate_final_manifest.SOURCE_SCOPE
    assert generated["self_excluded_from_hash_list"] is True

    output.write_text(json.dumps(generated, indent=2) + "\n", encoding="utf-8")
    _git(repository, "add", "FINAL_FILE_MANIFEST.json")
    _git(repository, "commit", "-q", "-m", "Freeze manifest fixture")

    committed = generate_final_manifest.generate(commit="HEAD")
    existing = generate_final_manifest._existing_manifest(commit="HEAD")
    generate_final_manifest._validate(existing, committed)
    assert committed == generated

    (repository / "alpha.txt").write_text("uncommitted replacement\n", encoding="utf-8")
    output.write_text("{}\n", encoding="utf-8")
    assert generate_final_manifest.generate(commit="HEAD") == committed
    assert generate_final_manifest._existing_manifest(commit="HEAD") == existing
    assert generate_final_manifest._existing_manifest(commit=None) == existing


def test_manifest_validation_fails_closed_on_scope_mismatch() -> None:
    with pytest.raises(RuntimeError, match="manifest_scope_digest"):
        generate_final_manifest._validate(
            {"manifest_scope_digest": "stale"},
            {"manifest_scope_digest": "current"},
        )

    with pytest.raises(RuntimeError, match="unexpected_keys=candidate_commit"):
        generate_final_manifest._validate(
            {"manifest_scope_digest": "current", "candidate_commit": "misleading"},
            {"manifest_scope_digest": "current"},
        )


def test_manifest_decoder_rejects_duplicate_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    manifest = repository / "FINAL_FILE_MANIFEST.json"
    manifest.write_text('{"schema_version":"one","schema_version":"two"}\n', encoding="utf-8")
    _git(repository, "add", manifest.name)
    monkeypatch.setattr(generate_final_manifest, "ROOT", repository)
    monkeypatch.setattr(generate_final_manifest, "OUTPUT", manifest)

    with pytest.raises(RuntimeError, match="duplicate JSON key: schema_version"):
        generate_final_manifest._existing_manifest(commit=None)


def test_manifest_generation_rejects_unmerged_index_and_unsupported_modes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        generate_final_manifest,
        "_git",
        lambda *arguments: b"100644 0123456789012345678901234567890123456789 2\tfile.txt\0",
    )
    with pytest.raises(RuntimeError, match="unmerged Git index"):
        generate_final_manifest._index_entries()

    monkeypatch.setattr(
        generate_final_manifest,
        "_index_entries",
        lambda: [("submodule", "160000", "0123456789012345678901234567890123456789")],
    )
    with pytest.raises(RuntimeError, match="unsupported Git mode"):
        generate_final_manifest.generate()
