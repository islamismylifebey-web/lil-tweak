from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from liltweak.providers.self_hosted.qualification_manifest import (
    JOB_B_ARTIFACT_CONTENT,
    JOB_B_ARTIFACT_PATH,
)
from runner.execution import (
    ExecutionSecurityError,
    inspect_job_a_checkout,
    inspect_job_b_candidate,
)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@invalid")
    (repo / "README.md").write_text("source\n", encoding="utf-8", newline="\n")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "source")
    commit = _git(repo, "rev-parse", "HEAD")
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    return repo, commit, tree


def test_job_a_checkout_requires_exact_commit_tree_and_zero_mutation(tmp_path: Path) -> None:
    repo, commit, tree = _repository(tmp_path)

    receipt = inspect_job_a_checkout(
        repo,
        expected_commit=commit,
        expected_tree=tree,
    )

    assert receipt == {
        "candidate_sha": None,
        "source_commit": commit,
        "source_tree": tree,
        "source_mutated": False,
    }
    (repo / "README.md").write_text("mutated\n", encoding="utf-8", newline="\n")
    with pytest.raises(ExecutionSecurityError, match="mutated"):
        inspect_job_a_checkout(repo, expected_commit=commit, expected_tree=tree)


def test_job_b_candidate_must_be_one_exact_docs_commit(tmp_path: Path) -> None:
    repo, source_commit, source_tree = _repository(tmp_path)
    artifact = repo / JOB_B_ARTIFACT_PATH
    artifact.parent.mkdir(parents=True)
    artifact.write_text(JOB_B_ARTIFACT_CONTENT, encoding="utf-8", newline="\n")
    _git(repo, "add", JOB_B_ARTIFACT_PATH)
    _git(repo, "commit", "-m", "bounded")
    candidate = _git(repo, "rev-parse", "HEAD")

    receipt = inspect_job_b_candidate(
        repo,
        expected_source_commit=source_commit,
        expected_source_tree=source_tree,
    )

    assert receipt["candidate_sha"] == candidate
    assert receipt["artifact_path"] == JOB_B_ARTIFACT_PATH
    assert receipt["source_mutated"] is True


def test_job_b_candidate_rejects_any_second_changed_path(tmp_path: Path) -> None:
    repo, source_commit, source_tree = _repository(tmp_path)
    artifact = repo / JOB_B_ARTIFACT_PATH
    artifact.parent.mkdir(parents=True)
    artifact.write_text(JOB_B_ARTIFACT_CONTENT, encoding="utf-8", newline="\n")
    (repo / "extra.txt").write_text("not authorized\n", encoding="utf-8")
    _git(repo, "add", JOB_B_ARTIFACT_PATH, "extra.txt")
    _git(repo, "commit", "-m", "too broad")

    with pytest.raises(ExecutionSecurityError, match="bounded diff"):
        inspect_job_b_candidate(
            repo,
            expected_source_commit=source_commit,
            expected_source_tree=source_tree,
        )
