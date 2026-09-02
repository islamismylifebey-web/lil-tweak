from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from liltweak.providers.self_hosted.qualification_manifest import (
    JOB_B_ARTIFACT_CONTENT,
    JOB_B_ARTIFACT_PATH,
)
from runner.candidates import CandidateStore, CandidateStoreError


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _candidate(tmp_path: Path) -> tuple[Path, str, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@invalid")
    (repo / "README.md").write_text("source\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "source")
    source = _git(repo, "rev-parse", "HEAD")
    branch = "qualification/galor-tweak-runner-01/probe-001"
    _git(repo, "switch", "-c", branch)
    artifact = repo / JOB_B_ARTIFACT_PATH
    artifact.parent.mkdir(parents=True)
    artifact.write_text(JOB_B_ARTIFACT_CONTENT, encoding="utf-8", newline="\n")
    _git(repo, "add", JOB_B_ARTIFACT_PATH)
    _git(repo, "commit", "-m", "bounded")
    return repo, source, _git(repo, "rev-parse", "HEAD"), branch


def test_candidate_store_persists_only_private_bounded_bundle_and_receipt(
    tmp_path: Path,
) -> None:
    repo, source, candidate, branch = _candidate(tmp_path)
    root = tmp_path / "candidates"
    root.mkdir(mode=0o700)
    store = CandidateStore(root=root, max_bundle_bytes=1_000_000)

    receipt = store.persist(
        execution_id="exec-001",
        workspace=repo,
        source_commit=source,
        candidate_commit=candidate,
        qualification_branch=branch,
        base_receipt={"candidate_sha": candidate},
        now_ms=1_000_000,
    )

    target = root / "exec-001"
    assert set(path.name for path in target.iterdir()) == {"candidate.bundle", "receipt.json"}
    if os.name != "nt":
        assert stat.S_IMODE(target.stat().st_mode) == 0o700
        assert stat.S_IMODE((target / "candidate.bundle").stat().st_mode) == 0o600
        assert stat.S_IMODE((target / "receipt.json").stat().st_mode) == 0o600
    assert receipt["bundle_size"] == (target / "candidate.bundle").stat().st_size
    assert json.loads((target / "receipt.json").read_text(encoding="utf-8")) == receipt
    assert _git(repo, "bundle", "verify", str(target / "candidate.bundle")) is not None

    finalized = store.finalize(
        execution_id="exec-001",
        receipt={**receipt, "workspace_cleaned": True, "cgroup_cleaned": True},
    )
    assert finalized["workspace_cleaned"] is True
    assert json.loads((target / "receipt.json").read_text(encoding="utf-8")) == finalized


def test_candidate_store_refuses_overwrite_and_cleans_only_expired_records(
    tmp_path: Path,
) -> None:
    repo, source, candidate, branch = _candidate(tmp_path)
    root = tmp_path / "candidates"
    root.mkdir(mode=0o700)
    store = CandidateStore(root=root, max_bundle_bytes=1_000_000)
    arguments = {
        "execution_id": "exec-001",
        "workspace": repo,
        "source_commit": source,
        "candidate_commit": candidate,
        "qualification_branch": branch,
        "base_receipt": {"candidate_sha": candidate},
        "now_ms": 1_000_000,
    }
    store.persist(**arguments)
    with pytest.raises(CandidateStoreError, match="already exists"):
        store.persist(**arguments)

    old = root / "old-exec"
    old.mkdir(mode=0o700)
    (old / "receipt.json").write_text("{}\n", encoding="utf-8")
    (old / "candidate.bundle").write_bytes(b"bundle")
    os.utime(old, (1, 1))

    assert store.cleanup_expired(now_seconds=100_000, retention_seconds=3_600) == 1
    assert not old.exists()
    assert (root / "exec-001").exists()
