from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from liltweak.providers.self_hosted.qualification_manifest import (
    JOB_B_ARTIFACT_CONTENT,
    JOB_B_ARTIFACT_CONTENT_SHA256,
    JOB_B_ARTIFACT_PATH,
)


def _load_operator() -> ModuleType:
    path = Path(__file__).parents[1] / "scripts" / "private_runner_operator.py"
    spec = importlib.util.spec_from_file_location("private_runner_operator", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


OPERATOR = _load_operator()


def _git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-c", f"safe.directory={repo}", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip()


def test_single_accepts_the_run_suffixed_attestation_artifact(tmp_path: Path) -> None:
    artifact = (
        tmp_path / "phase71-attestation" / ("liltweak-qualification-attestation-33582317655-1.json")
    )
    artifact.parent.mkdir()
    artifact.write_text("{}\n", encoding="utf-8")

    assert (
        OPERATOR._single(
            tmp_path,
            "liltweak-qualification-attestation*.json",
        )
        == artifact
    )


def _candidate_artifacts(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, object]]:
    repo = tmp_path / "source"
    repo.mkdir()
    _git(repo, "init", "--initial-branch=main")
    _git(repo, "config", "user.name", "Qualification Test")
    _git(repo, "config", "user.email", "qualification@example.invalid")
    (repo / "README.md").write_text("source\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "source")
    source_commit = _git(repo, "rev-parse", "HEAD")
    source_tree = _git(repo, "rev-parse", "HEAD^{tree}")

    branch = "qualification/galor-tweak-runner-01/test-proof"
    _git(repo, "switch", "-c", branch)
    artifact = repo / JOB_B_ARTIFACT_PATH
    artifact.parent.mkdir(parents=True)
    artifact.write_text(JOB_B_ARTIFACT_CONTENT, encoding="utf-8", newline="\n")
    _git(repo, "add", JOB_B_ARTIFACT_PATH)
    _git(repo, "commit", "-m", "Add bounded qualification receipt")
    candidate_sha = _git(repo, "rev-parse", "HEAD")
    candidate_tree = _git(repo, "rev-parse", "HEAD^{tree}")

    bundle = tmp_path / "candidate.bundle"
    _git(repo, "bundle", "create", str(bundle), branch, f"^{source_commit}")
    bundle_bytes = bundle.read_bytes()
    receipt: dict[str, object] = {
        "runner_id": "galor-tweak-runner-01",
        "runtime_image": (
            "python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
        ),
        "seccomp_sha256": ("50eeb8b4cb2c33284f09453c8dd64c5895f5e1a2fa6b7a7440dfbac175fe1c23"),
        "apparmor_profile": "liltweak-runner-job",
        "network_denied": True,
        "package_install_allowed": False,
        "production_access_allowed": False,
        "deploy_allowed": False,
        "workspace_cleaned": True,
        "cgroup_cleaned": True,
        "artifact_path": JOB_B_ARTIFACT_PATH,
        "artifact_sha256": JOB_B_ARTIFACT_CONTENT_SHA256,
        "candidate_sha": candidate_sha,
        "candidate_tree": candidate_tree,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "source_mutated": True,
        "bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
        "bundle_size": len(bundle_bytes),
        "candidate_store_id": "execution-test",
        "created_at_ms": 1_000,
        "qualification_branch": branch,
    }
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    _git(repo, "switch", "main")
    return repo, receipt_path, bundle, receipt


def test_candidate_artifacts_are_bound_to_signed_receipt_and_exact_git_diff(
    tmp_path: Path,
) -> None:
    repo, receipt_path, bundle, receipt = _candidate_artifacts(tmp_path)

    verified = OPERATOR._verify_candidate_artifacts(
        repo=repo,
        receipt_path=receipt_path,
        bundle_path=bundle,
        execution_id="execution-test",
        signed_receipt=receipt,
    )

    assert verified["candidate_sha"] == receipt["candidate_sha"]
    assert verified["candidate_tree"] == receipt["candidate_tree"]
    assert verified["bundle_sha256"] == receipt["bundle_sha256"]
    assert _git(repo, "status", "--porcelain=v1", "--untracked-files=all") == ""


def test_candidate_artifacts_reject_receipt_not_equal_to_signed_evidence(
    tmp_path: Path,
) -> None:
    repo, receipt_path, bundle, receipt = _candidate_artifacts(tmp_path)
    observed = json.loads(receipt_path.read_text(encoding="utf-8"))
    observed["candidate_tree"] = "0" * 40
    receipt_path.write_text(json.dumps(observed), encoding="utf-8")

    with pytest.raises(RuntimeError, match="signed runner evidence"):
        OPERATOR._verify_candidate_artifacts(
            repo=repo,
            receipt_path=receipt_path,
            bundle_path=bundle,
            execution_id="execution-test",
            signed_receipt=receipt,
        )


def test_candidate_retrieval_uses_bounded_noninteractive_scp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, receipt_path, bundle_path, _ = _candidate_artifacts(tmp_path)
    ssh_key = tmp_path / "runner.key"
    ssh_key.write_text("not-a-real-key", encoding="utf-8")
    destination = tmp_path / "retrieved"

    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        assert command[:8] == [
            "scp",
            "-q",
            "-i",
            str(ssh_key.resolve()),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
        ]
        assert command[-3:-1] == [
            (
                "root@runner.example.invalid:"
                "/var/lib/liltweak-runner/candidates/execution-test/receipt.json"
            ),
            (
                "root@runner.example.invalid:"
                "/var/lib/liltweak-runner/candidates/execution-test/candidate.bundle"
            ),
        ]
        target = Path(command[-1])
        shutil.copy2(receipt_path, target / "receipt.json")
        shutil.copy2(bundle_path, target / "candidate.bundle")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(OPERATOR.subprocess, "run", fake_run)

    retrieved_receipt, retrieved_bundle = OPERATOR._retrieve_candidate_artifacts(
        ssh_key=ssh_key,
        runner_host="runner.example.invalid",
        execution_id="execution-test",
        destination=destination,
    )

    assert retrieved_receipt == destination / "receipt.json"
    assert retrieved_bundle == destination / "candidate.bundle"
