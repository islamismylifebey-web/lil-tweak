from __future__ import annotations

import io
import os
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

from liltweak.agent import DeterministicPlanner
from liltweak.approvals import ApprovalError
from liltweak.artifacts import (
    ArtifactConfigurationError,
    EncryptedArtifactStore,
)
from liltweak.costs import CostGuard
from liltweak.models import (
    ApprovalDecisionRequest,
    ApprovalStatus,
    ArtifactKind,
    ChangePreparationStatus,
    RecoveryCreateRequest,
    RecoveryStatus,
    RepositoryRef,
    TaskCreate,
)
from liltweak.recovery import RecoveryBlockedError, RecoveryCapture
from liltweak.repository import RepositoryInspector
from liltweak.service import LilTweakService, RecoveryUnavailableError
from liltweak.store import SQLiteStore
from tests.repository_helpers import (
    initialize_repository,
    repository_oracle,
    run_git,
)

OWNER_ID = "owner"


def _repository_task(head: str) -> TaskCreate:
    return TaskCreate(
        task_id="phase-3-recovery",
        requested_by=OWNER_ID,
        organization_id="org-1",
        project_id="project-1",
        repository=RepositoryRef(
            provider="local",
            repository_id="fixture",
            revision=head,
        ),
        objective="Prepare a safe, reviewable change without touching the source.",
        execution_permission=False,
    )


def _build_recovery_service(
    workspace: Path,
    artifact_root: Path,
) -> tuple[LilTweakService, EncryptedArtifactStore]:
    store = SQLiteStore(":memory:")
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )
    artifact_store = EncryptedArtifactStore(
        root=artifact_root,
        workspace_root=workspace,
        master_key=b"R" * 32,
        store=store,
    )
    service = LilTweakService(
        store=store,
        planner=DeterministicPlanner(),
        cost_guard=CostGuard(monthly_limit_usd=250, job_default_limit_usd=5),
        repository_inspector=inspector,
        recovery_capture=RecoveryCapture(
            inspector=inspector,
            artifact_store=artifact_store,
        ),
        owner_id=OWNER_ID,
    )
    return service, artifact_store


def _make_dirty_repository(repository: Path) -> None:
    (repository / "src" / "app.py").write_text(
        'from fastapi import FastAPI\n\napp = FastAPI(title="Staged")\n',
        encoding="utf-8",
    )
    run_git(repository, "add", "src/app.py")
    (repository / "src" / "app.py").write_text(
        'from fastapi import FastAPI\n\napp = FastAPI(title="Recovered")\n',
        encoding="utf-8",
    )
    (repository / "tests" / "test_app.py").write_text(
        "def test_recovered_behavior():\n    assert 2 + 2 == 4\n",
        encoding="utf-8",
    )
    (repository / "notes").mkdir()
    (repository / "notes" / "design.txt").write_text(
        "recovery artifact fixture\n",
        encoding="utf-8",
    )


async def _analyze_dirty_job(
    service: LilTweakService,
    head: str,
    idempotency_key: str,
):
    job = service.create_job(_repository_task(head), idempotency_key)
    analyzed = await service.analyze_job(job.id)
    assert analyzed.inspection is not None
    assert analyzed.plan is not None
    assert analyzed.inspection.recovery.dirty_worktree is True
    return analyzed


def _request_and_approve_recovery(
    service: LilTweakService,
    job_id: str,
    fingerprint: str,
    idempotency_key: str,
):
    package = service.create_recovery_request(
        job_id,
        RecoveryCreateRequest(
            expected_repository_fingerprint=fingerprint,
        ),
        idempotency_key,
        OWNER_ID,
    )
    approval = service.approvals.get(package.approval_id)
    service.decide_approval(
        approval.id,
        ApprovalDecisionRequest(
            decision="approve",
            action_digest=approval.action_digest,
        ),
        OWNER_ID,
    )
    return package


def _git_apply(repository: Path, patch: bytes, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(repository), "apply", *arguments, "-"],
        input=patch,
        check=True,
        capture_output=True,
    )


def _read_only_status(repository: Path) -> str:
    return subprocess.run(
        [
            "git",
            "--no-optional-locks",
            "-C",
            str(repository),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _restore_untracked_archive(repository: Path, archive_bytes: bytes) -> None:
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        for member in archive.getmembers():
            assert member.isfile()
            assert not member.issym()
            assert not member.islnk()
            destination = repository / member.name
            assert destination.resolve().is_relative_to(repository.resolve())
            destination.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            assert stream is not None
            destination.write_bytes(stream.read())
            destination.chmod(member.mode & 0o777)


@pytest.mark.asyncio
async def test_encrypted_recovery_restores_in_disposable_clone_without_source_writes(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    _make_dirty_repository(repository)
    artifact_root = tmp_path / "encrypted-artifacts"
    service, artifact_store = _build_recovery_service(workspace, artifact_root)
    source_before = repository_oracle(repository)

    job = await _analyze_dirty_job(
        service,
        head,
        "phase-3-recovery-job-0001",
    )
    assert job.inspection is not None
    requested = _request_and_approve_recovery(
        service,
        job.id,
        job.inspection.repository_fingerprint,
        "phase-3-recovery-request-0001",
    )
    approval = service.approvals.get(requested.approval_id)
    assert requested.source_snapshot_digest == job.inspection.git.recovery_snapshot_digest
    assert approval.proposal.source_snapshot_digest == requested.source_snapshot_digest
    assert requested.capture_scope == "tracked_and_all_non_index_files"
    package = service.prepare_recovery(job.id, OWNER_ID)

    assert package.status == RecoveryStatus.READY
    assert package.after_fingerprint == package.source_fingerprint
    assert repository_oracle(repository) == source_before
    assert {artifact.kind for artifact in package.artifacts} == {
        ArtifactKind.STAGED_PATCH,
        ArtifactKind.UNSTAGED_PATCH,
        ArtifactKind.UNTRACKED_ARCHIVE,
        ArtifactKind.RECOVERY_MANIFEST,
    }
    assert package.manifest_digest

    plaintext = {
        artifact.kind: artifact_store.verify_and_decrypt(artifact) for artifact in package.artifacts
    }
    for artifact in package.artifacts:
        storage_key, _nonce = service.store.get_artifact_storage(artifact.id)
        stored = artifact_root / storage_key
        assert stored.parent == artifact_root.resolve()
        assert stat.S_IMODE(stored.stat().st_mode) == 0o600
        assert stored.read_bytes() != plaintext[artifact.kind]
        assert b"recovery artifact fixture" not in stored.read_bytes()

    restored = tmp_path / "disposable-restore"
    subprocess.run(
        ["git", "clone", "--quiet", "--no-hardlinks", str(repository), str(restored)],
        check=True,
        capture_output=True,
    )
    _git_apply(
        restored,
        plaintext[ArtifactKind.STAGED_PATCH],
        "--index",
        "--binary",
    )
    _git_apply(
        restored,
        plaintext[ArtifactKind.UNSTAGED_PATCH],
        "--binary",
    )
    _restore_untracked_archive(
        restored,
        plaintext[ArtifactKind.UNTRACKED_ARCHIVE],
    )

    assert (restored / "src" / "app.py").read_bytes() == (
        repository / "src" / "app.py"
    ).read_bytes()
    assert (restored / "tests" / "test_app.py").read_bytes() == (
        repository / "tests" / "test_app.py"
    ).read_bytes()
    assert (restored / "notes" / "design.txt").read_bytes() == (
        repository / "notes" / "design.txt"
    ).read_bytes()
    assert _read_only_status(restored) == _read_only_status(repository)
    assert repository_oracle(repository) == source_before


@pytest.mark.asyncio
async def test_recovery_blocks_detected_credential_material(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    fake_secret = "sk-proj-" + ("S" * 32)
    (repository / "src" / "app.py").write_text(
        f'API_KEY = "{fake_secret}"\n',
        encoding="utf-8",
    )
    service, _artifact_store = _build_recovery_service(
        workspace,
        tmp_path / "encrypted-artifacts",
    )
    source_before = repository_oracle(repository)
    job = await _analyze_dirty_job(
        service,
        head,
        "phase-3-secret-job-0001",
    )
    assert job.inspection is not None
    _request_and_approve_recovery(
        service,
        job.id,
        job.inspection.repository_fingerprint,
        "phase-3-secret-request-0001",
    )

    with pytest.raises(RecoveryBlockedError) as blocked:
        service.prepare_recovery(job.id, OWNER_ID)

    assert blocked.value.code == "credential_material_detected"
    saved = service.get_recovery(job.id)
    assert saved.status == RecoveryStatus.BLOCKED
    assert saved.artifacts == []
    assert saved.blocker_codes == ["credential_material_detected"]
    assert list((tmp_path / "encrypted-artifacts").iterdir()) == []
    assert repository_oracle(repository) == source_before


@pytest.mark.asyncio
async def test_recovery_rejects_stale_approved_fingerprint(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    _make_dirty_repository(repository)
    service, _artifact_store = _build_recovery_service(
        workspace,
        tmp_path / "encrypted-artifacts",
    )
    job = await _analyze_dirty_job(
        service,
        head,
        "phase-3-stale-job-0001",
    )
    assert job.inspection is not None
    package = _request_and_approve_recovery(
        service,
        job.id,
        job.inspection.repository_fingerprint,
        "phase-3-stale-request-0001",
    )
    (repository / "notes" / "after-approval.txt").write_text(
        "this was not approved\n",
        encoding="utf-8",
    )

    with pytest.raises(RecoveryBlockedError) as blocked:
        service.prepare_recovery(job.id, OWNER_ID)

    assert blocked.value.code == "stale_source_fingerprint"
    saved = service.get_recovery(job.id)
    assert saved.id == package.id
    assert saved.status == RecoveryStatus.BLOCKED
    assert saved.artifacts == []
    assert saved.blocker_codes == ["stale_source_fingerprint"]


@pytest.mark.asyncio
async def test_recovery_rejects_same_size_post_approval_change_with_restored_mtime(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    _make_dirty_repository(repository)
    service, _artifact_store = _build_recovery_service(
        workspace,
        tmp_path / "encrypted-artifacts",
    )
    job = await _analyze_dirty_job(
        service,
        head,
        "phase-3-byte-stale-job-0001",
    )
    assert job.inspection is not None
    _request_and_approve_recovery(
        service,
        job.id,
        job.inspection.repository_fingerprint,
        "phase-3-byte-stale-request-0001",
    )
    target = repository / "src" / "app.py"
    metadata = target.stat()
    original = target.read_bytes()
    changed = original.replace(b"Recovered", b"ReXovered")
    assert len(changed) == len(original)
    target.write_bytes(changed)
    os.utime(target, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))

    with pytest.raises(RecoveryBlockedError) as blocked:
        service.prepare_recovery(job.id, OWNER_ID)

    assert blocked.value.code == "stale_source_fingerprint"
    assert service.get_recovery(job.id).status == RecoveryStatus.BLOCKED


@pytest.mark.asyncio
async def test_recovery_approval_is_consumed_exactly_once(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    (repository / "notes.txt").write_text("recover me\n", encoding="utf-8")
    service, _artifact_store = _build_recovery_service(
        workspace,
        tmp_path / "encrypted-artifacts",
    )
    job = await _analyze_dirty_job(
        service,
        head,
        "phase-3-one-use-job-0001",
    )
    assert job.inspection is not None
    package = _request_and_approve_recovery(
        service,
        job.id,
        job.inspection.repository_fingerprint,
        "phase-3-one-use-request-0001",
    )

    service.prepare_recovery(job.id, OWNER_ID)

    consumed = service.approvals.get(package.approval_id)
    assert consumed.status == ApprovalStatus.CONSUMED
    assert consumed.consumed_by == OWNER_ID
    assert consumed.consumed_at is not None
    with pytest.raises(ApprovalError):
        service.approvals.consume(
            package.approval_id,
            expected_digest=package.action_digest,
            expected_purpose="recovery_capture_v1",
            authenticated_identity=OWNER_ID,
        )


def test_artifact_root_must_be_disjoint_from_repository_workspace(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = SQLiteStore(":memory:")

    with pytest.raises(ArtifactConfigurationError):
        EncryptedArtifactStore(
            root=workspace / "artifacts",
            workspace_root=workspace,
            master_key=b"R" * 32,
            store=store,
        )
    assert not (workspace / "artifacts").exists()

    parent_root = tmp_path / "artifact-parent"
    parent_root.mkdir(mode=0o700)
    nested_workspace = parent_root / "repositories"
    nested_workspace.mkdir()
    with pytest.raises(ArtifactConfigurationError):
        EncryptedArtifactStore(
            root=parent_root,
            workspace_root=nested_workspace,
            master_key=b"R" * 32,
            store=store,
        )


@pytest.mark.asyncio
async def test_change_preparation_requires_recovery_and_never_writes_source(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    _make_dirty_repository(repository)
    service, _artifact_store = _build_recovery_service(
        workspace,
        tmp_path / "encrypted-artifacts",
    )
    source_before = repository_oracle(repository)
    job = await _analyze_dirty_job(
        service,
        head,
        "phase-3-change-job-0001",
    )
    assert job.inspection is not None

    with pytest.raises(RecoveryUnavailableError):
        service.prepare_change(job.id, OWNER_ID)
    assert repository_oracle(repository) == source_before

    _request_and_approve_recovery(
        service,
        job.id,
        job.inspection.repository_fingerprint,
        "phase-3-change-request-0001",
    )
    service.prepare_recovery(job.id, OWNER_ID)
    preparation = service.prepare_change(job.id, OWNER_ID)

    assert preparation.status == ChangePreparationStatus.READY_FOR_REVIEW
    assert preparation.source_fingerprint == job.inspection.repository_fingerprint
    assert preparation.recovery_package_id is not None
    assert preparation.source_writes_performed is False
    assert preparation.execution_ready is False
    assert preparation.rollback_plan
    assert repository_oracle(repository) == source_before
