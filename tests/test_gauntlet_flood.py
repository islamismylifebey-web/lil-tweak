from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from liltweak.agent import DeterministicPlanner
from liltweak.artifacts import EncryptedArtifactStore
from liltweak.costs import CostGuard
from liltweak.models import (
    ApprovalDecisionRequest,
    JobStatus,
    RecoveryCreateRequest,
    RecoveryStatus,
    RepositoryRef,
    TaskCreate,
)
from liltweak.recovery import (
    RecoveryBlockedError,
    RecoveryCapture,
    RecoveryLimits,
    RecoveryUnavailableError,
)
from liltweak.repository import (
    InspectionLimits,
    RepositoryAccessError,
    RepositoryInspector,
)
from liltweak.service import LilTweakService
from liltweak.store import SQLiteStore
from tests.repository_helpers import (
    initialize_repository,
    repository_oracle,
    run_git,
)

OWNER_ID = "owner"
BENIGN_FILE_COUNT = 65


def _task(head: str, task_id: str) -> TaskCreate:
    return TaskCreate(
        task_id=task_id,
        requested_by=OWNER_ID,
        organization_id="org-gauntlet",
        project_id="tweak-flood",
        repository=RepositoryRef(
            provider="local",
            repository_id="fixture",
            revision=head,
        ),
        objective="Prepare a bounded recovery package without changing the registered source.",
        execution_permission=False,
    )


def _build_service(
    workspace: Path,
    artifact_root: Path,
    *,
    inspection_limits: InspectionLimits | None = None,
    recovery_limits: RecoveryLimits | None = None,
) -> LilTweakService:
    store = SQLiteStore(":memory:")
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
        limits=inspection_limits,
    )
    artifact_store = EncryptedArtifactStore(
        root=artifact_root,
        workspace_root=workspace,
        master_key=b"G" * 32,
        store=store,
    )
    return LilTweakService(
        store=store,
        planner=DeterministicPlanner(),
        cost_guard=CostGuard(monthly_limit_usd=250, job_default_limit_usd=5),
        repository_inspector=inspector,
        recovery_capture=RecoveryCapture(
            inspector=inspector,
            artifact_store=artifact_store,
            limits=recovery_limits,
        ),
        owner_id=OWNER_ID,
    )


async def _analyze(
    service: LilTweakService,
    head: str,
    key: str,
):
    job = service.create_job(_task(head, key), key)
    job = await service.analyze_job(job.id)
    assert job.inspection is not None
    return job


def _approve_recovery(
    service: LilTweakService,
    job_id: str,
    fingerprint: str,
    key: str,
) -> None:
    package = service.create_recovery_request(
        job_id,
        RecoveryCreateRequest(expected_repository_fingerprint=fingerprint),
        key,
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


def _write_untracked_flood(
    repository: Path,
    directory: str,
    *,
    marker: bytes = b"benign flood payload\n",
) -> Path:
    root = repository / directory
    root.mkdir(parents=True)
    for index in range(BENIGN_FILE_COUNT):
        (root / f"{index:04d}-benign.txt").write_bytes(marker + str(index).encode() + b"\n")
    return root


def _commit_tracked_flood(
    repository: Path,
    *,
    tail_path: str,
    tail_content: bytes,
) -> tuple[str, Path]:
    flood = repository / "bulk"
    flood.mkdir()
    for index in range(BENIGN_FILE_COUNT):
        (flood / f"{index:04d}-benign.txt").write_text(
            f"benign tracked fixture {index}\n",
            encoding="utf-8",
        )
    tail = repository / tail_path
    tail.parent.mkdir(parents=True, exist_ok=True)
    tail.write_bytes(tail_content)
    run_git(repository, "add", "-f", ".")
    run_git(repository, "commit", "-q", "-m", "Add late-path gauntlet fixtures")
    return run_git(repository, "rev-parse", "HEAD"), tail


def _assert_no_plaintext_publication(
    artifact_root: Path,
    *plaintext_markers: bytes,
) -> None:
    for path in artifact_root.iterdir():
        assert path.is_file()
        ciphertext = path.read_bytes()
        for marker in plaintext_markers:
            assert marker not in ciphertext


@pytest.mark.asyncio
async def test_credential_in_lexicographically_last_file_survives_65_file_flood(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    flood = _write_untracked_flood(repository, "flood")
    synthetic_credential = ("sk-proj-" + ("Z" * 32)).encode()
    tail = flood / "zzzz-tail-secret.txt"
    tail.write_bytes(b"API_TOKEN=" + synthetic_credential + b"\n")
    source_before = repository_oracle(repository)
    artifact_root = tmp_path / "artifacts"
    service = _build_service(workspace, artifact_root)

    job = await _analyze(service, head, "gauntlet-tail-secret-job-0001")

    assert job.inspection.complete
    assert any(
        finding.path == "flood/zzzz-tail-secret.txt" and finding.rule_id == "openai-api-key"
        for finding in job.inspection.secret_findings
    )
    _approve_recovery(
        service,
        job.id,
        job.inspection.repository_fingerprint,
        "gauntlet-tail-secret-recovery-0001",
    )
    with pytest.raises(RecoveryBlockedError) as blocked:
        service.prepare_recovery(job.id, OWNER_ID)

    assert blocked.value.code == "credential_material_detected"
    assert service.get_recovery(job.id).status == RecoveryStatus.BLOCKED
    assert list(artifact_root.iterdir()) == []
    _assert_no_plaintext_publication(artifact_root, synthetic_credential)
    assert repository_oracle(repository) == source_before


@pytest.mark.asyncio
async def test_ignored_tail_secret_is_not_hidden_by_ignored_file_flood(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    (repository / ".gitignore").write_text("ignored/\n", encoding="utf-8")
    run_git(repository, "add", ".gitignore")
    run_git(repository, "commit", "-q", "-m", "Ignore the gauntlet flood")
    head = run_git(repository, "rev-parse", "HEAD")
    flood = _write_untracked_flood(repository, "ignored")
    synthetic_credential = ("ghp_" + ("Y" * 32)).encode()
    tail = flood / "zzzz-ignored-tail.txt"
    tail.write_bytes(b"token=" + synthetic_credential + b"\n")
    source_before = repository_oracle(repository)
    artifact_root = tmp_path / "artifacts"
    service = _build_service(workspace, artifact_root)

    job = await _analyze(service, head, "gauntlet-ignored-tail-job-0001")

    assert job.inspection.complete
    assert job.inspection.git.ignored_paths
    assert "ignored/zzzz-ignored-tail.txt" in job.inspection.git.untracked_paths
    assert any(
        finding.path == "ignored/zzzz-ignored-tail.txt" and finding.rule_id == "github-token"
        for finding in job.inspection.secret_findings
    )
    _approve_recovery(
        service,
        job.id,
        job.inspection.repository_fingerprint,
        "gauntlet-ignored-tail-recovery-0001",
    )
    with pytest.raises(RecoveryBlockedError) as blocked:
        service.prepare_recovery(job.id, OWNER_ID)

    assert blocked.value.code == "credential_material_detected"
    assert service.get_recovery(job.id).status == RecoveryStatus.BLOCKED
    assert list(artifact_root.iterdir()) == []
    _assert_no_plaintext_publication(artifact_root, synthetic_credential)
    assert repository_oracle(repository) == source_before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("inspection_limits", "expected_limit"),
    [
        (InspectionLimits(max_files=32), "file_count"),
        (InspectionLimits(max_git_output_bytes=128), "git_status_output"),
    ],
    ids=["file-count-limit", "git-output-truncation"],
)
async def test_inspection_limits_and_truncation_fail_closed_before_recovery(
    tmp_path: Path,
    inspection_limits: InspectionLimits,
    expected_limit: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    flood = _write_untracked_flood(repository, "flood")
    skipped_tail = ("sk-proj-" + ("L" * 32)).encode()
    (flood / "zzzz-beyond-bound.txt").write_bytes(skipped_tail)
    source_before = repository_oracle(repository)
    artifact_root = tmp_path / "artifacts"
    service = _build_service(
        workspace,
        artifact_root,
        inspection_limits=inspection_limits,
    )

    job = await _analyze(service, head, f"gauntlet-{expected_limit}-job-0001")

    assert not job.inspection.complete
    assert expected_limit in job.inspection.limits_reached
    with pytest.raises(RecoveryBlockedError) as blocked:
        service.create_recovery_request(
            job.id,
            RecoveryCreateRequest(
                expected_repository_fingerprint=job.inspection.repository_fingerprint,
            ),
            f"gauntlet-{expected_limit}-recovery-0001",
            OWNER_ID,
        )

    assert blocked.value.code == "inspection_incomplete"
    assert list(artifact_root.iterdir()) == []
    _assert_no_plaintext_publication(artifact_root, skipped_tail)
    assert repository_oracle(repository) == source_before


@pytest.mark.asyncio
async def test_recovery_file_count_limit_fails_closed_at_65th_file(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    marker = b"GAUNTLET-COUNT-LIMIT-PLAINTEXT"
    _write_untracked_flood(repository, "flood", marker=marker)
    source_before = repository_oracle(repository)
    artifact_root = tmp_path / "artifacts"
    service = _build_service(
        workspace,
        artifact_root,
        recovery_limits=RecoveryLimits(max_untracked_files=64),
    )
    job = await _analyze(service, head, "gauntlet-recovery-limit-job-0001")
    assert job.inspection.complete
    _approve_recovery(
        service,
        job.id,
        job.inspection.repository_fingerprint,
        "gauntlet-recovery-limit-request-0001",
    )

    with pytest.raises(RecoveryBlockedError) as blocked:
        service.prepare_recovery(job.id, OWNER_ID)

    assert blocked.value.code == "untracked_file_limit"
    assert service.get_recovery(job.id).status == RecoveryStatus.BLOCKED
    assert list(artifact_root.iterdir()) == []
    _assert_no_plaintext_publication(artifact_root, marker)
    assert repository_oracle(repository) == source_before


@pytest.mark.asyncio
async def test_repeated_recovery_preparation_has_one_bounded_artifact_set(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    marker = b"GAUNTLET-RECOVERY-PLAINTEXT-MUST-STAY-ENCRYPTED"
    _write_untracked_flood(repository, "flood", marker=marker)
    source_before = repository_oracle(repository)
    artifact_root = tmp_path / "artifacts"
    service = _build_service(workspace, artifact_root)
    job = await _analyze(service, head, "gauntlet-repeat-job-0001")
    _approve_recovery(
        service,
        job.id,
        job.inspection.repository_fingerprint,
        "gauntlet-repeat-recovery-0001",
    )

    def prepare() -> str:
        try:
            package = service.prepare_recovery(job.id, OWNER_ID)
        except RecoveryUnavailableError:
            return "rejected"
        return package.status.value

    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(lambda _index: prepare(), range(8)))

    assert outcomes.count(RecoveryStatus.READY.value) == 1
    assert outcomes.count("rejected") == 7
    package = service.get_recovery(job.id)
    assert package.status == RecoveryStatus.READY
    assert len(package.artifacts) == len(package.planned_artifacts) + 1
    assert len(package.artifacts) == 2
    assert len(list(artifact_root.glob("*.lta"))) == 2
    assert not list(artifact_root.glob("*.tmp"))
    _assert_no_plaintext_publication(artifact_root, marker)
    assert repository_oracle(repository) == source_before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tail_path", "initial", "changed", "expected_code"),
    [
        (
            "zzzz/zzzz-late.py",
            b"print('safe text')\n",
            b"\x00\xfflate binary payload\n",
            "binary_change_not_supported",
        ),
        (
            "zzzz/.env.local",
            b"SAFE_SETTING=initial\n",
            b"SAFE_SETTING=changed\n",
            "sensitive_path",
        ),
    ],
    ids=["late-binary", "late-sensitive-path"],
)
async def test_late_tracked_payloads_block_after_65_benign_files(
    tmp_path: Path,
    tail_path: str,
    initial: bytes,
    changed: bytes,
    expected_code: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    head, tail = _commit_tracked_flood(
        repository,
        tail_path=tail_path,
        tail_content=initial,
    )
    tail.write_bytes(changed)
    source_before = repository_oracle(repository)
    artifact_root = tmp_path / "artifacts"
    service = _build_service(workspace, artifact_root)
    job = await _analyze(service, head, f"gauntlet-{expected_code}-job-0001")
    assert job.inspection.complete
    _approve_recovery(
        service,
        job.id,
        job.inspection.repository_fingerprint,
        f"gauntlet-{expected_code}-recovery-0001",
    )

    with pytest.raises(RecoveryBlockedError) as blocked:
        service.prepare_recovery(job.id, OWNER_ID)

    assert blocked.value.code == expected_code
    assert service.get_recovery(job.id).status == RecoveryStatus.BLOCKED
    assert list(artifact_root.iterdir()) == []
    _assert_no_plaintext_publication(artifact_root, changed)
    assert repository_oracle(repository) == source_before


@pytest.mark.asyncio
async def test_late_casefold_collision_blocks_full_inventory_without_publication(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    head, _tail = _commit_tracked_flood(
        repository,
        tail_path="zzzz/zzzz-Case-Tail.txt",
        tail_content=b"tracked collision fixture\n",
    )
    collision_marker = b"GAUNTLET-LATE-COLLISION-PLAINTEXT"
    (repository / "zzzz" / "zzzz-case-tail.TXT").write_bytes(collision_marker)
    source_before = repository_oracle(repository)
    artifact_root = tmp_path / "artifacts"
    service = _build_service(workspace, artifact_root)
    job = service.create_job(
        _task(head, "gauntlet-late-collision-job-0001"),
        "gauntlet-late-collision-job-0001",
    )

    with pytest.raises(RepositoryAccessError, match="case-fold path collision"):
        await service.analyze_job(job.id)

    assert service.get_job(job.id).status == JobStatus.BLOCKED
    assert list(artifact_root.iterdir()) == []
    _assert_no_plaintext_publication(artifact_root, collision_marker)
    assert repository_oracle(repository) == source_before
