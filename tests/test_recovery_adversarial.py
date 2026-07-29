from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Event

import pytest
from httpx import ASGITransport, AsyncClient

from liltweak.agent import DeterministicPlanner
from liltweak.api import create_app
from liltweak.approvals import ApprovalError
from liltweak.artifacts import EncryptedArtifactStore
from liltweak.config import Settings
from liltweak.costs import CostGuard
from liltweak.models import (
    ApprovalDecisionRequest,
    ApprovalStatus,
    JobStatus,
    RecoveryCreateRequest,
    RecoveryStatus,
    RepositoryRef,
    TaskCreate,
)
from liltweak.recovery import RecoveryBlockedError, RecoveryCapture
from liltweak.repository import RepositoryAccessError, RepositoryInspector
from liltweak.service import LilTweakService
from liltweak.store import IdempotencyConflictError, SQLiteStore
from tests.repository_helpers import (
    initialize_repository,
    repository_oracle,
    run_git,
)

OWNER_ID = "owner"
AUTH_FIXTURE = "-".join(("phase", "3", "test", "credential"))


def _task(head: str, *, task_id: str = "phase-3-adversarial") -> TaskCreate:
    return TaskCreate(
        task_id=task_id,
        requested_by=OWNER_ID,
        organization_id="org-1",
        project_id="project-1",
        repository=RepositoryRef(
            provider="local",
            repository_id="fixture",
            revision=head,
        ),
        objective="Prepare recovery without changing the registered source.",
        execution_permission=False,
    )


def _task_payload(head: str) -> dict:
    return _task(head).model_dump(mode="json")


def _build_service(
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
        master_key=b"A" * 32,
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


def _build_api(
    workspace: Path,
    artifact_root: Path,
):
    service, artifact_store = _build_service(workspace, artifact_root)
    settings = Settings(
        environment="test",
        database_path=Path(":memory:"),
        dev_api_key=AUTH_FIXTURE,
        auth_disabled=False,
        model="gpt-5.6-luna",
        monthly_budget_usd=250,
        job_hard_limit_usd=5,
        workspace_root=workspace,
        repository_mappings={"local:fixture": "repository"},
        owner_id=OWNER_ID,
        artifact_root=artifact_root,
        artifact_encryption_key=b"A" * 32,
    )
    return create_app(service=service, settings=settings), service, artifact_store


async def _analyze(
    service: LilTweakService,
    head: str,
    key: str,
):
    job = service.create_job(_task(head, task_id=key), key)
    job = await service.analyze_job(job.id)
    assert job.inspection is not None
    return job


def _approve_recovery(
    service: LilTweakService,
    job_id: str,
    fingerprint: str,
    key: str,
):
    package = service.create_recovery_request(
        job_id,
        RecoveryCreateRequest(
            expected_repository_fingerprint=fingerprint,
        ),
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
    return package


@pytest.mark.asyncio
async def test_recovery_api_requires_auth_and_completes_approved_flow(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    (repository / "notes.txt").write_text("preserve this\n", encoding="utf-8")
    artifact_root = tmp_path / "artifacts"
    app, _service, _artifact_store = _build_api(workspace, artifact_root)
    auth = {"Authorization": f"Bearer {AUTH_FIXTURE}"}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        created = await client.post(
            "/v1/jobs",
            headers={**auth, "Idempotency-Key": "adversarial-job-api-0001"},
            json=_task_payload(head),
        )
        assert created.status_code == 202
        job_id = created.json()["id"]
        analyzed = await client.post(f"/v1/jobs/{job_id}/analyze", headers=auth)
        assert analyzed.status_code == 200
        fingerprint = analyzed.json()["inspection"]["repository_fingerprint"]
        body = {"expected_repository_fingerprint": fingerprint}

        unauthenticated_create = await client.post(
            f"/v1/jobs/{job_id}/recovery",
            headers={"Idempotency-Key": "adversarial-recovery-api-0001"},
            json=body,
        )
        assert unauthenticated_create.status_code == 401
        unauthenticated_prepare = await client.post(f"/v1/jobs/{job_id}/recovery/prepare")
        assert unauthenticated_prepare.status_code == 401

        requested = await client.post(
            f"/v1/jobs/{job_id}/recovery",
            headers={
                **auth,
                "Idempotency-Key": "adversarial-recovery-api-0001",
            },
            json=body,
        )
        assert requested.status_code == 202
        package = requested.json()
        assert package["status"] == RecoveryStatus.AWAITING_APPROVAL.value

        approval_response = await client.get(
            f"/v1/approvals/{package['approval_id']}",
            headers=auth,
        )
        assert approval_response.status_code == 200
        approval = approval_response.json()
        approved = await client.post(
            f"/v1/approvals/{approval['id']}/decision",
            headers=auth,
            json={
                "decision": "approve",
                "action_digest": approval["action_digest"],
            },
        )
        assert approved.status_code == 200
        assert approved.json()["recovery_package"]["status"] == "approved"

        prepared = await client.post(
            f"/v1/jobs/{job_id}/recovery/prepare",
            headers=auth,
        )
        assert prepared.status_code == 200
        result = prepared.json()
        assert result["status"] == RecoveryStatus.READY.value
        assert result["after_fingerprint"] == fingerprint
        assert len(result["artifacts"]) >= 2
        assert "storage_key" not in prepared.text
        assert "nonce" not in prepared.text
        assert prepared.headers["Cache-Control"] == "no-store"
        assert prepared.headers["X-Content-Type-Options"] == "nosniff"

        consumed = await client.get(
            f"/v1/approvals/{package['approval_id']}",
            headers=auth,
        )
        assert consumed.json()["status"] == ApprovalStatus.CONSUMED.value


@pytest.mark.asyncio
async def test_binary_tracked_change_is_blocked_without_artifacts(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    (repository / "src" / "app.py").write_bytes(b"\x00\x01binary-replacement\xff")
    source_before = repository_oracle(repository)
    artifact_root = tmp_path / "artifacts"
    service, _artifact_store = _build_service(workspace, artifact_root)
    job = await _analyze(service, head, "adversarial-binary-job-0001")
    assert job.inspection is not None
    _approve_recovery(
        service,
        job.id,
        job.inspection.repository_fingerprint,
        "adversarial-binary-recovery-0001",
    )

    with pytest.raises(RecoveryBlockedError) as blocked:
        service.prepare_recovery(job.id, OWNER_ID)

    assert blocked.value.code == "binary_change_not_supported"
    assert service.get_recovery(job.id).status == RecoveryStatus.BLOCKED
    assert list(artifact_root.iterdir()) == []
    assert repository_oracle(repository) == source_before


@pytest.mark.asyncio
async def test_sensitive_untracked_env_file_is_blocked_without_artifacts(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    (repository / ".env").write_text(
        "PRIVATE_SETTING=fixture-only-value\n",
        encoding="utf-8",
    )
    source_before = repository_oracle(repository)
    artifact_root = tmp_path / "artifacts"
    service, _artifact_store = _build_service(workspace, artifact_root)
    job = await _analyze(service, head, "adversarial-env-job-0001")
    assert job.inspection is not None
    assert any(item.rule_id == "sensitive-filename" for item in job.inspection.secret_findings)
    _approve_recovery(
        service,
        job.id,
        job.inspection.repository_fingerprint,
        "adversarial-env-recovery-0001",
    )

    with pytest.raises(RecoveryBlockedError) as blocked:
        service.prepare_recovery(job.id, OWNER_ID)

    assert blocked.value.code == "sensitive_path"
    assert service.get_recovery(job.id).status == RecoveryStatus.BLOCKED
    assert list(artifact_root.iterdir()) == []
    assert repository_oracle(repository) == source_before


@pytest.mark.asyncio
async def test_allowed_path_cannot_hide_sensitive_cross_scope_rename(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    (repository / ".env").write_text("MODE=demo\n", encoding="utf-8")
    run_git(repository, "add", ".env")
    run_git(repository, "commit", "-q", "-m", "Add sensitive scoped fixture")
    head = run_git(repository, "rev-parse", "HEAD")
    run_git(repository, "mv", ".env", "safe.txt")
    source_before = repository_oracle(repository)
    artifact_root = tmp_path / "artifacts"
    service, _artifact_store = _build_service(workspace, artifact_root)
    task = _task(head, task_id="adversarial-cross-scope-job-0001")
    assert task.repository is not None
    task.repository.allowed_paths = ["safe.txt"]
    job = service.create_job(task, "adversarial-cross-scope-job-0001")

    with pytest.raises(RepositoryAccessError, match="cross-scope rename"):
        await service.analyze_job(job.id)

    assert service.recovery_capture is not None
    with pytest.raises(RecoveryBlockedError) as capture_blocked:
        service.recovery_capture._capture_tracked_patches(
            repository,
            head,
            ["--", "safe.txt"],
        )
    assert capture_blocked.value.code == "cross_scope_move"
    assert list(artifact_root.iterdir()) == []
    assert repository_oracle(repository) == source_before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("unsafe_kind", "expected_code", "blocked_during_request"),
    [
        ("symlink", "symlink_boundary", False),
        ("hardlink", "inspection_incomplete", True),
    ],
)
async def test_unsafe_untracked_link_types_are_blocked(
    tmp_path: Path,
    unsafe_kind: str,
    expected_code: str,
    blocked_during_request: bool,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    if unsafe_kind == "symlink":
        (repository / "unsafe-link").symlink_to("src/app.py")
    else:
        os.link(repository / "src" / "app.py", repository / "unsafe-hardlink")
    source_before = repository_oracle(repository)
    artifact_root = tmp_path / "artifacts"
    service, _artifact_store = _build_service(workspace, artifact_root)
    job = await _analyze(
        service,
        head,
        f"adversarial-{unsafe_kind}-job-0001",
    )
    assert job.inspection is not None
    if blocked_during_request:
        with pytest.raises(RecoveryBlockedError) as blocked:
            service.create_recovery_request(
                job.id,
                RecoveryCreateRequest(
                    expected_repository_fingerprint=(job.inspection.repository_fingerprint),
                ),
                f"adversarial-{unsafe_kind}-recovery-0001",
                OWNER_ID,
            )
    else:
        _approve_recovery(
            service,
            job.id,
            job.inspection.repository_fingerprint,
            f"adversarial-{unsafe_kind}-recovery-0001",
        )
        with pytest.raises(RecoveryBlockedError) as blocked:
            service.prepare_recovery(job.id, OWNER_ID)

    assert blocked.value.code == expected_code
    if not blocked_during_request:
        assert service.get_recovery(job.id).status == RecoveryStatus.BLOCKED
    assert list(artifact_root.iterdir()) == []
    assert repository_oracle(repository) == source_before


@pytest.mark.asyncio
async def test_control_character_untracked_path_is_blocked(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    unsafe = repository / "unsafe\nname.txt"
    unsafe.write_text("must not be archived\n", encoding="utf-8")
    source_before = repository_oracle(repository)
    artifact_root = tmp_path / "artifacts"
    service, _artifact_store = _build_service(workspace, artifact_root)

    with pytest.raises(RepositoryAccessError, match="unsafe path"):
        await _analyze(service, head, "adversarial-control-path-job-0001")

    assert list(artifact_root.iterdir()) == []
    assert repository_oracle(repository) == source_before


@pytest.mark.asyncio
async def test_recovery_does_not_execute_configured_fsmonitor_or_git_hook(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    (repository / "notes.txt").write_text("recover safely\n", encoding="utf-8")
    sentinel = tmp_path / "command-executed"
    monitor = repository / "malicious-fsmonitor.sh"
    monitor.write_text(
        f"#!/bin/sh\ntouch '{sentinel}'\n",
        encoding="utf-8",
    )
    monitor.chmod(0o755)
    run_git(repository, "config", "core.fsmonitor", str(monitor))
    hook = repository / ".git" / "hooks" / "post-index-change"
    hook.write_text(
        f"#!/bin/sh\ntouch '{sentinel}'\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    notes_before = (repository / "notes.txt").read_bytes()
    monitor_before = monitor.read_bytes()
    config_before = (repository / ".git" / "config").read_bytes()
    index_before = (repository / ".git" / "index").read_bytes()
    assert not sentinel.exists()

    service, _artifact_store = _build_service(
        workspace,
        tmp_path / "artifacts",
    )
    job = await _analyze(service, head, "adversarial-hook-job-0001")
    assert job.inspection is not None
    _approve_recovery(
        service,
        job.id,
        job.inspection.repository_fingerprint,
        "adversarial-hook-recovery-0001",
    )
    package = service.prepare_recovery(job.id, OWNER_ID)

    assert package.status == RecoveryStatus.READY
    assert not sentinel.exists()
    assert (repository / "notes.txt").read_bytes() == notes_before
    assert monitor.read_bytes() == monitor_before
    assert (repository / ".git" / "config").read_bytes() == config_before
    assert (repository / ".git" / "index").read_bytes() == index_before


@pytest.mark.asyncio
async def test_inspection_blocks_git_clean_filter_without_executing_it(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, _head = initialize_repository(workspace)
    (repository / ".gitattributes").write_text(
        "src/app.py filter=hostile\n",
        encoding="utf-8",
    )
    run_git(repository, "add", ".gitattributes")
    run_git(repository, "commit", "-q", "-m", "Add filter attribute fixture")
    head = run_git(repository, "rev-parse", "HEAD")
    sentinel = tmp_path / "filter-executed"
    filter_program = tmp_path / "hostile-filter.sh"
    filter_program.write_text(
        f"#!/bin/sh\ntouch '{sentinel}'\ncat\n",
        encoding="utf-8",
    )
    filter_program.chmod(0o755)
    run_git(repository, "config", "filter.hostile.clean", str(filter_program))
    (repository / "src" / "app.py").write_text(
        "from fastapi import FastAPI\n\napp = FastAPI(title='changed')\n",
        encoding="utf-8",
    )
    original_content = (repository / "src" / "app.py").read_bytes()
    service, _artifact_store = _build_service(
        workspace,
        tmp_path / "artifacts",
    )
    job = service.create_job(
        _task(head, task_id="adversarial-filter-job-0001"),
        "adversarial-filter-job-0001",
    )
    with pytest.raises(RepositoryAccessError, match="content filters"):
        await service.analyze_job(job.id)

    assert service.get_job(job.id).status == JobStatus.BLOCKED
    assert not sentinel.exists()
    assert (repository / "src" / "app.py").read_bytes() == original_content
    assert list((tmp_path / "artifacts").iterdir()) == []


@pytest.mark.asyncio
async def test_recovery_operation_idempotency_conflict_is_rejected(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    (repository / "notes.txt").write_text("recover safely\n", encoding="utf-8")
    service, _artifact_store = _build_service(
        workspace,
        tmp_path / "artifacts",
    )
    job = await _analyze(service, head, "adversarial-idempotency-job-0001")
    assert job.inspection is not None
    key = "adversarial-idempotency-recovery-0001"
    first = service.create_recovery_request(
        job.id,
        RecoveryCreateRequest(
            expected_repository_fingerprint=job.inspection.repository_fingerprint,
            retention_hours=24,
        ),
        key,
        OWNER_ID,
    )
    repeated = service.create_recovery_request(
        job.id,
        RecoveryCreateRequest(
            expected_repository_fingerprint=job.inspection.repository_fingerprint,
            retention_hours=24,
        ),
        key,
        OWNER_ID,
    )
    assert repeated.id == first.id

    with pytest.raises(IdempotencyConflictError):
        service.create_recovery_request(
            job.id,
            RecoveryCreateRequest(
                expected_repository_fingerprint=job.inspection.repository_fingerprint,
                retention_hours=48,
            ),
            key,
            OWNER_ID,
        )


@pytest.mark.asyncio
async def test_concurrent_approval_decision_allows_exactly_one_success(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    (repository / "notes.txt").write_text("recover safely\n", encoding="utf-8")
    service, _artifact_store = _build_service(
        workspace,
        tmp_path / "artifacts",
    )
    job = await _analyze(service, head, "adversarial-concurrency-job-0001")
    assert job.inspection is not None
    package = service.create_recovery_request(
        job.id,
        RecoveryCreateRequest(
            expected_repository_fingerprint=job.inspection.repository_fingerprint,
        ),
        "adversarial-concurrency-recovery-0001",
        OWNER_ID,
    )
    approval = service.approvals.get(package.approval_id)
    request = ApprovalDecisionRequest(
        decision="approve",
        action_digest=approval.action_digest,
    )
    barrier = Barrier(2)

    def decide() -> str:
        barrier.wait(timeout=5)
        try:
            service.decide_approval(approval.id, request, OWNER_ID)
        except ApprovalError:
            return "rejected-as-duplicate"
        return "approved"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: decide(), range(2)))

    assert sorted(results) == ["approved", "rejected-as-duplicate"]
    decided = service.approvals.get(approval.id)
    assert decided.status == ApprovalStatus.APPROVED
    assert decided.decided_by == OWNER_ID
    assert service.get_recovery(job.id).status == RecoveryStatus.APPROVED


@pytest.mark.asyncio
async def test_cancellation_stops_capture_without_resurrecting_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    (repository / "notes.txt").write_text("recover safely\n", encoding="utf-8")
    artifact_root = tmp_path / "artifacts"
    service, _artifact_store = _build_service(workspace, artifact_root)
    job = await _analyze(service, head, "adversarial-cancel-job-0001")
    assert job.inspection is not None
    _approve_recovery(
        service,
        job.id,
        job.inspection.repository_fingerprint,
        "adversarial-cancel-recovery-0001",
    )
    started = Event()
    original = service.recovery_capture._prepare_artifacts  # type: ignore[union-attr]

    def delayed_prepare(*args, **kwargs):
        started.set()
        deadline = time.monotonic() + 5
        while not service.store.is_job_cancel_requested(job.id) and time.monotonic() < deadline:
            time.sleep(0.01)
        return original(*args, **kwargs)

    monkeypatch.setattr(
        service.recovery_capture,
        "_prepare_artifacts",
        delayed_prepare,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        capture = executor.submit(service.prepare_recovery, job.id, OWNER_ID)
        assert started.wait(timeout=5)
        cancel = executor.submit(service.cancel_job, job.id, OWNER_ID)
        with pytest.raises(RecoveryBlockedError) as blocked:
            capture.result(timeout=10)
        canceled = cancel.result(timeout=10)

    assert blocked.value.code == "capture_stopped"
    assert canceled.status == JobStatus.CANCELED
    persisted = service.get_job(job.id)
    assert persisted.status == JobStatus.CANCELED
    assert persisted.recovery_package is not None
    assert persisted.recovery_package.status == RecoveryStatus.BLOCKED
    assert list(artifact_root.iterdir()) == []
