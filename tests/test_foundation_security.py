from __future__ import annotations

import asyncio
import base64
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from liltweak.agent import DeterministicPlanner
from liltweak.config import Settings
from liltweak.costs import CostGuard
from liltweak.evidence import EvidenceLedger
from liltweak.models import JobStatus, TaskCreate
from liltweak.repository import RepositoryAccessError
from liltweak.service import LilTweakService, SensitiveInputError
from liltweak.store import SQLiteStore


def _task(task_id: str) -> TaskCreate:
    return TaskCreate(
        task_id=task_id,
        requested_by="owner",
        organization_id="owner",
        project_id="lil-tweak",
        objective="Prepare a bounded plan.",
    )


class BlockingPaidPlanner:
    paid_provider = True

    def __init__(self) -> None:
        self.calls = 0
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def plan(self, task: TaskCreate, inspection_context=None):
        self.calls += 1
        self.started.set()
        await self.release.wait()
        return await DeterministicPlanner().plan(task, inspection_context)


def test_invalid_foundation_configuration_fails_closed(tmp_path: Path) -> None:
    common = {
        "environment": "production",
        "database_path": tmp_path / "settings.db",
        "dev_api_key": "development-only",
        "auth_disabled": False,
        "model": "test-model",
        "monthly_budget_usd": 250,
        "job_hard_limit_usd": 5,
    }
    with pytest.raises(ValueError, match="EVIDENCE_SIGNING_KEY"):
        Settings(**common)
    with pytest.raises(ValueError, match="finite"):
        CostGuard(monthly_limit_usd=float("nan"), job_default_limit_usd=5)
    with pytest.raises(ValueError, match="exactly 32"):
        EvidenceLedger(SQLiteStore(":memory:"), b"")


def test_unpadded_urlsafe_evidence_key_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoded = base64.urlsafe_b64encode(b"K" * 32).decode().rstrip("=")
    monkeypatch.setenv("LILTWEAK_ENVIRONMENT", "production")
    monkeypatch.setenv("LILTWEAK_EVIDENCE_SIGNING_KEY", encoded)
    settings = Settings.from_env()
    assert settings.evidence_signing_key == b"K" * 32


def test_budget_admission_is_serialized_across_store_connections(
    tmp_path: Path,
) -> None:
    database = tmp_path / "budget.db"
    first_store = SQLiteStore(database)
    service = LilTweakService(
        store=first_store,
        planner=DeterministicPlanner(),
        cost_guard=CostGuard(monthly_limit_usd=1, job_default_limit_usd=5),
    )
    first = service.create_job(_task("budget-one"), "budget-job-key-0001")
    second = service.create_job(_task("budget-two"), "budget-job-key-0002")
    second_store = SQLiteStore(database)
    barrier = Barrier(2)

    def reserve(store: SQLiteStore, job_id: str) -> str:
        barrier.wait()
        try:
            store.reserve_budget(
                job_id=job_id,
                organization_id="owner",
                amount_usd=1,
                monthly_limit_usd=1,
            )
        except ValueError:
            return "blocked"
        return "reserved"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [
            pool.submit(reserve, first_store, first.id),
            pool.submit(reserve, second_store, second.id),
        ]
    assert sorted(item.result() for item in outcomes) == ["blocked", "reserved"]
    assert first_store.month_to_date_cost() == 1


def test_evidence_appends_serialize_across_store_connections(tmp_path: Path) -> None:
    database = tmp_path / "concurrent-evidence.db"
    signing_key = b"E" * 32
    first_store = SQLiteStore(database)
    service = LilTweakService(
        store=first_store,
        planner=DeterministicPlanner(),
        cost_guard=CostGuard(monthly_limit_usd=250, job_default_limit_usd=5),
        evidence_signing_key=signing_key,
    )
    job = service.create_job(_task("evidence-concurrency"), "evidence-append-key-0001")
    second_ledger = EvidenceLedger(SQLiteStore(database), signing_key)
    barrier = Barrier(2)

    def append_many(ledger: EvidenceLedger, worker: str) -> None:
        barrier.wait()
        for index in range(8):
            ledger.append(job.id, "concurrent_event", {"worker": worker, "index": index})

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [
            pool.submit(append_many, service.evidence, "first"),
            pool.submit(append_many, second_ledger, "second"),
        ]
        for result in results:
            result.result()
    assert len(service.evidence.list(job.id)) == 17
    assert service.evidence.verify(job.id)


def test_sqlite_store_requires_private_directory_and_file_modes(tmp_path: Path) -> None:
    private = tmp_path / "private"
    database = private / "liltweak.db"
    SQLiteStore(database)
    assert stat.S_IMODE(private.stat().st_mode) == 0o700
    assert stat.S_IMODE(database.stat().st_mode) == 0o600

    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    with pytest.raises(PermissionError, match="private 0700"):
        SQLiteStore(public / "unsafe.db")

    hardlink_parent = tmp_path / "hardlink-private"
    hardlink_parent.mkdir(mode=0o700)
    hardlink_parent.chmod(0o700)
    external = tmp_path / "external.db"
    external.write_bytes(b"not a database")
    hardlink = hardlink_parent / "linked.db"
    hardlink.hardlink_to(external)
    with pytest.raises(PermissionError, match="owned regular files"):
        SQLiteStore(hardlink)


@pytest.mark.asyncio
async def test_planning_claim_prevents_duplicate_paid_provider_calls() -> None:
    planner = BlockingPaidPlanner()
    service = LilTweakService(
        store=SQLiteStore(":memory:"),
        planner=planner,
        cost_guard=CostGuard(
            monthly_limit_usd=1,
            job_default_limit_usd=5,
            planning_reservation_usd=1,
        ),
    )
    job = service.create_job(_task("one-shot"), "planning-claim-key-0001")
    first = asyncio.create_task(service.analyze_job(job.id))
    await planner.started.wait()
    with pytest.raises(RepositoryAccessError, match="already claimed"):
        await service.analyze_job(job.id)
    planner.release.set()
    result = await first
    assert result.status == JobStatus.PLAN_READY
    assert planner.calls == 1
    assert service.store.month_to_date_cost() == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("stop_kind", ["cancel", "emergency"])
async def test_long_planning_cannot_resurrect_stopped_job(stop_kind: str) -> None:
    planner = BlockingPaidPlanner()
    service = LilTweakService(
        store=SQLiteStore(":memory:"),
        planner=planner,
        cost_guard=CostGuard(
            monthly_limit_usd=5,
            job_default_limit_usd=5,
            planning_reservation_usd=1,
        ),
    )
    job = service.create_job(_task(f"stop-{stop_kind}"), f"stop-{stop_kind}-key-0001")
    analysis = asyncio.create_task(service.analyze_job(job.id))
    await planner.started.wait()
    if stop_kind == "cancel":
        service.cancel_job(job.id, "owner")
    else:
        assert service.emergency_stop("owner") == [job.id]
    planner.release.set()
    result = await analysis
    assert result.status == JobStatus.CANCELED
    assert result.plan is None
    assert service.get_job(job.id).status == JobStatus.CANCELED
    assert service.evidence.verify(job.id)


def test_idempotency_key_credentials_are_rejected_before_storage() -> None:
    service = LilTweakService(
        store=SQLiteStore(":memory:"),
        planner=DeterministicPlanner(),
        cost_guard=CostGuard(monthly_limit_usd=250, job_default_limit_usd=5),
    )
    fake_credential = "sk-" + "proj-" + ("X" * 32)
    with pytest.raises(SensitiveInputError, match="credential-like"):
        service.create_job(_task("sensitive-key"), fake_credential)
    assert service.store.list_active_jobs() == []
