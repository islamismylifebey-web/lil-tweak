from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Event

import pytest

from liltweak.agent import DeterministicPlanner
from liltweak.approvals import ApprovalError
from liltweak.artifacts import EncryptedArtifactStore
from liltweak.costs import CostGuard
from liltweak.evidence import EvidenceLedger
from liltweak.models import (
    ApprovalDecisionRequest,
    ApprovalStatus,
    Environment,
    JobRecord,
    JobStatus,
    RecoveryCreateRequest,
    RepositoryRef,
    TaskCreate,
)
from liltweak.recovery import RecoveryCapture
from liltweak.repository import RepositoryAccessError, RepositoryInspector
from liltweak.service import EmergencyStopError, LilTweakService
from liltweak.store import SQLiteStore
from tests.repository_helpers import initialize_repository

WORKERS = 64
OWNER_ID = "owner"
EVIDENCE_KEY = b"G" * 32


def _task(
    task_id: str,
    *,
    environment: Environment = Environment.DEVELOPMENT,
    repository: RepositoryRef | None = None,
) -> TaskCreate:
    return TaskCreate(
        task_id=task_id,
        requested_by=OWNER_ID,
        organization_id="gauntlet-org",
        project_id="gauntlet-project",
        repository=repository,
        environment=environment,
        objective="Prepare one bounded, non-executing technical plan.",
        execution_permission=False,
    )


def _service(
    store: SQLiteStore,
    *,
    planner=None,
    monthly_limit: float = 250,
    inspector: RepositoryInspector | None = None,
    recovery_capture: RecoveryCapture | None = None,
) -> LilTweakService:
    return LilTweakService(
        store=store,
        planner=planner or DeterministicPlanner(),
        cost_guard=CostGuard(
            monthly_limit_usd=monthly_limit,
            job_default_limit_usd=5,
            planning_reservation_usd=1,
        ),
        repository_inspector=inspector,
        recovery_capture=recovery_capture,
        owner_id=OWNER_ID,
        evidence_signing_key=EVIDENCE_KEY,
    )


def _run_workers(
    action: Callable[[int], object],
    *,
    workers: int = WORKERS,
) -> list[tuple[str, object]]:
    start = Barrier(workers)

    def invoke(index: int) -> tuple[str, object]:
        start.wait(timeout=30)
        try:
            return "ok", action(index)
        except Exception as exc:  # The caller asserts the exact accepted failures.
            return "error", exc

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(invoke, index) for index in range(workers)]
        return [future.result(timeout=60) for future in futures]


def _database_counts(database: Path, job_id: str | None = None) -> dict[str, int]:
    with sqlite3.connect(database) as connection:
        values = {
            "jobs": int(connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]),
            "idempotency": int(
                connection.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0]
            ),
            "approvals": int(connection.execute("SELECT COUNT(*) FROM approvals").fetchone()[0]),
            "operation_idempotency": int(
                connection.execute("SELECT COUNT(*) FROM operation_idempotency").fetchone()[0]
            ),
        }
        if job_id is not None:
            values["job_evidence"] = int(
                connection.execute(
                    "SELECT COUNT(*) FROM evidence WHERE job_id = ?",
                    (job_id,),
                ).fetchone()[0]
            )
            values["job_approvals"] = int(
                connection.execute(
                    "SELECT COUNT(*) FROM approvals WHERE job_id = ?",
                    (job_id,),
                ).fetchone()[0]
            )
        values["orphan_jobs"] = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM jobs AS jobs
                LEFT JOIN idempotency AS keys ON keys.job_id = jobs.id
                WHERE keys.job_id IS NULL
                """
            ).fetchone()[0]
        )
    return values


def test_64_duplicate_create_requests_are_one_atomic_idempotent_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "create-db" / "liltweak.db"
    store = SQLiteStore(database)
    service = _service(store)
    task = _task("gauntlet-duplicate-create")
    key = "gauntlet-create-idempotency-0001"

    # Force the valid interleaving where every request observes the key as absent
    # before any request is allowed to persist its job.
    lookup_gate = Barrier(WORKERS)
    original_lookup = store.get_idempotent_job

    def synchronized_lookup(
        organization_id: str,
        idempotency_key: str,
        request_hash: str,
    ):
        result = original_lookup(organization_id, idempotency_key, request_hash)
        lookup_gate.wait(timeout=30)
        return result

    monkeypatch.setattr(store, "get_idempotent_job", synchronized_lookup)
    outcomes = _run_workers(lambda _index: service.create_job(task, key))
    successes = [value for status, value in outcomes if status == "ok"]
    errors = [value for status, value in outcomes if status == "error"]
    returned_ids = {value.id for value in successes if isinstance(value, JobRecord)}
    counts = _database_counts(database)

    assert (
        len(successes),
        len(errors),
        len(returned_ids),
        counts,
    ) == (
        WORKERS,
        0,
        1,
        {
            "jobs": 1,
            "idempotency": 1,
            "approvals": 0,
            "operation_idempotency": 0,
            "orphan_jobs": 0,
        },
    )


def test_job_creation_rolls_back_if_idempotency_binding_fails(
    tmp_path: Path,
) -> None:
    database = tmp_path / "create-rollback-db" / "liltweak.db"
    store = SQLiteStore(database)
    service = _service(store)
    task = _task("gauntlet-create-rollback")
    key = "gauntlet-create-rollback-idempotency-0001"
    with store._lock, store._connection:
        store._connection.executescript(
            """
            CREATE TRIGGER gauntlet_fail_idempotency
            BEFORE INSERT ON idempotency
            BEGIN
                SELECT RAISE(ABORT, 'forced idempotency failure');
            END;
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="forced idempotency failure"):
        service.create_job(task, key)
    assert _database_counts(database) == {
        "jobs": 0,
        "idempotency": 0,
        "approvals": 0,
        "operation_idempotency": 0,
        "orphan_jobs": 0,
    }

    with store._lock, store._connection:
        store._connection.execute("DROP TRIGGER gauntlet_fail_idempotency")
    created = service.create_job(task, key)
    assert service.get_job(created.id).id == created.id
    assert service.evidence.verify(created.id)


class _BlockingPaidPlanner:
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


@pytest.mark.asyncio
async def test_64_simultaneous_analyze_calls_make_one_paid_provider_call() -> None:
    planner = _BlockingPaidPlanner()
    store = SQLiteStore(":memory:")
    service = _service(store, planner=planner, monthly_limit=1)
    job = service.create_job(
        _task("gauntlet-analyze"),
        "gauntlet-analyze-idempotency-0001",
    )

    calls = [asyncio.create_task(service.analyze_job(job.id)) for _ in range(WORKERS)]
    await asyncio.wait_for(planner.started.wait(), timeout=10)
    for _ in range(4):
        await asyncio.sleep(0)
    planner.release.set()
    outcomes = await asyncio.gather(*calls, return_exceptions=True)

    successes = [value for value in outcomes if isinstance(value, JobRecord)]
    rejections = [value for value in outcomes if isinstance(value, RepositoryAccessError)]
    unexpected = [
        value for value in outcomes if not isinstance(value, (JobRecord, RepositoryAccessError))
    ]
    with store._lock:
        planning_claims = int(
            store._connection.execute(
                "SELECT COUNT(*) FROM planning_claims WHERE job_id = ?",
                (job.id,),
            ).fetchone()[0]
        )
        reservations = int(
            store._connection.execute(
                "SELECT COUNT(*) FROM budget_reservations WHERE job_id = ?",
                (job.id,),
            ).fetchone()[0]
        )

    assert len(successes) == 1
    assert len(rejections) == WORKERS - 1
    assert unexpected == []
    assert planner.calls == 1
    assert planning_claims == 1
    assert reservations == 1
    assert store.month_to_date_cost() == 1
    assert service.get_job(job.id).status == JobStatus.PLAN_READY
    assert service.evidence.verify(job.id)


def test_cancel_before_technical_approval_publication_leaves_no_orphan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "approval-publication-db" / "liltweak.db"
    analyzing_service = _service(SQLiteStore(database))
    canceling_service = _service(SQLiteStore(database))
    job = analyzing_service.create_job(
        _task(
            "gauntlet-approval-publication",
            environment=Environment.PRODUCTION,
        ),
        "gauntlet-approval-publication-idempotency-0001",
    )
    publication_started = Event()
    publication_released = Event()
    original_publish = analyzing_service.store.publish_technical_approval

    def delayed_publish(*args, **kwargs):
        publication_started.set()
        if not publication_released.wait(timeout=30):
            raise TimeoutError("technical approval publication was not released")
        return original_publish(*args, **kwargs)

    monkeypatch.setattr(
        analyzing_service.store,
        "publish_technical_approval",
        delayed_publish,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        analysis = executor.submit(lambda: asyncio.run(analyzing_service.analyze_job(job.id)))
        assert publication_started.wait(timeout=30)
        canceled = canceling_service.cancel_job(job.id, OWNER_ID)
        publication_released.set()
        analyzed = analysis.result(timeout=30)

    counts = _database_counts(database, job.id)
    assert canceled.status == JobStatus.CANCELED
    assert analyzed.status == JobStatus.CANCELED
    assert counts["job_approvals"] == 0
    assert analyzing_service.evidence.verify(job.id)


@pytest.mark.asyncio
async def test_cross_connection_decision_cancel_race_ends_nonactionable(
    tmp_path: Path,
) -> None:
    database = tmp_path / "approval-decision-db" / "liltweak.db"
    primary = _service(SQLiteStore(database))
    job = primary.create_job(
        _task(
            "gauntlet-cross-connection-approval",
            environment=Environment.PRODUCTION,
        ),
        "gauntlet-cross-connection-approval-idempotency-0001",
    )
    waiting = await primary.analyze_job(job.id)
    assert waiting.approval_id is not None
    approval = primary.approvals.get(waiting.approval_id)
    decision = ApprovalDecisionRequest(
        decision="approve",
        action_digest=approval.action_digest,
    )
    services = [_service(SQLiteStore(database)) for _ in range(WORKERS)]

    def race(index: int):
        if index < WORKERS // 2:
            return services[index].decide_approval(
                approval.id,
                decision,
                OWNER_ID,
            )
        return services[index].cancel_job(job.id, OWNER_ID)

    outcomes = _run_workers(race)
    unexpected = [
        value
        for status, value in outcomes
        if status == "error" and not isinstance(value, ApprovalError)
    ]
    persisted = primary.get_job(job.id)
    persisted_approval = primary.approvals.get(approval.id)

    assert unexpected == []
    assert persisted.status == JobStatus.CANCELED
    assert persisted_approval.status == ApprovalStatus.INVALIDATED
    assert primary.evidence.verify(job.id)


def test_64_simultaneous_budget_admissions_never_exceed_monthly_limit(
    tmp_path: Path,
) -> None:
    database = tmp_path / "budget-db" / "liltweak.db"
    primary_store = SQLiteStore(database)
    service = _service(primary_store, monthly_limit=10)
    jobs = [
        service.create_job(
            _task(f"gauntlet-budget-{index}"),
            f"gauntlet-budget-idempotency-{index:04d}",
        )
        for index in range(WORKERS)
    ]
    stores = [SQLiteStore(database) for _ in range(WORKERS)]

    def reserve(index: int) -> float:
        return stores[index].reserve_budget(
            job_id=jobs[index].id,
            organization_id="gauntlet-org",
            amount_usd=1,
            monthly_limit_usd=10,
        )

    outcomes = _run_workers(reserve)
    successes = [value for status, value in outcomes if status == "ok"]
    expected_blocks = [
        value
        for status, value in outcomes
        if status == "error" and isinstance(value, ValueError) and "monthly" in str(value)
    ]
    unexpected = [
        value for status, value in outcomes if status == "error" and value not in expected_blocks
    ]
    with sqlite3.connect(database) as connection:
        reservation_count, reservation_total = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(amount_usd), 0) FROM budget_reservations"
        ).fetchone()

    assert len(successes) == 10
    assert len(expected_blocks) == WORKERS - 10
    assert unexpected == []
    assert int(reservation_count) == 10
    assert float(reservation_total) == 10
    assert primary_store.month_to_date_cost() == 10


@pytest.mark.asyncio
@pytest.mark.parametrize("stop_kind", ["cancel", "emergency"])
async def test_approval_race_cannot_leave_actionable_approval_on_stopped_job(
    stop_kind: str,
) -> None:
    service = _service(SQLiteStore(":memory:"))
    job = service.create_job(
        _task(
            f"gauntlet-{stop_kind}-approval",
            environment=Environment.PRODUCTION,
        ),
        f"gauntlet-{stop_kind}-approval-idempotency-0001",
    )
    analyzed = await service.analyze_job(job.id)
    assert analyzed.status == JobStatus.AWAITING_APPROVAL
    assert analyzed.approval_id is not None
    approval = service.approvals.get(analyzed.approval_id)
    decision = ApprovalDecisionRequest(
        decision="approve",
        action_digest=approval.action_digest,
    )

    def race(index: int):
        if index < WORKERS // 2:
            return service.decide_approval(approval.id, decision, OWNER_ID)
        if stop_kind == "cancel":
            return service.cancel_job(job.id, OWNER_ID)
        return service.emergency_stop(OWNER_ID)

    outcomes = _run_workers(race)
    approved_responses = [
        value
        for status, value in outcomes
        if status == "ok" and isinstance(value, JobRecord) and value.status == JobStatus.APPROVED
    ]
    expected_errors = [
        value
        for status, value in outcomes
        if status == "error" and isinstance(value, (ApprovalError, EmergencyStopError))
    ]
    unexpected_errors = [
        value for status, value in outcomes if status == "error" and value not in expected_errors
    ]
    persisted = service.get_job(job.id)
    persisted_approval = service.approvals.get(approval.id)

    assert len(approved_responses) <= 1
    assert unexpected_errors == []
    assert persisted.status == JobStatus.CANCELED
    assert persisted_approval.status not in {
        ApprovalStatus.PENDING,
        ApprovalStatus.APPROVED,
    }
    assert service.evidence.verify(job.id)


def test_64_cross_connection_evidence_appends_form_one_verified_chain(
    tmp_path: Path,
) -> None:
    database = tmp_path / "evidence-db" / "liltweak.db"
    primary_store = SQLiteStore(database)
    service = _service(primary_store)
    job = service.create_job(
        _task("gauntlet-evidence"),
        "gauntlet-evidence-idempotency-0001",
    )
    ledgers = [EvidenceLedger(SQLiteStore(database), EVIDENCE_KEY) for _ in range(WORKERS)]

    outcomes = _run_workers(
        lambda index: ledgers[index].append(
            job.id,
            "gauntlet_concurrent_event",
            {"worker": index},
        )
    )
    errors = [value for status, value in outcomes if status == "error"]
    records = service.evidence.list(job.id)

    assert errors == []
    assert len(records) == WORKERS + 1
    assert [record.sequence for record in records] == list(range(1, WORKERS + 2))
    assert service.evidence.verify(job.id)


@pytest.mark.asyncio
async def test_64_repeated_recovery_requests_create_one_package_and_one_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    (repository / "recovery-note.txt").write_text(
        "preserve this bounded fixture\n",
        encoding="utf-8",
    )
    database = tmp_path / "recovery-db" / "liltweak.db"
    store = SQLiteStore(database)
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:gauntlet-repository": "repository"},
    )
    artifact_store = EncryptedArtifactStore(
        root=tmp_path / "artifacts",
        workspace_root=workspace,
        master_key=b"A" * 32,
        store=store,
    )
    service = _service(
        store,
        inspector=inspector,
        recovery_capture=RecoveryCapture(
            inspector=inspector,
            artifact_store=artifact_store,
        ),
    )
    job = service.create_job(
        _task(
            "gauntlet-recovery",
            repository=RepositoryRef(
                provider="local",
                repository_id="gauntlet-repository",
                revision=head,
            ),
        ),
        "gauntlet-recovery-job-idempotency-0001",
    )
    analyzed = await service.analyze_job(job.id)
    assert analyzed.inspection is not None
    request = RecoveryCreateRequest(
        expected_repository_fingerprint=analyzed.inspection.repository_fingerprint,
    )
    key = "gauntlet-recovery-request-idempotency-0001"

    # As with job creation, force every request to observe the operation key as
    # absent before any request may publish its recovery package.
    lookup_gate = Barrier(WORKERS)
    original_lookup = store.get_operation_result

    def synchronized_lookup(
        organization_id: str,
        operation_scope: str,
        idempotency_key: str,
        request_hash: str,
    ):
        result = original_lookup(
            organization_id,
            operation_scope,
            idempotency_key,
            request_hash,
        )
        lookup_gate.wait(timeout=30)
        return result

    monkeypatch.setattr(store, "get_operation_result", synchronized_lookup)
    outcomes = _run_workers(
        lambda _index: service.create_recovery_request(
            analyzed.id,
            request,
            key,
            OWNER_ID,
        )
    )
    successes = [value for status, value in outcomes if status == "ok"]
    errors = [value for status, value in outcomes if status == "error"]
    package_ids = {value.id for value in successes}
    counts = _database_counts(database, analyzed.id)
    persisted = service.get_job(analyzed.id)

    assert persisted.recovery_package is not None
    assert (
        len(successes),
        len(errors),
        len(package_ids),
        counts["job_approvals"],
        counts["operation_idempotency"],
        persisted.recovery_package.id in package_ids,
    ) == (WORKERS, 0, 1, 1, 1, True)
    assert service.evidence.verify(analyzed.id)


@pytest.mark.asyncio
async def test_recovery_publication_rolls_back_as_one_unit(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    repository, head = initialize_repository(workspace)
    (repository / "recovery-note.txt").write_text(
        "preserve this bounded fixture\n",
        encoding="utf-8",
    )
    database = tmp_path / "recovery-rollback-db" / "liltweak.db"
    store = SQLiteStore(database)
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:gauntlet-repository": "repository"},
    )
    artifact_store = EncryptedArtifactStore(
        root=tmp_path / "artifacts",
        workspace_root=workspace,
        master_key=b"A" * 32,
        store=store,
    )
    service = _service(
        store,
        inspector=inspector,
        recovery_capture=RecoveryCapture(
            inspector=inspector,
            artifact_store=artifact_store,
        ),
    )
    job = service.create_job(
        _task(
            "gauntlet-recovery-rollback",
            repository=RepositoryRef(
                provider="local",
                repository_id="gauntlet-repository",
                revision=head,
            ),
        ),
        "gauntlet-recovery-rollback-job-idempotency-0001",
    )
    analyzed = await service.analyze_job(job.id)
    assert analyzed.inspection is not None
    request = RecoveryCreateRequest(
        expected_repository_fingerprint=analyzed.inspection.repository_fingerprint,
    )
    key = "gauntlet-recovery-rollback-request-idempotency-0001"
    with store._lock, store._connection:
        store._connection.executescript(
            """
            CREATE TRIGGER gauntlet_fail_recovery_publication
            BEFORE INSERT ON operation_idempotency
            BEGIN
                SELECT RAISE(ABORT, 'forced recovery publication failure');
            END;
            """
        )

    with pytest.raises(
        sqlite3.IntegrityError,
        match="forced recovery publication failure",
    ):
        service.create_recovery_request(
            analyzed.id,
            request,
            key,
            OWNER_ID,
        )
    counts = _database_counts(database, analyzed.id)
    assert counts["job_approvals"] == 0
    assert counts["operation_idempotency"] == 0
    assert service.get_job(analyzed.id).recovery_package is None

    with store._lock, store._connection:
        store._connection.execute("DROP TRIGGER gauntlet_fail_recovery_publication")
    package = service.create_recovery_request(
        analyzed.id,
        request,
        key,
        OWNER_ID,
    )
    assert service.get_job(analyzed.id).recovery_package == package
    assert _database_counts(database, analyzed.id)["job_approvals"] == 1
    assert service.evidence.verify(analyzed.id)
