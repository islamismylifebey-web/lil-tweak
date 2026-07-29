from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import sqlite3
import stat
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any

from .models import (
    ApprovalRecord,
    ApprovalStatus,
    ArtifactRecord,
    ArtifactStatus,
    EvidenceRecord,
    JobRecord,
    JobStatus,
    RecoveryStatus,
)
from .states import TERMINAL_STATES


class NotFoundError(LookupError):
    pass


class IdempotencyConflictError(ValueError):
    pass


class StoreStateConflictError(RuntimeError):
    pass


class EmergencyStopActiveError(StoreStateConflictError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class SQLiteStore:
    def __init__(self, path: Path | str) -> None:
        self._path = str(path)
        self._database_path: Path | None = None
        if self._path != ":memory:":
            self._database_path = Path(self._path)
            self._prepare_private_database_path(self._database_path)
        self._connection = sqlite3.connect(self._path, check_same_thread=False)
        self._secure_database_files()
        self._connection.row_factory = sqlite3.Row
        self._lock = RLock()
        self._initialize()
        self._secure_database_files()

    @staticmethod
    def _prepare_private_database_path(database_path: Path) -> None:
        parent = database_path.parent
        parent_existed = parent.exists()
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not parent_existed:
            os.chmod(parent, 0o700)
        parent_metadata = parent.lstat()
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
            or (hasattr(os, "geteuid") and parent_metadata.st_uid != os.geteuid())
        ):
            raise PermissionError("database parent directory must be a private 0700 directory")
        if database_path.exists() or database_path.is_symlink():
            SQLiteStore._secure_private_file(database_path)
            return
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(database_path, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)

    @staticmethod
    def _secure_private_file(candidate: Path) -> None:
        metadata = candidate.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
        ):
            raise PermissionError(
                "database, WAL, and shared-memory paths must be owned regular files"
            )
        os.chmod(candidate, 0o600, follow_symlinks=False)
        if stat.S_IMODE(candidate.lstat().st_mode) != 0o600:
            raise PermissionError("database files must use private 0600 permissions")

    def _secure_database_files(self) -> None:
        if self._database_path is None:
            return
        for candidate in (
            self._database_path,
            Path(f"{self._database_path}-wal"),
            Path(f"{self._database_path}-shm"),
        ):
            if candidate.exists():
                self._secure_private_file(candidate)

    def _initialize(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                PRAGMA foreign_keys = ON;
                PRAGMA journal_mode = WAL;
                PRAGMA busy_timeout = 30000;

                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS idempotency (
                    organization_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    job_id TEXT NOT NULL REFERENCES jobs(id),
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (organization_id, idempotency_key)
                );

                CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id),
                    status TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS approvals_job_status_idx
                ON approvals(job_id, status);

                CREATE TABLE IF NOT EXISTS operation_idempotency (
                    organization_id TEXT NOT NULL,
                    operation_scope TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    result_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (organization_id, operation_scope, idempotency_key)
                );

                CREATE TABLE IF NOT EXISTS artifacts (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id),
                    status TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    storage_key TEXT NOT NULL UNIQUE,
                    nonce_b64 TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS budget_reservations (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(id),
                    organization_id TEXT NOT NULL,
                    amount_usd REAL NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS planning_claims (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(id),
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(id),
                    sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(job_id, sequence)
                );

                CREATE TABLE IF NOT EXISTS evidence_anchors (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(id),
                    sequence INTEGER NOT NULL,
                    head_hash TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS system_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def save_job(self, job: JobRecord) -> None:
        payload = job.model_dump(mode="json")
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO jobs (
                    id, organization_id, project_id, status, record_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status = excluded.status,
                    record_json = excluded.record_json,
                    updated_at = excluded.updated_at
                """,
                (
                    job.id,
                    job.task.organization_id,
                    job.task.project_id,
                    job.status.value,
                    canonical_json(payload),
                    job.created_at.isoformat(),
                    job.updated_at.isoformat(),
                ),
            )

    def create_job_idempotently(
        self,
        job: JobRecord,
        *,
        idempotency_key: str,
        request_hash: str,
    ) -> tuple[JobRecord, bool]:
        """Atomically bind one request key to one newly created job."""
        organization_id = job.task.organization_id
        payload = job.model_dump(mode="json")
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                prior = self._connection.execute(
                    """
                    SELECT request_hash, job_id
                    FROM idempotency
                    WHERE organization_id = ? AND idempotency_key = ?
                    """,
                    (organization_id, idempotency_key),
                ).fetchone()
                if prior is not None:
                    if str(prior["request_hash"]) != request_hash:
                        raise IdempotencyConflictError(
                            "idempotency key was reused with different input"
                        )
                    row = self._connection.execute(
                        "SELECT record_json FROM jobs WHERE id = ?",
                        (str(prior["job_id"]),),
                    ).fetchone()
                    if row is None:
                        raise StoreStateConflictError(
                            "idempotency record does not have a durable job"
                        )
                    existing = JobRecord.model_validate_json(row["record_json"])
                    self._connection.commit()
                    return existing, False

                emergency = self._connection.execute(
                    "SELECT value FROM system_state WHERE key = 'emergency_stop'"
                ).fetchone()
                if emergency is not None and str(emergency["value"]) == "true":
                    raise EmergencyStopActiveError("Lil Tweak is emergency-stopped")

                self._connection.execute(
                    """
                    INSERT INTO jobs (
                        id, organization_id, project_id, status,
                        record_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        job.id,
                        organization_id,
                        job.task.project_id,
                        job.status.value,
                        canonical_json(payload),
                        job.created_at.isoformat(),
                        job.updated_at.isoformat(),
                    ),
                )
                self._connection.execute(
                    """
                    INSERT INTO idempotency (
                        organization_id, idempotency_key, request_hash, job_id, created_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        organization_id,
                        idempotency_key,
                        request_hash,
                        job.id,
                        datetime.now(UTC).isoformat(),
                    ),
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return job, True

    def compare_and_save_job(
        self,
        job: JobRecord,
        *,
        expected_status: JobStatus,
        expected_updated_at: datetime,
    ) -> bool:
        """Save only if the durable job still matches the caller's version snapshot."""
        payload = job.model_dump(mode="json")
        with self._lock, self._connection:
            updated = self._connection.execute(
                """
                UPDATE jobs
                SET status = ?, record_json = ?, updated_at = ?
                WHERE id = ? AND status = ? AND updated_at = ?
                """,
                (
                    job.status.value,
                    canonical_json(payload),
                    job.updated_at.isoformat(),
                    job.id,
                    expected_status.value,
                    expected_updated_at.isoformat(),
                ),
            )
        return updated.rowcount == 1

    def get_job(self, job_id: str) -> JobRecord:
        with self._lock:
            row = self._connection.execute(
                "SELECT record_json FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError(f"job not found: {job_id}")
        return JobRecord.model_validate_json(row["record_json"])

    def list_active_jobs(self) -> list[JobRecord]:
        terminal = tuple(state.value for state in TERMINAL_STATES)
        placeholders = ",".join("?" for _ in terminal)
        with self._lock:
            rows = self._connection.execute(
                f"SELECT record_json FROM jobs WHERE status NOT IN ({placeholders})",
                terminal,
            ).fetchall()
        return [JobRecord.model_validate_json(row["record_json"]) for row in rows]

    def month_to_date_cost(self, now: datetime | None = None) -> float:
        now = now or datetime.now(UTC)
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        with self._lock:
            row = self._connection.execute(
                """
                SELECT COALESCE(SUM(amount_usd), 0) AS total
                FROM budget_reservations WHERE created_at >= ?
                """,
                (start,),
            ).fetchone()
        return float(row["total"]) if row is not None else 0.0

    def reserve_budget(
        self,
        *,
        job_id: str,
        organization_id: str,
        amount_usd: float,
        monthly_limit_usd: float,
        now: datetime | None = None,
    ) -> float:
        if not math.isfinite(amount_usd) or amount_usd <= 0:
            raise ValueError("budget reservation must be a finite positive amount")
        if not math.isfinite(monthly_limit_usd) or monthly_limit_usd < 0:
            raise ValueError("monthly budget must be a finite non-negative amount")
        now = now or datetime.now(UTC)
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        with self._lock:
            try:
                # Acquire the database write lock before reading the aggregate. A
                # deferred transaction would permit two worker processes to admit
                # against the same remaining monthly budget.
                self._connection.execute("BEGIN IMMEDIATE")
                existing = self._connection.execute(
                    """
                    SELECT organization_id, amount_usd
                    FROM budget_reservations WHERE job_id = ?
                    """,
                    (job_id,),
                ).fetchone()
                if existing is not None:
                    reserved = float(existing["amount_usd"])
                    if (
                        str(existing["organization_id"]) != organization_id
                        or abs(reserved - amount_usd) > 0.000001
                    ):
                        raise ValueError("job budget reservation no longer matches")
                    self._connection.commit()
                    return reserved
                total = self._connection.execute(
                    """
                    SELECT COALESCE(SUM(amount_usd), 0) AS total
                    FROM budget_reservations WHERE created_at >= ?
                    """,
                    (start,),
                ).fetchone()
                committed = float(total["total"]) if total is not None else 0.0
                if committed + amount_usd > monthly_limit_usd:
                    raise ValueError("monthly Lil Tweak budget would be exceeded")
                self._connection.execute(
                    """
                    INSERT INTO budget_reservations (
                        job_id, organization_id, amount_usd, created_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (job_id, organization_id, amount_usd, now.isoformat()),
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return amount_usd

    def claim_planning(self, job_id: str, now: datetime | None = None) -> bool:
        """Durably admit at most one model-planning attempt for a job."""
        now = now or datetime.now(UTC)
        with self._lock, self._connection:
            claimed = self._connection.execute(
                """
                INSERT OR IGNORE INTO planning_claims (job_id, created_at)
                VALUES (?, ?)
                """,
                (job_id, now.isoformat()),
            )
        return claimed.rowcount == 1

    def get_idempotent_job(
        self, organization_id: str, idempotency_key: str, request_hash: str
    ) -> JobRecord | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT request_hash, job_id FROM idempotency
                WHERE organization_id = ? AND idempotency_key = ?
                """,
                (organization_id, idempotency_key),
            ).fetchone()
        if row is None:
            return None
        if row["request_hash"] != request_hash:
            raise IdempotencyConflictError("idempotency key was reused with different input")
        return self.get_job(row["job_id"])

    def save_idempotency(
        self,
        organization_id: str,
        idempotency_key: str,
        request_hash: str,
        job_id: str,
    ) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO idempotency (
                    organization_id, idempotency_key, request_hash, job_id, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    organization_id,
                    idempotency_key,
                    request_hash,
                    job_id,
                    datetime.now(UTC).isoformat(),
                ),
            )

    def save_approval(self, approval: ApprovalRecord) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO approvals (id, job_id, status, record_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status = excluded.status,
                    record_json = excluded.record_json
                """,
                (
                    approval.id,
                    approval.job_id,
                    approval.status.value,
                    approval.model_dump_json(),
                    approval.created_at.isoformat(),
                ),
            )

    def publish_technical_approval(
        self,
        job: JobRecord,
        approval: ApprovalRecord,
        *,
        expected_updated_at: datetime,
    ) -> tuple[JobRecord, bool]:
        """Atomically link an approval and enter the awaiting-approval state."""
        if job.status != JobStatus.AWAITING_APPROVAL:
            raise ValueError("approval publication requires an awaiting-approval job")
        if job.approval_id != approval.id or approval.job_id != job.id:
            raise ValueError("technical approval does not match the job")

        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                emergency = self._connection.execute(
                    "SELECT value FROM system_state WHERE key = 'emergency_stop'"
                ).fetchone()
                canceled = self._connection.execute(
                    "SELECT value FROM system_state WHERE key = ?",
                    (f"cancel:{job.id}",),
                ).fetchone()
                row = self._connection.execute(
                    "SELECT status, updated_at, record_json FROM jobs WHERE id = ?",
                    (job.id,),
                ).fetchone()
                if row is None:
                    raise NotFoundError(f"job not found: {job.id}")
                current = JobRecord.model_validate_json(row["record_json"])
                if (
                    (emergency is not None and str(emergency["value"]) == "true")
                    or (canceled is not None and str(canceled["value"]) == "true")
                    or current.status in TERMINAL_STATES
                ):
                    self._connection.commit()
                    return current, False
                if (
                    str(row["status"]) != JobStatus.PLAN_READY.value
                    or str(row["updated_at"]) != expected_updated_at.isoformat()
                ):
                    self._connection.commit()
                    return current, False
                if current.approval_id is not None:
                    raise StoreStateConflictError("job already has a technical approval")

                self._connection.execute(
                    """
                    INSERT INTO approvals (id, job_id, status, record_json, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        approval.id,
                        approval.job_id,
                        approval.status.value,
                        approval.model_dump_json(),
                        approval.created_at.isoformat(),
                    ),
                )
                updated = self._connection.execute(
                    """
                    UPDATE jobs
                    SET status = ?, record_json = ?, updated_at = ?
                    WHERE id = ? AND status = ? AND updated_at = ?
                    """,
                    (
                        job.status.value,
                        canonical_json(job.model_dump(mode="json")),
                        job.updated_at.isoformat(),
                        job.id,
                        JobStatus.PLAN_READY.value,
                        expected_updated_at.isoformat(),
                    ),
                )
                if updated.rowcount != 1:
                    raise StoreStateConflictError(
                        "job changed before technical approval publication"
                    )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return job, True

    def get_approval(self, approval_id: str) -> ApprovalRecord:
        with self._lock:
            row = self._connection.execute(
                "SELECT record_json FROM approvals WHERE id = ?", (approval_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError(f"approval not found: {approval_id}")
        return ApprovalRecord.model_validate_json(row["record_json"])

    def decide_approval(
        self,
        approval_id: str,
        *,
        expected_digest: str,
        approved: bool,
        decided_by: str,
        now: datetime,
    ) -> ApprovalRecord:
        expired = False
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT status, record_json FROM approvals WHERE id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"approval not found: {approval_id}")
            approval = ApprovalRecord.model_validate_json(row["record_json"])
            if approval.status != ApprovalStatus.PENDING:
                raise ValueError("approval is not pending")
            if approval.expires_at <= now:
                approval.status = ApprovalStatus.EXPIRED
                self._connection.execute(
                    """
                    UPDATE approvals SET status = ?, record_json = ?
                    WHERE id = ? AND status = ?
                    """,
                    (
                        approval.status.value,
                        approval.model_dump_json(),
                        approval_id,
                        ApprovalStatus.PENDING.value,
                    ),
                )
                expired = True
            elif approval.action_digest != expected_digest:
                raise ValueError("approval no longer matches the proposed action")
            else:
                approval.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
                approval.decided_by = decided_by
                approval.decided_at = now
                updated = self._connection.execute(
                    """
                    UPDATE approvals SET status = ?, record_json = ?
                    WHERE id = ? AND status = ?
                    """,
                    (
                        approval.status.value,
                        approval.model_dump_json(),
                        approval_id,
                        ApprovalStatus.PENDING.value,
                    ),
                )
                if updated.rowcount != 1:
                    raise ValueError("approval was already decided")
        if expired:
            raise ValueError("approval expired before decision")
        return approval

    def decide_linked_approval(
        self,
        approval_id: str,
        *,
        expected_digest: str,
        expected_linked_digest: str,
        expected_job_updated_at: datetime,
        approved: bool,
        decided_by: str,
        now: datetime,
    ) -> tuple[JobRecord, ApprovalRecord, bool]:
        """Atomically decide an approval and mutate its linked job/package."""
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                emergency = self._connection.execute(
                    "SELECT value FROM system_state WHERE key = 'emergency_stop'"
                ).fetchone()
                approval_row = self._connection.execute(
                    "SELECT status, record_json FROM approvals WHERE id = ?",
                    (approval_id,),
                ).fetchone()
                if approval_row is None:
                    raise NotFoundError(f"approval not found: {approval_id}")
                approval = ApprovalRecord.model_validate_json(approval_row["record_json"])
                job_row = self._connection.execute(
                    "SELECT status, updated_at, record_json FROM jobs WHERE id = ?",
                    (approval.job_id,),
                ).fetchone()
                if job_row is None:
                    raise NotFoundError(f"job not found: {approval.job_id}")
                job = JobRecord.model_validate_json(job_row["record_json"])
                canceled = self._connection.execute(
                    "SELECT value FROM system_state WHERE key = ?",
                    (f"cancel:{job.id}",),
                ).fetchone()
                if emergency is not None and str(emergency["value"]) == "true":
                    raise EmergencyStopActiveError("Lil Tweak is emergency-stopped")
                if (
                    canceled is not None and str(canceled["value"]) == "true"
                ) or job.status in TERMINAL_STATES:
                    raise StoreStateConflictError("approval belongs to a canceled or terminal job")
                if approval.status != ApprovalStatus.PENDING:
                    raise StoreStateConflictError("approval is not pending")
                if str(job_row["updated_at"]) != expected_job_updated_at.isoformat():
                    raise StoreStateConflictError("job changed before the approval decision")
                if not hmac.compare_digest(
                    approval.action_digest,
                    expected_digest,
                ) or not hmac.compare_digest(
                    approval.action_digest,
                    expected_linked_digest,
                ):
                    raise StoreStateConflictError("approval no longer matches the proposed action")

                if approval.expires_at <= now:
                    approval.status = ApprovalStatus.EXPIRED
                    if approval.purpose == "technical_change_review_v1":
                        if (
                            job.approval_id != approval.id
                            or job.status != JobStatus.AWAITING_APPROVAL
                        ):
                            raise StoreStateConflictError("technical approval is stale")
                        job.status = JobStatus.CANCELED
                        self._connection.execute(
                            """
                            INSERT INTO system_state (key, value) VALUES (?, 'true')
                            ON CONFLICT(key) DO UPDATE SET value = excluded.value
                            """,
                            (f"cancel:{job.id}",),
                        )
                    elif approval.purpose == "recovery_capture_v1":
                        package = job.recovery_package
                        if (
                            package is None
                            or package.approval_id != approval.id
                            or package.status != RecoveryStatus.AWAITING_APPROVAL
                        ):
                            raise StoreStateConflictError("recovery approval is stale")
                        package.status = RecoveryStatus.BLOCKED
                        package.blocker_codes = sorted(
                            {
                                *package.blocker_codes,
                                "approval_expired",
                            }
                        )
                        package.updated_at = now
                        job.recovery_package = package
                    else:
                        raise StoreStateConflictError("approval purpose is not supported")
                    job.updated_at = now
                    self._connection.execute(
                        """
                        UPDATE approvals SET status = ?, record_json = ?
                        WHERE id = ? AND status = ?
                        """,
                        (
                            approval.status.value,
                            approval.model_dump_json(),
                            approval.id,
                            ApprovalStatus.PENDING.value,
                        ),
                    )
                    self._connection.execute(
                        """
                        UPDATE jobs
                        SET status = ?, record_json = ?, updated_at = ?
                        WHERE id = ? AND updated_at = ?
                        """,
                        (
                            job.status.value,
                            canonical_json(job.model_dump(mode="json")),
                            job.updated_at.isoformat(),
                            job.id,
                            expected_job_updated_at.isoformat(),
                        ),
                    )
                    self._connection.commit()
                    return job, approval, False

                approval.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
                approval.decided_by = decided_by
                approval.decided_at = now
                if approval.purpose == "technical_change_review_v1":
                    if job.approval_id != approval.id or job.status != JobStatus.AWAITING_APPROVAL:
                        raise StoreStateConflictError("technical approval is stale")
                    job.status = JobStatus.APPROVED if approved else JobStatus.CANCELED
                    if not approved:
                        self._connection.execute(
                            """
                            INSERT INTO system_state (key, value) VALUES (?, 'true')
                            ON CONFLICT(key) DO UPDATE SET value = excluded.value
                            """,
                            (f"cancel:{job.id}",),
                        )
                elif approval.purpose == "recovery_capture_v1":
                    package = job.recovery_package
                    if (
                        package is None
                        or package.approval_id != approval.id
                        or not hmac.compare_digest(
                            package.action_digest,
                            approval.action_digest,
                        )
                        or package.status != RecoveryStatus.AWAITING_APPROVAL
                    ):
                        raise StoreStateConflictError("recovery approval is stale")
                    package.status = (
                        RecoveryStatus.APPROVED if approved else RecoveryStatus.REJECTED
                    )
                    package.updated_at = now
                    job.recovery_package = package
                else:
                    raise StoreStateConflictError("approval purpose is not supported")

                job.updated_at = now
                approval_update = self._connection.execute(
                    """
                    UPDATE approvals SET status = ?, record_json = ?
                    WHERE id = ? AND status = ?
                    """,
                    (
                        approval.status.value,
                        approval.model_dump_json(),
                        approval.id,
                        ApprovalStatus.PENDING.value,
                    ),
                )
                job_update = self._connection.execute(
                    """
                    UPDATE jobs
                    SET status = ?, record_json = ?, updated_at = ?
                    WHERE id = ? AND updated_at = ?
                    """,
                    (
                        job.status.value,
                        canonical_json(job.model_dump(mode="json")),
                        job.updated_at.isoformat(),
                        job.id,
                        expected_job_updated_at.isoformat(),
                    ),
                )
                if approval_update.rowcount != 1 or job_update.rowcount != 1:
                    raise StoreStateConflictError("approval decision lost a concurrent race")
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return job, approval, True

    def consume_approval(
        self,
        approval_id: str,
        *,
        consumed_by: str,
        now: datetime,
    ) -> ApprovalRecord:
        expired = False
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT status, record_json FROM approvals WHERE id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"approval not found: {approval_id}")
            approval = ApprovalRecord.model_validate_json(row["record_json"])
            if approval.status != ApprovalStatus.APPROVED:
                raise ValueError("approval is not approved and unused")
            if approval.expires_at <= now:
                approval.status = ApprovalStatus.EXPIRED
                self._connection.execute(
                    """
                    UPDATE approvals
                    SET status = ?, record_json = ?
                    WHERE id = ? AND status = ?
                    """,
                    (
                        approval.status.value,
                        approval.model_dump_json(),
                        approval_id,
                        ApprovalStatus.APPROVED.value,
                    ),
                )
                expired = True
            else:
                approval.status = ApprovalStatus.CONSUMED
                approval.consumed_by = consumed_by
                approval.consumed_at = now
                updated = self._connection.execute(
                    """
                    UPDATE approvals
                    SET status = ?, record_json = ?
                    WHERE id = ? AND status = ?
                    """,
                    (
                        approval.status.value,
                        approval.model_dump_json(),
                        approval_id,
                        ApprovalStatus.APPROVED.value,
                    ),
                )
                if updated.rowcount != 1:
                    raise ValueError("approval was already used")
        if expired:
            raise ValueError("approval expired before use")
        return approval

    def get_operation_result(
        self,
        organization_id: str,
        operation_scope: str,
        idempotency_key: str,
        request_hash: str,
    ) -> str | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT request_hash, result_id
                FROM operation_idempotency
                WHERE organization_id = ? AND operation_scope = ? AND idempotency_key = ?
                """,
                (organization_id, operation_scope, idempotency_key),
            ).fetchone()
        if row is None:
            return None
        if row["request_hash"] != request_hash:
            raise IdempotencyConflictError("idempotency key was reused with different input")
        return str(row["result_id"])

    def save_operation_result(
        self,
        organization_id: str,
        operation_scope: str,
        idempotency_key: str,
        request_hash: str,
        result_id: str,
    ) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO operation_idempotency (
                    organization_id, operation_scope, idempotency_key,
                    request_hash, result_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    organization_id,
                    operation_scope,
                    idempotency_key,
                    request_hash,
                    result_id,
                    datetime.now(UTC).isoformat(),
                ),
            )

    def publish_recovery_request_idempotently(
        self,
        job: JobRecord,
        approval: ApprovalRecord,
        *,
        operation_scope: str,
        idempotency_key: str,
        request_hash: str,
        expected_status: JobStatus,
        expected_updated_at: datetime,
    ) -> tuple[JobRecord, bool]:
        """Atomically publish a recovery package, approval, and operation key."""
        package = job.recovery_package
        if package is None:
            raise ValueError("recovery publication requires a package")
        if approval.job_id != job.id or approval.id != package.approval_id:
            raise ValueError("recovery approval does not match the package")
        if not hmac.compare_digest(approval.action_digest, package.action_digest):
            raise ValueError("recovery approval digest does not match the package")

        organization_id = job.task.organization_id
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                prior = self._connection.execute(
                    """
                    SELECT request_hash, result_id
                    FROM operation_idempotency
                    WHERE organization_id = ?
                      AND operation_scope = ?
                      AND idempotency_key = ?
                    """,
                    (organization_id, operation_scope, idempotency_key),
                ).fetchone()
                if prior is not None:
                    if str(prior["request_hash"]) != request_hash:
                        raise IdempotencyConflictError(
                            "idempotency key was reused with different input"
                        )
                    row = self._connection.execute(
                        "SELECT record_json FROM jobs WHERE id = ?",
                        (job.id,),
                    ).fetchone()
                    if row is None:
                        raise StoreStateConflictError("recovery job is not durable")
                    current = JobRecord.model_validate_json(row["record_json"])
                    current_package = current.recovery_package
                    if current_package is None or current_package.id != str(prior["result_id"]):
                        raise StoreStateConflictError("idempotent recovery record is unavailable")
                    self._connection.commit()
                    return current, False

                emergency = self._connection.execute(
                    "SELECT value FROM system_state WHERE key = 'emergency_stop'"
                ).fetchone()
                canceled = self._connection.execute(
                    "SELECT value FROM system_state WHERE key = ?",
                    (f"cancel:{job.id}",),
                ).fetchone()
                if (emergency is not None and str(emergency["value"]) == "true") or (
                    canceled is not None and str(canceled["value"]) == "true"
                ):
                    raise EmergencyStopActiveError("recovery publication was stopped before commit")

                row = self._connection.execute(
                    "SELECT status, updated_at, record_json FROM jobs WHERE id = ?",
                    (job.id,),
                ).fetchone()
                if row is None:
                    raise NotFoundError(f"job not found: {job.id}")
                current = JobRecord.model_validate_json(row["record_json"])
                if current.recovery_package is not None:
                    raise StoreStateConflictError("this Phase 3 job already has a recovery request")
                if (
                    str(row["status"]) != expected_status.value
                    or str(row["updated_at"]) != expected_updated_at.isoformat()
                ):
                    raise StoreStateConflictError("job changed before recovery publication")

                self._connection.execute(
                    """
                    INSERT INTO approvals (id, job_id, status, record_json, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        approval.id,
                        approval.job_id,
                        approval.status.value,
                        approval.model_dump_json(),
                        approval.created_at.isoformat(),
                    ),
                )
                updated = self._connection.execute(
                    """
                    UPDATE jobs
                    SET status = ?, record_json = ?, updated_at = ?
                    WHERE id = ? AND status = ? AND updated_at = ?
                    """,
                    (
                        job.status.value,
                        canonical_json(job.model_dump(mode="json")),
                        job.updated_at.isoformat(),
                        job.id,
                        expected_status.value,
                        expected_updated_at.isoformat(),
                    ),
                )
                if updated.rowcount != 1:
                    raise StoreStateConflictError("job changed before recovery publication")
                self._connection.execute(
                    """
                    INSERT INTO operation_idempotency (
                        organization_id, operation_scope, idempotency_key,
                        request_hash, result_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        organization_id,
                        operation_scope,
                        idempotency_key,
                        request_hash,
                        package.id,
                        datetime.now(UTC).isoformat(),
                    ),
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return job, True

    def save_artifact(
        self,
        artifact: ArtifactRecord,
        *,
        storage_key: str,
        nonce_b64: str,
    ) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO artifacts (
                    id, job_id, status, record_json, storage_key, nonce_b64, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact.id,
                    artifact.job_id,
                    artifact.status.value,
                    artifact.model_dump_json(),
                    storage_key,
                    nonce_b64,
                    artifact.created_at.isoformat(),
                ),
            )

    def get_artifact(self, artifact_id: str) -> ArtifactRecord:
        with self._lock:
            row = self._connection.execute(
                "SELECT record_json FROM artifacts WHERE id = ?",
                (artifact_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError(f"artifact not found: {artifact_id}")
        return ArtifactRecord.model_validate_json(row["record_json"])

    def get_artifact_storage(self, artifact_id: str) -> tuple[str, str]:
        with self._lock:
            row = self._connection.execute(
                "SELECT storage_key, nonce_b64 FROM artifacts WHERE id = ?",
                (artifact_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError(f"artifact not found: {artifact_id}")
        return str(row["storage_key"]), str(row["nonce_b64"])

    def quarantine_artifact(self, artifact_id: str) -> ArtifactRecord:
        artifact = self.get_artifact(artifact_id)
        artifact.status = ArtifactStatus.QUARANTINED
        with self._lock, self._connection:
            self._connection.execute(
                """
                UPDATE artifacts SET status = ?, record_json = ? WHERE id = ?
                """,
                (artifact.status.value, artifact.model_dump_json(), artifact_id),
            )
        return artifact

    def append_evidence(
        self,
        evidence_id: str,
        job_id: str,
        event_type: str,
        payload: dict[str, Any],
        created_at: datetime,
        signing_key: bytes,
    ) -> EvidenceRecord:
        with self._lock:
            try:
                # Serialize cross-process appends before reading the current tail.
                self._connection.execute("BEGIN IMMEDIATE")
                anchor = self._connection.execute(
                    """
                SELECT sequence, head_hash, signature
                FROM evidence_anchors WHERE job_id = ?
                """,
                    (job_id,),
                ).fetchone()
                previous = self._connection.execute(
                    """
                SELECT sequence, record_hash FROM evidence
                WHERE job_id = ? ORDER BY sequence DESC LIMIT 1
                """,
                    (job_id,),
                ).fetchone()
                if (anchor is None) != (previous is None):
                    raise ValueError("evidence anchor and chain tail do not match")
                if anchor is not None and previous is not None:
                    prior_anchor_payload = {
                        "schema": "liltweak-evidence-anchor-v1",
                        "job_id": job_id,
                        "sequence": int(anchor["sequence"]),
                        "head_hash": str(anchor["head_hash"]),
                    }
                    expected_signature = hmac.new(
                        signing_key,
                        canonical_json(prior_anchor_payload).encode(),
                        hashlib.sha256,
                    ).hexdigest()
                    if (
                        int(anchor["sequence"]) != int(previous["sequence"])
                        or str(anchor["head_hash"]) != str(previous["record_hash"])
                        or not hmac.compare_digest(
                            str(anchor["signature"]),
                            expected_signature,
                        )
                    ):
                        raise ValueError("evidence anchor authentication failed")
                sequence = 1 if previous is None else int(previous["sequence"]) + 1
                previous_hash = None if previous is None else str(previous["record_hash"])
                hash_input = {
                    "id": evidence_id,
                    "job_id": job_id,
                    "sequence": sequence,
                    "event_type": event_type,
                    "payload": payload,
                    "previous_hash": previous_hash,
                    "created_at": created_at.isoformat(),
                }
                record_hash = hashlib.sha256(canonical_json(hash_input).encode()).hexdigest()
                self._connection.execute(
                    """
                INSERT INTO evidence (
                    id, job_id, sequence, event_type, payload_json,
                    previous_hash, record_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        evidence_id,
                        job_id,
                        sequence,
                        event_type,
                        canonical_json(payload),
                        previous_hash,
                        record_hash,
                        created_at.isoformat(),
                    ),
                )
                anchor_payload = {
                    "schema": "liltweak-evidence-anchor-v1",
                    "job_id": job_id,
                    "sequence": sequence,
                    "head_hash": record_hash,
                }
                signature = hmac.new(
                    signing_key,
                    canonical_json(anchor_payload).encode(),
                    hashlib.sha256,
                ).hexdigest()
                self._connection.execute(
                    """
                INSERT INTO evidence_anchors (
                    job_id, sequence, head_hash, signature, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    sequence = excluded.sequence,
                    head_hash = excluded.head_hash,
                    signature = excluded.signature,
                    updated_at = excluded.updated_at
                """,
                    (job_id, sequence, record_hash, signature, created_at.isoformat()),
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return EvidenceRecord(
            id=evidence_id,
            job_id=job_id,
            sequence=sequence,
            event_type=event_type,
            payload=payload,
            previous_hash=previous_hash,
            record_hash=record_hash,
            created_at=created_at,
        )

    def get_evidence_anchor(self, job_id: str) -> tuple[int, str, str] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT sequence, head_hash, signature
                FROM evidence_anchors WHERE job_id = ?
                """,
                (job_id,),
            ).fetchone()
        if row is None:
            return None
        return int(row["sequence"]), str(row["head_hash"]), str(row["signature"])

    def list_evidence(self, job_id: str) -> list[EvidenceRecord]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM evidence WHERE job_id = ? ORDER BY sequence", (job_id,)
            ).fetchall()
        return [
            EvidenceRecord(
                id=row["id"],
                job_id=row["job_id"],
                sequence=row["sequence"],
                event_type=row["event_type"],
                payload=json.loads(row["payload_json"]),
                previous_hash=row["previous_hash"],
                record_hash=row["record_hash"],
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]

    def set_emergency_stop(self, enabled: bool) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO system_state (key, value) VALUES ('emergency_stop', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                ("true" if enabled else "false",),
            )

    def is_emergency_stopped(self) -> bool:
        with self._lock:
            row = self._connection.execute(
                "SELECT value FROM system_state WHERE key = 'emergency_stop'"
            ).fetchone()
        return row is not None and row["value"] == "true"

    def set_job_cancel_requested(self, job_id: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO system_state (key, value) VALUES (?, 'true')
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (f"cancel:{job_id}",),
            )

    def _invalidate_job_approvals_locked(
        self,
        job_id: str,
        *,
        invalidated_by: str,
        now: datetime,
    ) -> list[str]:
        rows = self._connection.execute(
            """
            SELECT id, record_json
            FROM approvals
            WHERE job_id = ? AND status IN (?, ?)
            """,
            (
                job_id,
                ApprovalStatus.PENDING.value,
                ApprovalStatus.APPROVED.value,
            ),
        ).fetchall()
        invalidated: list[str] = []
        for row in rows:
            approval = ApprovalRecord.model_validate_json(row["record_json"])
            approval.status = ApprovalStatus.INVALIDATED
            approval.invalidated_by = invalidated_by
            approval.invalidated_at = now
            updated = self._connection.execute(
                """
                UPDATE approvals
                SET status = ?, record_json = ?
                WHERE id = ? AND status IN (?, ?)
                """,
                (
                    approval.status.value,
                    approval.model_dump_json(),
                    approval.id,
                    ApprovalStatus.PENDING.value,
                    ApprovalStatus.APPROVED.value,
                ),
            )
            if updated.rowcount == 1:
                invalidated.append(approval.id)
        return invalidated

    def _cancel_job_locked(
        self,
        job_id: str,
        *,
        requested_by: str,
        now: datetime,
    ) -> tuple[JobRecord, JobStatus | None, list[str]]:
        row = self._connection.execute(
            "SELECT record_json FROM jobs WHERE id = ?",
            (job_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"job not found: {job_id}")
        job = JobRecord.model_validate_json(row["record_json"])
        self._connection.execute(
            """
            INSERT INTO system_state (key, value) VALUES (?, 'true')
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (f"cancel:{job.id}",),
        )
        if job.status in TERMINAL_STATES:
            invalidated = self._invalidate_job_approvals_locked(
                job.id,
                invalidated_by=requested_by,
                now=now,
            )
            return job, None, invalidated

        previous_status = job.status
        job.status = JobStatus.CANCELED
        job.updated_at = now
        if job.recovery_package is not None and job.recovery_package.status in {
            RecoveryStatus.AWAITING_APPROVAL,
            RecoveryStatus.APPROVED,
            RecoveryStatus.CAPTURING,
        }:
            job.recovery_package.status = RecoveryStatus.BLOCKED
            job.recovery_package.blocker_codes = sorted(
                {
                    *job.recovery_package.blocker_codes,
                    "job_canceled",
                }
            )
            job.recovery_package.updated_at = now

        invalidated = self._invalidate_job_approvals_locked(
            job.id,
            invalidated_by=requested_by,
            now=now,
        )
        self._connection.execute(
            """
            UPDATE jobs
            SET status = ?, record_json = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                job.status.value,
                canonical_json(job.model_dump(mode="json")),
                job.updated_at.isoformat(),
                job.id,
            ),
        )
        return job, previous_status, invalidated

    def cancel_job_atomically(
        self,
        job_id: str,
        *,
        requested_by: str,
        now: datetime,
    ) -> tuple[JobRecord, JobStatus | None, list[str]]:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                result = self._cancel_job_locked(
                    job_id,
                    requested_by=requested_by,
                    now=now,
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return result

    def emergency_stop_and_cancel_jobs(
        self,
        *,
        requested_by: str,
        now: datetime,
    ) -> list[tuple[JobRecord, JobStatus, list[str]]]:
        terminal = tuple(state.value for state in TERMINAL_STATES)
        placeholders = ",".join("?" for _ in terminal)
        results: list[tuple[JobRecord, JobStatus, list[str]]] = []
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    """
                    INSERT INTO system_state (key, value)
                    VALUES ('emergency_stop', 'true')
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """
                )
                rows = self._connection.execute(
                    f"SELECT id FROM jobs WHERE status NOT IN ({placeholders})",
                    terminal,
                ).fetchall()
                for row in rows:
                    job, previous_status, invalidated = self._cancel_job_locked(
                        str(row["id"]),
                        requested_by=requested_by,
                        now=now,
                    )
                    if previous_status is not None:
                        results.append((job, previous_status, invalidated))
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return results

    def is_job_cancel_requested(self, job_id: str) -> bool:
        with self._lock:
            row = self._connection.execute(
                "SELECT value FROM system_state WHERE key = ?",
                (f"cancel:{job_id}",),
            ).fetchone()
        return row is not None and row["value"] == "true"
