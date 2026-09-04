"""PostgreSQL persistence adapter for durable Test Worlds."""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from typing import Any

from .test_world import (
    AttemptMode,
    AttemptStatus,
    TestCheck,
    TestWorld,
    TestWorldAttempt,
    TestWorldConflict,
    TestWorldLease,
    TestWorldLimitReached,
    TestWorldNotFound,
    WorldStatus,
    _has_complete_pass_proof,
    _judge_version,
    _validate_duration,
    _validate_feedback,
    _validate_world_definition,
    _world_fingerprint,
)


_WORLD_COLUMNS = (
    "id,owner_id,name,objective,repository_url,source_commit,checks,max_attempts,status,"
    "world_fingerprint,judge_version,extract(epoch from created_at),extract(epoch from updated_at)"
)
_ATTEMPT_COLUMNS = (
    "id,world_id,owner_id,attempt_number,status,attempt_mode,world_fingerprint,judge_version,outcome,"
    "previous_attempt_id,feedback,cumulative_patch,plan,summary,tests,model_calls,input_tokens,"
    "output_tokens,total_tokens,duration_ms,judge_duration_ms,extract(epoch from created_at),"
    "extract(epoch from started_at),extract(epoch from finished_at)"
)


def _json_value(value: Any) -> Any:
    if isinstance(value, str):
        return json.loads(value)
    return value


def _world_from_row(row: Sequence[Any]) -> TestWorld:
    checks_value = _json_value(row[6]) or []
    checks = tuple(
        TestCheck(
            str(item["name"]),
            tuple(str(part) for part in item["command"]),
            int(item.get("timeoutSeconds", 120)),
        )
        for item in checks_value
    )
    return TestWorld(
        id=str(row[0]),
        owner_id=str(row[1]),
        name=str(row[2]),
        objective=str(row[3]),
        repository_url=str(row[4]),
        commit=str(row[5]),
        checks=checks,
        max_attempts=int(row[7]),
        status=WorldStatus(str(row[8])),
        fingerprint=str(row[9]),
        judge_version=str(row[10]),
        created_at=float(row[11]),
        updated_at=float(row[12]),
    )


def _attempt_from_row(row: Sequence[Any]) -> TestWorldAttempt:
    feedback_value = _json_value(row[10]) or []
    return TestWorldAttempt(
        id=str(row[0]),
        world_id=str(row[1]),
        owner_id=str(row[2]),
        number=int(row[3]),
        status=AttemptStatus(str(row[4])),
        mode=AttemptMode(str(row[5])),
        world_fingerprint=str(row[6]),
        judge_version=str(row[7]),
        outcome=None if row[8] is None else str(row[8]),
        previous_attempt_id=None if row[9] is None else str(row[9]),
        feedback=tuple(dict(item) for item in feedback_value),
        cumulative_patch=str(row[11] or ""),
        plan=str(row[12] or ""),
        summary=str(row[13] or ""),
        tests=str(row[14] or ""),
        model_calls=int(row[15] or 0),
        input_tokens=int(row[16] or 0),
        output_tokens=int(row[17] or 0),
        total_tokens=int(row[18] or 0),
        duration_ms=int(row[19] or 0),
        judge_duration_ms=int(row[20] or 0),
        created_at=float(row[21]),
        started_at=None if row[22] is None else float(row[22]),
        finished_at=None if row[23] is None else float(row[23]),
    )


class PostgresTestWorldStore:
    """Durable Test World adapter using a psycopg-compatible connection factory."""

    def __init__(self, connection_factory: Callable[[], Any]) -> None:
        self._connect = connection_factory

    def _fetch_world(self, cursor: Any, world_id: str, owner_id: str, *, for_update: bool = False) -> TestWorld:
        cursor.execute(
            f"SELECT {_WORLD_COLUMNS} FROM lil_tweak_test_worlds WHERE id=%s AND owner_id=%s"
            + (" FOR UPDATE" if for_update else ""),
            (world_id, owner_id),
        )
        row = cursor.fetchone()
        if row is None:
            raise TestWorldNotFound("world not found")
        return _world_from_row(row)

    def _fetch_attempt(self, cursor: Any, attempt_id: str, owner_id: str, *, for_update: bool = False) -> TestWorldAttempt:
        cursor.execute(
            f"SELECT {_ATTEMPT_COLUMNS} FROM lil_tweak_test_world_attempts WHERE id=%s AND owner_id=%s"
            + (" FOR UPDATE" if for_update else ""),
            (attempt_id, owner_id),
        )
        row = cursor.fetchone()
        if row is None:
            raise TestWorldNotFound("attempt not found")
        return _attempt_from_row(row)

    def create_world(
        self,
        owner_id: str,
        *,
        idempotency_key: str,
        name: str,
        objective: str,
        repository_url: str,
        commit: str,
        checks: Sequence[TestCheck],
        max_attempts: int = 5,
    ) -> TestWorld:
        check_tuple = _validate_world_definition(
            owner_id,
            idempotency_key,
            name,
            objective,
            repository_url,
            commit,
            checks,
            max_attempts,
        )
        fingerprint = _world_fingerprint(name, objective, repository_url, commit, check_tuple, max_attempts)
        judge_version = _judge_version(check_tuple)
        identity = f"test-world-create\n{owner_id}\n{idempotency_key}"
        checks_json = json.dumps(
            [
                {"name": item.name, "command": list(item.command), "timeoutSeconds": item.timeout_seconds}
                for item in check_tuple
            ],
            separators=(",", ":"),
        )
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (identity,))
            cursor.execute(
                "SELECT id,request_hash FROM lil_tweak_test_worlds "
                "WHERE owner_id=%s AND create_idempotency_key=%s FOR UPDATE",
                (owner_id, idempotency_key),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if str(existing[1]) != fingerprint:
                    raise TestWorldConflict("idempotency key reused")
                return self._fetch_world(cursor, str(existing[0]), owner_id)
            world_id = f"world:{uuid.uuid4().hex}"
            cursor.execute(
                "INSERT INTO lil_tweak_test_worlds "
                "(id,owner_id,name,objective,repository_url,source_commit,checks,max_attempts,status,"
                "world_fingerprint,judge_version,create_idempotency_key,request_hash) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s,'ready',%s,%s,%s,%s)",
                (
                    world_id,
                    owner_id,
                    name.strip(),
                    objective.strip(),
                    repository_url,
                    commit,
                    checks_json,
                    max_attempts,
                    fingerprint,
                    judge_version,
                    idempotency_key,
                    fingerprint,
                ),
            )
            return self._fetch_world(cursor, world_id, owner_id)

    def list_worlds(self, owner_id: str, *, limit: int = 20) -> list[TestWorld]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("invalid world limit")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT {_WORLD_COLUMNS} FROM lil_tweak_test_worlds WHERE owner_id=%s "
                "ORDER BY updated_at DESC,created_at DESC,id DESC LIMIT %s",
                (owner_id, limit),
            )
            return [_world_from_row(row) for row in cursor.fetchall()]

    def get_world(self, world_id: str, owner_id: str) -> TestWorld | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT {_WORLD_COLUMNS} FROM lil_tweak_test_worlds WHERE id=%s AND owner_id=%s",
                (world_id, owner_id),
            )
            row = cursor.fetchone()
            return None if row is None else _world_from_row(row)

    def list_attempts(self, world_id: str, owner_id: str) -> list[TestWorldAttempt]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM lil_tweak_test_worlds WHERE id=%s AND owner_id=%s", (world_id, owner_id))
            if cursor.fetchone() is None:
                raise TestWorldNotFound("world not found")
            cursor.execute(
                f"SELECT {_ATTEMPT_COLUMNS} FROM lil_tweak_test_world_attempts "
                "WHERE world_id=%s AND owner_id=%s ORDER BY attempt_number ASC",
                (world_id, owner_id),
            )
            return [_attempt_from_row(row) for row in cursor.fetchall()]

    def get_attempt(self, attempt_id: str, owner_id: str) -> TestWorldAttempt | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT {_ATTEMPT_COLUMNS} FROM lil_tweak_test_world_attempts WHERE id=%s AND owner_id=%s",
                (attempt_id, owner_id),
            )
            row = cursor.fetchone()
            return None if row is None else _attempt_from_row(row)

    def enqueue_attempt(
        self,
        world_id: str,
        owner_id: str,
        *,
        idempotency_key: str,
        mode: AttemptMode | str = AttemptMode.RETRY,
    ) -> TestWorldAttempt:
        if not idempotency_key or len(idempotency_key.encode("utf-8")) > 200:
            raise ValueError("invalid idempotency key")
        try:
            attempt_mode = AttemptMode(mode)
        except (TypeError, ValueError):
            raise ValueError("invalid attempt mode") from None
        identity = f"test-world-attempt\n{owner_id}\n{idempotency_key}"
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (identity,))
            cursor.execute(
                "SELECT id,world_id,attempt_mode FROM lil_tweak_test_world_attempts "
                "WHERE owner_id=%s AND attempt_idempotency_key=%s FOR UPDATE",
                (owner_id, idempotency_key),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if str(existing[1]) != world_id or str(existing[2]) != attempt_mode.value:
                    raise TestWorldConflict("idempotency key reused")
                return self._fetch_attempt(cursor, str(existing[0]), owner_id)
            world = self._fetch_world(cursor, world_id, owner_id, for_update=True)
            if world.status in {WorldStatus.PASSED, WorldStatus.EXHAUSTED, WorldStatus.BLOCKED}:
                raise TestWorldLimitReached("world cannot accept another attempt")
            cursor.execute(
                "SELECT id,attempt_number,status FROM lil_tweak_test_world_attempts "
                "WHERE world_id=%s AND owner_id=%s ORDER BY attempt_number DESC FOR UPDATE",
                (world_id, owner_id),
            )
            rows = cursor.fetchall()
            if any(str(row[2]) in {AttemptStatus.QUEUED.value, AttemptStatus.RUNNING.value} for row in rows):
                raise TestWorldConflict("world already has an active attempt")
            if len(rows) >= world.max_attempts:
                raise TestWorldLimitReached("attempt budget exhausted")
            attempt_number = len(rows) + 1
            previous_attempt_id = None if not rows else str(rows[0][0])
            attempt_id = f"attempt:{uuid.uuid4().hex}"
            cursor.execute(
                "INSERT INTO lil_tweak_test_world_attempts "
                "(id,world_id,owner_id,attempt_number,status,attempt_mode,world_fingerprint,judge_version,expected_check_count,"
                "previous_attempt_id,attempt_idempotency_key) "
                "VALUES (%s,%s,%s,%s,'queued',%s,%s,%s,%s,%s,%s)",
                (
                    attempt_id,
                    world_id,
                    owner_id,
                    attempt_number,
                    attempt_mode.value,
                    world.fingerprint,
                    world.judge_version,
                    len(world.checks),
                    previous_attempt_id,
                    idempotency_key,
                ),
            )
            cursor.execute(
                "UPDATE lil_tweak_test_worlds SET status='running',updated_at=now() WHERE id=%s AND owner_id=%s",
                (world_id, owner_id),
            )
            return self._fetch_attempt(cursor, attempt_id, owner_id)

    def list_schedulable_attempts(self, *, now: float | None = None, limit: int = 10) -> list[TestWorldAttempt]:
        current_time = time.time() if now is None else now
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValueError("invalid scheduler limit")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT {_ATTEMPT_COLUMNS} FROM lil_tweak_test_world_attempts "
                "WHERE status='queued' AND (lease_expires_at IS NULL OR lease_expires_at<=to_timestamp(%s)) "
                "ORDER BY created_at ASC,id ASC LIMIT %s",
                (current_time, limit),
            )
            return [_attempt_from_row(row) for row in cursor.fetchall()]

    def reconcile_active_attempts(self, *, now: float | None = None, limit: int = 100) -> list[TestWorldAttempt]:
        current_time = time.time() if now is None else now
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValueError("invalid scheduler limit")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "WITH candidates AS (SELECT id FROM lil_tweak_test_world_attempts "
                "WHERE status='running' AND (lease_expires_at IS NULL OR lease_expires_at<=to_timestamp(%s)) "
                "ORDER BY created_at ASC,id ASC LIMIT %s FOR UPDATE SKIP LOCKED) "
                "UPDATE lil_tweak_test_world_attempts AS a SET status='queued',started_at=NULL,"
                "lease_owner=NULL,lease_expires_at=NULL FROM candidates c WHERE a.id=c.id RETURNING a.id,a.world_id,a.owner_id",
                (current_time, limit),
            )
            recovered = cursor.fetchall()
            result: list[TestWorldAttempt] = []
            for attempt_id, world_id, owner_id in recovered:
                cursor.execute(
                    "UPDATE lil_tweak_test_worlds SET status='running',updated_at=to_timestamp(%s) WHERE id=%s AND owner_id=%s",
                    (current_time, world_id, owner_id),
                )
                result.append(self._fetch_attempt(cursor, str(attempt_id), str(owner_id)))
            return result

    def claim_attempt(self, attempt_id: str, worker_id: str, *, lease_seconds: int, now: float | None = None) -> TestWorldLease | None:
        current_time = time.time() if now is None else now
        if not worker_id or lease_seconds <= 0:
            raise ValueError("invalid lease")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "UPDATE lil_tweak_test_world_attempts SET status='running',lease_owner=%s,"
                "lease_generation=lease_generation+1,lease_expires_at=to_timestamp(%s),"
                "started_at=COALESCE(started_at,to_timestamp(%s)) "
                "WHERE id=%s AND status='queued' AND (lease_expires_at IS NULL OR lease_expires_at<=to_timestamp(%s)) "
                "RETURNING world_id,owner_id,lease_generation,extract(epoch from lease_expires_at)",
                (worker_id, current_time + lease_seconds, current_time, attempt_id, current_time),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            cursor.execute(
                "UPDATE lil_tweak_test_worlds SET status='running',updated_at=to_timestamp(%s) WHERE id=%s AND owner_id=%s",
                (current_time, row[0], row[1]),
            )
            return TestWorldLease(
                attempt_id=attempt_id,
                world_id=str(row[0]),
                owner_id=str(row[1]),
                worker_id=worker_id,
                generation=int(row[2]),
                expires_at=float(row[3]),
            )

    def renew_attempt(self, lease: TestWorldLease, *, lease_seconds: int, now: float | None = None) -> TestWorldLease:
        current_time = time.time() if now is None else now
        if lease_seconds <= 0:
            raise ValueError("invalid lease")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "UPDATE lil_tweak_test_world_attempts SET lease_expires_at=to_timestamp(%s) "
                "WHERE id=%s AND world_id=%s AND owner_id=%s AND lease_owner=%s AND lease_generation=%s "
                "AND status='running' AND lease_expires_at>to_timestamp(%s) RETURNING extract(epoch from lease_expires_at)",
                (
                    current_time + lease_seconds,
                    lease.attempt_id,
                    lease.world_id,
                    lease.owner_id,
                    lease.worker_id,
                    lease.generation,
                    current_time,
                ),
            )
            row = cursor.fetchone()
            if row is None:
                raise TestWorldConflict("stale attempt lease")
            return replace(lease, expires_at=float(row[0]))

    def release_attempt(self, lease: TestWorldLease) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "UPDATE lil_tweak_test_world_attempts SET lease_owner=NULL,lease_expires_at=NULL "
                "WHERE id=%s AND owner_id=%s AND lease_owner=%s AND lease_generation=%s",
                (lease.attempt_id, lease.owner_id, lease.worker_id, lease.generation),
            )

    def complete_attempt(
        self,
        lease: TestWorldLease,
        *,
        passed: bool,
        feedback: Sequence[Mapping[str, Any]],
        cumulative_patch: str,
        plan: str = "",
        summary: str = "",
        tests: str = "",
        model_calls: int = 0,
        input_tokens: int = 0,
        output_tokens: int = 0,
        total_tokens: int = 0,
        duration_ms: int = 0,
        judge_duration_ms: int = 0,
        now: float | None = None,
    ) -> TestWorldAttempt:
        current_time = time.time() if now is None else now
        if not isinstance(passed, bool) or not isinstance(cumulative_patch, str) or len(cumulative_patch.encode("utf-8")) > 2 * 1024 * 1024:
            raise ValueError("invalid attempt result")
        bounded_feedback = _validate_feedback(feedback)
        duration_ms = _validate_duration(duration_ms, "duration")
        judge_duration_ms = _validate_duration(judge_duration_ms, "judge duration")
        if judge_duration_ms > duration_ms and duration_ms != 0:
            raise ValueError("judge duration exceeds attempt duration")
        if any(not isinstance(value, str) or len(value.encode("utf-8")) > 64 * 1024 for value in (plan, summary, tests)):
            raise ValueError("invalid attempt text")
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in (model_calls, input_tokens, output_tokens, total_tokens)):
            raise ValueError("invalid attempt usage")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT world_id,owner_id,attempt_number,world_fingerprint,judge_version FROM lil_tweak_test_world_attempts "
                "WHERE id=%s AND world_id=%s AND owner_id=%s AND status='running' AND lease_owner=%s "
                "AND lease_generation=%s FOR UPDATE",
                (lease.attempt_id, lease.world_id, lease.owner_id, lease.worker_id, lease.generation),
            )
            row = cursor.fetchone()
            if row is None:
                raise TestWorldConflict("stale attempt lease")
            world = self._fetch_world(cursor, lease.world_id, lease.owner_id, for_update=True)
            if str(row[3]) != world.fingerprint or str(row[4]) != world.judge_version:
                raise TestWorldConflict("attempt challenge version mismatch")
            if passed and not _has_complete_pass_proof(world, bounded_feedback):
                raise TestWorldConflict("pass requires complete judge proof")
            status = AttemptStatus.PASSED if passed else AttemptStatus.FAILED
            outcome = "pass" if passed else "fail"
            cursor.execute(
                "UPDATE lil_tweak_test_world_attempts SET status=%s,outcome=%s,feedback=%s::jsonb,"
                "cumulative_patch=%s,plan=%s,summary=%s,tests=%s,model_calls=%s,input_tokens=%s,"
                "output_tokens=%s,total_tokens=%s,duration_ms=%s,judge_duration_ms=%s,"
                "finished_at=to_timestamp(%s),lease_owner=NULL,lease_expires_at=NULL "
                "WHERE id=%s AND owner_id=%s AND lease_generation=%s",
                (
                    status.value,
                    outcome,
                    json.dumps(list(bounded_feedback), separators=(",", ":")),
                    cumulative_patch,
                    plan,
                    summary,
                    tests,
                    model_calls,
                    input_tokens,
                    output_tokens,
                    total_tokens,
                    duration_ms,
                    judge_duration_ms,
                    current_time,
                    lease.attempt_id,
                    lease.owner_id,
                    lease.generation,
                ),
            )
            if cursor.rowcount != 1:
                raise TestWorldConflict("stale attempt lease")
            world_status = WorldStatus.PASSED if passed else (
                WorldStatus.EXHAUSTED if int(row[2]) >= world.max_attempts else WorldStatus.FAILED
            )
            cursor.execute(
                "UPDATE lil_tweak_test_worlds SET status=%s,updated_at=to_timestamp(%s) WHERE id=%s AND owner_id=%s",
                (world_status.value, current_time, lease.world_id, lease.owner_id),
            )
            return self._fetch_attempt(cursor, lease.attempt_id, lease.owner_id)

    def fail_attempt(
        self,
        lease: TestWorldLease,
        *,
        feedback: Sequence[Mapping[str, Any]],
        summary: str = "",
        blocked: bool = False,
        duration_ms: int = 0,
        now: float | None = None,
    ) -> TestWorldAttempt:
        current_time = time.time() if now is None else now
        bounded_feedback = _validate_feedback(feedback)
        duration_ms = _validate_duration(duration_ms, "duration")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT attempt_number FROM lil_tweak_test_world_attempts WHERE id=%s AND world_id=%s "
                "AND owner_id=%s AND status='running' AND lease_owner=%s AND lease_generation=%s FOR UPDATE",
                (lease.attempt_id, lease.world_id, lease.owner_id, lease.worker_id, lease.generation),
            )
            row = cursor.fetchone()
            if row is None:
                raise TestWorldConflict("stale attempt lease")
            world = self._fetch_world(cursor, lease.world_id, lease.owner_id, for_update=True)
            cursor.execute(
                "UPDATE lil_tweak_test_world_attempts SET status='error',outcome='error',feedback=%s::jsonb,"
                "summary=%s,duration_ms=%s,finished_at=to_timestamp(%s),lease_owner=NULL,lease_expires_at=NULL "
                "WHERE id=%s AND owner_id=%s AND lease_generation=%s",
                (
                    json.dumps(list(bounded_feedback), separators=(",", ":")),
                    summary,
                    duration_ms,
                    current_time,
                    lease.attempt_id,
                    lease.owner_id,
                    lease.generation,
                ),
            )
            world_status = WorldStatus.BLOCKED if blocked else (
                WorldStatus.EXHAUSTED if int(row[0]) >= world.max_attempts else WorldStatus.FAILED
            )
            cursor.execute(
                "UPDATE lil_tweak_test_worlds SET status=%s,updated_at=to_timestamp(%s) WHERE id=%s AND owner_id=%s",
                (world_status.value, current_time, lease.world_id, lease.owner_id),
            )
            return self._fetch_attempt(cursor, lease.attempt_id, lease.owner_id)
