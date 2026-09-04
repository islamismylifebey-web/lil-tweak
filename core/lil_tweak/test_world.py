"""Durable Test World domain contracts and in-memory executable store."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Protocol


_WORLD_ID = re.compile(r"^world:[0-9a-f]{32}$")
_ATTEMPT_ID = re.compile(r"^attempt:[0-9a-f]{32}$")
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_MAX_PATCH_BYTES = 2 * 1024 * 1024
_MAX_FEEDBACK_BYTES = 256 * 1024
_MAX_DURATION_MS = 24 * 60 * 60 * 1000


class TestWorldError(RuntimeError):
    code = "test_world_error"


class TestWorldConflict(TestWorldError):
    code = "test_world_conflict"


class TestWorldNotFound(TestWorldError):
    code = "test_world_not_found"


class TestWorldLimitReached(TestWorldError):
    code = "test_world_limit_reached"


class WorldStatus(str, Enum):
    READY = "ready"
    RUNNING = "running"
    FAILED = "failed"
    PASSED = "passed"
    EXHAUSTED = "exhausted"
    BLOCKED = "blocked"


class AttemptStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


class AttemptMode(str, Enum):
    RETRY = "retry"
    FRESH = "fresh"


@dataclass(frozen=True, slots=True)
class TestCheck:
    name: str
    command: tuple[str, ...]
    timeout_seconds: int = 120

    def __post_init__(self) -> None:
        if (
            not isinstance(self.name, str)
            or not self.name.strip()
            or len(self.name.encode("utf-8")) > 200
            or not isinstance(self.command, tuple)
            or not 1 <= len(self.command) <= 128
            or any(
                not isinstance(part, str)
                or not part
                or len(part.encode("utf-8")) > 4096
                for part in self.command
            )
            or not isinstance(self.timeout_seconds, int)
            or isinstance(self.timeout_seconds, bool)
            or not 1 <= self.timeout_seconds <= 1200
        ):
            raise ValueError("invalid test check")


@dataclass(frozen=True, slots=True)
class TestWorld:
    id: str
    owner_id: str
    name: str
    objective: str
    repository_url: str
    commit: str
    checks: tuple[TestCheck, ...]
    max_attempts: int
    status: WorldStatus
    fingerprint: str
    judge_version: str
    created_at: float
    updated_at: float


@dataclass(frozen=True, slots=True)
class TestWorldAttempt:
    id: str
    world_id: str
    owner_id: str
    number: int
    status: AttemptStatus
    world_fingerprint: str
    judge_version: str
    mode: AttemptMode = AttemptMode.RETRY
    outcome: str | None = None
    previous_attempt_id: str | None = None
    feedback: tuple[Mapping[str, Any], ...] = ()
    cumulative_patch: str = ""
    plan: str = ""
    summary: str = ""
    tests: str = ""
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    duration_ms: int = 0
    judge_duration_ms: int = 0
    created_at: float = 0.0
    started_at: float | None = None
    finished_at: float | None = None


@dataclass(frozen=True, slots=True)
class TestWorldLease:
    attempt_id: str
    world_id: str
    owner_id: str
    worker_id: str
    generation: int
    expires_at: float


class TestWorldStore(Protocol):
    def create_world(self, owner_id: str, **fields: Any) -> TestWorld: ...
    def list_worlds(self, owner_id: str, *, limit: int = 20) -> list[TestWorld]: ...
    def get_world(self, world_id: str, owner_id: str) -> TestWorld | None: ...
    def list_attempts(self, world_id: str, owner_id: str) -> list[TestWorldAttempt]: ...
    def get_attempt(self, attempt_id: str, owner_id: str) -> TestWorldAttempt | None: ...
    def enqueue_attempt(
        self,
        world_id: str,
        owner_id: str,
        *,
        idempotency_key: str,
        mode: AttemptMode | str = AttemptMode.RETRY,
    ) -> TestWorldAttempt: ...
    def list_schedulable_attempts(self, *, now: float | None = None, limit: int = 10) -> list[TestWorldAttempt]: ...
    def reconcile_active_attempts(self, *, now: float | None = None, limit: int = 100) -> list[TestWorldAttempt]: ...
    def claim_attempt(self, attempt_id: str, worker_id: str, *, lease_seconds: int, now: float | None = None) -> TestWorldLease | None: ...
    def renew_attempt(self, lease: TestWorldLease, *, lease_seconds: int, now: float | None = None) -> TestWorldLease: ...
    def release_attempt(self, lease: TestWorldLease) -> None: ...
    def complete_attempt(self, lease: TestWorldLease, **fields: Any) -> TestWorldAttempt: ...
    def fail_attempt(self, lease: TestWorldLease, **fields: Any) -> TestWorldAttempt: ...


def _judge_version(checks: tuple[TestCheck, ...]) -> str:
    payload = [
        {"name": item.name, "command": list(item.command), "timeout_seconds": item.timeout_seconds}
        for item in checks
    ]
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b"lil-tweak-test-world-judge-v1\0" + encoded).hexdigest()


def _world_fingerprint(
    name: str,
    objective: str,
    repository_url: str,
    commit: str,
    checks: tuple[TestCheck, ...],
    max_attempts: int,
) -> str:
    payload = {
        "name": name,
        "objective": objective,
        "repository_url": repository_url,
        "commit": commit,
        "checks": [
            {"name": item.name, "command": list(item.command), "timeout_seconds": item.timeout_seconds}
            for item in checks
        ],
        "max_attempts": max_attempts,
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(b"lil-tweak-test-world-v1\0" + encoded).hexdigest()


def _copy_world(world: TestWorld) -> TestWorld:
    return replace(world, checks=tuple(world.checks))


def _copy_attempt(attempt: TestWorldAttempt) -> TestWorldAttempt:
    return replace(attempt, feedback=tuple(copy.deepcopy(dict(item)) for item in attempt.feedback))


def _validate_world_definition(
    owner_id: str,
    idempotency_key: str,
    name: str,
    objective: str,
    repository_url: str,
    commit: str,
    checks: Sequence[TestCheck],
    max_attempts: int,
) -> tuple[TestCheck, ...]:
    check_tuple = tuple(checks)
    if (
        not isinstance(owner_id, str)
        or not owner_id
        or not isinstance(idempotency_key, str)
        or not idempotency_key
        or len(idempotency_key.encode("utf-8")) > 200
        or not isinstance(name, str)
        or not name.strip()
        or len(name.encode("utf-8")) > 240
        or not isinstance(objective, str)
        or not objective.strip()
        or len(objective.encode("utf-8")) > 16_000
        or not isinstance(repository_url, str)
        or not repository_url.startswith("https://")
        or len(repository_url.encode("utf-8")) > 2048
        or not isinstance(commit, str)
        or _COMMIT.fullmatch(commit) is None
        or not 1 <= len(check_tuple) <= 8
        or any(not isinstance(item, TestCheck) for item in check_tuple)
        or not isinstance(max_attempts, int)
        or isinstance(max_attempts, bool)
        or not 1 <= max_attempts <= 10
    ):
        raise ValueError("invalid test world definition")
    return check_tuple


def _validate_feedback(feedback: Sequence[Mapping[str, Any]]) -> tuple[Mapping[str, Any], ...]:
    value = tuple(copy.deepcopy(dict(item)) for item in feedback)
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("invalid test world feedback") from None
    if len(encoded) > _MAX_FEEDBACK_BYTES:
        raise ValueError("test world feedback too large")
    return value


def _validate_duration(value: int, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= _MAX_DURATION_MS:
        raise ValueError(f"invalid {field}")
    return value


def _has_complete_pass_proof(world: TestWorld, feedback: tuple[Mapping[str, Any], ...]) -> bool:
    if len(feedback) != len(world.checks):
        return False
    for check, item in zip(world.checks, feedback, strict=True):
        if item.get("check") != check.name or item.get("passed") is not True:
            return False
    return True


class MemoryTestWorldStore:
    """Thread-safe executable Test World contract for tests and local use."""

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.RLock()
        self._worlds: dict[str, TestWorld] = {}
        self._attempts: dict[str, TestWorldAttempt] = {}
        self._attempt_ids: dict[str, list[str]] = {}
        self._world_idempotency: dict[tuple[str, str], tuple[str, str]] = {}
        self._attempt_idempotency: dict[tuple[str, str], tuple[str, str, AttemptMode]] = {}
        self._claims: dict[str, TestWorldLease] = {}
        self._generations: dict[str, int] = {}

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
        identity = (owner_id, idempotency_key)
        with self._lock:
            existing = self._world_idempotency.get(identity)
            if existing is not None:
                world_id, previous = existing
                if previous != fingerprint:
                    raise TestWorldConflict("idempotency key reused")
                return _copy_world(self._worlds[world_id])
            now = self._clock()
            world = TestWorld(
                id=f"world:{uuid.uuid4().hex}",
                owner_id=owner_id,
                name=name.strip(),
                objective=objective.strip(),
                repository_url=repository_url,
                commit=commit,
                checks=check_tuple,
                max_attempts=max_attempts,
                status=WorldStatus.READY,
                fingerprint=fingerprint,
                judge_version=judge_version,
                created_at=now,
                updated_at=now,
            )
            self._worlds[world.id] = world
            self._attempt_ids[world.id] = []
            self._world_idempotency[identity] = (world.id, fingerprint)
            return _copy_world(world)

    def list_worlds(self, owner_id: str, *, limit: int = 20) -> list[TestWorld]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("invalid world limit")
        with self._lock:
            values = [item for item in self._worlds.values() if item.owner_id == owner_id]
            values.sort(key=lambda item: (item.updated_at, item.created_at, item.id), reverse=True)
            return [_copy_world(item) for item in values[:limit]]

    def get_world(self, world_id: str, owner_id: str) -> TestWorld | None:
        with self._lock:
            world = self._worlds.get(world_id)
            if world is None or world.owner_id != owner_id:
                return None
            return _copy_world(world)

    def list_attempts(self, world_id: str, owner_id: str) -> list[TestWorldAttempt]:
        with self._lock:
            world = self._worlds.get(world_id)
            if world is None or world.owner_id != owner_id:
                raise TestWorldNotFound("world not found")
            return [_copy_attempt(self._attempts[item]) for item in self._attempt_ids[world_id]]

    def get_attempt(self, attempt_id: str, owner_id: str) -> TestWorldAttempt | None:
        with self._lock:
            attempt = self._attempts.get(attempt_id)
            if attempt is None or attempt.owner_id != owner_id:
                return None
            return _copy_attempt(attempt)

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
        identity = (owner_id, idempotency_key)
        with self._lock:
            previous = self._attempt_idempotency.get(identity)
            if previous is not None:
                previous_world_id, attempt_id, previous_mode = previous
                if previous_world_id != world_id or previous_mode is not attempt_mode:
                    raise TestWorldConflict("idempotency key reused")
                return _copy_attempt(self._attempts[attempt_id])
            world = self._worlds.get(world_id)
            if world is None or world.owner_id != owner_id:
                raise TestWorldNotFound("world not found")
            if world.status in {WorldStatus.PASSED, WorldStatus.EXHAUSTED, WorldStatus.BLOCKED}:
                raise TestWorldLimitReached("world cannot accept another attempt")
            attempt_ids = self._attempt_ids[world_id]
            if any(self._attempts[item].status in {AttemptStatus.QUEUED, AttemptStatus.RUNNING} for item in attempt_ids):
                raise TestWorldConflict("world already has an active attempt")
            if len(attempt_ids) >= world.max_attempts:
                raise TestWorldLimitReached("attempt budget exhausted")
            now = self._clock()
            previous_attempt_id = attempt_ids[-1] if attempt_ids else None
            attempt = TestWorldAttempt(
                id=f"attempt:{uuid.uuid4().hex}",
                world_id=world_id,
                owner_id=owner_id,
                number=len(attempt_ids) + 1,
                status=AttemptStatus.QUEUED,
                world_fingerprint=world.fingerprint,
                judge_version=world.judge_version,
                mode=attempt_mode,
                previous_attempt_id=previous_attempt_id,
                created_at=now,
            )
            self._attempts[attempt.id] = attempt
            attempt_ids.append(attempt.id)
            self._attempt_idempotency[identity] = (world_id, attempt.id, attempt_mode)
            self._worlds[world_id] = replace(world, status=WorldStatus.RUNNING, updated_at=now)
            return _copy_attempt(attempt)

    def list_schedulable_attempts(self, *, now: float | None = None, limit: int = 10) -> list[TestWorldAttempt]:
        current_time = self._clock() if now is None else now
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValueError("invalid scheduler limit")
        with self._lock:
            result: list[TestWorldAttempt] = []
            for attempt in sorted(self._attempts.values(), key=lambda item: (item.created_at, item.id)):
                claim = self._claims.get(attempt.id)
                if attempt.status is AttemptStatus.QUEUED and (claim is None or claim.expires_at <= current_time):
                    result.append(_copy_attempt(attempt))
                    if len(result) == limit:
                        break
            return result

    def reconcile_active_attempts(self, *, now: float | None = None, limit: int = 100) -> list[TestWorldAttempt]:
        current_time = self._clock() if now is None else now
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValueError("invalid scheduler limit")
        recovered: list[TestWorldAttempt] = []
        with self._lock:
            for attempt in sorted(self._attempts.values(), key=lambda item: (item.created_at, item.id)):
                if len(recovered) >= limit or attempt.status is not AttemptStatus.RUNNING:
                    continue
                claim = self._claims.get(attempt.id)
                if claim is not None and claim.expires_at > current_time:
                    continue
                queued = replace(attempt, status=AttemptStatus.QUEUED, started_at=None)
                self._attempts[attempt.id] = queued
                self._claims.pop(attempt.id, None)
                world = self._worlds[attempt.world_id]
                self._worlds[world.id] = replace(world, status=WorldStatus.RUNNING, updated_at=current_time)
                recovered.append(_copy_attempt(queued))
        return recovered

    def claim_attempt(
        self,
        attempt_id: str,
        worker_id: str,
        *,
        lease_seconds: int,
        now: float | None = None,
    ) -> TestWorldLease | None:
        current_time = self._clock() if now is None else now
        if not worker_id or lease_seconds <= 0:
            raise ValueError("invalid lease")
        with self._lock:
            attempt = self._attempts.get(attempt_id)
            if attempt is None or attempt.status is not AttemptStatus.QUEUED:
                return None
            current = self._claims.get(attempt_id)
            if current is not None and current.expires_at > current_time:
                return None
            generation = self._generations.get(attempt_id, 0) + 1
            self._generations[attempt_id] = generation
            lease = TestWorldLease(
                attempt_id=attempt.id,
                world_id=attempt.world_id,
                owner_id=attempt.owner_id,
                worker_id=worker_id,
                generation=generation,
                expires_at=current_time + lease_seconds,
            )
            self._claims[attempt_id] = lease
            self._attempts[attempt_id] = replace(attempt, status=AttemptStatus.RUNNING, started_at=current_time)
            world = self._worlds[attempt.world_id]
            self._worlds[world.id] = replace(world, status=WorldStatus.RUNNING, updated_at=current_time)
            return lease

    def renew_attempt(
        self,
        lease: TestWorldLease,
        *,
        lease_seconds: int,
        now: float | None = None,
    ) -> TestWorldLease:
        current_time = self._clock() if now is None else now
        if lease_seconds <= 0:
            raise ValueError("invalid lease")
        with self._lock:
            current = self._claims.get(lease.attempt_id)
            if (
                current is None
                or current.worker_id != lease.worker_id
                or current.owner_id != lease.owner_id
                or current.world_id != lease.world_id
                or current.generation != lease.generation
                or current.expires_at <= current_time
            ):
                raise TestWorldConflict("stale attempt lease")
            renewed = replace(current, expires_at=current_time + lease_seconds)
            self._claims[lease.attempt_id] = renewed
            return renewed

    def release_attempt(self, lease: TestWorldLease) -> None:
        with self._lock:
            current = self._claims.get(lease.attempt_id)
            if current is not None and current == lease:
                self._claims.pop(lease.attempt_id, None)

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
        current_time = self._clock() if now is None else now
        if not isinstance(passed, bool) or not isinstance(cumulative_patch, str) or len(cumulative_patch.encode("utf-8")) > _MAX_PATCH_BYTES:
            raise ValueError("invalid attempt result")
        bounded_feedback = _validate_feedback(feedback)
        duration_ms = _validate_duration(duration_ms, "duration")
        judge_duration_ms = _validate_duration(judge_duration_ms, "judge duration")
        if judge_duration_ms > duration_ms and duration_ms != 0:
            raise ValueError("judge duration exceeds attempt duration")
        for value in (plan, summary, tests):
            if not isinstance(value, str) or len(value.encode("utf-8")) > 64 * 1024:
                raise ValueError("invalid attempt text")
        for value in (model_calls, input_tokens, output_tokens, total_tokens):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError("invalid attempt usage")
        with self._lock:
            current_lease = self._claims.get(lease.attempt_id)
            attempt = self._attempts.get(lease.attempt_id)
            if (
                current_lease is None
                or attempt is None
                or current_lease.worker_id != lease.worker_id
                or current_lease.generation != lease.generation
                or current_lease.owner_id != lease.owner_id
                or current_lease.world_id != lease.world_id
                or attempt.status is not AttemptStatus.RUNNING
            ):
                raise TestWorldConflict("stale attempt lease")
            world = self._worlds[attempt.world_id]
            if attempt.world_fingerprint != world.fingerprint or attempt.judge_version != world.judge_version:
                raise TestWorldConflict("attempt challenge version mismatch")
            if passed and not _has_complete_pass_proof(world, bounded_feedback):
                raise TestWorldConflict("pass requires complete judge proof")
            status = AttemptStatus.PASSED if passed else AttemptStatus.FAILED
            completed = replace(
                attempt,
                status=status,
                outcome="pass" if passed else "fail",
                feedback=bounded_feedback,
                cumulative_patch=cumulative_patch,
                plan=plan,
                summary=summary,
                tests=tests,
                model_calls=model_calls,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens,
                duration_ms=duration_ms,
                judge_duration_ms=judge_duration_ms,
                finished_at=current_time,
            )
            self._attempts[attempt.id] = completed
            self._claims.pop(attempt.id, None)
            if passed:
                world_status = WorldStatus.PASSED
            elif attempt.number >= world.max_attempts:
                world_status = WorldStatus.EXHAUSTED
            else:
                world_status = WorldStatus.FAILED
            self._worlds[world.id] = replace(world, status=world_status, updated_at=current_time)
            return _copy_attempt(completed)

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
        current_time = self._clock() if now is None else now
        bounded_feedback = _validate_feedback(feedback)
        duration_ms = _validate_duration(duration_ms, "duration")
        with self._lock:
            current_lease = self._claims.get(lease.attempt_id)
            attempt = self._attempts.get(lease.attempt_id)
            if current_lease is None or attempt is None or current_lease.generation != lease.generation or current_lease.worker_id != lease.worker_id:
                raise TestWorldConflict("stale attempt lease")
            failed = replace(
                attempt,
                status=AttemptStatus.ERROR,
                outcome="error",
                feedback=bounded_feedback,
                summary=summary,
                duration_ms=duration_ms,
                finished_at=current_time,
            )
            self._attempts[attempt.id] = failed
            self._claims.pop(attempt.id, None)
            world = self._worlds[attempt.world_id]
            world_status = WorldStatus.BLOCKED if blocked else (
                WorldStatus.EXHAUSTED if attempt.number >= world.max_attempts else WorldStatus.FAILED
            )
            self._worlds[world.id] = replace(world, status=world_status, updated_at=current_time)
            return _copy_attempt(failed)


def valid_world_id(value: str) -> bool:
    return isinstance(value, str) and _WORLD_ID.fullmatch(value) is not None


def valid_attempt_id(value: str) -> bool:
    return isinstance(value, str) and _ATTEMPT_ID.fullmatch(value) is not None
