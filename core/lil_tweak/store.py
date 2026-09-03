"""Authoritative job-store contracts and production/in-memory adapters."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Protocol

from .contracts import JobMode, JobState
from .state import transition


class StoreError(RuntimeError):
    code = "store_error"


class IdempotencyConflict(StoreError):
    code = "idempotency_conflict"


class StaleRevision(StoreError):
    code = "stale_revision"


class StaleLease(StoreError):
    code = "stale_lease"


class ApprovalError(StoreError):
    code = "invalid_approval"


class JobNotFound(StoreError):
    code = "job_not_found"


_CANONICAL_APPROVAL_TOKEN = re.compile(
    r"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"
)


_EMPTY_EVENTS = frozenset(
    {
        "queued",
        "ingesting",
        "planning",
        "executing",
        "testing",
        "collecting",
        "awaiting_approval",
        "rejected",
        "failed",
        "timed_out",
    }
)
_CODE_EVENTS = frozenset(
    {
        "admission_unavailable",
        "source_intake_failed",
        "galor_unavailable",
        "engineering_failed",
    }
)


def _validated_event_data(kind: str, data: Mapping[str, Any] | None) -> dict[str, Any]:
    value = copy.deepcopy(dict(data or {}))
    if kind in _EMPTY_EVENTS:
        valid = not value
    elif kind in _CODE_EVENTS:
        valid = value == {"code": kind}
    elif kind == "cancel_requested":
        valid = set(value) == {"revision"} and isinstance(value["revision"], int)
    elif kind == "cancelled":
        valid = not value or (
            set(value) == {"revision"} and isinstance(value["revision"], int)
        ) or value == {"code": "cancelled"}
    elif kind == "applying":
        valid = value == {"action": "export_patch"}
    elif kind == "completed":
        valid = not value or value == {"action": "export_patch"}
    elif kind == "approval_required":
        valid = (
            value.get("action") == "export_patch"
            and set(value)
            == {"action", "proposal_digest", "source_digest", "revision"}
            and isinstance(value.get("revision"), int)
            and all(
                isinstance(value[name], str)
                and len(value[name]) == 64
                and all(char in "0123456789abcdef" for char in value[name])
                for name in ("proposal_digest", "source_digest")
            )
        )
    elif kind == "approved":
        valid = (
            set(value)
            == {"revision", "proposal_digest", "source_digest", "expires_at"}
            and isinstance(value.get("revision"), int)
            and isinstance(value.get("expires_at"), (int, float))
            and all(
                isinstance(value.get(name), str) and len(value[name]) == 64
                for name in ("proposal_digest", "source_digest")
            )
        )
    else:
        valid = False
    if not valid:
        raise ValueError("invalid audit event")
    return value


@dataclass(frozen=True, slots=True)
class SourceSpec:
    source_id: str
    filename: str
    media_type: str
    size_bytes: int
    object_key: str
    sha256: str | None = None


@dataclass(frozen=True, slots=True)
class GitSourceSpec:
    repository_url: str
    commit: str


@dataclass(frozen=True, slots=True)
class JobLease:
    job_id: str
    owner_id: str
    worker_id: str
    generation: int
    expires_at: float


@dataclass(frozen=True, slots=True)
class Job:
    id: str
    owner_id: str
    mode: JobMode
    prompt: str
    state: JobState = JobState.DRAFT
    revision: int = 0
    proposal_digest: str | None = None
    evidence_manifest: Mapping[str, Any] | None = None
    evidence_created_at: Mapping[str, float] = field(default_factory=dict)
    summary: str = ""
    sources: tuple[SourceSpec, ...] = ()
    source_digest: str | None = None
    approval_proposal: Mapping[str, Any] | None = None
    approval_consumed: bool = False
    project_context: Mapping[str, Any] | None = None
    git_source: GitSourceSpec | None = None
    created_at: float = 0.0
    updated_at: float = 0.0
    cancel_requested: bool = False
    lease_owner: str | None = None
    lease_generation: int = 0
    lease_expires_at: float | None = None


@dataclass(frozen=True, slots=True)
class JobEvent:
    job_id: str
    sequence: int
    kind: str
    data: dict[str, Any]
    created_at: float


@dataclass(frozen=True, slots=True)
class Approval:
    token_hash: str
    job_id: str
    owner_id: str
    revision: int
    proposal_digest: str
    source_digest: str
    action: str
    target: str
    policy_version: str
    resource_profile: Mapping[str, Any]
    expires_at: float
    consumed: bool = False
    consumed_at: float | None = None


class JobStore(Protocol):
    def consume_nonce(self, key_id: str, nonce: str, timestamp: int) -> bool: ...

    def claim_job(
        self,
        job_id: str,
        owner_id: str,
        worker_id: str,
        *,
        lease_seconds: int,
        now: float | None = None,
    ) -> JobLease | None: ...

    def renew_claim(
        self, lease: JobLease, *, lease_seconds: int, now: float | None = None
    ) -> JobLease: ...

    def release_claim(self, lease: JobLease) -> None: ...

    def list_schedulable_jobs(
        self, *, now: float | None = None, limit: int = 10
    ) -> list[Job]: ...

    def reconcile_active_jobs(
        self, *, now: float | None = None, limit: int = 100
    ) -> list[Job]: ...

    def create_job(
        self,
        owner_id: str,
        idempotency_key: str,
        mode: JobMode | str,
        prompt: str,
        sources: list[SourceSpec] | tuple[SourceSpec, ...] = (),
        project_context: Mapping[str, Any] | None = None,
        git_source: GitSourceSpec | None = None,
    ) -> Job: ...

    def request_cancel(
        self, job_id: str, *, owner_id: str, expected_revision: int
    ) -> Job: ...

    def request_cancel_idempotent(self, job_id: str, **fields: Any) -> Job: ...

    def decide_job_idempotent(self, job_id: str, **fields: Any) -> Job: ...

    def consume_export_idempotent(self, job_id: str, **fields: Any) -> Job: ...

    def append_event(
        self,
        job_id: str,
        owner_id: str,
        kind: str,
        data: Mapping[str, Any] | None = None,
    ) -> JobEvent: ...

    def transition_job(
        self,
        job_id: str,
        *,
        owner_id: str,
        expected_revision: int,
        state: JobState | str,
        event_kind: str,
        event_data: Mapping[str, Any] | None = None,
        **fields: Any,
    ) -> Job: ...

    def list_events(self, job_id: str, owner_id: str) -> list[JobEvent]: ...

    def create_approval(self, job_id: str, **fields: Any) -> Approval: ...

    def consume_approval(self, token: str, **fields: Any) -> Approval: ...

    def get_decision(
        self, owner_id: str, idempotency_key: str, request_hash: str
    ) -> Job | None: ...

    def record_decision(
        self, owner_id: str, idempotency_key: str, request_hash: str, job_id: str
    ) -> Job: ...

    def get_job(self, job_id: str, owner_id: str) -> Job | None: ...

    def update_job(
        self,
        job_id: str,
        *,
        owner_id: str,
        expected_revision: int,
        state: JobState | str,
        proposal_digest: str | None = None,
        evidence_manifest: Mapping[str, Any] | None = None,
        approved_digest: str | None = None,
        approval_consumed: bool = False,
        summary: str | None = None,
        source_digest: str | None = None,
        approval_proposal: Mapping[str, Any] | None = None,
        lease: JobLease | None = None,
    ) -> Job: ...


def _request_fingerprint(
    mode: JobMode,
    prompt: str,
    sources: tuple[SourceSpec, ...] = (),
    project_context: Mapping[str, Any] | None = None,
    git_source: GitSourceSpec | None = None,
) -> str:
    encoded = json.dumps(
        {
            "mode": mode.value,
            "prompt": prompt,
            "sources": [
                {
                    "id": source.source_id,
                    "filename": source.filename,
                    "media_type": source.media_type,
                    "size_bytes": source.size_bytes,
                    "object_key": source.object_key,
                    "sha256": source.sha256,
                }
                for source in sources
            ],
            "project_context": project_context,
            "git_source": {
                "repository_url": git_source.repository_url,
                "commit": git_source.commit,
            }
            if git_source is not None
            else None,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _json_type_equal(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _json_type_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_type_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    return left == right


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _copy_job(job: Job) -> Job:
    manifest = copy.deepcopy(job.evidence_manifest)
    evidence_created_at = copy.deepcopy(job.evidence_created_at or {})
    proposal = copy.deepcopy(job.approval_proposal)
    project_context = copy.deepcopy(job.project_context)
    return replace(
        job,
        evidence_manifest=manifest,
        evidence_created_at=evidence_created_at,
        approval_proposal=proposal,
        project_context=project_context,
        sources=tuple(job.sources),
    )


class MemoryJobStore:
    """Thread-safe executable contract used for local runs and unit tests."""

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.RLock()
        self._nonces: dict[tuple[str, str], float] = {}
        self._jobs: dict[str, Job] = {}
        self._idempotency: dict[tuple[str, str], tuple[str, str]] = {}
        self._events: dict[str, list[JobEvent]] = {}
        self._approvals: dict[str, Approval] = {}
        self._approval_index: dict[tuple[str, int, str], str] = {}
        self._decisions: dict[tuple[str, str], tuple[str, str]] = {}
        self._claims: dict[str, JobLease] = {}
        self._lease_generations: dict[str, int] = {}

    def consume_nonce(self, key_id: str, nonce: str, timestamp: int) -> bool:
        if not key_id or not nonce or not isinstance(timestamp, int):
            return False
        identity = (key_id, nonce)
        with self._lock:
            cutoff = self._clock() - 600
            self._nonces = {
                item: consumed_at
                for item, consumed_at in self._nonces.items()
                if consumed_at > cutoff
            }
            if identity in self._nonces:
                return False
            self._nonces[identity] = self._clock()
            return True

    def claim_job(
        self,
        job_id: str,
        owner_id: str,
        worker_id: str,
        *,
        lease_seconds: int,
        now: float | None = None,
    ) -> JobLease | None:
        current_time = self._clock() if now is None else now
        if not worker_id or lease_seconds <= 0:
            raise ValueError("invalid lease")
        with self._lock:
            job = self._jobs.get(job_id)
            if (
                job is None
                or job.owner_id != owner_id
                or job.state
                in {
                    JobState.AWAITING_APPROVAL,
                    JobState.COMPLETED,
                    JobState.REJECTED,
                    JobState.CANCELLED,
                    JobState.FAILED,
                    JobState.TIMED_OUT,
                }
            ):
                return None
            claim = self._claims.get(job_id)
            if claim and claim.expires_at > current_time:
                return None
            generation = self._lease_generations.get(job_id, 0) + 1
            self._lease_generations[job_id] = generation
            claimed = JobLease(
                job_id,
                owner_id,
                worker_id,
                generation,
                current_time + lease_seconds,
            )
            self._claims[job_id] = claimed
            return claimed

    def renew_claim(
        self,
        lease: JobLease,
        *,
        lease_seconds: int,
        now: float | None = None,
    ) -> JobLease:
        current_time = self._clock() if now is None else now
        if lease_seconds <= 0:
            raise ValueError("invalid lease")
        with self._lock:
            current = self._claims.get(lease.job_id)
            if (
                current is None
                or current.owner_id != lease.owner_id
                or current.worker_id != lease.worker_id
                or current.generation != lease.generation
                or current.expires_at <= current_time
            ):
                raise StaleLease("stale lease")
            renewed = replace(current, expires_at=current_time + lease_seconds)
            self._claims[lease.job_id] = renewed
            return renewed

    def release_claim(self, lease: JobLease) -> None:
        with self._lock:
            current = self._claims.get(lease.job_id)
            if (
                current is not None
                and current.owner_id == lease.owner_id
                and current.worker_id == lease.worker_id
                and current.generation == lease.generation
            ):
                self._claims.pop(lease.job_id, None)

    def list_schedulable_jobs(
        self, *, now: float | None = None, limit: int = 10
    ) -> list[Job]:
        current_time = self._clock() if now is None else now
        if not 1 <= limit <= 1000:
            raise ValueError("invalid scheduler limit")
        with self._lock:
            jobs = []
            for job in sorted(
                self._jobs.values(), key=lambda item: (item.created_at, item.id)
            ):
                claim = self._claims.get(job.id)
                if job.state is JobState.QUEUED and (
                    claim is None or claim.expires_at <= current_time
                ):
                    jobs.append(_copy_job(job))
                    if len(jobs) == limit:
                        break
            return jobs

    def reconcile_active_jobs(
        self, *, now: float | None = None, limit: int = 100
    ) -> list[Job]:
        current_time = self._clock() if now is None else now
        active = {
            JobState.INGESTING,
            JobState.PLANNING,
            JobState.EXECUTING,
            JobState.TESTING,
            JobState.COLLECTING,
            JobState.APPLYING,
        }
        recovered: list[Job] = []
        with self._lock:
            for job in sorted(self._jobs.values(), key=lambda item: (item.created_at, item.id)):
                if len(recovered) >= limit or job.state not in active:
                    continue
                claim = self._claims.get(job.id)
                if claim and claim.expires_at > current_time:
                    continue
                if job.state is JobState.APPLYING:
                    approval = next(
                        (
                            item
                            for item in self._approvals.values()
                            if item.job_id == job.id
                            and item.owner_id == job.owner_id
                            and item.proposal_digest == job.proposal_digest
                        ),
                        None,
                    )
                    if approval is not None and not approval.consumed:
                        if approval.expires_at > current_time:
                            continue
                        target = JobState.TIMED_OUT
                    elif approval is not None and approval.consumed:
                        target = JobState.COMPLETED
                    else:
                        target = JobState.TIMED_OUT
                else:
                    target = JobState.QUEUED
                updated = replace(
                    job,
                    state=target,
                    revision=job.revision + 1,
                    updated_at=current_time,
                )
                self._jobs[job.id] = updated
                self._claims.pop(job.id, None)
                event_data = (
                    {"action": "export_patch"}
                    if target is JobState.COMPLETED
                    else {}
                )
                self._append_event_locked(job.id, target.value, event_data)
                if target is JobState.QUEUED:
                    recovered.append(_copy_job(updated))
        return recovered

    def create_job(
        self,
        owner_id: str,
        idempotency_key: str,
        mode: JobMode | str,
        prompt: str,
        sources: list[SourceSpec] | tuple[SourceSpec, ...] = (),
        project_context: Mapping[str, Any] | None = None,
        git_source: GitSourceSpec | None = None,
    ) -> Job:
        mode_value = JobMode(mode)
        if not owner_id or not idempotency_key or not prompt.strip():
            raise ValueError("owner, idempotency key, and prompt are required")
        source_tuple = tuple(sources)
        fingerprint = _request_fingerprint(
            mode_value, prompt, source_tuple, project_context, git_source
        )
        identity = (owner_id, idempotency_key)
        with self._lock:
            existing = self._idempotency.get(identity)
            if existing:
                job_id, previous_fingerprint = existing
                if previous_fingerprint != fingerprint:
                    raise IdempotencyConflict("idempotency key reused")
                return _copy_job(self._jobs[job_id])
            now = self._clock()
            job = Job(
                id=str(uuid.uuid4()),
                owner_id=owner_id,
                mode=mode_value,
                prompt=prompt,
                created_at=now,
                updated_at=now,
                sources=source_tuple,
                project_context=copy.deepcopy(project_context),
                git_source=git_source,
            )
            self._jobs[job.id] = job
            self._idempotency[identity] = (job.id, fingerprint)
            self._events[job.id] = []
            return _copy_job(job)

    def get_job(self, job_id: str, owner_id: str) -> Job | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.owner_id != owner_id:
                return None
            return _copy_job(job)

    def update_job(
        self,
        job_id: str,
        *,
        owner_id: str,
        expected_revision: int,
        state: JobState | str,
        proposal_digest: str | None = None,
        evidence_manifest: Mapping[str, Any] | None = None,
        approved_digest: str | None = None,
        approval_consumed: bool = False,
        summary: str | None = None,
        source_digest: str | None = None,
        approval_proposal: Mapping[str, Any] | None = None,
        lease: JobLease | None = None,
    ) -> Job:
        with self._lock:
            current = self._jobs.get(job_id)
            if current is None or current.owner_id != owner_id:
                raise JobNotFound("job not found")
            if current.revision != expected_revision:
                raise StaleRevision("stale revision")
            current_lease = self._claims.get(job_id)
            now = self._clock()
            if lease is not None:
                if (
                    current_lease is None
                    or lease.job_id != job_id
                    or lease.owner_id != owner_id
                    or lease.worker_id != current_lease.worker_id
                    or lease.generation != current_lease.generation
                    or current_lease.expires_at <= now
                ):
                    raise StaleLease("stale lease")
            elif current_lease is not None and current_lease.expires_at > now:
                    raise StaleLease("stale lease")
            target = transition(
                current.state,
                state,
                proposal_digest=proposal_digest,
                evidence_manifest=evidence_manifest,
                approved_digest=approved_digest,
                approval_consumed=approval_consumed,
            )
            evidence_created_at = dict(current.evidence_created_at or {})
            if evidence_manifest is not None:
                for name in evidence_manifest:
                    evidence_created_at.setdefault(name, now)
            updated = replace(
                current,
                state=target,
                revision=current.revision + 1,
                proposal_digest=proposal_digest or current.proposal_digest,
                evidence_manifest=copy.deepcopy(evidence_manifest)
                if evidence_manifest is not None
                else current.evidence_manifest,
                evidence_created_at=evidence_created_at,
                updated_at=now,
                summary=current.summary if summary is None else summary,
                source_digest=source_digest or current.source_digest,
                approval_proposal=copy.deepcopy(approval_proposal)
                if approval_proposal is not None
                else current.approval_proposal,
                approval_consumed=current.approval_consumed or approval_consumed,
            )
            self._jobs[job_id] = updated
            return _copy_job(updated)

    def request_cancel(
        self, job_id: str, *, owner_id: str, expected_revision: int
    ) -> Job:
        with self._lock:
            current = self._jobs.get(job_id)
            if current is None or current.owner_id != owner_id:
                raise JobNotFound("job not found")
            if current.revision != expected_revision:
                raise StaleRevision("stale revision")
            transition(current.state, JobState.CANCELLED)
            target_state = (
                JobState.CANCELLED
                if current.state in {JobState.AWAITING_APPROVAL, JobState.APPLYING}
                else current.state
            )
            updated = replace(
                current,
                state=target_state,
                cancel_requested=True,
                revision=current.revision + 1,
                updated_at=self._clock(),
            )
            self._jobs[job_id] = updated
            return _copy_job(updated)

    def request_cancel_idempotent(
        self,
        job_id: str,
        *,
        owner_id: str,
        expected_revision: int,
        idempotency_key: str,
        request_hash: str,
    ) -> Job:
        identity = (owner_id, idempotency_key)
        with self._lock:
            existing = self._decisions.get(identity)
            if existing is not None:
                if existing != (request_hash, job_id):
                    raise IdempotencyConflict("idempotency key reused")
                return _copy_job(self._jobs[job_id])
            current = self._jobs.get(job_id)
            if current is None or current.owner_id != owner_id:
                raise JobNotFound("job not found")
            if current.revision != expected_revision:
                raise StaleRevision("stale revision")
            transition(current.state, JobState.CANCELLED)
            target_state = (
                JobState.CANCELLED
                if current.state in {JobState.AWAITING_APPROVAL, JobState.APPLYING}
                else current.state
            )
            updated = replace(
                current,
                state=target_state,
                cancel_requested=True,
                revision=current.revision + 1,
                updated_at=self._clock(),
            )
            event_kind = (
                "cancelled"
                if target_state is JobState.CANCELLED
                else "cancel_requested"
            )
            event_data = _validated_event_data(
                event_kind, {"revision": updated.revision}
            )
            self._jobs[job_id] = updated
            self._decisions[identity] = (request_hash, job_id)
            self._append_event_locked(job_id, event_kind, event_data)
            return _copy_job(updated)

    def decide_job_idempotent(
        self,
        job_id: str,
        *,
        owner_id: str,
        expected_revision: int,
        idempotency_key: str,
        request_hash: str,
        decision: str,
        proposal_digest: str,
        approval_proposal: Mapping[str, Any] | None = None,
        approval_token_hash: str | None = None,
        expires_at: float | None = None,
        now: float | None = None,
    ) -> Job:
        identity = (owner_id, idempotency_key)
        current_time = self._clock() if now is None else now
        with self._lock:
            existing = self._decisions.get(identity)
            if existing is not None:
                if existing != (request_hash, job_id):
                    raise IdempotencyConflict("idempotency key reused")
                return _copy_job(self._jobs[job_id])
            current = self._jobs.get(job_id)
            if current is None or current.owner_id != owner_id:
                raise JobNotFound("job not found")
            if (
                current.state is not JobState.AWAITING_APPROVAL
                or current.revision != expected_revision
                or current.proposal_digest != proposal_digest
            ):
                raise StaleRevision("stale revision")
            if decision == "reject":
                target = transition(current.state, JobState.REJECTED)
                event_data = _validated_event_data("rejected", {})
                updated = replace(
                    current,
                    state=target,
                    revision=current.revision + 1,
                    updated_at=current_time,
                )
                self._jobs[job_id] = updated
                self._decisions[identity] = (request_hash, job_id)
                self._append_event_locked(job_id, "rejected", event_data)
                return _copy_job(updated)
            if (
                decision != "approve"
                or approval_proposal is None
                or current.approval_proposal is None
                or not _json_type_equal(
                    dict(approval_proposal), dict(current.approval_proposal)
                )
                or current.source_digest is None
                or approval_proposal.get("action") != "export_patch"
                or approval_proposal.get("target") != "owner_download"
                or approval_proposal.get("proposalDigest") != proposal_digest
                or approval_proposal.get("sourceDigest") != current.source_digest
                or not isinstance(approval_proposal.get("policyVersion"), str)
                or not isinstance(approval_proposal.get("resourceProfile"), Mapping)
                or not _valid_sha256(approval_token_hash)
                or expires_at is None
                or expires_at <= current_time
            ):
                raise ApprovalError("invalid approval")
            transition(
                current.state,
                JobState.APPLYING,
                proposal_digest=proposal_digest,
                approved_digest=proposal_digest,
                approval_recorded=True,
                approval_consumed=False,
            )
            approval_key = (job_id, current.revision, proposal_digest)
            if approval_key in self._approval_index:
                raise ApprovalError("invalid approval")
            approval = Approval(
                approval_token_hash,
                job_id,
                owner_id,
                current.revision,
                proposal_digest,
                current.source_digest,
                "export_patch",
                "owner_download",
                str(approval_proposal["policyVersion"]),
                copy.deepcopy(dict(approval_proposal["resourceProfile"])),
                expires_at,
            )
            approved_data = _validated_event_data(
                "approved",
                {
                    "revision": current.revision,
                    "proposal_digest": proposal_digest,
                    "source_digest": current.source_digest,
                    "expires_at": expires_at,
                },
            )
            applying_data = _validated_event_data(
                "applying", {"action": "export_patch"}
            )
            updated = replace(
                current,
                state=JobState.APPLYING,
                revision=current.revision + 1,
                approval_consumed=False,
                updated_at=current_time,
            )
            self._jobs[job_id] = updated
            self._approvals[approval_token_hash] = approval
            self._approval_index[approval_key] = approval_token_hash
            self._decisions[identity] = (request_hash, job_id)
            self._append_event_locked(job_id, "approved", approved_data)
            self._append_event_locked(job_id, "applying", applying_data)
            return _copy_job(updated)

    def consume_export_idempotent(
        self,
        job_id: str,
        *,
        owner_id: str,
        expected_revision: int,
        idempotency_key: str,
        request_hash: str,
        approval_token: str,
        proposal_digest: str,
        source_digest: str,
        policy_version: str,
        resource_profile: Mapping[str, Any],
        evidence_name: str,
        evidence_sha256: str,
        evidence_size_bytes: int,
        now: float | None = None,
    ) -> Job:
        current_time = self._clock() if now is None else now
        identity = (owner_id, f"export:{idempotency_key}")
        if not _CANONICAL_APPROVAL_TOKEN.fullmatch(approval_token):
            raise ApprovalError("invalid approval")
        token_hash = hashlib.sha256(approval_token.encode("ascii")).hexdigest()
        with self._lock:
            existing = self._decisions.get(identity)
            approval = self._approvals.get(token_hash)
            current = self._jobs.get(job_id)
            if existing is not None:
                if existing != (request_hash, job_id):
                    raise IdempotencyConflict("idempotency key reused")
                if (
                    approval is None
                    or approval.expires_at <= current_time
                    or current is None
                    or current.owner_id != owner_id
                    or current.state is not JobState.COMPLETED
                    or not current.approval_consumed
                ):
                    raise ApprovalError("invalid approval")
                return _copy_job(current)
            descriptor = (
                (current.evidence_manifest or {}).get(evidence_name)
                if current is not None
                else None
            )
            if (
                approval is None
                or approval.consumed
                or approval.owner_id != owner_id
                or approval.job_id != job_id
                or approval.proposal_digest != proposal_digest
                or approval.source_digest != source_digest
                or approval.action != "export_patch"
                or approval.target != "owner_download"
                or approval.policy_version != policy_version
                or not _json_type_equal(
                    dict(approval.resource_profile), dict(resource_profile)
                )
                or approval.expires_at <= current_time
                or current is None
                or current.owner_id != owner_id
                or current.state is not JobState.APPLYING
                or current.revision != expected_revision
                or current.proposal_digest != proposal_digest
                or current.source_digest != source_digest
                or current.approval_consumed
                or evidence_name != "changes.patch"
                or not isinstance(descriptor, Mapping)
                or descriptor.get("sha256") != evidence_sha256
                or descriptor.get("bytes") != evidence_size_bytes
            ):
                raise ApprovalError("invalid approval")
            transition(current.state, JobState.COMPLETED)
            consumed = replace(approval, consumed=True, consumed_at=current_time)
            completed = replace(
                current,
                state=JobState.COMPLETED,
                revision=current.revision + 1,
                approval_consumed=True,
                updated_at=current_time,
            )
            self._approvals[token_hash] = consumed
            self._jobs[job_id] = completed
            self._decisions[identity] = (request_hash, job_id)
            self._append_event_locked(
                job_id,
                "completed",
                _validated_event_data("completed", {"action": "export_patch"}),
            )
            return _copy_job(completed)

    def append_event(
        self,
        job_id: str,
        owner_id: str,
        kind: str,
        data: Mapping[str, Any] | None = None,
    ) -> JobEvent:
        if not kind:
            raise ValueError("event kind is required")
        event_data = _validated_event_data(kind, data)
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.owner_id != owner_id:
                raise JobNotFound("job not found")
            event = self._append_event_locked(job_id, kind, event_data)
            return replace(event, data=copy.deepcopy(event.data))

    def _append_event_locked(
        self, job_id: str, kind: str, event_data: Mapping[str, Any]
    ) -> JobEvent:
        events = self._events[job_id]
        event = JobEvent(
            job_id,
            len(events) + 1,
            kind,
            copy.deepcopy(dict(event_data)),
            self._clock(),
        )
        events.append(event)
        return event

    def transition_job(
        self,
        job_id: str,
        *,
        owner_id: str,
        expected_revision: int,
        state: JobState | str,
        event_kind: str,
        event_data: Mapping[str, Any] | None = None,
        **fields: Any,
    ) -> Job:
        validated = _validated_event_data(event_kind, event_data)
        with self._lock:
            moved = self.update_job(
                job_id,
                owner_id=owner_id,
                expected_revision=expected_revision,
                state=state,
                **fields,
            )
            self._append_event_locked(job_id, event_kind, validated)
            return moved

    def list_events(self, job_id: str, owner_id: str) -> list[JobEvent]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.owner_id != owner_id:
                raise JobNotFound("job not found")
            return [
                replace(event, data=copy.deepcopy(event.data))
                for event in self._events[job_id]
            ]

    def create_approval(
        self,
        job_id: str,
        *,
        owner_id: str,
        revision: int,
        proposal_digest: str,
        source_digest: str,
        action: str,
        target: str,
        policy_version: str,
        resource_profile: Mapping[str, Any],
        approval_token_hash: str,
        expires_at: float,
        now: float | None = None,
    ) -> Approval:
        current_time = self._clock() if now is None else now
        with self._lock:
            job = self._jobs.get(job_id)
            if (
                job is None
                or job.owner_id != owner_id
                or job.revision != revision
                or job.proposal_digest != proposal_digest
                or job.source_digest != source_digest
                or expires_at <= current_time
                or not _valid_sha256(approval_token_hash)
            ):
                raise ApprovalError("invalid approval")
            approval_key = (job_id, revision, proposal_digest)
            if approval_key in self._approval_index:
                raise ApprovalError("invalid approval")
            approval = Approval(
                approval_token_hash,
                job_id,
                owner_id,
                revision,
                proposal_digest,
                source_digest,
                action,
                target,
                policy_version,
                copy.deepcopy(dict(resource_profile)),
                expires_at,
            )
            self._approvals[approval_token_hash] = approval
            self._approval_index[approval_key] = approval_token_hash
            return approval

    def consume_approval(
        self,
        token: str,
        *,
        owner_id: str,
        job_id: str,
        revision: int,
        proposal_digest: str,
        source_digest: str,
        policy_version: str,
        resource_profile: Mapping[str, Any],
        now: float | None = None,
    ) -> Approval:
        current_time = self._clock() if now is None else now
        with self._lock:
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            approval = self._approvals.get(token_hash)
            job = self._jobs.get(job_id)
            if (
                approval is None
                or approval.consumed
                or approval.owner_id != owner_id
                or approval.job_id != job_id
                or approval.revision != revision
                or approval.proposal_digest != proposal_digest
                or approval.source_digest != source_digest
                or approval.policy_version != policy_version
                or not _json_type_equal(
                    dict(approval.resource_profile), dict(resource_profile)
                )
                or approval.expires_at <= current_time
                or job is None
                or job.owner_id != owner_id
                or job.revision != revision
                or job.proposal_digest != proposal_digest
                or job.source_digest != source_digest
            ):
                raise ApprovalError("invalid approval")
            consumed = replace(approval, consumed=True, consumed_at=current_time)
            self._approvals[token_hash] = consumed
            return consumed

    def get_decision(
        self, owner_id: str, idempotency_key: str, request_hash: str
    ) -> Job | None:
        with self._lock:
            existing = self._decisions.get((owner_id, idempotency_key))
            if existing is None:
                return None
            stored_hash, job_id = existing
            if stored_hash != request_hash:
                raise IdempotencyConflict("idempotency key reused")
            return _copy_job(self._jobs[job_id])

    def record_decision(
        self, owner_id: str, idempotency_key: str, request_hash: str, job_id: str
    ) -> Job:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.owner_id != owner_id:
                raise JobNotFound("job not found")
            identity = (owner_id, idempotency_key)
            existing = self._decisions.get(identity)
            if existing is not None and existing != (request_hash, job_id):
                raise IdempotencyConflict("idempotency key reused")
            self._decisions[identity] = (request_hash, job_id)
            return _copy_job(job)


class PostgresJobStore:
    """PostgreSQL adapter using a psycopg-compatible connection factory.

    The factory indirection keeps importing this module dependency-light and
    lets process wiring configure pooling and row factories explicitly.
    """

    def __init__(self, connection_factory: Callable[[], Any]) -> None:
        self._connect = connection_factory

    def consume_nonce(self, key_id: str, nonce: str, timestamp: int) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM lil_tweak_nonces WHERE key_id=%s AND nonce=%s "
                "AND consumed_at<now()-interval '10 minutes'",
                (key_id, nonce),
            )
            cursor.execute(
                "DELETE FROM lil_tweak_nonces WHERE ctid IN ("
                "SELECT ctid FROM lil_tweak_nonces "
                "WHERE consumed_at<now()-interval '10 minutes' LIMIT 1000)",
                (),
            )
            cursor.execute(
                "INSERT INTO lil_tweak_nonces (key_id, nonce, request_timestamp) "
                "VALUES (%s, %s, to_timestamp(%s)) ON CONFLICT DO NOTHING",
                (key_id, nonce, timestamp),
            )
            return cursor.rowcount == 1

    def claim_job(
        self,
        job_id: str,
        owner_id: str,
        worker_id: str,
        *,
        lease_seconds: int,
        now: float | None = None,
    ) -> JobLease | None:
        current_time = time.time() if now is None else now
        if not worker_id or lease_seconds <= 0:
            raise ValueError("invalid lease")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "UPDATE lil_tweak_jobs SET lease_owner=%s,"
                "lease_expires_at=to_timestamp(%s),attempt=attempt+1,"
                "lease_generation=lease_generation+1 "
                "WHERE id=%s AND owner_id=%s "
                "AND state NOT IN ('awaiting_approval','completed','rejected','cancelled','failed','timed_out') "
                "AND (lease_expires_at IS NULL OR lease_expires_at<=to_timestamp(%s)) "
                "RETURNING lease_generation,extract(epoch from lease_expires_at)",
                (
                    worker_id,
                    current_time + lease_seconds,
                    job_id,
                    owner_id,
                    current_time,
                ),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return JobLease(
                job_id,
                owner_id,
                worker_id,
                int(row[0]),
                float(row[1]),
            )

    def renew_claim(
        self,
        lease: JobLease,
        *,
        lease_seconds: int,
        now: float | None = None,
    ) -> JobLease:
        current_time = time.time() if now is None else now
        if lease_seconds <= 0:
            raise ValueError("invalid lease")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "UPDATE lil_tweak_jobs SET lease_expires_at=to_timestamp(%s) "
                "WHERE id=%s AND owner_id=%s AND lease_owner=%s "
                "AND lease_generation=%s AND lease_expires_at>to_timestamp(%s) "
                "RETURNING extract(epoch from lease_expires_at)",
                (
                    current_time + lease_seconds,
                    lease.job_id,
                    lease.owner_id,
                    lease.worker_id,
                    lease.generation,
                    current_time,
                ),
            )
            row = cursor.fetchone()
            if row is None:
                raise StaleLease("stale lease")
            return replace(lease, expires_at=float(row[0]))

    def release_claim(self, lease: JobLease) -> None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "UPDATE lil_tweak_jobs SET lease_owner=NULL,lease_expires_at=NULL "
                "WHERE id=%s AND owner_id=%s AND lease_owner=%s AND lease_generation=%s",
                (
                    lease.job_id,
                    lease.owner_id,
                    lease.worker_id,
                    lease.generation,
                ),
            )

    def list_schedulable_jobs(
        self, *, now: float | None = None, limit: int = 10
    ) -> list[Job]:
        current_time = time.time() if now is None else now
        if not 1 <= limit <= 1000:
            raise ValueError("invalid scheduler limit")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT id,owner_id FROM lil_tweak_jobs WHERE state='queued' "
                "AND (lease_expires_at IS NULL OR lease_expires_at<=to_timestamp(%s)) "
                "ORDER BY created_at LIMIT %s",
                (current_time, limit),
            )
            rows = cursor.fetchall()
            return [self._fetch_job(cursor, row[0], row[1]) for row in rows]

    def reconcile_active_jobs(
        self, *, now: float | None = None, limit: int = 100
    ) -> list[Job]:
        current_time = time.time() if now is None else now
        if not 1 <= limit <= 1000:
            raise ValueError("invalid reconciliation limit")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT j.id,j.owner_id,j.state,j.approval_consumed,"
                "extract(epoch from a.expires_at),a.consumed_at "
                "FROM lil_tweak_jobs j LEFT JOIN lil_tweak_approvals a "
                "ON a.job_id=j.id AND a.proposal_digest=j.proposal_digest "
                "WHERE j.state IN ('ingesting','planning','executing','testing','collecting','applying')"
                " AND (j.lease_expires_at IS NULL OR j.lease_expires_at<=to_timestamp(%s))"
                " ORDER BY j.created_at FOR UPDATE OF j SKIP LOCKED LIMIT %s",
                (current_time, limit),
            )
            recoverable = list(cursor.fetchall())
            recovered: list[Job] = []
            for (
                job_id,
                owner_id,
                state,
                approval_consumed,
                approval_expires_at,
                consumed_at,
            ) in recoverable:
                if state == "applying":
                    if (
                        not approval_consumed
                        and consumed_at is None
                        and approval_expires_at is not None
                        and float(approval_expires_at) > current_time
                    ):
                        continue
                    target = "completed" if approval_consumed and consumed_at else "timed_out"
                else:
                    target = "queued"
                cursor.execute(
                    "UPDATE lil_tweak_jobs SET state=%s,revision=revision+1,"
                    "lease_owner=NULL,lease_expires_at=NULL,updated_at=now() "
                    "WHERE id=%s AND owner_id=%s",
                    (target, job_id, owner_id),
                )
                event_data = {"action": "export_patch"} if target == "completed" else {}
                self._insert_event_cursor(
                    cursor, str(job_id), owner_id, target, event_data
                )
                if target == "queued":
                    recovered.append(
                        self._fetch_job(cursor, str(job_id), owner_id)
                    )
            return recovered

    def create_job(
        self,
        owner_id: str,
        idempotency_key: str,
        mode: JobMode | str,
        prompt: str,
        sources: list[SourceSpec] | tuple[SourceSpec, ...] = (),
        project_context: Mapping[str, Any] | None = None,
        git_source: GitSourceSpec | None = None,
    ) -> Job:
        mode_value = JobMode(mode)
        source_tuple = tuple(sources)
        fingerprint = _request_fingerprint(
            mode_value, prompt, source_tuple, project_context, git_source
        )
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"{owner_id}\n{idempotency_key}",),
            )
            cursor.execute(
                "SELECT job_id, request_hash FROM lil_tweak_idempotency "
                "WHERE owner_id=%s AND idempotency_key=%s FOR UPDATE",
                (owner_id, idempotency_key),
            )
            existing = cursor.fetchone()
            if existing:
                if existing[1] != fingerprint:
                    raise IdempotencyConflict("idempotency key reused")
                return self._fetch_job(cursor, existing[0], owner_id)
            job_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO lil_tweak_jobs "
                "(id,owner_id,mode,prompt,state,source_manifest,project_context,git_source) "
                "VALUES (%s,%s,%s,%s,'draft',%s::jsonb,%s::jsonb,%s::jsonb)",
                (
                    job_id,
                    owner_id,
                    mode_value.value,
                    prompt,
                    json.dumps(
                        [
                            {
                                "source_id": source.source_id,
                                "filename": source.filename,
                                "media_type": source.media_type,
                                "size_bytes": source.size_bytes,
                                "object_key": source.object_key,
                                "sha256": source.sha256,
                            }
                            for source in source_tuple
                        ]
                    ),
                    json.dumps(project_context) if project_context is not None else None,
                    json.dumps(
                        {
                            "repository_url": git_source.repository_url,
                            "commit": git_source.commit,
                        }
                    )
                    if git_source is not None
                    else None,
                ),
            )
            cursor.execute(
                "INSERT INTO lil_tweak_idempotency "
                "(owner_id,idempotency_key,request_hash,job_id) VALUES (%s,%s,%s,%s)",
                (owner_id, idempotency_key, fingerprint, job_id),
            )
            for source in source_tuple:
                cursor.execute(
                    "INSERT INTO lil_tweak_sources "
                    "(id,job_id,owner_id,source_id,kind,filename,media_type,object_key,"
                    "source_digest,size_bytes) VALUES (%s,%s,%s,%s,'upload',%s,%s,%s,%s,%s)",
                    (
                        str(uuid.uuid5(uuid.NAMESPACE_URL, f"{job_id}:{source.source_id}")),
                        job_id,
                        owner_id,
                        source.source_id,
                        source.filename,
                        source.media_type,
                        source.object_key,
                        source.sha256,
                        source.size_bytes,
                    ),
                )
            if git_source is not None:
                cursor.execute(
                    "INSERT INTO lil_tweak_sources "
                    "(id,job_id,owner_id,source_id,kind,filename,media_type,source_digest,"
                    "frozen_reference,size_bytes) VALUES (%s,%s,%s,'git','git','repository',"
                    "'application/x-git',NULL,%s,0)",
                    (
                        str(uuid.uuid5(uuid.NAMESPACE_URL, f"{job_id}:git")),
                        job_id,
                        owner_id,
                        git_source.commit,
                    ),
                )
            return self._fetch_job(cursor, job_id, owner_id)

    def request_cancel_idempotent(
        self,
        job_id: str,
        *,
        owner_id: str,
        expected_revision: int,
        idempotency_key: str,
        request_hash: str,
    ) -> Job:
        identity = f"{owner_id}\n{idempotency_key}"
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (identity,),
            )
            cursor.execute(
                "SELECT request_hash,job_id FROM lil_tweak_decisions "
                "WHERE owner_id=%s AND idempotency_key=%s FOR UPDATE",
                (owner_id, idempotency_key),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing[0] != request_hash or str(existing[1]) != job_id:
                    raise IdempotencyConflict("idempotency key reused")
                current = self._fetch_job(cursor, job_id, owner_id, for_update=True)
                if current.cancel_requested or current.state in {
                    JobState.CANCELLED,
                    JobState.COMPLETED,
                    JobState.REJECTED,
                    JobState.FAILED,
                    JobState.TIMED_OUT,
                }:
                    return current
            else:
                current = self._fetch_job(cursor, job_id, owner_id, for_update=True)
            if current.revision != expected_revision:
                raise StaleRevision("stale revision")
            transition(current.state, JobState.CANCELLED)
            target_state = (
                JobState.CANCELLED
                if current.state in {JobState.AWAITING_APPROVAL, JobState.APPLYING}
                else current.state
            )
            next_revision = current.revision + 1
            event_kind = (
                "cancelled"
                if target_state is JobState.CANCELLED
                else "cancel_requested"
            )
            event_data = _validated_event_data(
                event_kind, {"revision": next_revision}
            )
            cursor.execute(
                "UPDATE lil_tweak_jobs SET state=%s,cancel_requested=true,"
                "revision=revision+1,updated_at=now() "
                "WHERE id=%s AND owner_id=%s AND revision=%s",
                (target_state.value, job_id, owner_id, current.revision),
            )
            if cursor.rowcount != 1:
                raise StaleRevision("stale revision")
            if existing is None:
                cursor.execute(
                    "INSERT INTO lil_tweak_decisions "
                    "(owner_id,idempotency_key,request_hash,job_id) "
                    "VALUES (%s,%s,%s,%s)",
                    (owner_id, idempotency_key, request_hash, job_id),
                )
            self._insert_event_cursor(
                cursor, job_id, owner_id, event_kind, event_data
            )
            return self._fetch_job(cursor, job_id, owner_id)

    def decide_job_idempotent(
        self,
        job_id: str,
        *,
        owner_id: str,
        expected_revision: int,
        idempotency_key: str,
        request_hash: str,
        decision: str,
        proposal_digest: str,
        approval_proposal: Mapping[str, Any] | None = None,
        approval_token_hash: str | None = None,
        expires_at: float | None = None,
        now: float | None = None,
    ) -> Job:
        current_time = time.time() if now is None else now
        identity = f"{owner_id}\n{idempotency_key}"
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (identity,),
            )
            cursor.execute(
                "SELECT request_hash,job_id FROM lil_tweak_decisions "
                "WHERE owner_id=%s AND idempotency_key=%s FOR UPDATE",
                (owner_id, idempotency_key),
            )
            existing = cursor.fetchone()
            if existing is not None and (
                existing[0] != request_hash or str(existing[1]) != job_id
            ):
                raise IdempotencyConflict("idempotency key reused")
            current = self._fetch_job(cursor, job_id, owner_id, for_update=True)
            if existing is not None and current.state in {
                JobState.APPLYING,
                JobState.COMPLETED,
                JobState.REJECTED,
            }:
                return current
            if (
                current.state is not JobState.AWAITING_APPROVAL
                or current.revision != expected_revision
                or current.proposal_digest != proposal_digest
            ):
                raise StaleRevision("stale revision")
            if decision == "reject":
                transition(current.state, JobState.REJECTED)
                cursor.execute(
                    "UPDATE lil_tweak_jobs SET state='rejected',revision=revision+1,"
                    "updated_at=now() WHERE id=%s AND owner_id=%s AND revision=%s",
                    (job_id, owner_id, current.revision),
                )
                if cursor.rowcount != 1:
                    raise StaleRevision("stale revision")
                if existing is None:
                    cursor.execute(
                        "INSERT INTO lil_tweak_decisions "
                        "(owner_id,idempotency_key,request_hash,job_id) "
                        "VALUES (%s,%s,%s,%s)",
                        (owner_id, idempotency_key, request_hash, job_id),
                    )
                self._insert_event_cursor(cursor, job_id, owner_id, "rejected", {})
                return self._fetch_job(cursor, job_id, owner_id)
            if (
                decision != "approve"
                or approval_proposal is None
                or current.approval_proposal is None
                or not _json_type_equal(
                    dict(approval_proposal), dict(current.approval_proposal)
                )
                or current.source_digest is None
                or approval_proposal.get("action") != "export_patch"
                or approval_proposal.get("target") != "owner_download"
                or approval_proposal.get("proposalDigest") != proposal_digest
                or approval_proposal.get("sourceDigest") != current.source_digest
                or not isinstance(approval_proposal.get("policyVersion"), str)
                or not isinstance(approval_proposal.get("resourceProfile"), Mapping)
                or not _valid_sha256(approval_token_hash)
                or expires_at is None
                or expires_at <= current_time
            ):
                raise ApprovalError("invalid approval")
            transition(
                current.state,
                JobState.APPLYING,
                proposal_digest=proposal_digest,
                approved_digest=proposal_digest,
                approval_recorded=True,
                approval_consumed=False,
            )
            cursor.execute(
                "SELECT token_hash,action,target,source_digest,policy_version,resource_profile,"
                "extract(epoch from expires_at),consumed_at "
                "FROM lil_tweak_approvals WHERE job_id=%s AND revision=%s "
                "AND proposal_digest=%s FOR UPDATE",
                (job_id, current.revision, proposal_digest),
            )
            approval_row = cursor.fetchone()
            resource_profile = dict(approval_proposal["resourceProfile"])
            if approval_row is None:
                cursor.execute(
                    "INSERT INTO lil_tweak_approvals "
                    "(token_hash,job_id,owner_id,revision,proposal_digest,source_digest,"
                    "action,target,policy_version,resource_profile,expires_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s,'export_patch','owner_download',"
                    "%s,%s::jsonb,to_timestamp(%s))",
                    (
                        approval_token_hash,
                        job_id,
                        owner_id,
                        current.revision,
                        proposal_digest,
                        current.source_digest,
                        approval_proposal["policyVersion"],
                        json.dumps(resource_profile, sort_keys=True, separators=(",", ":")),
                        expires_at,
                    ),
                )
            else:
                if (
                    approval_row[0] != approval_token_hash
                    or approval_row[1] != "export_patch"
                    or approval_row[2] != "owner_download"
                    or approval_row[3] != current.source_digest
                    or approval_row[4] != approval_proposal["policyVersion"]
                    or not _json_type_equal(dict(approval_row[5]), resource_profile)
                    or float(approval_row[6]) != float(expires_at)
                    or float(approval_row[6]) <= current_time
                    or approval_row[7] is not None
                ):
                    raise ApprovalError("invalid approval")
            cursor.execute(
                "UPDATE lil_tweak_jobs SET state='applying',revision=revision+1,"
                "approval_consumed=false,updated_at=now() "
                "WHERE id=%s AND owner_id=%s AND revision=%s",
                (job_id, owner_id, current.revision),
            )
            if cursor.rowcount != 1:
                raise StaleRevision("stale revision")
            if existing is None:
                cursor.execute(
                    "INSERT INTO lil_tweak_decisions "
                    "(owner_id,idempotency_key,request_hash,job_id) "
                    "VALUES (%s,%s,%s,%s)",
                    (owner_id, idempotency_key, request_hash, job_id),
                )
            approved_data = {
                "revision": current.revision,
                "proposal_digest": proposal_digest,
                "source_digest": current.source_digest,
                "expires_at": expires_at,
            }
            self._ensure_event_cursor(
                cursor, job_id, owner_id, "approved", approved_data
            )
            self._ensure_event_cursor(
                cursor,
                job_id,
                owner_id,
                "applying",
                {"action": "export_patch"},
            )
            return self._fetch_job(cursor, job_id, owner_id)

    def consume_export_idempotent(
        self,
        job_id: str,
        *,
        owner_id: str,
        expected_revision: int,
        idempotency_key: str,
        request_hash: str,
        approval_token: str,
        proposal_digest: str,
        source_digest: str,
        policy_version: str,
        resource_profile: Mapping[str, Any],
        evidence_name: str,
        evidence_sha256: str,
        evidence_size_bytes: int,
        now: float | None = None,
    ) -> Job:
        current_time = time.time() if now is None else now
        stored_key = f"export:{idempotency_key}"
        if not _CANONICAL_APPROVAL_TOKEN.fullmatch(approval_token):
            raise ApprovalError("invalid approval")
        token_hash = hashlib.sha256(approval_token.encode("ascii")).hexdigest()
        identity = f"{owner_id}\n{stored_key}"
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (identity,),
            )
            cursor.execute(
                "SELECT request_hash,job_id FROM lil_tweak_decisions "
                "WHERE owner_id=%s AND idempotency_key=%s FOR UPDATE",
                (owner_id, stored_key),
            )
            existing = cursor.fetchone()
            if existing is not None and (
                existing[0] != request_hash or str(existing[1]) != job_id
            ):
                raise IdempotencyConflict("idempotency key reused")
            current = self._fetch_job(cursor, job_id, owner_id, for_update=True)
            cursor.execute(
                "SELECT revision,proposal_digest,source_digest,action,target,"
                "policy_version,resource_profile,extract(epoch from expires_at),consumed_at "
                "FROM lil_tweak_approvals WHERE token_hash=%s AND job_id=%s "
                "AND owner_id=%s FOR UPDATE",
                (token_hash, job_id, owner_id),
            )
            approval = cursor.fetchone()
            if existing is not None:
                if (
                    approval is None
                    or float(approval[7]) <= current_time
                    or approval[8] is None
                    or current.state is not JobState.COMPLETED
                    or not current.approval_consumed
                ):
                    raise ApprovalError("invalid approval")
                return current
            descriptor = (current.evidence_manifest or {}).get(evidence_name)
            if (
                approval is None
                or approval[1] != proposal_digest
                or approval[2] != source_digest
                or approval[3] != "export_patch"
                or approval[4] != "owner_download"
                or approval[5] != policy_version
                or not _json_type_equal(dict(approval[6]), dict(resource_profile))
                or float(approval[7]) <= current_time
                or approval[8] is not None
                or current.state is not JobState.APPLYING
                or current.revision != expected_revision
                or current.proposal_digest != proposal_digest
                or current.source_digest != source_digest
                or current.approval_consumed
                or evidence_name != "changes.patch"
                or not isinstance(descriptor, Mapping)
                or descriptor.get("sha256") != evidence_sha256
                or descriptor.get("bytes") != evidence_size_bytes
            ):
                raise ApprovalError("invalid approval")
            transition(current.state, JobState.COMPLETED)
            cursor.execute(
                "UPDATE lil_tweak_approvals SET consumed_at=to_timestamp(%s) "
                "WHERE token_hash=%s AND consumed_at IS NULL AND expires_at>to_timestamp(%s)",
                (current_time, token_hash, current_time),
            )
            if cursor.rowcount != 1:
                raise ApprovalError("invalid approval")
            cursor.execute(
                "UPDATE lil_tweak_jobs SET state='completed',revision=revision+1,"
                "approval_consumed=true,updated_at=now() WHERE id=%s AND owner_id=%s "
                "AND revision=%s AND state='applying' AND approval_consumed=false",
                (job_id, owner_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise StaleRevision("stale revision")
            cursor.execute(
                "INSERT INTO lil_tweak_decisions "
                "(owner_id,idempotency_key,request_hash,job_id) VALUES (%s,%s,%s,%s)",
                (owner_id, stored_key, request_hash, job_id),
            )
            self._insert_event_cursor(
                cursor,
                job_id,
                owner_id,
                "completed",
                {"action": "export_patch"},
            )
            return self._fetch_job(cursor, job_id, owner_id)

    def transition_job(
        self,
        job_id: str,
        *,
        owner_id: str,
        expected_revision: int,
        state: JobState | str,
        event_kind: str,
        event_data: Mapping[str, Any] | None = None,
        proposal_digest: str | None = None,
        evidence_manifest: Mapping[str, Any] | None = None,
        approved_digest: str | None = None,
        approval_consumed: bool = False,
        summary: str | None = None,
        source_digest: str | None = None,
        approval_proposal: Mapping[str, Any] | None = None,
        lease: JobLease | None = None,
    ) -> Job:
        target = JobState(state)
        validated_event = _validated_event_data(event_kind, event_data)
        with self._connect() as connection, connection.cursor() as cursor:
            current = self._fetch_job(
                cursor, job_id, owner_id, for_update=True
            )
            if current.revision != expected_revision:
                raise StaleRevision("stale revision")
            current_time = time.time()
            if lease is not None:
                if (
                    current.lease_owner is None
                    or lease.job_id != job_id
                    or lease.owner_id != owner_id
                    or lease.worker_id != current.lease_owner
                    or lease.generation != current.lease_generation
                    or current.lease_expires_at is None
                    or current.lease_expires_at <= current_time
                ):
                    raise StaleLease("stale lease")
            elif (
                current.lease_owner is not None
                and current.lease_expires_at is not None
                and current.lease_expires_at > current_time
            ):
                raise StaleLease("stale lease")
            transition(
                current.state,
                target,
                proposal_digest=proposal_digest,
                evidence_manifest=evidence_manifest,
                approved_digest=approved_digest,
                approval_consumed=approval_consumed,
            )
            cursor.execute(
                "UPDATE lil_tweak_jobs SET state=%s,revision=revision+1,"
                "proposal_digest=COALESCE(%s,proposal_digest),"
                "evidence_manifest=COALESCE(%s::jsonb,evidence_manifest),"
                "summary=COALESCE(%s,summary),"
                "source_digest=COALESCE(%s,source_digest),"
                "approval_proposal=COALESCE(%s::jsonb,approval_proposal),"
                "approval_consumed=approval_consumed OR %s,updated_at=now() "
                "WHERE id=%s AND owner_id=%s AND revision=%s"
                + (
                    " AND lease_owner=%s AND lease_generation=%s AND lease_expires_at>now()"
                    if lease is not None
                    else " AND (lease_owner IS NULL OR lease_expires_at<=now())"
                ),
                (
                    target.value,
                    proposal_digest,
                    json.dumps(evidence_manifest)
                    if evidence_manifest is not None
                    else None,
                    summary,
                    source_digest,
                    json.dumps(approval_proposal)
                    if approval_proposal is not None
                    else None,
                    approval_consumed,
                    job_id,
                    owner_id,
                    expected_revision,
                    *((lease.worker_id, lease.generation) if lease is not None else ()),
                ),
            )
            if cursor.rowcount != 1:
                if lease is None:
                    raise StaleRevision("stale revision")
                raise StaleLease("stale lease")
            if evidence_manifest is not None:
                owner_prefix = hashlib.sha256(owner_id.encode("utf-8")).hexdigest()
                for name, descriptor in sorted(evidence_manifest.items()):
                    if not isinstance(descriptor, Mapping):
                        continue
                    digest = descriptor.get("sha256")
                    size = descriptor.get("bytes")
                    object_key = descriptor.get("objectKey")
                    if not isinstance(digest, str) or not isinstance(size, int):
                        continue
                    if not isinstance(object_key, str):
                        object_key = f"{owner_prefix}/{job_id}/{name}"
                    cursor.execute(
                        "INSERT INTO lil_tweak_evidence "
                        "(id,job_id,owner_id,name,object_key,sha256,size_bytes) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s) "
                        "ON CONFLICT (job_id,name) DO UPDATE SET "
                        "object_key=EXCLUDED.object_key,sha256=EXCLUDED.sha256,"
                        "size_bytes=EXCLUDED.size_bytes",
                        (
                            str(uuid.uuid5(uuid.NAMESPACE_URL, f"{job_id}:{name}")),
                            job_id,
                            owner_id,
                            name,
                            object_key,
                            digest,
                            size,
                        ),
                    )
            self._insert_event_cursor(
                cursor, job_id, owner_id, event_kind, validated_event
            )
            return self._fetch_job(cursor, job_id, owner_id)

    def _fetch_job(
        self, cursor: Any, job_id: str, owner_id: str, *, for_update: bool = False
    ) -> Job:
        cursor.execute(
            "SELECT id,owner_id,mode,prompt,state,revision,proposal_digest,"
            "evidence_manifest,summary,source_manifest,source_digest,"
            "approval_proposal,approval_consumed,"
            "project_context,"
            "git_source,"
            "extract(epoch from created_at),extract(epoch from updated_at),"
            "cancel_requested,lease_owner,lease_generation,"
            "extract(epoch from lease_expires_at) "
            "FROM lil_tweak_jobs WHERE id=%s AND owner_id=%s"
            + (" FOR UPDATE" if for_update else ""),
            (job_id, owner_id),
        )
        row = cursor.fetchone()
        if not row:
            raise JobNotFound("job not found")
        cursor.execute(
            "SELECT name,extract(epoch from created_at) FROM lil_tweak_evidence "
            "WHERE job_id=%s AND owner_id=%s ORDER BY name",
            (job_id, owner_id),
        )
        evidence_created_at = {
            name: float(created_at) for name, created_at in cursor.fetchall()
        }
        return Job(
            id=str(row[0]),
            owner_id=row[1],
            mode=JobMode(row[2]),
            prompt=row[3],
            state=JobState(row[4]),
            revision=row[5],
            proposal_digest=row[6],
            evidence_manifest=row[7],
            evidence_created_at=evidence_created_at,
            summary=row[8],
            sources=tuple(SourceSpec(**item) for item in (row[9] or [])),
            source_digest=row[10],
            approval_proposal=row[11],
            approval_consumed=row[12],
            project_context=row[13],
            git_source=GitSourceSpec(**row[14]) if row[14] else None,
            created_at=float(row[15]),
            updated_at=float(row[16]),
            cancel_requested=row[17],
            lease_owner=row[18],
            lease_generation=int(row[19]),
            lease_expires_at=float(row[20]) if row[20] is not None else None,
        )

    def get_job(self, job_id: str, owner_id: str) -> Job | None:
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                return self._fetch_job(cursor, job_id, owner_id)
        except JobNotFound:
            return None

    def update_job(
        self,
        job_id: str,
        *,
        owner_id: str,
        expected_revision: int,
        state: JobState | str,
        proposal_digest: str | None = None,
        evidence_manifest: Mapping[str, Any] | None = None,
        approved_digest: str | None = None,
        approval_consumed: bool = False,
        summary: str | None = None,
        source_digest: str | None = None,
        approval_proposal: Mapping[str, Any] | None = None,
        lease: JobLease | None = None,
    ) -> Job:
        target = JobState(state)
        with self._connect() as connection, connection.cursor() as cursor:
            current = self._fetch_job(cursor, job_id, owner_id)
            if current.revision != expected_revision:
                raise StaleRevision("stale revision")
            current_time = time.time()
            if lease is not None:
                if (
                    current.lease_owner is None
                    or lease.job_id != job_id
                    or lease.owner_id != owner_id
                    or lease.worker_id != current.lease_owner
                    or lease.generation != current.lease_generation
                    or current.lease_expires_at is None
                    or current.lease_expires_at <= current_time
                ):
                    raise StaleLease("stale lease")
            elif (
                current.lease_owner is not None
                and current.lease_expires_at is not None
                and current.lease_expires_at > current_time
            ):
                    raise StaleLease("stale lease")
            transition(
                current.state,
                target,
                proposal_digest=proposal_digest,
                evidence_manifest=evidence_manifest,
                approved_digest=approved_digest,
                approval_consumed=approval_consumed,
            )
            cursor.execute(
                "UPDATE lil_tweak_jobs SET state=%s,revision=revision+1,"
                "proposal_digest=COALESCE(%s,proposal_digest),"
                "evidence_manifest=COALESCE(%s::jsonb,evidence_manifest),"
                "summary=COALESCE(%s,summary),"
                "source_digest=COALESCE(%s,source_digest),"
                "approval_proposal=COALESCE(%s::jsonb,approval_proposal),"
                "approval_consumed=approval_consumed OR %s,"
                "updated_at=now() WHERE id=%s AND owner_id=%s AND revision=%s"
                + (
                    " AND lease_owner=%s AND lease_generation=%s AND lease_expires_at>now()"
                    if lease is not None
                    else " AND (lease_owner IS NULL OR lease_expires_at<=now())"
                ),
                (
                    target.value,
                    proposal_digest,
                    json.dumps(evidence_manifest) if evidence_manifest is not None else None,
                    summary,
                    source_digest,
                    json.dumps(approval_proposal)
                    if approval_proposal is not None
                    else None,
                    approval_consumed,
                    job_id,
                    owner_id,
                    expected_revision,
                    *(
                        (lease.worker_id, lease.generation)
                        if lease is not None
                        else ()
                    ),
                ),
            )
            if cursor.rowcount != 1:
                if lease is None:
                    raise StaleRevision("stale revision")
                raise StaleLease("stale lease")
            if evidence_manifest is not None:
                owner_prefix = hashlib.sha256(owner_id.encode("utf-8")).hexdigest()
                for name, descriptor in sorted(evidence_manifest.items()):
                    if not isinstance(descriptor, Mapping):
                        continue
                    digest = descriptor.get("sha256")
                    size = descriptor.get("bytes")
                    object_key = descriptor.get("objectKey")
                    if not isinstance(digest, str) or not isinstance(size, int):
                        continue
                    if not isinstance(object_key, str):
                        object_key = f"{owner_prefix}/{job_id}/{name}"
                    cursor.execute(
                        "INSERT INTO lil_tweak_evidence "
                        "(id,job_id,owner_id,name,object_key,sha256,size_bytes) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s) "
                        "ON CONFLICT (job_id,name) DO UPDATE SET "
                        "object_key=EXCLUDED.object_key,sha256=EXCLUDED.sha256,"
                        "size_bytes=EXCLUDED.size_bytes",
                        (
                            str(uuid.uuid5(uuid.NAMESPACE_URL, f"{job_id}:{name}")),
                            job_id,
                            owner_id,
                            name,
                            object_key,
                            digest,
                            size,
                        ),
                    )
            return self._fetch_job(cursor, job_id, owner_id)

    def request_cancel(
        self, job_id: str, *, owner_id: str, expected_revision: int
    ) -> Job:
        with self._connect() as connection, connection.cursor() as cursor:
            current = self._fetch_job(cursor, job_id, owner_id)
            if current.revision != expected_revision:
                raise StaleRevision("stale revision")
            transition(current.state, JobState.CANCELLED)
            target_state = (
                JobState.CANCELLED
                if current.state in {JobState.AWAITING_APPROVAL, JobState.APPLYING}
                else current.state
            )
            cursor.execute(
                "UPDATE lil_tweak_jobs SET state=%s,cancel_requested=true,revision=revision+1,"
                "updated_at=now() WHERE id=%s AND owner_id=%s AND revision=%s",
                (target_state.value, job_id, owner_id, expected_revision),
            )
            if cursor.rowcount != 1:
                cursor.execute(
                    "SELECT revision FROM lil_tweak_jobs WHERE id=%s AND owner_id=%s",
                    (job_id, owner_id),
                )
                if cursor.fetchone() is None:
                    raise JobNotFound("job not found")
                raise StaleRevision("stale revision")
            return self._fetch_job(cursor, job_id, owner_id)

    def append_event(
        self,
        job_id: str,
        owner_id: str,
        kind: str,
        data: Mapping[str, Any] | None = None,
    ) -> JobEvent:
        if not kind:
            raise ValueError("event kind is required")
        event_data = _validated_event_data(kind, data)
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT 1 FROM lil_tweak_jobs WHERE id=%s AND owner_id=%s FOR UPDATE",
                (job_id, owner_id),
            )
            if cursor.fetchone() is None:
                raise JobNotFound("job not found")
            return self._insert_event_cursor(
                cursor, job_id, owner_id, kind, event_data
            )

    def _insert_event_cursor(
        self,
        cursor: Any,
        job_id: str,
        owner_id: str,
        kind: str,
        event_data: Mapping[str, Any],
    ) -> JobEvent:
        cursor.execute(
            "SELECT COALESCE(MAX(sequence),0)+1 FROM lil_tweak_events WHERE job_id=%s",
            (job_id,),
        )
        sequence = int(cursor.fetchone()[0])
        cursor.execute(
            "INSERT INTO lil_tweak_events "
            "(job_id,sequence,owner_id,kind,redacted_data) VALUES (%s,%s,%s,%s,%s::jsonb) "
            "RETURNING extract(epoch from created_at)",
            (job_id, sequence, owner_id, kind, json.dumps(event_data)),
        )
        created_at = float(cursor.fetchone()[0])
        return JobEvent(job_id, sequence, kind, copy.deepcopy(event_data), created_at)

    def _ensure_event_cursor(
        self,
        cursor: Any,
        job_id: str,
        owner_id: str,
        kind: str,
        event_data: Mapping[str, Any],
    ) -> None:
        validated = _validated_event_data(kind, event_data)
        cursor.execute(
            "SELECT 1 FROM lil_tweak_events WHERE job_id=%s AND owner_id=%s "
            "AND kind=%s AND redacted_data=%s::jsonb LIMIT 1",
            (job_id, owner_id, kind, json.dumps(validated)),
        )
        if cursor.fetchone() is None:
            self._insert_event_cursor(cursor, job_id, owner_id, kind, validated)

    def list_events(self, job_id: str, owner_id: str) -> list[JobEvent]:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT 1 FROM lil_tweak_jobs WHERE id=%s AND owner_id=%s",
                (job_id, owner_id),
            )
            if cursor.fetchone() is None:
                raise JobNotFound("job not found")
            cursor.execute(
                "SELECT sequence,kind,redacted_data,extract(epoch from created_at) "
                "FROM lil_tweak_events WHERE job_id=%s AND owner_id=%s ORDER BY sequence",
                (job_id, owner_id),
            )
            return [
                JobEvent(job_id, int(row[0]), row[1], copy.deepcopy(row[2]), float(row[3]))
                for row in cursor.fetchall()
            ]

    def create_approval(
        self,
        job_id: str,
        *,
        owner_id: str,
        revision: int,
        proposal_digest: str,
        source_digest: str,
        action: str,
        target: str,
        policy_version: str,
        resource_profile: Mapping[str, Any],
        approval_token_hash: str,
        expires_at: float,
        now: float | None = None,
    ) -> Approval:
        current_time = time.time() if now is None else now
        if expires_at <= current_time or not _valid_sha256(approval_token_hash):
            raise ApprovalError("invalid approval")
        with self._connect() as connection, connection.cursor() as cursor:
            current = self._fetch_job(cursor, job_id, owner_id)
            if (
                current.revision != revision
                or current.proposal_digest != proposal_digest
                or current.source_digest != source_digest
            ):
                raise ApprovalError("invalid approval")
            cursor.execute(
                "INSERT INTO lil_tweak_approvals "
                "(token_hash,job_id,owner_id,revision,proposal_digest,source_digest,"
                "action,target,policy_version,resource_profile,expires_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,to_timestamp(%s))",
                (
                    approval_token_hash,
                    job_id,
                    owner_id,
                    revision,
                    proposal_digest,
                    source_digest,
                    action,
                    target,
                    policy_version,
                    json.dumps(resource_profile, sort_keys=True, separators=(",", ":")),
                    expires_at,
                ),
            )
            return Approval(
                approval_token_hash,
                job_id,
                owner_id,
                revision,
                proposal_digest,
                source_digest,
                action,
                target,
                policy_version,
                copy.deepcopy(dict(resource_profile)),
                expires_at,
            )

    def consume_approval(
        self,
        token: str,
        *,
        owner_id: str,
        job_id: str,
        revision: int,
        proposal_digest: str,
        source_digest: str,
        policy_version: str,
        resource_profile: Mapping[str, Any],
        now: float | None = None,
    ) -> Approval:
        current_time = time.time() if now is None else now
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT a.job_id,a.owner_id,a.revision,a.proposal_digest,a.action,a.target,"
                "a.source_digest,a.policy_version,a.resource_profile,"
                "extract(epoch from a.expires_at),a.consumed_at,"
                "j.revision,j.proposal_digest,j.source_digest "
                "FROM lil_tweak_approvals a JOIN lil_tweak_jobs j ON j.id=a.job_id "
                "WHERE a.token_hash=%s FOR UPDATE OF a",
                (token_hash,),
            )
            row = cursor.fetchone()
            if (
                row is None
                or str(row[0]) != job_id
                or row[1] != owner_id
                or int(row[2]) != revision
                or row[3] != proposal_digest
                or row[6] != source_digest
                or row[7] != policy_version
                or not _json_type_equal(dict(row[8]), dict(resource_profile))
                or float(row[9]) <= current_time
                or row[10] is not None
                or int(row[11]) != revision
                or row[12] != proposal_digest
                or row[13] != source_digest
            ):
                raise ApprovalError("invalid approval")
            cursor.execute(
                "UPDATE lil_tweak_approvals SET consumed_at=to_timestamp(%s) "
                "WHERE token_hash=%s AND consumed_at IS NULL",
                (current_time, token_hash),
            )
            if cursor.rowcount != 1:
                raise ApprovalError("invalid approval")
            return Approval(
                token_hash,
                job_id,
                owner_id,
                revision,
                proposal_digest,
                source_digest,
                row[4],
                row[5],
                row[7],
                copy.deepcopy(row[8]),
                float(row[9]),
                consumed=True,
                consumed_at=current_time,
            )

    def get_decision(
        self, owner_id: str, idempotency_key: str, request_hash: str
    ) -> Job | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT request_hash,job_id FROM lil_tweak_decisions "
                "WHERE owner_id=%s AND idempotency_key=%s",
                (owner_id, idempotency_key),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            if row[0] != request_hash:
                raise IdempotencyConflict("idempotency key reused")
            return self._fetch_job(cursor, str(row[1]), owner_id)

    def record_decision(
        self, owner_id: str, idempotency_key: str, request_hash: str, job_id: str
    ) -> Job:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO lil_tweak_decisions "
                "(owner_id,idempotency_key,request_hash,job_id) VALUES (%s,%s,%s,%s) "
                "ON CONFLICT (owner_id,idempotency_key) DO NOTHING",
                (owner_id, idempotency_key, request_hash, job_id),
            )
            cursor.execute(
                "SELECT request_hash,job_id FROM lil_tweak_decisions "
                "WHERE owner_id=%s AND idempotency_key=%s",
                (owner_id, idempotency_key),
            )
            row = cursor.fetchone()
            if row is None or row[0] != request_hash or str(row[1]) != job_id:
                raise IdempotencyConflict("idempotency key reused")
            return self._fetch_job(cursor, job_id, owner_id)
