"""Small dependency-light ASGI service for the trusted core protocol."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import time
from datetime import UTC, datetime
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlsplit

from .contracts import JobMode, JobState, TERMINAL_STATES
from .evidence import EvidenceStore, EvidenceTooLarge
from .limits import MAX_EVIDENCE_BYTES
from .orchestrator import AdmissionUnavailable
from .signing import AuthenticationError, ReplayError, verify_request
from .store import (
    ApprovalError,
    IdempotencyConflict,
    GitSourceSpec,
    Job,
    JobNotFound,
    JobStore,
    SourceSpec,
    StaleRevision,
)


JOB_BODY_LIMIT = 32 * 1024
DECISION_BODY_LIMIT = 8 * 1024
STATUS_BODY_LIMIT = 256 * 1024
_JOB_PATH = re.compile(r"^/v1/jobs/([A-Za-z0-9-]{1,128})$")
_DECISION_PATH = re.compile(r"^/v1/jobs/([A-Za-z0-9-]{1,128})/decisions$")
_EXPORT_PATH = re.compile(r"^/v1/jobs/([A-Za-z0-9-]{1,128})/exports/patch$")
_CANCEL_PATH = re.compile(r"^/v1/jobs/([A-Za-z0-9-]{1,128})/cancel$")
_EVIDENCE_PATH = re.compile(
    r"^/v1/jobs/([A-Za-z0-9-]{1,128})/evidence/"
    r"(plan\.md|changes\.patch|tests\.log|manifest\.json|summary\.md)$"
)
_PUBLIC_JOB_ID = re.compile(r"^job:[0-9a-f]{32}$")
_SOURCE_ID = re.compile(r"^src:[0-9a-f]{32}$")
_OWNER_SCOPE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ApiProblem(Exception):
    def __init__(self, status: int, code: str) -> None:
        self.status = status
        self.code = code
        super().__init__(code)


def _parse_iso_timestamp(value: Any) -> float:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("invalid timestamp")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo is None:
        raise ValueError("invalid timestamp")
    return parsed.timestamp()


def _headers(scope: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_name, raw_value in scope.get("headers", []):
        name = raw_name.decode("latin-1").lower()
        if name in result:
            raise ApiProblem(400, "invalid_request")
        result[name] = raw_value.decode("latin-1")
    return result


async def _read_body(receive: Any, limit: int) -> bytes:
    body = bytearray()
    while True:
        message = await receive()
        if message.get("type") == "http.disconnect":
            if body:
                return bytes(body)
            return b""
        if message.get("type") != "http.request":
            raise ApiProblem(400, "invalid_request")
        chunk = message.get("body", b"")
        if not isinstance(chunk, bytes):
            raise ApiProblem(400, "invalid_request")
        body.extend(chunk)
        if len(body) > limit:
            raise ApiProblem(413, "body_too_large")
        if not message.get("more_body", False):
            return bytes(body)


def _job_json(job: Job) -> dict[str, Any]:
    evidence_categories = {
        "plan.md": ("plan", "text/markdown"),
        "changes.patch": ("patch", "text/x-diff"),
        "tests.log": ("tests", "text/plain"),
        "manifest.json": ("manifest", "application/json"),
        "summary.md": ("summary", "text/markdown"),
    }
    evidence = []
    for name, descriptor in sorted((job.evidence_manifest or {}).items()):
        if isinstance(descriptor, str):
            digest, size = descriptor, 0
        elif isinstance(descriptor, Mapping):
            digest = descriptor.get("sha256")
            size = descriptor.get("bytes")
            if not isinstance(digest, str) or not isinstance(size, int) or size < 0:
                continue
        else:
            continue
        category, media_type = evidence_categories.get(name, ("log", "application/octet-stream"))
        evidence_timestamp = (job.evidence_created_at or {}).get(name, job.created_at)
        created_at = (
            datetime.fromtimestamp(evidence_timestamp, UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
        evidence_id = hashlib.sha256(f"{job.id}\n{name}".encode()).hexdigest()[:32]
        evidence.append(
            {
                "id": f"evidence:{evidence_id}",
                "category": category,
                "filename": name,
                "mediaType": media_type,
                "sizeBytes": size,
                "sha256": digest,
                "createdAt": created_at,
                "corePath": f"/v1/jobs/{job.id}/evidence/{name}",
            }
        )
    return {
        "id": job.id,
        "mode": job.mode.value,
        "state": job.state.value,
        "revision": job.revision,
        "coreRevision": job.revision,
        "proposal_digest": job.proposal_digest,
        "proposalDigest": job.proposal_digest,
        "sourceDigest": job.source_digest,
        "gitSource": {
            "repositoryUrl": job.git_source.repository_url,
            "commit": job.git_source.commit,
        } if job.git_source is not None else None,
        "approvalProposal": copy.deepcopy(job.approval_proposal),
        "approvalConsumed": job.approval_consumed,
        "evidence_manifest": dict(job.evidence_manifest or {}),
        "evidence": evidence,
        "summary": job.summary,
        "cancel_requested": job.cancel_requested,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
    }


def _json_body(body: bytes) -> dict[str, Any]:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ApiProblem(400, "invalid_request") from None
    if not isinstance(value, dict):
        raise ApiProblem(400, "invalid_request")
    return value


def _source_manifest(payload: Mapping[str, Any]) -> tuple[SourceSpec, ...]:
    raw_sources = payload.get("sources", [])
    if not isinstance(raw_sources, list) or len(raw_sources) > 10:
        raise ApiProblem(400, "invalid_request")
    if not raw_sources:
        return ()
    public_job_id = payload.get("id")
    owner_scope = payload.get("ownerKey")
    if (
        not isinstance(public_job_id, str)
        or not _PUBLIC_JOB_ID.fullmatch(public_job_id)
        or not isinstance(owner_scope, str)
        or not _OWNER_SCOPE.fullmatch(owner_scope)
    ):
        raise ApiProblem(400, "invalid_source_manifest")
    prefix = f"engineering/{owner_scope}/jobs/{public_job_id}/sources/"
    sources: list[SourceSpec] = []
    seen_names: set[str] = set()
    total = 0
    for raw in raw_sources:
        if not isinstance(raw, dict):
            raise ApiProblem(400, "invalid_source_manifest")
        source_id = raw.get("id")
        filename = raw.get("filename")
        media_type = raw.get("mediaType")
        size = raw.get("sizeBytes")
        object_key = raw.get("r2Key")
        digest = raw.get("sha256")
        if (
            not isinstance(source_id, str)
            or not _SOURCE_ID.fullmatch(source_id)
            or not isinstance(filename, str)
            or not filename
            or filename in (".", "..")
            or len(filename) > 255
            or "/" in filename
            or "\\" in filename
            or any(ord(character) < 32 or ord(character) == 127 for character in filename)
            or filename.casefold() in seen_names
            or not isinstance(media_type, str)
            or not media_type
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= 25 * 1024 * 1024
            or not isinstance(object_key, str)
            or object_key != prefix + source_id
            or not isinstance(digest, str)
            or not _SHA256.fullmatch(digest)
        ):
            raise ApiProblem(400, "invalid_source_manifest")
        total += size
        if total > 100 * 1024 * 1024:
            raise ApiProblem(400, "invalid_source_manifest")
        seen_names.add(filename.casefold())
        sources.append(
            SourceSpec(source_id, filename, media_type, size, object_key, digest)
        )
    return tuple(sources)


def _project_context(payload: Mapping[str, Any]) -> Mapping[str, Any] | None:
    context = payload.get("projectContext")
    if context is None:
        return None
    allowed = {
        "schemaVersion",
        "projectId",
        "name",
        "description",
        "status",
        "requirements",
        "milestones",
        "board",
        "notes",
    }
    if (
        not isinstance(context, dict)
        or set(context) - allowed
        or context.get("schemaVersion") != "project-context-v1"
        or not isinstance(context.get("projectId"), str)
        or not context["projectId"]
        or not isinstance(context.get("name"), str)
        or not context["name"]
        or not _bounded_json_value(context, depth=0)
        or len(
            json.dumps(
                context, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        )
        > 8 * 1024
    ):
        raise ApiProblem(400, "invalid_project_context")
    return copy.deepcopy(context)


def _git_source(payload: Mapping[str, Any]) -> GitSourceSpec | None:
    raw = payload.get("gitSource")
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) != {"repositoryUrl", "commit"}:
        raise ApiProblem(400, "invalid_git_source")
    repository_url = raw.get("repositoryUrl")
    commit = raw.get("commit")
    if not isinstance(repository_url, str) or not isinstance(commit, str):
        raise ApiProblem(400, "invalid_git_source")
    parsed = urlsplit(repository_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", commit)
    ):
        raise ApiProblem(400, "invalid_git_source")
    return GitSourceSpec(repository_url, commit.lower())


def _bounded_json_value(value: Any, *, depth: int) -> bool:
    if depth > 4:
        return False
    if value is None or isinstance(value, (str, bool, int)):
        return not isinstance(value, str) or len(value.encode("utf-8")) <= 4096
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return len(value) <= 100 and all(
            _bounded_json_value(item, depth=depth + 1) for item in value
        )
    if isinstance(value, dict):
        return len(value) <= 100 and all(
            isinstance(key, str)
            and len(key) <= 100
            and _bounded_json_value(item, depth=depth + 1)
            for key, item in value.items()
        )
    return False


def _json_exact(left: Any, right: Any) -> bool:
    """Compare canonical JSON values without Python's bool/int coercion."""

    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _json_exact(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_exact(a, b) for a, b in zip(left, right, strict=True)
        )
    return left == right


class LilTweakApi:
    def __init__(
        self,
        *,
        store: JobStore,
        signing_keys: Mapping[str, bytes | str],
        canonical_owner_id: str,
        readiness: Callable[[], bool | Mapping[str, bool]],
        clock: Callable[[], float] = time.time,
        on_job_queued: Callable[[str, str], None] | None = None,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        if (
            not signing_keys
            or not re.fullmatch(r"[0-9a-f]{32}", canonical_owner_id)
        ):
            raise ValueError("signing keys and owner are required")
        self.store = store
        self.signing_keys = dict(signing_keys)
        self.canonical_owner_id = canonical_owner_id
        self.readiness = readiness
        self.clock = clock
        self.on_job_queued = on_job_queued
        self.evidence_store = evidence_store

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            return
        try:
            method = str(scope.get("method", "")).upper()
            path = str(scope.get("path", ""))
            query = bytes(scope.get("query_string", b"")).decode("ascii", "strict")
            target = path + (f"?{query}" if query else "")
            headers = _headers(scope)
            if method == "GET" and path == "/healthz":
                await self._respond(send, 200, {"status": "ok"})
                return
            limit = JOB_BODY_LIMIT if path == "/v1/jobs" else DECISION_BODY_LIMIT
            body = await _read_body(receive, limit)
            owner_id, idempotency_key = self._authenticate(
                method, target, body, headers, mutation=method in {"POST", "PUT", "PATCH", "DELETE"}
            )
            if method == "GET" and path == "/readyz":
                result = self.readiness()
                checks = dict(result) if isinstance(result, Mapping) else {"service": bool(result)}
                if checks and all(checks.values()):
                    await self._respond(send, 200, {"status": "ready", "checks": checks})
                else:
                    await self._respond(
                        send, 503, {"error": {"code": "not_ready"}, "checks": checks}
                    )
                return
            if method == "POST" and path == "/v1/jobs":
                payload = _json_body(body)
                allowed_create = {
                    "id",
                    "ownerKey",
                    "mode",
                    "projectId",
                    "prompt",
                    "requestR2Key",
                    "source",
                    "sources",
                    "createdAt",
                    "projectContext",
                    "gitSource",
                }
                if set(payload) - allowed_create:
                    raise ApiProblem(400, "invalid_request")
                public_job_id = payload.get("id")
                if public_job_id is not None and (
                    not isinstance(public_job_id, str)
                    or not _PUBLIC_JOB_ID.fullmatch(public_job_id)
                ):
                    raise ApiProblem(400, "invalid_request")
                payload_owner = payload.get("ownerKey")
                if payload_owner is not None and payload_owner != owner_id:
                    raise ApiProblem(403, "owner_forbidden")
                try:
                    mode = JobMode(payload.get("mode"))
                except (ValueError, TypeError):
                    raise ApiProblem(400, "invalid_request") from None
                prompt = payload.get("prompt")
                if (
                    not isinstance(prompt, str)
                    or not prompt.strip()
                    or len(prompt.encode("utf-8")) > JOB_BODY_LIMIT
                ):
                    raise ApiProblem(400, "invalid_request")
                sources = _source_manifest(payload)
                project_context = _project_context(payload)
                git_source = _git_source(payload)
                if sources and git_source is not None:
                    raise ApiProblem(400, "invalid_source_manifest")
                project_id = payload.get("projectId")
                if project_id is not None and (
                    not isinstance(project_id, str)
                    or project_context is None
                    or project_context.get("projectId") != project_id
                ):
                    raise ApiProblem(400, "invalid_project_context")
                if mode is JobMode.CHAT:
                    if project_context is None:
                        raise ApiProblem(400, "invalid_project_context")
                    if sources or git_source is not None:
                        raise ApiProblem(400, "invalid_source_manifest")
                try:
                    job = self.store.create_job(
                        owner_id,
                        idempotency_key,
                        mode,
                        prompt,
                        sources=sources,
                        project_context=project_context,
                        git_source=git_source,
                    )
                    if job.state is JobState.DRAFT:
                        job = self.store.transition_job(
                            job.id,
                            owner_id=owner_id,
                            expected_revision=job.revision,
                            state=JobState.QUEUED,
                            event_kind="queued",
                            event_data={},
                        )
                        if self.on_job_queued:
                            try:
                                self.on_job_queued(job.id, owner_id)
                            except AdmissionUnavailable:
                                job = self.store.transition_job(
                                    job.id,
                                    owner_id=owner_id,
                                    expected_revision=job.revision,
                                    state=JobState.FAILED,
                                    event_kind="admission_unavailable",
                                    event_data={"code": "admission_unavailable"},
                                )
                                raise ApiProblem(503, "admission_unavailable") from None
                except IdempotencyConflict:
                    raise ApiProblem(409, "idempotency_conflict") from None
                await self._respond(send, 202, _job_json(job))
                return
            status_match = _JOB_PATH.fullmatch(path)
            if method == "GET" and status_match:
                job = self.store.get_job(status_match.group(1), owner_id)
                if job is None:
                    raise ApiProblem(404, "job_not_found")
                await self._respond(send, 200, _job_json(job))
                return
            evidence_match = _EVIDENCE_PATH.fullmatch(path)
            if method == "GET" and evidence_match:
                await self._evidence(
                    send, evidence_match.group(1), evidence_match.group(2), owner_id
                )
                return
            cancel_match = _CANCEL_PATH.fullmatch(path)
            if method == "POST" and cancel_match:
                cancel_key = f"cancel:{idempotency_key}"
                request_hash = hashlib.sha256(
                    b"cancel\0" + path.encode("ascii") + b"\0" + body
                ).hexdigest()
                payload = _json_body(body)
                if (
                    set(payload)
                    - {"jobId", "ownerKey", "revision", "expectedCoreRevision"}
                ):
                    raise ApiProblem(400, "invalid_request")
                expected_revision = self._expected_core_revision(payload)
                try:
                    job = self.store.request_cancel_idempotent(
                        cancel_match.group(1),
                        owner_id=owner_id,
                        expected_revision=expected_revision,
                        idempotency_key=cancel_key,
                        request_hash=request_hash,
                    )
                except JobNotFound:
                    raise ApiProblem(404, "job_not_found") from None
                except StaleRevision:
                    raise ApiProblem(409, "stale_revision") from None
                except IdempotencyConflict:
                    raise ApiProblem(409, "idempotency_conflict") from None
                await self._respond(send, 202, _job_json(job))
                return
            decision_match = _DECISION_PATH.fullmatch(path)
            if method == "POST" and decision_match:
                job = await self._decision(
                    decision_match.group(1),
                    owner_id,
                    idempotency_key,
                    _json_body(body),
                )
                await self._respond(send, 200, job)
                return
            export_match = _EXPORT_PATH.fullmatch(path)
            if method == "POST" and export_match:
                job = self._export_patch(
                    export_match.group(1),
                    owner_id,
                    idempotency_key,
                    path,
                    _json_body(body),
                )
                await self._respond(send, 200, job)
                return
            raise ApiProblem(404, "not_found")
        except ApiProblem as problem:
            await self._respond(send, problem.status, {"error": {"code": problem.code}})
        except (UnicodeError, ValueError):
            await self._respond(send, 400, {"error": {"code": "invalid_request"}})
        except Exception:
            await self._respond(send, 500, {"error": {"code": "internal_error"}})

    def _authenticate(
        self,
        method: str,
        target: str,
        body: bytes,
        headers: Mapping[str, str],
        *,
        mutation: bool,
    ) -> tuple[str, str]:
        key_id = headers.get("x-lil-tweak-key-id", "")
        supplied_owner = headers.get("x-lil-tweak-owner")
        signed_owner = supplied_owner or self.canonical_owner_id
        idempotency_key = headers.get("idempotency-key", "")
        try:
            verify_request(
                key_id=key_id,
                signature=headers.get("x-lil-tweak-signature", ""),
                body=body,
                keys=self.signing_keys,
                consume_nonce=self.store.consume_nonce,
                now=self.clock(),
                method=method,
                path_and_query=target,
                timestamp=headers.get("x-lil-tweak-timestamp", ""),
                nonce=headers.get("x-lil-tweak-nonce", ""),
                body_sha256=headers.get("x-lil-tweak-body-sha256", ""),
                request_id=headers.get("x-lil-tweak-request-id", ""),
                idempotency_key=idempotency_key,
                owner_id=signed_owner,
            )
        except AuthenticationError:
            raise ApiProblem(401, "authentication_failed") from None
        except ReplayError:
            raise ApiProblem(409, "request_replayed") from None
        if supplied_owner is not None and supplied_owner != self.canonical_owner_id:
            raise ApiProblem(403, "owner_forbidden")
        owner_id = self.canonical_owner_id
        if mutation and (not idempotency_key or len(idempotency_key.encode()) > 200):
            raise ApiProblem(400, "invalid_idempotency_key")
        return owner_id, idempotency_key

    async def _decision(
        self,
        job_id: str,
        owner_id: str,
        idempotency_key: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        request_hash = hashlib.sha256(
            b"decision\0"
            + job_id.encode("ascii")
            + b"\0"
            + json.dumps(
                payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        approval_proposal = payload.get("approvalProposal")
        proposal_digest = (
            approval_proposal.get("proposalDigest")
            if isinstance(approval_proposal, dict)
            else payload.get("proposal_digest", payload.get("proposalDigest"))
        )
        if "decision" not in payload or not isinstance(proposal_digest, str):
            raise ApiProblem(400, "invalid_request")
        expected_revision = self._expected_core_revision(payload)
        control_fields = {
            "decision",
            "revision",
            "proposal_digest",
            "proposalDigest",
            "jobId",
            "ownerKey",
            "reason",
            "expectedCoreRevision",
            "approvalProposal",
            "approvalTokenHash",
        }
        decision = payload["decision"]
        if decision not in {"approve", "reject"} or bool(
            set(payload) - control_fields
        ):
            raise ApiProblem(400, "invalid_request")
        expires_at = None
        if decision == "approve":
            current = self.store.get_job(job_id, owner_id)
            if current is None:
                raise ApiProblem(404, "job_not_found")
            if (
                not isinstance(approval_proposal, dict)
                or not _json_exact(approval_proposal, current.approval_proposal)
            ):
                raise ApiProblem(400, "invalid_request")
            if approval_proposal.get("action") != "export_patch" or approval_proposal.get(
                "target"
            ) != "owner_download":
                raise ApiProblem(400, "unsupported_action")
            expires_at = _parse_iso_timestamp(approval_proposal.get("expiresAt"))
            approval_token_hash = payload.get("approvalTokenHash")
            if not isinstance(approval_token_hash, str) or not _SHA256.fullmatch(
                approval_token_hash
            ):
                raise ApiProblem(400, "invalid_request")
        else:
            if "approvalTokenHash" in payload:
                raise ApiProblem(400, "invalid_request")
            approval_token_hash = None
        try:
            decided = self.store.decide_job_idempotent(
                job_id,
                owner_id=owner_id,
                expected_revision=expected_revision,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                decision=decision,
                proposal_digest=proposal_digest,
                approval_proposal=approval_proposal
                if isinstance(approval_proposal, dict)
                else None,
                approval_token_hash=approval_token_hash,
                expires_at=expires_at,
                now=self.clock(),
            )
        except JobNotFound:
            raise ApiProblem(404, "job_not_found") from None
        except IdempotencyConflict:
            raise ApiProblem(409, "idempotency_conflict") from None
        except StaleRevision:
            raise ApiProblem(409, "stale_revision") from None
        except ApprovalError:
            raise ApiProblem(409, "invalid_approval") from None
        return _job_json(decided)

    def _export_patch(
        self,
        job_id: str,
        owner_id: str,
        idempotency_key: str,
        path: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        allowed = {
            "approvalToken",
            "expectedCoreRevision",
            "proposalDigest",
            "sourceDigest",
            "policyVersion",
            "resourceProfile",
            "evidenceId",
            "evidenceName",
            "evidenceSha256",
            "evidenceSizeBytes",
        }
        if set(payload) != allowed:
            raise ApiProblem(400, "invalid_request")
        token = payload.get("approvalToken")
        proposal_digest = payload.get("proposalDigest")
        source_digest = payload.get("sourceDigest")
        policy_version = payload.get("policyVersion")
        resource_profile = payload.get("resourceProfile")
        evidence_id = payload.get("evidenceId")
        evidence_name = payload.get("evidenceName")
        evidence_sha256 = payload.get("evidenceSha256")
        evidence_size_bytes = payload.get("evidenceSizeBytes")
        if (
            not isinstance(token, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]", token)
            or not isinstance(proposal_digest, str)
            or not _SHA256.fullmatch(proposal_digest)
            or not isinstance(source_digest, str)
            or not _SHA256.fullmatch(source_digest)
            or not isinstance(policy_version, str)
            or not policy_version
            or len(policy_version) > 64
            or not isinstance(resource_profile, dict)
            or evidence_name != "changes.patch"
            or not isinstance(evidence_sha256, str)
            or not _SHA256.fullmatch(evidence_sha256)
            or not isinstance(evidence_size_bytes, int)
            or isinstance(evidence_size_bytes, bool)
            or evidence_size_bytes < 0
        ):
            raise ApiProblem(400, "invalid_request")
        expected_evidence_id = "evidence:" + hashlib.sha256(
            f"{job_id}\n{evidence_name}".encode()
        ).hexdigest()[:32]
        if evidence_id != expected_evidence_id:
            raise ApiProblem(409, "invalid_approval")
        expected_revision = self._expected_core_revision(payload)
        request_hash = hashlib.sha256(
            b"export\0"
            + path.encode("ascii")
            + b"\0"
            + json.dumps(
                payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        try:
            exported = self.store.consume_export_idempotent(
                job_id,
                owner_id=owner_id,
                expected_revision=expected_revision,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                approval_token=token,
                proposal_digest=proposal_digest,
                source_digest=source_digest,
                policy_version=policy_version,
                resource_profile=resource_profile,
                evidence_name=evidence_name,
                evidence_sha256=evidence_sha256,
                evidence_size_bytes=evidence_size_bytes,
                now=self.clock(),
            )
        except JobNotFound:
            raise ApiProblem(404, "job_not_found") from None
        except IdempotencyConflict:
            raise ApiProblem(409, "idempotency_conflict") from None
        except (ApprovalError, StaleRevision):
            raise ApiProblem(409, "invalid_approval") from None
        return _job_json(exported)

    @staticmethod
    def _expected_core_revision(payload: Mapping[str, Any]) -> int:
        value = payload.get("expectedCoreRevision", payload.get("revision"))
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ApiProblem(400, "invalid_request")
        return value

    async def _evidence(
        self, send: Any, job_id: str, name: str, owner_id: str
    ) -> None:
        job = self.store.get_job(job_id, owner_id)
        if job is None:
            raise ApiProblem(404, "job_not_found")
        descriptor = (job.evidence_manifest or {}).get(name)
        if isinstance(descriptor, str):
            expected_digest, expected_size = descriptor, None
        elif isinstance(descriptor, Mapping):
            expected_digest = descriptor.get("sha256")
            expected_size = descriptor.get("bytes")
            object_key = descriptor.get("objectKey")
        else:
            expected_digest, expected_size, object_key = None, None, None
        if isinstance(descriptor, str):
            object_key = None
        if not isinstance(expected_digest, str) or len(expected_digest) != 64:
            raise ApiProblem(404, "evidence_not_found")
        if self.evidence_store is None:
            raise ApiProblem(503, "evidence_unavailable")
        owner_prefix = hashlib.sha256(owner_id.encode("utf-8")).hexdigest()
        legacy_key = f"{owner_prefix}/{job_id}/{name}"
        if object_key is None:
            evidence_key = legacy_key
        else:
            expected_key = f"{owner_prefix}/{job_id}/{job.proposal_digest}/{name}"
            if object_key != expected_key:
                raise ApiProblem(500, "evidence_integrity_failed")
            evidence_key = object_key
        if expected_size is not None and (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0
        ):
            raise ApiProblem(500, "evidence_integrity_failed")
        if expected_size is not None and expected_size > MAX_EVIDENCE_BYTES:
            raise ApiProblem(413, "evidence_too_large")
        read_limit = (
            MAX_EVIDENCE_BYTES if expected_size is None else expected_size
        )
        try:
            data = self.evidence_store.get(evidence_key, max_bytes=read_limit)
        except (FileNotFoundError, KeyError):
            raise ApiProblem(404, "evidence_not_found") from None
        except EvidenceTooLarge:
            if expected_size is not None and expected_size < MAX_EVIDENCE_BYTES:
                raise ApiProblem(500, "evidence_integrity_failed") from None
            raise ApiProblem(413, "evidence_too_large") from None
        if len(data) > MAX_EVIDENCE_BYTES:
            raise ApiProblem(413, "evidence_too_large")
        if expected_size is not None and len(data) != expected_size:
            raise ApiProblem(500, "evidence_integrity_failed")
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected_digest:
            raise ApiProblem(500, "evidence_integrity_failed")
        media_types = {
            "plan.md": "text/markdown; charset=utf-8",
            "changes.patch": "text/x-diff; charset=utf-8",
            "tests.log": "text/plain; charset=utf-8",
            "manifest.json": "application/json",
            "summary.md": "text/markdown; charset=utf-8",
        }
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", media_types[name].encode("ascii")),
                    (b"content-length", str(len(data)).encode("ascii")),
                    (b"cache-control", b"private, no-store"),
                    (b"x-content-sha256", digest.encode("ascii")),
                    (
                        b"content-disposition",
                        f'attachment; filename="{name}"'.encode("ascii"),
                    ),
                ],
            }
        )
        await send({"type": "http.response.body", "body": data})

    @staticmethod
    async def _respond(send: Any, status: int, payload: Mapping[str, Any]) -> None:
        body = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if len(body) > STATUS_BODY_LIMIT:
            status = 500
            body = b'{"error":{"code":"response_too_large"}}'
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json; charset=utf-8"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def create_app(**dependencies: Any) -> LilTweakApi:
    return LilTweakApi(**dependencies)
