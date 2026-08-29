from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast

from .workbench_executor import ExecutorUnavailableError

_HANDSHAKE_SCHEMA_VERSION = "galor-executor-health-handshake-v1"
_HANDSHAKE_FIELDS = frozenset(
    {
        "schemaVersion",
        "authenticated",
        "serviceId",
        "hub",
        "nonce",
        "runnerId",
        "tenantId",
        "checkedAt",
        "expiresAt",
        "gateway",
        "heartbeat",
    }
)
_GATEWAY_HEALTH_FIELDS = frozenset(
    {
        "healthy",
        "storeAvailable",
        "transportConfigured",
        "signingAvailable",
    }
)
_HEARTBEAT_ROUTE_FIELDS = frozenset({"action", "scope", "maxAgeMs"})
_SIGNED_RESULT_FIELDS = frozenset(
    {
        "envelope",
        "receipt",
        "stdout",
        "stderr",
        "failureReason",
        "state",
    }
)
_SIGNED_ENVELOPE_FIELDS = frozenset(
    {
        "keyId",
        "issuedAt",
        "expiresAt",
        "jobId",
        "dispatchId",
        "runnerId",
        "signature",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "jobId",
        "operation",
        "commit",
        "commandLine",
        "exitCode",
        "state",
        "startedAt",
        "finishedAt",
        "durationMs",
        "cpuMs",
        "peakMemoryBytes",
        "outputBytes",
        "outputTruncated",
        "artifacts",
        "workspaceFingerprint",
        "digest",
    }
)
_HEX = frozenset("0123456789abcdef")
_SAFE_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")
_HANDSHAKE_MAX_AGE = timedelta(seconds=30)
_CLOCK_SKEW = timedelta(seconds=5)


class RunnerConnectionGateway(Protocol):
    async def handshake(self, payload: Mapping[str, object]) -> Mapping[str, object]: ...

    async def create_approval(self, payload: Mapping[str, object]) -> Mapping[str, object]: ...

    async def submit_job(self, payload: Mapping[str, object]) -> Mapping[str, object]: ...

    async def poll_job(self, job_id: str) -> Mapping[str, object]: ...

    async def cancel_job(self, job_id: str) -> None: ...


@dataclass(frozen=True)
class RunnerConnectionProof:
    runner_id: str
    tenant_id: str
    handshake_checked_at: datetime
    handshake_expires_at: datetime
    heartbeat_job_id: str
    heartbeat_issued_at: datetime
    heartbeat_expires_at: datetime
    heartbeat_max_age_ms: int
    hub_commit: str

    def is_fresh(self, now: datetime) -> bool:
        current = _utc(now)
        age_ms = (current - self.heartbeat_issued_at).total_seconds() * 1_000
        return (
            -_CLOCK_SKEW.total_seconds() * 1_000 <= age_ms <= self.heartbeat_max_age_ms
            and current < self.handshake_expires_at
            and current < self.heartbeat_expires_at
        )


@dataclass(frozen=True)
class _HandshakeEvidence:
    runner_id: str
    tenant_id: str
    checked_at: datetime
    expires_at: datetime
    heartbeat_scope: str
    heartbeat_commit: str
    heartbeat_max_age_ms: int


class RunnerConnectionVerifier:
    def __init__(
        self,
        *,
        gateway: RunnerConnectionGateway,
        execution_host: str,
        authorization_digest: str,
        result_signing_keys: Mapping[str, str],
        now: Callable[[], datetime] | None = None,
        poll_interval_seconds: float = 0.25,
    ) -> None:
        if not _is_safe_id(execution_host):
            raise ValueError("GALOR Runner V2 execution host identity is invalid")
        if not _is_digest(authorization_digest):
            raise ValueError("GALOR Runner V2 authorization digest is invalid")
        if result_signing_keys:
            validate_result_signing_keys(result_signing_keys)
        if poll_interval_seconds < 0 or poll_interval_seconds > 5:
            raise ValueError("GALOR Runner V2 poll interval is invalid")
        self._gateway = gateway
        self._execution_host = execution_host
        self._authorization_digest = authorization_digest
        self._result_signing_keys = dict(result_signing_keys)
        self._now = now or (lambda: datetime.now(UTC))
        self._poll_interval_seconds = poll_interval_seconds
        self._proof: RunnerConnectionProof | None = None
        self._refresh_lock = asyncio.Lock()
        self._disconnect_reason = (
            "GALOR Runner V2 requires an authenticated handshake and recent signed heartbeat"
        )

    @property
    def connected(self) -> bool:
        proof = self._proof
        if proof is None:
            return False
        try:
            fresh = proof.is_fresh(self._now())
        except ValueError:
            fresh = False
        if not fresh:
            self._proof = None
            self._disconnect_reason = "GALOR Runner V2 connection proof is stale"
        return fresh

    @property
    def disconnect_reason(self) -> str:
        return self._disconnect_reason

    async def refresh(self) -> RunnerConnectionProof:
        proof = self._proof
        if proof is not None and self.connected:
            return proof

        async with self._refresh_lock:
            proof = self._proof
            if proof is not None and self.connected:
                return proof
            self._proof = None
            if not self._result_signing_keys:
                self._disconnect_reason = (
                    "GALOR Runner V2 heartbeat signing keys are not configured"
                )
                raise ExecutorUnavailableError(self._disconnect_reason)

            nonce = secrets.token_urlsafe(32)
            try:
                handshake_payload = await self._gateway.handshake({"nonce": nonce})
                handshake = self._validate_handshake(handshake_payload, nonce=nonce)
                tenant_id, job_id, result = await self._run_identity_heartbeat(handshake)
                proof = self._validate_signed_heartbeat(
                    result,
                    expected_runner_id=handshake.runner_id,
                    expected_tenant_id=tenant_id,
                    expected_job_id=job_id,
                    expected_commit=handshake.heartbeat_commit,
                    handshake=handshake,
                )
                if not proof.is_fresh(self._now()):
                    raise ExecutorUnavailableError("GALOR Runner V2 connection proof is stale")
            except asyncio.CancelledError:
                raise
            except ExecutorUnavailableError as exc:
                self._disconnect_reason = str(exc)
                raise
            except Exception as exc:
                self._disconnect_reason = "GALOR Runner V2 connection proof failed closed"
                raise ExecutorUnavailableError(self._disconnect_reason) from exc

            self._proof = proof
            self._disconnect_reason = (
                "GALOR Runner V2 authenticated handshake and signed heartbeat are current"
            )
            return proof

    async def _run_identity_heartbeat(
        self,
        handshake: _HandshakeEvidence,
    ) -> tuple[str, str, Mapping[str, object]]:
        objective = "Lil' Tweak verified the authenticated GALOR Runner V2 identity heartbeat."
        approval = await self._gateway.create_approval(
            {
                "scope": handshake.heartbeat_scope,
                "action": "runner.reportIdentity",
                "effectClass": "READ",
                "input": {},
                "secretNames": [],
                "reason": objective,
                "ownerApprovalDigest": self._authorization_digest,
            }
        )
        approval_id = approval.get("approvalId")
        tenant_id = approval.get("tenantId")
        expires_at = approval.get("expiresAt")
        if not all(
            isinstance(value, str) and value for value in (approval_id, tenant_id, expires_at)
        ):
            raise ExecutorUnavailableError("GALOR Hub returned an invalid heartbeat approval")
        if tenant_id != handshake.tenant_id:
            raise ExecutorUnavailableError("GALOR Hub heartbeat approval tenant binding is invalid")

        accepted = await self._gateway.submit_job(
            {
                "project": "lil-tweak",
                "command": "runner.reportIdentity",
                "objective": objective,
                "idempotencyKey": f"liltweak-heartbeat:{uuid.uuid4().hex}",
                "effectClass": "READ",
                "priority": 100,
                "resources": [
                    {
                        "resource": f"runner:{handshake.runner_id}",
                        "mode": "exclusive",
                    }
                ],
                "dependencyIds": [],
                "approvalRequired": True,
                "execution": {
                    "tenantId": tenant_id,
                    "scope": handshake.heartbeat_scope,
                    "action": "runner.reportIdentity",
                    "input": {},
                    "secretNames": [],
                    "approvalId": approval_id,
                    "expiresAt": expires_at,
                },
            }
        )
        job_id = accepted.get("jobId")
        if accepted.get("accepted") is not True or not isinstance(job_id, str) or not job_id:
            raise ExecutorUnavailableError("GALOR Hub did not accept the heartbeat job")

        deadline = _utc(self._now()) + timedelta(seconds=30)
        while True:
            if _utc(self._now()) >= deadline:
                await self._gateway.cancel_job(job_id)
                raise ExecutorUnavailableError("GALOR Runner V2 heartbeat timed out")
            status = await self._gateway.poll_job(job_id)
            if status.get("jobId") != job_id or status.get("tenantId") != tenant_id:
                raise ExecutorUnavailableError("GALOR Hub heartbeat job binding is invalid")
            state = status.get("state")
            if state not in {"succeeded", "failed", "cancelled", "blocked"}:
                await asyncio.sleep(self._poll_interval_seconds)
                continue
            if state != "succeeded":
                raise ExecutorUnavailableError(f"GALOR Runner V2 heartbeat ended in {state}")
            result = status.get("result")
            if not isinstance(result, Mapping):
                raise ExecutorUnavailableError("GALOR Runner V2 heartbeat result is unavailable")
            receipt = result.get("receipt")
            if (
                not isinstance(receipt, Mapping)
                or receipt.get("commit") != handshake.heartbeat_commit
            ):
                raise ExecutorUnavailableError(
                    "GALOR Runner V2 heartbeat repository binding is invalid"
                )
            return cast(str, tenant_id), job_id, cast(Mapping[str, object], result)

    def _validate_handshake(
        self,
        payload: Mapping[str, object],
        *,
        nonce: str,
    ) -> _HandshakeEvidence:
        if set(payload) != _HANDSHAKE_FIELDS:
            raise ExecutorUnavailableError("GALOR Hub handshake fields are invalid")
        if (
            payload.get("schemaVersion") != _HANDSHAKE_SCHEMA_VERSION
            or payload.get("authenticated") is not True
            or payload.get("serviceId") != "lil-tweak"
            or payload.get("hub") != "islamismylifebey-web/galor-hub"
        ):
            raise ExecutorUnavailableError("GALOR Hub authenticated handshake is invalid")
        observed_nonce = payload.get("nonce")
        if not isinstance(observed_nonce, str) or not hmac.compare_digest(observed_nonce, nonce):
            raise ExecutorUnavailableError("GALOR Hub handshake nonce binding is invalid")
        runner_id = payload.get("runnerId")
        if runner_id != self._execution_host:
            raise ExecutorUnavailableError("GALOR Hub handshake runner identity is invalid")
        tenant_id = payload.get("tenantId")
        if not _is_safe_id(tenant_id):
            raise ExecutorUnavailableError("GALOR Hub handshake tenant identity is invalid")

        now = _utc(self._now())
        checked_at = _parse_iso(payload.get("checkedAt"), "handshake checkedAt")
        expires_at = _parse_iso(payload.get("expiresAt"), "handshake expiresAt")
        if (
            checked_at > now + _CLOCK_SKEW
            or now - checked_at > _HANDSHAKE_MAX_AGE
            or expires_at <= now
            or expires_at - checked_at > _HANDSHAKE_MAX_AGE
        ):
            raise ExecutorUnavailableError("GALOR Hub handshake freshness is invalid")

        gateway = _mapping(
            payload.get("gateway"),
            "GALOR Hub gateway health is invalid",
        )
        if set(gateway) != _GATEWAY_HEALTH_FIELDS or any(
            gateway.get(field_name) is not True for field_name in _GATEWAY_HEALTH_FIELDS
        ):
            raise ExecutorUnavailableError("GALOR Hub gateway health is not operational")

        heartbeat = _mapping(
            payload.get("heartbeat"),
            "GALOR Hub heartbeat route is invalid",
        )
        if set(heartbeat) != _HEARTBEAT_ROUTE_FIELDS:
            raise ExecutorUnavailableError("GALOR Hub heartbeat route fields are invalid")
        if heartbeat.get("action") != "runner.reportIdentity":
            raise ExecutorUnavailableError("GALOR Hub heartbeat action is invalid")
        scope = heartbeat.get("scope")
        if not isinstance(scope, str) or not scope.startswith("repo:galor-hub@"):
            raise ExecutorUnavailableError("GALOR Hub heartbeat scope is invalid")
        heartbeat_commit = scope.removeprefix("repo:galor-hub@")
        if not _is_sha(heartbeat_commit):
            raise ExecutorUnavailableError("GALOR Hub heartbeat commit is invalid")
        max_age_ms = heartbeat.get("maxAgeMs")
        if (
            not isinstance(max_age_ms, int)
            or isinstance(max_age_ms, bool)
            or max_age_ms < 1_000
            or max_age_ms > 60_000
        ):
            raise ExecutorUnavailableError("GALOR Hub heartbeat max age is invalid")
        return _HandshakeEvidence(
            runner_id=cast(str, runner_id),
            tenant_id=cast(str, tenant_id),
            checked_at=checked_at,
            expires_at=expires_at,
            heartbeat_scope=scope,
            heartbeat_commit=heartbeat_commit,
            heartbeat_max_age_ms=max_age_ms,
        )

    def _validate_signed_heartbeat(
        self,
        result: Mapping[str, object],
        *,
        expected_runner_id: str,
        expected_tenant_id: str,
        expected_job_id: str,
        expected_commit: str,
        handshake: _HandshakeEvidence,
    ) -> RunnerConnectionProof:
        if expected_tenant_id != handshake.tenant_id:
            raise ExecutorUnavailableError("GALOR Runner V2 heartbeat tenant binding is invalid")
        if set(result) != _SIGNED_RESULT_FIELDS:
            raise ExecutorUnavailableError("GALOR Runner V2 heartbeat result fields are invalid")
        envelope = _mapping(
            result.get("envelope"),
            "GALOR Runner V2 heartbeat envelope is invalid",
        )
        receipt = _mapping(
            result.get("receipt"),
            "GALOR Runner V2 heartbeat receipt is invalid",
        )
        if set(envelope) != _SIGNED_ENVELOPE_FIELDS or set(receipt) != _RECEIPT_FIELDS:
            raise ExecutorUnavailableError("GALOR Runner V2 heartbeat signed fields are invalid")
        key_id = envelope.get("keyId")
        signature = envelope.get("signature")
        if not isinstance(key_id, str) or not isinstance(signature, str):
            raise ExecutorUnavailableError("GALOR Runner V2 heartbeat signature is invalid")
        signing_key = self._result_signing_keys.get(key_id)
        if signing_key is None:
            raise ExecutorUnavailableError("GALOR Runner V2 heartbeat signature key is unknown")
        expected_signature = hmac.new(
            signing_key.encode(),
            _canonical_signed_result(result).encode(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            raise ExecutorUnavailableError("GALOR Runner V2 heartbeat signature is invalid")

        if (
            envelope.get("jobId") != expected_job_id
            or envelope.get("runnerId") != expected_runner_id
            or receipt.get("jobId") != expected_job_id
            or receipt.get("commit") != expected_commit
            or receipt.get("operation") != "approved_script"
            or "runner-report-identity.sh" not in str(receipt.get("commandLine") or "")
            or receipt.get("exitCode") != 0
            or receipt.get("state") != "succeeded"
            or result.get("state") != "succeeded"
            or result.get("failureReason") not in {None, ""}
            or result.get("stderr") != ""
        ):
            raise ExecutorUnavailableError("GALOR Runner V2 heartbeat binding is invalid")

        issued_at = _epoch_millis(envelope.get("issuedAt"), "heartbeat issuedAt")
        heartbeat_expires_at = _epoch_millis(
            envelope.get("expiresAt"),
            "heartbeat expiresAt",
        )
        now = _utc(self._now())
        age_ms = (now - issued_at).total_seconds() * 1_000
        if (
            issued_at > now + _CLOCK_SKEW
            or age_ms > handshake.heartbeat_max_age_ms
            or heartbeat_expires_at <= now
            or heartbeat_expires_at - issued_at > timedelta(minutes=5)
        ):
            raise ExecutorUnavailableError("GALOR Runner V2 heartbeat is stale")

        stdout = result.get("stdout")
        if not isinstance(stdout, str):
            raise ExecutorUnavailableError("GALOR Runner V2 heartbeat output is invalid")
        identity = _parse_identity_output(stdout)
        if identity.get("runner_id") != expected_runner_id:
            raise ExecutorUnavailableError("GALOR Runner V2 heartbeat runner identity is invalid")
        reported_at = _parse_iso(identity.get("utc"), "heartbeat utc")
        reported_age_ms = (now - reported_at).total_seconds() * 1_000
        if reported_at > now + _CLOCK_SKEW or reported_age_ms > handshake.heartbeat_max_age_ms:
            raise ExecutorUnavailableError("GALOR Runner V2 heartbeat is stale")

        return RunnerConnectionProof(
            runner_id=expected_runner_id,
            tenant_id=handshake.tenant_id,
            handshake_checked_at=handshake.checked_at,
            handshake_expires_at=handshake.expires_at,
            heartbeat_job_id=expected_job_id,
            heartbeat_issued_at=issued_at,
            heartbeat_expires_at=heartbeat_expires_at,
            heartbeat_max_age_ms=handshake.heartbeat_max_age_ms,
            hub_commit=expected_commit,
        )


def validate_result_signing_keys(keys: Mapping[str, str]) -> None:
    if not keys or len(keys) > 8:
        raise ValueError("GALOR Runner V2 requires one to eight result signing keys")
    for key_id, secret_value in keys.items():
        if not _is_safe_id(key_id):
            raise ValueError("GALOR Runner V2 result signing key identifier is invalid")
        if (
            not isinstance(secret_value, str)
            or len(secret_value) < 16
            or len(secret_value) > 512
            or any(ord(character) < 33 or ord(character) == 127 for character in secret_value)
        ):
            raise ValueError("GALOR Runner V2 result signing key secret is invalid")


def parse_result_signing_keys(payload: str | None) -> dict[str, str]:
    if payload is None or not payload.strip():
        raise ValueError("GALOR Runner V2 heartbeat signing keys are missing")
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError("GALOR Runner V2 heartbeat signing keys are invalid JSON") from exc
    if not isinstance(parsed, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in parsed.items()
    ):
        raise ValueError("GALOR Runner V2 heartbeat signing keys must be a string map")
    result = cast(dict[str, str], parsed)
    validate_result_signing_keys(result)
    return dict(result)


def _canonical_signed_result(result: Mapping[str, object]) -> str:
    envelope = _mapping(result.get("envelope"), "signed result envelope is invalid")
    receipt = _mapping(result.get("receipt"), "signed result receipt is invalid")
    payload = [
        envelope.get("keyId"),
        envelope.get("issuedAt"),
        envelope.get("expiresAt"),
        envelope.get("jobId"),
        envelope.get("dispatchId"),
        envelope.get("runnerId"),
        result.get("state"),
        result.get("failureReason") or "",
        result.get("stdout"),
        result.get("stderr"),
        receipt.get("jobId"),
        receipt.get("operation"),
        receipt.get("commit"),
        receipt.get("commandLine"),
        receipt.get("exitCode"),
        receipt.get("state"),
        receipt.get("startedAt"),
        receipt.get("finishedAt"),
        receipt.get("durationMs"),
        receipt.get("cpuMs"),
        receipt.get("peakMemoryBytes"),
        receipt.get("outputBytes"),
        receipt.get("outputTruncated"),
        receipt.get("artifacts"),
        receipt.get("workspaceFingerprint"),
        receipt.get("digest"),
    ]
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _mapping(value: object, message: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ExecutorUnavailableError(message)
    return cast(Mapping[str, object], value)


def _parse_identity_output(stdout: str) -> dict[str, str]:
    if len(stdout.encode()) > 4_096:
        raise ExecutorUnavailableError("GALOR Runner V2 heartbeat output is invalid")
    values: dict[str, str] = {}
    for line in stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in {"runner_id", "utc", "node"} or not value:
            raise ExecutorUnavailableError("GALOR Runner V2 heartbeat output is invalid")
        if key in values:
            raise ExecutorUnavailableError("GALOR Runner V2 heartbeat output is invalid")
        values[key] = value
    if set(values) != {"runner_id", "utc", "node"}:
        raise ExecutorUnavailableError("GALOR Runner V2 heartbeat output is invalid")
    return values


def _parse_iso(value: object, name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ExecutorUnavailableError(f"GALOR Runner V2 {name} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExecutorUnavailableError(f"GALOR Runner V2 {name} is invalid") from exc
    return _utc(parsed)


def _epoch_millis(value: object, name: str) -> datetime:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ExecutorUnavailableError(f"GALOR Runner V2 {name} is invalid")
    try:
        return datetime.fromtimestamp(value / 1_000, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise ExecutorUnavailableError(f"GALOR Runner V2 {name} is invalid") from exc


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("GALOR Runner V2 time source must be timezone-aware")
    return value.astimezone(UTC)


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _is_sha(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(character in _HEX for character in value)
    )


def _is_safe_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and value[0].isalnum()
        and all(character in _SAFE_ID_CHARS for character in value)
    )
