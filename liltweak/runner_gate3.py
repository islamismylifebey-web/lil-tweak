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
from typing import Any, cast

from .runner_connection import (
    RunnerConnectionGateway,
    RunnerConnectionProof,
)
from .runner_connection import (
    RunnerConnectionVerifier as LegacyRunnerConnectionVerifier,
)
from .runner_evidence import (
    RunnerQualificationBundleVerifier,
    VerifiedRunnerQualificationBundle,
)
from .workbench_executor import ExecutorUnavailableError

_HANDSHAKE_SCHEMA_VERSION = "galor-executor-health-handshake-v2"
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
        "qualification",
        "authorization",
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
_AUTHORIZATION_FIELDS = frozenset(
    {
        "schemaVersion",
        "keyId",
        "issuedAt",
        "expiresAt",
        "authorizationId",
        "sequence",
        "revocationEpoch",
        "serviceId",
        "nonce",
        "tenantId",
        "runnerId",
        "executionHost",
        "contractSha256",
        "qualificationId",
        "qualificationEvidenceDigest",
        "qualificationBundleDigest",
        "qualificationVerifiedAt",
        "qualificationExpiresAt",
        "repositoryId",
        "repositoryCommit",
        "action",
        "ownerAuthorizationDigest",
        "signature",
    }
)
_AUTHORIZATION_SCHEMA_VERSION = "runner-connection-authorization-v1"
_AUTHORIZATION_SIGNATURE_DOMAIN = "galor:runner-connection-authorization:v1\0"
_HEX = frozenset("0123456789abcdef")
_SAFE_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")
_HANDSHAKE_MAX_AGE = timedelta(seconds=30)
_AUTHORIZATION_MAX_AGE = timedelta(minutes=5)
_CLOCK_SKEW = timedelta(seconds=5)


@dataclass(frozen=True)
class _HeartbeatHandshake:
    runner_id: str
    tenant_id: str
    checked_at: datetime
    expires_at: datetime
    heartbeat_scope: str
    heartbeat_commit: str
    heartbeat_max_age_ms: int
    qualification_digest: str
    qualification_key_id: str
    qualification_evidence_digest: str
    qualification_expires_at: datetime


@dataclass(frozen=True)
class VerifiedRunnerConnectionAuthorization:
    authorization_id: str
    key_id: str
    sequence: int
    revocation_epoch: int
    issued_at: datetime
    expires_at: datetime
    qualification_expires_at: datetime
    evidence_digest: str


@dataclass(frozen=True)
class _HeartbeatAuthorizationEvidence:
    key_id: str
    evidence_digest: str
    expires_at: datetime


@dataclass(frozen=True)
class Gate3RunnerConnectionProof(RunnerConnectionProof):
    lil_tweak_commit: str
    qualification_id: str
    qualification_evidence_digest: str
    qualification_bundle_digest: str
    qualification_verified_at: datetime
    qualification_valid_until: datetime
    qualification_issuer_key_id: str
    qualification_runner_key_id: str
    authorization_id: str
    authorization_key_id: str
    authorization_sequence: int
    authorization_revocation_epoch: int
    authorization_issued_at: datetime
    authorization_expires_at: datetime

    def is_fresh(self, now: datetime) -> bool:
        current = _utc(now)
        return (
            super().is_fresh(current)
            and current < self.qualification_valid_until
            and current < self.authorization_expires_at
        )


class Gate3RunnerConnectionVerifier:
    """Require verified qualification, authorization, handshake, and heartbeat."""

    def __init__(
        self,
        *,
        gateway: RunnerConnectionGateway,
        execution_host: str,
        contract_digest: str,
        qualification_evidence_digest: str,
        qualification_issuer_public_keys: Mapping[str, str],
        qualification_runner_public_keys: Mapping[str, str],
        qualification_maximum_age: timedelta,
        authorization_digest: str,
        connection_authorization_signing_keys: Mapping[str, str],
        connection_authorization_minimum_sequence: int,
        connection_authorization_minimum_revocation_epoch: int,
        repository_id: str,
        repository_commit: str,
        result_signing_keys: Mapping[str, str],
        now: Callable[[], datetime] | None = None,
        poll_interval_seconds: float = 0.25,
    ) -> None:
        if not _is_safe_id(execution_host):
            raise ValueError("GALOR Runner V2 execution host identity is invalid")
        if not _is_digest(contract_digest):
            raise ValueError("GALOR Runner V2 contract digest is invalid")
        if not _is_digest(qualification_evidence_digest):
            raise ValueError("GALOR Runner V2 qualification evidence digest is invalid")
        if not _is_digest(authorization_digest):
            raise ValueError("GALOR Runner V2 owner authorization digest is invalid")
        if repository_id != "lil-tweak":
            raise ValueError("GALOR Runner V2 repository identity is invalid")
        if not _is_object_id(repository_commit):
            raise ValueError("GALOR Runner V2 repository commit is invalid")
        if not isinstance(qualification_maximum_age, timedelta) or not (
            timedelta(seconds=1) <= qualification_maximum_age <= timedelta(days=30)
        ):
            raise ValueError("GALOR Runner V2 qualification maximum age is invalid")
        if (
            not isinstance(connection_authorization_minimum_sequence, int)
            or isinstance(connection_authorization_minimum_sequence, bool)
            or connection_authorization_minimum_sequence < 0
        ):
            raise ValueError("GALOR Runner V2 connection authorization minimum sequence is invalid")
        if (
            not isinstance(connection_authorization_minimum_revocation_epoch, int)
            or isinstance(connection_authorization_minimum_revocation_epoch, bool)
            or connection_authorization_minimum_revocation_epoch < 1
        ):
            raise ValueError("GALOR Runner V2 connection authorization revocation epoch is invalid")
        if connection_authorization_signing_keys:
            _validate_secret_keys(
                connection_authorization_signing_keys,
                "connection authorization",
            )
        if result_signing_keys:
            _validate_secret_keys(result_signing_keys, "heartbeat")
        if poll_interval_seconds < 0 or poll_interval_seconds > 5:
            raise ValueError("GALOR Runner V2 poll interval is invalid")

        self._gateway = gateway
        self._execution_host = execution_host
        self._contract_digest = contract_digest
        self._qualification_evidence_digest = qualification_evidence_digest
        self._qualification_issuer_public_keys = dict(qualification_issuer_public_keys)
        self._qualification_runner_public_keys = dict(qualification_runner_public_keys)
        self._qualification_maximum_age = qualification_maximum_age
        self._authorization_digest = authorization_digest
        self._connection_authorization_signing_keys = dict(connection_authorization_signing_keys)
        self._connection_authorization_minimum_sequence = connection_authorization_minimum_sequence
        self._connection_authorization_minimum_revocation_epoch = (
            connection_authorization_minimum_revocation_epoch
        )
        self._repository_id = repository_id
        self._repository_commit = repository_commit
        self._result_signing_keys = dict(result_signing_keys)
        self._now = now or (lambda: datetime.now(UTC))
        self._poll_interval_seconds = poll_interval_seconds
        self._proof: Gate3RunnerConnectionProof | None = None
        self._refresh_lock = asyncio.Lock()
        self._seen_authorization_ids: set[str] = set()
        self._disconnect_reason = (
            "GALOR Runner V2 requires verified qualification and authorization "
            "before the authenticated handshake and signed heartbeat"
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

    async def refresh(self) -> Gate3RunnerConnectionProof:
        proof = self._proof
        if proof is not None and self.connected:
            return proof

        async with self._refresh_lock:
            proof = self._proof
            if proof is not None and self.connected:
                return proof
            self._proof = None
            if not self._qualification_issuer_public_keys:
                self._disconnect_reason = (
                    "GALOR Runner V2 qualification issuer keys are not configured"
                )
                raise ExecutorUnavailableError(self._disconnect_reason)
            if not self._qualification_runner_public_keys:
                self._disconnect_reason = (
                    "GALOR Runner V2 qualification runner keys are not configured"
                )
                raise ExecutorUnavailableError(self._disconnect_reason)
            if not self._connection_authorization_signing_keys:
                self._disconnect_reason = (
                    "GALOR Runner V2 connection authorization signing keys are not configured"
                )
                raise ExecutorUnavailableError(self._disconnect_reason)
            if not self._result_signing_keys:
                self._disconnect_reason = (
                    "GALOR Runner V2 heartbeat signing keys are not configured"
                )
                raise ExecutorUnavailableError(self._disconnect_reason)
            nonce = secrets.token_urlsafe(32)
            try:
                handshake_payload = await self._gateway.handshake({"nonce": nonce})
                handshake, qualification, authorization = self._validate_handshake(
                    handshake_payload,
                    nonce=nonce,
                )
                tenant_id, job_id, result = await self._run_identity_heartbeat(handshake)
                heartbeat_authorization = _HeartbeatAuthorizationEvidence(
                    key_id=authorization.key_id,
                    evidence_digest=authorization.evidence_digest,
                    expires_at=authorization.expires_at,
                )
                heartbeat = LegacyRunnerConnectionVerifier._validate_signed_heartbeat(
                    cast(LegacyRunnerConnectionVerifier, cast(Any, self)),
                    result,
                    expected_runner_id=handshake.runner_id,
                    expected_tenant_id=tenant_id,
                    expected_job_id=job_id,
                    expected_commit=self._repository_commit,
                    handshake=cast(Any, handshake),
                    authorization=cast(Any, heartbeat_authorization),
                )
                qualification_valid_until = (
                    qualification.verified_at + self._qualification_maximum_age
                )
                proof = Gate3RunnerConnectionProof(
                    runner_id=heartbeat.runner_id,
                    tenant_id=heartbeat.tenant_id,
                    handshake_checked_at=heartbeat.handshake_checked_at,
                    handshake_expires_at=heartbeat.handshake_expires_at,
                    heartbeat_job_id=heartbeat.heartbeat_job_id,
                    heartbeat_issued_at=heartbeat.heartbeat_issued_at,
                    heartbeat_expires_at=heartbeat.heartbeat_expires_at,
                    heartbeat_max_age_ms=heartbeat.heartbeat_max_age_ms,
                    hub_commit=heartbeat.hub_commit,
                    qualification_digest=qualification.bundle_digest,
                    qualification_key_id=qualification.issuer_key_id,
                    qualification_expires_at=qualification_valid_until,
                    authorization_evidence_digest=authorization.evidence_digest,
                    lil_tweak_commit=self._repository_commit,
                    qualification_id=qualification.qualification_id,
                    qualification_evidence_digest=qualification.evidence_digest,
                    qualification_bundle_digest=qualification.bundle_digest,
                    qualification_verified_at=qualification.verified_at,
                    qualification_valid_until=qualification_valid_until,
                    qualification_issuer_key_id=qualification.issuer_key_id,
                    qualification_runner_key_id=qualification.runner_key_id,
                    authorization_id=authorization.authorization_id,
                    authorization_key_id=authorization.key_id,
                    authorization_sequence=authorization.sequence,
                    authorization_revocation_epoch=authorization.revocation_epoch,
                    authorization_issued_at=authorization.issued_at,
                    authorization_expires_at=authorization.expires_at,
                )
                if not proof.is_fresh(self._now()):
                    raise ExecutorUnavailableError("GALOR Runner V2 connection proof is stale")
            except asyncio.CancelledError:
                raise
            except ExecutorUnavailableError as exc:
                self._disconnect_reason = str(exc)
                raise
            except Exception as exc:
                self._disconnect_reason = (
                    "GALOR Runner V2 cryptographic connection proof failed closed"
                )
                raise ExecutorUnavailableError(self._disconnect_reason) from exc

            self._proof = proof
            self._seen_authorization_ids.add(authorization.authorization_id)
            if len(self._seen_authorization_ids) > 256:
                self._seen_authorization_ids = {
                    authorization.authorization_id,
                }
            self._disconnect_reason = (
                "GALOR Runner V2 qualification, authorization, authenticated "
                "handshake, and signed heartbeat are current"
            )
            return proof

    async def _run_identity_heartbeat(
        self,
        handshake: _HeartbeatHandshake,
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

        idempotency_key = f"liltweak-heartbeat:{uuid.uuid4().hex}"
        accepted = await self._gateway.submit_job(
            {
                "project": "lil-tweak",
                "command": "runner.reportIdentity",
                "objective": objective,
                "idempotencyKey": idempotency_key,
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
            return tenant_id, job_id, cast(Mapping[str, object], result)

    def _validate_handshake(
        self,
        payload: Mapping[str, object],
        *,
        nonce: str,
    ) -> tuple[
        _HeartbeatHandshake,
        VerifiedRunnerQualificationBundle,
        VerifiedRunnerConnectionAuthorization,
    ]:
        if not isinstance(payload, Mapping) or set(payload) != _HANDSHAKE_FIELDS:
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

        gateway = _mapping(payload.get("gateway"), "GALOR Hub gateway health is invalid")
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
        if not _is_object_id(heartbeat_commit):
            raise ExecutorUnavailableError("GALOR Hub heartbeat commit is invalid")
        max_age_ms = heartbeat.get("maxAgeMs")
        if (
            not isinstance(max_age_ms, int)
            or isinstance(max_age_ms, bool)
            or max_age_ms < 1_000
            or max_age_ms > 60_000
        ):
            raise ExecutorUnavailableError("GALOR Hub heartbeat max age is invalid")

        qualification_payload = _mapping(
            payload.get("qualification"),
            "GALOR Runner V2 qualification evidence is unavailable",
        )
        qualification = RunnerQualificationBundleVerifier(
            expected_runner_id=self._execution_host,
            expected_repository_id="github:islamismylifebey-web/galor-hub",
            expected_repository_commit=heartbeat_commit,
            expected_evidence_digest=self._qualification_evidence_digest,
            trusted_issuer_public_keys=self._qualification_issuer_public_keys,
            trusted_runner_public_keys=self._qualification_runner_public_keys,
            maximum_age=self._qualification_maximum_age,
        ).verify(
            qualification_payload,
            now=now,
        )

        authorization_payload = _mapping(
            payload.get("authorization"),
            "GALOR Runner V2 connection authorization is unavailable",
        )
        authorization = self._verify_connection_authorization(
            authorization_payload,
            nonce=nonce,
            tenant_id=cast(str, tenant_id),
            qualification=qualification,
            now=now,
        )
        if authorization.authorization_id in self._seen_authorization_ids:
            raise ExecutorUnavailableError("GALOR Runner V2 connection authorization was replayed")

        return (
            _HeartbeatHandshake(
                runner_id=runner_id,
                tenant_id=cast(str, tenant_id),
                checked_at=checked_at,
                expires_at=expires_at,
                heartbeat_scope=scope,
                heartbeat_commit=heartbeat_commit,
                heartbeat_max_age_ms=max_age_ms,
                qualification_digest=qualification.bundle_digest,
                qualification_key_id=qualification.issuer_key_id,
                qualification_evidence_digest=qualification.evidence_digest,
                qualification_expires_at=(
                    qualification.verified_at + self._qualification_maximum_age
                ),
            ),
            qualification,
            authorization,
        )

    def _verify_connection_authorization(
        self,
        payload: Mapping[str, object],
        *,
        nonce: str,
        tenant_id: str,
        qualification: VerifiedRunnerQualificationBundle,
        now: datetime,
    ) -> VerifiedRunnerConnectionAuthorization:
        if set(payload) != _AUTHORIZATION_FIELDS:
            raise ExecutorUnavailableError(
                "GALOR Runner V2 connection authorization fields are invalid"
            )
        if payload.get("schemaVersion") != _AUTHORIZATION_SCHEMA_VERSION:
            raise ExecutorUnavailableError(
                "GALOR Runner V2 connection authorization schema is invalid"
            )
        key_id = payload.get("keyId")
        signature = payload.get("signature")
        if not _is_safe_id(key_id) or not _is_digest(signature):
            raise ExecutorUnavailableError(
                "GALOR Runner V2 connection authorization signature is invalid"
            )
        signing_key = self._connection_authorization_signing_keys.get(cast(str, key_id))
        if signing_key is None:
            raise ExecutorUnavailableError(
                "GALOR Runner V2 connection authorization signing key is unknown"
            )
        unsigned = {key: value for key, value in payload.items() if key != "signature"}
        expected_signature = hmac.new(
            signing_key.encode(),
            (_AUTHORIZATION_SIGNATURE_DOMAIN + _canonical_json(unsigned)).encode(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(cast(str, signature), expected_signature):
            raise ExecutorUnavailableError(
                "GALOR Runner V2 connection authorization signature is invalid"
            )

        issued_at = _epoch_millis(
            payload.get("issuedAt"),
            "connection authorization issuedAt",
        )
        expires_at = _epoch_millis(
            payload.get("expiresAt"),
            "connection authorization expiresAt",
        )
        if (
            issued_at > now + _CLOCK_SKEW
            or expires_at <= now
            or expires_at <= issued_at
            or expires_at - issued_at > _AUTHORIZATION_MAX_AGE
        ):
            raise ExecutorUnavailableError(
                "GALOR Runner V2 connection authorization is stale or expired"
            )
        qualification_verified_at = _parse_iso(
            payload.get("qualificationVerifiedAt"),
            "connection authorization qualificationVerifiedAt",
        )
        qualification_expires_at = _parse_iso(
            payload.get("qualificationExpiresAt"),
            "connection authorization qualificationExpiresAt",
        )
        if (
            qualification_verified_at != qualification.verified_at
            or qualification_expires_at <= now
            or qualification_expires_at <= qualification_verified_at
        ):
            raise ExecutorUnavailableError(
                "GALOR Runner V2 connection authorization qualification lifetime is invalid"
            )

        expected_bindings: tuple[tuple[str, object, object], ...] = (
            ("service", payload.get("serviceId"), "lil-tweak"),
            ("nonce", payload.get("nonce"), nonce),
            ("tenant", payload.get("tenantId"), tenant_id),
            ("runner", payload.get("runnerId"), self._execution_host),
            (
                "execution host",
                payload.get("executionHost"),
                self._execution_host,
            ),
            ("contract", payload.get("contractSha256"), self._contract_digest),
            (
                "qualification id",
                payload.get("qualificationId"),
                qualification.qualification_id,
            ),
            (
                "qualification evidence",
                payload.get("qualificationEvidenceDigest"),
                qualification.evidence_digest,
            ),
            (
                "qualification bundle",
                payload.get("qualificationBundleDigest"),
                qualification.bundle_digest,
            ),
            ("repository", payload.get("repositoryId"), self._repository_id),
            (
                "repository commit",
                payload.get("repositoryCommit"),
                self._repository_commit,
            ),
            ("action", payload.get("action"), "runner.reportIdentity"),
            (
                "owner authorization",
                payload.get("ownerAuthorizationDigest"),
                self._authorization_digest,
            ),
        )
        for label, actual, expected in expected_bindings:
            if actual != expected:
                raise ExecutorUnavailableError(
                    f"GALOR Runner V2 connection authorization {label} binding is invalid"
                )

        authorization_id = payload.get("authorizationId")
        if (
            not isinstance(authorization_id, str)
            or not authorization_id.startswith("rca_")
            or len(authorization_id) != 36
            or any(character not in _HEX for character in authorization_id[4:])
        ):
            raise ExecutorUnavailableError("GALOR Runner V2 connection authorization id is invalid")
        sequence = payload.get("sequence")
        revocation_epoch = payload.get("revocationEpoch")
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence <= self._connection_authorization_minimum_sequence
        ):
            raise ExecutorUnavailableError(
                "GALOR Runner V2 connection authorization sequence was replayed or rolled back"
            )
        if (
            not isinstance(revocation_epoch, int)
            or isinstance(revocation_epoch, bool)
            or revocation_epoch < self._connection_authorization_minimum_revocation_epoch
        ):
            raise ExecutorUnavailableError(
                "GALOR Runner V2 connection authorization revocation epoch is obsolete"
            )

        return VerifiedRunnerConnectionAuthorization(
            authorization_id=authorization_id,
            key_id=cast(str, key_id),
            sequence=sequence,
            revocation_epoch=revocation_epoch,
            issued_at=issued_at,
            expires_at=expires_at,
            qualification_expires_at=qualification_expires_at,
            evidence_digest=hashlib.sha256(_canonical_json(payload).encode()).hexdigest(),
        )


def parse_secret_keys_json(
    payload: str | None,
    *,
    label: str,
) -> dict[str, str]:
    if payload is None or not payload.strip():
        raise ValueError(f"GALOR Runner V2 {label} signing keys are missing")
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(f"GALOR Runner V2 {label} signing keys are invalid JSON") from exc
    if not isinstance(parsed, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in parsed.items()
    ):
        raise ValueError(f"GALOR Runner V2 {label} signing keys must be a string map")
    result = cast(dict[str, str], parsed)
    _validate_secret_keys(result, label)
    return dict(result)


def _validate_secret_keys(keys: Mapping[str, str], label: str) -> None:
    if not keys or len(keys) > 16:
        raise ValueError(f"GALOR Runner V2 requires one to sixteen {label} signing keys")
    for key_id, secret_value in keys.items():
        if not _is_safe_id(key_id):
            raise ValueError(f"GALOR Runner V2 {label} signing key identifier is invalid")
        if (
            not isinstance(secret_value, str)
            or len(secret_value) < 16
            or len(secret_value) > 512
            or any(ord(character) < 33 or ord(character) == 127 for character in secret_value)
        ):
            raise ValueError(f"GALOR Runner V2 {label} signing key secret is invalid")


def _canonical_json(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not value.is_integer():
            raise ExecutorUnavailableError(
                "GALOR Runner V2 connection authorization contains an unsupported number"
            )
        return str(int(value))
    if isinstance(value, list):
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ExecutorUnavailableError(
                "GALOR Runner V2 connection authorization contains an invalid key"
            )
        return (
            "{"
            + ",".join(
                json.dumps(key, ensure_ascii=False, separators=(",", ":"))
                + ":"
                + _canonical_json(value[key])
                for key in sorted(value)
            )
            + "}"
        )
    raise ExecutorUnavailableError(
        "GALOR Runner V2 connection authorization contains an unsupported value"
    )


def _mapping(value: object, message: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ExecutorUnavailableError(message)
    return cast(Mapping[str, object], value)


def _parse_iso(value: object, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ExecutorUnavailableError(f"GALOR Runner V2 {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExecutorUnavailableError(f"GALOR Runner V2 {label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ExecutorUnavailableError(f"GALOR Runner V2 {label} is invalid")
    return parsed.astimezone(UTC)


def _epoch_millis(value: object, label: str) -> datetime:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > 32_503_680_000_000
    ):
        raise ExecutorUnavailableError(f"GALOR Runner V2 {label} is invalid")
    try:
        return datetime.fromtimestamp(value / 1_000, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise ExecutorUnavailableError(f"GALOR Runner V2 {label} is invalid") from exc


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("GALOR Runner V2 clock must be timezone-aware")
    return value.astimezone(UTC)


def _is_safe_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and value[0].isalnum()
        and all(character in _SAFE_ID_CHARS for character in value)
    )


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _is_object_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) in {40, 64}
        and all(character in _HEX for character in value)
    )
