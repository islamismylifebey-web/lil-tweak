"""Fail-closed GALOR Runner V3 service handshake for the trusted Core."""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable
from urllib.error import HTTPError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


GALOR_RUNNER_CONTRACT_NAME = "galor-runner"
GALOR_RUNNER_CONTRACT_VERSION = "3.0.0"
GALOR_RUNNER_EXECUTION_HOST = "galor-tweak-runner-01"
GALOR_RUNNER_CONTRACT_SHA256 = (
    "5c649d1c2c338bc4a01f8c20778867036a703b049f25476cfe5e246c84eadd4c"
)
GALOR_RUNNER_DROPLET_ID = "597343619"
GALOR_RUNNER_REPOSITORY_ID = "github:islamismylifebey-web/lil-tweak"
GALOR_HUB_REPOSITORY = "islamismylifebey-web/galor-hub"

_HANDSHAKE_SCHEMA = "galor-executor-health-handshake-v2"
_AUTHORIZATION_SCHEMA = "runner-connection-authorization-v1"
_RUNTIME_BLOCKER = "VERIFIED_SANDBOX_RUNTIME_NOT_CONNECTED"
_HEARTBEAT_ACTION = "runner.reportIdentity"
_MAX_RESPONSE_BYTES = 64 * 1024
_MAX_TIMEOUT_SECONDS = 2.0
_MAX_CLOCK_SKEW_SECONDS = 5.0
_MAX_HANDSHAKE_LIFETIME_SECONDS = 60.0
_MAX_AUTHORIZATION_LIFETIME_SECONDS = 5 * 60.0
_SAFE_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class RunnerV3HandshakeResult:
    connected: bool
    reason: str
    runner_id: str | None = None
    tenant_id: str | None = None
    checked_at: str | None = None
    expires_at: str | None = None


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


def _safe_opener() -> Any:
    # Ignore ambient HTTP(S)_PROXY values and never follow a response away from
    # the exact operator-configured GALOR origin.
    return build_opener(ProxyHandler({}), _NoRedirectHandler())


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _record(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _bounded_body(response: Any) -> bytes:
    declared = response.headers.get("content-length") if response.headers else None
    if declared:
        if not declared.isdigit() or int(declared) > _MAX_RESPONSE_BYTES:
            raise ValueError("response_too_large")
    body = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(body) > _MAX_RESPONSE_BYTES:
        raise ValueError("response_too_large")
    return body


def _json_record(body: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(body.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return _record(value)


class GalorRunnerV3Client:
    """Authenticated, bounded service client for the GALOR V3 handshake."""

    def __init__(
        self,
        base_url: str,
        *,
        service_token: str,
        repository_commit: str,
        opener: Any = None,
        timeout: float = _MAX_TIMEOUT_SECONDS,
        nonce: Callable[[], str] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("invalid GALOR runner gateway URL")
        if not 32 <= len(service_token.encode("utf-8")) <= 4096:
            raise ValueError("invalid GALOR service token")
        if not _GIT_COMMIT.fullmatch(repository_commit):
            raise ValueError("invalid repository commit")
        self.base_url = urlunsplit(("https", parsed.netloc, "", "", ""))
        self._service_token = service_token
        self.repository_commit = repository_commit
        self.opener = _safe_opener() if opener is None else opener
        self.timeout = min(max(float(timeout), 0.1), _MAX_TIMEOUT_SECONDS)
        self._nonce = nonce or (lambda: secrets.token_urlsafe(32))
        self._now = now or (lambda: datetime.now(UTC))

    def handshake(self) -> RunnerV3HandshakeResult:
        nonce = self._nonce()
        if not isinstance(nonce, str) or not _SAFE_NONCE.fullmatch(nonce):
            return RunnerV3HandshakeResult(False, "invalid_handshake")
        payload = json.dumps(
            {"nonce": nonce}, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        request = Request(
            f"{self.base_url}/api/executor/handshake",
            method="POST",
            data=payload,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._service_token}",
                "x-galor-service-id": "lil-tweak",
            },
        )
        open_request = getattr(self.opener, "open", self.opener)
        try:
            with open_request(request, timeout=self.timeout) as response:
                body = _bounded_body(response)
        except HTTPError as error:
            return self._http_failure(error)
        except Exception:
            return RunnerV3HandshakeResult(False, "handshake_unavailable")

        decoded = _json_record(body)
        if decoded is None:
            return RunnerV3HandshakeResult(False, "invalid_handshake")
        return self._validate_success(decoded, nonce)

    def _http_failure(self, error: HTTPError) -> RunnerV3HandshakeResult:
        if error.code == 503:
            try:
                decoded = _json_record(_bounded_body(error))
            except Exception:
                decoded = None
            if decoded and decoded.get("code") == _RUNTIME_BLOCKER:
                return RunnerV3HandshakeResult(
                    False, "runtime_supervisor_not_connected"
                )
        return RunnerV3HandshakeResult(False, "handshake_unavailable")

    def _validate_success(
        self, value: dict[str, Any], nonce: str
    ) -> RunnerV3HandshakeResult:
        gateway = _record(value.get("gateway"))
        heartbeat = _record(value.get("heartbeat"))
        qualification = _record(value.get("qualification"))
        authorization = _record(value.get("authorization"))
        runner_id = value.get("runnerId")
        tenant_id = value.get("tenantId")
        checked_at = _parse_timestamp(value.get("checkedAt"))
        expires_at = _parse_timestamp(value.get("expiresAt"))
        current = self._now().astimezone(UTC)

        if (
            value.get("schemaVersion") != _HANDSHAKE_SCHEMA
            or value.get("authenticated") is not True
            or value.get("serviceId") != "lil-tweak"
            or value.get("hub") != GALOR_HUB_REPOSITORY
            or value.get("nonce") != nonce
            or runner_id != GALOR_RUNNER_EXECUTION_HOST
            or not isinstance(tenant_id, str)
            or not _SAFE_ID.fullmatch(tenant_id)
            or checked_at is None
            or expires_at is None
            or checked_at.timestamp() > current.timestamp() + _MAX_CLOCK_SKEW_SECONDS
            or expires_at <= current
            or expires_at <= checked_at
            or (expires_at - checked_at).total_seconds()
            > _MAX_HANDSHAKE_LIFETIME_SECONDS
            or gateway is None
            or gateway.get("healthy") is not True
            or gateway.get("storeAvailable") is not True
            or gateway.get("transportConfigured") is not True
            or gateway.get("signingAvailable") is not True
            or heartbeat is None
            or heartbeat.get("action") != _HEARTBEAT_ACTION
            or not isinstance(heartbeat.get("scope"), str)
            or not heartbeat.get("scope")
            or not isinstance(heartbeat.get("maxAgeMs"), int)
            or isinstance(heartbeat.get("maxAgeMs"), bool)
            or not 1 <= heartbeat["maxAgeMs"] <= 300_000
            or qualification is None
            or authorization is None
            or not self._valid_authorization(
                authorization, nonce=nonce, runner_id=runner_id, tenant_id=tenant_id,
                current=current,
            )
        ):
            return RunnerV3HandshakeResult(False, "invalid_handshake")

        return RunnerV3HandshakeResult(
            True,
            "connected_unqualified",
            runner_id=runner_id,
            tenant_id=tenant_id,
            checked_at=value["checkedAt"],
            expires_at=value["expiresAt"],
        )

    def _valid_authorization(
        self,
        authorization: dict[str, Any],
        *,
        nonce: str,
        runner_id: str,
        tenant_id: str,
        current: datetime,
    ) -> bool:
        expires_at = authorization.get("expiresAt")
        if (
            not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or expires_at <= int(current.timestamp() * 1000)
            or expires_at
            > int(current.timestamp() * 1000 + _MAX_AUTHORIZATION_LIFETIME_SECONDS * 1000)
        ):
            return False
        contract = authorization.get("contractSha256")
        if not isinstance(contract, str) or not _HEX_64.fullmatch(contract):
            return False
        return (
            authorization.get("schemaVersion") == _AUTHORIZATION_SCHEMA
            and authorization.get("serviceId") == "lil-tweak"
            and authorization.get("nonce") == nonce
            and authorization.get("tenantId") == tenant_id
            and authorization.get("runnerId") == runner_id
            and authorization.get("executionHost") == GALOR_RUNNER_EXECUTION_HOST
            and contract == GALOR_RUNNER_CONTRACT_SHA256
            and authorization.get("repositoryId") == GALOR_RUNNER_REPOSITORY_ID
            and authorization.get("repositoryCommit") == self.repository_commit
            and authorization.get("action") == _HEARTBEAT_ACTION
        )
