from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol, cast
from urllib.parse import urlparse

import httpx

from .runner_connection import (
    RunnerConnectionProof,
    RunnerConnectionVerifier,
)
from .workbench_contract import NetworkMode, ToolKind, ToolRequest
from .workbench_executor import ExecutorUnavailableError, ProcessResult

_CONTRACT_FIELDS = frozenset(
    {
        "contract",
        "version",
        "owner",
        "consumers",
        "executionHost",
        "summary",
        "signing",
        "operations",
        "actions",
        "approvedScripts",
        "jobLifecycle",
        "errorCodes",
        "resourceLimits",
        "environment",
        "verification",
    }
)
_REQUIRED_ACTIONS = frozenset(
    {
        "runner.inspectRepository",
        "runner.readRepositoryFile",
        "runner.applyPatch",
        "runner.gitStatus",
        "runner.gitDiff",
        "runner.verifyTests",
        "runner.verifyTypecheck",
        "runner.verifyLint",
        "runner.verifyBuild",
        "runner.prepareLocalCommit",
        "runner.reportIdentity",
    }
)
_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class CanonicalGalorRunnerContract:
    owner: str
    execution_host: str
    version: str
    signing_algorithm: str
    action_ids: tuple[str, ...]
    digest: str
    document: Mapping[str, object]

    @classmethod
    def from_json(cls, payload: str, *, expected_digest: str) -> CanonicalGalorRunnerContract:
        digest = hashlib.sha256(payload.encode()).hexdigest()
        if digest != expected_digest:
            raise ValueError("GALOR Runner V2 contract digest mismatch")
        try:
            document = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("GALOR Runner V2 contract must be valid JSON") from exc
        if not isinstance(document, dict) or set(document) != _CONTRACT_FIELDS:
            raise ValueError("GALOR Runner V2 contract fields are invalid")
        version, signing, actions = (
            document.get("version"),
            document.get("signing"),
            document.get("actions"),
        )
        if document.get("contract") != "galor-runner":
            raise ValueError("GALOR Runner V2 contract identity is invalid")
        if not isinstance(version, str) or version.split(".", 1)[0] != "2":
            raise ValueError("GALOR Runner V1 downgrade is rejected")
        if (
            document.get("owner") != "islamismylifebey-web/galor-hub"
            or document.get("executionHost") != "galor-private-cloud-01"
        ):
            raise ValueError("GALOR Runner V2 authority is invalid")
        if not isinstance(signing, dict) or signing.get("algorithm") != "HMAC-SHA256":
            raise ValueError("GALOR Runner V2 signing algorithm is invalid")
        if not isinstance(actions, list) or not actions:
            raise ValueError("GALOR Runner V2 contract actions are missing")
        raw_actions = tuple(
            entry.get("action") if isinstance(entry, dict) else None for entry in actions
        )
        if any(not isinstance(action, str) for action in raw_actions):
            raise ValueError("GALOR Runner V2 contract action entry is invalid")
        action_ids = cast(tuple[str, ...], raw_actions)
        if len(set(action_ids)) != len(action_ids) or not _REQUIRED_ACTIONS.issubset(action_ids):
            raise ValueError("GALOR Runner V2 contract actions are invalid")
        return cls(
            str(document["owner"]),
            str(document["executionHost"]),
            version,
            str(signing["algorithm"]),
            action_ids,
            digest,
            document,
        )


def tool_request_action_id(request: ToolRequest) -> str:
    if request.kind == ToolKind.LIST_FILES:
        return "runner.inspectRepository"
    if request.kind == ToolKind.READ_FILE:
        return "runner.readRepositoryFile"
    if request.kind in {ToolKind.WRITE_FILE, ToolKind.APPLY_PATCH}:
        return "runner.applyPatch"
    if request.command is None:
        raise ValueError("tool request command payload is missing")
    return command_action_id(request.command.executable, request.command.args)


def command_action_id(executable: str, args: tuple[str, ...]) -> str:
    command, first = executable.casefold(), args[0].casefold() if args else ""
    if command == "pytest":
        return "runner.verifyTests"
    if command == "mypy":
        return "runner.verifyTypecheck"
    if command == "ruff" and (first == "check" or (first == "format" and "--check" in args[1:])):
        return "runner.verifyLint"
    if command == "git" and first in {"status", "diff", "commit"}:
        return {
            "status": "runner.gitStatus",
            "diff": "runner.gitDiff",
            "commit": "runner.prepareLocalCommit",
        }[first]
    if (command == "uv" and first == "build") or (
        command.startswith("python") and args[:2] == ("-m", "build")
    ):
        return "runner.verifyBuild"
    raise ValueError("runner does not support this structured command")


def command_action_input(action: str, args: tuple[str, ...]) -> dict[str, object]:
    if action != "runner.prepareLocalCommit":
        return {}
    try:
        message = args[args.index("-m") + 1]
    except (ValueError, IndexError) as exc:
        raise ValueError("runner commit requires one -m message") from exc
    return {"message": message}


class GalorWorkGatewayClient(Protocol):
    async def handshake(self, payload: Mapping[str, object]) -> Mapping[str, object]: ...
    async def create_approval(self, payload: Mapping[str, object]) -> Mapping[str, object]: ...
    async def submit_job(self, payload: Mapping[str, object]) -> Mapping[str, object]: ...
    async def poll_job(self, job_id: str) -> Mapping[str, object]: ...
    async def cancel_job(self, job_id: str) -> None: ...


class HttpGalorWorkGatewayClient:
    def __init__(
        self, *, base_url: str, auth_token: str, client: httpx.AsyncClient | None = None
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {auth_token}", "X-GALOR-Service-ID": "lil-tweak"}
        self._client = client

    def _http_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient()
        return self._client

    async def _json(
        self, method: str, path: str, payload: Mapping[str, object] | None = None
    ) -> Mapping[str, object]:
        response = await self._http_client().request(
            method, f"{self._base_url}{path}", json=payload, headers=self._headers, timeout=30.0
        )
        response.raise_for_status()
        return cast(Mapping[str, object], response.json())

    async def handshake(self, payload: Mapping[str, object]) -> Mapping[str, object]:
        return await self._json("POST", "/api/executor/handshake", payload)

    async def create_approval(self, payload: Mapping[str, object]) -> Mapping[str, object]:
        return await self._json("POST", "/api/executor/approvals/action", payload)

    async def submit_job(self, payload: Mapping[str, object]) -> Mapping[str, object]:
        return await self._json("POST", "/api/work-gateway", payload)

    async def poll_job(self, job_id: str) -> Mapping[str, object]:
        return await self._json("GET", f"/api/executor/jobs/{job_id}")

    async def cancel_job(self, job_id: str) -> None:
        await self._json(
            "POST",
            "/api/executor/cancel",
            {"jobId": job_id, "reason": "Lil' Tweak canceled the tool run"},
        )


@dataclass(frozen=True)
class GalorRunnerV2Config:
    gateway_url: str
    auth_token: str
    contract: CanonicalGalorRunnerContract
    expected_contract_digest: str
    qualification_evidence_digest: str
    authorization_digest: str
    workspace_root: Path
    repository_id: str
    repository_commit: str
    authorization_signing_keys: Mapping[str, str] = field(default_factory=dict, repr=False)
    result_signing_keys: Mapping[str, str] = field(default_factory=dict, repr=False)


@dataclass
class BlockedGalorRunnerV2Transport:
    disconnect_reason: str
    provider_name: str = "galor-runner-v2"
    qualification_status: str = "unqualified"
    authorization_digest: str | None = None
    server_authorized: bool = True
    connected: bool = False

    def action_for_request(self, request: ToolRequest) -> str:
        return tool_request_action_id(request)

    async def run(self, **_: object) -> ProcessResult:
        raise ExecutorUnavailableError(self.disconnect_reason)


class GalorRunnerV2Transport:
    provider_name, qualification_status, server_authorized = "galor-runner-v2", "qualified", True

    def __init__(
        self,
        config: GalorRunnerV2Config,
        *,
        gateway: GalorWorkGatewayClient | None = None,
        now: Callable[[], datetime] | None = None,
        poll_interval_seconds: float = 0.25,
    ) -> None:
        if config.contract.digest != config.expected_contract_digest:
            raise ValueError("GALOR Runner V2 contract digest mismatch")
        parsed = urlparse(config.gateway_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("GALOR Runner V2 gateway URL is invalid")
        if config.repository_id != "lil-tweak":
            raise ValueError("GALOR Runner V2 repository is not allowlisted")
        if len(config.repository_commit) != 40 or any(
            char not in _HEX for char in config.repository_commit
        ):
            raise ValueError(
                "GALOR Runner V2 repository commit must be an immutable lowercase Git SHA"
            )
        service_token = config.auth_token
        self._config, self._gateway = (
            config,
            gateway
            or HttpGalorWorkGatewayClient(base_url=config.gateway_url, auth_token=service_token),
        )
        self._now, self._poll_interval_seconds = (
            now or (lambda: datetime.now(UTC)),
            poll_interval_seconds,
        )
        self._connection = RunnerConnectionVerifier(
            gateway=self._gateway,
            execution_host=config.contract.execution_host,
            contract_digest=config.expected_contract_digest,
            qualification_evidence_digest=config.qualification_evidence_digest,
            authorization_digest=config.authorization_digest,
            authorization_signing_keys=config.authorization_signing_keys,
            result_signing_keys=config.result_signing_keys,
            now=self._now,
            poll_interval_seconds=self._poll_interval_seconds,
        )

    @property
    def connected(self) -> bool:
        return self._connection.connected

    @property
    def authorization_digest(self) -> str:
        return self._config.authorization_digest

    @property
    def disconnect_reason(self) -> str:
        return self._connection.disconnect_reason

    async def refresh_connection(self) -> RunnerConnectionProof:
        return await self._connection.refresh()

    def action_for_request(self, request: ToolRequest) -> str:
        action = tool_request_action_id(request)
        if action not in self._config.contract.action_ids:
            raise ValueError("GALOR Runner V2 contract does not support the requested action")
        return action

    async def run(
        self,
        *,
        executable: str,
        args: tuple[str, ...],
        cwd: Path,
        timeout_seconds: int,
        output_byte_limit: int,
        network: NetworkMode,
        cancel_event: asyncio.Event,
        approval_digest: str = "",
    ) -> ProcessResult:
        action = command_action_id(executable, args)
        return await self.run_action(
            action=action,
            input=command_action_input(action, args),
            cwd=cwd,
            timeout_seconds=timeout_seconds,
            output_byte_limit=output_byte_limit,
            network=network,
            cancel_event=cancel_event,
            approval_digest=approval_digest,
        )

    async def run_action(
        self,
        *,
        action: str,
        input: Mapping[str, object],
        cwd: Path,
        timeout_seconds: int,
        output_byte_limit: int,
        network: NetworkMode,
        cancel_event: asyncio.Event,
        approval_digest: str = "",
    ) -> ProcessResult:
        del cwd, output_byte_limit
        if action not in self._config.contract.action_ids:
            raise ExecutorUnavailableError("GALOR Runner V2 contract does not support this action")
        if network != NetworkMode.DENIED:
            raise ExecutorUnavailableError(
                "GALOR Runner V2 engineering actions require denied network"
            )
        if len(approval_digest) != 64 or any(char not in _HEX for char in approval_digest):
            raise ExecutorUnavailableError(
                "GALOR Runner V2 requires exact Workbench approval evidence"
            )
        scope = f"repo:{self._config.repository_id}@{self._config.repository_commit}"
        effect_class = (
            "WRITE" if action in {"runner.applyPatch", "runner.prepareLocalCommit"} else "READ"
        )
        reason = f"Lil' Tweak approved {action} for immutable repository scope"
        approval = await self._gateway.create_approval(
            {
                "scope": scope,
                "action": action,
                "effectClass": effect_class,
                "input": dict(input),
                "secretNames": [],
                "reason": reason,
                "ownerApprovalDigest": approval_digest,
            }
        )
        approval_id, tenant_id, expires_at = (
            approval.get("approvalId"),
            approval.get("tenantId"),
            approval.get("expiresAt"),
        )
        if not all(
            isinstance(value, str) and value for value in (approval_id, tenant_id, expires_at)
        ):
            raise ExecutorUnavailableError("GALOR Hub returned an invalid action approval")
        accepted = await self._gateway.submit_job(
            {
                "project": "lil-tweak",
                "command": action,
                "objective": reason,
                "idempotencyKey": f"liltweak:{uuid.uuid4().hex}",
                "effectClass": effect_class,
                "priority": 50,
                "resources": [{"resource": scope, "mode": "exclusive"}],
                "dependencyIds": [],
                "approvalRequired": True,
                "execution": {
                    "tenantId": tenant_id,
                    "scope": scope,
                    "action": action,
                    "input": dict(input),
                    "secretNames": [],
                    "approvalId": approval_id,
                    "expiresAt": expires_at,
                },
            }
        )
        job_id = accepted.get("jobId")
        if accepted.get("accepted") is not True or not isinstance(job_id, str) or not job_id:
            raise ExecutorUnavailableError("GALOR Hub did not accept the executor job")
        deadline, cancel_sent = self._now() + timedelta(seconds=max(timeout_seconds, 1)), False
        while True:
            if cancel_event.is_set() and not cancel_sent:
                await self._gateway.cancel_job(job_id)
                cancel_sent = True
            if self._now() >= deadline:
                if not cancel_sent:
                    await self._gateway.cancel_job(job_id)
                return ProcessResult(None, b"", b"", True, False)
            status = await self._gateway.poll_job(job_id)
            if status.get("jobId") != job_id or status.get("tenantId") != tenant_id:
                raise ExecutorUnavailableError("GALOR Hub job status binding is invalid")
            state = status.get("state")
            if state not in {"succeeded", "failed", "cancelled", "blocked"}:
                await asyncio.sleep(self._poll_interval_seconds)
                continue
            if state == "cancelled":
                return ProcessResult(None, b"", b"", False, True)
            result = status.get("result")
            if not isinstance(result, Mapping):
                return ProcessResult(
                    1,
                    b"",
                    str(status.get("failureReason") or "GALOR Runner V2 job failed").encode(),
                    False,
                    False,
                )
            receipt = result.get("receipt")
            if (
                not isinstance(receipt, Mapping)
                or receipt.get("commit") != self._config.repository_commit
            ):
                raise ExecutorUnavailableError("GALOR Hub result repository binding is invalid")
            exit_code = receipt.get("exitCode")
            return ProcessResult(
                exit_code if isinstance(exit_code, int) else None,
                str(result.get("stdout") or "").encode(),
                str(result.get("stderr") or "").encode(),
                False,
                False,
            )
