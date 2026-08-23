from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import secrets
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import urlparse

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ConfigDict, Field, StrictBool, StrictInt, StrictStr, model_validator

from .creator_contract import CreatorSchema, canonical_json, content_digest
from .workbench_contract import NetworkMode, ToolKind, ToolRequest
from .workbench_executor import ExecutorUnavailableError, ProcessResult

_SHA256 = r"^[0-9a-f]{64}$"
_SAFE_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_SIGNATURE = r"^[A-Za-z0-9_-]{86}$"
_RECEIPT_DOMAIN = b"liltweak:galor-runner-v2-receipt\0"
_CONTRACT_DOMAIN = b"liltweak:galor-runner-v2-contract\0"
_REQUIRED_ACTIONS = frozenset(
    {
        "repository.list",
        "repository.read",
        "workspace.write",
        "workspace.apply_patch",
        "git.status",
        "git.diff",
        "verification.pytest",
        "verification.mypy",
        "verification.ruff.check",
        "verification.ruff.format_check",
        "verification.build",
        "git.prepare_local_commit",
    }
)


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _decode_signature(value: str) -> bytes:
    padded = value + ("=" * (-len(value) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _encode_signature(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_b64(value: str) -> bytes:
    padded = value + ("=" * (-len(value) % 4))
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("runner receipt payload is not valid base64url") from exc


def _key_id(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise ValueError("GALOR Runner V2 public keys must be exactly 32 bytes")
    return hashlib.sha256(public_key).hexdigest()


def tool_request_action_id(request: ToolRequest) -> str:
    if request.kind == ToolKind.LIST_FILES:
        return "repository.list"
    if request.kind == ToolKind.READ_FILE:
        return "repository.read"
    if request.kind == ToolKind.WRITE_FILE:
        return "workspace.write"
    if request.kind == ToolKind.APPLY_PATCH:
        return "workspace.apply_patch"
    if request.command is None:
        raise ValueError("tool request command payload is missing")
    return command_action_id(request.command.executable, request.command.args)


def command_action_id(executable: str, args: tuple[str, ...]) -> str:
    normalized = executable.casefold()
    first = args[0].casefold() if args else ""
    if normalized == "pytest":
        return "verification.pytest"
    if normalized == "mypy":
        return "verification.mypy"
    if normalized == "ruff":
        if first == "check":
            return "verification.ruff.check"
        if first == "format" and "--check" in args[1:]:
            return "verification.ruff.format_check"
    if normalized == "git":
        if first == "status":
            return "git.status"
        if first == "diff":
            return "git.diff"
        if first == "commit":
            return "git.prepare_local_commit"
    if normalized == "uv" and first == "build":
        return "verification.build"
    if normalized.startswith("python") and args[:2] == ("-m", "build"):
        return "verification.build"
    raise ValueError("runner does not support this structured command")


class GalorRunnerV2Contract(CreatorSchema):
    schema_version: Literal["galor-runner-contract-v2"] = "galor-runner-contract-v2"
    contract_id: Literal["galor.runner.v2"] = "galor.runner.v2"
    runner_id: StrictStr = Field(pattern=_SAFE_ID)
    tenant_id: StrictStr = Field(pattern=_SAFE_ID)
    supported_actions: tuple[StrictStr, ...] = Field(min_length=1, max_length=128)
    signer_key_id: StrictStr = Field(pattern=_SHA256)
    contract_digest: StrictStr = Field(pattern=_SHA256)
    signature: StrictStr = Field(pattern=_SIGNATURE)

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @model_validator(mode="after")
    def validate_contract(self) -> GalorRunnerV2Contract:
        if len(set(self.supported_actions)) != len(self.supported_actions):
            raise ValueError("runner contract actions must be unique")
        if not _REQUIRED_ACTIONS.issubset(self.supported_actions):
            raise ValueError("runner contract does not support the required Lil Tweak actions")
        expected = content_digest(
            self.model_dump(mode="json", exclude={"contract_digest", "signature"})
        )
        if self.contract_digest != expected:
            raise ValueError("runner contract digest mismatch")
        return self


def galor_runner_contract_signature_message(contract: GalorRunnerV2Contract) -> bytes:
    payload = canonical_json(contract.model_dump(mode="json", exclude={"signature"})).encode("utf-8")
    return _CONTRACT_DOMAIN + payload


class GalorRunnerV2DispatchAccepted(CreatorSchema):
    schema_version: Literal["galor-dispatch-accepted-v2"] = "galor-dispatch-accepted-v2"
    dispatch_id: StrictStr = Field(pattern=_SAFE_ID)
    tenant_id: StrictStr = Field(pattern=_SAFE_ID)
    runner_id: StrictStr = Field(pattern=_SAFE_ID)
    job_id: StrictStr = Field(pattern=_SAFE_ID)
    action_id: StrictStr = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    accepted_at: datetime

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @model_validator(mode="after")
    def validate_times(self) -> GalorRunnerV2DispatchAccepted:
        if not _aware(self.accepted_at):
            raise ValueError("dispatch acceptance time must be timezone-aware")
        return self


class GalorRunnerV2Receipt(CreatorSchema):
    schema_version: Literal["galor-runner-receipt-v2"] = "galor-runner-receipt-v2"
    receipt_id: StrictStr = Field(pattern=_SAFE_ID)
    tenant_id: StrictStr = Field(pattern=_SAFE_ID)
    runner_id: StrictStr = Field(pattern=_SAFE_ID)
    job_id: StrictStr = Field(pattern=_SAFE_ID)
    dispatch_id: StrictStr = Field(pattern=_SAFE_ID)
    action_id: StrictStr = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    source_binding_digest: StrictStr = Field(pattern=_SHA256)
    exit_code: StrictInt | None = Field(default=None, ge=0, le=255)
    timed_out: StrictBool = False
    canceled: StrictBool = False
    stdout_b64: StrictStr
    stderr_b64: StrictStr
    started_at: datetime
    heartbeat_at: datetime
    completed_at: datetime
    evidence_digest: StrictStr = Field(pattern=_SHA256)
    signer_key_id: StrictStr = Field(pattern=_SHA256)
    signature: StrictStr = Field(pattern=_SIGNATURE)

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @model_validator(mode="after")
    def validate_receipt(self) -> GalorRunnerV2Receipt:
        for value in (self.started_at, self.heartbeat_at, self.completed_at):
            if not _aware(value):
                raise ValueError("runner receipt timestamps must be timezone-aware")
        if not (self.started_at <= self.heartbeat_at <= self.completed_at):
            raise ValueError("runner receipt timestamps are inconsistent")
        if (self.timed_out or self.canceled) and self.exit_code == 0:
            raise ValueError("runner receipt cannot claim a successful exit after timeout or cancel")
        expected = content_digest(
            self.model_dump(mode="json", exclude={"evidence_digest", "signature"})
        )
        if self.evidence_digest != expected:
            raise ValueError("runner receipt evidence digest mismatch")
        return self


def galor_runner_receipt_signature_message(receipt: GalorRunnerV2Receipt) -> bytes:
    payload = canonical_json(receipt.model_dump(mode="json", exclude={"signature"})).encode("utf-8")
    return _RECEIPT_DOMAIN + payload


class GalorRunnerV2Status(CreatorSchema):
    schema_version: Literal["galor-dispatch-status-v2"] = "galor-dispatch-status-v2"
    dispatch_id: StrictStr = Field(pattern=_SAFE_ID)
    tenant_id: StrictStr = Field(pattern=_SAFE_ID)
    runner_id: StrictStr = Field(pattern=_SAFE_ID)
    job_id: StrictStr = Field(pattern=_SAFE_ID)
    action_id: StrictStr = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    status: Literal["running", "succeeded", "failed", "canceled", "timed_out"]
    heartbeat_at: datetime
    completed_at: datetime | None = None
    receipt: GalorRunnerV2Receipt | None = None

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @model_validator(mode="after")
    def validate_status(self) -> GalorRunnerV2Status:
        if not _aware(self.heartbeat_at):
            raise ValueError("runner heartbeat time must be timezone-aware")
        if self.status == "running":
            if self.receipt is not None or self.completed_at is not None:
                raise ValueError("running dispatch status cannot include a terminal receipt")
            return self
        if self.receipt is None or self.completed_at is None:
            raise ValueError("terminal dispatch status requires a signed receipt")
        if not _aware(self.completed_at):
            raise ValueError("dispatch completion time must be timezone-aware")
        return self


class GalorWorkGatewayClient(Protocol):
    async def submit_dispatch(self, payload: Mapping[str, object]) -> Mapping[str, object]: ...

    async def poll_dispatch(self, dispatch_id: str) -> Mapping[str, object]: ...

    async def cancel_dispatch(self, dispatch_id: str) -> None: ...


class HttpGalorWorkGatewayClient:
    def __init__(
        self,
        *,
        base_url: str,
        auth_token: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_token = auth_token
        self._client = client

    async def submit_dispatch(self, payload: Mapping[str, object]) -> Mapping[str, object]:
        client = self._client or httpx.AsyncClient()
        owns_client = self._client is None
        try:
            response = await client.post(
                f"{self._base_url}/v2/dispatches",
                json=payload,
                headers={"Authorization": f"******"},
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()
        finally:
            if owns_client:
                await client.aclose()

    async def poll_dispatch(self, dispatch_id: str) -> Mapping[str, object]:
        client = self._client or httpx.AsyncClient()
        owns_client = self._client is None
        try:
            response = await client.get(
                f"{self._base_url}/v2/dispatches/{dispatch_id}",
                headers={"Authorization": f"******"},
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()
        finally:
            if owns_client:
                await client.aclose()

    async def cancel_dispatch(self, dispatch_id: str) -> None:
        client = self._client or httpx.AsyncClient()
        owns_client = self._client is None
        try:
            response = await client.post(
                f"{self._base_url}/v2/dispatches/{dispatch_id}/cancel",
                headers={"Authorization": f"******"},
                timeout=30.0,
            )
            response.raise_for_status()
        finally:
            if owns_client:
                await client.aclose()


@dataclass(frozen=True)
class GalorRunnerV2Config:
    gateway_url: str
    auth_token: str
    contract: GalorRunnerV2Contract
    expected_contract_digest: str
    qualification_evidence_digest: str
    authorization_digest: str
    signing_keys: Mapping[str, bytes]
    workspace_root: Path
    max_heartbeat_age_seconds: int = 120
    max_receipt_age_seconds: int = 300


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
    provider_name = "galor-runner-v2"
    qualification_status = "qualified"
    server_authorized = True

    def __init__(
        self,
        config: GalorRunnerV2Config,
        *,
        gateway: GalorWorkGatewayClient | None = None,
        now: callable | None = None,
        poll_interval_seconds: float = 0.25,
    ) -> None:
        if config.contract.schema_version != "galor-runner-contract-v2":
            raise ValueError("GALOR Runner V1 downgrade is rejected")
        if config.contract.contract_digest != config.expected_contract_digest:
            raise ValueError("GALOR Runner V2 contract digest mismatch")
        parsed = urlparse(config.gateway_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.params or parsed.query:
            raise ValueError("GALOR Runner V2 gateway URL is invalid")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError("GALOR Runner V2 gateway URL is invalid")
        if (
            not config.authorization_digest
            or len(config.authorization_digest) != 64
            or any(character not in "0123456789abcdef" for character in config.authorization_digest)
        ):
            raise ValueError("GALOR Runner V2 authorization digest is invalid")
        self._config = config
        self._gateway = gateway or HttpGalorWorkGatewayClient(
            base_url=config.gateway_url,
            auth_token=config.auth_token,
        )
        self._now = now or (lambda: datetime.now(UTC))
        self._poll_interval_seconds = poll_interval_seconds
        self._seen_receipts: set[str] = set()
        self._disconnect_reason = "GALOR Runner V2 is connected and authorized"
        self._verify_contract()

    @property
    def connected(self) -> bool:
        return True

    @property
    def authorization_digest(self) -> str:
        return self._config.authorization_digest

    @property
    def disconnect_reason(self) -> str:
        return self._disconnect_reason

    def action_for_request(self, request: ToolRequest) -> str:
        action_id = tool_request_action_id(request)
        if action_id not in self._config.contract.supported_actions:
            raise ValueError("GALOR Runner V2 contract does not support the requested action")
        return action_id

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
    ) -> ProcessResult:
        action_id = command_action_id(executable, args)
        if action_id not in self._config.contract.supported_actions:
            raise ExecutorUnavailableError("GALOR Runner V2 contract does not support this action")
        working_directory = self._relative_cwd(cwd)
        dispatch_id = f"dispatch:{uuid.uuid4().hex}"
        job_id = f"job:{uuid.uuid4().hex}"
        source_binding_digest = content_digest(
            {
                "action_id": action_id,
                "working_directory": working_directory,
                "network": network.value,
            }
        )
        payload = {
            "schema_version": "liltweak-galor-dispatch-request-v2",
            "dispatch_id": dispatch_id,
            "job_id": job_id,
            "tenant_id": self._config.contract.tenant_id,
            "runner_id": self._config.contract.runner_id,
            "contract_digest": self._config.contract.contract_digest,
            "authorization_digest": self._config.authorization_digest,
            "qualification_evidence_digest": self._config.qualification_evidence_digest,
            "action_id": action_id,
            "working_directory": working_directory,
            "executable": executable,
            "args": list(args),
            "timeout_seconds": timeout_seconds,
            "output_byte_limit": output_byte_limit,
            "network": network.value,
            "source_binding_digest": source_binding_digest,
        }
        accepted = self._validate_dispatch_accepted(
            await self._gateway.submit_dispatch(payload),
            dispatch_id=dispatch_id,
            job_id=job_id,
            action_id=action_id,
        )
        deadline = self._now() + timedelta(seconds=max(timeout_seconds, 1))
        while True:
            if cancel_event.is_set():
                await self._gateway.cancel_dispatch(dispatch_id)
            if self._now() >= deadline:
                await self._gateway.cancel_dispatch(dispatch_id)
                return ProcessResult(None, b"", b"", True, False)
            status = self._validate_dispatch_status(
                await self._gateway.poll_dispatch(dispatch_id),
                accepted=accepted,
            )
            if self._now() - status.heartbeat_at > timedelta(
                seconds=self._config.max_heartbeat_age_seconds
            ):
                raise ExecutorUnavailableError("GALOR Runner V2 heartbeat is stale")
            if status.receipt is None:
                await asyncio.sleep(self._poll_interval_seconds)
                continue
            receipt = self._verify_receipt(
                status.receipt,
                dispatch_id=dispatch_id,
                job_id=job_id,
                action_id=action_id,
                source_binding_digest=source_binding_digest,
            )
            stdout = _decode_b64(receipt.stdout_b64)
            stderr = _decode_b64(receipt.stderr_b64)
            return ProcessResult(
                receipt.exit_code,
                stdout,
                stderr,
                receipt.timed_out,
                receipt.canceled,
            )

    def _relative_cwd(self, cwd: Path) -> str:
        root = self._config.workspace_root.resolve()
        resolved = cwd.resolve()
        if not resolved.is_relative_to(root):
            raise ExecutorUnavailableError("GALOR Runner V2 source binding rejected the workspace path")
        relative = resolved.relative_to(root).as_posix()
        return "." if not relative else relative

    def _verify_contract(self) -> None:
        public_key = self._config.signing_keys.get(self._config.contract.signer_key_id)
        if public_key is None:
            raise ValueError("GALOR Runner V2 contract signer is untrusted")
        if _key_id(public_key) != self._config.contract.signer_key_id:
            raise ValueError("GALOR Runner V2 contract signer key id is invalid")
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                _decode_signature(self._config.contract.signature),
                galor_runner_contract_signature_message(self._config.contract),
            )
        except (InvalidSignature, ValueError) as exc:
            raise ValueError("GALOR Runner V2 contract signature is invalid") from exc

    def _validate_dispatch_accepted(
        self,
        payload: Mapping[str, object],
        *,
        dispatch_id: str,
        job_id: str,
        action_id: str,
    ) -> GalorRunnerV2DispatchAccepted:
        version = payload.get("schema_version")
        if version == "galor-dispatch-accepted-v1":
            raise ValueError("GALOR Runner V1 downgrade is rejected")
        accepted = GalorRunnerV2DispatchAccepted.model_validate(payload)
        if accepted.dispatch_id != dispatch_id:
            raise ValueError("GALOR Runner V2 dispatch binding is invalid")
        if accepted.job_id != job_id:
            raise ValueError("GALOR Runner V2 job binding is invalid")
        if accepted.action_id != action_id:
            raise ValueError("GALOR Runner V2 action binding is invalid")
        if accepted.tenant_id != self._config.contract.tenant_id:
            raise ValueError("GALOR Runner V2 tenant binding is invalid")
        if accepted.runner_id != self._config.contract.runner_id:
            raise ValueError("GALOR Runner V2 runner identity is invalid")
        return accepted

    def _validate_dispatch_status(
        self,
        payload: Mapping[str, object],
        *,
        accepted: GalorRunnerV2DispatchAccepted,
    ) -> GalorRunnerV2Status:
        version = payload.get("schema_version")
        if version == "galor-dispatch-status-v1":
            raise ValueError("GALOR Runner V1 downgrade is rejected")
        status = GalorRunnerV2Status.model_validate(payload)
        if status.dispatch_id != accepted.dispatch_id:
            raise ValueError("GALOR Runner V2 dispatch binding is invalid")
        if status.job_id != accepted.job_id:
            raise ValueError("GALOR Runner V2 job binding is invalid")
        if status.action_id != accepted.action_id:
            raise ValueError("GALOR Runner V2 action binding is invalid")
        if status.tenant_id != self._config.contract.tenant_id:
            raise ValueError("GALOR Runner V2 tenant binding is invalid")
        if status.runner_id != self._config.contract.runner_id:
            raise ValueError("GALOR Runner V2 runner identity is invalid")
        return status

    def _verify_receipt(
        self,
        receipt: GalorRunnerV2Receipt,
        *,
        dispatch_id: str,
        job_id: str,
        action_id: str,
        source_binding_digest: str,
    ) -> GalorRunnerV2Receipt:
        if receipt.dispatch_id != dispatch_id:
            raise ValueError("GALOR Runner V2 dispatch binding is invalid")
        if receipt.job_id != job_id:
            raise ValueError("GALOR Runner V2 job binding is invalid")
        if receipt.action_id != action_id:
            raise ValueError("GALOR Runner V2 action binding is invalid")
        if receipt.tenant_id != self._config.contract.tenant_id:
            raise ValueError("GALOR Runner V2 tenant binding is invalid")
        if receipt.runner_id != self._config.contract.runner_id:
            raise ValueError("GALOR Runner V2 runner identity is invalid")
        if receipt.source_binding_digest != source_binding_digest:
            raise ValueError("GALOR Runner V2 source binding is invalid")
        if receipt.receipt_id in self._seen_receipts or receipt.evidence_digest in self._seen_receipts:
            raise ValueError("GALOR Runner V2 receipt replay is rejected")
        if self._now() - receipt.completed_at > timedelta(seconds=self._config.max_receipt_age_seconds):
            raise ValueError("GALOR Runner V2 receipt is stale")
        public_key = self._config.signing_keys.get(receipt.signer_key_id)
        if public_key is None:
            raise ValueError("GALOR Runner V2 receipt signer is untrusted")
        if _key_id(public_key) != receipt.signer_key_id:
            raise ValueError("GALOR Runner V2 receipt signer key id is invalid")
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                _decode_signature(receipt.signature),
                galor_runner_receipt_signature_message(receipt),
            )
        except (InvalidSignature, ValueError) as exc:
            raise ValueError("GALOR Runner V2 receipt signature is invalid") from exc
        self._seen_receipts.add(receipt.receipt_id)
        self._seen_receipts.add(receipt.evidence_digest)
        return receipt


def parse_signing_keys(payload: str) -> dict[str, bytes]:
    try:
        raw = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError("GALOR Runner V2 signing keys must be valid JSON") from exc
    if not isinstance(raw, dict) or not raw:
        raise ValueError("GALOR Runner V2 signing keys must be a non-empty object")
    parsed: dict[str, bytes] = {}
    for key_id, encoded in raw.items():
        if not isinstance(key_id, str) or not isinstance(encoded, str):
            raise ValueError("GALOR Runner V2 signing keys must map strings to strings")
        key = _decode_b64(encoded)
        if _key_id(key) != key_id:
            raise ValueError("GALOR Runner V2 signing key id does not match the supplied key")
        parsed[key_id] = key
    return parsed


def sign_contract(
    *,
    runner_id: str,
    tenant_id: str,
    supported_actions: tuple[str, ...],
    public_key: bytes,
    private_key_signer: callable,
) -> GalorRunnerV2Contract:
    signer_key_id = _key_id(public_key)
    unsigned = GalorRunnerV2Contract.model_construct(
        runner_id=runner_id,
        tenant_id=tenant_id,
        supported_actions=supported_actions,
        signer_key_id=signer_key_id,
        contract_digest="0" * 64,
        signature="A" * 86,
    )
    digest = content_digest(unsigned.model_dump(mode="json", exclude={"contract_digest", "signature"}))
    draft = GalorRunnerV2Contract.model_construct(
        runner_id=runner_id,
        tenant_id=tenant_id,
        supported_actions=supported_actions,
        signer_key_id=signer_key_id,
        contract_digest=digest,
        signature="A" * 86,
    )
    signature = _encode_signature(private_key_signer(galor_runner_contract_signature_message(draft)))
    return GalorRunnerV2Contract(
        runner_id=runner_id,
        tenant_id=tenant_id,
        supported_actions=supported_actions,
        signer_key_id=signer_key_id,
        contract_digest=digest,
        signature=signature,
    )
