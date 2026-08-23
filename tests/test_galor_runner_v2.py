from __future__ import annotations

import asyncio
import base64
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from liltweak.api import create_app
from liltweak.config import Settings
from liltweak.creator_contract import content_digest
from liltweak.galor_runner_v2 import (
    BlockedGalorRunnerV2Transport,
    GalorRunnerV2Config,
    GalorRunnerV2Receipt,
    GalorRunnerV2Transport,
    command_action_id,
    galor_runner_receipt_signature_message,
    parse_signing_keys,
    sign_contract,
    tool_request_action_id,
)
from liltweak.workbench_contract import (
    NetworkMode,
    StepPhase,
    ToolKind,
    ToolRequest,
)

NOW = datetime(2026, 8, 23, 3, 0, tzinfo=UTC)


def _public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _signature(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _contract(runner_key: Ed25519PrivateKey):
    return sign_contract(
        runner_id="galor-private-cloud-01",
        tenant_id="tenant-1",
        supported_actions=tuple(
            sorted(
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
        ),
        public_key=_public_bytes(runner_key),
        private_key_signer=runner_key.sign,
    )


def _config(tmp_path: Path, runner_key: Ed25519PrivateKey) -> GalorRunnerV2Config:
    contract = _contract(runner_key)
    public_key = _public_bytes(runner_key)
    return GalorRunnerV2Config(
        gateway_url="https://galor.invalid/runner",
        auth_token="t" * 24,
        contract=contract,
        expected_contract_digest=contract.contract_digest,
        qualification_evidence_digest="a" * 64,
        authorization_digest="b" * 64,
        signing_keys={contract.signer_key_id: public_key},
        workspace_root=tmp_path / "tasks",
    )


def _receipt(
    runner_key: Ed25519PrivateKey,
    *,
    dispatch_id: str = "dispatch:one",
    job_id: str = "job:one",
    runner_id: str = "galor-private-cloud-01",
    tenant_id: str = "tenant-1",
    action_id: str = "verification.pytest",
    source_binding_digest: str = "c" * 64,
    completed_at: datetime = NOW,
    exit_code: int | None = 0,
    timed_out: bool = False,
    canceled: bool = False,
) -> GalorRunnerV2Receipt:
    signer_key_id = _contract(runner_key).signer_key_id
    values = {
        "receipt_id": "receipt:one",
        "tenant_id": tenant_id,
        "runner_id": runner_id,
        "job_id": job_id,
        "dispatch_id": dispatch_id,
        "action_id": action_id,
        "source_binding_digest": source_binding_digest,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "canceled": canceled,
        "stdout_b64": _signature(b"ok"),
        "stderr_b64": "",
        "started_at": NOW - timedelta(seconds=1),
        "heartbeat_at": NOW,
        "completed_at": completed_at,
        "signer_key_id": signer_key_id,
    }
    unsigned = GalorRunnerV2Receipt.model_construct(
        **values,
        evidence_digest="0" * 64,
        signature="A" * 86,
    )
    exact_digest = content_digest(unsigned.model_dump(mode="json", exclude={"evidence_digest", "signature"}))
    signed = GalorRunnerV2Receipt.model_construct(
        **values,
        evidence_digest=exact_digest,
        signature="A" * 86,
    )
    signature = _signature(runner_key.sign(galor_runner_receipt_signature_message(signed)))
    return GalorRunnerV2Receipt(**values, evidence_digest=exact_digest, signature=signature)


class _Gateway:
    def __init__(self, *, statuses: list[dict[str, object]]) -> None:
        self.statuses = list(statuses)
        self.canceled: list[str] = []
        self.submitted: dict[str, object] | None = None

    async def submit_dispatch(self, payload):
        self.submitted = dict(payload)
        return {
            "schema_version": "galor-dispatch-accepted-v2",
            "dispatch_id": payload["dispatch_id"],
            "tenant_id": payload["tenant_id"],
            "runner_id": payload["runner_id"],
            "job_id": payload["job_id"],
            "action_id": payload["action_id"],
            "accepted_at": NOW,
        }

    async def poll_dispatch(self, dispatch_id: str):
        assert dispatch_id
        payload = dict(self.statuses.pop(0))
        submitted = self.submitted or {}
        for key in ("dispatch_id", "tenant_id", "runner_id", "job_id", "action_id"):
            if key in submitted:
                payload[key] = submitted[key]
        return payload

    async def cancel_dispatch(self, dispatch_id: str) -> None:
        self.canceled.append(dispatch_id)


def _status(receipt: GalorRunnerV2Receipt | None, *, status: str = "running") -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "galor-dispatch-status-v2",
        "dispatch_id": receipt.dispatch_id if receipt is not None else "dispatch:one",
        "tenant_id": receipt.tenant_id if receipt is not None else "tenant-1",
        "runner_id": receipt.runner_id if receipt is not None else "galor-private-cloud-01",
        "job_id": receipt.job_id if receipt is not None else "job:one",
        "action_id": receipt.action_id if receipt is not None else "verification.pytest",
        "status": status,
        "heartbeat_at": NOW,
    }
    if receipt is not None:
        payload["completed_at"] = receipt.completed_at
        payload["receipt"] = receipt.model_dump(mode="python")
    return payload


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        database_path=tmp_path / "app.db",
        dev_api_key="owner-secret",
        auth_disabled=False,
        model="gpt-5.6-sol",
        monthly_budget_usd=10,
        job_hard_limit_usd=1,
        workbench_enabled=True,
        workbench_workspace_root=tmp_path / "tasks",
    )


def test_factory_reports_exact_runner_blocker_without_host_fallback(tmp_path: Path) -> None:
    client = TestClient(
        create_app(
            settings=_settings(tmp_path),
            workbench_transport=BlockedGalorRunnerV2Transport(
                "GALOR Runner V2 is blocked: qualification evidence is missing",
                qualification_status="unavailable",
            ),
        ),
        base_url="http://127.0.0.1",
    )
    login = client.post("/v1/workbench/session", json={"owner_key": "owner-secret"})
    assert login.status_code == 200
    health = client.get("/v1/workbench/health").json()
    assert health["runner_provider"] == "galor-runner-v2"
    assert health["runner_connected"] is False
    assert any("qualification evidence is missing" in item for item in health["missing_prerequisites"])


def test_action_mapping_covers_required_engineering_tools() -> None:
    read = ToolRequest(
        tool_id="read",
        kind=ToolKind.READ_FILE,
        phase=StepPhase.INSPECTION,
        purpose="read",
        file={"path": "src/app.py"},
    )
    patch = ToolRequest(
        tool_id="patch",
        kind=ToolKind.APPLY_PATCH,
        phase=StepPhase.MUTATION,
        purpose="patch",
        file={"path": "src/app.py", "content": "patched", "expected_sha256": "a" * 64},
    )
    assert tool_request_action_id(read) == "repository.read"
    assert tool_request_action_id(patch) == "workspace.apply_patch"
    assert command_action_id("git", ("status", "--short")) == "git.status"
    assert command_action_id("git", ("diff", "--stat")) == "git.diff"
    assert command_action_id("pytest", ("-q",)) == "verification.pytest"
    assert command_action_id("mypy", ()) == "verification.mypy"
    assert command_action_id("ruff", ("check", ".")) == "verification.ruff.check"
    assert command_action_id("ruff", ("format", "--check", ".")) == "verification.ruff.format_check"
    assert command_action_id("uv", ("build", "--offline")) == "verification.build"


def test_transport_rejects_contract_digest_mismatch_and_v1_downgrade(tmp_path: Path) -> None:
    runner_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    config = _config(tmp_path, runner_key)
    with pytest.raises(ValueError, match="digest mismatch"):
        GalorRunnerV2Transport(replace(config, expected_contract_digest="d" * 64))
    transport = GalorRunnerV2Transport(config, gateway=_Gateway(statuses=[]), now=lambda: NOW)
    with pytest.raises(ValueError, match="downgrade"):
        transport._validate_dispatch_accepted(
            {
                "schema_version": "galor-dispatch-accepted-v1",
                "dispatch_id": "dispatch:one",
                "tenant_id": "tenant-1",
                "runner_id": "galor-private-cloud-01",
                "job_id": "job:one",
                "action_id": "verification.pytest",
                "accepted_at": NOW,
            },
            dispatch_id="dispatch:one",
            job_id="job:one",
            action_id="verification.pytest",
        )


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("runner_id", "other-runner", "runner identity"),
        ("tenant_id", "other-tenant", "tenant binding"),
        ("job_id", "job:two", "job binding"),
        ("dispatch_id", "dispatch:two", "dispatch binding"),
        ("source_binding_digest", "d" * 64, "source binding"),
    ],
)
def test_receipt_verification_rejects_wrong_bindings_and_replay(
    tmp_path: Path,
    field: str,
    value: str,
    error: str,
) -> None:
    runner_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    config = _config(tmp_path, runner_key)
    transport = GalorRunnerV2Transport(config, gateway=_Gateway(statuses=[]), now=lambda: NOW)
    receipt = _receipt(runner_key)
    with pytest.raises(ValueError, match=error):
        transport._verify_receipt(
            receipt.model_copy(update={field: value}),
            dispatch_id="dispatch:one",
            job_id="job:one",
            action_id="verification.pytest",
            source_binding_digest="c" * 64,
        )
    verified = transport._verify_receipt(
        receipt,
        dispatch_id="dispatch:one",
        job_id="job:one",
        action_id="verification.pytest",
        source_binding_digest="c" * 64,
    )
    assert verified.receipt_id == "receipt:one"
    with pytest.raises(ValueError, match="replay"):
        transport._verify_receipt(
            receipt,
            dispatch_id="dispatch:one",
            job_id="job:one",
            action_id="verification.pytest",
            source_binding_digest="c" * 64,
        )


@pytest.mark.asyncio
async def test_transport_handles_timeout_and_cancellation(tmp_path: Path) -> None:
    runner_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    config = _config(tmp_path, runner_key)
    workspaces = config.workspace_root
    (workspaces / "task").mkdir(parents=True)
    timeout_gateway = _Gateway(statuses=[_status(None)])
    clock = iter([NOW, NOW, NOW, NOW + timedelta(seconds=2), NOW + timedelta(seconds=2)])
    timeout_transport = GalorRunnerV2Transport(
        config,
        gateway=timeout_gateway,
        now=clock.__next__,
        poll_interval_seconds=0,
    )
    with patch(
        "liltweak.galor_runner_v2.uuid.uuid4",
        side_effect=[SimpleNamespace(hex="one"), SimpleNamespace(hex="one")],
    ):
        timed_out = await timeout_transport.run(
            executable="pytest",
            args=("-q",),
            cwd=workspaces / "task",
            timeout_seconds=1,
            output_byte_limit=1_000_000,
            network=NetworkMode.DENIED,
            cancel_event=asyncio.Event(),
        )
    assert timed_out.timed_out is True
    assert timeout_gateway.canceled

    receipt = _receipt(
        runner_key,
        source_binding_digest=content_digest(
            {
                "action_id": "verification.pytest",
                "working_directory": "task",
                "network": NetworkMode.DENIED.value,
            }
        ),
        exit_code=None,
        canceled=True,
    )
    cancel_gateway = _Gateway(statuses=[_status(receipt, status="canceled")])
    cancel_transport = GalorRunnerV2Transport(
        config,
        gateway=cancel_gateway,
        now=lambda: NOW,
        poll_interval_seconds=0,
    )
    event = asyncio.Event()
    event.set()
    with patch(
        "liltweak.galor_runner_v2.uuid.uuid4",
        side_effect=[SimpleNamespace(hex="one"), SimpleNamespace(hex="one")],
    ):
        canceled = await cancel_transport.run(
            executable="pytest",
            args=("-q",),
            cwd=workspaces / "task",
            timeout_seconds=30,
            output_byte_limit=1_000_000,
            network=NetworkMode.DENIED,
            cancel_event=event,
        )
    assert canceled.canceled is True
    assert cancel_gateway.canceled


def test_parse_signing_keys_requires_matching_key_ids() -> None:
    runner_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public_key = _public_bytes(runner_key)
    payload = '{"bad":"%s"}' % _signature(public_key)
    with pytest.raises(ValueError, match="does not match"):
        parse_signing_keys(payload)
