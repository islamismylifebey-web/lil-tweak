from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from liltweak.galor_runner_v2 import (
    CanonicalGalorRunnerContract,
    GalorRunnerV2Config,
    GalorRunnerV2Transport,
    HttpGalorWorkGatewayClient,
    command_action_id,
    tool_request_action_id,
)
from liltweak.runner_gate3 import Gate3RunnerConnectionProof
from liltweak.workbench_contract import NetworkMode, StepPhase, ToolKind, ToolRequest

FIXTURE = Path(__file__).parent / "fixtures" / "galor-runner-contract.v2.json"
CONTRACT_SHA256 = "4e65b14a7d1045b25ed7f769a2f5aedbada964bcbf80f1cbfc0c020b722a9c49"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
NOW = datetime(2026, 8, 23, 3, 0, tzinfo=UTC)


def contract() -> CanonicalGalorRunnerContract:
    payload = FIXTURE.read_text()
    assert hashlib.sha256(payload.encode()).hexdigest() == CONTRACT_SHA256
    return CanonicalGalorRunnerContract.from_json(payload, expected_digest=CONTRACT_SHA256)


def config(tmp_path: Path) -> GalorRunnerV2Config:
    return GalorRunnerV2Config(
        gateway_url="https://command.galor.test",
        auth_token="dedicated-service-token",
        contract=contract(),
        expected_contract_digest=CONTRACT_SHA256,
        qualification_evidence_digest="a" * 64,
        authorization_digest="b" * 64,
        workspace_root=tmp_path,
        repository_id="lil-tweak",
        repository_commit=COMMIT,
        authorization_signing_keys={
            "executor-authorization-key": "executor-authorization-secret-value"
        },
        result_signing_keys={"runner-result-key": "runner-result-secret-value"},
    )


def test_loads_exact_canonical_hub_contract_and_rejects_downgrade() -> None:
    loaded = contract()
    assert loaded.owner == "islamismylifebey-web/galor-hub"
    assert loaded.execution_host == "galor-private-cloud-01"
    assert loaded.signing_algorithm == "HMAC-SHA256"
    downgraded = FIXTURE.read_text().replace('"version": "2.0.0"', '"version": "1.0.0"')
    with pytest.raises(ValueError, match="downgrade"):
        CanonicalGalorRunnerContract.from_json(
            downgraded,
            expected_digest=hashlib.sha256(downgraded.encode()).hexdigest(),
        )


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
    assert tool_request_action_id(read) == "runner.readRepositoryFile"
    assert tool_request_action_id(patch) == "runner.applyPatch"
    assert command_action_id("git", ("status", "--short")) == "runner.gitStatus"
    assert command_action_id("pytest", ("-q",)) == "runner.verifyTests"
    assert command_action_id("mypy", ()) == "runner.verifyTypecheck"
    assert command_action_id("ruff", ("check", ".")) == "runner.verifyLint"
    assert command_action_id("uv", ("build", "--offline")) == "runner.verifyBuild"


@pytest.mark.asyncio
async def test_http_client_uses_real_hub_endpoints_and_service_identity() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        gateway = HttpGalorWorkGatewayClient(
            base_url="https://command.galor.test", auth_token="token", client=client
        )
        await gateway.create_approval({"action": "runner.gitStatus"})
        await gateway.submit_job({"project": "lil-tweak"})
        await gateway.poll_job("job-1")
        await gateway.cancel_job("job-1")
    assert [request.url.path for request in calls] == [
        "/api/executor/approvals/action",
        "/api/work-gateway",
        "/api/executor/jobs/job-1",
        "/api/executor/cancel",
    ]
    assert all(request.headers["x-galor-service-id"] == "lil-tweak" for request in calls)


class Gateway:
    def __init__(self) -> None:
        self.approval: dict[str, object] | None = None
        self.job: dict[str, object] | None = None
        self.canceled: list[str] = []

    async def create_approval(self, payload):
        self.approval = dict(payload)
        return {
            "approvalId": "approval-1",
            "tenantId": "owner-tenant",
            "expiresAt": "2026-08-23T03:05:00Z",
        }

    async def submit_job(self, payload):
        self.job = dict(payload)
        return {"accepted": True, "jobId": "job-1"}

    async def poll_job(self, job_id: str):
        return {
            "jobId": job_id,
            "tenantId": "owner-tenant",
            "state": "succeeded",
            "result": {
                "stdout": "clean",
                "stderr": "",
                "receipt": {"commit": COMMIT, "exitCode": 0},
            },
        }

    async def cancel_job(self, job_id: str) -> None:
        self.canceled.append(job_id)


def connected_transport(tmp_path: Path, gateway: Gateway) -> GalorRunnerV2Transport:
    transport = GalorRunnerV2Transport(
        config(tmp_path), gateway=gateway, now=lambda: NOW, poll_interval_seconds=0
    )
    transport._connection._proof = Gate3RunnerConnectionProof(
        runner_id="galor-private-cloud-01",
        tenant_id="owner-tenant",
        handshake_checked_at=NOW,
        handshake_expires_at=NOW + timedelta(seconds=30),
        qualification_digest="1" * 64,
        qualification_key_id="2" * 64,
        qualification_evidence_digest="3" * 64,
        qualification_expires_at=NOW + timedelta(minutes=5),
        authorization_key_id="connection-key",
        authorization_evidence_digest="4" * 64,
        authorization_expires_at=NOW + timedelta(seconds=30),
        heartbeat_job_id="heartbeat-job-1",
        heartbeat_issued_at=NOW,
        heartbeat_expires_at=NOW + timedelta(seconds=60),
        heartbeat_max_age_ms=60_000,
        hub_commit="5" * 40,
        lil_tweak_commit=COMMIT,
        qualification_id="rq_" + "6" * 32,
        qualification_bundle_digest="7" * 64,
        qualification_verified_at=NOW,
        qualification_valid_until=NOW + timedelta(minutes=5),
        qualification_issuer_key_id="8" * 64,
        qualification_runner_key_id="9" * 64,
        authorization_id="rca_" + "a" * 32,
        authorization_sequence=1,
        authorization_revocation_epoch=1,
        authorization_issued_at=NOW,
    )
    return transport


@pytest.mark.asyncio
async def test_transport_runs_exact_approval_gateway_status_flow(tmp_path: Path) -> None:
    gateway = Gateway()
    transport = connected_transport(tmp_path, gateway)
    result = await transport.run(
        executable="git",
        args=("status", "--short"),
        cwd=tmp_path,
        timeout_seconds=30,
        output_byte_limit=1_000_000,
        network=NetworkMode.DENIED,
        cancel_event=asyncio.Event(),
        approval_digest="c" * 64,
    )
    assert result.exit_code == 0 and result.stdout == b"clean"
    assert gateway.approval == {
        "scope": f"repo:lil-tweak@{COMMIT}",
        "action": "runner.gitStatus",
        "effectClass": "READ",
        "input": {},
        "secretNames": [],
        "reason": "Lil' Tweak approved runner.gitStatus for immutable repository scope",
        "ownerApprovalDigest": "c" * 64,
    }
    assert gateway.job is not None
    assert gateway.job["execution"]["approvalId"] == "approval-1"
    assert gateway.job["execution"]["scope"] == f"repo:lil-tweak@{COMMIT}"


@pytest.mark.asyncio
async def test_transport_rejects_missing_approval_and_wrong_receipt_commit(tmp_path: Path) -> None:
    gateway = Gateway()
    transport = connected_transport(tmp_path, gateway)
    with pytest.raises(Exception, match="approval evidence"):
        await transport.run(
            executable="git",
            args=("status",),
            cwd=tmp_path,
            timeout_seconds=30,
            output_byte_limit=100,
            network=NetworkMode.DENIED,
            cancel_event=asyncio.Event(),
        )

    async def wrong_status(job_id: str):
        return {
            "jobId": job_id,
            "tenantId": "owner-tenant",
            "state": "succeeded",
            "result": {"stdout": "", "stderr": "", "receipt": {"commit": "f" * 40, "exitCode": 0}},
        }

    gateway.poll_job = wrong_status  # type: ignore[method-assign]
    with pytest.raises(Exception, match="repository binding"):
        await transport.run(
            executable="git",
            args=("status",),
            cwd=tmp_path,
            timeout_seconds=30,
            output_byte_limit=100,
            network=NetworkMode.DENIED,
            cancel_event=asyncio.Event(),
            approval_digest="d" * 64,
        )
