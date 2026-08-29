from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from liltweak.galor_runner_v2 import (
    CanonicalGalorRunnerContract,
    GalorRunnerV2Config,
    GalorRunnerV2Transport,
)
from liltweak.workbench_executor import ExecutorUnavailableError

FIXTURE = Path(__file__).parent / "fixtures" / "galor-runner-contract.v2.json"
CONTRACT_SHA256 = "4e65b14a7d1045b25ed7f769a2f5aedbada964bcbf80f1cbfc0c020b722a9c49"
HUB_COMMIT = "fae0117c7ea58e47fc0aa03b9d96203e8a119595"
LIL_TWEAK_COMMIT = "0123456789abcdef0123456789abcdef01234567"
RUNNER_ID = "galor-private-cloud-01"
TENANT_ID = "owner-tenant"
KEY_ID = "runner-result-key"
KEY_SECRET = "runner-result-secret-value"
NOW = datetime(2026, 8, 29, 20, 0, tzinfo=UTC)


def contract() -> CanonicalGalorRunnerContract:
    return CanonicalGalorRunnerContract.from_json(
        FIXTURE.read_text(),
        expected_digest=CONTRACT_SHA256,
    )


def canonical_result(result: dict[str, object]) -> str:
    envelope = result["envelope"]
    receipt = result["receipt"]
    assert isinstance(envelope, dict)
    assert isinstance(receipt, dict)
    payload = [
        envelope["keyId"],
        envelope["issuedAt"],
        envelope["expiresAt"],
        envelope["jobId"],
        envelope["dispatchId"],
        envelope["runnerId"],
        result["state"],
        result["failureReason"] or "",
        result["stdout"],
        result["stderr"],
        receipt["jobId"],
        receipt["operation"],
        receipt["commit"],
        receipt["commandLine"],
        receipt["exitCode"],
        receipt["state"],
        receipt["startedAt"],
        receipt["finishedAt"],
        receipt["durationMs"],
        receipt["cpuMs"],
        receipt["peakMemoryBytes"],
        receipt["outputBytes"],
        receipt["outputTruncated"],
        receipt["artifacts"],
        receipt["workspaceFingerprint"],
        receipt["digest"],
    ]
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def signed_heartbeat(*, issued_at: datetime = NOW, signature: str | None = None) -> dict[str, object]:
    job_id = "heartbeat-job-1"
    dispatch_id = "heartbeat-dispatch-1"
    stdout = (
        f"runner_id={RUNNER_ID}\n"
        f"utc={issued_at.strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        "node=v22.13.0\n"
    )
    result: dict[str, object] = {
        "envelope": {
            "keyId": KEY_ID,
            "issuedAt": int(issued_at.timestamp() * 1000),
            "expiresAt": int((issued_at + timedelta(seconds=60)).timestamp() * 1000),
            "jobId": job_id,
            "dispatchId": dispatch_id,
            "runnerId": RUNNER_ID,
            "signature": "",
        },
        "receipt": {
            "jobId": job_id,
            "operation": "approved_script",
            "commit": HUB_COMMIT,
            "commandLine": "bash apps/command-center/scripts/runner-report-identity.sh",
            "exitCode": 0,
            "state": "succeeded",
            "startedAt": issued_at.isoformat().replace("+00:00", "Z"),
            "finishedAt": (issued_at + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
            "durationMs": 1_000,
            "cpuMs": 50,
            "peakMemoryBytes": 16_384,
            "outputBytes": len(stdout),
            "outputTruncated": False,
            "artifacts": [],
            "workspaceFingerprint": "a" * 64,
            "digest": "b" * 64,
        },
        "stdout": stdout,
        "stderr": "",
        "failureReason": None,
        "state": "succeeded",
    }
    envelope = result["envelope"]
    assert isinstance(envelope, dict)
    envelope["signature"] = signature or hmac.new(
        KEY_SECRET.encode(),
        canonical_result(result).encode(),
        hashlib.sha256,
    ).hexdigest()
    return result


class Gateway:
    def __init__(
        self,
        *,
        heartbeat: dict[str, object] | None = None,
        handshake_overrides: dict[str, object] | None = None,
    ) -> None:
        self.heartbeat = heartbeat or signed_heartbeat()
        self.handshake_overrides = handshake_overrides or {}
        self.handshakes: list[dict[str, object]] = []
        self.approvals: list[dict[str, object]] = []
        self.jobs: list[dict[str, object]] = []

    async def handshake(self, payload):
        self.handshakes.append(dict(payload))
        checked_at = NOW.isoformat().replace("+00:00", "Z")
        response = {
            "schemaVersion": "galor-executor-health-handshake-v1",
            "authenticated": True,
            "serviceId": "lil-tweak",
            "hub": "islamismylifebey-web/galor-hub",
            "nonce": payload["nonce"],
            "runnerId": RUNNER_ID,
            "tenantId": TENANT_ID,
            "checkedAt": checked_at,
            "expiresAt": (NOW + timedelta(seconds=30)).isoformat().replace("+00:00", "Z"),
            "gateway": {
                "healthy": True,
                "storeAvailable": True,
                "transportConfigured": True,
                "signingAvailable": True,
            },
            "heartbeat": {
                "action": "runner.reportIdentity",
                "scope": f"repo:galor-hub@{HUB_COMMIT}",
                "maxAgeMs": 60_000,
            },
        }
        response.update(self.handshake_overrides)
        return response

    async def create_approval(self, payload):
        self.approvals.append(dict(payload))
        return {
            "approvalId": "heartbeat-approval-1",
            "tenantId": TENANT_ID,
            "expiresAt": (NOW + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        }

    async def submit_job(self, payload):
        self.jobs.append(dict(payload))
        return {"accepted": True, "jobId": "heartbeat-job-1"}

    async def poll_job(self, job_id: str):
        return {
            "jobId": job_id,
            "tenantId": TENANT_ID,
            "state": "succeeded",
            "result": self.heartbeat,
        }

    async def cancel_job(self, job_id: str) -> None:
        raise AssertionError(f"unexpected cancellation: {job_id}")


def config(tmp_path: Path) -> GalorRunnerV2Config:
    return GalorRunnerV2Config(
        gateway_url="https://command.galor.test",
        auth_token="dedicated-service-token",
        contract=contract(),
        expected_contract_digest=CONTRACT_SHA256,
        qualification_evidence_digest="c" * 64,
        authorization_digest="d" * 64,
        workspace_root=tmp_path,
        repository_id="lil-tweak",
        repository_commit=LIL_TWEAK_COMMIT,
        result_signing_keys={KEY_ID: KEY_SECRET},
    )


@pytest.mark.asyncio
async def test_authenticated_handshake_and_recent_signed_heartbeat_establish_connection(
    tmp_path: Path,
) -> None:
    gateway = Gateway()
    transport = GalorRunnerV2Transport(
        config(tmp_path),
        gateway=gateway,
        now=lambda: NOW,
        poll_interval_seconds=0,
    )

    proof = await transport.refresh_connection()

    assert proof.runner_id == RUNNER_ID
    assert proof.tenant_id == TENANT_ID
    assert proof.heartbeat_job_id == "heartbeat-job-1"
    assert proof.heartbeat_issued_at == NOW
    assert transport.connected is True
    assert len(gateway.handshakes) == 1
    assert gateway.approvals[0]["action"] == "runner.reportIdentity"
    assert gateway.approvals[0]["scope"] == f"repo:galor-hub@{HUB_COMMIT}"
    assert gateway.jobs[0]["execution"]["action"] == "runner.reportIdentity"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("gateway", "message"),
    [
        (Gateway(handshake_overrides={"nonce": "wrong-nonce-value-0123456789012345"}), "nonce"),
        (Gateway(handshake_overrides={"runnerId": "wrong-runner"}), "runner identity"),
        (
            Gateway(heartbeat=signed_heartbeat(signature="0" * 64)),
            "signature",
        ),
        (
            Gateway(heartbeat=signed_heartbeat(issued_at=NOW - timedelta(minutes=5))),
            "stale",
        ),
    ],
)
async def test_connection_fails_closed_on_invalid_handshake_or_heartbeat(
    tmp_path: Path,
    gateway: Gateway,
    message: str,
) -> None:
    transport = GalorRunnerV2Transport(
        config(tmp_path),
        gateway=gateway,
        now=lambda: NOW,
        poll_interval_seconds=0,
    )

    with pytest.raises(ExecutorUnavailableError, match=message):
        await transport.refresh_connection()

    assert transport.connected is False
