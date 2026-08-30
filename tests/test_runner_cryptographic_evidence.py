from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from liltweak.runner_connection import RunnerConnectionVerifier
from liltweak.workbench_executor import ExecutorUnavailableError

NOW = datetime(2026, 8, 29, 20, 0, tzinfo=UTC)
RUNNER_ID = "galor-private-cloud-01"
TENANT_ID = "owner-tenant"
HUB_COMMIT = "fae0117c7ea58e47fc0aa03b9d96203e8a119595"
CONTRACT_SHA256 = "4e65b14a7d1045b25ed7f769a2f5aedbada964bcbf80f1cbfc0c020b722a9c49"
QUALIFICATION_DIGEST = "c" * 64
OWNER_AUTHORIZATION_DIGEST = "d" * 64
AUTH_KEY_ID = "executor-authorization-key"
AUTH_KEY_SECRET = "executor-authorization-secret-value"
RESULT_KEY_ID = "runner-result-key"
RESULT_KEY_SECRET = "runner-result-secret-value"


def iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def canonical_qualification(evidence: dict[str, object]) -> str:
    return json.dumps(
        [
            evidence["schemaVersion"],
            evidence["keyId"],
            evidence["issuedAt"],
            evidence["expiresAt"],
            evidence["serviceId"],
            evidence["nonce"],
            evidence["tenantId"],
            evidence["runnerId"],
            evidence["executionHost"],
            evidence["contractSha256"],
            evidence["sourceRepository"],
            evidence["sourceCommit"],
            evidence["qualificationDigest"],
            evidence["heartbeatAction"],
            evidence["heartbeatScope"],
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def qualification(
    nonce: str,
    *,
    issued_at: datetime = NOW,
    overrides: dict[str, object] | None = None,
    signature: str | None = None,
) -> dict[str, object]:
    evidence: dict[str, object] = {
        "schemaVersion": "galor-runner-qualification-evidence-v1",
        "keyId": AUTH_KEY_ID,
        "signature": "",
        "issuedAt": int(issued_at.timestamp() * 1_000),
        "expiresAt": int((issued_at + timedelta(seconds=30)).timestamp() * 1_000),
        "serviceId": "lil-tweak",
        "nonce": nonce,
        "tenantId": TENANT_ID,
        "runnerId": RUNNER_ID,
        "executionHost": RUNNER_ID,
        "contractSha256": CONTRACT_SHA256,
        "sourceRepository": "islamismylifebey-web/galor-hub",
        "sourceCommit": HUB_COMMIT,
        "qualificationDigest": QUALIFICATION_DIGEST,
        "heartbeatAction": "runner.reportIdentity",
        "heartbeatScope": f"repo:galor-hub@{HUB_COMMIT}",
    }
    evidence.update(overrides or {})
    evidence["signature"] = signature or hmac.new(
        AUTH_KEY_SECRET.encode(),
        canonical_qualification(evidence).encode(),
        hashlib.sha256,
    ).hexdigest()
    return evidence


def normalize_input(value: dict[str, object]) -> str:
    ordered = {key: value[key] for key in sorted(value)}
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":"))


def canonical_authorization(authorization: dict[str, object]) -> str:
    input_value = authorization["input"]
    assert isinstance(input_value, dict)
    return json.dumps(
        [
            authorization["keyId"],
            authorization["issuedAt"],
            authorization["expiresAt"],
            authorization["jobId"],
            authorization["tenantId"],
            authorization["scope"],
            authorization["action"],
            normalize_input(input_value),
            authorization["secretNames"],
            authorization["requestedBy"],
            authorization["idempotencyKey"],
            authorization["approvalId"] or "",
            authorization["approvalState"],
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def authorization(
    *,
    job_id: str,
    approval_id: str,
    idempotency_key: str,
    issued_at: datetime = NOW,
    overrides: dict[str, object] | None = None,
    signature: str | None = None,
) -> dict[str, object]:
    evidence: dict[str, object] = {
        "keyId": AUTH_KEY_ID,
        "signature": "",
        "issuedAt": int(issued_at.timestamp() * 1_000),
        "expiresAt": iso(issued_at + timedelta(minutes=5)),
        "jobId": job_id,
        "tenantId": TENANT_ID,
        "scope": f"repo:galor-hub@{HUB_COMMIT}",
        "action": "runner.reportIdentity",
        "input": {},
        "secretNames": [],
        "requestedBy": "owner@example.test",
        "idempotencyKey": idempotency_key,
        "approvalId": approval_id,
        "approvalState": "approved",
    }
    evidence.update(overrides or {})
    evidence["signature"] = signature or hmac.new(
        AUTH_KEY_SECRET.encode(),
        canonical_authorization(evidence).encode(),
        hashlib.sha256,
    ).hexdigest()
    return evidence


def canonical_result(result: dict[str, object]) -> str:
    envelope = result["envelope"]
    receipt = result["receipt"]
    assert isinstance(envelope, dict)
    assert isinstance(receipt, dict)
    return json.dumps(
        [
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
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def signed_result(job_id: str) -> dict[str, object]:
    dispatch_id = "heartbeat-dispatch-1"
    stdout = f"runner_id={RUNNER_ID}\nutc={NOW.strftime('%Y-%m-%dT%H:%M:%SZ')}\nnode=v22.13.0\n"
    result: dict[str, object] = {
        "envelope": {
            "keyId": RESULT_KEY_ID,
            "signature": "",
            "issuedAt": int(NOW.timestamp() * 1_000),
            "expiresAt": int((NOW + timedelta(seconds=60)).timestamp() * 1_000),
            "jobId": job_id,
            "dispatchId": dispatch_id,
            "runnerId": RUNNER_ID,
        },
        "receipt": {
            "jobId": job_id,
            "operation": "approved_script",
            "commit": HUB_COMMIT,
            "commandLine": "bash apps/command-center/scripts/runner-report-identity.sh",
            "exitCode": 0,
            "state": "succeeded",
            "startedAt": iso(NOW),
            "finishedAt": iso(NOW + timedelta(seconds=1)),
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
    envelope["signature"] = hmac.new(
        RESULT_KEY_SECRET.encode(),
        canonical_result(result).encode(),
        hashlib.sha256,
    ).hexdigest()
    return result


class Gateway:
    def __init__(
        self,
        *,
        qualification_overrides: dict[str, object] | None = None,
        qualification_signature: str | None = None,
        authorization_overrides: dict[str, object] | None = None,
        authorization_signature: str | None = None,
    ) -> None:
        self.qualification_overrides = qualification_overrides
        self.qualification_signature = qualification_signature
        self.authorization_overrides = authorization_overrides
        self.authorization_signature = authorization_signature
        self.approval_id = "heartbeat-approval-1"
        self.job_id = "heartbeat-job-1"
        self.idempotency_key = ""

    async def handshake(self, payload):
        checked_at = iso(NOW)
        return {
            "schemaVersion": "galor-executor-health-handshake-v1",
            "authenticated": True,
            "serviceId": "lil-tweak",
            "hub": "islamismylifebey-web/galor-hub",
            "nonce": payload["nonce"],
            "runnerId": RUNNER_ID,
            "tenantId": TENANT_ID,
            "checkedAt": checked_at,
            "expiresAt": iso(NOW + timedelta(seconds=30)),
            "gateway": {
                "healthy": True,
                "storeAvailable": True,
                "transportConfigured": True,
                "signingAvailable": True,
            },
            "qualification": qualification(
                payload["nonce"],
                overrides=self.qualification_overrides,
                signature=self.qualification_signature,
            ),
            "heartbeat": {
                "action": "runner.reportIdentity",
                "scope": f"repo:galor-hub@{HUB_COMMIT}",
                "maxAgeMs": 60_000,
            },
        }

    async def create_approval(self, payload):
        assert payload["ownerApprovalDigest"] == OWNER_AUTHORIZATION_DIGEST
        return {
            "approvalId": self.approval_id,
            "tenantId": TENANT_ID,
            "expiresAt": iso(NOW + timedelta(minutes=5)),
        }

    async def submit_job(self, payload):
        self.idempotency_key = payload["idempotencyKey"]
        return {"accepted": True, "jobId": self.job_id}

    async def poll_job(self, job_id: str):
        assert job_id == self.job_id
        return {
            "jobId": job_id,
            "tenantId": TENANT_ID,
            "state": "succeeded",
            "authorization": authorization(
                job_id=job_id,
                approval_id=self.approval_id,
                idempotency_key=self.idempotency_key,
                overrides=self.authorization_overrides,
                signature=self.authorization_signature,
            ),
            "result": signed_result(job_id),
        }

    async def cancel_job(self, job_id: str) -> None:
        raise AssertionError(f"unexpected cancellation: {job_id}")


def verifier(gateway: Gateway) -> RunnerConnectionVerifier:
    return RunnerConnectionVerifier(
        gateway=gateway,
        execution_host=RUNNER_ID,
        contract_digest=CONTRACT_SHA256,
        qualification_evidence_digest=QUALIFICATION_DIGEST,
        authorization_digest=OWNER_AUTHORIZATION_DIGEST,
        authorization_signing_keys={AUTH_KEY_ID: AUTH_KEY_SECRET},
        result_signing_keys={RESULT_KEY_ID: RESULT_KEY_SECRET},
        now=lambda: NOW,
        poll_interval_seconds=0,
    )


@pytest.mark.asyncio
async def test_connection_requires_valid_signed_qualification_and_authorization() -> None:
    proof = await verifier(Gateway()).refresh()

    assert proof.qualification_digest == QUALIFICATION_DIGEST
    assert proof.qualification_key_id == AUTH_KEY_ID
    assert proof.authorization_key_id == AUTH_KEY_ID
    assert len(proof.authorization_evidence_digest) == 64
    assert proof.authorization_expires_at == NOW + timedelta(minutes=5)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("gateway", "message"),
    [
        (Gateway(qualification_signature="0" * 64), "qualification signature"),
        (
            Gateway(qualification_overrides={"qualificationDigest": "e" * 64}),
            "qualification digest",
        ),
        (
            Gateway(
                qualification_overrides={
                    "issuedAt": int((NOW - timedelta(minutes=5)).timestamp() * 1_000),
                    "expiresAt": int((NOW - timedelta(minutes=4)).timestamp() * 1_000),
                }
            ),
            "qualification.*expired|qualification.*stale",
        ),
        (Gateway(authorization_signature="0" * 64), "authorization signature"),
        (
            Gateway(authorization_overrides={"action": "runner.verifyTests"}),
            "authorization binding",
        ),
        (
            Gateway(
                authorization_overrides={
                    "issuedAt": int((NOW - timedelta(minutes=10)).timestamp() * 1_000),
                    "expiresAt": iso(NOW - timedelta(minutes=5)),
                }
            ),
            "authorization.*expired|authorization.*stale",
        ),
    ],
)
async def test_connection_fails_closed_on_invalid_cryptographic_evidence(
    gateway: Gateway,
    message: str,
) -> None:
    connection = verifier(gateway)

    with pytest.raises(ExecutorUnavailableError, match=message):
        await connection.refresh()

    assert connection.connected is False
