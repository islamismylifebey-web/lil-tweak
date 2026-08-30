from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from liltweak.creator_contract import content_digest
from liltweak.galor_runner_v2 import (
    CanonicalGalorRunnerContract,
    GalorRunnerV2Config,
    GalorRunnerV2Transport,
)
from liltweak.runner_gate3 import _AUTHORIZATION_SIGNATURE_DOMAIN, _canonical_json
from liltweak.runner_qualification import (
    QUALIFICATION_SUITE_DIGEST,
    REQUIRED_QUALIFICATION_CHECKS,
    QualificationObservation,
    RunnerQualificationExpectations,
    RunnerQualificationVerifier,
    SignedRunnerQualificationAttestation,
    build_runner_qualification_challenge,
    encode_runner_signature,
    runner_key_id,
    runner_qualification_signature_message,
)
from liltweak.workbench_executor import ExecutorUnavailableError

FIXTURE = Path(__file__).parent / "fixtures" / "galor-runner-contract.v2.json"
CONTRACT_SHA256 = "4e65b14a7d1045b25ed7f769a2f5aedbada964bcbf80f1cbfc0c020b722a9c49"
HUB_COMMIT = "fae0117c7ea58e47fc0aa03b9d96203e8a119595"
HUB_TREE = "b" * 40
LIL_TWEAK_COMMIT = "0123456789abcdef0123456789abcdef01234567"
RUNNER_ID = "galor-private-cloud-01"
TENANT_ID = "owner-tenant"
HEARTBEAT_KEY_ID = "runner-result-key"
HEARTBEAT_SECRET = "runner-result-" + "secret-value"
AUTH_KEY_ID = "runner-connection-key"
AUTH_SECRET = "runner-" + "connection-secret-value"
OWNER_AUTHORIZATION_DIGEST = "d" * 64
NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


def _raw_public(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _encoded_public(private_key: Ed25519PrivateKey) -> str:
    return base64.urlsafe_b64encode(_raw_public(private_key)).decode().rstrip("=")


def _contract() -> CanonicalGalorRunnerContract:
    return CanonicalGalorRunnerContract.from_json(
        FIXTURE.read_text(),
        expected_digest=CONTRACT_SHA256,
    )


def _qualification_bundle() -> tuple[dict[str, object], str, str, str]:
    issuer_private = Ed25519PrivateKey.generate()
    runner_private = Ed25519PrivateKey.generate()
    issuer_raw = _raw_public(issuer_private)
    runner_raw = _raw_public(runner_private)
    challenge = build_runner_qualification_challenge(
        runner_id=RUNNER_ID,
        key_id=runner_key_id(runner_raw),
        repository_id="github:islamismylifebey-web/galor-hub",
        repository_commit=HUB_COMMIT,
        repository_tree=HUB_TREE,
        image_ref="galor/runner@sha256:" + "3" * 64,
        sandbox_profile_digest="4" * 64,
        runtime_sha256="5" * 64,
        limiter_sha256="6" * 64,
        qualifier_sha256="7" * 64,
        destroyer_sha256="8" * 64,
        issuer_private_key=issuer_private,
        issued_at=NOW - timedelta(minutes=5),
        lifetime_seconds=600,
        qualification_id="rq_" + "1" * 32,
        nonce="2" * 64,
    )
    observations = tuple(
        QualificationObservation(
            check_id=check_id,
            passed=True,
            evidence_digest=hashlib.sha256(check_id.encode()).hexdigest(),
            duration_ms=index,
            failure_code=None,
        )
        for index, check_id in enumerate(REQUIRED_QUALIFICATION_CHECKS)
    )
    common = {
        "qualification_id": challenge.qualification_id,
        "challenge_digest": challenge.challenge_digest,
        "runner_id": challenge.runner_id,
        "key_id": challenge.key_id,
        "nonce": challenge.nonce,
        "suite_digest": QUALIFICATION_SUITE_DIGEST,
        "repository_id": challenge.repository_id,
        "repository_commit": challenge.repository_commit,
        "repository_tree": challenge.repository_tree,
        "image_ref": challenge.image_ref,
        "sandbox_profile_digest": challenge.sandbox_profile_digest,
        "runtime_sha256": challenge.runtime_sha256,
        "limiter_sha256": challenge.limiter_sha256,
        "qualifier_sha256": challenge.qualifier_sha256,
        "destroyer_sha256": challenge.destroyer_sha256,
        "boot_id_digest": "9" * 64,
        "session_id": "runner-session-1",
        "started_at": NOW - timedelta(minutes=4),
        "finished_at": NOW - timedelta(minutes=3),
        "observations": observations,
        "cleanup_verified": True,
        "raw_output_retained": False,
    }
    draft = SignedRunnerQualificationAttestation.model_construct(
        **common,
        evidence_digest="0" * 64,
        signature="A" * 86,
    )
    evidence_digest = content_digest(
        draft.model_dump(
            mode="json",
            exclude={"evidence_digest", "signature"},
        )
    )
    unsigned = SignedRunnerQualificationAttestation.model_construct(
        **common,
        evidence_digest=evidence_digest,
        signature="A" * 86,
    )
    attestation = SignedRunnerQualificationAttestation(
        **common,
        evidence_digest=evidence_digest,
        signature=encode_runner_signature(
            runner_private.sign(runner_qualification_signature_message(unsigned))
        ),
    )
    decision = RunnerQualificationVerifier(
        expectations=RunnerQualificationExpectations(
            runner_id=RUNNER_ID,
            repository_id=challenge.repository_id,
            repository_commit=challenge.repository_commit,
            repository_tree=challenge.repository_tree,
            image_ref=challenge.image_ref,
            sandbox_profile_digest=challenge.sandbox_profile_digest,
            runtime_sha256=challenge.runtime_sha256,
            limiter_sha256=challenge.limiter_sha256,
            qualifier_sha256=challenge.qualifier_sha256,
            destroyer_sha256=challenge.destroyer_sha256,
        ),
        trusted_issuer_public_keys={runner_key_id(issuer_raw): issuer_raw},
        trusted_runner_public_keys={RUNNER_ID: runner_raw},
    ).verify(
        challenge=challenge,
        attestation=attestation,
        now=NOW,
    )
    unsigned_bundle: dict[str, object] = {
        "schema_version": "runner-qualification-bundle-v1",
        "challenge": challenge.model_dump(mode="json"),
        "attestation": attestation.model_dump(mode="json"),
        "decision": decision.model_dump(mode="json"),
        "issuer_public_key": _encoded_public(issuer_private),
        "runner_public_key": _encoded_public(runner_private),
    }
    bundle = {
        **unsigned_bundle,
        "bundle_digest": content_digest(unsigned_bundle),
    }
    return (
        bundle,
        evidence_digest,
        json.dumps(
            {runner_key_id(issuer_raw): _encoded_public(issuer_private)},
            separators=(",", ":"),
        ),
        json.dumps(
            {RUNNER_ID: _encoded_public(runner_private)},
            separators=(",", ":"),
        ),
    )


def _authorization(
    *,
    nonce: str,
    qualification: dict[str, object],
    evidence_digest: str,
    signature: str | None = None,
    authorization_id: str = "rca_" + "a" * 32,
) -> dict[str, object]:
    decision = qualification["decision"]
    assert isinstance(decision, dict)
    payload: dict[str, object] = {
        "schemaVersion": "runner-connection-authorization-v1",
        "keyId": AUTH_KEY_ID,
        "issuedAt": int(NOW.timestamp() * 1_000),
        "expiresAt": int((NOW + timedelta(seconds=30)).timestamp() * 1_000),
        "authorizationId": authorization_id,
        "sequence": 1,
        "revocationEpoch": 1,
        "serviceId": "lil-tweak",
        "nonce": nonce,
        "tenantId": TENANT_ID,
        "runnerId": RUNNER_ID,
        "executionHost": RUNNER_ID,
        "contractSha256": CONTRACT_SHA256,
        "qualificationId": decision["qualification_id"],
        "qualificationEvidenceDigest": evidence_digest,
        "qualificationBundleDigest": qualification["bundle_digest"],
        "qualificationVerifiedAt": decision["verified_at"],
        "qualificationExpiresAt": (NOW + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        "repositoryId": "lil-tweak",
        "repositoryCommit": LIL_TWEAK_COMMIT,
        "action": "runner.reportIdentity",
        "ownerAuthorizationDigest": OWNER_AUTHORIZATION_DIGEST,
    }
    payload["signature"] = (
        signature
        or hmac.new(
            AUTH_SECRET.encode(),
            (_AUTHORIZATION_SIGNATURE_DOMAIN + _canonical_json(payload)).encode(),
            hashlib.sha256,
        ).hexdigest()
    )
    return payload


def _canonical_result(result: dict[str, object]) -> str:
    envelope = result["envelope"]
    receipt = result["receipt"]
    assert isinstance(envelope, dict)
    assert isinstance(receipt, dict)
    values = [
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
    return json.dumps(values, ensure_ascii=False, separators=(",", ":"))


def _heartbeat(*, issued_at: datetime = NOW) -> dict[str, object]:
    job_id = "heartbeat-job-1"
    stdout = (
        f"runner_id={RUNNER_ID}\nutc={issued_at.strftime('%Y-%m-%dT%H:%M:%SZ')}\nnode=v22.13.0\n"
    )
    result: dict[str, object] = {
        "envelope": {
            "keyId": HEARTBEAT_KEY_ID,
            "issuedAt": int(issued_at.timestamp() * 1_000),
            "expiresAt": int((issued_at + timedelta(seconds=60)).timestamp() * 1_000),
            "jobId": job_id,
            "dispatchId": "heartbeat-dispatch-1",
            "runnerId": RUNNER_ID,
            "signature": "",
        },
        "receipt": {
            "jobId": job_id,
            "operation": "approved_script",
            "commit": LIL_TWEAK_COMMIT,
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
    envelope["signature"] = hmac.new(
        HEARTBEAT_SECRET.encode(),
        _canonical_result(result).encode(),
        hashlib.sha256,
    ).hexdigest()
    return result


class Gateway:
    def __init__(self, *, authorization_signature: str | None = None) -> None:
        self.bundle, self.evidence_digest, self.issuer_keys, self.runner_keys = (
            _qualification_bundle()
        )
        self.authorization_signature = authorization_signature
        self.authorization_id = "rca_" + "a" * 32

    async def handshake(self, payload):
        nonce = payload["nonce"]
        return {
            "schemaVersion": "galor-executor-health-handshake-v2",
            "authenticated": True,
            "serviceId": "lil-tweak",
            "hub": "islamismylifebey-web/galor-hub",
            "nonce": nonce,
            "runnerId": RUNNER_ID,
            "tenantId": TENANT_ID,
            "checkedAt": NOW.isoformat().replace("+00:00", "Z"),
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
            "qualification": self.bundle,
            "authorization": _authorization(
                nonce=nonce,
                qualification=self.bundle,
                evidence_digest=self.evidence_digest,
                signature=self.authorization_signature,
                authorization_id=self.authorization_id,
            ),
        }

    async def create_approval(self, payload):
        return {
            "approvalId": "heartbeat-approval-1",
            "tenantId": TENANT_ID,
            "expiresAt": (NOW + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        }

    async def submit_job(self, payload):
        return {"accepted": True, "jobId": "heartbeat-job-1"}

    async def poll_job(self, job_id: str):
        return {
            "jobId": job_id,
            "tenantId": TENANT_ID,
            "state": "succeeded",
            "result": _heartbeat(),
        }

    async def cancel_job(self, job_id: str) -> None:
        raise AssertionError(f"unexpected cancellation: {job_id}")


def _config(tmp_path: Path, gateway: Gateway) -> GalorRunnerV2Config:
    return GalorRunnerV2Config(
        gateway_url="https://command.galor.test",
        auth_token="dedicated-" + "service-token",
        contract=_contract(),
        expected_contract_digest=CONTRACT_SHA256,
        qualification_evidence_digest=gateway.evidence_digest,
        authorization_digest=OWNER_AUTHORIZATION_DIGEST,
        workspace_root=tmp_path,
        repository_id="lil-tweak",
        repository_commit=LIL_TWEAK_COMMIT,
        result_signing_keys={HEARTBEAT_KEY_ID: HEARTBEAT_SECRET},
        gate3_qualification_issuer_public_keys=json.loads(gateway.issuer_keys),
        gate3_qualification_runner_public_keys=json.loads(gateway.runner_keys),
        gate3_connection_authorization_signing_keys={AUTH_KEY_ID: AUTH_SECRET},
        gate3_connection_authorization_minimum_sequence=0,
        gate3_connection_authorization_minimum_revocation_epoch=1,
    )


@pytest.mark.asyncio
async def test_all_four_cryptographic_gates_establish_connection(tmp_path: Path) -> None:
    gateway = Gateway()
    transport = GalorRunnerV2Transport(
        _config(tmp_path, gateway),
        gateway=gateway,
        now=lambda: NOW,
        poll_interval_seconds=0,
    )

    proof = await transport.refresh_connection()

    assert transport.connected is True
    assert proof.runner_id == RUNNER_ID
    assert proof.qualification_evidence_digest == gateway.evidence_digest
    assert proof.authorization_id == gateway.authorization_id
    assert proof.authorization_sequence == 1
    assert proof.authorization_revocation_epoch == 1
    assert proof.lil_tweak_commit == LIL_TWEAK_COMMIT


@pytest.mark.asyncio
async def test_connection_fails_closed_on_authorization_tampering(tmp_path: Path) -> None:
    gateway = Gateway(authorization_signature="0" * 64)
    transport = GalorRunnerV2Transport(
        _config(tmp_path, gateway),
        gateway=gateway,
        now=lambda: NOW,
        poll_interval_seconds=0,
    )

    with pytest.raises(ExecutorUnavailableError, match="authorization signature"):
        await transport.refresh_connection()

    assert transport.connected is False


@pytest.mark.asyncio
async def test_connection_authorization_cannot_be_replayed_after_proof_is_cleared(
    tmp_path: Path,
) -> None:
    gateway = Gateway()
    transport = GalorRunnerV2Transport(
        _config(tmp_path, gateway),
        gateway=gateway,
        now=lambda: NOW,
        poll_interval_seconds=0,
    )
    await transport.refresh_connection()
    transport._connection._proof = None

    with pytest.raises(ExecutorUnavailableError, match="replayed"):
        await transport.refresh_connection()

    assert transport.connected is False


@pytest.mark.asyncio
async def test_timeout_clears_public_connection_status(tmp_path: Path) -> None:
    clock = [NOW]

    class TimeoutGateway(Gateway):
        async def poll_job(self, job_id: str):
            clock[0] += timedelta(seconds=31)
            return {
                "jobId": job_id,
                "tenantId": TENANT_ID,
                "state": "running",
            }

        async def cancel_job(self, job_id: str) -> None:
            assert job_id == "heartbeat-job-1"

    gateway = TimeoutGateway()
    transport = GalorRunnerV2Transport(
        _config(tmp_path, gateway),
        gateway=gateway,
        now=lambda: clock[0],
        poll_interval_seconds=0,
    )

    with pytest.raises(ExecutorUnavailableError, match="timed out"):
        await transport.refresh_connection()

    assert transport.connected is False


@pytest.mark.asyncio
async def test_http_401_clears_public_connection_status(tmp_path: Path) -> None:
    class UnauthorizedGateway(Gateway):
        async def handshake(self, payload):
            request = httpx.Request("POST", "https://command.galor.test/api/executor/handshake")
            response = httpx.Response(401, request=request)
            raise httpx.HTTPStatusError(
                "unauthorized",
                request=request,
                response=response,
            )

    gateway = UnauthorizedGateway()
    transport = GalorRunnerV2Transport(
        _config(tmp_path, gateway),
        gateway=gateway,
        now=lambda: NOW,
        poll_interval_seconds=0,
    )

    with pytest.raises(ExecutorUnavailableError, match="failed closed"):
        await transport.refresh_connection()

    assert transport.connected is False


@pytest.mark.asyncio
async def test_gateway_failure_clears_public_connection_status(tmp_path: Path) -> None:
    class FailedGateway(Gateway):
        async def handshake(self, payload):
            raise RuntimeError("gateway unavailable")

    gateway = FailedGateway()
    transport = GalorRunnerV2Transport(
        _config(tmp_path, gateway),
        gateway=gateway,
        now=lambda: NOW,
        poll_interval_seconds=0,
    )

    with pytest.raises(ExecutorUnavailableError, match="failed closed"):
        await transport.refresh_connection()

    assert transport.connected is False


@pytest.mark.asyncio
async def test_stale_heartbeat_clears_public_connection_status(tmp_path: Path) -> None:
    class StaleHeartbeatGateway(Gateway):
        async def poll_job(self, job_id: str):
            return {
                "jobId": job_id,
                "tenantId": TENANT_ID,
                "state": "succeeded",
                "result": _heartbeat(issued_at=NOW - timedelta(minutes=5)),
            }

    gateway = StaleHeartbeatGateway()
    transport = GalorRunnerV2Transport(
        _config(tmp_path, gateway),
        gateway=gateway,
        now=lambda: NOW,
        poll_interval_seconds=0,
    )

    with pytest.raises(ExecutorUnavailableError, match="stale"):
        await transport.refresh_connection()

    assert transport.connected is False
