from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import pytest

from liltweak.runner_evidence import RunnerConnectionAuthorizationVerifier
from liltweak.workbench_executor import ExecutorUnavailableError

NOW = datetime(2026, 8, 30, 12, 5, tzinfo=UTC)
KEY_ID = "executor-authorization-key"
KEY_SECRET = "executor-authorization-secret-value"
RUNNER_ID = "galor-private-cloud-01"
CONTRACT_DIGEST = "4e65b14a7d1045b25ed7f769a2f5aedbada964bcbf80f1cbfc0c020b722a9c49"
QUALIFICATION_ID = "rq_" + ("1" * 32)
EVIDENCE_DIGEST = "7" * 64
BUNDLE_DIGEST = "8" * 64
COMMIT = "0123456789abcdef0123456789abcdef01234567"
NONCE = "handshake_nonce_0123456789abcdef0123456789"
OWNER_DIGEST = "d" * 64


def canonical(value: dict[str, object]) -> str:
    fields = (
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
    )
    return json.dumps([value[field] for field in fields], separators=(",", ":"))


def signed_authorization() -> dict[str, object]:
    issued_at = int(NOW.timestamp() * 1_000)
    value: dict[str, object] = {
        "schemaVersion": "galor-runner-connection-authorization-v1",
        "keyId": KEY_ID,
        "issuedAt": issued_at,
        "expiresAt": issued_at + 30_000,
        "authorizationId": "rca_" + ("a" * 32),
        "sequence": 17,
        "revocationEpoch": 3,
        "serviceId": "lil-tweak",
        "nonce": NONCE,
        "tenantId": "owner-tenant",
        "runnerId": RUNNER_ID,
        "executionHost": RUNNER_ID,
        "contractSha256": CONTRACT_DIGEST,
        "qualificationId": QUALIFICATION_ID,
        "qualificationEvidenceDigest": EVIDENCE_DIGEST,
        "qualificationBundleDigest": BUNDLE_DIGEST,
        "qualificationVerifiedAt": "2026-08-30T12:02:01Z",
        "qualificationExpiresAt": "2026-08-31T11:05:00Z",
        "repositoryId": "lil-tweak",
        "repositoryCommit": COMMIT,
        "action": "runner.reportIdentity",
        "ownerAuthorizationDigest": OWNER_DIGEST,
    }
    value["signature"] = hmac.new(
        KEY_SECRET.encode(), canonical(value).encode(), hashlib.sha256
    ).hexdigest()
    return value


def verifier(**overrides: object) -> RunnerConnectionAuthorizationVerifier:
    values: dict[str, object] = {
        "signing_keys": {KEY_ID: KEY_SECRET},
        "expected_service_id": "lil-tweak",
        "expected_nonce": NONCE,
        "expected_tenant_id": "owner-tenant",
        "expected_runner_id": RUNNER_ID,
        "expected_execution_host": RUNNER_ID,
        "expected_contract_digest": CONTRACT_DIGEST,
        "expected_qualification_id": QUALIFICATION_ID,
        "expected_qualification_evidence_digest": EVIDENCE_DIGEST,
        "expected_qualification_bundle_digest": BUNDLE_DIGEST,
        "expected_repository_id": "lil-tweak",
        "expected_repository_commit": COMMIT,
        "expected_action": "runner.reportIdentity",
        "expected_owner_authorization_digest": OWNER_DIGEST,
        "minimum_sequence": 16,
        "minimum_revocation_epoch": 3,
    }
    values.update(overrides)
    return RunnerConnectionAuthorizationVerifier(**values)  # type: ignore[arg-type]


def test_signed_connection_authorization_is_verified_and_bound() -> None:
    verified = verifier().verify(signed_authorization(), now=NOW)

    assert verified.authorization_id == "rca_" + ("a" * 32)
    assert verified.key_id == KEY_ID
    assert verified.sequence == 17
    assert verified.revocation_epoch == 3
    assert verified.repository_commit == COMMIT
    assert verified.expires_at == NOW + timedelta(seconds=30)


def test_tampered_expired_replayed_or_revoked_authorization_fails_closed() -> None:
    tampered = signed_authorization()
    tampered["repositoryCommit"] = "f" * 40
    with pytest.raises(ExecutorUnavailableError, match=r"signature|binding"):
        verifier().verify(tampered, now=NOW)

    with pytest.raises(ExecutorUnavailableError, match=r"expired|stale"):
        verifier().verify(signed_authorization(), now=NOW + timedelta(minutes=2))
    with pytest.raises(ExecutorUnavailableError, match=r"sequence|replay|rollback"):
        verifier(minimum_sequence=17).verify(signed_authorization(), now=NOW)
    with pytest.raises(ExecutorUnavailableError, match=r"revocation|revoked|stale"):
        verifier(minimum_revocation_epoch=4).verify(signed_authorization(), now=NOW)
