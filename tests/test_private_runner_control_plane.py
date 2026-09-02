from __future__ import annotations

import hashlib
import json
from base64 import urlsafe_b64encode
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from liltweak.config import Settings
from liltweak.private_runner_control_plane import (
    HttpPrivateRunnerControlPlaneClient,
    PrivateRunnerAttestationIssuer,
    PrivateRunnerControlPlaneError,
    build_private_runner_control_plane_client,
)
from liltweak.providers.self_hosted.qualification_manifest import (
    QualificationReadOnlyManifest,
    QualificationSource,
)
from liltweak.resource.contracts import (
    ApprovalBinding,
    HealthStatus,
    ImmutableSourceBinding,
    NetworkPolicy,
    QualificationStatus,
    ResourceExecutionContractV2,
    ResourceProfile,
    ResourceProvider,
    ResourceType,
    RiskLevel,
    VerificationLevel,
    WorkloadAuthority,
    WorkloadRequirements,
)
from liltweak.resource.dispatch import DispatchAttestationVerifier, dispatch_issuer_key_id
from liltweak.resource.leases import ExecutionLease
from runner.protocol import canonical_json, sign_runner_request


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        database_path=tmp_path / "liltweak.db",
        dev_api_key=None,
        auth_disabled=True,
        model="gpt-5.6-sol",
        monthly_budget_usd=10,
        job_hard_limit_usd=1,
    )


def test_private_runner_control_plane_is_inert_by_default(tmp_path: Path) -> None:
    configured = _settings(tmp_path)

    assert configured.private_runner_control_plane_enabled is False
    assert configured.private_runner_control_plane_url is None
    assert configured.private_runner_access_client_id is None
    assert configured.private_runner_access_client_secret is None
    assert configured.private_runner_dispatch_signing_key is None


def _enabled_settings(configured: Settings) -> Settings:
    return replace(
        configured,
        private_runner_control_plane_enabled=True,
        private_runner_control_plane_url="https://runner-control.invalid",
        private_runner_control_plane_auth_token="a" * 32,
        private_runner_access_client_id="control-client-id.access",
        private_runner_access_client_secret="s" * 32,
        private_runner_dispatch_key_id="f" * 64,
        private_runner_dispatch_signing_key=b"b" * 32,
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("private_runner_control_plane_url", None, "URL"),
        ("private_runner_control_plane_auth_token", None, "AUTH_TOKEN"),
        ("private_runner_access_client_id", None, "ACCESS_CLIENT_ID"),
        ("private_runner_access_client_secret", None, "ACCESS_CLIENT_SECRET"),
        ("private_runner_dispatch_key_id", None, "KEY_ID"),
        ("private_runner_dispatch_signing_key", None, "SIGNING_KEY"),
    ),
)
def test_private_runner_control_plane_requires_complete_server_held_configuration(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    configured = _enabled_settings(_settings(tmp_path))

    with pytest.raises(ValueError, match=message):
        replace(
            configured,
            **{field: value},
        )


def test_private_runner_control_plane_rejects_non_https_endpoint(tmp_path: Path) -> None:
    configured = _enabled_settings(_settings(tmp_path))

    with pytest.raises(ValueError, match="URL"):
        replace(
            configured,
            private_runner_control_plane_url="http://runner-control.invalid",
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("private_runner_access_client_id", "short", "ACCESS_CLIENT_ID"),
        (
            "private_runner_access_client_secret",
            "unsafe-secret\r\nvalue",
            "ACCESS_CLIENT_SECRET",
        ),
    ),
)
def test_private_runner_control_plane_rejects_unsafe_access_credentials(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    configured = _enabled_settings(_settings(tmp_path))

    with pytest.raises(ValueError, match=message):
        replace(configured, **{field: value})


def test_control_plane_client_factory_refuses_disabled_configuration(tmp_path: Path) -> None:
    with pytest.raises(PrivateRunnerControlPlaneError, match="disabled"):
        build_private_runner_control_plane_client(_settings(tmp_path))


def test_access_credentials_load_from_server_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LILTWEAK_ENVIRONMENT", "test")
    monkeypatch.setenv("LILTWEAK_AUTH_DISABLED", "true")
    monkeypatch.setenv("LILTWEAK_PRIVATE_RUNNER_CONTROL_PLANE_ENABLED", "true")
    monkeypatch.setenv(
        "LILTWEAK_PRIVATE_RUNNER_CONTROL_PLANE_URL",
        "https://runner-control.invalid",
    )
    monkeypatch.setenv("LILTWEAK_PRIVATE_RUNNER_CONTROL_PLANE_AUTH_TOKEN", "a" * 32)
    monkeypatch.setenv(
        "LILTWEAK_PRIVATE_RUNNER_ACCESS_CLIENT_ID",
        "control-client-id.access",
    )
    monkeypatch.setenv("LILTWEAK_PRIVATE_RUNNER_ACCESS_CLIENT_SECRET", "s" * 32)
    monkeypatch.setenv("LILTWEAK_PRIVATE_RUNNER_DISPATCH_KEY_ID", "f" * 64)
    monkeypatch.setenv(
        "LILTWEAK_PRIVATE_RUNNER_DISPATCH_SIGNING_KEY",
        urlsafe_b64encode(b"b" * 32).decode("ascii").rstrip("="),
    )

    configured = Settings.from_env()

    assert configured.private_runner_access_client_id == "control-client-id.access"
    assert configured.private_runner_access_client_secret == "s" * 32


@pytest.mark.parametrize(
    ("access_client_id", "access_client_secret"),
    (
        ("short", "s" * 32),
        ("control-client-id.access", "unsafe-secret\nvalue"),
    ),
)
def test_http_client_rejects_unsafe_access_credentials(
    access_client_id: str,
    access_client_secret: str,
) -> None:
    with pytest.raises(ValueError, match="Access service-token"):
        HttpPrivateRunnerControlPlaneClient(
            base_url="https://control.invalid",
            bearer_token="a" * 32,
            access_client_id=access_client_id,
            access_client_secret=access_client_secret,
        )


def _read_only_manifest() -> QualificationReadOnlyManifest:
    return QualificationReadOnlyManifest(
        source=QualificationSource(commit_sha="f" * 40, tree_sha="e" * 40),
        timeout_seconds=900,
    )


def _signed_offer(private_key: Ed25519PrivateKey, *, commands_digest: str = "c" * 64):
    from liltweak.resource.dispatch import SignedDispatchAttestation

    now = datetime(2026, 9, 1, tzinfo=UTC)
    return SignedDispatchAttestation.issue(
        issuer_private_key=private_key,
        execution_id="execution_001",
        lease_digest="a" * 64,
        contract_digest="b" * 64,
        commands_digest=commands_digest,
        approval_digest="d" * 64,
        policy_digest="e" * 64,
        attempt_nonce=urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("="),
        issued_at_ms=int(now.timestamp() * 1_000),
        expires_at_ms=int((now + timedelta(minutes=2)).timestamp() * 1_000),
    )


@pytest.mark.asyncio
async def test_http_client_offers_only_the_signed_typed_envelope() -> None:
    private_key = Ed25519PrivateKey.generate()
    manifest = _read_only_manifest()
    offer = _signed_offer(private_key, commands_digest=manifest.commands_digest)
    observed: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        observed["url"] = str(request.url)
        observed["authorization"] = request.headers["Authorization"]
        observed["access_client_id"] = request.headers["CF-Access-Client-Id"]
        observed["access_client_secret"] = request.headers["CF-Access-Client-Secret"]
        observed["payload"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "execution_id": offer.attestation.execution_id,
                "runner_id": "galor-tweak-runner-01",
                "status": "OFFERED",
                "lease_digest": offer.attestation.lease_digest,
                "contract_digest": offer.attestation.contract_digest,
                "commands_digest": offer.attestation.commands_digest,
                "expires_at_ms": offer.attestation.expires_at_ms,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        client = HttpPrivateRunnerControlPlaneClient(
            base_url="https://control.invalid/runner",
            bearer_token="a" * 32,
            access_client_id="control-client-id.access",
            access_client_secret="s" * 32,
            client=transport,
        )
        receipt = await client.offer(attestation=offer, manifest=manifest)

    assert observed["url"] == "https://control.invalid/runner/v1/control/offer"
    assert observed["authorization"] == "Bearer " + "a" * 32
    assert observed["access_client_id"] == "control-client-id.access"
    assert observed["access_client_secret"] == "s" * 32
    assert observed["payload"] == {
        "attestation": offer.model_dump(mode="json"),
        "manifest": manifest.model_dump(mode="json"),
    }
    assert receipt.execution_id == offer.attestation.execution_id
    assert receipt.status == "OFFERED"


@pytest.mark.asyncio
async def test_http_client_rejects_manifest_not_bound_to_attested_commands_digest() -> None:
    offer = _signed_offer(Ed25519PrivateKey.generate(), commands_digest="c" * 64)
    manifest = _read_only_manifest()

    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("a digest-mismatched manifest must not be transmitted")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        client = HttpPrivateRunnerControlPlaneClient(
            base_url="https://control.invalid",
            bearer_token="a" * 32,
            access_client_id="control-client-id.access",
            access_client_secret="s" * 32,
            client=transport,
        )
        with pytest.raises(PrivateRunnerControlPlaneError, match="manifest digest"):
            await client.offer(attestation=offer, manifest=manifest)


@pytest.mark.asyncio
async def test_http_client_reads_typed_control_status_without_completion_inference() -> None:
    observed: dict[str, object] = {}
    receipt = {
        "runner_id": "galor-tweak-runner-01",
        "runtime_image": (
            "python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
        ),
        "seccomp_sha256": ("50eeb8b4cb2c33284f09453c8dd64c5895f5e1a2fa6b7a7440dfbac175fe1c23"),
        "apparmor_profile": "liltweak-runner-job",
        "network_denied": True,
        "package_install_allowed": False,
        "production_access_allowed": False,
        "deploy_allowed": False,
        "workspace_cleaned": True,
        "cgroup_cleaned": True,
        "candidate_sha": None,
        "source_commit": "f" * 40,
        "source_tree": "e" * 40,
        "source_mutated": False,
    }
    evidence = {
        "schema_version": "lil-tweak.runner-evidence/v2",
        "outcome": "succeeded",
        "operation_digest": "c" * 64,
        "stdout_digest": "3" * 64,
        "stderr_digest": "4" * 64,
        "receipt_digest": hashlib.sha256(canonical_json(receipt).encode()).hexdigest(),
        "receipt": receipt,
        "exit_code": 0,
        "started_at_ms": 1_788_229_000_000,
        "finished_at_ms": 1_788_229_001_000,
    }
    envelope = sign_runner_request(
        operation="evidence",
        payload={
            "execution_id": "execution_001",
            "attempt_nonce": urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("="),
            "evidence": evidence,
        },
        private_key=Ed25519PrivateKey.from_private_bytes(b"R" * 32),
        issued_at_ms=1_788_229_001_000,
        request_nonce=b"N" * 32,
    )
    evidence_digest = hashlib.sha256(canonical_json(evidence).encode()).hexdigest()

    def handler(request: httpx.Request) -> httpx.Response:
        observed["method"] = request.method
        observed["url"] = str(request.url)
        return httpx.Response(
            200,
            json={
                "execution_id": "execution_001",
                "runner_id": "galor-tweak-runner-01",
                "runner_role": "role-tweak-runner",
                "status": "EVIDENCE_RECORDED",
                "lease_digest": "a" * 64,
                "contract_digest": "b" * 64,
                "commands_digest": "c" * 64,
                "approval_digest": "d" * 64,
                "policy_digest": "e" * 64,
                "expires_at_ms": 1_788_229_200_000,
                "claim_receipt_digest": "1" * 64,
                "evidence_digest": evidence_digest,
                "evidence_outcome": "succeeded",
                "evidence_envelope": envelope,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        client = HttpPrivateRunnerControlPlaneClient(
            base_url="https://control.invalid",
            bearer_token="a" * 32,
            access_client_id="control-client-id.access",
            access_client_secret="s" * 32,
            client=transport,
        )
        status = await client.status("execution_001")

    assert observed == {
        "method": "GET",
        "url": "https://control.invalid/v1/control/executions/execution_001",
    }
    assert status.status == "EVIDENCE_RECORDED"
    assert status.evidence_outcome == "succeeded"
    assert status.evidence_digest == evidence_digest
    assert status.evidence_envelope is not None


@pytest.mark.asyncio
async def test_http_client_posts_only_a_digest_bound_cancel_request() -> None:
    observed: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        observed["method"] = request.method
        observed["url"] = str(request.url)
        observed["payload"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "execution_id": "execution_001",
                "status": "CANCEL_REQUESTED",
                "reason_digest": "9" * 64,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        client = HttpPrivateRunnerControlPlaneClient(
            base_url="https://control.invalid",
            bearer_token="a" * 32,
            access_client_id="control-client-id.access",
            access_client_secret="s" * 32,
            client=transport,
        )
        receipt = await client.cancel(
            "execution_001",
            reason_digest="9" * 64,
        )

    assert observed == {
        "method": "POST",
        "url": "https://control.invalid/v1/control/executions/execution_001/cancel",
        "payload": {"reason_digest": "9" * 64},
    }
    assert receipt.status == "CANCEL_REQUESTED"


@pytest.mark.asyncio
async def test_http_client_rejects_path_injection_before_control_request() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("an unsafe execution identity must not be transmitted")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        client = HttpPrivateRunnerControlPlaneClient(
            base_url="https://control.invalid",
            bearer_token="a" * 32,
            access_client_id="control-client-id.access",
            access_client_secret="s" * 32,
            client=transport,
        )
        with pytest.raises(PrivateRunnerControlPlaneError, match="execution identity"):
            await client.status("../admin")


@pytest.mark.asyncio
async def test_client_factory_wires_access_service_token_credentials(tmp_path: Path) -> None:
    manifest = _read_only_manifest()
    offer = _signed_offer(
        Ed25519PrivateKey.generate(),
        commands_digest=manifest.commands_digest,
    )
    observed: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        observed["authorization"] = request.headers.get("Authorization")
        observed["access_client_id"] = request.headers.get("CF-Access-Client-Id")
        observed["access_client_secret"] = request.headers.get("CF-Access-Client-Secret")
        return httpx.Response(
            200,
            json={
                "execution_id": offer.attestation.execution_id,
                "runner_id": "galor-tweak-runner-01",
                "status": "OFFERED",
                "lease_digest": offer.attestation.lease_digest,
                "contract_digest": offer.attestation.contract_digest,
                "commands_digest": offer.attestation.commands_digest,
                "expires_at_ms": offer.attestation.expires_at_ms,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        client = build_private_runner_control_plane_client(
            _enabled_settings(_settings(tmp_path)),
            client=transport,
        )
        await client.offer(attestation=offer, manifest=manifest)

    assert observed == {
        "authorization": "Bearer " + "a" * 32,
        "access_client_id": "control-client-id.access",
        "access_client_secret": "s" * 32,
    }


@pytest.mark.asyncio
async def test_http_client_rejects_a_malformed_control_plane_receipt() -> None:
    private_key = Ed25519PrivateKey.generate()
    manifest = _read_only_manifest()
    offer = _signed_offer(private_key, commands_digest=manifest.commands_digest)

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "OFFERED"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as transport:
        client = HttpPrivateRunnerControlPlaneClient(
            base_url="https://control.invalid",
            bearer_token="a" * 32,
            access_client_id="control-client-id.access",
            access_client_secret="s" * 32,
            client=transport,
        )
        with pytest.raises(PrivateRunnerControlPlaneError, match="invalid"):
            await client.offer(attestation=offer, manifest=manifest)


def test_issuer_binds_the_existing_contract_and_lease_to_the_server_held_key(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    raw_private_key = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    raw_public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    configured = replace(
        _settings(tmp_path),
        private_runner_control_plane_enabled=True,
        private_runner_control_plane_url="https://control.invalid",
        private_runner_control_plane_auth_token="a" * 32,
        private_runner_access_client_id="control-client-id.access",
        private_runner_access_client_secret="s" * 32,
        private_runner_dispatch_key_id=dispatch_issuer_key_id(raw_public_key),
        private_runner_dispatch_signing_key=raw_private_key,
    )
    now = datetime(2026, 9, 1, tzinfo=UTC)
    requirements = WorkloadRequirements(
        requirement_id="private_runner_requirement",
        job_id="private_runner_job",
        required_cpu=2,
        required_memory_mb=2_048,
        required_disk_mb=4_096,
        shared_memory_required=True,
        network_policy=NetworkPolicy(),
        estimated_duration_seconds=300,
        parallelizable=False,
        desired_parallelism=1,
        verification_level=VerificationLevel.INDEPENDENT,
        authority=WorkloadAuthority(
            requested_by="owner",
            risk_level=RiskLevel.LOW,
            maximum_authorized_cost_microusd=50_000,
            approval_digest="d" * 64,
            policy_digest="e" * 64,
        ),
    )
    profile = ResourceProfile(
        runner_profile_id="galor-tweak-runner-01",
        provider=ResourceProvider.SELF_HOSTED,
        resource_type=ResourceType.SELF_HOSTED_LINUX,
        single_machine_cpu=2,
        single_machine_memory_mb=4_096,
        single_machine_disk_mb=8_192,
        aggregate_parallel_cpu=2,
        aggregate_parallel_memory_mb=4_096,
        parallel_limit=1,
        maximum_duration_seconds=3_600,
        qualification_status=QualificationStatus.QUALIFIED,
        health_status=HealthStatus.HEALTHY,
        last_qualified_at=now,
        last_verified_at=now,
        estimated_cpu_microusd_per_second=1,
        estimated_memory_microusd_per_gb_second=1,
        estimated_storage_microusd_per_gb_second=1,
        included_allowance_microusd=0,
        current_usage_microusd=0,
        risk_surface=RiskLevel.LOW,
        priority=1,
    )
    contract = ResourceExecutionContractV2.issue(
        contract_id="private_runner_contract",
        requirements=requirements,
        profile=profile,
        source=ImmutableSourceBinding(
            repository_id="github:islamismylifebey-web/lil-tweak",
            source_commit="f" * 40,
            source_tree="e" * 40,
            source_archive_digest="a" * 64,
        ),
        approval=ApprovalBinding(
            approval_id="private_runner_approval",
            approval_digest="d" * 64,
            policy_digest="e" * 64,
        ),
        commands_digest="c" * 64,
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=4),
    )
    lease = ExecutionLease.issue(
        lease_id="private_runner_lease",
        execution_id="execution_001",
        contract=contract,
        attempt_nonce="1" * 64,
        authorization_sequence=5,
        revocation_epoch=2,
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=3),
        signing_key=b"l" * 32,
    )

    signed = PrivateRunnerAttestationIssuer(configured, clock=lambda: now).issue(contract, lease)
    verifier = DispatchAttestationVerifier(
        trusted_issuer_public_keys={dispatch_issuer_key_id(raw_public_key): raw_public_key}
    )
    verified = verifier.verify(signed, now=now + timedelta(seconds=1), consume=False)

    assert verified.execution_id == lease.execution_id
    assert verified.lease_digest == lease.lease_digest
    assert verified.contract_digest == contract.contract_digest

    forged_contract = contract.model_copy(update={"contract_digest": "0" * 64})
    with pytest.raises(PrivateRunnerControlPlaneError, match="contract or lease is invalid"):
        PrivateRunnerAttestationIssuer(configured, clock=lambda: now).issue(forged_contract, lease)
