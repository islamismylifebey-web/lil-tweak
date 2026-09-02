from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from liltweak.cloudflare_runner_qualification import CloudflareRunnerQualificationProof
from liltweak.creator_contract import content_digest
from liltweak.providers.contracts import (
    ProviderExecutionStatus,
    VerificationOutcome,
)
from liltweak.providers.self_hosted.galor_tweak_runner import (
    GALOR_TWEAK_RUNNER_ID,
    GALOR_TWEAK_RUNNER_ROLE,
    GalorTweakRunnerConfig,
    GalorTweakRunnerGate3Config,
    GalorTweakRunnerProvider,
    RunnerCancelReceipt,
    RunnerExecutionSummary,
    RunnerOfferReceipt,
)
from liltweak.providers.self_hosted.qualification_manifest import (
    QualificationJobManifest,
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
from liltweak.resource.dispatch import (
    DispatchAttestationVerifier,
    SignedDispatchAttestation,
    dispatch_issuer_key_id,
)
from liltweak.resource.leases import ExecutionLease
from runner.protocol import canonical_json, sign_runner_request

NOW = datetime(2026, 9, 1, tzinfo=UTC)
LEASE_SIGNING_KEY = b"T" * 32
RUNNER_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(b"R" * 32)
RUNNER_PUBLIC_KEY = RUNNER_PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)


class FixtureDispatchClient:
    def __init__(
        self,
        receipt: RunnerOfferReceipt,
        *,
        summary: RunnerExecutionSummary | None = None,
        cancel_receipt: RunnerCancelReceipt | None = None,
    ) -> None:
        self.receipt = receipt
        self.offers: list[SignedDispatchAttestation] = []
        self.manifests: list[QualificationJobManifest] = []
        self.summary = summary
        self.status_calls: list[str] = []
        self.cancel_receipt = cancel_receipt
        self.cancel_calls: list[tuple[str, str]] = []

    async def offer(
        self,
        *,
        attestation: SignedDispatchAttestation,
        manifest: QualificationJobManifest,
    ) -> RunnerOfferReceipt:
        self.offers.append(attestation)
        self.manifests.append(manifest)
        return self.receipt

    async def status(self, execution_id: str) -> RunnerExecutionSummary:
        self.status_calls.append(execution_id)
        if self.summary is None:
            raise RuntimeError("status fixture is unavailable")
        return self.summary

    async def cancel(
        self,
        execution_id: str,
        *,
        reason_digest: str,
    ) -> RunnerCancelReceipt:
        self.cancel_calls.append((execution_id, reason_digest))
        if self.cancel_receipt is None:
            raise RuntimeError("cancel fixture is unavailable")
        return self.cancel_receipt


class FixtureGate3Verifier:
    def __init__(
        self,
        proof: CloudflareRunnerQualificationProof | Exception,
        *,
        contract_digest: str = "a" * 64,
    ) -> None:
        self.proof = proof
        self.contract_digest = contract_digest
        self.refresh_calls = 0

    async def refresh(self) -> CloudflareRunnerQualificationProof:
        self.refresh_calls += 1
        if isinstance(self.proof, Exception):
            raise self.proof
        return self.proof


def _profile() -> ResourceProfile:
    return ResourceProfile(
        runner_profile_id=GALOR_TWEAK_RUNNER_ID,
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
        last_qualified_at=NOW,
        last_verified_at=NOW,
        estimated_cpu_microusd_per_second=1,
        estimated_memory_microusd_per_gb_second=1,
        estimated_storage_microusd_per_gb_second=1,
        included_allowance_microusd=0,
        current_usage_microusd=0,
        risk_surface=RiskLevel.LOW,
        priority=1,
    )


def _manifest() -> QualificationReadOnlyManifest:
    return QualificationReadOnlyManifest(
        source=QualificationSource(commit_sha="f" * 40, tree_sha="e" * 40),
        timeout_seconds=900,
    )


def _contract_and_lease(
    *, commands_digest: str | None = None
) -> tuple[ResourceExecutionContractV2, ExecutionLease]:
    if commands_digest is None:
        commands_digest = _manifest().commands_digest
    requirements = WorkloadRequirements(
        requirement_id="runner_dispatch_requirement",
        job_id="runner_dispatch_job",
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
            approval_digest="a" * 64,
            policy_digest="b" * 64,
        ),
    )
    contract = ResourceExecutionContractV2.issue(
        contract_id="runner_dispatch_contract",
        requirements=requirements,
        profile=_profile(),
        source=ImmutableSourceBinding(
            repository_id="github:islamismylifebey-web/lil-tweak",
            source_commit="f" * 40,
            source_tree="e" * 40,
            source_archive_digest="c" * 64,
        ),
        approval=ApprovalBinding(
            approval_id="runner_dispatch_approval",
            approval_digest="a" * 64,
            policy_digest="b" * 64,
        ),
        commands_digest=commands_digest,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    lease = ExecutionLease.issue(
        lease_id="runner_dispatch_lease",
        execution_id="runner_dispatch_execution",
        contract=contract,
        attempt_nonce="1" * 64,
        authorization_sequence=5,
        revocation_epoch=2,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        signing_key=LEASE_SIGNING_KEY,
    )
    return contract, lease


def _dispatch_nonce(lease: ExecutionLease) -> str:
    return base64.urlsafe_b64encode(bytes.fromhex(lease.attempt_nonce)).decode("ascii").rstrip("=")


def _attestation_factory(
    private_key: Ed25519PrivateKey,
) -> Callable[[ResourceExecutionContractV2, ExecutionLease], SignedDispatchAttestation]:
    def issue(
        contract: ResourceExecutionContractV2, lease: ExecutionLease
    ) -> SignedDispatchAttestation:
        return SignedDispatchAttestation.issue(
            issuer_private_key=private_key,
            execution_id=lease.execution_id,
            lease_digest=lease.lease_digest,
            contract_digest=contract.contract_digest,
            commands_digest=contract.commands_digest,
            approval_digest=lease.approval_digest,
            policy_digest=lease.policy_digest,
            attempt_nonce=_dispatch_nonce(lease),
            issued_at_ms=int(NOW.timestamp() * 1_000),
            expires_at_ms=int((NOW + timedelta(minutes=1)).timestamp() * 1_000),
        )

    return issue


def _attestation_verifier(private_key: Ed25519PrivateKey) -> DispatchAttestationVerifier:
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return DispatchAttestationVerifier(
        trusted_issuer_public_keys={dispatch_issuer_key_id(public_key): public_key}
    )


def _receipt(
    contract: ResourceExecutionContractV2,
    lease: ExecutionLease,
) -> RunnerOfferReceipt:
    return RunnerOfferReceipt(
        runner_id=GALOR_TWEAK_RUNNER_ID,
        execution_id=lease.execution_id,
        lease_digest=lease.lease_digest,
        contract_digest=contract.contract_digest,
        commands_digest=contract.commands_digest,
        status="OFFERED",
        expires_at_ms=int((NOW + timedelta(minutes=1)).timestamp() * 1_000),
    )


def _summary(
    contract: ResourceExecutionContractV2,
    lease: ExecutionLease,
    *,
    status: str = "CLAIMED",
    evidence_outcome: str | None = None,
) -> RunnerExecutionSummary:
    payload: dict[str, object] = {
        "execution_id": lease.execution_id,
        "runner_id": GALOR_TWEAK_RUNNER_ID,
        "runner_role": GALOR_TWEAK_RUNNER_ROLE,
        "status": status,
        "lease_digest": lease.lease_digest,
        "contract_digest": contract.contract_digest,
        "commands_digest": contract.commands_digest,
        "approval_digest": lease.approval_digest,
        "policy_digest": lease.policy_digest,
        "expires_at_ms": int((NOW + timedelta(minutes=1)).timestamp() * 1_000),
        "claim_receipt_digest": "1" * 64,
    }
    if status == "EVIDENCE_RECORDED":
        evidence_envelope, evidence_digest = _signed_runner_evidence(
            contract,
            lease,
            outcome=evidence_outcome or "succeeded",
        )
        payload.update(
            evidence_digest=evidence_digest,
            evidence_outcome=evidence_outcome or "succeeded",
            evidence_envelope=evidence_envelope,
        )
    if status == "CANCEL_REQUESTED":
        payload["cancellation_reason_digest"] = "3" * 64
    return RunnerExecutionSummary.model_validate(payload)


def _signed_runner_evidence(
    contract: ResourceExecutionContractV2,
    lease: ExecutionLease,
    *,
    outcome: str = "succeeded",
) -> tuple[dict[str, object], str]:
    receipt = {
        "runner_id": GALOR_TWEAK_RUNNER_ID,
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
        "source_commit": contract.source.source_commit,
        "source_tree": contract.source.source_tree,
        "source_mutated": False,
    }
    evidence = {
        "schema_version": "lil-tweak.runner-evidence/v2",
        "outcome": outcome,
        "operation_digest": contract.commands_digest,
        "stdout_digest": "6" * 64,
        "stderr_digest": "7" * 64,
        "receipt_digest": hashlib.sha256(canonical_json(receipt).encode()).hexdigest(),
        "receipt": receipt,
        "exit_code": 0 if outcome == "succeeded" else 1,
        "started_at_ms": int(NOW.timestamp() * 1_000),
        "finished_at_ms": int((NOW + timedelta(seconds=1)).timestamp() * 1_000),
    }
    envelope = sign_runner_request(
        operation="evidence",
        payload={
            "execution_id": lease.execution_id,
            "attempt_nonce": _dispatch_nonce(lease),
            "evidence": evidence,
        },
        private_key=RUNNER_PRIVATE_KEY,
        issued_at_ms=int((NOW + timedelta(seconds=1)).timestamp() * 1_000),
        request_nonce=b"N" * 32,
    )
    return envelope, hashlib.sha256(canonical_json(evidence).encode()).hexdigest()


def test_recorded_status_rejects_legacy_digest_only_runner_evidence() -> None:
    contract, lease = _contract_and_lease()
    payload = {
        "execution_id": lease.execution_id,
        "runner_id": GALOR_TWEAK_RUNNER_ID,
        "runner_role": GALOR_TWEAK_RUNNER_ROLE,
        "status": "EVIDENCE_RECORDED",
        "lease_digest": lease.lease_digest,
        "contract_digest": contract.contract_digest,
        "commands_digest": contract.commands_digest,
        "approval_digest": lease.approval_digest,
        "policy_digest": lease.policy_digest,
        "expires_at_ms": int((NOW + timedelta(minutes=1)).timestamp() * 1_000),
        "claim_receipt_digest": "1" * 64,
        "evidence_digest": "2" * 64,
        "evidence_outcome": "succeeded",
    }

    with pytest.raises(ValidationError, match="signed runner evidence"):
        RunnerExecutionSummary.model_validate(payload)


def test_recorded_status_accepts_signed_detailed_runner_evidence() -> None:
    contract, lease = _contract_and_lease()
    envelope, evidence_digest = _signed_runner_evidence(contract, lease)

    summary = RunnerExecutionSummary.model_validate(
        {
            "execution_id": lease.execution_id,
            "runner_id": GALOR_TWEAK_RUNNER_ID,
            "runner_role": GALOR_TWEAK_RUNNER_ROLE,
            "status": "EVIDENCE_RECORDED",
            "lease_digest": lease.lease_digest,
            "contract_digest": contract.contract_digest,
            "commands_digest": contract.commands_digest,
            "approval_digest": lease.approval_digest,
            "policy_digest": lease.policy_digest,
            "expires_at_ms": int((NOW + timedelta(minutes=1)).timestamp() * 1_000),
            "claim_receipt_digest": "1" * 64,
            "evidence_digest": evidence_digest,
            "evidence_outcome": "succeeded",
            "evidence_envelope": envelope,
        }
    )

    assert summary.evidence_envelope is not None
    assert summary.evidence_envelope.request.payload.evidence.receipt.source_mutated is False


def _gate3_proof(
    *,
    runner_id: str = GALOR_TWEAK_RUNNER_ID,
    authorization_sequence: int = 5,
    authorization_revocation_epoch: int = 2,
    authorization_evidence_digest: str = "5" * 64,
) -> CloudflareRunnerQualificationProof:
    values = dict(
        runner_id=runner_id,
        runner_role=GALOR_TWEAK_RUNNER_ROLE,
        repository_id="github:islamismylifebey-web/lil-tweak",
        repository_commit="f" * 40,
        repository_tree="e" * 40,
        runner_key_id="2" * 64,
        profile_spec_digest="e6d24dd720d661535a806e985153ef4801509e67b2a32b31ae9a302ce3298394",
        qualification_id="rq_" + "1" * 32,
        qualification_evidence_digest="3" * 64,
        qualification_verified_at=NOW,
        authorization_id="lra_" + "2" * 32,
        authorization_evidence_digest=authorization_evidence_digest,
        authorization_sequence=authorization_sequence,
        authorization_revocation_epoch=authorization_revocation_epoch,
        host_report_digest="6" * 64,
        local_decision_digest="7" * 64,
        cloudflare_poll_observation_digest="8" * 64,
        cloudflare_poll_observed_at=NOW,
        valid_until=NOW + timedelta(minutes=5),
    )
    draft = CloudflareRunnerQualificationProof.model_construct(**values, proof_digest="0" * 64)
    values["proof_digest"] = content_digest(draft.model_dump(mode="json", exclude={"proof_digest"}))
    if runner_id != GALOR_TWEAK_RUNNER_ID:
        return CloudflareRunnerQualificationProof.model_construct(**values)
    return CloudflareRunnerQualificationProof(**values)


def _gate3_config() -> GalorTweakRunnerGate3Config:
    return GalorTweakRunnerGate3Config(
        contract_digest="a" * 64,
        qualification_evidence_digest="3" * 64,
        authorization_digest="5" * 64,
        minimum_authorization_sequence=5,
        revocation_epoch=2,
    )


def _provider(
    *,
    client: FixtureDispatchClient,
    private_key: Ed25519PrivateKey,
    gate3_proof: CloudflareRunnerQualificationProof | Exception,
    gate3_contract_digest: str = "a" * 64,
    attestation_factory: Callable[
        [ResourceExecutionContractV2, ExecutionLease], SignedDispatchAttestation
    ]
    | None = None,
) -> GalorTweakRunnerProvider:
    return GalorTweakRunnerProvider(
        config=GalorTweakRunnerConfig(),
        client=client,
        gate3_verifier=FixtureGate3Verifier(
            gate3_proof,
            contract_digest=gate3_contract_digest,
        ),
        gate3_config=_gate3_config(),
        attestation_factory=attestation_factory or _attestation_factory(private_key),
        attestation_verifier=_attestation_verifier(private_key),
        runner_public_key=RUNNER_PUBLIC_KEY,
        lease_signing_key=LEASE_SIGNING_KEY,
        clock=lambda: NOW + timedelta(seconds=1),
    )


def test_galor_tweak_runner_config_is_pinned_to_the_approved_runner_identity() -> None:
    config = GalorTweakRunnerConfig()
    gate3 = _gate3_config()

    assert config.runner_id == GALOR_TWEAK_RUNNER_ID == "galor-tweak-runner-01"
    assert config.role == GALOR_TWEAK_RUNNER_ROLE == "role-tweak-runner"
    assert config.runner_profile_id == GALOR_TWEAK_RUNNER_ID
    assert gate3.execution_host == GALOR_TWEAK_RUNNER_ID
    assert gate3.runner_role == GALOR_TWEAK_RUNNER_ROLE
    assert gate3.contract_digest == "a" * 64


@pytest.mark.asyncio
async def test_provider_refuses_to_offer_when_fresh_gate3_evidence_is_missing() -> None:
    contract, lease = _contract_and_lease()
    private_key = Ed25519PrivateKey.generate()
    client = FixtureDispatchClient(_receipt(contract, lease))
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=RuntimeError("Gate 3 evidence unavailable"),
    )

    result = await provider.execute(contract=contract, lease=lease, manifest=_manifest())

    assert result.status is ProviderExecutionStatus.BLOCKED
    assert client.offers == []


@pytest.mark.asyncio
async def test_provider_refuses_a_forged_gate3_proof_for_another_runner() -> None:
    contract, lease = _contract_and_lease()
    private_key = Ed25519PrivateKey.generate()
    client = FixtureDispatchClient(_receipt(contract, lease))
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=_gate3_proof(runner_id="untrusted-runner"),
    )

    result = await provider.execute(contract=contract, lease=lease, manifest=_manifest())

    assert result.status is ProviderExecutionStatus.BLOCKED
    assert "Gate 3" in result.reason
    assert client.offers == []


@pytest.mark.asyncio
async def test_provider_refuses_gate3_evidence_at_the_wrong_revocation_epoch() -> None:
    contract, lease = _contract_and_lease()
    private_key = Ed25519PrivateKey.generate()
    client = FixtureDispatchClient(_receipt(contract, lease))
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=_gate3_proof(authorization_revocation_epoch=1),
    )

    result = await provider.execute(contract=contract, lease=lease, manifest=_manifest())

    assert result.status is ProviderExecutionStatus.BLOCKED
    assert "revocation" in result.reason
    assert client.offers == []


@pytest.mark.asyncio
async def test_provider_refuses_gate3_evidence_with_the_wrong_authorization_digest() -> None:
    contract, lease = _contract_and_lease()
    private_key = Ed25519PrivateKey.generate()
    client = FixtureDispatchClient(_receipt(contract, lease))
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=_gate3_proof(authorization_evidence_digest="f" * 64),
    )

    result = await provider.execute(contract=contract, lease=lease)

    assert result.status is ProviderExecutionStatus.BLOCKED
    assert "authorization evidence" in result.reason
    assert client.offers == []


@pytest.mark.asyncio
async def test_provider_refuses_a_gate3_verifier_pinned_to_a_different_contract() -> None:
    contract, lease = _contract_and_lease()
    private_key = Ed25519PrivateKey.generate()
    client = FixtureDispatchClient(_receipt(contract, lease))
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=_gate3_proof(),
        gate3_contract_digest="f" * 64,
    )

    result = await provider.execute(contract=contract, lease=lease)

    assert result.status is ProviderExecutionStatus.BLOCKED
    assert "contract digest" in result.reason
    assert client.offers == []


@pytest.mark.asyncio
async def test_provider_refuses_an_empty_bounded_action_manifest_digest() -> None:
    contract, lease = _contract_and_lease(commands_digest="0" * 64)
    private_key = Ed25519PrivateKey.generate()
    client = FixtureDispatchClient(_receipt(contract, lease))
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=_gate3_proof(),
    )

    result = await provider.execute(contract=contract, lease=lease)

    assert result.status is ProviderExecutionStatus.BLOCKED
    assert "bounded action manifest" in result.reason
    assert client.offers == []


@pytest.mark.asyncio
async def test_provider_refuses_dispatch_without_a_typed_qualification_manifest() -> None:
    contract, lease = _contract_and_lease()
    private_key = Ed25519PrivateKey.generate()
    client = FixtureDispatchClient(_receipt(contract, lease))
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=_gate3_proof(),
    )

    result = await provider.execute(contract=contract, lease=lease)

    assert result.status is ProviderExecutionStatus.BLOCKED
    assert "typed qualification manifest" in result.reason
    assert client.offers == []


@pytest.mark.asyncio
async def test_provider_refuses_manifest_bound_to_different_source() -> None:
    contract, lease = _contract_and_lease()
    private_key = Ed25519PrivateKey.generate()
    client = FixtureDispatchClient(_receipt(contract, lease))
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=_gate3_proof(),
    )
    wrong_source = QualificationReadOnlyManifest(
        source=QualificationSource(commit_sha="a" * 40, tree_sha="e" * 40),
        timeout_seconds=900,
    )

    result = await provider.execute(
        contract=contract,
        lease=lease,
        manifest=wrong_source,
    )

    assert result.status is ProviderExecutionStatus.BLOCKED
    assert "source binding" in result.reason
    assert client.offers == []


@pytest.mark.asyncio
async def test_provider_refuses_a_tampered_signed_dispatch_attestation() -> None:
    contract, lease = _contract_and_lease()
    private_key = Ed25519PrivateKey.generate()
    original_factory = _attestation_factory(private_key)

    def tampered_factory(
        issued_contract: ResourceExecutionContractV2,
        issued_lease: ExecutionLease,
    ) -> SignedDispatchAttestation:
        signed = original_factory(issued_contract, issued_lease)
        return signed.model_copy(
            update={
                "attestation": signed.attestation.model_copy(update={"commands_digest": "e" * 64})
            }
        )

    client = FixtureDispatchClient(_receipt(contract, lease))
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=_gate3_proof(),
        attestation_factory=tampered_factory,
    )

    result = await provider.execute(contract=contract, lease=lease, manifest=_manifest())

    assert result.status is ProviderExecutionStatus.BLOCKED
    assert "attestation" in result.reason
    assert client.offers == []


@pytest.mark.asyncio
async def test_provider_refuses_a_receipt_with_a_mismatched_runner_identity() -> None:
    contract, lease = _contract_and_lease()
    private_key = Ed25519PrivateKey.generate()
    client = FixtureDispatchClient(
        _receipt(contract, lease).model_copy(update={"runner_id": "other"})
    )
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=_gate3_proof(),
    )

    result = await provider.execute(contract=contract, lease=lease, manifest=_manifest())

    assert result.status is ProviderExecutionStatus.BLOCKED
    assert "receipt" in result.reason


@pytest.mark.asyncio
async def test_provider_returns_a_structured_pending_receipt_without_a_completion_claim() -> None:
    contract, lease = _contract_and_lease()
    private_key = Ed25519PrivateKey.generate()
    receipt = _receipt(contract, lease)
    client = FixtureDispatchClient(receipt)
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=_gate3_proof(),
    )

    result = await provider.execute(contract=contract, lease=lease, manifest=_manifest())

    assert result.status is ProviderExecutionStatus.RUNNING
    assert result.verification_outcome is VerificationOutcome.PENDING
    assert result.operation_id == receipt.operation_id
    assert result.evidence_digest is None
    stored = provider.receipt_for(lease.execution_id)
    assert stored is not None
    assert stored.model_dump(mode="json") == receipt.model_dump(mode="json")
    assert stored.model_dump(mode="json") == {
        "runner_id": GALOR_TWEAK_RUNNER_ID,
        "execution_id": lease.execution_id,
        "lease_digest": lease.lease_digest,
        "contract_digest": contract.contract_digest,
        "commands_digest": contract.commands_digest,
        "status": "OFFERED",
        "expires_at_ms": int((NOW + timedelta(minutes=1)).timestamp() * 1_000),
    }
    assert "completed" not in result.reason.casefold()
    assert client.manifests == [_manifest()]


@pytest.mark.asyncio
async def test_provider_keeps_successful_runner_evidence_pending_independent_verification() -> None:
    contract, lease = _contract_and_lease()
    private_key = Ed25519PrivateKey.generate()
    client = FixtureDispatchClient(_receipt(contract, lease))
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=_gate3_proof(),
    )
    offered = await provider.execute(
        contract=contract,
        lease=lease,
        manifest=_manifest(),
    )
    client.summary = _summary(
        contract,
        lease,
        status="EVIDENCE_RECORDED",
        evidence_outcome="succeeded",
    )

    reconciled = await provider.status(lease.execution_id)

    assert offered.status is ProviderExecutionStatus.RUNNING
    assert reconciled.status is ProviderExecutionStatus.RUNNING
    assert reconciled.verification_outcome is VerificationOutcome.PENDING
    assert reconciled.evidence_digest == client.summary.evidence_digest
    assert provider.evidence_for(lease.execution_id) == client.summary.evidence_envelope
    assert "independent" in reconciled.reason
    assert client.status_calls == [lease.execution_id]


@pytest.mark.asyncio
async def test_provider_collect_reconciles_failed_runner_evidence_fail_closed() -> None:
    contract, lease = _contract_and_lease()
    private_key = Ed25519PrivateKey.generate()
    client = FixtureDispatchClient(_receipt(contract, lease))
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=_gate3_proof(),
    )
    await provider.execute(contract=contract, lease=lease, manifest=_manifest())
    client.summary = _summary(
        contract,
        lease,
        status="EVIDENCE_RECORDED",
        evidence_outcome="failed",
    )

    reconciled = await provider.collect(lease.execution_id)

    assert reconciled.status is ProviderExecutionStatus.FAILED
    assert reconciled.verification_outcome is VerificationOutcome.FAILED
    assert reconciled.evidence_digest == client.summary.evidence_digest
    assert client.status_calls == [lease.execution_id]


@pytest.mark.asyncio
async def test_provider_rejects_forged_detailed_runner_evidence_signature() -> None:
    contract, lease = _contract_and_lease()
    private_key = Ed25519PrivateKey.generate()
    client = FixtureDispatchClient(_receipt(contract, lease))
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=_gate3_proof(),
    )
    await provider.execute(contract=contract, lease=lease, manifest=_manifest())
    summary = _summary(contract, lease, status="EVIDENCE_RECORDED")
    assert summary.evidence_envelope is not None
    forged = summary.evidence_envelope.model_copy(update={"signature": "A" * 86})
    client.summary = summary.model_copy(update={"evidence_envelope": forged})

    reconciled = await provider.collect(lease.execution_id)

    assert reconciled.status is ProviderExecutionStatus.BLOCKED
    assert "signature" in reconciled.reason


@pytest.mark.asyncio
async def test_provider_rejects_remote_status_with_a_changed_contract_binding() -> None:
    contract, lease = _contract_and_lease()
    private_key = Ed25519PrivateKey.generate()
    client = FixtureDispatchClient(_receipt(contract, lease))
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=_gate3_proof(),
    )
    await provider.execute(contract=contract, lease=lease, manifest=_manifest())
    client.summary = _summary(contract, lease).model_copy(update={"contract_digest": "9" * 64})

    reconciled = await provider.status(lease.execution_id)

    assert reconciled.status is ProviderExecutionStatus.BLOCKED
    assert "binding mismatch" in reconciled.reason


@pytest.mark.asyncio
async def test_provider_cancel_requests_termination_without_claiming_it_completed() -> None:
    contract, lease = _contract_and_lease()
    private_key = Ed25519PrivateKey.generate()
    reason_digest = "c95b6148c51e3f0e88f9103214fab2b89ffdc4546b193582ea8b775329b783e2"
    client = FixtureDispatchClient(
        _receipt(contract, lease),
        cancel_receipt=RunnerCancelReceipt(
            execution_id=lease.execution_id,
            reason_digest=reason_digest,
        ),
    )
    provider = _provider(
        client=client,
        private_key=private_key,
        gate3_proof=_gate3_proof(),
    )
    await provider.execute(contract=contract, lease=lease, manifest=_manifest())

    canceled = await provider.cancel(lease.execution_id)

    assert client.cancel_calls == [(lease.execution_id, reason_digest)]
    assert canceled.status is ProviderExecutionStatus.RUNNING
    assert canceled.verification_outcome is VerificationOutcome.PENDING
    assert "requested" in canceled.reason
    assert "completed" not in canceled.reason
