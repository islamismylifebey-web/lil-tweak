from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, runtime_checkable

from pydantic import Field, StrictInt, StrictStr, ValidationError

from ...creator_contract import CreatorSchema
from ...resource.contracts import (
    DeploymentPurpose,
    HealthStatus,
    ResourceExecutionContractV2,
    ResourceProfile,
    ResourceProvider,
    ResourceType,
    WorkloadRequirements,
)
from ...resource.dispatch import (
    DispatchAttestation,
    DispatchAttestationError,
    DispatchAttestationVerifier,
    SignedDispatchAttestation,
)
from ...resource.estimator import ResourceCostEstimate, ResourceEstimator
from ...resource.leases import ExecutionLease, ExecutionLeaseError, ExecutionLeaseRegistry
from ...runner_gate3 import Gate3RunnerConnectionProof
from ..contracts import (
    ProviderCapabilities,
    ProviderExecutionStatus,
    ProviderHealth,
    ProviderOperationResult,
    ProviderQualification,
    VerificationOutcome,
)

GALOR_TWEAK_RUNNER_ID = "galor-tweak-runner-01"
GALOR_TWEAK_RUNNER_ROLE = "role-tweak-runner"
GALOR_TWEAK_REPOSITORY_ID = "github:islamismylifebey-web/lil-tweak"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SAFE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"


class GalorTweakRunnerConfig(CreatorSchema):
    """Identity pins for the one approved Lil' Tweak private runner."""

    runner_id: Literal["galor-tweak-runner-01"] = "galor-tweak-runner-01"
    role: Literal["role-tweak-runner"] = "role-tweak-runner"
    runner_profile_id: Literal["galor-tweak-runner-01"] = "galor-tweak-runner-01"
    repository_id: Literal["github:islamismylifebey-web/lil-tweak"] = (
        "github:islamismylifebey-web/lil-tweak"
    )


class GalorTweakRunnerGate3Config(CreatorSchema):
    """Pins the separate Gate 3 verifier configuration for the approved runner."""

    execution_host: Literal["galor-tweak-runner-01"] = "galor-tweak-runner-01"
    runner_role: Literal["role-tweak-runner"] = "role-tweak-runner"
    contract_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    qualification_evidence_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    authorization_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    minimum_authorization_sequence: StrictInt = Field(ge=0)
    revocation_epoch: StrictInt = Field(ge=1)


class RunnerOfferReceipt(CreatorSchema):
    """The exact minimal response to an outbound Worker offer request."""

    runner_id: Literal["galor-tweak-runner-01"] = "galor-tweak-runner-01"
    execution_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    lease_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    contract_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    commands_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    status: Literal["OFFERED"] = "OFFERED"
    expires_at_ms: StrictInt = Field(ge=0)

    @property
    def operation_id(self) -> str:
        return f"runner-offer:{self.execution_id}:{self.lease_digest[:16]}"


@runtime_checkable
class SelfHostedDispatchClient(Protocol):
    """The only private-runner control-plane operations this adapter may invoke."""

    async def offer(self, *, attestation: SignedDispatchAttestation) -> RunnerOfferReceipt: ...


@runtime_checkable
class Gate3ProofRefresher(Protocol):
    """A Gate 3 verifier, not a mutable health or qualification flag."""

    @property
    def contract_digest(self) -> str: ...

    async def refresh(self) -> Gate3RunnerConnectionProof: ...


DispatchAttestationFactory = Callable[
    [ResourceExecutionContractV2, ExecutionLease], SignedDispatchAttestation
]


@dataclass(frozen=True)
class _DispatchRecord:
    contract: ResourceExecutionContractV2
    lease: ExecutionLease
    attestation: DispatchAttestation
    receipt: RunnerOfferReceipt


class GalorTweakRunnerProvider:
    """Fail-closed adapter for exactly one signed, private GALOR runner.

    It offers a typed, signed attestation to an injected control-plane client.  It
    never forwards commands, shell text, credentials, or a completion claim.
    """

    def __init__(
        self,
        *,
        config: GalorTweakRunnerConfig,
        client: SelfHostedDispatchClient,
        gate3_verifier: Gate3ProofRefresher,
        gate3_config: GalorTweakRunnerGate3Config,
        attestation_factory: DispatchAttestationFactory,
        attestation_verifier: DispatchAttestationVerifier,
        lease_signing_key: bytes,
        clock: Callable[[], datetime],
    ) -> None:
        if not isinstance(lease_signing_key, bytes) or len(lease_signing_key) != 32:
            raise ValueError("self-hosted provider lease signing key must contain exactly 32 bytes")
        if (
            gate3_config.execution_host != config.runner_id
            or gate3_config.runner_role != config.role
        ):
            raise ValueError("self-hosted provider Gate 3 identity pins do not match the runner")
        self._config = config
        self._client = client
        self._gate3_verifier = gate3_verifier
        self._gate3_config = gate3_config
        self._attestation_factory = attestation_factory
        self._attestation_verifier = attestation_verifier
        self._lease_signing_key = lease_signing_key
        self._clock = clock
        self._leases = ExecutionLeaseRegistry()
        self._records: dict[str, _DispatchRecord] = {}
        self._gate3_proof: Gate3RunnerConnectionProof | None = None

    def qualify(self) -> ProviderQualification:
        blocker = self._cached_gate3_proof_blocker()
        return ProviderQualification(
            provider=ResourceProvider.SELF_HOSTED,
            qualified=blocker is None,
            blockers=() if blocker is None else (blocker,),
        )

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider=ResourceProvider.SELF_HOSTED,
            resource_types=(ResourceType.SELF_HOSTED_LINUX,),
            builder=True,
            independent_verifier=False,
            preview_only=False,
            production_deployment=False,
        )

    def health(self) -> ProviderHealth:
        proof = self._gate3_proof
        if proof is None or self._cached_gate3_proof_blocker() is not None:
            return ProviderHealth(
                provider=ResourceProvider.SELF_HOSTED,
                status=HealthStatus.UNKNOWN,
                connected=False,
                active=False,
            )
        return ProviderHealth(
            provider=ResourceProvider.SELF_HOSTED,
            status=HealthStatus.HEALTHY,
            connected=True,
            active=True,
            last_verified_at=proof.handshake_checked_at,
        )

    @staticmethod
    def estimate(
        requirements: WorkloadRequirements,
        profile: ResourceProfile,
    ) -> ResourceCostEstimate:
        return ResourceEstimator().estimate(requirements, profile)

    async def provision(
        self,
        *,
        contract: ResourceExecutionContractV2,
        lease: ExecutionLease,
    ) -> ProviderOperationResult:
        normalized = self._normalize(contract, lease)
        if isinstance(normalized, str):
            return self._result(lease.execution_id, ProviderExecutionStatus.BLOCKED, normalized)
        validated_contract, validated_lease = normalized
        gate3_blocker = await self._refresh_gate3_proof(validated_contract, validated_lease)
        if gate3_blocker is not None:
            return self._result(
                validated_lease.execution_id,
                ProviderExecutionStatus.BLOCKED,
                gate3_blocker,
            )
        blocker = self._readiness_blocker(validated_contract, validated_lease)
        if blocker is not None:
            return self._result(
                validated_lease.execution_id, ProviderExecutionStatus.BLOCKED, blocker
            )
        return self._result(
            validated_lease.execution_id,
            ProviderExecutionStatus.PROVISIONED,
            "private runner dispatch is eligible for a signed offer",
        )

    async def execute(
        self,
        *,
        contract: ResourceExecutionContractV2,
        lease: ExecutionLease,
    ) -> ProviderOperationResult:
        normalized = self._normalize(contract, lease)
        if isinstance(normalized, str):
            return self._result(lease.execution_id, ProviderExecutionStatus.BLOCKED, normalized)
        validated_contract, validated_lease = normalized
        gate3_blocker = await self._refresh_gate3_proof(validated_contract, validated_lease)
        if gate3_blocker is not None:
            return self._result(
                validated_lease.execution_id,
                ProviderExecutionStatus.BLOCKED,
                gate3_blocker,
            )
        blocker = self._readiness_blocker(validated_contract, validated_lease)
        if blocker is not None:
            return self._result(
                validated_lease.execution_id, ProviderExecutionStatus.BLOCKED, blocker
            )
        signed = self._issue_and_verify_attestation(validated_contract, validated_lease)
        if isinstance(signed, str):
            return self._result(
                validated_lease.execution_id, ProviderExecutionStatus.BLOCKED, signed
            )
        signed_attestation, attestation = signed
        try:
            self._leases.consume(
                validated_lease,
                contract=validated_contract,
                signing_key=self._lease_signing_key,
                now=self._clock(),
                minimum_authorization_sequence=(self._gate3_config.minimum_authorization_sequence),
                revocation_epoch=self._gate3_config.revocation_epoch,
            )
        except ExecutionLeaseError:
            return self._result(
                validated_lease.execution_id,
                ProviderExecutionStatus.BLOCKED,
                "execution lease was rejected",
            )
        try:
            response = await self._client.offer(attestation=signed_attestation)
        except Exception:
            return self._result(
                validated_lease.execution_id,
                ProviderExecutionStatus.BLOCKED,
                "private runner control plane did not accept the signed offer",
            )
        receipt = self._validated_receipt(response, attestation)
        if isinstance(receipt, str):
            return self._result(
                validated_lease.execution_id, ProviderExecutionStatus.BLOCKED, receipt
            )
        self._records[validated_lease.execution_id] = _DispatchRecord(
            contract=validated_contract,
            lease=validated_lease,
            attestation=attestation,
            receipt=receipt,
        )
        return self._receipt_result(receipt)

    async def status(self, execution_id: str) -> ProviderOperationResult:
        record = self._records.get(execution_id)
        if record is None:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "private runner dispatch is unknown",
            )
        return self._receipt_result(record.receipt)

    async def collect(self, execution_id: str) -> ProviderOperationResult:
        record = self._records.get(execution_id)
        if record is None:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "private runner dispatch is unknown",
            )
        return self._receipt_result(record.receipt)

    async def cancel(self, execution_id: str) -> ProviderOperationResult:
        return self._result(
            execution_id,
            ProviderExecutionStatus.BLOCKED,
            "private runner cancellation requires a separate signed control-plane receipt",
        )

    async def destroy(self, execution_id: str) -> ProviderOperationResult:
        record = self._records.pop(execution_id, None)
        if record is None:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "private runner dispatch is unknown",
            )
        return self._result(
            execution_id,
            ProviderExecutionStatus.DESTROYED,
            "private runner adapter released local dispatch state",
            operation_id=record.receipt.operation_id,
        )

    def receipt_for(self, execution_id: str) -> RunnerOfferReceipt | None:
        record = self._records.get(execution_id)
        return None if record is None else record.receipt

    def _normalize(
        self,
        contract: ResourceExecutionContractV2,
        lease: ExecutionLease,
    ) -> tuple[ResourceExecutionContractV2, ExecutionLease] | str:
        try:
            validated_contract = ResourceExecutionContractV2.model_validate(
                contract.model_dump(mode="json")
            )
            validated_lease = ExecutionLease.model_validate(lease.model_dump(mode="json"))
        except (AttributeError, ValidationError):
            return "resource contract or execution lease is invalid"
        return validated_contract, validated_lease

    async def _refresh_gate3_proof(
        self,
        contract: ResourceExecutionContractV2,
        lease: ExecutionLease,
    ) -> str | None:
        try:
            verifier_contract_digest = self._gate3_verifier.contract_digest
        except (AttributeError, TypeError):
            return "Gate 3 verifier contract digest is unavailable"
        if verifier_contract_digest != self._gate3_config.contract_digest:
            return "Gate 3 verifier contract digest does not match the private runner pin"
        try:
            proof = await self._gate3_verifier.refresh()
        except Exception:
            return (
                "fresh cryptographically verified Gate 3 runner connection evidence is unavailable"
            )
        if not isinstance(proof, Gate3RunnerConnectionProof):
            return "Gate 3 verifier did not return a typed runner connection proof"
        blocker = self._gate3_proof_blocker(proof, contract=contract, lease=lease)
        if blocker is not None:
            return blocker
        self._gate3_proof = proof
        return None

    def _cached_gate3_proof_blocker(self) -> str | None:
        proof = self._gate3_proof
        if proof is None:
            return "fresh cryptographically verified Gate 3 runner connection evidence is required"
        return self._gate3_proof_blocker(proof, contract=None, lease=None)

    def _gate3_proof_blocker(
        self,
        proof: Gate3RunnerConnectionProof,
        *,
        contract: ResourceExecutionContractV2 | None,
        lease: ExecutionLease | None,
    ) -> str | None:
        if proof.runner_id != self._config.runner_id:
            return "Gate 3 runner connection proof identity does not match the approved runner"
        try:
            fresh = proof.is_fresh(self._clock())
        except (AttributeError, TypeError, ValueError):
            return "Gate 3 runner connection proof freshness is invalid"
        if not fresh:
            return "Gate 3 runner connection proof is stale"
        sequence = proof.authorization_sequence
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            return "Gate 3 runner connection proof authorization sequence is invalid"
        required_sequence = self._gate3_config.minimum_authorization_sequence
        if lease is not None:
            required_sequence = max(required_sequence, lease.authorization_sequence)
        if sequence < required_sequence:
            return "Gate 3 runner connection proof authorization sequence is obsolete"
        epoch = proof.authorization_revocation_epoch
        if not isinstance(epoch, int) or isinstance(epoch, bool):
            return "Gate 3 runner connection proof authorization revocation epoch is invalid"
        if epoch != self._gate3_config.revocation_epoch or (
            lease is not None and epoch != lease.revocation_epoch
        ):
            return "Gate 3 runner connection proof authorization revocation epoch does not match"
        if proof.qualification_evidence_digest != self._gate3_config.qualification_evidence_digest:
            return "Gate 3 runner connection proof qualification evidence does not match"
        if proof.authorization_evidence_digest != self._gate3_config.authorization_digest:
            return "Gate 3 runner connection proof authorization evidence does not match"
        if contract is not None and proof.lil_tweak_commit != contract.source.source_commit:
            return "Gate 3 runner connection proof is not pinned to the immutable source commit"
        return None

    def _readiness_blocker(
        self,
        contract: ResourceExecutionContractV2,
        lease: ExecutionLease,
    ) -> str | None:
        qualification = self.qualify()
        if not qualification.qualified:
            return "; ".join(qualification.blockers)
        if contract.provider is not ResourceProvider.SELF_HOSTED:
            return "resource contract provider is not self-hosted"
        if contract.provider_resource_type is not ResourceType.SELF_HOSTED_LINUX:
            return "resource contract is not a self-hosted Linux resource"
        if contract.runner_profile_id != self._config.runner_profile_id:
            return "resource contract runner profile is not the approved private runner"
        if contract.source.repository_id != self._config.repository_id:
            return "resource contract repository is not the approved Lil' Tweak repository"
        if contract.network_policy.network_required:
            return "private runner dispatch forbids network access"
        if contract.secrets_required or lease.secret_scope:
            return "private runner dispatch forbids secret scope"
        if contract.browser_required or contract.docker_required:
            return "private runner dispatch forbids browser and Docker access"
        if contract.production_access_required:
            return "private runner dispatch forbids production access"
        if (
            contract.deployment_authorized
            or contract.deployment_purpose is not DeploymentPurpose.NONE
        ):
            return "private runner dispatch forbids deployment"
        if contract.commands_digest == "0" * 64:
            return "private runner dispatch requires a nonempty bounded action manifest"
        if lease.commands_digest != contract.commands_digest:
            return "execution lease commands digest does not match the bounded action manifest"
        if lease.execution_id in self._records:
            return "private runner dispatch already exists"
        return None

    def _issue_and_verify_attestation(
        self,
        contract: ResourceExecutionContractV2,
        lease: ExecutionLease,
    ) -> tuple[SignedDispatchAttestation, DispatchAttestation] | str:
        try:
            signed = self._attestation_factory(contract, lease)
            normalized = SignedDispatchAttestation.model_validate(signed.model_dump(mode="json"))
            attestation = self._attestation_verifier.verify(
                normalized,
                now=self._clock(),
                consume=False,
            )
        except (AttributeError, DispatchAttestationError, ValidationError, ValueError):
            return "signed private runner dispatch attestation was rejected"
        expected_nonce = (
            base64.urlsafe_b64encode(bytes.fromhex(lease.attempt_nonce)).decode("ascii").rstrip("=")
        )
        bindings = (
            (attestation.runner_id, self._config.runner_id),
            (attestation.runner_role, self._config.role),
            (attestation.execution_id, lease.execution_id),
            (attestation.lease_digest, lease.lease_digest),
            (attestation.contract_digest, contract.contract_digest),
            (attestation.commands_digest, contract.commands_digest),
            (attestation.approval_digest, lease.approval_digest),
            (attestation.policy_digest, lease.policy_digest),
            (attestation.attempt_nonce, expected_nonce),
        )
        if any(observed != expected for observed, expected in bindings):
            return "signed private runner dispatch attestation binding mismatch"
        if attestation.commands_digest == "0" * 64:
            return "signed private runner dispatch attestation lacks a bounded action manifest"
        return normalized, attestation

    def _validated_receipt(
        self,
        receipt: RunnerOfferReceipt,
        attestation: DispatchAttestation,
    ) -> RunnerOfferReceipt | str:
        try:
            validated = RunnerOfferReceipt.model_validate(receipt.model_dump(mode="json"))
        except (AttributeError, ValidationError):
            return "private runner dispatch receipt is invalid"
        bindings = (
            (validated.runner_id, self._config.runner_id),
            (validated.execution_id, attestation.execution_id),
            (validated.lease_digest, attestation.lease_digest),
            (validated.contract_digest, attestation.contract_digest),
            (validated.commands_digest, attestation.commands_digest),
        )
        if any(observed != expected for observed, expected in bindings):
            return "private runner dispatch receipt binding mismatch"
        if (
            validated.expires_at_ms <= attestation.issued_at_ms
            or validated.expires_at_ms > attestation.expires_at_ms
        ):
            return "private runner dispatch receipt expiration mismatch"
        return validated

    @staticmethod
    def _receipt_result(receipt: RunnerOfferReceipt) -> ProviderOperationResult:
        return GalorTweakRunnerProvider._result(
            receipt.execution_id,
            ProviderExecutionStatus.RUNNING,
            "private runner accepted bounded dispatch; independent verification remains pending",
            operation_id=receipt.operation_id,
            verification_outcome=VerificationOutcome.PENDING,
        )

    @staticmethod
    def _result(
        execution_id: str,
        status: ProviderExecutionStatus,
        reason: str,
        *,
        operation_id: str | None = None,
        verification_outcome: VerificationOutcome = VerificationOutcome.NOT_APPLICABLE,
        evidence_digest: str | None = None,
    ) -> ProviderOperationResult:
        return ProviderOperationResult(
            provider=ResourceProvider.SELF_HOSTED,
            execution_id=execution_id,
            status=status,
            operation_id=operation_id,
            reason=reason,
            verification_outcome=verification_outcome,
            evidence_digest=evidence_digest,
        )
