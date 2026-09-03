from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, Self, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, StrictBool, StrictInt, StrictStr, ValidationError, model_validator

from ...cloudflare_runner_qualification import CloudflareRunnerQualificationProof
from ...creator_contract import CreatorSchema, canonical_json, content_digest
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
from ..contracts import (
    ProviderCapabilities,
    ProviderExecutionStatus,
    ProviderHealth,
    ProviderOperationResult,
    ProviderQualification,
    VerificationOutcome,
)
from .qualification_manifest import (
    JOB_B_ARTIFACT_PATH,
    QualificationBoundedWriteManifest,
    QualificationJobManifest,
    QualificationReadOnlyManifest,
)

GALOR_TWEAK_RUNNER_ID = "galor-tweak-runner-01"
GALOR_TWEAK_RUNNER_ROLE = "role-tweak-runner"
GALOR_TWEAK_REPOSITORY_ID = "github:islamismylifebey-web/lil-tweak"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SAFE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_BASE64URL_PATTERN = r"^[A-Za-z0-9_-]+$"
_GIT_SHA_PATTERN = r"^[0-9a-f]{40}$"
_QUALIFICATION_BRANCH_PATTERN = r"^qualification/galor-tweak-runner-01/[a-z0-9][a-z0-9-]{0,31}$"
_RUNNER_RUNTIME_IMAGE: Literal[
    "python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
] = "python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
_RUNNER_SECCOMP_SHA256: Literal[
    "50eeb8b4cb2c33284f09453c8dd64c5895f5e1a2fa6b7a7440dfbac175fe1c23"
] = "50eeb8b4cb2c33284f09453c8dd64c5895f5e1a2fa6b7a7440dfbac175fe1c23"


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


class RunnerBaseReceipt(CreatorSchema):
    """Fixed sandbox facts available even when execution fails before checkout inspection."""

    runner_id: Literal["galor-tweak-runner-01"] = "galor-tweak-runner-01"
    runtime_image: Literal[
        "python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
    ] = _RUNNER_RUNTIME_IMAGE
    seccomp_sha256: Literal["50eeb8b4cb2c33284f09453c8dd64c5895f5e1a2fa6b7a7440dfbac175fe1c23"] = (
        _RUNNER_SECCOMP_SHA256
    )
    apparmor_profile: Literal["liltweak-runner-job"] = "liltweak-runner-job"
    network_denied: Literal[True] = True
    package_install_allowed: Literal[False] = False
    production_access_allowed: Literal[False] = False
    deploy_allowed: Literal[False] = False
    workspace_cleaned: StrictBool
    cgroup_cleaned: StrictBool


class RunnerReadOnlyReceipt(RunnerBaseReceipt):
    candidate_sha: None
    source_commit: StrictStr = Field(pattern=_GIT_SHA_PATTERN)
    source_tree: StrictStr = Field(pattern=_GIT_SHA_PATTERN)
    source_mutated: Literal[False] = False


class RunnerBoundedWriteReceipt(RunnerBaseReceipt):
    artifact_path: Literal["docs/runner-qualification/galor-tweak-runner-01.md"] = (
        JOB_B_ARTIFACT_PATH
    )
    artifact_sha256: Literal["62253a2945ea498f3b206a0449e5a97a0cf5783dd7858d7a11fbb365f4c04a91"] = (
        "62253a2945ea498f3b206a0449e5a97a0cf5783dd7858d7a11fbb365f4c04a91"
    )
    candidate_sha: StrictStr = Field(pattern=_GIT_SHA_PATTERN)
    candidate_tree: StrictStr = Field(pattern=_GIT_SHA_PATTERN)
    source_commit: StrictStr = Field(pattern=_GIT_SHA_PATTERN)
    source_tree: StrictStr = Field(pattern=_GIT_SHA_PATTERN)
    source_mutated: Literal[True] = True
    bundle_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    bundle_size: StrictInt = Field(ge=1, le=1_000_000)
    candidate_store_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    created_at_ms: StrictInt = Field(ge=0, le=9_007_199_254_740_991)
    qualification_branch: StrictStr = Field(pattern=_QUALIFICATION_BRANCH_PATTERN)


class RunnerPreExecutionCancellationReceipt(CreatorSchema):
    cancelled_before_execution: Literal[True] = True


type RunnerReceipt = (
    RunnerBoundedWriteReceipt
    | RunnerReadOnlyReceipt
    | RunnerBaseReceipt
    | RunnerPreExecutionCancellationReceipt
)


class RunnerEvidence(CreatorSchema):
    schema_version: Literal["lil-tweak.runner-evidence/v2"] = "lil-tweak.runner-evidence/v2"
    outcome: Literal["succeeded", "failed", "cancelled"]
    operation_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    stdout_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    stderr_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    receipt_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    receipt: RunnerReceipt
    exit_code: StrictInt = Field(ge=0, le=255)
    started_at_ms: StrictInt = Field(ge=0, le=9_007_199_254_740_991)
    finished_at_ms: StrictInt = Field(ge=0, le=9_007_199_254_740_991)

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        if self.started_at_ms > self.finished_at_ms:
            raise ValueError("runner evidence timestamps are not ordered")
        if self.receipt_digest != content_digest(self.receipt):
            raise ValueError("runner evidence receipt digest does not match")
        if self.outcome == "succeeded":
            if not isinstance(
                self.receipt,
                (RunnerReadOnlyReceipt, RunnerBoundedWriteReceipt),
            ):
                raise ValueError("successful runner evidence requires a detailed receipt")
            if (
                self.exit_code != 0
                or not self.receipt.workspace_cleaned
                or not self.receipt.cgroup_cleaned
            ):
                raise ValueError("successful runner evidence requires completed cleanup")
        if isinstance(self.receipt, RunnerPreExecutionCancellationReceipt) and (
            self.outcome != "cancelled" or self.exit_code != 0
        ):
            raise ValueError("pre-execution cancellation receipt is invalid")
        return self

    @property
    def evidence_digest(self) -> str:
        return content_digest(self)


class RunnerEvidenceRequestPayload(CreatorSchema):
    execution_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    attempt_nonce: StrictStr = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    evidence: RunnerEvidence


class RunnerEvidenceRequest(CreatorSchema):
    schema_version: Literal["lil-tweak.runner-request/v1"] = "lil-tweak.runner-request/v1"
    runner_id: Literal["galor-tweak-runner-01"] = "galor-tweak-runner-01"
    operation: Literal["evidence"] = "evidence"
    request_nonce: StrictStr = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    issued_at_ms: StrictInt = Field(ge=0, le=9_007_199_254_740_991)
    payload: RunnerEvidenceRequestPayload


class SignedRunnerEvidenceEnvelope(CreatorSchema):
    request: RunnerEvidenceRequest
    signature: StrictStr = Field(pattern=r"^[A-Za-z0-9_-]{86}$")


class RunnerExecutionSummary(CreatorSchema):
    """Typed controller view of one durable private-runner dispatch."""

    execution_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    runner_id: Literal["galor-tweak-runner-01"] = "galor-tweak-runner-01"
    runner_role: Literal["role-tweak-runner"] = "role-tweak-runner"
    status: Literal[
        "OFFERED",
        "CLAIMED",
        "EVIDENCE_RECORDED",
        "CANCEL_REQUESTED",
        "EXPIRED",
    ]
    lease_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    contract_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    commands_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    approval_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    policy_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    expires_at_ms: StrictInt = Field(ge=0)
    claim_receipt_digest: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    evidence_digest: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    evidence_outcome: Literal["succeeded", "failed", "cancelled"] | None = None
    evidence_envelope: SignedRunnerEvidenceEnvelope | None = None
    cancellation_reason_digest: StrictStr | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )

    @model_validator(mode="after")
    def validate_status_evidence(self) -> RunnerExecutionSummary:
        if self.status == "CLAIMED" and self.claim_receipt_digest is None:
            raise ValueError("claimed execution requires a claim receipt digest")
        has_evidence = self.evidence_digest is not None or self.evidence_outcome is not None
        if self.status == "EVIDENCE_RECORDED":
            if (
                self.evidence_digest is None
                or self.evidence_outcome is None
                or self.evidence_envelope is None
            ):
                raise ValueError("recorded execution requires signed runner evidence")
            evidence = self.evidence_envelope.request.payload.evidence
            if (
                evidence.evidence_digest != self.evidence_digest
                or evidence.outcome != self.evidence_outcome
            ):
                raise ValueError("recorded execution evidence is incomplete")
        elif has_evidence:
            raise ValueError("execution evidence contradicts status")
        elif self.evidence_envelope is not None:
            raise ValueError("signed runner evidence contradicts status")
        if self.status == "CANCEL_REQUESTED":
            if self.cancellation_reason_digest is None:
                raise ValueError("cancellation status requires a reason digest")
        elif self.cancellation_reason_digest is not None:
            raise ValueError("cancellation reason contradicts status")
        return self


class RunnerCancelReceipt(CreatorSchema):
    """Typed acknowledgement that cancellation was requested, not completed."""

    execution_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    status: Literal["CANCEL_REQUESTED"] = "CANCEL_REQUESTED"
    reason_digest: StrictStr = Field(pattern=_SHA256_PATTERN)


@runtime_checkable
class SelfHostedDispatchClient(Protocol):
    """The only private-runner control-plane operations this adapter may invoke."""

    async def offer(
        self,
        *,
        attestation: SignedDispatchAttestation,
        manifest: QualificationJobManifest,
    ) -> RunnerOfferReceipt: ...

    async def status(self, execution_id: str) -> RunnerExecutionSummary: ...

    async def cancel(
        self,
        execution_id: str,
        *,
        reason_digest: str,
    ) -> RunnerCancelReceipt: ...


@runtime_checkable
class Gate3ProofRefresher(Protocol):
    """A Gate 3 verifier, not a mutable health or qualification flag."""

    @property
    def contract_digest(self) -> str: ...

    async def refresh(self) -> CloudflareRunnerQualificationProof: ...


DispatchAttestationFactory = Callable[
    [ResourceExecutionContractV2, ExecutionLease], SignedDispatchAttestation
]


@dataclass(frozen=True)
class _DispatchRecord:
    contract: ResourceExecutionContractV2
    lease: ExecutionLease
    manifest: QualificationJobManifest
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
        runner_public_key: bytes,
        lease_signing_key: bytes,
        clock: Callable[[], datetime],
    ) -> None:
        if not isinstance(lease_signing_key, bytes) or len(lease_signing_key) != 32:
            raise ValueError("self-hosted provider lease signing key must contain exactly 32 bytes")
        if not isinstance(runner_public_key, bytes) or len(runner_public_key) != 32:
            raise ValueError("self-hosted provider runner public key must contain exactly 32 bytes")
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
        self._runner_public_key = Ed25519PublicKey.from_public_bytes(runner_public_key)
        self._lease_signing_key = lease_signing_key
        self._clock = clock
        self._leases = ExecutionLeaseRegistry()
        self._records: dict[str, _DispatchRecord] = {}
        self._evidence: dict[str, SignedRunnerEvidenceEnvelope] = {}
        self._gate3_proof: CloudflareRunnerQualificationProof | None = None

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
            last_verified_at=proof.cloudflare_poll_observed_at,
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
        manifest: QualificationJobManifest | None = None,
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
        normalized_manifest = self._normalize_manifest(manifest, contract=validated_contract)
        if isinstance(normalized_manifest, str):
            return self._result(
                validated_lease.execution_id,
                ProviderExecutionStatus.BLOCKED,
                normalized_manifest,
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
        except ExecutionLeaseError as exc:
            return self._result(
                validated_lease.execution_id,
                ProviderExecutionStatus.BLOCKED,
                f"execution lease rejected: {exc}",
            )
        try:
            response = await self._client.offer(
                attestation=signed_attestation,
                manifest=normalized_manifest,
            )
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
            manifest=normalized_manifest,
            attestation=attestation,
            receipt=receipt,
        )
        return self._receipt_result(receipt)

    async def status(self, execution_id: str) -> ProviderOperationResult:
        return await self._reconcile(execution_id)

    async def collect(self, execution_id: str) -> ProviderOperationResult:
        return await self._reconcile(execution_id)

    async def cancel(self, execution_id: str) -> ProviderOperationResult:
        record = self._records.get(execution_id)
        if record is None:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "private runner dispatch is unknown",
            )
        reason_digest = hashlib.sha256(
            f"lil-tweak.private-runner-cancel/v1\n{execution_id}".encode()
        ).hexdigest()
        try:
            response = await self._client.cancel(
                execution_id,
                reason_digest=reason_digest,
            )
            receipt = RunnerCancelReceipt.model_validate(response.model_dump(mode="json"))
        except Exception:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "private runner control plane did not accept cancellation",
            )
        if receipt.execution_id != execution_id or receipt.reason_digest != reason_digest:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "private runner cancellation receipt binding mismatch",
            )
        return self._result(
            execution_id,
            ProviderExecutionStatus.RUNNING,
            "private runner cancellation was requested; termination evidence remains pending",
            operation_id=record.receipt.operation_id,
            verification_outcome=VerificationOutcome.PENDING,
        )

    async def destroy(self, execution_id: str) -> ProviderOperationResult:
        record = self._records.pop(execution_id, None)
        self._evidence.pop(execution_id, None)
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

    def evidence_for(self, execution_id: str) -> SignedRunnerEvidenceEnvelope | None:
        return self._evidence.get(execution_id)

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

    def _normalize_manifest(
        self,
        manifest: QualificationJobManifest | None,
        *,
        contract: ResourceExecutionContractV2,
    ) -> QualificationJobManifest | str:
        try:
            if isinstance(manifest, QualificationReadOnlyManifest):
                validated: QualificationJobManifest = QualificationReadOnlyManifest.model_validate(
                    manifest.model_dump(mode="json")
                )
            elif isinstance(manifest, QualificationBoundedWriteManifest):
                validated = QualificationBoundedWriteManifest.model_validate(
                    manifest.model_dump(mode="json")
                )
            else:
                return "private runner dispatch requires a typed qualification manifest"
        except (AttributeError, ValidationError):
            return "private runner qualification manifest is invalid"
        source = validated.source
        if (
            f"github:{source.repository}" != contract.source.repository_id
            or source.commit_sha != contract.source.source_commit
            or source.tree_sha != contract.source.source_tree
        ):
            return "private runner qualification manifest source binding mismatch"
        if validated.commands_digest != contract.commands_digest:
            return "private runner qualification manifest commands digest mismatch"
        return validated

    async def _reconcile(self, execution_id: str) -> ProviderOperationResult:
        record = self._records.get(execution_id)
        if record is None:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "private runner dispatch is unknown",
            )
        try:
            response = await self._client.status(execution_id)
            summary = RunnerExecutionSummary.model_validate(response.model_dump(mode="json"))
        except Exception:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "private runner control-plane status could not be reconciled",
            )
        bindings = (
            (summary.runner_id, self._config.runner_id),
            (summary.runner_role, self._config.role),
            (summary.execution_id, record.lease.execution_id),
            (summary.lease_digest, record.lease.lease_digest),
            (summary.contract_digest, record.contract.contract_digest),
            (summary.commands_digest, record.manifest.commands_digest),
            (summary.approval_digest, record.lease.approval_digest),
            (summary.policy_digest, record.lease.policy_digest),
            (summary.expires_at_ms, record.receipt.expires_at_ms),
        )
        if any(observed != expected for observed, expected in bindings):
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "private runner control-plane status binding mismatch",
            )
        operation_id = record.receipt.operation_id
        if summary.status in {"OFFERED", "CLAIMED"}:
            return self._result(
                execution_id,
                ProviderExecutionStatus.RUNNING,
                "private runner dispatch remains in bounded execution",
                operation_id=operation_id,
                verification_outcome=VerificationOutcome.PENDING,
            )
        if summary.status == "CANCEL_REQUESTED":
            return self._result(
                execution_id,
                ProviderExecutionStatus.RUNNING,
                "private runner cancellation is requested; termination evidence remains pending",
                operation_id=operation_id,
                verification_outcome=VerificationOutcome.PENDING,
            )
        if summary.status == "EXPIRED":
            return self._result(
                execution_id,
                ProviderExecutionStatus.FAILED,
                "private runner dispatch expired without verified completion",
                operation_id=operation_id,
                verification_outcome=VerificationOutcome.FAILED,
            )
        evidence = self._validated_runner_evidence(summary, record)
        if isinstance(evidence, str):
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                evidence,
                operation_id=operation_id,
                verification_outcome=VerificationOutcome.FAILED,
            )
        self._evidence[execution_id] = evidence
        if summary.evidence_outcome == "succeeded":
            return self._result(
                execution_id,
                ProviderExecutionStatus.RUNNING,
                (
                    "private runner evidence is recorded; "
                    "independent GitHub verification remains pending"
                ),
                operation_id=operation_id,
                verification_outcome=VerificationOutcome.PENDING,
                evidence_digest=summary.evidence_digest,
            )
        if summary.evidence_outcome == "cancelled":
            return self._result(
                execution_id,
                ProviderExecutionStatus.CANCELED,
                "private runner supplied bounded cancellation evidence",
                operation_id=operation_id,
                evidence_digest=summary.evidence_digest,
            )
        return self._result(
            execution_id,
            ProviderExecutionStatus.FAILED,
            "private runner supplied failed execution evidence",
            operation_id=operation_id,
            verification_outcome=VerificationOutcome.FAILED,
            evidence_digest=summary.evidence_digest,
        )

    def _validated_runner_evidence(
        self,
        summary: RunnerExecutionSummary,
        record: _DispatchRecord,
    ) -> SignedRunnerEvidenceEnvelope | str:
        envelope = summary.evidence_envelope
        if envelope is None or summary.evidence_digest is None:
            return "private runner status lacks signed detailed evidence"
        request = envelope.request
        try:
            signature = base64.b64decode(
                envelope.signature + ("=" * (-len(envelope.signature) % 4)),
                altchars=b"-_",
                validate=True,
            )
        except (binascii.Error, ValueError, UnicodeEncodeError):
            return "signed runner evidence signature encoding was rejected"
        if len(signature) != 64:
            return "signed runner evidence signature encoding was rejected"
        signing_bytes = (
            "lil-tweak.runner-request/evidence/v1\n"
            + canonical_json(request.model_dump(mode="json"))
        ).encode("utf-8")
        try:
            self._runner_public_key.verify(signature, signing_bytes)
        except InvalidSignature:
            return "signed runner evidence signature was rejected"

        payload = request.payload
        evidence = payload.evidence
        expected_attempt_nonce = (
            base64.urlsafe_b64encode(bytes.fromhex(record.lease.attempt_nonce))
            .decode("ascii")
            .rstrip("=")
        )
        bindings = (
            (payload.execution_id, record.lease.execution_id),
            (payload.attempt_nonce, expected_attempt_nonce),
            (evidence.operation_digest, record.manifest.commands_digest),
            (evidence.evidence_digest, summary.evidence_digest),
            (evidence.outcome, summary.evidence_outcome),
        )
        if any(observed != expected for observed, expected in bindings):
            return "signed runner evidence binding mismatch"

        receipt = evidence.receipt
        if isinstance(
            receipt,
            (RunnerReadOnlyReceipt, RunnerBoundedWriteReceipt),
        ) and (
            receipt.source_commit != record.manifest.source.commit_sha
            or receipt.source_tree != record.manifest.source.tree_sha
        ):
            return "signed runner evidence source binding mismatch"
        if isinstance(receipt, RunnerBoundedWriteReceipt):
            if not isinstance(record.manifest, QualificationBoundedWriteManifest):
                return "signed runner evidence job type binding mismatch"
            bounded_bindings = (
                (receipt.artifact_path, record.manifest.artifact.path),
                (receipt.artifact_sha256, record.manifest.artifact.content_sha256),
                (receipt.qualification_branch, record.manifest.qualification_branch),
                (receipt.candidate_store_id, record.lease.execution_id),
            )
            if any(observed != expected for observed, expected in bounded_bindings):
                return "signed runner evidence bounded-write binding mismatch"
            if (
                receipt.candidate_sha == receipt.source_commit
                or receipt.candidate_tree == receipt.source_tree
                or receipt.created_at_ms < evidence.started_at_ms
                or receipt.created_at_ms > evidence.finished_at_ms
            ):
                return "signed runner evidence bounded-write candidate is invalid"
        if evidence.outcome == "succeeded":
            if isinstance(record.manifest, QualificationReadOnlyManifest):
                if not isinstance(receipt, RunnerReadOnlyReceipt):
                    return "signed runner evidence read-only receipt is unavailable"
            elif not isinstance(receipt, RunnerBoundedWriteReceipt):
                return "signed runner evidence bounded-write receipt is unavailable"
        return envelope

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
        if not isinstance(proof, CloudflareRunnerQualificationProof):
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
        proof: CloudflareRunnerQualificationProof,
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
        if contract is not None and proof.repository_commit != contract.source.source_commit:
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
