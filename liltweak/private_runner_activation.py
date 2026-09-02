from __future__ import annotations

import base64
import binascii
import ctypes
import hashlib
import hmac
import json
import os
import secrets
import stat
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol, Self

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import (
    Field,
    SecretBytes,
    SecretStr,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from .cloudflare_runner_qualification import (
    CloudflareRunnerQualificationProof,
    CloudflareRunnerQualificationVerifier,
)
from .config import Settings
from .creator_contract import CreatorSchema, content_digest
from .private_runner_control_plane import (
    PrivateRunnerAttestationIssuer,
    build_private_runner_control_plane_client,
)
from .providers.contracts import (
    ProviderExecutionStatus,
    ProviderOperationResult,
    VerificationOutcome,
)
from .providers.self_hosted.galor_tweak_runner import (
    GALOR_TWEAK_RUNNER_ID,
    GalorTweakRunnerConfig,
    GalorTweakRunnerGate3Config,
    GalorTweakRunnerProvider,
    SignedRunnerEvidenceEnvelope,
)
from .providers.self_hosted.qualification_manifest import (
    QualificationBoundedWriteManifest,
    QualificationJobManifest,
    QualificationReadOnlyManifest,
)
from .reasoning_policy import REASONING_POLICY
from .resource.budget import ResourceBudgetError, ResourceLedger
from .resource.catalog import ResourceCatalog
from .resource.contracts import (
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
    WorkspacePolicy,
)
from .resource.director import ResourceDirector, ResourceDirectorMode
from .resource.dispatch import DispatchAttestationVerifier, dispatch_issuer_key_id
from .resource.leases import ExecutionLease

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_OBJECT_ID_PATTERN = r"^[0-9a-f]{40}$"
_DPAPI_ENTROPY = b"lil-tweak-runner-control-plane-v1"
_CONTROL_PLANE_ENDPOINT: Literal["https://runner-control.liltweak.galorweb.works"] = (
    "https://runner-control.liltweak.galorweb.works"
)
_REPOSITORY_ID: Literal["github:islamismylifebey-web/lil-tweak"] = (
    "github:islamismylifebey-web/lil-tweak"
)
_RUNNER_ROLE: Literal["role-tweak-runner"] = "role-tweak-runner"
_RUNNER_ID: Literal["galor-tweak-runner-01"] = "galor-tweak-runner-01"

_GALOR_TWEAK_PROFILE_SPEC = {
    "schema_version": "galor-tweak-runner-profile-spec/v1",
    "runner_profile_id": GALOR_TWEAK_RUNNER_ID,
    "runner_role": _RUNNER_ROLE,
    "repository_id": _REPOSITORY_ID,
    "provider": ResourceProvider.SELF_HOSTED.value,
    "resource_type": ResourceType.SELF_HOSTED_LINUX.value,
    "single_machine_cpu": 2,
    "single_machine_memory_mb": 3_840,
    "single_machine_disk_mb": 32_768,
    "parallel_limit": 1,
    "maximum_duration_seconds": 1_800,
    "network_policy": "sandbox_no_network",
    "package_install": False,
    "production_access": False,
    "deployment": False,
}
GALOR_TWEAK_PROFILE_SPEC_DIGEST = content_digest(_GALOR_TWEAK_PROFILE_SPEC)


class PrivateRunnerActivationError(RuntimeError):
    """A bounded private-runner activation gate failed closed."""


class QualifiedRunnerScope(StrEnum):
    JOB_A = "job_a"
    JOB_B = "job_b"


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


class PrivateRunnerQualificationEvidence(CreatorSchema):
    """Controller input derived from independently verified Gate 3 evidence."""

    schema_version: Literal["lil-tweak.private-runner-qualification-input/v1"] = (
        "lil-tweak.private-runner-qualification-input/v1"
    )
    runner_id: Literal["galor-tweak-runner-01"] = _RUNNER_ID
    runner_role: Literal["role-tweak-runner"] = _RUNNER_ROLE
    repository_id: Literal["github:islamismylifebey-web/lil-tweak"] = _REPOSITORY_ID
    profile_spec_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    qualified: StrictBool
    healthy: StrictBool
    qualified_scopes: tuple[QualifiedRunnerScope, ...] = Field(min_length=1, max_length=2)
    gate3_contract_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    qualification_evidence_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    authorization_evidence_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    proof: CloudflareRunnerQualificationProof

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if self.profile_spec_digest != GALOR_TWEAK_PROFILE_SPEC_DIGEST:
            raise ValueError("private runner profile spec digest does not match")
        if len(set(self.qualified_scopes)) != len(self.qualified_scopes):
            raise ValueError("private runner qualified scopes must be unique")
        proof = self.proof
        if proof.runner_id != self.runner_id:
            raise ValueError("private runner proof identity does not match")
        if proof.qualification_evidence_digest != self.qualification_evidence_digest:
            raise ValueError("private runner qualification evidence digest does not match")
        if proof.authorization_evidence_digest != self.authorization_evidence_digest:
            raise ValueError("private runner authorization evidence digest does not match")
        if proof.repository_commit == "0" * 40:
            raise ValueError("private runner proof source commit is invalid")
        return self


class PrivateRunnerApproval(CreatorSchema):
    schema_version: Literal["lil-tweak.private-runner-approval-input/v1"] = (
        "lil-tweak.private-runner-approval-input/v1"
    )
    approval_id: StrictStr = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    requested_by: Literal["maurice-pennington-bey"] = "maurice-pennington-bey"
    approved: StrictBool
    approval_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    policy_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    maximum_execution_cost_microusd: StrictInt = Field(ge=0, le=10_000_000)


class SourceEvidence(CreatorSchema):
    schema_version: Literal["lil-tweak.private-runner-source-input/v1"] = (
        "lil-tweak.private-runner-source-input/v1"
    )
    repository_id: Literal["github:islamismylifebey-web/lil-tweak"] = _REPOSITORY_ID
    commit_sha: StrictStr = Field(pattern=_OBJECT_ID_PATTERN)
    tree_sha: StrictStr = Field(pattern=_OBJECT_ID_PATTERN)
    source_archive_digest: StrictStr = Field(pattern=_SHA256_PATTERN)


class IndependentVerificationReceipt(CreatorSchema):
    schema_version: Literal["lil-tweak.private-runner-independent-verification/v1"] = (
        "lil-tweak.private-runner-independent-verification/v1"
    )
    provider: Literal[ResourceProvider.GITHUB] = ResourceProvider.GITHUB
    job_type: Literal["read_only", "bounded_write"]
    runner_execution_id: StrictStr = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    source_commit: StrictStr = Field(pattern=_OBJECT_ID_PATTERN)
    runner_evidence_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    github_evidence_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    verification_outcome: Literal[VerificationOutcome.VERIFIED, VerificationOutcome.FAILED]


class PrivateRunnerDispatchReceipt(CreatorSchema):
    schema_version: Literal["lil-tweak.private-runner-dispatch-receipt/v1"] = (
        "lil-tweak.private-runner-dispatch-receipt/v1"
    )
    job_type: Literal["read_only", "bounded_write"]
    runner_profile_id: Literal["galor-tweak-runner-01"] = _RUNNER_ID
    execution_id: StrictStr
    source_commit: StrictStr = Field(pattern=_OBJECT_ID_PATTERN)
    route_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    contract_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    lease_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    commands_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    operation_id: StrictStr | None = None
    runner_evidence_digest: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    runner_evidence_envelope: SignedRunnerEvidenceEnvelope | None = None
    independent_verification_required: Literal[True] = True


class PrivateRunnerVerifiedResult(CreatorSchema):
    schema_version: Literal["lil-tweak.private-runner-verified-result/v1"] = (
        "lil-tweak.private-runner-verified-result/v1"
    )
    job_type: Literal["read_only", "bounded_write"]
    execution_id: StrictStr
    source_commit: StrictStr = Field(pattern=_OBJECT_ID_PATTERN)
    runner_evidence_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    github_evidence_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    verification_outcome: Literal[VerificationOutcome.VERIFIED] = VerificationOutcome.VERIFIED


class _QualificationProvider(Protocol):
    async def provision(
        self, *, contract: ResourceExecutionContractV2, lease: ExecutionLease
    ) -> ProviderOperationResult: ...

    async def execute(
        self,
        *,
        contract: ResourceExecutionContractV2,
        lease: ExecutionLease,
        manifest: QualificationJobManifest,
    ) -> ProviderOperationResult: ...

    async def collect(self, execution_id: str) -> ProviderOperationResult: ...

    def evidence_for(self, execution_id: str) -> SignedRunnerEvidenceEnvelope | None: ...

    async def cancel(self, execution_id: str) -> ProviderOperationResult: ...


class PrivateRunnerQualificationOrchestrator:
    """Explicit activation layer above Director for only qualification Jobs A and B."""

    def __init__(
        self,
        *,
        provider: _QualificationProvider,
        lease_signing_key: bytes,
        resource_ledger: ResourceLedger,
        clock: Callable[[], datetime],
        identifier_factory: Callable[[str], str] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        if not isinstance(lease_signing_key, bytes) or len(lease_signing_key) != 32:
            raise ValueError("private runner lease signing key must contain exactly 32 bytes")
        self._provider = provider
        self._lease_signing_key = lease_signing_key
        self._ledger = resource_ledger
        self._clock = clock
        self._identifier_factory = identifier_factory or (
            lambda label: f"{label}-{uuid.uuid4().hex}"
        )
        self._nonce_factory = nonce_factory or (lambda: secrets.token_hex(32))
        self._dispatches: dict[str, PrivateRunnerDispatchReceipt] = {}
        self._job_a_verifications: dict[str, PrivateRunnerVerifiedResult] = {}

    async def offer(
        self,
        *,
        manifest: QualificationJobManifest,
        source: SourceEvidence,
        approval: PrivateRunnerApproval,
        qualification: PrivateRunnerQualificationEvidence,
        prior_job_a_verification: PrivateRunnerVerifiedResult | None = None,
    ) -> PrivateRunnerDispatchReceipt:
        manifest = self._validated_manifest(manifest)
        source = SourceEvidence.model_validate(source.model_dump(mode="json"))
        approval = PrivateRunnerApproval.model_validate(approval.model_dump(mode="json"))
        qualification = PrivateRunnerQualificationEvidence.model_validate(
            qualification.model_dump(mode="python")
        )
        now = self._clock()
        if not _aware(now):
            raise PrivateRunnerActivationError("private runner activation time is invalid")
        if not approval.approved:
            raise PrivateRunnerActivationError("private runner Founder approval is not active")
        if (
            source.commit_sha != manifest.source.commit_sha
            or source.tree_sha != manifest.source.tree_sha
            or qualification.proof.repository_commit != source.commit_sha
        ):
            raise PrivateRunnerActivationError("private runner immutable source binding mismatch")
        scope = (
            QualifiedRunnerScope.JOB_A
            if isinstance(manifest, QualificationReadOnlyManifest)
            else QualifiedRunnerScope.JOB_B
        )
        if scope not in qualification.qualified_scopes:
            raise PrivateRunnerActivationError("private runner qualification scope is missing")
        if isinstance(manifest, QualificationBoundedWriteManifest):
            self._validate_prior_job_a(
                prior_job_a_verification, source, self._dispatches, self._job_a_verifications
            )

        profile = self._profile(qualification)
        requirements = self._requirements(manifest, approval)
        director = ResourceDirector(
            ResourceCatalog((profile,)),
            mode=ResourceDirectorMode.ACTIVE,
        )
        decision = director.route(
            requirements,
            as_of=now,
            existing_execution_decision="private-runner-qualification-v1",
        )
        route = decision.route
        if route is None or route.selected_profile is None or route.estimate is None:
            reason = "private runner is not qualified, healthy, capable, authorized, and budgeted"
            if route is not None and route.eliminations:
                reason = route.eliminations[0].reason
            raise PrivateRunnerActivationError(reason)
        selected = route.selected_profile
        if (
            selected.runner_profile_id != GALOR_TWEAK_RUNNER_ID
            or selected.profile_digest != profile.profile_digest
        ):
            raise PrivateRunnerActivationError(
                "private runner Director selected an invalid profile"
            )

        execution_id = self._identifier_factory("execution")
        try:
            self._ledger.reserve(
                execution_id=execution_id,
                estimate=route.estimate,
                maximum_authorized_cost_microusd=approval.maximum_execution_cost_microusd,
                chosen_reason="Director selected exact qualified private runner profile",
                reserved_at=now,
            )
        except ResourceBudgetError as exc:
            raise PrivateRunnerActivationError(
                "private runner resource budget rejected dispatch"
            ) from exc

        dispatch_expiry = now + timedelta(minutes=5)
        contract = ResourceExecutionContractV2.issue(
            contract_id=self._identifier_factory("contract"),
            requirements=requirements,
            profile=selected,
            source=ImmutableSourceBinding(
                repository_id=source.repository_id,
                source_commit=source.commit_sha,
                source_tree=source.tree_sha,
                source_archive_digest=source.source_archive_digest,
            ),
            approval=ApprovalBinding(
                approval_id=approval.approval_id,
                approval_digest=approval.approval_digest,
                policy_digest=approval.policy_digest,
            ),
            commands_digest=manifest.commands_digest,
            issued_at=now,
            expires_at=dispatch_expiry,
        )
        lease = ExecutionLease.issue(
            lease_id=self._identifier_factory("lease"),
            execution_id=execution_id,
            contract=contract,
            attempt_nonce=self._nonce_factory(),
            authorization_sequence=qualification.proof.authorization_sequence,
            revocation_epoch=qualification.proof.authorization_revocation_epoch,
            issued_at=now,
            expires_at=dispatch_expiry,
            signing_key=self._lease_signing_key,
        )
        provisioned = await self._provider.provision(contract=contract, lease=lease)
        if provisioned.status is not ProviderExecutionStatus.PROVISIONED:
            raise PrivateRunnerActivationError(
                f"private runner provisioning blocked: {provisioned.reason}"
            )
        offered = await self._provider.execute(
            contract=contract,
            lease=lease,
            manifest=manifest,
        )
        if offered.status is not ProviderExecutionStatus.RUNNING:
            raise PrivateRunnerActivationError(f"private runner dispatch blocked: {offered.reason}")
        receipt = PrivateRunnerDispatchReceipt(
            job_type=manifest.job_type,
            execution_id=execution_id,
            source_commit=source.commit_sha,
            route_digest=route.decision_digest,
            contract_digest=contract.contract_digest,
            lease_digest=lease.lease_digest,
            commands_digest=manifest.commands_digest,
            operation_id=offered.operation_id,
        )
        self._dispatches[execution_id] = receipt
        return receipt

    async def collect(self, receipt: PrivateRunnerDispatchReceipt) -> PrivateRunnerDispatchReceipt:
        receipt = self._known_receipt(receipt)
        result = await self._provider.collect(receipt.execution_id)
        if result.status in {
            ProviderExecutionStatus.BLOCKED,
            ProviderExecutionStatus.FAILED,
            ProviderExecutionStatus.CANCELED,
        }:
            raise PrivateRunnerActivationError(result.reason)
        if result.evidence_digest is None:
            return receipt
        evidence = self._provider.evidence_for(receipt.execution_id)
        if (
            evidence is None
            or evidence.request.payload.evidence.evidence_digest != result.evidence_digest
        ):
            raise PrivateRunnerActivationError("verified signed runner evidence is unavailable")
        collected = receipt.model_copy(
            update={
                "runner_evidence_digest": result.evidence_digest,
                "runner_evidence_envelope": evidence,
            }
        )
        self._dispatches[receipt.execution_id] = collected
        return collected

    async def cancel(self, receipt: PrivateRunnerDispatchReceipt) -> ProviderOperationResult:
        receipt = self._known_receipt(receipt)
        return await self._provider.cancel(receipt.execution_id)

    def accept_independent_verification(
        self,
        receipt: PrivateRunnerDispatchReceipt,
        verification: IndependentVerificationReceipt,
    ) -> PrivateRunnerVerifiedResult:
        receipt = self._known_receipt(receipt)
        verification = IndependentVerificationReceipt.model_validate(
            verification.model_dump(mode="json")
        )
        if verification.verification_outcome is not VerificationOutcome.VERIFIED:
            raise PrivateRunnerActivationError("private runner independent verification failed")
        if receipt.runner_evidence_digest is None:
            raise PrivateRunnerActivationError("private runner evidence digest is unavailable")
        bindings = (
            (verification.job_type, receipt.job_type),
            (verification.runner_execution_id, receipt.execution_id),
            (verification.source_commit, receipt.source_commit),
            (verification.runner_evidence_digest, receipt.runner_evidence_digest),
        )
        if any(observed != expected for observed, expected in bindings):
            raise PrivateRunnerActivationError(
                "private runner independent verification binding mismatch"
            )
        result = PrivateRunnerVerifiedResult(
            job_type=receipt.job_type,
            execution_id=receipt.execution_id,
            source_commit=receipt.source_commit,
            runner_evidence_digest=verification.runner_evidence_digest,
            github_evidence_digest=verification.github_evidence_digest,
        )
        self._job_a_verifications[receipt.execution_id] = result
        return result

    def _known_receipt(self, receipt: PrivateRunnerDispatchReceipt) -> PrivateRunnerDispatchReceipt:
        normalized = PrivateRunnerDispatchReceipt.model_validate(receipt.model_dump(mode="json"))
        expected = self._dispatches.get(normalized.execution_id)
        if expected is None or expected != normalized:
            raise PrivateRunnerActivationError("private runner dispatch receipt is unknown")
        return normalized

    @staticmethod
    def _validated_manifest(manifest: QualificationJobManifest) -> QualificationJobManifest:
        if isinstance(manifest, QualificationReadOnlyManifest):
            return QualificationReadOnlyManifest.model_validate(manifest.model_dump(mode="json"))
        if isinstance(manifest, QualificationBoundedWriteManifest):
            return QualificationBoundedWriteManifest.model_validate(
                manifest.model_dump(mode="json")
            )
        raise PrivateRunnerActivationError(
            "only fixed private runner qualification manifests are allowed"
        )

    @staticmethod
    def _validate_prior_job_a(
        verification: PrivateRunnerVerifiedResult | None,
        source: SourceEvidence,
        dispatches: dict[str, PrivateRunnerDispatchReceipt],
        job_a_verifications: dict[str, PrivateRunnerVerifiedResult],
    ) -> None:
        if (
            verification is None
            or verification.job_type != "read_only"
            or verification.source_commit != source.commit_sha
            or verification.runner_evidence_digest is None
        ):
            raise PrivateRunnerActivationError(
                "Job A independent verification is required before Job B"
            )
        prior_receipt = dispatches.get(verification.execution_id)
        if (
            prior_receipt is None
            or prior_receipt.job_type != verification.job_type
            or prior_receipt.source_commit != verification.source_commit
            or prior_receipt.runner_evidence_digest != verification.runner_evidence_digest
        ):
            raise PrivateRunnerActivationError("Job A independent verification binding mismatch")
        prior_result = job_a_verifications.get(verification.execution_id)
        if prior_result is None:
            raise PrivateRunnerActivationError(
                "Job A independent verification is required before Job B"
            )
        if prior_result != verification:
            raise PrivateRunnerActivationError("Job A independent verification binding mismatch")

    @staticmethod
    def _profile(qualification: PrivateRunnerQualificationEvidence) -> ResourceProfile:
        proof = qualification.proof
        workspace = (
            WorkspacePolicy.EPHEMERAL_WRITABLE
            if QualifiedRunnerScope.JOB_B in qualification.qualified_scopes
            else WorkspacePolicy.READ_ONLY
        )
        return ResourceProfile(
            runner_profile_id=GALOR_TWEAK_RUNNER_ID,
            provider=ResourceProvider.SELF_HOSTED,
            resource_type=ResourceType.SELF_HOSTED_LINUX,
            single_machine_cpu=2,
            single_machine_memory_mb=3_840,
            single_machine_disk_mb=32_768,
            aggregate_parallel_cpu=2,
            aggregate_parallel_memory_mb=3_840,
            parallel_limit=1,
            maximum_duration_seconds=1_800,
            workspace_policy=workspace,
            source_write_capability=QualifiedRunnerScope.JOB_B in qualification.qualified_scopes,
            qualification_status=(
                QualificationStatus.QUALIFIED
                if qualification.qualified
                else QualificationStatus.UNQUALIFIED
            ),
            health_status=(
                HealthStatus.HEALTHY if qualification.healthy else HealthStatus.UNHEALTHY
            ),
            last_qualified_at=proof.qualification_verified_at,
            last_verified_at=proof.cloudflare_poll_observed_at,
            estimated_cpu_microusd_per_second=1,
            estimated_memory_microusd_per_gb_second=1,
            estimated_storage_microusd_per_gb_second=1,
            included_allowance_microusd=0,
            current_usage_microusd=0,
            risk_surface=RiskLevel.LOW,
            priority=1,
        )

    @staticmethod
    def _requirements(
        manifest: QualificationJobManifest,
        approval: PrivateRunnerApproval,
    ) -> WorkloadRequirements:
        writable = isinstance(manifest, QualificationBoundedWriteManifest)
        return WorkloadRequirements(
            requirement_id=f"requirement-{manifest.job_type}",
            job_id=f"qualification-{manifest.job_type}",
            required_cpu=2,
            required_memory_mb=2_048,
            required_disk_mb=4_096,
            shared_memory_required=True,
            network_policy=NetworkPolicy(),
            workspace_policy=(
                WorkspacePolicy.EPHEMERAL_WRITABLE if writable else WorkspacePolicy.READ_ONLY
            ),
            source_write_required=writable,
            estimated_duration_seconds=manifest.timeout_seconds,
            parallelizable=False,
            desired_parallelism=1,
            verification_level=VerificationLevel.INDEPENDENT,
            authority=WorkloadAuthority(
                requested_by=approval.requested_by,
                risk_level=RiskLevel.LOW,
                maximum_resource_risk=RiskLevel.LOW,
                maximum_authorized_cost_microusd=(approval.maximum_execution_cost_microusd),
                approval_digest=approval.approval_digest,
                policy_digest=approval.policy_digest,
                writable_workspace_authorized=writable,
                source_write_authorized=writable,
            ),
        )


class ProtectedControllerConfig(CreatorSchema):
    """Secrets decrypted from the local DPAPI bundle; repr/JSON stay redacted."""

    endpoint: Literal["https://runner-control.liltweak.galorweb.works"] = _CONTROL_PLANE_ENDPOINT
    bearer_token: SecretStr
    access_client_id: SecretStr
    access_client_secret: SecretStr
    dispatch_private_key: SecretBytes
    dispatch_public_key: StrictStr
    dispatch_key_id: StrictStr = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_signing_identity(self) -> Self:
        private_key = self.dispatch_private_key.get_secret_value()
        public_key = _decode_base64url(self.dispatch_public_key, label="public key")
        if len(private_key) != 32 or len(public_key) != 32:
            raise ValueError("protected controller signing key length is invalid")
        derived_public = (
            Ed25519PrivateKey.from_private_bytes(private_key)
            .public_key()
            .public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )
        if not secrets.compare_digest(derived_public, public_key):
            raise ValueError("protected controller signing key pair does not match")
        if self.dispatch_key_id != dispatch_issuer_key_id(public_key):
            raise ValueError("protected controller signing key identity does not match")
        return self


def build_live_private_runner_orchestrator(
    *,
    controller: ProtectedControllerConfig,
    qualification: PrivateRunnerQualificationEvidence,
    qualification_verifier: CloudflareRunnerQualificationVerifier,
    runner_public_key: bytes,
    monthly_resource_limit_microusd: int,
    clock: Callable[[], datetime],
) -> PrivateRunnerQualificationOrchestrator:
    """Wire Director activation to the actual Cloudflare client and runner provider."""

    controller = ProtectedControllerConfig.model_validate(controller.model_dump(mode="python"))
    qualification = PrivateRunnerQualificationEvidence.model_validate(
        qualification.model_dump(mode="python")
    )
    private_key = controller.dispatch_private_key.get_secret_value()
    public_key = _decode_base64url(controller.dispatch_public_key, label="public key")
    settings = Settings(
        environment="test",
        database_path=Path("private-runner-activation.db"),
        dev_api_key="private-runner-activation-disabled-http-api",
        auth_disabled=False,
        model=REASONING_POLICY.primary_model.value,
        monthly_budget_usd=0.01,
        job_hard_limit_usd=0.01,
        private_runner_control_plane_enabled=True,
        private_runner_control_plane_url=controller.endpoint,
        private_runner_control_plane_auth_token=(controller.bearer_token.get_secret_value()),
        private_runner_access_client_id=controller.access_client_id.get_secret_value(),
        private_runner_access_client_secret=(controller.access_client_secret.get_secret_value()),
        private_runner_dispatch_key_id=controller.dispatch_key_id,
        private_runner_dispatch_signing_key=private_key,
    )
    client = build_private_runner_control_plane_client(settings)
    issuer = PrivateRunnerAttestationIssuer(settings, clock=clock)
    lease_signing_key = hmac.new(
        private_key,
        b"liltweak:private-runner-lease-key:v1\0",
        hashlib.sha256,
    ).digest()
    provider = GalorTweakRunnerProvider(
        config=GalorTweakRunnerConfig(),
        client=client,
        gate3_verifier=qualification_verifier,
        gate3_config=GalorTweakRunnerGate3Config(
            contract_digest=qualification.gate3_contract_digest,
            qualification_evidence_digest=(qualification.qualification_evidence_digest),
            authorization_digest=qualification.authorization_evidence_digest,
            minimum_authorization_sequence=(qualification.proof.authorization_sequence),
            revocation_epoch=qualification.proof.authorization_revocation_epoch,
        ),
        attestation_factory=issuer.issue,
        attestation_verifier=DispatchAttestationVerifier(
            trusted_issuer_public_keys={controller.dispatch_key_id: public_key}
        ),
        runner_public_key=runner_public_key,
        lease_signing_key=lease_signing_key,
        clock=clock,
    )
    return PrivateRunnerQualificationOrchestrator(
        provider=provider,
        lease_signing_key=lease_signing_key,
        resource_ledger=ResourceLedger(monthly_limit_microusd=monthly_resource_limit_microusd),
        clock=clock,
    )


def _decode_base64url(value: object, *, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise PrivateRunnerActivationError(f"protected controller {label} is invalid")
    try:
        return base64.b64decode(
            (value + "=" * (-len(value) % 4)).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise PrivateRunnerActivationError(f"protected controller {label} is invalid") from exc


def _decrypt_dpapi(payload: bytes) -> bytes:
    if os.name != "nt":
        raise PrivateRunnerActivationError("DPAPI controller bundle requires Windows")

    class DataBlob(ctypes.Structure):
        _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_ubyte))]

    def blob(value: bytes) -> tuple[DataBlob, Any]:
        buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
        return DataBlob(len(value), buffer), buffer

    encrypted, encrypted_buffer = blob(payload)
    entropy, entropy_buffer = blob(_DPAPI_ENTROPY)
    decrypted = DataBlob()
    win_dll = getattr(ctypes, "WinDLL", None)
    if not callable(win_dll):
        raise PrivateRunnerActivationError("DPAPI controller bundle requires Windows")
    crypt32 = win_dll("crypt32", use_last_error=True)
    kernel32 = win_dll("kernel32", use_last_error=True)
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(encrypted),
        None,
        ctypes.byref(entropy),
        None,
        None,
        0,
        ctypes.byref(decrypted),
    )
    _ = encrypted_buffer, entropy_buffer
    if not ok:
        raise PrivateRunnerActivationError("DPAPI controller bundle could not be decrypted")
    try:
        return ctypes.string_at(decrypted.data, decrypted.size)
    finally:
        ctypes.memset(decrypted.data, 0, decrypted.size)
        kernel32.LocalFree(decrypted.data)


def load_protected_controller_config(
    path: Path,
    *,
    decrypt: Callable[[bytes], bytes] | None = None,
) -> ProtectedControllerConfig:
    resolved = path.resolve(strict=True)
    metadata = resolved.lstat()
    if not stat.S_ISREG(metadata.st_mode) or resolved.is_symlink():
        raise PrivateRunnerActivationError("protected controller bundle must be a regular file")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise PrivateRunnerActivationError("protected controller bundle permissions are too broad")
    encrypted = resolved.read_bytes()
    plaintext = bytearray((decrypt or _decrypt_dpapi)(encrypted))
    try:
        raw: Any = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PrivateRunnerActivationError("protected controller bundle is invalid") from exc
    finally:
        for index in range(len(plaintext)):
            plaintext[index] = 0
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise PrivateRunnerActivationError("protected controller bundle version is invalid")
    if raw.get("endpoint") != _CONTROL_PLANE_ENDPOINT:
        raise PrivateRunnerActivationError("protected controller endpoint identity is invalid")
    runner = raw.get("runner")
    if not isinstance(runner, dict) or runner.get("runnerId") != GALOR_TWEAK_RUNNER_ID:
        raise PrivateRunnerActivationError("protected controller runner identity is invalid")
    control = raw.get("control")
    dispatch = raw.get("dispatch")
    if not isinstance(control, dict) or not isinstance(dispatch, dict):
        raise PrivateRunnerActivationError("protected controller bundle fields are incomplete")
    private_key = _decode_base64url(dispatch.get("privateKey"), label="private key")
    public_key = _decode_base64url(dispatch.get("publicKey"), label="public key")
    if len(private_key) != 32 or len(public_key) != 32:
        raise PrivateRunnerActivationError("protected controller signing key length is invalid")
    derived_public = (
        Ed25519PrivateKey.from_private_bytes(private_key)
        .public_key()
        .public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )
    if not secrets.compare_digest(derived_public, public_key):
        raise PrivateRunnerActivationError("protected controller signing key pair does not match")
    key_id = dispatch.get("keyId")
    if not isinstance(key_id, str) or len(key_id) != 64:
        raise PrivateRunnerActivationError("protected controller signing key id is invalid")
    for label, value in (
        ("bearer token", control.get("bearerToken")),
        ("Access client id", control.get("accessClientId")),
        ("Access client secret", control.get("accessClientSecret")),
    ):
        if not isinstance(value, str) or len(value) < 16:
            raise PrivateRunnerActivationError(f"protected controller {label} is invalid")
    return ProtectedControllerConfig(
        bearer_token=SecretStr(control["bearerToken"]),
        access_client_id=SecretStr(control["accessClientId"]),
        access_client_secret=SecretStr(control["accessClientSecret"]),
        dispatch_private_key=SecretBytes(private_key),
        dispatch_public_key=dispatch["publicKey"],
        dispatch_key_id=key_id,
    )
