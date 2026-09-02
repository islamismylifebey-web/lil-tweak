from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from pydantic import ValidationError

from ...creator_contract import canonical_json
from ...resource.contracts import (
    DeploymentPurpose,
    HealthStatus,
    QualificationStatus,
    ResourceExecutionContractV2,
    ResourceProfile,
    ResourceProvider,
    ResourceType,
    WorkloadRequirements,
    WorkspacePolicy,
)
from ...resource.estimator import ResourceCostEstimate, ResourceEstimator
from ...resource.leases import ExecutionLease, ExecutionLeaseError, ExecutionLeaseRegistry
from ..contracts import (
    ProviderCapabilities,
    ProviderExecutionStatus,
    ProviderHealth,
    ProviderOperationResult,
    ProviderQualification,
    ProviderRuntimeState,
    VerificationOutcome,
)
from .runner_v3_contracts import (
    RunnerV3Client,
    RunnerV3JobManifest,
    RunnerV3Outcome,
    RunnerV3ProviderConfig,
    RunnerV3WorkflowSnapshot,
    RunnerV3WorkspaceMode,
)

RunnerV3ManifestFactory = Callable[
    [ResourceExecutionContractV2, ExecutionLease],
    RunnerV3JobManifest,
]


@dataclass(frozen=True)
class _RunnerV3Run:
    run_id: str
    source_commit: str
    source_tree: str
    manifest_digest: str


class GitHubRunnerV3Provider:
    """Lease-bound GitHub builder adapter for the first Runner V3 factory profile."""

    def __init__(
        self,
        *,
        config: RunnerV3ProviderConfig,
        state: ProviderRuntimeState,
        client: RunnerV3Client,
        manifest_factory: RunnerV3ManifestFactory,
        lease_signing_key: bytes,
        minimum_authorization_sequence: int,
        revocation_epoch: int,
        clock: Callable[[], datetime],
    ) -> None:
        if not isinstance(lease_signing_key, bytes) or len(lease_signing_key) != 32:
            raise ValueError("Runner V3 lease signing key must contain exactly 32 bytes")
        if minimum_authorization_sequence < 0:
            raise ValueError("Runner V3 minimum authorization sequence cannot be negative")
        if revocation_epoch < 1:
            raise ValueError("Runner V3 revocation epoch must be positive")
        self._config = config
        self._state = state
        self._client = client
        self._manifest_factory = manifest_factory
        self._lease_signing_key = lease_signing_key
        self._minimum_authorization_sequence = minimum_authorization_sequence
        self._revocation_epoch = revocation_epoch
        self._clock = clock
        self._leases = ExecutionLeaseRegistry()
        self._runs: dict[str, _RunnerV3Run] = {}

    def qualify(self) -> ProviderQualification:
        blockers: list[str] = []
        if self._state.qualification_status is not QualificationStatus.QUALIFIED:
            blockers.append("Runner V3 provider is not qualified")
        if self._state.health_status is not HealthStatus.HEALTHY:
            blockers.append("Runner V3 provider is not healthy")
        elif not self._runtime_state_is_fresh():
            blockers.append("Runner V3 provider runtime health verification is stale")
        if not self._state.connected:
            blockers.append("Runner V3 provider is not connected")
        if not self._state.active:
            blockers.append("Runner V3 provider is not active")
        return ProviderQualification(
            provider=ResourceProvider.GITHUB,
            qualified=not blockers,
            blockers=tuple(blockers),
        )

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider=ResourceProvider.GITHUB,
            resource_types=(ResourceType.GITHUB_ACTIONS,),
            builder=True,
            independent_verifier=False,
            preview_only=False,
            production_deployment=False,
        )

    def health(self) -> ProviderHealth:
        status = self._state.health_status
        if status is HealthStatus.HEALTHY and not self._runtime_state_is_fresh():
            status = HealthStatus.UNKNOWN
        return ProviderHealth(
            provider=ResourceProvider.GITHUB,
            status=status,
            connected=self._state.connected,
            active=self._state.active,
            last_verified_at=self._state.last_verified_at,
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
        blocker = self._readiness_blocker(contract, lease)
        if blocker is not None:
            return self._result(lease.execution_id, ProviderExecutionStatus.BLOCKED, blocker)
        return self._result(
            lease.execution_id,
            ProviderExecutionStatus.PROVISIONED,
            "Runner V3 GitHub builder is eligible for one bounded dispatch",
        )

    async def execute(
        self,
        *,
        contract: ResourceExecutionContractV2,
        lease: ExecutionLease,
    ) -> ProviderOperationResult:
        blocker = self._readiness_blocker(contract, lease)
        if blocker is not None:
            return self._result(lease.execution_id, ProviderExecutionStatus.BLOCKED, blocker)
        try:
            self._leases.consume(
                lease,
                contract=contract,
                signing_key=self._lease_signing_key,
                now=self._clock(),
                minimum_authorization_sequence=self._minimum_authorization_sequence,
                revocation_epoch=self._revocation_epoch,
            )
        except ExecutionLeaseError as exc:
            return self._result(
                lease.execution_id,
                ProviderExecutionStatus.BLOCKED,
                f"execution lease rejected: {exc}",
            )

        try:
            candidate = self._manifest_factory(contract, lease)
        except (TypeError, ValueError) as exc:
            return self._result(
                lease.execution_id,
                ProviderExecutionStatus.BLOCKED,
                f"Runner V3 manifest construction failed: {exc}",
            )
        manifest, manifest_blocker = self._validated_manifest(candidate, contract, lease)
        if manifest_blocker is not None or manifest is None:
            return self._result(
                lease.execution_id,
                ProviderExecutionStatus.BLOCKED,
                manifest_blocker or "Runner V3 manifest is invalid",
            )

        run_id = await self._client.dispatch_job(
            repository_id=self._config.repository_id,
            workflow_path=self._config.workflow_path,
            source_commit=contract.source.source_commit,
            manifest_json=canonical_json(manifest.model_dump(mode="json")),
            manifest_digest=manifest.manifest_digest,
        )
        self._runs[lease.execution_id] = _RunnerV3Run(
            run_id=run_id,
            source_commit=manifest.source_commit,
            source_tree=manifest.source_tree,
            manifest_digest=manifest.manifest_digest,
        )
        return self._result(
            lease.execution_id,
            ProviderExecutionStatus.RUNNING,
            (
                "Runner V3 GitHub builder workflow dispatched; "
                "independent verification remains separate"
            ),
            operation_id=run_id,
        )

    async def status(self, execution_id: str) -> ProviderOperationResult:
        run = self._runs.get(execution_id)
        if run is None:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "Runner V3 execution is unknown",
            )
        snapshot = await self._client.get_workflow(run.run_id)
        return self._from_snapshot(execution_id, run, snapshot, collect=False)

    async def collect(self, execution_id: str) -> ProviderOperationResult:
        run = self._runs.get(execution_id)
        if run is None:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "Runner V3 execution is unknown",
            )
        snapshot = await self._client.get_workflow(run.run_id)
        return self._from_snapshot(execution_id, run, snapshot, collect=True)

    async def cancel(self, execution_id: str) -> ProviderOperationResult:
        run = self._runs.get(execution_id)
        if run is None:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "Runner V3 execution is unknown",
            )
        await self._client.cancel_workflow(run.run_id)
        return self._result(
            execution_id,
            ProviderExecutionStatus.CANCELED,
            "Runner V3 GitHub workflow cancellation requested",
            operation_id=run.run_id,
        )

    async def destroy(self, execution_id: str) -> ProviderOperationResult:
        run = self._runs.pop(execution_id, None)
        if run is None:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "Runner V3 execution is unknown",
            )
        return self._result(
            execution_id,
            ProviderExecutionStatus.DESTROYED,
            "Runner V3 adapter released local run state only",
            operation_id=run.run_id,
        )

    def _readiness_blocker(
        self,
        contract: ResourceExecutionContractV2,
        lease: ExecutionLease,
    ) -> str | None:
        qualification = self.qualify()
        if not qualification.qualified:
            return "; ".join(qualification.blockers)
        if contract.provider is not ResourceProvider.GITHUB:
            return "resource contract provider is not GitHub"
        if contract.provider_resource_type is not ResourceType.GITHUB_ACTIONS:
            return "resource contract is not a GitHub Actions resource"
        if contract.runner_profile_id != self._config.runner_profile_id:
            return "resource contract runner profile is not configured"
        if contract.source.repository_id != self._config.repository_id:
            return "resource contract repository is not configured"
        if lease.execution_id in self._runs:
            return "Runner V3 execution already exists"

        requirements = contract.requirements
        if contract.gpu_required or requirements.gpu_required:
            return "Runner V3 forbids GPU workloads"
        if contract.browser_required or requirements.browser_required:
            return "Runner V3 forbids browser workloads"
        if contract.docker_required or requirements.docker_required:
            return "Runner V3 forbids Docker workloads"
        if contract.package_install_required or requirements.package_install_required:
            return "Runner V3 forbids dynamic package installation"
        if (
            contract.persistent_workspace_required
            or requirements.persistent_workspace_required
            or contract.workspace_policy is WorkspacePolicy.PERSISTENT_WRITABLE
        ):
            return "Runner V3 forbids persistent workspaces"
        if contract.secrets_required or requirements.secrets_required or lease.secret_scope:
            return "Runner V3 forbids workload secrets"
        if contract.production_access_required or requirements.production_access_required:
            return "Runner V3 forbids production access"
        if (
            contract.deployment_authorized
            or requirements.deployment_required
            or contract.deployment_purpose is not DeploymentPurpose.NONE
        ):
            return "Runner V3 forbids deployment"
        if contract.network_policy.network_required or requirements.network_policy.network_required:
            return "Runner V3 forbids workload network access"
        if contract.concurrency_requirement != 1:
            return "Runner V3 accepts one bounded worker slot per execution"
        if contract.max_wall_clock_seconds > 1_800:
            return "Runner V3 timeout exceeds 1800 seconds"

        profile = contract.selected_profile
        if not profile.enabled:
            return "Runner V3 selected profile is disabled"
        if profile.runner_profile_id != self._config.runner_profile_id:
            return "Runner V3 selected profile does not match configuration"
        if profile.provider is not ResourceProvider.GITHUB:
            return "Runner V3 selected profile provider is not GitHub"
        if profile.resource_type is not ResourceType.GITHUB_ACTIONS:
            return "Runner V3 selected profile is not GitHub Actions"
        if contract.cpu_ceiling > profile.single_machine_cpu:
            return "Runner V3 CPU ceiling exceeds the selected profile"
        if contract.memory_mb_ceiling > profile.single_machine_memory_mb:
            return "Runner V3 memory ceiling exceeds the selected profile"
        if contract.disk_mb_ceiling > profile.single_machine_disk_mb:
            return "Runner V3 disk ceiling exceeds the selected profile"
        if contract.max_wall_clock_seconds > profile.maximum_duration_seconds:
            return "Runner V3 timeout exceeds the selected profile"
        if any(
            (
                profile.gpu,
                profile.browser,
                profile.docker,
                profile.package_install_capability,
                profile.persistent_workspace,
                profile.secrets_capability,
                profile.production_access_capability,
                profile.deployment_capability,
            )
        ):
            return "Runner V3 selected profile exposes a prohibited capability"
        if profile.network_capability or profile.allowed_destinations:
            return "Runner V3 selected profile exposes workload network access"

        if contract.workspace_policy is WorkspacePolicy.READ_ONLY:
            if contract.source_write_authorized or requirements.source_write_required:
                return "Runner V3 read-only work forbids source-write authority"
        elif contract.workspace_policy is WorkspacePolicy.EPHEMERAL_WRITABLE:
            if not contract.source_write_authorized or not requirements.source_write_required:
                return "Runner V3 patch work requires exact source-write authority"
            if not profile.source_write_capability:
                return "Runner V3 selected profile cannot apply an ephemeral patch"
        else:
            return "Runner V3 workspace policy is unsupported"
        return None

    def _validated_manifest(
        self,
        candidate: object,
        contract: ResourceExecutionContractV2,
        lease: ExecutionLease,
    ) -> tuple[RunnerV3JobManifest | None, str | None]:
        if not isinstance(candidate, RunnerV3JobManifest):
            return None, "Runner V3 manifest factory returned an invalid type"
        try:
            manifest = RunnerV3JobManifest.model_validate(
                candidate.model_dump(mode="python")
            )
        except ValidationError:
            return None, "Runner V3 manifest failed strict digest and schema validation"

        bindings = (
            (manifest.execution_id, lease.execution_id, "execution id"),
            (manifest.attempt_nonce, lease.attempt_nonce, "attempt nonce"),
            (manifest.runner_profile_id, contract.runner_profile_id, "runner profile"),
            (manifest.repository_id, contract.source.repository_id, "repository"),
            (manifest.source_commit, contract.source.source_commit, "source commit"),
            (manifest.source_tree, contract.source.source_tree, "source tree"),
            (manifest.contract_digest, contract.contract_digest, "contract digest"),
            (manifest.lease_digest, lease.lease_digest, "lease digest"),
            (manifest.commands_digest, contract.commands_digest, "commands digest"),
            (
                manifest.approval_digest,
                contract.approval.approval_digest,
                "approval digest",
            ),
            (manifest.policy_digest, contract.approval.policy_digest, "policy digest"),
            (manifest.issued_at, lease.issued_at, "issuance time"),
            (manifest.expires_at, lease.expires_at, "expiry time"),
            (manifest.cpu_ceiling, lease.cpu_ceiling, "CPU ceiling"),
            (manifest.memory_mb_ceiling, lease.memory_mb_ceiling, "memory ceiling"),
            (manifest.disk_mb_ceiling, lease.disk_mb_ceiling, "disk ceiling"),
            (manifest.timeout_seconds, lease.timeout_seconds, "timeout"),
            (
                manifest.source_write_authorized,
                contract.source_write_authorized,
                "source-write authority",
            ),
        )
        for observed, expected, label in bindings:
            if observed != expected:
                return None, f"Runner V3 manifest {label} mismatch"

        expected_mode = (
            RunnerV3WorkspaceMode.EPHEMERAL_PATCH
            if contract.workspace_policy is WorkspacePolicy.EPHEMERAL_WRITABLE
            else RunnerV3WorkspaceMode.READ_ONLY
        )
        if manifest.workspace_mode is not expected_mode:
            return None, "Runner V3 manifest workspace mode mismatch"
        if manifest.actions[0].value != "inspect_source":
            return None, "Runner V3 manifest must inspect source before engineering actions"
        return manifest, None

    def _from_snapshot(
        self,
        execution_id: str,
        run: _RunnerV3Run,
        snapshot: RunnerV3WorkflowSnapshot,
        *,
        collect: bool,
    ) -> ProviderOperationResult:
        identity_matches = (
            snapshot.run_id == run.run_id
            and snapshot.source_commit == run.source_commit
            and snapshot.source_tree == run.source_tree
            and snapshot.manifest_digest == run.manifest_digest
        )
        if not identity_matches:
            return self._result(
                execution_id,
                ProviderExecutionStatus.FAILED,
                "Runner V3 workflow identity does not match the dispatched builder job",
                operation_id=run.run_id,
            )
        if snapshot.status != "completed":
            return self._result(
                execution_id,
                ProviderExecutionStatus.RUNNING,
                "Runner V3 GitHub builder workflow has not completed",
                operation_id=run.run_id,
            )
        if not collect:
            return self._result(
                execution_id,
                ProviderExecutionStatus.RUNNING,
                "Runner V3 workflow completed and awaits evidence collection",
                operation_id=run.run_id,
            )
        succeeded = (
            snapshot.conclusion == "success"
            and snapshot.outcome is RunnerV3Outcome.SUCCEEDED
            and snapshot.receipt_digest is not None
        )
        if succeeded:
            return self._result(
                execution_id,
                ProviderExecutionStatus.SUCCEEDED,
                "Runner V3 builder evidence collected; independent verification is still required",
                operation_id=run.run_id,
                evidence_digest=snapshot.receipt_digest,
            )
        return self._result(
            execution_id,
            ProviderExecutionStatus.FAILED,
            (
                "Runner V3 workflow did not produce trusted builder evidence; "
                "independent verification remains separate"
            ),
            operation_id=run.run_id,
        )

    def _runtime_state_is_fresh(self) -> bool:
        verified_at = self._state.last_verified_at
        now = self._clock()
        if verified_at is None or now.tzinfo is None or now.utcoffset() is None:
            return False
        age = (now - verified_at).total_seconds()
        return 0 <= age <= self._config.maximum_state_age_seconds

    @staticmethod
    def _result(
        execution_id: str,
        status: ProviderExecutionStatus,
        reason: str,
        *,
        operation_id: str | None = None,
        evidence_digest: str | None = None,
    ) -> ProviderOperationResult:
        return ProviderOperationResult(
            provider=ResourceProvider.GITHUB,
            execution_id=execution_id,
            status=status,
            operation_id=operation_id,
            reason=reason,
            verification_outcome=VerificationOutcome.NOT_APPLICABLE,
            evidence_digest=evidence_digest,
        )
