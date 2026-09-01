from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from ...resource.contracts import (
    HealthStatus,
    QualificationStatus,
    ResourceExecutionContractV2,
    ResourceProfile,
    ResourceProvider,
    ResourceType,
    WorkloadRequirements,
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
from .contracts import GitHubActionsClient, GitHubProviderConfig, GitHubWorkflowSnapshot


class GitHubActionsProvider:
    """GitHub Actions adapter restricted to independent verification workflows."""

    def __init__(
        self,
        *,
        config: GitHubProviderConfig,
        state: ProviderRuntimeState,
        client: GitHubActionsClient,
        lease_signing_key: bytes,
        minimum_authorization_sequence: int,
        revocation_epoch: int,
        clock: Callable[[], datetime],
        maximum_state_age_seconds: int = 300,
    ) -> None:
        if not isinstance(lease_signing_key, bytes) or len(lease_signing_key) != 32:
            raise ValueError("GitHub provider lease signing key must contain exactly 32 bytes")
        if maximum_state_age_seconds <= 0:
            raise ValueError("GitHub provider state freshness limit must be positive")
        self._config = config
        self._state = state
        self._client = client
        self._lease_signing_key = lease_signing_key
        self._minimum_authorization_sequence = minimum_authorization_sequence
        self._revocation_epoch = revocation_epoch
        self._clock = clock
        self._maximum_state_age_seconds = maximum_state_age_seconds
        self._leases = ExecutionLeaseRegistry()
        self._runs: dict[str, tuple[str, str]] = {}

    def qualify(self) -> ProviderQualification:
        blockers: list[str] = []
        if self._state.qualification_status is not QualificationStatus.QUALIFIED:
            blockers.append("GitHub provider is not qualified")
        if self._state.health_status is not HealthStatus.HEALTHY:
            blockers.append("GitHub provider is not healthy")
        elif not self._runtime_state_is_fresh():
            blockers.append("GitHub provider runtime health verification is stale")
        if not self._state.connected:
            blockers.append("GitHub provider is not connected")
        if not self._state.active:
            blockers.append("GitHub provider is not active")
        return ProviderQualification(
            provider=ResourceProvider.GITHUB,
            qualified=not blockers,
            blockers=tuple(blockers),
        )

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider=ResourceProvider.GITHUB,
            resource_types=(ResourceType.GITHUB_ACTIONS,),
            builder=False,
            independent_verifier=True,
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
            "GitHub verification workflow is eligible for dispatch",
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
        run_id = await self._client.dispatch_verification(
            repository_id=self._config.repository_id,
            workflow_path=self._config.workflow_path,
            source_commit=contract.source.source_commit,
            lease_digest=lease.lease_digest,
        )
        self._runs[lease.execution_id] = (run_id, contract.source.source_commit)
        return self._result(
            lease.execution_id,
            ProviderExecutionStatus.RUNNING,
            "GitHub independent verification workflow dispatched",
            operation_id=run_id,
            verification_outcome=VerificationOutcome.PENDING,
        )

    async def status(self, execution_id: str) -> ProviderOperationResult:
        run = self._runs.get(execution_id)
        if run is None:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "GitHub verification run is unknown",
            )
        snapshot = await self._client.get_workflow(run[0])
        return self._from_snapshot(execution_id, snapshot, run[1], collect=False)

    async def collect(self, execution_id: str) -> ProviderOperationResult:
        run = self._runs.get(execution_id)
        if run is None:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "GitHub verification run is unknown",
            )
        snapshot = await self._client.get_workflow(run[0])
        return self._from_snapshot(execution_id, snapshot, run[1], collect=True)

    async def cancel(self, execution_id: str) -> ProviderOperationResult:
        run = self._runs.get(execution_id)
        if run is None:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "GitHub verification run is unknown",
            )
        await self._client.cancel_workflow(run[0])
        return self._result(
            execution_id,
            ProviderExecutionStatus.CANCELED,
            "GitHub verification workflow canceled",
            operation_id=run[0],
            verification_outcome=VerificationOutcome.FAILED,
        )

    async def destroy(self, execution_id: str) -> ProviderOperationResult:
        run = self._runs.pop(execution_id, None)
        if run is None:
            return self._result(
                execution_id,
                ProviderExecutionStatus.BLOCKED,
                "GitHub verification run is unknown",
            )
        return self._result(
            execution_id,
            ProviderExecutionStatus.DESTROYED,
            "GitHub adapter released local run state",
            operation_id=run[0],
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
        if contract.source_write_authorized or contract.deployment_authorized:
            return "GitHub verification adapter forbids source write and deployment"
        if contract.production_access_required:
            return "GitHub verification adapter forbids production access"
        if lease.execution_id in self._runs:
            return "GitHub verification execution already exists"
        return None

    def _from_snapshot(
        self,
        execution_id: str,
        snapshot: GitHubWorkflowSnapshot,
        expected_source_commit: str,
        *,
        collect: bool,
    ) -> ProviderOperationResult:
        if snapshot.status != "completed":
            return self._result(
                execution_id,
                ProviderExecutionStatus.RUNNING,
                "GitHub verification workflow has not completed",
                operation_id=snapshot.run_id,
                verification_outcome=VerificationOutcome.PENDING,
            )
        verified = (
            collect
            and snapshot.conclusion == "success"
            and snapshot.required_checks_passed
            and self._required_checks_completed(snapshot)
            and snapshot.evidence_digest is not None
            and snapshot.source_commit == expected_source_commit
        )
        if verified:
            return self._result(
                execution_id,
                ProviderExecutionStatus.SUCCEEDED,
                "GitHub independent verification evidence passed",
                operation_id=snapshot.run_id,
                verification_outcome=VerificationOutcome.VERIFIED,
                evidence_digest=snapshot.evidence_digest,
            )
        return self._result(
            execution_id,
            ProviderExecutionStatus.FAILED,
            "GitHub workflow result cannot establish independent verification",
            operation_id=snapshot.run_id,
            verification_outcome=VerificationOutcome.FAILED,
            evidence_digest=snapshot.evidence_digest,
        )

    def _runtime_state_is_fresh(self) -> bool:
        verified_at = self._state.last_verified_at
        now = self._clock()
        if verified_at is None or now.tzinfo is None or now.utcoffset() is None:
            return False
        age = (now - verified_at).total_seconds()
        return 0 <= age <= self._maximum_state_age_seconds

    def _required_checks_completed(self, snapshot: GitHubWorkflowSnapshot) -> bool:
        completed = {item.casefold() for item in snapshot.completed_checks}
        required = {item.casefold() for item in self._config.required_checks}
        return required <= completed

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
            provider=ResourceProvider.GITHUB,
            execution_id=execution_id,
            status=status,
            operation_id=operation_id,
            reason=reason,
            verification_outcome=verification_outcome,
            evidence_digest=evidence_digest,
        )
