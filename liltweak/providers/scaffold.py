from __future__ import annotations

from ..resource.contracts import (
    HealthStatus,
    ResourceExecutionContractV2,
    ResourceProfile,
    ResourceProvider,
    ResourceType,
    WorkloadRequirements,
)
from ..resource.estimator import ResourceCostEstimate, ResourceEstimator
from ..resource.leases import ExecutionLease
from .contracts import (
    ProviderCapabilities,
    ProviderExecutionStatus,
    ProviderHealth,
    ProviderOperationResult,
    ProviderQualification,
)


class FailClosedProviderScaffold:
    def __init__(
        self,
        *,
        provider: ResourceProvider,
        resource_types: tuple[ResourceType, ...],
        builder: bool,
        independent_verifier: bool,
    ) -> None:
        self._provider = provider
        self._resource_types = resource_types
        self._builder = builder
        self._independent_verifier = independent_verifier

    def qualify(self) -> ProviderQualification:
        return ProviderQualification(
            provider=self._provider,
            qualified=False,
            blockers=(
                f"{self._provider.value} adapter is scaffolded, unqualified, "
                "disconnected, and inactive",
            ),
        )

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider=self._provider,
            resource_types=self._resource_types,
            builder=self._builder,
            independent_verifier=self._independent_verifier,
            preview_only=True,
            production_deployment=False,
        )

    def health(self) -> ProviderHealth:
        return ProviderHealth(
            provider=self._provider,
            status=HealthStatus.UNKNOWN,
            connected=False,
            active=False,
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
        return self._blocked(lease.execution_id, "provision")

    async def execute(
        self,
        *,
        contract: ResourceExecutionContractV2,
        lease: ExecutionLease,
    ) -> ProviderOperationResult:
        return self._blocked(lease.execution_id, "execute")

    async def status(self, execution_id: str) -> ProviderOperationResult:
        return self._blocked(execution_id, "status")

    async def collect(self, execution_id: str) -> ProviderOperationResult:
        return self._blocked(execution_id, "collect")

    async def cancel(self, execution_id: str) -> ProviderOperationResult:
        return self._blocked(execution_id, "cancel")

    async def destroy(self, execution_id: str) -> ProviderOperationResult:
        return self._blocked(execution_id, "destroy")

    def _blocked(self, execution_id: str, operation: str) -> ProviderOperationResult:
        return ProviderOperationResult(
            provider=self._provider,
            execution_id=execution_id,
            status=ProviderExecutionStatus.BLOCKED,
            reason=(
                f"{self._provider.value} {operation} is blocked because the adapter is "
                "scaffolded, unqualified, disconnected, and inactive"
            ),
        )
