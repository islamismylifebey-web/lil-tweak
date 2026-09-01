import pytest

from liltweak.providers.cloudflare.workflows import CloudflareOrchestrationProvider
from liltweak.providers.contracts import ProviderExecutionStatus
from liltweak.resource.contracts import ResourceProvider, ResourceType
from tests.resource_provider_helpers import provider_contract_and_lease


@pytest.mark.asyncio
async def test_cloudflare_scaffold_exposes_orchestration_but_cannot_execute() -> None:
    provider = CloudflareOrchestrationProvider()
    contract, lease = provider_contract_and_lease(
        provider=ResourceProvider.CLOUDFLARE,
        resource_type=ResourceType.CLOUDFLARE_WORKFLOWS,
        runner_profile_id="cloudflare-workflows",
    )

    assert provider.qualify().qualified is False
    assert provider.health().active is False
    assert provider.capabilities().production_deployment is False
    assert (await provider.provision(contract=contract, lease=lease)).status is (
        ProviderExecutionStatus.BLOCKED
    )
    assert (await provider.execute(contract=contract, lease=lease)).status is (
        ProviderExecutionStatus.BLOCKED
    )
    assert (await provider.status(lease.execution_id)).status is ProviderExecutionStatus.BLOCKED
    assert (await provider.collect(lease.execution_id)).status is ProviderExecutionStatus.BLOCKED
    assert (await provider.cancel(lease.execution_id)).status is ProviderExecutionStatus.BLOCKED
    assert (await provider.destroy(lease.execution_id)).status is ProviderExecutionStatus.BLOCKED
