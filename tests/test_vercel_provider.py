import pytest

from liltweak.providers.contracts import ProviderExecutionStatus
from liltweak.providers.vercel.sandbox import VercelSandboxProvider
from liltweak.resource.contracts import ResourceProvider, ResourceType
from tests.resource_provider_helpers import provider_contract_and_lease


@pytest.mark.asyncio
async def test_vercel_scaffold_exposes_capability_but_cannot_execute() -> None:
    provider = VercelSandboxProvider()
    contract, lease = provider_contract_and_lease(
        provider=ResourceProvider.VERCEL,
        resource_type=ResourceType.VERCEL_SANDBOX,
        runner_profile_id="vercel-sandbox",
    )

    assert provider.qualify().qualified is False
    assert provider.health().connected is False
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
