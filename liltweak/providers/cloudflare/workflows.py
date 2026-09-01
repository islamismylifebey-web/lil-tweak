from __future__ import annotations

from ...resource.contracts import ResourceProvider, ResourceType
from ..scaffold import FailClosedProviderScaffold


class CloudflareOrchestrationProvider(FailClosedProviderScaffold):
    def __init__(self) -> None:
        super().__init__(
            provider=ResourceProvider.CLOUDFLARE,
            resource_types=(
                ResourceType.CLOUDFLARE_WORKERS,
                ResourceType.CLOUDFLARE_WORKFLOWS,
                ResourceType.CLOUDFLARE_QUEUES,
                ResourceType.CLOUDFLARE_CONTAINERS,
            ),
            builder=False,
            independent_verifier=False,
        )
