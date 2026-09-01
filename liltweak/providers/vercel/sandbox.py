from __future__ import annotations

from ...resource.contracts import ResourceProvider, ResourceType
from ..scaffold import FailClosedProviderScaffold


class VercelSandboxProvider(FailClosedProviderScaffold):
    def __init__(self) -> None:
        super().__init__(
            provider=ResourceProvider.VERCEL,
            resource_types=(ResourceType.VERCEL_SANDBOX, ResourceType.VERCEL_BUILD),
            builder=True,
            independent_verifier=False,
        )
