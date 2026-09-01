from __future__ import annotations

from ...resource.contracts import ResourceProvider, ResourceType
from ..scaffold import FailClosedProviderScaffold


class GitHubCodespacesProvider(FailClosedProviderScaffold):
    """Disconnected Codespaces builder scaffold; no API or credential integration."""

    def __init__(self) -> None:
        super().__init__(
            provider=ResourceProvider.GITHUB,
            resource_types=(ResourceType.GITHUB_CODESPACES,),
            builder=True,
            independent_verifier=False,
        )
