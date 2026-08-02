from __future__ import annotations

from liltweak.canonical_lifecycle import CapabilityName, CapabilityStatus
from liltweak.workbench_store import WorkbenchStore


def enable_test_canonical_capabilities(
    store: WorkbenchStore,
    *names: CapabilityName,
) -> WorkbenchStore:
    """Record explicit synthetic capability authority for an isolated test database."""

    selected = names or tuple(CapabilityName)
    for name in selected:
        current = store.canonical.capability(name)
        store.canonical.update_capability(
            name,
            expected_version=current.version,
            status=CapabilityStatus.OPERATIONAL,
            feature_enabled=True,
            installed=True,
            configured=True,
            connected=True,
            healthy=True,
            qualified=True,
            authorized=True,
            operational=True,
            detail_code="isolated_test_authority",
            actor_id="test:canonical_authority",
        )
    return store
