from datetime import UTC, datetime

import pytest

from liltweak.resource.catalog import ResourceCatalog
from liltweak.resource.contracts import (
    HealthStatus,
    QualificationStatus,
    ResourceProfile,
    ResourceProvider,
    ResourceType,
)

NOW = datetime(2026, 9, 1, tzinfo=UTC)


def _profile(profile_id: str, *, enabled: bool = True) -> ResourceProfile:
    return ResourceProfile(
        runner_profile_id=profile_id,
        provider=ResourceProvider.GITHUB,
        resource_type=ResourceType.GITHUB_ACTIONS,
        single_machine_cpu=2,
        single_machine_memory_mb=7_000,
        single_machine_disk_mb=14_000,
        aggregate_parallel_cpu=40,
        aggregate_parallel_memory_mb=140_000,
        parallel_limit=20,
        maximum_duration_seconds=21_600,
        qualification_status=QualificationStatus.QUALIFIED,
        health_status=HealthStatus.HEALTHY,
        last_qualified_at=NOW,
        last_verified_at=NOW,
        estimated_cpu_microusd_per_second=2,
        estimated_memory_microusd_per_gb_second=1,
        estimated_storage_microusd_per_gb_second=1,
        included_allowance_microusd=1_000,
        current_usage_microusd=0,
        priority=10,
        enabled=enabled,
    )


def test_catalog_rejects_duplicate_server_profile_ids() -> None:
    with pytest.raises(ValueError, match="unique"):
        ResourceCatalog((_profile("duplicate"), _profile("duplicate")))


def test_catalog_returns_immutable_deterministic_snapshots() -> None:
    disabled = _profile("z-disabled", enabled=False)
    enabled = _profile("a-enabled")
    catalog = ResourceCatalog((disabled, enabled))

    assert tuple(profile.runner_profile_id for profile in catalog.snapshot()) == (
        "a-enabled",
        "z-disabled",
    )
    assert catalog.enabled_profiles() == (enabled,)
    assert catalog.get("a-enabled") is enabled
    with pytest.raises(KeyError):
        catalog.get("missing")


def test_catalog_revalidates_forged_profile_and_pricing_objects() -> None:
    forged = _profile("forged-pricing").model_copy(update={"estimated_cpu_microusd_per_second": -1})

    with pytest.raises(ValueError):
        ResourceCatalog((forged,))
