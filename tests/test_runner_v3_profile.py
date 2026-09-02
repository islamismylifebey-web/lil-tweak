from __future__ import annotations

from liltweak.providers.github.runner_v3_contracts import RUNNER_V3_PROFILE_ID
from liltweak.providers.github.runner_v3_profile import github_runner_v3_profile
from liltweak.resource.catalog import ResourceCatalog
from liltweak.resource.contracts import (
    HealthStatus,
    QualificationStatus,
    ResourceProvider,
    ResourceType,
    RiskLevel,
    WorkspacePolicy,
)


def test_first_factory_profile_is_conservative_and_headless() -> None:
    profile = github_runner_v3_profile()

    assert profile.runner_profile_id == RUNNER_V3_PROFILE_ID
    assert profile.provider is ResourceProvider.GITHUB
    assert profile.resource_type is ResourceType.GITHUB_ACTIONS
    assert profile.single_machine_cpu == 2
    assert profile.single_machine_memory_mb == 7_000
    assert profile.single_machine_disk_mb == 14_000
    assert profile.aggregate_parallel_cpu == 2
    assert profile.aggregate_parallel_memory_mb == 7_000
    assert profile.parallel_limit == 1
    assert profile.maximum_duration_seconds == 1_800
    assert profile.workspace_policy is WorkspacePolicy.EPHEMERAL_WRITABLE
    assert profile.source_write_capability is True
    assert profile.gpu is False
    assert profile.browser is False
    assert profile.docker is False
    assert profile.network_capability is False
    assert profile.allowed_destinations == ()
    assert profile.package_install_capability is False
    assert profile.persistent_workspace is False
    assert profile.secrets_capability is False
    assert profile.production_access_capability is False
    assert profile.deployment_capability is False
    assert profile.risk_surface is RiskLevel.LOW
    assert profile.priority == 100
    assert profile.enabled is True


def test_first_factory_profile_starts_live_unqualified() -> None:
    profile = github_runner_v3_profile()

    assert profile.qualification_status is QualificationStatus.UNQUALIFIED
    assert profile.health_status is HealthStatus.UNKNOWN
    assert profile.last_qualified_at is None
    assert profile.last_verified_at is None
    assert profile.estimated_cpu_microusd_per_second == 0
    assert profile.estimated_memory_microusd_per_gb_second == 0
    assert profile.estimated_storage_microusd_per_gb_second == 0
    assert profile.included_allowance_microusd == 0
    assert profile.current_usage_microusd == 0
    assert len(profile.profile_digest) == 64


def test_first_factory_profile_is_catalog_compatible() -> None:
    profile = github_runner_v3_profile()
    catalog = ResourceCatalog((profile,))

    assert catalog.snapshot() == (profile,)
    assert catalog.enabled_profiles() == (profile,)
    assert catalog.get(RUNNER_V3_PROFILE_ID) == profile
