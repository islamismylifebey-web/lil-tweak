from __future__ import annotations

from ...resource.contracts import (
    HealthStatus,
    QualificationStatus,
    ResourceProfile,
    ResourceProvider,
    ResourceType,
    RiskLevel,
    WorkspacePolicy,
)
from .runner_v3_contracts import RUNNER_V3_PROFILE_ID


def github_runner_v3_profile() -> ResourceProfile:
    """Return the conservative, live-unqualified first Runner V3 profile."""

    return ResourceProfile(
        runner_profile_id=RUNNER_V3_PROFILE_ID,
        provider=ResourceProvider.GITHUB,
        resource_type=ResourceType.GITHUB_ACTIONS,
        single_machine_cpu=2,
        single_machine_memory_mb=7_000,
        single_machine_disk_mb=14_000,
        aggregate_parallel_cpu=2,
        aggregate_parallel_memory_mb=7_000,
        parallel_limit=1,
        maximum_duration_seconds=1_800,
        gpu=False,
        browser=False,
        docker=False,
        network_capability=False,
        allowed_destinations=(),
        package_install_capability=False,
        workspace_policy=WorkspacePolicy.EPHEMERAL_WRITABLE,
        persistent_workspace=False,
        secrets_capability=False,
        production_access_capability=False,
        source_write_capability=True,
        deployment_capability=False,
        qualification_status=QualificationStatus.UNQUALIFIED,
        health_status=HealthStatus.UNKNOWN,
        last_qualified_at=None,
        last_verified_at=None,
        estimated_cpu_microusd_per_second=0,
        estimated_memory_microusd_per_gb_second=0,
        estimated_storage_microusd_per_gb_second=0,
        included_allowance_microusd=0,
        current_usage_microusd=0,
        risk_surface=RiskLevel.LOW,
        priority=100,
        enabled=True,
    )
