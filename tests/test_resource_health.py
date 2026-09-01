from datetime import UTC, datetime, timedelta

import pytest

from liltweak.resource.contracts import (
    HealthStatus,
    QualificationStatus,
    ResourceProfile,
    ResourceProvider,
    ResourceType,
)
from liltweak.resource.health import ResourceHealthError, ResourceHealthRegistry

NOW = datetime(2026, 9, 1, tzinfo=UTC)


def _profile() -> ResourceProfile:
    return ResourceProfile(
        runner_profile_id="github-actions-standard",
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
        health_status=HealthStatus.UNKNOWN,
        last_qualified_at=NOW,
        estimated_cpu_microusd_per_second=1,
        estimated_memory_microusd_per_gb_second=1,
        estimated_storage_microusd_per_gb_second=1,
        included_allowance_microusd=0,
        current_usage_microusd=0,
        priority=10,
    )


def test_health_registry_rejects_replayed_sequences_and_expires_fail_closed() -> None:
    registry = ResourceHealthRegistry()
    record = registry.record(
        runner_profile_id="github-actions-standard",
        status=HealthStatus.HEALTHY,
        checked_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        sequence=4,
        evidence_digest="a" * 64,
    )

    healthy = registry.apply(_profile(), as_of=NOW + timedelta(minutes=1))
    assert healthy.health_status is HealthStatus.HEALTHY
    assert healthy.last_verified_at == NOW
    assert record.record_digest != record.evidence_digest

    with pytest.raises(ResourceHealthError, match="sequence"):
        registry.record(
            runner_profile_id="github-actions-standard",
            status=HealthStatus.HEALTHY,
            checked_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            sequence=4,
            evidence_digest="b" * 64,
        )

    expired = registry.apply(_profile(), as_of=NOW + timedelta(minutes=6))
    assert expired.health_status is HealthStatus.UNKNOWN
    assert expired.last_verified_at is None
