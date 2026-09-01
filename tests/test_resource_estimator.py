from datetime import UTC, datetime

from liltweak.resource.contracts import (
    HealthStatus,
    NetworkPolicy,
    QualificationStatus,
    ResourceProfile,
    ResourceProvider,
    ResourceType,
    RiskLevel,
    VerificationLevel,
    WorkloadAuthority,
    WorkloadRequirements,
)
from liltweak.resource.estimator import ResourceEstimator

NOW = datetime(2026, 9, 1, tzinfo=UTC)


def _requirements() -> WorkloadRequirements:
    return WorkloadRequirements(
        requirement_id="req_estimator",
        job_id="job_estimator",
        required_cpu=2,
        required_memory_mb=2_048,
        required_disk_mb=4_096,
        shared_memory_required=True,
        network_policy=NetworkPolicy(),
        estimated_duration_seconds=300,
        parallelizable=False,
        desired_parallelism=1,
        verification_level=VerificationLevel.FULL,
        authority=WorkloadAuthority(
            requested_by="owner",
            risk_level=RiskLevel.LOW,
            maximum_authorized_cost_microusd=50_000,
            approval_digest="a" * 64,
            policy_digest="b" * 64,
        ),
    )


def _profile(*, included: int, used: int) -> ResourceProfile:
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
        health_status=HealthStatus.HEALTHY,
        last_qualified_at=NOW,
        last_verified_at=NOW,
        estimated_cpu_microusd_per_second=2,
        estimated_memory_microusd_per_gb_second=1,
        estimated_storage_microusd_per_gb_second=1,
        included_allowance_microusd=included,
        current_usage_microusd=used,
        priority=10,
    )


def test_estimate_records_components_and_remaining_included_allowance() -> None:
    estimate = ResourceEstimator().estimate(
        _requirements(),
        _profile(included=1_000, used=0),
    )

    assert estimate.cpu_cost_microusd == 1_200
    assert estimate.memory_cost_microusd == 600
    assert estimate.storage_cost_microusd == 1_200
    assert estimate.gross_cost_microusd == 3_000
    assert estimate.included_allowance_applied_microusd == 1_000
    assert estimate.net_cost_microusd == 2_000


def test_used_included_allowance_does_not_hide_metered_cost() -> None:
    estimate = ResourceEstimator().estimate(
        _requirements(),
        _profile(included=500, used=500),
    )

    assert estimate.included_allowance_applied_microusd == 0
    assert estimate.net_cost_microusd == 3_000
