from datetime import UTC, datetime, timedelta

import pytest

from liltweak.resource.catalog import ResourceCatalog
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
from liltweak.resource.scheduler import EliminationStage, ResourceScheduler

NOW = datetime(2026, 9, 1, tzinfo=UTC)


def _requirements(*, ceiling: int = 5_000) -> WorkloadRequirements:
    return WorkloadRequirements(
        requirement_id="req_scheduler",
        job_id="job_scheduler",
        required_cpu=2,
        required_memory_mb=4_096,
        required_disk_mb=4_096,
        shared_memory_required=True,
        network_policy=NetworkPolicy(),
        estimated_duration_seconds=300,
        parallelizable=False,
        desired_parallelism=1,
        verification_level=VerificationLevel.FULL,
        authority=WorkloadAuthority(
            requested_by="owner",
            risk_level=RiskLevel.HIGH,
            maximum_resource_risk=RiskLevel.LOW,
            maximum_authorized_cost_microusd=ceiling,
            approval_digest="a" * 64,
            policy_digest="b" * 64,
        ),
    )


def _profile(
    profile_id: str,
    *,
    qualification: QualificationStatus = QualificationStatus.QUALIFIED,
    health: HealthStatus = HealthStatus.HEALTHY,
    last_verified_at: datetime = NOW,
    single_memory_mb: int = 8_192,
    rate: int = 1,
    included_allowance: int = 0,
    risk_surface: RiskLevel = RiskLevel.LOW,
) -> ResourceProfile:
    return ResourceProfile(
        runner_profile_id=profile_id,
        provider=ResourceProvider.GITHUB,
        resource_type=ResourceType.GITHUB_ACTIONS,
        single_machine_cpu=2,
        single_machine_memory_mb=single_memory_mb,
        single_machine_disk_mb=16_384,
        aggregate_parallel_cpu=64,
        aggregate_parallel_memory_mb=262_144,
        parallel_limit=32,
        maximum_duration_seconds=21_600,
        qualification_status=qualification,
        health_status=health,
        last_qualified_at=NOW,
        last_verified_at=last_verified_at,
        estimated_cpu_microusd_per_second=rate,
        estimated_memory_microusd_per_gb_second=rate,
        estimated_storage_microusd_per_gb_second=rate,
        included_allowance_microusd=included_allowance,
        current_usage_microusd=0,
        risk_surface=risk_surface,
        priority=10,
    )


def test_scheduler_applies_ordered_gates_then_prefers_included_capacity() -> None:
    catalog = ResourceCatalog(
        (
            _profile("01-unqualified", qualification=QualificationStatus.UNQUALIFIED),
            _profile("02-stale", last_verified_at=NOW - timedelta(hours=2)),
            _profile("03-incapable", single_memory_mb=1_024),
            _profile("04-unauthorized-risk", risk_surface=RiskLevel.HIGH),
            _profile("05-over-cost", rate=10),
            _profile("06-paid"),
            _profile("07-included", included_allowance=3_000),
        )
    )

    decision = ResourceScheduler(
        maximum_health_age_seconds=600,
        maximum_qualification_age_seconds=86_400,
    ).select(_requirements(), catalog, as_of=NOW)

    assert decision.selected_profile is not None
    assert decision.selected_profile.runner_profile_id == "07-included"
    assert decision.estimate is not None
    assert decision.estimate.net_cost_microusd == 0
    assert tuple(item.stage for item in decision.eliminations) == (
        EliminationStage.QUALIFICATION,
        EliminationStage.HEALTH,
        EliminationStage.CAPABILITY,
        EliminationStage.AUTHORIZATION,
        EliminationStage.COST,
    )


def test_scheduler_never_treats_aggregate_memory_as_shared_memory() -> None:
    catalog = ResourceCatalog((_profile("aggregate-only", single_memory_mb=1_024),))

    decision = ResourceScheduler().select(_requirements(), catalog, as_of=NOW)

    assert decision.selected_profile is None
    assert decision.eliminations[0].stage is EliminationStage.CAPABILITY
    assert "single-machine memory" in decision.eliminations[0].reason


def test_scheduler_rejects_stale_qualification_even_when_health_is_fresh() -> None:
    profile = _profile("stale-qualification").model_copy(
        update={"last_qualified_at": NOW - timedelta(days=2)}
    )

    decision = ResourceScheduler(maximum_qualification_age_seconds=86_400).select(
        _requirements(),
        ResourceCatalog((profile,)),
        as_of=NOW,
    )

    assert decision.selected_profile is None
    assert decision.eliminations[0].stage is EliminationStage.QUALIFICATION
    assert "stale" in decision.eliminations[0].reason


def test_scheduler_rejects_unauthorized_network_expansion() -> None:
    profile = _profile("network-limited").model_copy(
        update={
            "network_capability": True,
            "allowed_destinations": ("api.github.com",),
        }
    )
    approved_network = NetworkPolicy(
        network_required=True,
        allowed_destinations=("api.github.com", "uploads.github.com"),
    )
    base_requirements = _requirements()
    requirements = WorkloadRequirements.model_validate(
        {
            **base_requirements.model_dump(mode="python"),
            "network_policy": approved_network,
            "authority": base_requirements.authority.model_copy(
                update={"network_policy": approved_network}
            ),
        }
    )

    decision = ResourceScheduler().select(
        requirements,
        ResourceCatalog((profile,)),
        as_of=NOW,
    )

    assert decision.selected_profile is None
    assert decision.eliminations[0].stage is EliminationStage.CAPABILITY
    assert "destinations" in decision.eliminations[0].reason


def test_scheduler_revalidates_forged_workload_authority_objects() -> None:
    forged_requirements = _requirements().model_copy(update={"package_install_required": True})
    capable_profile = _profile("package-capable").model_copy(
        update={"package_install_capability": True}
    )

    with pytest.raises(ValueError, match="package installation"):
        ResourceScheduler().select(
            forged_requirements,
            ResourceCatalog((capable_profile,)),
            as_of=NOW,
        )
