from datetime import UTC, datetime

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
from liltweak.resource.director import ResourceDirector, ResourceDirectorMode

NOW = datetime(2026, 9, 1, tzinfo=UTC)


def _catalog() -> ResourceCatalog:
    return ResourceCatalog(
        (
            ResourceProfile(
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
                estimated_cpu_microusd_per_second=1,
                estimated_memory_microusd_per_gb_second=1,
                estimated_storage_microusd_per_gb_second=1,
                included_allowance_microusd=10_000,
                current_usage_microusd=0,
                risk_surface=RiskLevel.LOW,
                priority=10,
            ),
        )
    )


def _requirements() -> WorkloadRequirements:
    return WorkloadRequirements(
        requirement_id="req_shadow",
        job_id="job_shadow",
        required_cpu=2,
        required_memory_mb=2_048,
        required_disk_mb=4_096,
        shared_memory_required=True,
        network_policy=NetworkPolicy(),
        estimated_duration_seconds=300,
        parallelizable=False,
        desired_parallelism=1,
        verification_level=VerificationLevel.INDEPENDENT,
        authority=WorkloadAuthority(
            requested_by="owner",
            risk_level=RiskLevel.LOW,
            maximum_authorized_cost_microusd=50_000,
            approval_digest="a" * 64,
            policy_digest="b" * 64,
        ),
    )


def test_director_defaults_to_disabled_and_does_not_calculate_or_dispatch() -> None:
    director = ResourceDirector.from_environment(_catalog(), environment={})

    decision = director.route(
        _requirements(),
        as_of=NOW,
        existing_execution_decision="local-readonly-v1",
    )

    assert decision.mode is ResourceDirectorMode.DISABLED
    assert decision.route is None
    assert decision.dispatch_authorized is False
    assert decision.provider_provisioned is False
    assert decision.command_sent is False


def test_shadow_mode_records_comparison_without_provisioning_or_command() -> None:
    director = ResourceDirector.from_environment(
        _catalog(),
        environment={"RESOURCE_DIRECTOR_MODE": "shadow"},
    )

    decision = director.route(
        _requirements(),
        as_of=NOW,
        existing_execution_decision="local-readonly-v1",
    )

    assert decision.mode is ResourceDirectorMode.SHADOW
    assert decision.existing_execution_decision == "local-readonly-v1"
    assert decision.route is not None
    assert decision.route.selected_profile is not None
    assert decision.route.selected_profile.runner_profile_id == "github-actions-standard"
    assert decision.dispatch_authorized is False
    assert decision.provider_provisioned is False
    assert decision.command_sent is False
    assert decision.evidence_digest != decision.route.decision_digest


def test_active_mode_without_separate_activation_remains_fail_closed() -> None:
    director = ResourceDirector.from_environment(
        _catalog(),
        environment={"RESOURCE_DIRECTOR_MODE": "active"},
    )

    decision = director.route(
        _requirements(),
        as_of=NOW,
        existing_execution_decision="local-readonly-v1",
    )

    assert decision.route is not None
    assert decision.dispatch_authorized is False
    assert "activation" in decision.blocked_reason


def test_unauthorized_failover_never_dispatches_to_an_alternative_provider() -> None:
    requirements = _requirements()
    assert requirements.authority.failover_authorized is False
    primary = _catalog().snapshot()[0]
    expensive_alternative = primary.model_copy(
        update={
            "runner_profile_id": "github-actions-expensive-alternative",
            "estimated_cpu_microusd_per_second": 20,
            "estimated_memory_microusd_per_gb_second": 20,
            "estimated_storage_microusd_per_gb_second": 20,
            "included_allowance_microusd": 0,
        }
    )
    director = ResourceDirector.from_environment(
        ResourceCatalog((primary, expensive_alternative)),
        environment={"RESOURCE_DIRECTOR_MODE": "active"},
    )

    decision = director.route(
        requirements,
        as_of=NOW,
        existing_execution_decision="failed-primary",
        failed_runner_profile_id=primary.runner_profile_id,
    )

    assert decision.route is None
    assert decision.dispatch_authorized is False
    assert decision.provider_provisioned is False
    assert decision.command_sent is False
    assert "failover" in decision.blocked_reason
