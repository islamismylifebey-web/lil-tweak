from datetime import UTC, datetime, timedelta

from liltweak.resource.contracts import (
    ApprovalBinding,
    HealthStatus,
    ImmutableSourceBinding,
    NetworkPolicy,
    QualificationStatus,
    ResourceExecutionContractV2,
    ResourceProfile,
    ResourceProvider,
    ResourceType,
    RiskLevel,
    VerificationLevel,
    WorkloadAuthority,
    WorkloadRequirements,
)
from liltweak.resource.leases import ExecutionLease

NOW = datetime(2026, 9, 1, tzinfo=UTC)
SIGNING_KEY = b"S" * 32


def provider_contract_and_lease(
    *,
    provider: ResourceProvider,
    resource_type: ResourceType,
    runner_profile_id: str,
) -> tuple[ResourceExecutionContractV2, ExecutionLease]:
    requirements = WorkloadRequirements(
        requirement_id=f"req_{provider.value}",
        job_id=f"job_{provider.value}",
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
    profile = ResourceProfile(
        runner_profile_id=runner_profile_id,
        provider=provider,
        resource_type=resource_type,
        single_machine_cpu=2,
        single_machine_memory_mb=4_096,
        single_machine_disk_mb=8_192,
        aggregate_parallel_cpu=20,
        aggregate_parallel_memory_mb=40_960,
        parallel_limit=10,
        maximum_duration_seconds=3_600,
        qualification_status=QualificationStatus.QUALIFIED,
        health_status=HealthStatus.HEALTHY,
        last_qualified_at=NOW,
        last_verified_at=NOW,
        estimated_cpu_microusd_per_second=1,
        estimated_memory_microusd_per_gb_second=1,
        estimated_storage_microusd_per_gb_second=1,
        included_allowance_microusd=0,
        current_usage_microusd=0,
        priority=10,
    )
    contract = ResourceExecutionContractV2.issue(
        contract_id=f"contract_{provider.value}",
        requirements=requirements,
        profile=profile,
        source=ImmutableSourceBinding(
            repository_id="github:islamismylifebey-web/lil-tweak",
            source_commit="f" * 40,
            source_tree="e" * 40,
            source_archive_digest="c" * 64,
        ),
        approval=ApprovalBinding(
            approval_id=f"approval_{provider.value}",
            approval_digest="a" * 64,
            policy_digest="b" * 64,
        ),
        commands_digest="d" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    lease = ExecutionLease.issue(
        lease_id=f"lease_{provider.value}",
        execution_id=f"execution_{provider.value}",
        contract=contract,
        attempt_nonce=("1" if provider is ResourceProvider.VERCEL else "2") * 64,
        authorization_sequence=1,
        revocation_epoch=1,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        signing_key=SIGNING_KEY,
    )
    return contract, lease
