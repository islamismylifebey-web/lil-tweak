from datetime import UTC, datetime, timedelta

import pytest

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
from liltweak.resource.leases import ExecutionLease, ExecutionLeaseError, ExecutionLeaseRegistry

NOW = datetime(2026, 9, 1, tzinfo=UTC)
SIGNING_KEY = b"L" * 32


def _contract() -> ResourceExecutionContractV2:
    authority = WorkloadAuthority(
        requested_by="owner",
        risk_level=RiskLevel.LOW,
        maximum_authorized_cost_microusd=50_000,
        approval_digest="a" * 64,
        policy_digest="b" * 64,
    )
    requirements = WorkloadRequirements(
        requirement_id="req_lease",
        job_id="job_lease",
        required_cpu=2,
        required_memory_mb=2_048,
        required_disk_mb=4_096,
        shared_memory_required=True,
        network_policy=NetworkPolicy(),
        estimated_duration_seconds=300,
        parallelizable=False,
        desired_parallelism=1,
        verification_level=VerificationLevel.INDEPENDENT,
        authority=authority,
    )
    profile = ResourceProfile(
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
        priority=10,
    )
    return ResourceExecutionContractV2.issue(
        contract_id="contract_lease",
        requirements=requirements,
        profile=profile,
        source=ImmutableSourceBinding(
            repository_id="github:islamismylifebey-web/lil-tweak",
            source_commit="f" * 40,
            source_tree="e" * 40,
            source_archive_digest="c" * 64,
        ),
        approval=ApprovalBinding(
            approval_id="approval_lease",
            approval_digest="a" * 64,
            policy_digest="b" * 64,
        ),
        commands_digest="d" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )


def _lease(contract: ResourceExecutionContractV2, **changes: object) -> ExecutionLease:
    values: dict[str, object] = {
        "lease_id": "lease_001",
        "execution_id": "execution_001",
        "contract": contract,
        "attempt_nonce": "1" * 64,
        "authorization_sequence": 7,
        "revocation_epoch": 3,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
        "signing_key": SIGNING_KEY,
    }
    values.update(changes)
    return ExecutionLease.issue(**values)  # type: ignore[arg-type]


def test_lease_binds_contract_source_approval_limits_and_signature() -> None:
    contract = _contract()
    lease = _lease(contract)

    assert lease.source == contract.source
    assert lease.approval_digest == contract.approval.approval_digest
    assert lease.cpu_ceiling == 2
    assert lease.maximum_cost_microusd == 50_000
    assert lease.signature != lease.lease_digest

    tampered = lease.model_copy(
        update={"source": lease.source.model_copy(update={"source_commit": "0" * 40})}
    )
    with pytest.raises(ExecutionLeaseError, match="contract source"):
        ExecutionLeaseRegistry().consume(
            tampered,
            contract=contract,
            signing_key=SIGNING_KEY,
            now=NOW + timedelta(minutes=1),
            minimum_authorization_sequence=7,
            revocation_epoch=3,
        )


def test_expired_and_replayed_leases_fail_closed() -> None:
    contract = _contract()
    registry = ExecutionLeaseRegistry()
    lease = _lease(contract)

    registry.consume(
        lease,
        contract=contract,
        signing_key=SIGNING_KEY,
        now=NOW + timedelta(minutes=1),
        minimum_authorization_sequence=7,
        revocation_epoch=3,
    )
    with pytest.raises(ExecutionLeaseError, match="replay"):
        registry.consume(
            lease,
            contract=contract,
            signing_key=SIGNING_KEY,
            now=NOW + timedelta(minutes=2),
            minimum_authorization_sequence=7,
            revocation_epoch=3,
        )

    expired = _lease(
        contract,
        lease_id="lease_expired",
        execution_id="execution_expired",
        attempt_nonce="2" * 64,
        expires_at=NOW + timedelta(seconds=30),
    )
    with pytest.raises(ExecutionLeaseError, match="expired"):
        registry.consume(
            expired,
            contract=contract,
            signing_key=SIGNING_KEY,
            now=NOW + timedelta(minutes=1),
            minimum_authorization_sequence=7,
            revocation_epoch=3,
        )


def test_stale_authorization_sequence_or_revocation_epoch_fails_closed() -> None:
    contract = _contract()
    lease = _lease(contract)

    with pytest.raises(ExecutionLeaseError, match="authorization sequence"):
        ExecutionLeaseRegistry().consume(
            lease,
            contract=contract,
            signing_key=SIGNING_KEY,
            now=NOW + timedelta(minutes=1),
            minimum_authorization_sequence=8,
            revocation_epoch=3,
        )
    with pytest.raises(ExecutionLeaseError, match="revocation epoch"):
        ExecutionLeaseRegistry().consume(
            lease,
            contract=contract,
            signing_key=SIGNING_KEY,
            now=NOW + timedelta(minutes=1),
            minimum_authorization_sequence=7,
            revocation_epoch=4,
        )


@pytest.mark.parametrize(
    ("field", "expected_message"),
    (
        ("approval_digest", "approval digest"),
        ("commands_digest", "commands digest"),
    ),
)
def test_altered_approval_or_command_digest_fails_closed(
    field: str,
    expected_message: str,
) -> None:
    contract = _contract()
    lease = _lease(contract).model_copy(update={field: "0" * 64})

    with pytest.raises(ExecutionLeaseError, match=expected_message):
        ExecutionLeaseRegistry().consume(
            lease,
            contract=contract,
            signing_key=SIGNING_KEY,
            now=NOW + timedelta(minutes=1),
            minimum_authorization_sequence=7,
            revocation_epoch=3,
        )


def test_lease_cannot_begin_before_its_resource_contract() -> None:
    contract = _contract()

    with pytest.raises(ValueError, match="before its resource contract"):
        _lease(
            contract,
            issued_at=NOW - timedelta(seconds=1),
            expires_at=NOW + timedelta(minutes=1),
        )
