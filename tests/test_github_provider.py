from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from liltweak.providers.contracts import (
    ProviderExecutionStatus,
    ProviderRuntimeState,
    VerificationOutcome,
)
from liltweak.providers.github.actions import GitHubActionsProvider
from liltweak.providers.github.codespaces import GitHubCodespacesProvider
from liltweak.providers.github.contracts import GitHubProviderConfig, GitHubWorkflowSnapshot
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
SIGNING_KEY = b"G" * 32


class FixtureGitHubClient:
    def __init__(self, snapshot: GitHubWorkflowSnapshot) -> None:
        self.snapshot = snapshot
        self.dispatches: list[dict[str, str]] = []
        self.canceled: list[str] = []

    async def dispatch_verification(
        self,
        *,
        repository_id: str,
        workflow_path: str,
        source_commit: str,
        lease_digest: str,
    ) -> str:
        self.dispatches.append(
            {
                "repository_id": repository_id,
                "workflow_path": workflow_path,
                "source_commit": source_commit,
                "lease_digest": lease_digest,
            }
        )
        return self.snapshot.run_id

    async def get_workflow(self, run_id: str) -> GitHubWorkflowSnapshot:
        assert run_id == self.snapshot.run_id
        return self.snapshot

    async def cancel_workflow(self, run_id: str) -> None:
        self.canceled.append(run_id)


def _profile() -> ResourceProfile:
    return ResourceProfile(
        runner_profile_id="github-actions-verifier",
        provider=ResourceProvider.GITHUB,
        resource_type=ResourceType.GITHUB_ACTIONS,
        single_machine_cpu=2,
        single_machine_memory_mb=7_000,
        single_machine_disk_mb=14_000,
        aggregate_parallel_cpu=40,
        aggregate_parallel_memory_mb=140_000,
        parallel_limit=20,
        maximum_duration_seconds=21_600,
        network_capability=True,
        allowed_destinations=("api.github.com", "github.com"),
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
    )


def _contract_and_lease() -> tuple[ResourceExecutionContractV2, ExecutionLease]:
    requirements = WorkloadRequirements(
        requirement_id="req_github_provider",
        job_id="job_github_provider",
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
    contract = ResourceExecutionContractV2.issue(
        contract_id="contract_github_provider",
        requirements=requirements,
        profile=_profile(),
        source=ImmutableSourceBinding(
            repository_id="github:islamismylifebey-web/lil-tweak",
            source_commit="f" * 40,
            source_tree="e" * 40,
            source_archive_digest="c" * 64,
        ),
        approval=ApprovalBinding(
            approval_id="approval_github_provider",
            approval_digest="a" * 64,
            policy_digest="b" * 64,
        ),
        commands_digest="d" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    lease = ExecutionLease.issue(
        lease_id="lease_github_provider",
        execution_id="execution_github_provider",
        contract=contract,
        attempt_nonce="1" * 64,
        authorization_sequence=5,
        revocation_epoch=2,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        signing_key=SIGNING_KEY,
    )
    return contract, lease


def _config() -> GitHubProviderConfig:
    return GitHubProviderConfig(
        repository_id="github:islamismylifebey-web/lil-tweak",
        workflow_path=".github/workflows/ci.yml",
        runner_profile_id="github-actions-verifier",
        required_checks=("lint", "mypy", "pytest", "build", "deterministic"),
    )


def _state(*, active: bool) -> ProviderRuntimeState:
    if not active:
        return ProviderRuntimeState()
    return ProviderRuntimeState(
        qualification_status=QualificationStatus.QUALIFIED,
        health_status=HealthStatus.HEALTHY,
        connected=True,
        active=True,
        last_verified_at=NOW,
    )


def test_github_codespaces_is_scaffolded_and_fail_closed() -> None:
    provider = GitHubCodespacesProvider()

    assert provider.qualify().qualified is False
    assert provider.health().connected is False
    assert provider.health().active is False
    assert provider.capabilities().builder is True
    assert provider.capabilities().production_deployment is False


@pytest.mark.asyncio
async def test_github_provider_is_fail_closed_until_qualified_connected_and_active() -> None:
    contract, lease = _contract_and_lease()
    client = FixtureGitHubClient(
        GitHubWorkflowSnapshot(
            run_id="run_blocked",
            source_commit=contract.source.source_commit,
            status="queued",
            conclusion=None,
            required_checks_passed=False,
            evidence_digest=None,
        )
    )
    provider = GitHubActionsProvider(
        config=_config(),
        state=_state(active=False),
        client=client,
        lease_signing_key=SIGNING_KEY,
        minimum_authorization_sequence=5,
        revocation_epoch=2,
        clock=lambda: NOW + timedelta(minutes=1),
    )

    assert provider.qualify().qualified is False
    result = await provider.execute(contract=contract, lease=lease)
    assert result.status is ProviderExecutionStatus.BLOCKED
    assert client.dispatches == []


@pytest.mark.asyncio
async def test_github_provider_dispatches_exact_source_and_only_ci_can_verify() -> None:
    contract, lease = _contract_and_lease()
    snapshot = GitHubWorkflowSnapshot(
        run_id="run_verified",
        source_commit=contract.source.source_commit,
        status="completed",
        conclusion="success",
        required_checks_passed=True,
        completed_checks=("lint", "mypy", "pytest", "build", "deterministic"),
        evidence_digest="9" * 64,
    )
    client = FixtureGitHubClient(snapshot)
    provider = GitHubActionsProvider(
        config=_config(),
        state=_state(active=True),
        client=client,
        lease_signing_key=SIGNING_KEY,
        minimum_authorization_sequence=5,
        revocation_epoch=2,
        clock=lambda: NOW + timedelta(minutes=1),
    )

    provisioned = await provider.provision(contract=contract, lease=lease)
    running = await provider.execute(contract=contract, lease=lease)
    collected = await provider.collect(lease.execution_id)

    assert provisioned.status is ProviderExecutionStatus.PROVISIONED
    assert running.status is ProviderExecutionStatus.RUNNING
    assert client.dispatches == [
        {
            "repository_id": "github:islamismylifebey-web/lil-tweak",
            "workflow_path": ".github/workflows/ci.yml",
            "source_commit": "f" * 40,
            "lease_digest": lease.lease_digest,
        }
    ]
    assert collected.status is ProviderExecutionStatus.SUCCEEDED
    assert collected.verification_outcome is VerificationOutcome.VERIFIED


@pytest.mark.asyncio
async def test_provider_success_message_cannot_override_failed_independent_checks() -> None:
    contract, lease = _contract_and_lease()
    client = FixtureGitHubClient(
        GitHubWorkflowSnapshot(
            run_id="run_failed_checks",
            source_commit=contract.source.source_commit,
            status="completed",
            conclusion="success",
            required_checks_passed=False,
            evidence_digest="8" * 64,
        )
    )
    provider = GitHubActionsProvider(
        config=_config(),
        state=_state(active=True),
        client=client,
        lease_signing_key=SIGNING_KEY,
        minimum_authorization_sequence=5,
        revocation_epoch=2,
        clock=lambda: NOW + timedelta(minutes=1),
    )

    await provider.execute(contract=contract, lease=lease)
    collected = await provider.collect(lease.execution_id)

    assert collected.status is ProviderExecutionStatus.FAILED
    assert collected.verification_outcome is VerificationOutcome.FAILED


@pytest.mark.asyncio
async def test_provider_timeout_fails_independent_verification() -> None:
    contract, lease = _contract_and_lease()
    client = FixtureGitHubClient(
        GitHubWorkflowSnapshot(
            run_id="run_timed_out",
            source_commit=contract.source.source_commit,
            status="completed",
            conclusion="timed_out",
            required_checks_passed=False,
            evidence_digest="7" * 64,
        )
    )
    provider = GitHubActionsProvider(
        config=_config(),
        state=_state(active=True),
        client=client,
        lease_signing_key=SIGNING_KEY,
        minimum_authorization_sequence=5,
        revocation_epoch=2,
        clock=lambda: NOW + timedelta(minutes=1),
    )

    await provider.execute(contract=contract, lease=lease)
    collected = await provider.collect(lease.execution_id)

    assert collected.status is ProviderExecutionStatus.FAILED
    assert collected.verification_outcome is VerificationOutcome.FAILED


def test_provider_rejects_malformed_workflow_result() -> None:
    with pytest.raises(ValidationError, match="conclusion"):
        GitHubWorkflowSnapshot(
            run_id="run_malformed",
            source_commit="f" * 40,
            status="completed",
            conclusion=None,
            required_checks_passed=True,
            evidence_digest="6" * 64,
        )


@pytest.mark.asyncio
async def test_duplicate_provider_execution_attempt_is_blocked() -> None:
    contract, lease = _contract_and_lease()
    client = FixtureGitHubClient(
        GitHubWorkflowSnapshot(
            run_id="run_duplicate",
            source_commit=contract.source.source_commit,
            status="queued",
            conclusion=None,
            required_checks_passed=False,
            evidence_digest=None,
        )
    )
    provider = GitHubActionsProvider(
        config=_config(),
        state=_state(active=True),
        client=client,
        lease_signing_key=SIGNING_KEY,
        minimum_authorization_sequence=5,
        revocation_epoch=2,
        clock=lambda: NOW + timedelta(minutes=1),
    )

    first = await provider.execute(contract=contract, lease=lease)
    duplicate = await provider.execute(contract=contract, lease=lease)

    assert first.status is ProviderExecutionStatus.RUNNING
    assert duplicate.status is ProviderExecutionStatus.BLOCKED
    assert len(client.dispatches) == 1


@pytest.mark.asyncio
async def test_github_verification_requires_every_configured_check() -> None:
    contract, lease = _contract_and_lease()
    client = FixtureGitHubClient(
        GitHubWorkflowSnapshot(
            run_id="run_missing_check",
            source_commit=contract.source.source_commit,
            status="completed",
            conclusion="success",
            required_checks_passed=True,
            completed_checks=("lint", "mypy", "pytest", "build"),
            evidence_digest="5" * 64,
        )
    )
    provider = GitHubActionsProvider(
        config=_config(),
        state=_state(active=True),
        client=client,
        lease_signing_key=SIGNING_KEY,
        minimum_authorization_sequence=5,
        revocation_epoch=2,
        clock=lambda: NOW + timedelta(minutes=1),
    )

    await provider.execute(contract=contract, lease=lease)
    collected = await provider.collect(lease.execution_id)

    assert collected.status is ProviderExecutionStatus.FAILED
    assert collected.verification_outcome is VerificationOutcome.FAILED


def test_github_provider_rejects_stale_runtime_health() -> None:
    contract, _ = _contract_and_lease()
    client = FixtureGitHubClient(
        GitHubWorkflowSnapshot(
            run_id="run_stale",
            source_commit=contract.source.source_commit,
            status="queued",
            conclusion=None,
            required_checks_passed=False,
            evidence_digest=None,
        )
    )
    provider = GitHubActionsProvider(
        config=_config(),
        state=_state(active=True),
        client=client,
        lease_signing_key=SIGNING_KEY,
        minimum_authorization_sequence=5,
        revocation_epoch=2,
        clock=lambda: NOW + timedelta(minutes=10),
    )

    qualification = provider.qualify()

    assert qualification.qualified is False
    assert "stale" in "; ".join(qualification.blockers)
