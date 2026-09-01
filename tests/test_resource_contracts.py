from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from liltweak.creator_contract import content_digest
from liltweak.resource.contracts import (
    ApprovalBinding,
    DeploymentPurpose,
    HealthStatus,
    ImmutableSourceBinding,
    ModelWorkloadSuggestion,
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
    WorkspacePolicy,
)

NOW = datetime(2026, 9, 1, tzinfo=UTC)
SHA256_A = "a" * 64
SHA256_B = "b" * 64
SHA256_C = "c" * 64


def _authority(**changes: object) -> WorkloadAuthority:
    values: dict[str, object] = {
        "requested_by": "owner",
        "risk_level": RiskLevel.LOW,
        "maximum_authorized_cost_microusd": 50_000,
        "approval_digest": SHA256_A,
        "policy_digest": SHA256_B,
        "secrets_authorized": False,
        "production_access_authorized": False,
        "source_write_authorized": False,
        "deployment_authorized": False,
        "retry_authorized": False,
        "failover_authorized": False,
    }
    values.update(changes)
    return WorkloadAuthority.model_validate(values)


def _requirements(**changes: object) -> WorkloadRequirements:
    values: dict[str, object] = {
        "requirement_id": "req_contracts",
        "job_id": "job_contracts",
        "required_cpu": 2,
        "required_memory_mb": 2_048,
        "required_disk_mb": 4_096,
        "shared_memory_required": True,
        "browser_required": False,
        "docker_required": False,
        "network_policy": NetworkPolicy(),
        "package_install_required": False,
        "persistent_workspace_required": False,
        "secrets_required": False,
        "production_access_required": False,
        "source_write_required": False,
        "deployment_required": False,
        "estimated_duration_seconds": 300,
        "parallelizable": False,
        "desired_parallelism": 1,
        "verification_level": VerificationLevel.FULL,
        "authority": _authority(),
    }
    values.update(changes)
    return WorkloadRequirements.model_validate(values)


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
        health_status=HealthStatus.HEALTHY,
        last_qualified_at=NOW,
        last_verified_at=NOW,
        estimated_cpu_microusd_per_second=2,
        estimated_memory_microusd_per_gb_second=1,
        estimated_storage_microusd_per_gb_second=1,
        included_allowance_microusd=1_000_000,
        current_usage_microusd=0,
        priority=10,
    )


def test_model_suggestion_cannot_manufacture_provider_or_authority() -> None:
    with pytest.raises(ValidationError):
        ModelWorkloadSuggestion.model_validate(
            {
                "required_cpu": 2,
                "required_memory_mb": 2_048,
                "required_disk_mb": 4_096,
                "provider": "vercel",
            }
        )

    with pytest.raises(ValidationError):
        ModelWorkloadSuggestion.model_validate(
            {
                "required_cpu": 2,
                "required_memory_mb": 2_048,
                "required_disk_mb": 4_096,
                "resource_profile": _profile().model_dump(mode="json"),
                "estimated_cpu_microusd_per_second": 0,
            }
        )


def test_resource_profile_rejects_cross_provider_resource_substitution() -> None:
    with pytest.raises(ValidationError, match="provider and resource type"):
        ResourceProfile.model_validate(
            {
                **_profile().model_dump(mode="json"),
                "resource_type": ResourceType.VERCEL_BUILD,
            }
        )


def test_network_policy_rejects_destinations_when_network_is_denied() -> None:
    with pytest.raises(ValidationError, match="destinations"):
        NetworkPolicy(network_required=False, allowed_destinations=("api.github.com",))

    with pytest.raises(ValidationError, match="wildcard"):
        NetworkPolicy(network_required=True, allowed_destinations=("*",))


def test_workload_cannot_request_authority_the_server_did_not_grant() -> None:
    with pytest.raises(ValidationError, match="production access"):
        _requirements(production_access_required=True)

    with pytest.raises(ValidationError, match="source write"):
        _requirements(source_write_required=True)

    with pytest.raises(ValidationError, match="secrets"):
        _requirements(secrets_required=True)

    with pytest.raises(ValidationError, match="deployment"):
        _requirements(deployment_required=True)

    with pytest.raises(ValidationError, match="package installation"):
        _requirements(package_install_required=True)

    with pytest.raises(ValidationError, match="writable workspace"):
        _requirements(workspace_policy=WorkspacePolicy.EPHEMERAL_WRITABLE)

    with pytest.raises(ValidationError, match="network"):
        _requirements(
            network_policy=NetworkPolicy(
                network_required=True,
                allowed_destinations=("attacker.example",),
            )
        )


def test_v2_contract_digest_binds_source_approval_and_selected_profile() -> None:
    requirements = _requirements()
    profile = _profile()
    source = ImmutableSourceBinding(
        repository_id="github:islamismylifebey-web/lil-tweak",
        source_commit="f" * 40,
        source_tree="e" * 40,
        source_archive_digest=SHA256_C,
    )
    approval = ApprovalBinding(
        approval_id="approval_contracts",
        approval_digest=SHA256_A,
        policy_digest=SHA256_B,
    )
    contract = ResourceExecutionContractV2.issue(
        contract_id="resource_contract_v2",
        requirements=requirements,
        profile=profile,
        source=source,
        approval=approval,
        commands_digest="d" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )

    assert contract.schema_version == "resource-execution-v2"
    assert contract.provider is ResourceProvider.GITHUB
    assert contract.runner_profile_id == "github-actions-standard"
    assert contract.workspace_policy is WorkspacePolicy.READ_ONLY
    assert contract.deployment_purpose is DeploymentPurpose.NONE
    assert contract.included_usage_preferred is True
    with pytest.raises(ValidationError, match="contract digest mismatch"):
        ResourceExecutionContractV2.model_validate(
            {**contract.model_dump(mode="json"), "contract_digest": "0" * 64}
        )

    substituted_profile = profile.model_copy(update={"runner_profile_id": "forged-profile"})
    with pytest.raises(ValidationError):
        ResourceExecutionContractV2.model_validate(
            {
                **contract.model_dump(mode="json"),
                "selected_profile": substituted_profile.model_dump(mode="json"),
                "runner_profile_id": substituted_profile.runner_profile_id,
            }
        )


def test_v2_contract_rejects_a_digest_valid_internal_authority_expansion() -> None:
    contract = ResourceExecutionContractV2.issue(
        contract_id="resource_contract_expansion",
        requirements=_requirements(),
        profile=_profile(),
        source=ImmutableSourceBinding(
            repository_id="github:islamismylifebey-web/lil-tweak",
            source_commit="f" * 40,
            source_tree="e" * 40,
            source_archive_digest=SHA256_C,
        ),
        approval=ApprovalBinding(
            approval_id="approval_expansion",
            approval_digest=SHA256_A,
            policy_digest=SHA256_B,
        ),
        commands_digest="d" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    expanded = contract.model_dump(mode="json")
    expanded["cpu_ceiling"] = contract.cpu_ceiling + 1
    expanded["contract_digest"] = content_digest(
        {key: value for key, value in expanded.items() if key != "contract_digest"}
    )

    with pytest.raises(ValidationError, match="CPU requirement"):
        ResourceExecutionContractV2.model_validate(expanded)


def test_v2_contract_factory_revalidates_forged_workload_objects() -> None:
    forged_requirements = _requirements().model_copy(update={"package_install_required": True})

    with pytest.raises(ValidationError, match="package installation"):
        ResourceExecutionContractV2.issue(
            contract_id="resource_contract_forged_requirements",
            requirements=forged_requirements,
            profile=_profile(),
            source=ImmutableSourceBinding(
                repository_id="github:islamismylifebey-web/lil-tweak",
                source_commit="f" * 40,
                source_tree="e" * 40,
                source_archive_digest=SHA256_C,
            ),
            approval=ApprovalBinding(
                approval_id="approval_forged_requirements",
                approval_digest=SHA256_A,
                policy_digest=SHA256_B,
            ),
            commands_digest="d" * 64,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        )
