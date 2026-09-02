from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from liltweak.creator_contract import canonical_json
from liltweak.providers.contracts import (
    ProviderExecutionStatus,
    ProviderRuntimeState,
    VerificationOutcome,
)
from liltweak.providers.github.runner_v3 import GitHubRunnerV3Provider
from liltweak.providers.github.runner_v3_contracts import (
    RUNNER_V3_PROFILE_ID,
    RUNNER_V3_WORKFLOW_PATH,
    RunnerV3Action,
    RunnerV3JobManifest,
    RunnerV3Outcome,
    RunnerV3Patch,
    RunnerV3ProviderConfig,
    RunnerV3WorkflowSnapshot,
    RunnerV3WorkspaceMode,
)
from liltweak.resource.contracts import (
    ApprovalBinding,
    DeploymentPurpose,
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
    WorkspacePolicy,
)
from liltweak.resource.leases import ExecutionLease

NOW = datetime(2026, 9, 2, 18, 0, tzinfo=UTC)
SIGNING_KEY = b"V" * 32
REPOSITORY_ID = "github:islamismylifebey-web/lil-tweak"
PATCH_TEXT = """diff --git a/docs/runner-v3-fixture.txt b/docs/runner-v3-fixture.txt
new file mode 100644
index 0000000..ce01362
--- /dev/null
+++ b/docs/runner-v3-fixture.txt
@@ -0,0 +1 @@
+hello
"""


class FixtureRunnerV3Client:
    def __init__(self) -> None:
        self.run_id = "runner_v3_run_1"
        self.dispatches: list[dict[str, str]] = []
        self.snapshot: RunnerV3WorkflowSnapshot | None = None
        self.canceled: list[str] = []

    async def dispatch_job(
        self,
        *,
        repository_id: str,
        workflow_path: str,
        source_commit: str,
        manifest_json: str,
        manifest_digest: str,
    ) -> str:
        self.dispatches.append(
            {
                "repository_id": repository_id,
                "workflow_path": workflow_path,
                "source_commit": source_commit,
                "manifest_json": manifest_json,
                "manifest_digest": manifest_digest,
            }
        )
        manifest = RunnerV3JobManifest.model_validate_json(manifest_json)
        if self.snapshot is None:
            self.snapshot = RunnerV3WorkflowSnapshot(
                run_id=self.run_id,
                source_commit=manifest.source_commit,
                source_tree=manifest.source_tree,
                manifest_digest=manifest.manifest_digest,
                status="queued",
            )
        return self.run_id

    async def get_workflow(self, run_id: str) -> RunnerV3WorkflowSnapshot:
        assert run_id == self.run_id
        assert self.snapshot is not None
        return self.snapshot

    async def cancel_workflow(self, run_id: str) -> None:
        self.canceled.append(run_id)


def _profile(*, writable: bool = False) -> ResourceProfile:
    workspace_policy = (
        WorkspacePolicy.EPHEMERAL_WRITABLE if writable else WorkspacePolicy.READ_ONLY
    )
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
        workspace_policy=workspace_policy,
        source_write_capability=writable,
        qualification_status=QualificationStatus.QUALIFIED,
        health_status=HealthStatus.HEALTHY,
        last_qualified_at=NOW,
        last_verified_at=NOW,
        estimated_cpu_microusd_per_second=0,
        estimated_memory_microusd_per_gb_second=0,
        estimated_storage_microusd_per_gb_second=0,
        included_allowance_microusd=1_000_000,
        current_usage_microusd=0,
        risk_surface=RiskLevel.LOW,
        priority=100,
    )


def _contract_and_lease(
    *,
    writable: bool = False,
    execution_id: str = "execution_runner_v3_provider",
) -> tuple[ResourceExecutionContractV2, ExecutionLease]:
    requirements = WorkloadRequirements(
        requirement_id="req_runner_v3_provider",
        job_id="job_runner_v3_provider",
        required_cpu=2,
        required_memory_mb=2_048,
        required_disk_mb=4_096,
        shared_memory_required=True,
        workspace_policy=(
            WorkspacePolicy.EPHEMERAL_WRITABLE
            if writable
            else WorkspacePolicy.READ_ONLY
        ),
        source_write_required=writable,
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
            writable_workspace_authorized=writable,
            source_write_authorized=writable,
        ),
    )
    contract = ResourceExecutionContractV2.issue(
        contract_id="contract_runner_v3_provider",
        requirements=requirements,
        profile=_profile(writable=writable),
        source=ImmutableSourceBinding(
            repository_id=REPOSITORY_ID,
            source_commit="f" * 40,
            source_tree="e" * 40,
            source_archive_digest="c" * 64,
        ),
        approval=ApprovalBinding(
            approval_id="approval_runner_v3_provider",
            approval_digest="a" * 64,
            policy_digest="b" * 64,
        ),
        commands_digest="d" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )
    lease = ExecutionLease.issue(
        lease_id="lease_runner_v3_provider",
        execution_id=execution_id,
        contract=contract,
        attempt_nonce="1" * 64,
        authorization_sequence=5,
        revocation_epoch=2,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        signing_key=SIGNING_KEY,
    )
    return contract, lease


def _manifest_factory(
    contract: ResourceExecutionContractV2,
    lease: ExecutionLease,
) -> RunnerV3JobManifest:
    writable = contract.workspace_policy is WorkspacePolicy.EPHEMERAL_WRITABLE
    patch = (
        RunnerV3Patch.issue(
            text=PATCH_TEXT,
            authorized_paths=("docs/runner-v3-fixture.txt",),
        )
        if writable
        else None
    )
    return RunnerV3JobManifest.issue(
        execution_id=lease.execution_id,
        attempt_nonce=lease.attempt_nonce,
        repository_id=contract.source.repository_id,
        source_commit=contract.source.source_commit,
        source_tree=contract.source.source_tree,
        contract_digest=contract.contract_digest,
        lease_digest=lease.lease_digest,
        commands_digest=contract.commands_digest,
        approval_digest=contract.approval.approval_digest,
        policy_digest=contract.approval.policy_digest,
        issued_at=lease.issued_at,
        expires_at=lease.expires_at,
        cpu_ceiling=contract.cpu_ceiling,
        memory_mb_ceiling=contract.memory_mb_ceiling,
        disk_mb_ceiling=contract.disk_mb_ceiling,
        timeout_seconds=contract.max_wall_clock_seconds,
        output_byte_limit=128_000,
        workspace_mode=(
            RunnerV3WorkspaceMode.EPHEMERAL_PATCH
            if writable
            else RunnerV3WorkspaceMode.READ_ONLY
        ),
        source_write_authorized=contract.source_write_authorized,
        actions=(RunnerV3Action.INSPECT_SOURCE, RunnerV3Action.GIT_DIFF),
        patch=patch,
    )


def _config() -> RunnerV3ProviderConfig:
    return RunnerV3ProviderConfig(
        repository_id=REPOSITORY_ID,
        workflow_path=RUNNER_V3_WORKFLOW_PATH,
        runner_profile_id=RUNNER_V3_PROFILE_ID,
    )


def _active_state() -> ProviderRuntimeState:
    return ProviderRuntimeState(
        qualification_status=QualificationStatus.QUALIFIED,
        health_status=HealthStatus.HEALTHY,
        connected=True,
        active=True,
        last_verified_at=NOW,
    )


def _provider(
    client: FixtureRunnerV3Client,
    *,
    state: ProviderRuntimeState | None = None,
    clock_offset: timedelta = timedelta(minutes=1),
    manifest_factory=_manifest_factory,
) -> GitHubRunnerV3Provider:
    return GitHubRunnerV3Provider(
        config=_config(),
        state=state or _active_state(),
        client=client,
        manifest_factory=manifest_factory,
        lease_signing_key=SIGNING_KEY,
        minimum_authorization_sequence=5,
        revocation_epoch=2,
        clock=lambda: NOW + clock_offset,
    )


def _completed_snapshot(
    manifest: RunnerV3JobManifest,
    *,
    conclusion: str = "success",
    outcome: RunnerV3Outcome | None = RunnerV3Outcome.SUCCEEDED,
    source_commit: str | None = None,
    source_tree: str | None = None,
    manifest_digest: str | None = None,
    receipt_digest: str | None = "9" * 64,
) -> RunnerV3WorkflowSnapshot:
    return RunnerV3WorkflowSnapshot(
        run_id="runner_v3_run_1",
        source_commit=source_commit or manifest.source_commit,
        source_tree=source_tree or manifest.source_tree,
        manifest_digest=manifest_digest or manifest.manifest_digest,
        status="completed",
        conclusion=conclusion,
        outcome=outcome,
        receipt_digest=receipt_digest,
    )


def _mutate_contract(
    contract: ResourceExecutionContractV2,
    mutation: str,
) -> ResourceExecutionContractV2:
    if mutation == "provider":
        return contract.model_copy(update={"provider": ResourceProvider.VERCEL})
    if mutation == "resource_type":
        return contract.model_copy(
            update={"provider_resource_type": ResourceType.GITHUB_CODESPACES}
        )
    if mutation == "profile":
        return contract.model_copy(update={"runner_profile_id": "other-runner"})
    if mutation == "repository":
        source = contract.source.model_copy(
            update={"repository_id": "github:other/repository"}
        )
        return contract.model_copy(update={"source": source})
    if mutation == "gpu":
        return contract.model_copy(update={"gpu_required": True})
    if mutation == "browser":
        return contract.model_copy(update={"browser_required": True})
    if mutation == "docker":
        return contract.model_copy(update={"docker_required": True})
    if mutation == "package_install":
        return contract.model_copy(update={"package_install_required": True})
    if mutation == "persistent_workspace":
        return contract.model_copy(
            update={
                "workspace_policy": WorkspacePolicy.PERSISTENT_WRITABLE,
                "persistent_workspace_required": True,
            }
        )
    if mutation == "secrets":
        return contract.model_copy(update={"secrets_required": True})
    if mutation == "production":
        return contract.model_copy(update={"production_access_required": True})
    if mutation == "deployment":
        return contract.model_copy(
            update={
                "deployment_authorized": True,
                "deployment_purpose": DeploymentPurpose.PREVIEW,
            }
        )
    if mutation == "network":
        return contract.model_copy(
            update={
                "network_policy": NetworkPolicy(
                    network_required=True,
                    allowed_destinations=("example.com",),
                )
            }
        )
    if mutation == "parallel":
        return contract.model_copy(update={"concurrency_requirement": 2})
    if mutation == "read_only_source_write":
        return contract.model_copy(update={"source_write_authorized": True})
    raise AssertionError(f"unknown mutation: {mutation}")


def test_runner_v3_provider_declares_builder_only_capabilities() -> None:
    provider = _provider(FixtureRunnerV3Client())

    capabilities = provider.capabilities()

    assert capabilities.builder is True
    assert capabilities.independent_verifier is False
    assert capabilities.production_deployment is False
    assert capabilities.resource_types == (ResourceType.GITHUB_ACTIONS,)


@pytest.mark.parametrize(
    ("state", "clock_offset", "expected"),
    (
        (ProviderRuntimeState(), timedelta(minutes=1), "not qualified"),
        (
            ProviderRuntimeState(
                qualification_status=QualificationStatus.QUALIFIED,
                health_status=HealthStatus.HEALTHY,
                connected=True,
                active=False,
                last_verified_at=NOW,
            ),
            timedelta(minutes=1),
            "not active",
        ),
        (
            ProviderRuntimeState(
                qualification_status=QualificationStatus.QUALIFIED,
                health_status=HealthStatus.HEALTHY,
                connected=False,
                active=False,
                last_verified_at=NOW,
            ),
            timedelta(minutes=1),
            "not connected",
        ),
        (_active_state(), timedelta(minutes=10), "stale"),
    ),
)
@pytest.mark.asyncio
async def test_runner_v3_provider_fails_closed_on_runtime_state(
    state: ProviderRuntimeState,
    clock_offset: timedelta,
    expected: str,
) -> None:
    contract, lease = _contract_and_lease()
    client = FixtureRunnerV3Client()
    provider = _provider(client, state=state, clock_offset=clock_offset)

    result = await provider.execute(contract=contract, lease=lease)

    assert result.status is ProviderExecutionStatus.BLOCKED
    assert expected in result.reason
    assert client.dispatches == []


@pytest.mark.parametrize(
    "mutation",
    (
        "provider",
        "resource_type",
        "profile",
        "repository",
        "gpu",
        "browser",
        "docker",
        "package_install",
        "persistent_workspace",
        "secrets",
        "production",
        "deployment",
        "network",
        "parallel",
        "read_only_source_write",
    ),
)
@pytest.mark.asyncio
async def test_runner_v3_provider_rejects_unsupported_contracts(
    mutation: str,
) -> None:
    contract, lease = _contract_and_lease()
    client = FixtureRunnerV3Client()
    provider = _provider(client)

    result = await provider.execute(
        contract=_mutate_contract(contract, mutation),
        lease=lease,
    )

    assert result.status is ProviderExecutionStatus.BLOCKED
    assert client.dispatches == []


@pytest.mark.asyncio
async def test_runner_v3_provider_provisions_and_dispatches_exact_manifest() -> None:
    contract, lease = _contract_and_lease()
    client = FixtureRunnerV3Client()
    provider = _provider(client)

    provisioned = await provider.provision(contract=contract, lease=lease)
    running = await provider.execute(contract=contract, lease=lease)

    assert provisioned.status is ProviderExecutionStatus.PROVISIONED
    assert running.status is ProviderExecutionStatus.RUNNING
    assert running.verification_outcome is VerificationOutcome.NOT_APPLICABLE
    assert len(client.dispatches) == 1
    dispatch = client.dispatches[0]
    manifest = RunnerV3JobManifest.model_validate_json(dispatch["manifest_json"])
    assert dispatch["repository_id"] == REPOSITORY_ID
    assert dispatch["workflow_path"] == RUNNER_V3_WORKFLOW_PATH
    assert dispatch["source_commit"] == contract.source.source_commit
    assert dispatch["manifest_digest"] == manifest.manifest_digest
    assert dispatch["manifest_json"] == canonical_json(manifest.model_dump(mode="json"))
    assert manifest.execution_id == lease.execution_id
    assert manifest.attempt_nonce == lease.attempt_nonce
    assert manifest.contract_digest == contract.contract_digest
    assert manifest.lease_digest == lease.lease_digest
    assert manifest.commands_digest == contract.commands_digest
    assert manifest.approval_digest == contract.approval.approval_digest
    assert manifest.policy_digest == contract.approval.policy_digest


@pytest.mark.asyncio
async def test_runner_v3_provider_allows_only_authorized_ephemeral_patch_mode() -> None:
    contract, lease = _contract_and_lease(writable=True)
    client = FixtureRunnerV3Client()
    provider = _provider(client)

    result = await provider.execute(contract=contract, lease=lease)

    assert result.status is ProviderExecutionStatus.RUNNING
    manifest = RunnerV3JobManifest.model_validate_json(
        client.dispatches[0]["manifest_json"]
    )
    assert manifest.workspace_mode is RunnerV3WorkspaceMode.EPHEMERAL_PATCH
    assert manifest.source_write_authorized is True
    assert manifest.patch is not None


@pytest.mark.asyncio
async def test_runner_v3_provider_consumes_lease_before_rejecting_forged_manifest() -> None:
    contract, lease = _contract_and_lease()
    client = FixtureRunnerV3Client()

    def forged_factory(
        value: ResourceExecutionContractV2,
        bound_lease: ExecutionLease,
    ) -> RunnerV3JobManifest:
        manifest = _manifest_factory(value, bound_lease)
        return manifest.model_copy(update={"source_tree": "0" * 40})

    provider = _provider(client, manifest_factory=forged_factory)

    forged = await provider.execute(contract=contract, lease=lease)
    replay = await provider.execute(contract=contract, lease=lease)

    assert forged.status is ProviderExecutionStatus.BLOCKED
    assert "manifest" in forged.reason
    assert replay.status is ProviderExecutionStatus.BLOCKED
    assert "replay" in replay.reason
    assert client.dispatches == []


@pytest.mark.asyncio
async def test_runner_v3_provider_blocks_duplicate_execution() -> None:
    contract, lease = _contract_and_lease()
    client = FixtureRunnerV3Client()
    provider = _provider(client)

    first = await provider.execute(contract=contract, lease=lease)
    duplicate = await provider.execute(contract=contract, lease=lease)

    assert first.status is ProviderExecutionStatus.RUNNING
    assert duplicate.status is ProviderExecutionStatus.BLOCKED
    assert "already exists" in duplicate.reason
    assert len(client.dispatches) == 1


@pytest.mark.asyncio
async def test_runner_v3_status_remains_nonfinal_until_collection() -> None:
    contract, lease = _contract_and_lease()
    client = FixtureRunnerV3Client()
    provider = _provider(client)
    await provider.execute(contract=contract, lease=lease)

    queued = await provider.status(lease.execution_id)
    manifest = RunnerV3JobManifest.model_validate_json(
        client.dispatches[0]["manifest_json"]
    )
    client.snapshot = _completed_snapshot(manifest)
    completed = await provider.status(lease.execution_id)

    assert queued.status is ProviderExecutionStatus.RUNNING
    assert completed.status is ProviderExecutionStatus.RUNNING
    assert "collection" in completed.reason


@pytest.mark.asyncio
async def test_runner_v3_collection_returns_builder_evidence_not_verification() -> None:
    contract, lease = _contract_and_lease()
    client = FixtureRunnerV3Client()
    provider = _provider(client)
    await provider.execute(contract=contract, lease=lease)
    manifest = RunnerV3JobManifest.model_validate_json(
        client.dispatches[0]["manifest_json"]
    )
    client.snapshot = _completed_snapshot(manifest)

    result = await provider.collect(lease.execution_id)

    assert result.status is ProviderExecutionStatus.SUCCEEDED
    assert result.verification_outcome is VerificationOutcome.NOT_APPLICABLE
    assert result.evidence_digest == client.snapshot.receipt_digest
    assert "independent verification" in result.reason


@pytest.mark.parametrize(
    "mismatch",
    ("conclusion", "source_commit", "source_tree", "manifest_digest"),
)
@pytest.mark.asyncio
async def test_runner_v3_collection_rejects_failed_or_mismatched_snapshot(
    mismatch: str,
) -> None:
    contract, lease = _contract_and_lease()
    client = FixtureRunnerV3Client()
    provider = _provider(client)
    await provider.execute(contract=contract, lease=lease)
    manifest = RunnerV3JobManifest.model_validate_json(
        client.dispatches[0]["manifest_json"]
    )
    values: dict[str, object] = {}
    if mismatch == "conclusion":
        values.update(
            conclusion="failure",
            outcome=RunnerV3Outcome.FAILED,
            receipt_digest=None,
        )
    elif mismatch == "source_commit":
        values["source_commit"] = "0" * 40
    elif mismatch == "source_tree":
        values["source_tree"] = "0" * 40
    else:
        values["manifest_digest"] = "0" * 64
    client.snapshot = _completed_snapshot(manifest, **values)

    result = await provider.collect(lease.execution_id)

    assert result.status is ProviderExecutionStatus.FAILED
    assert result.verification_outcome is VerificationOutcome.NOT_APPLICABLE


@pytest.mark.asyncio
async def test_runner_v3_cancel_and_destroy_release_only_local_state() -> None:
    contract, lease = _contract_and_lease()
    client = FixtureRunnerV3Client()
    provider = _provider(client)
    await provider.execute(contract=contract, lease=lease)

    canceled = await provider.cancel(lease.execution_id)
    destroyed = await provider.destroy(lease.execution_id)
    unknown = await provider.status(lease.execution_id)

    assert canceled.status is ProviderExecutionStatus.CANCELED
    assert client.canceled == [client.run_id]
    assert destroyed.status is ProviderExecutionStatus.DESTROYED
    assert unknown.status is ProviderExecutionStatus.BLOCKED


def test_dispatch_payload_contains_no_untyped_command_channel() -> None:
    contract, lease = _contract_and_lease()
    manifest = _manifest_factory(contract, lease)
    payload = json.loads(canonical_json(manifest.model_dump(mode="json")))

    assert "command" not in payload
    assert "shell" not in payload
    assert "executable" not in payload
    assert payload["actions"] == ["inspect_source", "git_diff"]
