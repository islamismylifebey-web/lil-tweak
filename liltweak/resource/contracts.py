from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator

from ..creator_contract import CreatorSchema, content_digest

_OBJECT_ID_PATTERN = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
_SAFE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


class ResourceProvider(StrEnum):
    GITHUB = "github"
    CLOUDFLARE = "cloudflare"
    VERCEL = "vercel"
    SELF_HOSTED = "self_hosted"


class ResourceType(StrEnum):
    GITHUB_ACTIONS = "github_actions"
    GITHUB_CODESPACES = "github_codespaces"
    CLOUDFLARE_WORKERS = "cloudflare_workers"
    CLOUDFLARE_WORKFLOWS = "cloudflare_workflows"
    CLOUDFLARE_QUEUES = "cloudflare_queues"
    CLOUDFLARE_CONTAINERS = "cloudflare_containers"
    VERCEL_SANDBOX = "vercel_sandbox"
    VERCEL_BUILD = "vercel_build"
    SELF_HOSTED_LINUX = "self_hosted_linux"


_RESOURCE_TYPE_PROVIDERS = {
    ResourceType.GITHUB_ACTIONS: ResourceProvider.GITHUB,
    ResourceType.GITHUB_CODESPACES: ResourceProvider.GITHUB,
    ResourceType.CLOUDFLARE_WORKERS: ResourceProvider.CLOUDFLARE,
    ResourceType.CLOUDFLARE_WORKFLOWS: ResourceProvider.CLOUDFLARE,
    ResourceType.CLOUDFLARE_QUEUES: ResourceProvider.CLOUDFLARE,
    ResourceType.CLOUDFLARE_CONTAINERS: ResourceProvider.CLOUDFLARE,
    ResourceType.VERCEL_SANDBOX: ResourceProvider.VERCEL,
    ResourceType.VERCEL_BUILD: ResourceProvider.VERCEL,
    ResourceType.SELF_HOSTED_LINUX: ResourceProvider.SELF_HOSTED,
}


class QualificationStatus(StrEnum):
    UNQUALIFIED = "unqualified"
    QUALIFIED = "qualified"
    REVOKED = "revoked"


class HealthStatus(StrEnum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationLevel(StrEnum):
    FOCUSED = "focused"
    FULL = "full"
    INDEPENDENT = "independent"


class ArtifactPolicy(StrEnum):
    NONE = "none"
    VERIFIED_ONLY = "verified_only"
    IMMUTABLE_EVIDENCE = "immutable_evidence"


class WorkspacePolicy(StrEnum):
    READ_ONLY = "read_only"
    EPHEMERAL_WRITABLE = "ephemeral_writable"
    PERSISTENT_WRITABLE = "persistent_writable"


class DeploymentPurpose(StrEnum):
    NONE = "none"
    PREVIEW = "preview"
    PRODUCTION = "production"


class NetworkPolicy(CreatorSchema):
    network_required: StrictBool = False
    allowed_destinations: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=32)

    @model_validator(mode="after")
    def validate_destinations(self) -> Self:
        if not self.network_required and self.allowed_destinations:
            raise ValueError("network destinations require network access")
        if self.network_required and not self.allowed_destinations:
            raise ValueError("network access requires explicit destinations")
        normalized: set[str] = set()
        for destination in self.allowed_destinations:
            if (
                not destination
                or len(destination) > 253
                or "*" in destination
                or "/" in destination
                or any(ord(character) < 33 or ord(character) == 127 for character in destination)
            ):
                qualifier = "wildcard" if "*" in destination else "invalid"
                raise ValueError(f"network destination is {qualifier}")
            folded = destination.casefold()
            if folded in normalized:
                raise ValueError("network destinations must be unique")
            normalized.add(folded)
        return self


class ModelWorkloadSuggestion(CreatorSchema):
    """Technical hints only; intentionally contains no authority or provider choice."""

    required_cpu: StrictInt = Field(ge=1, le=1_024)
    required_memory_mb: StrictInt = Field(ge=128, le=4_194_304)
    required_disk_mb: StrictInt = Field(ge=1, le=16_777_216)
    shared_memory_required: StrictBool = True
    gpu_required: StrictBool = False
    browser_required: StrictBool = False
    docker_required: StrictBool = False
    network_required: StrictBool = False
    package_install_required: StrictBool = False
    workspace_policy: WorkspacePolicy = WorkspacePolicy.READ_ONLY
    persistent_workspace_required: StrictBool = False
    estimated_duration_seconds: StrictInt = Field(default=600, ge=1, le=604_800)
    parallelizable: StrictBool = False
    desired_parallelism: StrictInt = Field(default=1, ge=1, le=1_024)

    @model_validator(mode="after")
    def validate_parallelism(self) -> Self:
        if not self.parallelizable and self.desired_parallelism != 1:
            raise ValueError("non-parallel workloads require desired_parallelism=1")
        return self


class WorkloadAuthority(CreatorSchema):
    source: Literal["authenticated_server_context"] = "authenticated_server_context"
    requested_by: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    risk_level: RiskLevel
    maximum_resource_risk: RiskLevel = RiskLevel.MEDIUM
    maximum_authorized_cost_microusd: StrictInt = Field(ge=0)
    approval_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    policy_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    network_policy: NetworkPolicy = Field(default_factory=NetworkPolicy)
    package_install_authorized: StrictBool = False
    writable_workspace_authorized: StrictBool = False
    persistent_workspace_authorized: StrictBool = False
    secrets_authorized: StrictBool = False
    production_access_authorized: StrictBool = False
    source_write_authorized: StrictBool = False
    deployment_authorized: StrictBool = False
    retry_authorized: StrictBool = False
    failover_authorized: StrictBool = False


class WorkloadRequirements(CreatorSchema):
    schema_version: Literal["resource-workload-v1"] = "resource-workload-v1"
    requirement_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    job_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    required_cpu: StrictInt = Field(ge=1, le=1_024)
    required_memory_mb: StrictInt = Field(ge=128, le=4_194_304)
    required_disk_mb: StrictInt = Field(ge=1, le=16_777_216)
    shared_memory_required: StrictBool = True
    gpu_required: StrictBool = False
    browser_required: StrictBool = False
    docker_required: StrictBool = False
    network_policy: NetworkPolicy = Field(default_factory=NetworkPolicy)
    package_install_required: StrictBool = False
    workspace_policy: WorkspacePolicy = WorkspacePolicy.READ_ONLY
    persistent_workspace_required: StrictBool = False
    secrets_required: StrictBool = False
    production_access_required: StrictBool = False
    source_write_required: StrictBool = False
    deployment_required: StrictBool = False
    deployment_purpose: DeploymentPurpose = DeploymentPurpose.NONE
    included_usage_preferred: Literal[True] = True
    estimated_duration_seconds: StrictInt = Field(ge=1, le=604_800)
    parallelizable: StrictBool = False
    desired_parallelism: StrictInt = Field(ge=1, le=1_024)
    verification_level: VerificationLevel
    authority: WorkloadAuthority

    @model_validator(mode="after")
    def validate_authority(self) -> Self:
        if not self.parallelizable and self.desired_parallelism != 1:
            raise ValueError("non-parallel workloads require desired_parallelism=1")
        checks = (
            (
                self.package_install_required,
                self.authority.package_install_authorized,
                "package installation",
            ),
            (
                self.workspace_policy is not WorkspacePolicy.READ_ONLY,
                self.authority.writable_workspace_authorized,
                "writable workspace",
            ),
            (
                self.persistent_workspace_required,
                self.authority.persistent_workspace_authorized,
                "persistent workspace",
            ),
            (self.secrets_required, self.authority.secrets_authorized, "secrets"),
            (
                self.production_access_required,
                self.authority.production_access_authorized,
                "production access",
            ),
            (self.source_write_required, self.authority.source_write_authorized, "source write"),
            (self.deployment_required, self.authority.deployment_authorized, "deployment"),
        )
        for required, authorized, label in checks:
            if required and not authorized:
                raise ValueError(f"workload requests unauthorized {label}")
        if self.network_policy.network_required:
            authorized_network = self.authority.network_policy
            authorized_destinations = {
                destination.casefold() for destination in authorized_network.allowed_destinations
            }
            requested_destinations = {
                destination.casefold() for destination in self.network_policy.allowed_destinations
            }
            if (
                not authorized_network.network_required
                or not requested_destinations <= authorized_destinations
            ):
                raise ValueError("workload requests unauthorized network destinations")
        if self.persistent_workspace_required != (
            self.workspace_policy is WorkspacePolicy.PERSISTENT_WRITABLE
        ):
            raise ValueError("persistent workspace requirement and workspace policy must agree")
        if self.deployment_required != (self.deployment_purpose is not DeploymentPurpose.NONE):
            raise ValueError("deployment requirement and deployment purpose must agree")
        if (
            self.deployment_purpose is DeploymentPurpose.PRODUCTION
            and not self.production_access_required
        ):
            raise ValueError("production deployment requires production access")
        return self

    @property
    def requirements_digest(self) -> str:
        return content_digest(self.model_dump(mode="json"))


class ResourceProfile(CreatorSchema):
    schema_version: Literal["resource-profile-v1"] = "resource-profile-v1"
    runner_profile_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    provider: ResourceProvider
    resource_type: ResourceType
    single_machine_cpu: StrictInt = Field(ge=1, le=1_024)
    single_machine_memory_mb: StrictInt = Field(ge=128, le=4_194_304)
    single_machine_disk_mb: StrictInt = Field(ge=1, le=16_777_216)
    aggregate_parallel_cpu: StrictInt = Field(ge=1, le=65_536)
    aggregate_parallel_memory_mb: StrictInt = Field(ge=128, le=268_435_456)
    parallel_limit: StrictInt = Field(ge=1, le=1_024)
    maximum_duration_seconds: StrictInt = Field(ge=1, le=604_800)
    gpu: StrictBool = False
    browser: StrictBool = False
    docker: StrictBool = False
    network_capability: StrictBool = False
    allowed_destinations: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=64)
    package_install_capability: StrictBool = False
    workspace_policy: WorkspacePolicy = WorkspacePolicy.READ_ONLY
    persistent_workspace: StrictBool = False
    secrets_capability: StrictBool = False
    production_access_capability: StrictBool = False
    source_write_capability: StrictBool = False
    deployment_capability: StrictBool = False
    qualification_status: QualificationStatus = QualificationStatus.UNQUALIFIED
    health_status: HealthStatus = HealthStatus.UNKNOWN
    last_qualified_at: datetime | None = None
    last_verified_at: datetime | None = None
    estimated_cpu_microusd_per_second: StrictInt = Field(ge=0)
    estimated_memory_microusd_per_gb_second: StrictInt = Field(ge=0)
    estimated_storage_microusd_per_gb_second: StrictInt = Field(ge=0)
    included_allowance_microusd: StrictInt = Field(ge=0)
    current_usage_microusd: StrictInt = Field(ge=0)
    risk_surface: RiskLevel = RiskLevel.MEDIUM
    priority: StrictInt = Field(ge=0, le=1_000)
    enabled: StrictBool = True

    @model_validator(mode="after")
    def validate_profile(self) -> Self:
        if _RESOURCE_TYPE_PROVIDERS[self.resource_type] is not self.provider:
            raise ValueError("resource provider and resource type do not correspond")
        if self.aggregate_parallel_cpu < self.single_machine_cpu:
            raise ValueError("aggregate CPU cannot be below single-machine CPU")
        if self.aggregate_parallel_memory_mb < self.single_machine_memory_mb:
            raise ValueError("aggregate memory cannot be below single-machine memory")
        if self.qualification_status is QualificationStatus.QUALIFIED and (
            self.last_qualified_at is None or not _aware(self.last_qualified_at)
        ):
            raise ValueError("qualified resources require a timezone-aware qualification time")
        if self.health_status is HealthStatus.HEALTHY and (
            self.last_verified_at is None or not _aware(self.last_verified_at)
        ):
            raise ValueError("healthy resources require a timezone-aware verification time")
        if self.network_capability != bool(self.allowed_destinations):
            raise ValueError("network capability and destinations must agree")
        if self.persistent_workspace != (
            self.workspace_policy is WorkspacePolicy.PERSISTENT_WRITABLE
        ):
            raise ValueError("persistent workspace capability and workspace policy must agree")
        if len({item.casefold() for item in self.allowed_destinations}) != len(
            self.allowed_destinations
        ):
            raise ValueError("profile network destinations must be unique")
        return self

    @property
    def profile_digest(self) -> str:
        return content_digest(self.model_dump(mode="json"))


class ImmutableSourceBinding(CreatorSchema):
    repository_id: StrictStr = Field(min_length=1, max_length=512)
    source_commit: StrictStr = Field(pattern=_OBJECT_ID_PATTERN)
    source_tree: StrictStr = Field(pattern=_OBJECT_ID_PATTERN)
    source_archive_digest: StrictStr = Field(pattern=_SHA256_PATTERN)

    @property
    def source_binding_digest(self) -> str:
        return content_digest(self.model_dump(mode="json"))


class ApprovalBinding(CreatorSchema):
    approval_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    approval_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    policy_digest: StrictStr = Field(pattern=_SHA256_PATTERN)

    @property
    def approval_binding_digest(self) -> str:
        return content_digest(self.model_dump(mode="json"))


class ResourceExecutionContractV2(CreatorSchema):
    schema_version: Literal["resource-execution-v2"] = "resource-execution-v2"
    contract_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    requirements: WorkloadRequirements
    selected_profile: ResourceProfile
    provider: ResourceProvider
    provider_resource_type: ResourceType
    runner_profile_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    cpu_ceiling: StrictInt = Field(ge=1)
    memory_mb_ceiling: StrictInt = Field(ge=128)
    disk_mb_ceiling: StrictInt = Field(ge=1)
    gpu_required: StrictBool
    shared_memory_required: StrictBool
    browser_required: StrictBool
    docker_required: StrictBool
    package_install_required: StrictBool
    workspace_policy: WorkspacePolicy
    network_policy: NetworkPolicy
    persistent_workspace_required: StrictBool
    secrets_required: StrictBool
    production_access_required: StrictBool
    source_write_authorized: StrictBool
    deployment_authorized: StrictBool
    deployment_purpose: DeploymentPurpose
    artifact_policy: ArtifactPolicy
    max_wall_clock_seconds: StrictInt = Field(ge=1, le=604_800)
    concurrency_requirement: StrictInt = Field(ge=1, le=1_024)
    parallelizable: StrictBool
    maximum_authorized_cost_microusd: StrictInt = Field(ge=0)
    included_usage_preferred: Literal[True] = True
    source: ImmutableSourceBinding
    approval: ApprovalBinding
    verification_policy: VerificationLevel
    retry_authorized: StrictBool
    failover_authorized: StrictBool
    commands_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    issued_at: datetime
    expires_at: datetime
    contract_digest: StrictStr = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def issue(
        cls,
        *,
        contract_id: str,
        requirements: WorkloadRequirements,
        profile: ResourceProfile,
        source: ImmutableSourceBinding,
        approval: ApprovalBinding,
        commands_digest: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> ResourceExecutionContractV2:
        values: dict[str, Any] = {
            "contract_id": contract_id,
            "requirements": requirements,
            "selected_profile": profile,
            "provider": profile.provider,
            "provider_resource_type": profile.resource_type,
            "runner_profile_id": profile.runner_profile_id,
            "cpu_ceiling": requirements.required_cpu,
            "memory_mb_ceiling": requirements.required_memory_mb,
            "disk_mb_ceiling": requirements.required_disk_mb,
            "gpu_required": requirements.gpu_required,
            "shared_memory_required": requirements.shared_memory_required,
            "browser_required": requirements.browser_required,
            "docker_required": requirements.docker_required,
            "package_install_required": requirements.package_install_required,
            "workspace_policy": requirements.workspace_policy,
            "network_policy": requirements.network_policy,
            "persistent_workspace_required": requirements.persistent_workspace_required,
            "secrets_required": requirements.secrets_required,
            "production_access_required": requirements.production_access_required,
            "source_write_authorized": requirements.authority.source_write_authorized,
            "deployment_authorized": requirements.authority.deployment_authorized,
            "deployment_purpose": requirements.deployment_purpose,
            "artifact_policy": ArtifactPolicy.IMMUTABLE_EVIDENCE,
            "max_wall_clock_seconds": requirements.estimated_duration_seconds,
            "concurrency_requirement": requirements.desired_parallelism,
            "parallelizable": requirements.parallelizable,
            "maximum_authorized_cost_microusd": (
                requirements.authority.maximum_authorized_cost_microusd
            ),
            "included_usage_preferred": requirements.included_usage_preferred,
            "source": source,
            "approval": approval,
            "verification_policy": requirements.verification_level,
            "retry_authorized": requirements.authority.retry_authorized,
            "failover_authorized": requirements.authority.failover_authorized,
            "commands_digest": commands_digest,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        draft = cls.model_construct(**values, contract_digest="0" * 64)
        values["contract_digest"] = content_digest(
            draft.model_dump(mode="json", exclude={"contract_digest"})
        )
        return cls.model_validate(values)

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if not _aware(self.issued_at) or not _aware(self.expires_at):
            raise ValueError("resource contract timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("resource contract must expire after issuance")
        profile = self.selected_profile
        if (
            self.provider is not profile.provider
            or self.provider_resource_type is not profile.resource_type
            or self.runner_profile_id != profile.runner_profile_id
        ):
            raise ValueError("resource contract selected profile mismatch")
        authority = self.requirements.authority
        if self.approval.approval_digest != authority.approval_digest:
            raise ValueError("resource contract approval digest mismatch")
        if self.approval.policy_digest != authority.policy_digest:
            raise ValueError("resource contract policy digest mismatch")
        if self.source_write_authorized != authority.source_write_authorized:
            raise ValueError("resource contract source-write authority mismatch")
        if self.deployment_authorized != authority.deployment_authorized:
            raise ValueError("resource contract deployment authority mismatch")
        requirement_bindings = (
            (self.cpu_ceiling, self.requirements.required_cpu, "CPU requirement"),
            (self.memory_mb_ceiling, self.requirements.required_memory_mb, "memory requirement"),
            (self.disk_mb_ceiling, self.requirements.required_disk_mb, "disk requirement"),
            (self.gpu_required, self.requirements.gpu_required, "GPU requirement"),
            (
                self.shared_memory_required,
                self.requirements.shared_memory_required,
                "shared-memory requirement",
            ),
            (self.browser_required, self.requirements.browser_required, "browser requirement"),
            (self.docker_required, self.requirements.docker_required, "Docker requirement"),
            (
                self.package_install_required,
                self.requirements.package_install_required,
                "package-install requirement",
            ),
            (self.workspace_policy, self.requirements.workspace_policy, "workspace policy"),
            (self.network_policy, self.requirements.network_policy, "network policy"),
            (
                self.persistent_workspace_required,
                self.requirements.persistent_workspace_required,
                "persistent-workspace requirement",
            ),
            (self.secrets_required, self.requirements.secrets_required, "secrets requirement"),
            (
                self.production_access_required,
                self.requirements.production_access_required,
                "production-access requirement",
            ),
            (
                self.deployment_purpose,
                self.requirements.deployment_purpose,
                "deployment purpose",
            ),
            (
                self.max_wall_clock_seconds,
                self.requirements.estimated_duration_seconds,
                "wall-clock requirement",
            ),
            (
                self.concurrency_requirement,
                self.requirements.desired_parallelism,
                "concurrency requirement",
            ),
            (self.parallelizable, self.requirements.parallelizable, "parallelism requirement"),
            (
                self.maximum_authorized_cost_microusd,
                authority.maximum_authorized_cost_microusd,
                "cost authority",
            ),
            (
                self.included_usage_preferred,
                self.requirements.included_usage_preferred,
                "included-usage policy",
            ),
            (
                self.verification_policy,
                self.requirements.verification_level,
                "verification policy",
            ),
            (self.retry_authorized, authority.retry_authorized, "retry authority"),
            (self.failover_authorized, authority.failover_authorized, "failover authority"),
        )
        for observed, expected_value, label in requirement_bindings:
            if observed != expected_value:
                raise ValueError(f"resource contract {label} mismatch")
        if self.artifact_policy is not ArtifactPolicy.IMMUTABLE_EVIDENCE:
            raise ValueError("resource contract artifact policy is not permitted")
        if self.max_wall_clock_seconds > profile.maximum_duration_seconds:
            raise ValueError("resource contract exceeds profile duration")
        expected = content_digest(self.model_dump(mode="json", exclude={"contract_digest"}))
        if self.contract_digest != expected:
            raise ValueError("resource contract digest mismatch")
        return self
