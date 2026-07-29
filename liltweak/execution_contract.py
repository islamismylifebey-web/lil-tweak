from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator

from .creator_contract import (
    CreatorBriefEnvelope,
    CreatorSchema,
    RouteDecision,
    SandboxCommand,
    content_digest,
)

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SIGNATURE_PATTERN = r"^[0-9a-f]{64}$"
_IMAGE_PATTERN = r"^[a-z0-9][a-z0-9._/-]{0,255}@sha256:[0-9a-f]{64}$"


class ExecutionStatus(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"


class SourceSnapshotManifest(CreatorSchema):
    schema_version: Literal["1.0"] = "1.0"
    provider: StrictStr = Field(min_length=1, max_length=32)
    repository_id: StrictStr = Field(min_length=1, max_length=512)
    resolved_revision: StrictStr = Field(pattern=r"^[0-9a-f]{40,64}$")
    repository_fingerprint: StrictStr = Field(pattern=_SHA256_PATTERN)
    tree_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    archive_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    file_count: StrictInt = Field(ge=1, le=100_000)
    total_bytes: StrictInt = Field(ge=0, le=1_000_000_000)
    credential_finding_count: Literal[0] = 0
    git_metadata_included: Literal[False] = False
    working_tree_state_included: Literal[False] = False

    @property
    def manifest_digest(self) -> str:
        return content_digest(self.model_dump(mode="json"))


class SandboxProfile(CreatorSchema):
    schema_version: Literal["bubblewrap-readonly-v1"] = "bubblewrap-readonly-v1"
    runtime_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    limiter_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    image_ref: StrictStr = Field(pattern=_IMAGE_PATTERN)
    container_user: StrictStr = Field(pattern=r"^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$")
    network_namespace_isolated: Literal[True] = True
    environment_cleared: Literal[True] = True
    source_read_only: Literal[True] = True
    git_metadata_absent: Literal[True] = True
    host_sockets_absent: Literal[True] = True
    root_filesystem_read_only: Literal[True] = True
    capabilities_dropped: Literal[True] = True
    no_new_privileges: Literal[True] = True
    disposable_workspace: Literal[True] = True

    @property
    def profile_digest(self) -> str:
        return content_digest(self.model_dump(mode="json"))


class ExecutionRecipe(CreatorSchema):
    schema_version: Literal["1.0"] = "1.0"
    recipe_id: StrictStr = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    image_ref: StrictStr = Field(pattern=_IMAGE_PATTERN)
    container_user: StrictStr = Field(
        default="65532:65532",
        pattern=r"^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$",
    )
    commands: tuple[SandboxCommand, ...] = Field(min_length=1, max_length=16)
    wall_clock_seconds: StrictInt = Field(default=600, ge=1, le=600)
    memory_megabytes: StrictInt = Field(default=2_048, ge=128, le=2_048)
    cpu_count: StrictInt = Field(default=2, ge=1, le=2)
    pid_limit: StrictInt = Field(default=256, ge=16, le=256)
    file_size_limit_bytes: StrictInt = Field(
        default=50_000_000,
        ge=1,
        le=50_000_000,
    )
    output_byte_limit: StrictInt = Field(
        default=1_000_000,
        ge=1_024,
        le=1_000_000,
    )
    source_read_only: Literal[True] = True
    network_allowed: Literal[False] = False
    package_install_allowed: Literal[False] = False
    source_write_allowed: Literal[False] = False
    deployment_allowed: Literal[False] = False

    @model_validator(mode="after")
    def validate_recipe(self) -> ExecutionRecipe:
        command_ids = [item.command_id for item in self.commands]
        if len(command_ids) != len(set(command_ids)):
            raise ValueError("execution recipe command ids must be unique")
        blocked = {
            "bash",
            "busybox",
            "cmd",
            "curl",
            "env",
            "fish",
            "git",
            "nc",
            "netcat",
            "powershell",
            "pwsh",
            "scp",
            "sh",
            "ssh",
            "wget",
            "xargs",
            "zsh",
        }
        allowed = {"pytest", "ruff"}
        for command in self.commands:
            executable = command.argv[0]
            normalized_executable = executable.casefold()
            if normalized_executable.startswith("python") and any(
                argument in {"-c", "-m"} for argument in command.argv[1:]
            ):
                raise ValueError("execution recipes cannot use interpreter evaluation")
            if (
                "/" in executable
                or "\\" in executable
                or normalized_executable in blocked
                or normalized_executable not in allowed
            ):
                raise ValueError("execution recipes require a safe bare executable")
            if normalized_executable == "ruff":
                if len(command.argv) < 2 or command.argv[1] not in {"check", "format"}:
                    raise ValueError("ruff recipes require a read-only verification subcommand")
                if any(
                    argument in {"--fix", "--fix-only", "--unsafe-fixes"}
                    or argument.startswith("--fix=")
                    for argument in command.argv[2:]
                ):
                    raise ValueError("ruff recipes cannot modify source")
                if command.argv[1] == "format" and "--check" not in command.argv[2:]:
                    raise ValueError("ruff format recipes must use --check")
            if command.timeout_seconds > 300:
                raise ValueError("execution recipe commands are limited to five minutes")
        return self

    @property
    def recipe_digest(self) -> str:
        return content_digest(self.model_dump(mode="json"))


class ExecutionPrepareRequest(CreatorSchema):
    job_id: StrictStr = Field(min_length=1, max_length=128)
    recipe_id: StrictStr = Field(min_length=1, max_length=128)
    expected_repository_fingerprint: StrictStr = Field(pattern=_SHA256_PATTERN)
    envelope: CreatorBriefEnvelope
    route: RouteDecision


class RepositoryExecutionPlan(CreatorSchema):
    schema_version: Literal["1.0"] = "1.0"
    id: StrictStr = Field(min_length=1, max_length=128)
    job_id: StrictStr = Field(min_length=1, max_length=128)
    organization_id: StrictStr = Field(min_length=1, max_length=128)
    project_id: StrictStr = Field(min_length=1, max_length=128)
    brief_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    route_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    recipe_id: StrictStr = Field(min_length=1, max_length=128)
    recipe_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    source: SourceSnapshotManifest
    sandbox_profile_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    workspace_mount_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    image_ref: StrictStr = Field(pattern=_IMAGE_PATTERN)
    commands: tuple[SandboxCommand, ...] = Field(min_length=1, max_length=16)
    wall_clock_seconds: StrictInt = Field(ge=1, le=600)
    memory_megabytes: StrictInt = Field(ge=128, le=2_048)
    cpu_count: StrictInt = Field(ge=1, le=2)
    pid_limit: StrictInt = Field(ge=16, le=256)
    file_size_limit_bytes: StrictInt = Field(ge=1, le=50_000_000)
    output_byte_limit: StrictInt = Field(ge=1_024, le=1_000_000)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    network_allowed: Literal[False] = False
    source_read_only: Literal[True] = True
    source_write_authorized: Literal[False] = False
    package_install_authorized: Literal[False] = False
    deployment_authorized: Literal[False] = False
    automatic_retry_authorized: Literal[False] = False
    execution_authorized: Literal[False] = False
    attempt_nonce: StrictStr = Field(pattern=_SHA256_PATTERN)
    plan_digest: StrictStr = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_plan(self) -> RepositoryExecutionPlan:
        if self.expires_at <= self.created_at:
            raise ValueError("execution plan must expire after creation")
        expected_mount = content_digest(
            {
                "source_manifest_digest": self.source.manifest_digest,
                "sandbox_profile_digest": self.sandbox_profile_digest,
                "recipe_digest": self.recipe_digest,
            }
        )
        if self.workspace_mount_digest != expected_mount:
            raise ValueError("execution workspace mount digest mismatch")
        expected = content_digest(self.model_dump(mode="json", exclude={"plan_digest"}))
        if self.plan_digest != expected:
            raise ValueError("repository execution plan digest mismatch")
        return self


class ExecutionRecord(CreatorSchema):
    plan: RepositoryExecutionPlan
    status: ExecutionStatus
    approval_id: StrictStr | None = Field(default=None, min_length=1, max_length=128)
    result_digest: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    failure_code: StrictStr | None = Field(default=None, min_length=1, max_length=128)
    attempt_count: StrictInt = Field(default=0, ge=0, le=1)


class ExecutionDecisionRequest(CreatorSchema):
    decision: Literal["approve", "reject"]
    plan_digest: StrictStr = Field(pattern=_SHA256_PATTERN)


class RepositoryExecutionApproval(CreatorSchema):
    schema_version: Literal["1.0"] = "1.0"
    id: StrictStr = Field(min_length=1, max_length=128)
    execution_id: StrictStr = Field(min_length=1, max_length=128)
    job_id: StrictStr = Field(min_length=1, max_length=128)
    plan_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    approved_by: StrictStr = Field(min_length=1, max_length=128)
    signature: StrictStr = Field(pattern=_SIGNATURE_PATTERN)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime

    @model_validator(mode="after")
    def validate_expiry(self) -> RepositoryExecutionApproval:
        if self.expires_at <= self.created_at:
            raise ValueError("repository execution approval must expire after creation")
        return self


class ExecutionDecisionResponse(CreatorSchema):
    record: ExecutionRecord
    approval: RepositoryExecutionApproval | None = None


class ExecutionRunRequest(CreatorSchema):
    approval_id: StrictStr = Field(min_length=1, max_length=128)


class ProcessObservation(CreatorSchema):
    command_id: StrictStr = Field(min_length=1, max_length=128)
    exit_code: StrictInt | None = Field(default=None, ge=0, le=255)
    signal: StrictInt | None = Field(default=None, ge=1, le=255)
    stdout_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    stderr_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    stdout_bytes: StrictInt = Field(ge=0, le=1_000_000)
    stderr_bytes: StrictInt = Field(ge=0, le=1_000_000)
    duration_ms: StrictInt = Field(ge=0, le=600_000)
    timed_out: StrictBool = False
    output_limit_exceeded: StrictBool = False

    @model_validator(mode="after")
    def validate_process_outcome(self) -> ProcessObservation:
        if (self.exit_code is None) == (self.signal is None):
            raise ValueError("process observation requires exactly one exit code or signal")
        if self.timed_out and self.exit_code == 0:
            raise ValueError("a timed-out process cannot report a successful exit")
        return self


class RunnerAttestation(CreatorSchema):
    schema_version: Literal["bubblewrap-readonly-v1"] = "bubblewrap-readonly-v1"
    attempt_nonce: StrictStr = Field(pattern=_SHA256_PATTERN)
    runtime_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    limiter_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    sandbox_profile_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    image_ref: StrictStr = Field(pattern=_IMAGE_PATTERN)
    network_namespace_isolated: Literal[True] = True
    environment_cleared: Literal[True] = True
    source_read_only: Literal[True] = True
    git_metadata_absent: Literal[True] = True
    host_sockets_absent: Literal[True] = True
    capabilities_dropped: Literal[True] = True
    no_new_privileges: Literal[True] = True
    cleanup_verified: StrictBool
    raw_output_retained: Literal[False] = False

    @property
    def attestation_digest(self) -> str:
        return content_digest(self.model_dump(mode="json"))


class SandboxExecutionEvidence(CreatorSchema):
    plan_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    session_id: StrictStr = Field(min_length=1, max_length=128)
    source_before_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    source_after_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    observations: tuple[ProcessObservation, ...] = Field(min_length=1, max_length=16)
    attestation: RunnerAttestation
    artifact_count: Literal[0] = 0
    artifact_bytes: Literal[0] = 0


class ExecutionVerification(CreatorSchema):
    verified: StrictBool
    completion_claim_allowed: StrictBool
    required_check_count: StrictInt = Field(ge=0, le=16)
    passed_required_check_count: StrictInt = Field(ge=0, le=16)
    evidence_digests: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=64)
    failure_codes: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=64)


class ExecutionOutcomeRecord(CreatorSchema):
    schema_version: Literal["1.0"] = "1.0"
    execution_id: StrictStr = Field(min_length=1, max_length=128)
    plan_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    status: Literal["verified_success", "verified_failure"]
    evidence: SandboxExecutionEvidence
    verification: ExecutionVerification
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    outcome_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    verifier_signature: StrictStr = Field(pattern=_SIGNATURE_PATTERN)

    @model_validator(mode="after")
    def validate_outcome_digest(self) -> ExecutionOutcomeRecord:
        expected = content_digest(
            self.model_dump(
                mode="json",
                exclude={"outcome_digest", "verifier_signature"},
            )
        )
        if self.outcome_digest != expected:
            raise ValueError("repository execution outcome digest mismatch")
        verified_success = (
            self.verification.verified
            and self.verification.completion_claim_allowed
            and self.verification.passed_required_check_count
            == self.verification.required_check_count
            and not self.verification.failure_codes
        )
        if (self.status == "verified_success") != verified_success:
            raise ValueError("repository execution outcome status contradicts verification")
        if self.evidence.plan_digest != self.plan_digest:
            raise ValueError("repository execution evidence is bound to a different plan")
        return self
