from __future__ import annotations

import hashlib
import secrets
from datetime import datetime
from enum import StrEnum
from typing import Any, Final, Literal, Protocol, Self

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator

from ...creator_contract import CreatorSchema, content_digest

RUNNER_V3_PROFILE_ID: Final[Literal["galor-tweak-runner-v3-github-01"]] = (
    "galor-tweak-runner-v3-github-01"
)
RUNNER_V3_WORKFLOW_PATH = ".github/workflows/runner-v3.yml"
MAX_RUNNER_V3_PATCH_BYTES = 262_144
MAX_RUNNER_V3_AUTHORIZED_PATHS = 64
MAX_RUNNER_V3_ACTIONS = 8

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_GIT_SHA_PATTERN = r"^[0-9a-f]{40}$"
_SAFE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_REPOSITORY_PATTERN = r"^github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
_WORKFLOW_PATTERN = r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$"


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _validate_workspace_path(path: str) -> None:
    if (
        not path
        or len(path) > 512
        or path.startswith(("/", "\\"))
        or "\\" in path
        or "//" in path
        or "\x00" in path
    ):
        raise ValueError("Runner V3 path must be a normalized repository-relative path")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts) or parts[0].casefold() == ".git":
        raise ValueError("Runner V3 path must be a normalized repository-relative path")


class RunnerV3Action(StrEnum):
    INSPECT_SOURCE = "inspect_source"
    COMPILE_PYTHON = "compile_python"
    PYTEST = "pytest"
    RUFF_CHECK = "ruff_check"
    RUFF_FORMAT_CHECK = "ruff_format_check"
    MYPY = "mypy"
    BUILD_PACKAGE = "build_package"
    GIT_DIFF = "git_diff"


class RunnerV3WorkspaceMode(StrEnum):
    READ_ONLY = "read_only"
    EPHEMERAL_PATCH = "ephemeral_patch"


class RunnerV3Outcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RunnerV3Patch(CreatorSchema):
    schema_version: Literal["lil-tweak.runner-v3-patch/v1"] = "lil-tweak.runner-v3-patch/v1"
    text: StrictStr = Field(min_length=1)
    patch_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    authorized_paths: tuple[StrictStr, ...] = Field(
        min_length=1,
        max_length=MAX_RUNNER_V3_AUTHORIZED_PATHS,
    )

    @classmethod
    def issue(
        cls,
        *,
        text: str,
        authorized_paths: tuple[str, ...],
    ) -> RunnerV3Patch:
        values = {
            "text": text,
            "authorized_paths": authorized_paths,
            "patch_digest": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        }
        return cls.model_validate(values)

    @model_validator(mode="after")
    def validate_patch(self) -> Self:
        raw = self.text.encode("utf-8")
        if len(raw) > MAX_RUNNER_V3_PATCH_BYTES:
            raise ValueError("Runner V3 patch exceeds 262144 UTF-8 bytes")
        if "\x00" in self.text or "\r" in self.text:
            raise ValueError("Runner V3 patch contains an unsafe control separator")
        if len(set(self.authorized_paths)) != len(self.authorized_paths):
            raise ValueError("Runner V3 authorized paths must be unique")
        for path in self.authorized_paths:
            _validate_workspace_path(path)
        expected = hashlib.sha256(raw).hexdigest()
        if not secrets.compare_digest(self.patch_digest, expected):
            raise ValueError("Runner V3 patch digest mismatch")
        return self


class RunnerV3JobManifest(CreatorSchema):
    schema_version: Literal["lil-tweak.runner-v3-job/v1"] = "lil-tweak.runner-v3-job/v1"
    execution_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    attempt_nonce: StrictStr = Field(pattern=_SHA256_PATTERN)
    runner_profile_id: Literal["galor-tweak-runner-v3-github-01"] = RUNNER_V3_PROFILE_ID
    repository_id: StrictStr = Field(pattern=_REPOSITORY_PATTERN)
    source_commit: StrictStr = Field(pattern=_GIT_SHA_PATTERN)
    source_tree: StrictStr = Field(pattern=_GIT_SHA_PATTERN)
    contract_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    lease_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    commands_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    approval_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    policy_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    issued_at: datetime
    expires_at: datetime
    cpu_ceiling: StrictInt = Field(ge=1, le=64)
    memory_mb_ceiling: StrictInt = Field(ge=128, le=262_144)
    disk_mb_ceiling: StrictInt = Field(ge=1, le=1_048_576)
    timeout_seconds: StrictInt = Field(ge=1, le=1_800)
    output_byte_limit: StrictInt = Field(ge=1, le=1_000_000)
    workspace_mode: RunnerV3WorkspaceMode
    source_write_authorized: StrictBool
    actions: tuple[RunnerV3Action, ...] = Field(
        min_length=1,
        max_length=MAX_RUNNER_V3_ACTIONS,
    )
    patch: RunnerV3Patch | None = None
    manifest_digest: StrictStr = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def issue(
        cls,
        *,
        execution_id: str,
        attempt_nonce: str,
        repository_id: str,
        source_commit: str,
        source_tree: str,
        contract_digest: str,
        lease_digest: str,
        commands_digest: str,
        approval_digest: str,
        policy_digest: str,
        issued_at: datetime,
        expires_at: datetime,
        cpu_ceiling: int,
        memory_mb_ceiling: int,
        disk_mb_ceiling: int,
        timeout_seconds: int,
        output_byte_limit: int,
        workspace_mode: RunnerV3WorkspaceMode,
        source_write_authorized: bool,
        actions: tuple[RunnerV3Action, ...],
        patch: RunnerV3Patch | None,
    ) -> RunnerV3JobManifest:
        values: dict[str, Any] = {
            "execution_id": execution_id,
            "attempt_nonce": attempt_nonce,
            "runner_profile_id": RUNNER_V3_PROFILE_ID,
            "repository_id": repository_id,
            "source_commit": source_commit,
            "source_tree": source_tree,
            "contract_digest": contract_digest,
            "lease_digest": lease_digest,
            "commands_digest": commands_digest,
            "approval_digest": approval_digest,
            "policy_digest": policy_digest,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "cpu_ceiling": cpu_ceiling,
            "memory_mb_ceiling": memory_mb_ceiling,
            "disk_mb_ceiling": disk_mb_ceiling,
            "timeout_seconds": timeout_seconds,
            "output_byte_limit": output_byte_limit,
            "workspace_mode": workspace_mode,
            "source_write_authorized": source_write_authorized,
            "actions": actions,
            "patch": patch,
        }
        draft = cls.model_construct(**values, manifest_digest="0" * 64)
        values["manifest_digest"] = content_digest(
            draft.model_dump(mode="json", exclude={"manifest_digest"})
        )
        return cls.model_validate(values)

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        if not _aware(self.issued_at) or not _aware(self.expires_at):
            raise ValueError("Runner V3 manifest timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("Runner V3 manifest must expire after issuance")
        if (self.expires_at - self.issued_at).total_seconds() > 1_800:
            raise ValueError("Runner V3 manifest expiry exceeds 1800 seconds")
        if len(set(self.actions)) != len(self.actions):
            raise ValueError("Runner V3 actions must be unique")
        if RunnerV3Action.INSPECT_SOURCE not in self.actions:
            raise ValueError("Runner V3 actions must include inspect_source")
        if self.workspace_mode is RunnerV3WorkspaceMode.READ_ONLY:
            if self.patch is not None or self.source_write_authorized:
                raise ValueError("Runner V3 read-only work cannot contain a patch")
        else:
            if not self.source_write_authorized:
                raise ValueError("Runner V3 patch mode requires source-write authority")
            if self.patch is None:
                raise ValueError("Runner V3 patch mode requires a patch")
            if RunnerV3Action.GIT_DIFF not in self.actions:
                raise ValueError("Runner V3 patch mode requires git_diff evidence")
        expected = content_digest(self.model_dump(mode="json", exclude={"manifest_digest"}))
        if not secrets.compare_digest(self.manifest_digest, expected):
            raise ValueError("Runner V3 manifest digest mismatch")
        return self


class RunnerV3StepReceipt(CreatorSchema):
    schema_version: Literal["lil-tweak.runner-v3-step-receipt/v1"] = (
        "lil-tweak.runner-v3-step-receipt/v1"
    )
    action: RunnerV3Action
    outcome: RunnerV3Outcome
    exit_code: StrictInt = Field(ge=0, le=255)
    stdout_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    stderr_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    started_at_ms: StrictInt = Field(ge=0)
    finished_at_ms: StrictInt = Field(ge=0)
    output_truncated: StrictBool

    @model_validator(mode="after")
    def validate_step(self) -> Self:
        if self.finished_at_ms < self.started_at_ms:
            raise ValueError("Runner V3 step timestamps are invalid")
        if self.outcome is RunnerV3Outcome.SUCCEEDED and self.exit_code != 0:
            raise ValueError("successful Runner V3 step requires exit code zero")
        return self


class RunnerV3HostCapacity(CreatorSchema):
    schema_version: Literal["lil-tweak.runner-v3-host-capacity/v1"] = (
        "lil-tweak.runner-v3-host-capacity/v1"
    )
    cpu_count: StrictInt = Field(ge=1, le=1_024)
    memory_mb: StrictInt = Field(ge=128)
    free_disk_mb: StrictInt = Field(ge=1)
    runner_os: StrictStr = Field(min_length=1, max_length=64)
    runner_arch: StrictStr = Field(min_length=1, max_length=64)
    runner_name: StrictStr = Field(min_length=1, max_length=256)
    runner_label: StrictStr = Field(min_length=1, max_length=128)


class RunnerV3Receipt(CreatorSchema):
    schema_version: Literal["lil-tweak.runner-v3-receipt/v1"] = "lil-tweak.runner-v3-receipt/v1"
    execution_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    runner_profile_id: Literal["galor-tweak-runner-v3-github-01"]
    repository_id: StrictStr = Field(pattern=_REPOSITORY_PATTERN)
    manifest_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    lease_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    source_commit_before: StrictStr = Field(pattern=_GIT_SHA_PATTERN)
    source_tree_before: StrictStr = Field(pattern=_GIT_SHA_PATTERN)
    source_commit_after: StrictStr = Field(pattern=_GIT_SHA_PATTERN)
    source_tree_after: StrictStr = Field(pattern=_GIT_SHA_PATTERN)
    host_capacity: RunnerV3HostCapacity
    steps: tuple[RunnerV3StepReceipt, ...] = Field(max_length=MAX_RUNNER_V3_ACTIONS)
    outcome: RunnerV3Outcome
    workspace_changed: StrictBool
    changed_paths: tuple[StrictStr, ...] = Field(
        default_factory=tuple,
        max_length=MAX_RUNNER_V3_AUTHORIZED_PATHS,
    )
    candidate_patch_digest: StrictStr | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    started_at_ms: StrictInt = Field(ge=0)
    finished_at_ms: StrictInt = Field(ge=0)
    receipt_digest: StrictStr = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def issue(
        cls,
        *,
        manifest: RunnerV3JobManifest,
        host_capacity: RunnerV3HostCapacity,
        steps: tuple[RunnerV3StepReceipt, ...],
        outcome: RunnerV3Outcome,
        source_commit_after: str,
        source_tree_after: str,
        workspace_changed: bool,
        changed_paths: tuple[str, ...],
        candidate_patch_digest: str | None,
        started_at_ms: int,
        finished_at_ms: int,
    ) -> RunnerV3Receipt:
        values: dict[str, Any] = {
            "execution_id": manifest.execution_id,
            "runner_profile_id": manifest.runner_profile_id,
            "repository_id": manifest.repository_id,
            "manifest_digest": manifest.manifest_digest,
            "lease_digest": manifest.lease_digest,
            "source_commit_before": manifest.source_commit,
            "source_tree_before": manifest.source_tree,
            "source_commit_after": source_commit_after,
            "source_tree_after": source_tree_after,
            "host_capacity": host_capacity,
            "steps": steps,
            "outcome": outcome,
            "workspace_changed": workspace_changed,
            "changed_paths": changed_paths,
            "candidate_patch_digest": candidate_patch_digest,
            "started_at_ms": started_at_ms,
            "finished_at_ms": finished_at_ms,
        }
        draft = cls.model_construct(**values, receipt_digest="0" * 64)
        values["receipt_digest"] = content_digest(
            draft.model_dump(mode="json", exclude={"receipt_digest"})
        )
        return cls.model_validate(values)

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        if self.finished_at_ms < self.started_at_ms:
            raise ValueError("Runner V3 receipt timestamps are invalid")
        if len(set(self.changed_paths)) != len(self.changed_paths):
            raise ValueError("Runner V3 changed paths must be unique")
        for path in self.changed_paths:
            _validate_workspace_path(path)
        if not self.workspace_changed and self.changed_paths:
            raise ValueError("unchanged Runner V3 workspace cannot report changed paths")
        if not self.workspace_changed and self.candidate_patch_digest is not None:
            raise ValueError("unchanged Runner V3 workspace cannot report a candidate patch")
        if self.workspace_changed and not self.changed_paths:
            raise ValueError("changed Runner V3 workspace requires changed paths")
        if self.workspace_changed and self.candidate_patch_digest is None:
            raise ValueError("changed Runner V3 workspace requires a candidate patch digest")
        if self.outcome is RunnerV3Outcome.SUCCEEDED and any(
            step.outcome is not RunnerV3Outcome.SUCCEEDED for step in self.steps
        ):
            raise ValueError("successful Runner V3 receipt cannot contain a failed step")
        expected = content_digest(self.model_dump(mode="json", exclude={"receipt_digest"}))
        if not secrets.compare_digest(self.receipt_digest, expected):
            raise ValueError("Runner V3 receipt digest mismatch")
        return self


class RunnerV3ProviderConfig(CreatorSchema):
    provider_role: Literal["builder"] = "builder"
    repository_id: StrictStr = Field(pattern=_REPOSITORY_PATTERN)
    workflow_path: StrictStr = Field(pattern=_WORKFLOW_PATTERN)
    runner_profile_id: Literal["galor-tweak-runner-v3-github-01"] = RUNNER_V3_PROFILE_ID
    maximum_state_age_seconds: StrictInt = Field(default=300, ge=1, le=3_600)


class RunnerV3WorkflowSnapshot(CreatorSchema):
    run_id: StrictStr = Field(min_length=1, max_length=256)
    source_commit: StrictStr = Field(pattern=_GIT_SHA_PATTERN)
    source_tree: StrictStr = Field(pattern=_GIT_SHA_PATTERN)
    manifest_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    status: Literal["queued", "in_progress", "completed"]
    conclusion: Literal["success", "failure", "cancelled", "timed_out"] | None = None
    outcome: RunnerV3Outcome | None = None
    receipt_digest: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        if self.status != "completed":
            if self.conclusion is not None or self.outcome is not None:
                raise ValueError("incomplete Runner V3 workflow cannot have an outcome")
            if self.receipt_digest is not None:
                raise ValueError("incomplete Runner V3 workflow cannot have a receipt")
            return self
        if self.conclusion is None:
            raise ValueError("completed Runner V3 workflow requires a conclusion")
        if self.conclusion == "success":
            if self.outcome is not RunnerV3Outcome.SUCCEEDED:
                raise ValueError("successful Runner V3 workflow requires succeeded outcome")
            if self.receipt_digest is None:
                raise ValueError("successful Runner V3 workflow requires a receipt digest")
        elif self.outcome is RunnerV3Outcome.SUCCEEDED:
            raise ValueError("failed Runner V3 workflow cannot report succeeded outcome")
        return self


class RunnerV3Client(Protocol):
    async def dispatch_job(
        self,
        *,
        repository_id: str,
        workflow_path: str,
        source_commit: str,
        manifest_json: str,
        manifest_digest: str,
    ) -> str: ...

    async def get_workflow(self, run_id: str) -> RunnerV3WorkflowSnapshot: ...

    async def cancel_workflow(self, run_id: str) -> None: ...
