from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    StringConstraints,
    field_validator,
    model_validator,
)
from pydantic_core import to_jsonable_python

SHA256 = r"^[0-9a-f]{64}$"
SAFE_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
RelativePath = Annotated[
    str,
    StringConstraints(min_length=1, max_length=512, pattern=r"^[^\\\x00-\x1f\x7f]+$"),
]


def utc_now() -> datetime:
    return datetime.now(UTC)


def canonical_json(value: object) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", exclude_none=False)
    else:
        value = to_jsonable_python(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class WorkbenchSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class WorkbenchCapability(StrEnum):
    MODEL = "model"
    RUNNER = "runner"
    CHECKPOINT = "checkpoint"
    PUBLISHER = "publisher"
    BROWSER = "browser"
    GCP = "gcp"


class CapabilityState(StrEnum):
    BLOCKED = "blocked"
    OPERATIONAL = "operational"


class CapabilityStatus(WorkbenchSchema):
    capability: WorkbenchCapability
    state: CapabilityState = CapabilityState.BLOCKED
    configured: StrictBool = False
    connected: StrictBool = False
    authorized: StrictBool = False
    healthy: StrictBool = False
    qualified: StrictBool = False
    operational: StrictBool = False
    blockers: tuple[StrictStr, ...] = ("Capability qualification has not been recorded.",)

    @field_validator("blockers")
    @classmethod
    def blockers_are_exact_and_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not blocker.strip() for blocker in value):
            raise ValueError("capability blockers must be non-empty")
        if len(set(value)) != len(value):
            raise ValueError("capability blockers must be unique")
        return value

    @model_validator(mode="after")
    def operational_state_requires_every_gate(self) -> CapabilityStatus:
        every_gate = all(
            (
                self.configured,
                self.connected,
                self.authorized,
                self.healthy,
                self.qualified,
            )
        )
        if self.operational:
            if self.state != CapabilityState.OPERATIONAL or not every_gate or self.blockers:
                raise ValueError("operational capability requires every gate and no blockers")
        elif self.state != CapabilityState.BLOCKED or not self.blockers:
            raise ValueError("non-operational capability must be blocked with exact blockers")
        return self


def default_workbench_capabilities() -> tuple[CapabilityStatus, ...]:
    return tuple(CapabilityStatus(capability=capability) for capability in WorkbenchCapability)


class WorkbenchMode(StrEnum):
    ENGINEERING = "engineering"
    GCP_QUALIFICATION = "gcp_qualification"


class WorkbenchState(StrEnum):
    RECEIVED = "RECEIVED"
    INSPECTING = "INSPECTING"
    ANALYZED = "ANALYZED"
    PLAN_READY = "PLAN_READY"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    TESTING = "TESTING"
    VERIFIED = "VERIFIED"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    CANCELED = "CANCELED"


TERMINAL_STATES = frozenset(
    {
        WorkbenchState.COMPLETED,
        WorkbenchState.BLOCKED,
        WorkbenchState.FAILED,
        WorkbenchState.ROLLED_BACK,
        WorkbenchState.CANCELED,
    }
)


class ToolKind(StrEnum):
    LIST_FILES = "list_files"
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    APPLY_PATCH = "apply_patch"
    COMMAND = "command"


class StepPhase(StrEnum):
    INSPECTION = "inspection"
    MUTATION = "mutation"
    TEST = "test"
    VERIFICATION = "verification"


class NetworkMode(StrEnum):
    DENIED = "denied"
    TASK_SCOPED = "task_scoped"


class SubmissionStatus(StrEnum):
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class ApprovalPurpose(StrEnum):
    EXECUTE = "execute"
    ROLLBACK = "rollback"
    APPLY_PATCH = "apply_patch"
    LOCAL_COMMIT = "local_commit"


class GcpExamConfig(WorkbenchSchema):
    examination_id: StrictStr = Field(pattern=SAFE_ID)
    examiner: Literal["Sol"] = "Sol"
    candidate: Literal["Lil Tweak"] = "Lil Tweak"
    authorized_project: StrictStr = Field(pattern=r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
    candidate_service_account: StrictStr = Field(
        pattern=r"^[A-Za-z0-9._%+-]+@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$"
    )
    region: StrictStr = Field(pattern=r"^[a-z]+-[a-z]+[0-9]$")
    zone: StrictStr = Field(pattern=r"^[a-z]+-[a-z]+[0-9]-[a-z]$")
    spending_ceiling_usd: float = Field(ge=0, le=10_000)
    current_task_number: StrictInt = Field(ge=1)

    @model_validator(mode="after")
    def zone_matches_region(self) -> GcpExamConfig:
        if not self.zone.startswith(f"{self.region}-"):
            raise ValueError("GCP examination zone must belong to the authorized region")
        return self

    @property
    def config_digest(self) -> str:
        return content_digest(self)


class TaskImport(WorkbenchSchema):
    mode: WorkbenchMode = WorkbenchMode.ENGINEERING
    title: StrictStr = Field(min_length=1, max_length=256)
    direction: StrictStr = Field(min_length=1, max_length=32_000)
    repository_id: StrictStr | None = Field(default=None, max_length=512)
    repository_fingerprint: StrictStr | None = Field(default=None, pattern=SHA256)
    source_snapshot_digest: StrictStr = Field(pattern=SHA256)
    requires_changes: StrictBool = False
    acceptance_commands: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=16)
    examination: GcpExamConfig | None = None

    @model_validator(mode="after")
    def validate_mode(self) -> TaskImport:
        if self.mode == WorkbenchMode.GCP_QUALIFICATION and self.examination is None:
            raise ValueError("GCP qualification tasks require an examination configuration")
        if self.mode != WorkbenchMode.GCP_QUALIFICATION and self.examination is not None:
            raise ValueError("examination configuration is limited to GCP qualification mode")
        if self.repository_fingerprint is not None and self.repository_id is None:
            raise ValueError("repository fingerprint requires a registered repository identity")
        if self.repository_id is not None and (
            not self.requires_changes or not self.acceptance_commands
        ):
            raise ValueError(
                "repository tasks require a source change and server-owned acceptance commands"
            )
        if any(
            not command
            or len(command) > 512
            or any(ord(character) < 32 or ord(character) == 127 for character in command)
            for command in self.acceptance_commands
        ):
            raise ValueError("acceptance command binding is invalid")
        return self

    @property
    def task_digest(self) -> str:
        return content_digest(self)


class CommandRequest(WorkbenchSchema):
    executable: StrictStr = Field(min_length=1, max_length=128)
    args: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=128)
    working_directory: RelativePath = "."
    timeout_seconds: StrictInt = Field(default=300, ge=1, le=1_800)
    output_byte_limit: StrictInt = Field(default=1_000_000, ge=1_024, le=10_000_000)
    network: NetworkMode = NetworkMode.DENIED
    estimated_cost_usd: float = Field(default=0, ge=0, le=10_000)

    @model_validator(mode="after")
    def structured_only(self) -> CommandRequest:
        if "/" in self.executable or "\\" in self.executable:
            raise ValueError("commands require a configured bare executable")
        for value in (self.executable, *self.args):
            if not value or "\x00" in value or "\r" in value or "\n" in value:
                raise ValueError("command values must be non-empty structured arguments")
            if len(value) > 2_048:
                raise ValueError("command argument exceeds the bounded length")
        return self


class FileRequest(WorkbenchSchema):
    path: RelativePath
    content: StrictStr | None = Field(default=None, max_length=2_000_000)
    expected_sha256: StrictStr | None = Field(default=None, pattern=SHA256)


class ToolRequest(WorkbenchSchema):
    tool_id: StrictStr = Field(pattern=SAFE_ID)
    kind: ToolKind
    phase: StepPhase
    purpose: StrictStr = Field(min_length=1, max_length=1_000)
    command: CommandRequest | None = None
    file: FileRequest | None = None
    required: StrictBool = True

    @model_validator(mode="after")
    def exactly_one_payload(self) -> ToolRequest:
        if self.kind == ToolKind.COMMAND:
            if self.command is None or self.file is not None:
                raise ValueError("command tools require only a command payload")
        elif self.file is None or self.command is not None:
            raise ValueError("file tools require only a file payload")
        if self.phase == StepPhase.INSPECTION and self.kind in {
            ToolKind.WRITE_FILE,
            ToolKind.APPLY_PATCH,
        }:
            raise ValueError("inspection steps cannot mutate files")
        return self

    @property
    def request_digest(self) -> str:
        return content_digest(self)


class WorkbenchPlan(WorkbenchSchema):
    schema_version: Literal["workbench-plan-v1"] = "workbench-plan-v1"
    summary: StrictStr = Field(min_length=1, max_length=2_000)
    reasoning: StrictStr = Field(min_length=1, max_length=8_000)
    source_snapshot_digest: StrictStr = Field(pattern=SHA256)
    steps: tuple[ToolRequest, ...] = Field(min_length=1, max_length=64)
    expected_artifacts: tuple[RelativePath, ...] = Field(default_factory=tuple, max_length=128)
    rollback_steps: tuple[StrictStr, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def unique_and_verifiable(self) -> WorkbenchPlan:
        ids = [step.tool_id for step in self.steps]
        if len(ids) != len(set(ids)):
            raise ValueError("tool ids must be unique")
        phase_order = {
            StepPhase.INSPECTION: 0,
            StepPhase.MUTATION: 1,
            StepPhase.TEST: 2,
            StepPhase.VERIFICATION: 3,
        }
        observed = [phase_order[step.phase] for step in self.steps]
        if observed != sorted(observed):
            raise ValueError("plan phases must be ordered inspection, mutation, test, verification")
        if any(
            step.kind in {ToolKind.WRITE_FILE, ToolKind.APPLY_PATCH}
            and step.phase != StepPhase.MUTATION
            for step in self.steps
        ):
            raise ValueError("file mutation tools are limited to the mutation phase")
        required_commands = {
            step.phase for step in self.steps if step.required and step.kind == ToolKind.COMMAND
        }
        if StepPhase.TEST not in required_commands:
            raise ValueError("a plan requires at least one required command test")
        if StepPhase.VERIFICATION not in required_commands:
            raise ValueError("a plan requires at least one required command verification")
        return self

    @property
    def plan_digest(self) -> str:
        return content_digest(self)


class WorkbenchTask(WorkbenchSchema):
    id: StrictStr = Field(pattern=SAFE_ID)
    imported: TaskImport
    task_digest: StrictStr = Field(pattern=SHA256)
    state: WorkbenchState
    creator_brief_digest: StrictStr | None = Field(default=None, pattern=SHA256)
    creator_route_digest: StrictStr | None = Field(default=None, pattern=SHA256)
    plan: WorkbenchPlan | None = None
    plan_digest: StrictStr | None = Field(default=None, pattern=SHA256)
    active_attempt: StrictInt = Field(default=0, ge=0, le=100)
    blocked_reason: StrictStr | None = Field(default=None, max_length=2_000)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def truthful_state(self) -> WorkbenchTask:
        if self.task_digest != self.imported.task_digest:
            raise ValueError("task digest mismatch")
        if self.plan is not None and self.plan_digest != self.plan.plan_digest:
            raise ValueError("plan digest mismatch")
        if (
            self.state
            in {
                WorkbenchState.PLAN_READY,
                WorkbenchState.AWAITING_APPROVAL,
                WorkbenchState.APPROVED,
                WorkbenchState.EXECUTING,
                WorkbenchState.TESTING,
                WorkbenchState.VERIFIED,
                WorkbenchState.COMPLETED,
            }
            and self.plan is None
        ):
            raise ValueError("plan-bound states require an immutable plan")
        return self


class ApprovalDecision(WorkbenchSchema):
    decision: Literal["approve", "reject", "request_revision"]
    approval_digest: StrictStr = Field(pattern=SHA256)


class WorkbenchApproval(WorkbenchSchema):
    id: StrictStr = Field(pattern=SAFE_ID)
    task_id: StrictStr = Field(pattern=SAFE_ID)
    task_digest: StrictStr = Field(pattern=SHA256)
    purpose: ApprovalPurpose = ApprovalPurpose.EXECUTE
    plan_digest: StrictStr = Field(pattern=SHA256)
    source_snapshot_digest: StrictStr = Field(pattern=SHA256)
    repository_id: StrictStr | None = Field(default=None, max_length=512)
    examination_digest: StrictStr | None = Field(default=None, pattern=SHA256)
    project: StrictStr | None = None
    candidate_identity: StrictStr | None = None
    execution_attempt: StrictInt = Field(ge=1, le=100)
    approved_tool_digests: tuple[StrictStr, ...] = Field(min_length=1, max_length=64)
    policy_digest: StrictStr = Field(pattern=SHA256)
    runner_grant_digest: StrictStr | None = Field(default=None, pattern=SHA256)
    network_mode: NetworkMode = NetworkMode.DENIED
    nonce: StrictStr = Field(pattern=SAFE_ID)
    approval_digest: StrictStr = Field(pattern=SHA256)
    status: Literal["pending", "approved", "rejected", "revision", "consumed", "expired"]
    approved_by: StrictStr | None = Field(default=None, max_length=128)
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    decided_at: datetime | None = None
    consumed_at: datetime | None = None

    @model_validator(mode="after")
    def valid_approval(self) -> WorkbenchApproval:
        if self.expires_at <= self.created_at:
            raise ValueError("approval expiry must follow creation")
        expected = content_digest(
            {
                "task_id": self.task_id,
                "task_digest": self.task_digest,
                "purpose": self.purpose.value,
                "plan_digest": self.plan_digest,
                "source_snapshot_digest": self.source_snapshot_digest,
                "repository_id": self.repository_id,
                "examination_digest": self.examination_digest,
                "project": self.project,
                "candidate_identity": self.candidate_identity,
                "execution_attempt": self.execution_attempt,
                "approved_tool_digests": self.approved_tool_digests,
                "policy_digest": self.policy_digest,
                "runner_grant_digest": self.runner_grant_digest,
                "network_mode": self.network_mode.value,
                "nonce": self.nonce,
            }
        )
        if self.approval_digest != expected:
            raise ValueError("approval binding digest mismatch")
        return self


class ToolRunRecord(WorkbenchSchema):
    id: StrictStr = Field(pattern=SAFE_ID)
    task_id: StrictStr = Field(pattern=SAFE_ID)
    attempt: StrictInt = Field(ge=1)
    tool_id: StrictStr = Field(pattern=SAFE_ID)
    request_digest: StrictStr = Field(pattern=SHA256)
    executable: StrictStr | None = None
    args: tuple[StrictStr, ...] = ()
    working_directory: RelativePath = "."
    started_at: datetime
    ended_at: datetime
    exit_code: StrictInt | None = Field(default=None, ge=0, le=255)
    timed_out: StrictBool = False
    canceled: StrictBool = False
    output_digest: StrictStr = Field(pattern=SHA256)
    redacted_output: StrictStr = Field(max_length=100_000)
    network_status: NetworkMode
    evidence_id: StrictStr = Field(pattern=SAFE_ID)
    success: StrictBool


class EvidenceKind(StrEnum):
    TASK = "task"
    SOURCE = "source"
    PLAN = "plan"
    APPROVAL = "approval"
    MODEL = "model"
    PROPOSED = "proposed"
    EXECUTED = "executed"
    TEST = "test"
    VERIFIED = "verified"
    SUBMISSION = "submission"
    CONTROL = "control"
    RECOVERY = "recovery"


class WorkbenchEvidence(WorkbenchSchema):
    id: StrictStr = Field(pattern=SAFE_ID)
    task_id: StrictStr = Field(pattern=SAFE_ID)
    sequence: StrictInt = Field(ge=1)
    kind: EvidenceKind
    event_type: StrictStr = Field(pattern=SAFE_ID)
    payload: dict[str, object]
    previous_hash: StrictStr | None = Field(default=None, pattern=SHA256)
    record_hash: StrictStr = Field(pattern=SHA256)
    created_at: datetime = Field(default_factory=utc_now)


class CandidateSubmission(WorkbenchSchema):
    id: StrictStr = Field(pattern=SAFE_ID)
    task_id: StrictStr = Field(pattern=SAFE_ID)
    status: SubmissionStatus
    summary: StrictStr = Field(max_length=700)
    resources: tuple[StrictStr, ...] = Field(max_length=100)
    verification: tuple[StrictStr, ...] = Field(max_length=100)
    reasoning: StrictStr = Field(max_length=1_200)
    evidence: tuple[StrictStr, ...] = Field(max_length=200)
    known_issues: tuple[StrictStr, ...] = Field(max_length=100)
    locked: StrictBool = False
    submission_digest: StrictStr = Field(pattern=SHA256)
    created_at: datetime = Field(default_factory=utc_now)
    locked_at: datetime | None = None

    @field_validator("summary")
    @classmethod
    def summary_word_limit(cls, value: str) -> str:
        if len(value.split()) > 100:
            raise ValueError("submission summary exceeds 100 words")
        return value

    @field_validator("reasoning")
    @classmethod
    def reasoning_word_limit(cls, value: str) -> str:
        if len(value.split()) > 150:
            raise ValueError("submission reasoning exceeds 150 words")
        return value

    @model_validator(mode="after")
    def digest_matches_content(self) -> CandidateSubmission:
        expected = content_digest(
            self.model_dump(
                mode="json",
                exclude={"submission_digest", "locked", "locked_at"},
            )
        )
        if self.submission_digest != expected:
            raise ValueError("submission digest mismatch")
        return self

    @property
    def rendered(self) -> str:
        resources = "\n".join(f"- {item}" for item in self.resources) or "- None"
        verification = "\n".join(f"- {item}" for item in self.verification) or "- None"
        evidence = "\n".join(f"- {item}" for item in self.evidence) or "- None"
        issues = "\n".join(f"- {item}" for item in self.known_issues) or "None"
        return (
            f"STATUS: {self.status.value}\n"
            f"SUMMARY: {self.summary}\n"
            f"RESOURCES:\n{resources}\n"
            f"VERIFICATION:\n{verification}\n"
            f"REASONING: {self.reasoning}\n"
            f"EVIDENCE:\n{evidence}\n"
            f"KNOWN ISSUES: {issues}"
        )


class WorkbenchHealth(WorkbenchSchema):
    engine_version: Literal["0.8.0-workbench"] = "0.8.0-workbench"
    backend: Literal["fastapi"] = "fastapi"
    provider: StrictStr
    model: StrictStr
    reasoning_tier: StrictStr
    model_connected: StrictBool
    model_status: Literal["connected", "disabled", "failed"]
    runner_provider: StrictStr
    runner_qualification: Literal["qualified", "unqualified", "unavailable"]
    runner_connection: Literal["connected", "disconnected"]
    runner_connected: StrictBool
    repository: StrictStr | None
    project: StrictStr | None
    identity: StrictStr | None
    network: NetworkMode
    execution_permission: StrictBool
    cost_ceiling_usd: float = Field(ge=0)
    emergency_stopped: StrictBool
    evidence_integrity: Literal["durable_hmac", "ephemeral_hmac", "invalid"]
    missing_prerequisites: tuple[StrictStr, ...] = ()
    capabilities: tuple[CapabilityStatus, ...] = Field(
        default_factory=default_workbench_capabilities
    )

    @field_validator("capabilities")
    @classmethod
    def every_capability_is_reported_once(
        cls, value: tuple[CapabilityStatus, ...]
    ) -> tuple[CapabilityStatus, ...]:
        expected = tuple(WorkbenchCapability)
        reported = tuple(status.capability for status in value)
        if reported != expected:
            raise ValueError("Workbench health must report every capability exactly once")
        return value
