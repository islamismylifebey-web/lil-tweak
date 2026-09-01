from __future__ import annotations

from typing import Literal, Protocol, Self

from pydantic import Field, StrictBool, StrictStr, model_validator

from ...creator_contract import CreatorSchema


class GitHubProviderConfig(CreatorSchema):
    provider_role: Literal["independent_verifier"] = "independent_verifier"
    repository_id: StrictStr = Field(pattern=r"^github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    workflow_path: StrictStr = Field(pattern=r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
    runner_profile_id: StrictStr = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    required_checks: tuple[StrictStr, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_checks(self) -> Self:
        if len({item.casefold() for item in self.required_checks}) != len(self.required_checks):
            raise ValueError("GitHub required checks must be unique")
        return self


class GitHubWorkflowSnapshot(CreatorSchema):
    run_id: StrictStr = Field(min_length=1, max_length=256)
    source_commit: StrictStr = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    status: Literal["queued", "in_progress", "completed"]
    conclusion: Literal["success", "failure", "cancelled", "timed_out"] | None = None
    required_checks_passed: StrictBool
    completed_checks: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=64)
    evidence_digest: StrictStr | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        if self.status == "completed" and self.conclusion is None:
            raise ValueError("completed GitHub workflow requires a conclusion")
        if self.status != "completed" and self.conclusion is not None:
            raise ValueError("incomplete GitHub workflow cannot have a conclusion")
        if len({item.casefold() for item in self.completed_checks}) != len(self.completed_checks):
            raise ValueError("completed GitHub workflow checks must be unique")
        return self


class GitHubActionsClient(Protocol):
    async def dispatch_verification(
        self,
        *,
        repository_id: str,
        workflow_path: str,
        source_commit: str,
        lease_digest: str,
    ) -> str: ...

    async def get_workflow(self, run_id: str) -> GitHubWorkflowSnapshot: ...

    async def cancel_workflow(self, run_id: str) -> None: ...
