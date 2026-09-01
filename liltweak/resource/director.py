from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import Field, StrictBool, StrictStr, model_validator

from ..creator_contract import CreatorSchema, content_digest
from .catalog import ResourceCatalog
from .contracts import WorkloadRequirements
from .scheduler import ResourceScheduler, RoutingDecision


class ResourceDirectorMode(StrEnum):
    DISABLED = "disabled"
    SHADOW = "shadow"
    ACTIVE = "active"


class ResourceDirectorDecision(CreatorSchema):
    schema_version: Literal["resource-director-decision-v1"] = "resource-director-decision-v1"
    mode: ResourceDirectorMode
    requirement_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    existing_execution_decision: StrictStr = Field(min_length=1, max_length=512)
    failed_runner_profile_id: StrictStr | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    )
    route: RoutingDecision | None = None
    dispatch_authorized: StrictBool = False
    provider_provisioned: Literal[False] = False
    command_sent: Literal[False] = False
    blocked_reason: StrictStr = Field(min_length=1, max_length=512)
    evidence_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        if self.mode is ResourceDirectorMode.DISABLED and self.route is not None:
            raise ValueError("disabled Resource Director cannot calculate a route")
        if self.mode is ResourceDirectorMode.SHADOW and self.dispatch_authorized:
            raise ValueError("shadow Resource Director cannot authorize dispatch")
        if (
            self.failed_runner_profile_id is not None
            and self.route is not None
            and self.route.selected_profile is not None
            and self.route.selected_profile.runner_profile_id == self.failed_runner_profile_id
        ):
            raise ValueError("Resource Director cannot reselect the failed runner profile")
        expected = content_digest(self.model_dump(mode="json", exclude={"evidence_digest"}))
        if self.evidence_digest != expected:
            raise ValueError("resource director evidence digest mismatch")
        return self


class ResourceDirector:
    def __init__(
        self,
        catalog: ResourceCatalog,
        *,
        mode: ResourceDirectorMode = ResourceDirectorMode.DISABLED,
        scheduler: ResourceScheduler | None = None,
    ) -> None:
        self._catalog = catalog
        self._mode = mode
        self._scheduler = ResourceScheduler() if scheduler is None else scheduler

    @classmethod
    def from_environment(
        cls,
        catalog: ResourceCatalog,
        *,
        environment: Mapping[str, str],
        scheduler: ResourceScheduler | None = None,
    ) -> ResourceDirector:
        raw_mode = environment.get("RESOURCE_DIRECTOR_MODE", ResourceDirectorMode.DISABLED.value)
        try:
            mode = ResourceDirectorMode(raw_mode)
        except ValueError as exc:
            raise ValueError("RESOURCE_DIRECTOR_MODE must be disabled, shadow, or active") from exc
        return cls(catalog, mode=mode, scheduler=scheduler)

    def route(
        self,
        requirements: WorkloadRequirements,
        *,
        as_of: datetime,
        existing_execution_decision: str,
        failed_runner_profile_id: str | None = None,
    ) -> ResourceDirectorDecision:
        route: RoutingDecision | None = None
        if self._mode is ResourceDirectorMode.DISABLED:
            blocked_reason = "Resource Director is disabled"
        elif failed_runner_profile_id is not None:
            if requirements.authority.failover_authorized:
                blocked_reason = "authorized failover requires separate verified activation"
            else:
                blocked_reason = "resource failover is not authorized"
        else:
            route = self._scheduler.select(requirements, self._catalog, as_of=as_of)
            if self._mode is ResourceDirectorMode.SHADOW:
                blocked_reason = "shadow mode records a comparison and forbids dispatch"
            else:
                blocked_reason = "active routing requires separate verified activation"
        values: dict[str, Any] = {
            "mode": self._mode,
            "requirement_digest": requirements.requirements_digest,
            "existing_execution_decision": existing_execution_decision,
            "failed_runner_profile_id": failed_runner_profile_id,
            "route": route,
            "dispatch_authorized": False,
            "provider_provisioned": False,
            "command_sent": False,
            "blocked_reason": blocked_reason,
        }
        draft = ResourceDirectorDecision.model_construct(**values, evidence_digest="0" * 64)
        values["evidence_digest"] = content_digest(
            draft.model_dump(mode="json", exclude={"evidence_digest"})
        )
        return ResourceDirectorDecision.model_validate(values)
