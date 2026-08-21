from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr

from .planning_chat import PlanningChatService
from .reasoning_policy import FoundationModel
from .workbench import WorkbenchController


class OperationalSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ConnectionState(OperationalSchema):
    state: Literal["CONNECTED", "DISCONNECTED", "BLOCKED"]
    verified: StrictBool
    detail: StrictStr


class OperationalStatus(OperationalSchema):
    backend: ConnectionState
    provider: ConnectionState
    primary_model: ConnectionState
    fallback_model: ConnectionState
    runner: ConnectionState
    execution: ConnectionState
    browser: ConnectionState
    git: ConnectionState
    repository: ConnectionState
    project_workspace: ConnectionState
    planning_chat: ConnectionState
    engineering_mode: ConnectionState


def _state(connected: bool, detail: str) -> ConnectionState:
    return ConnectionState(
        state="CONNECTED" if connected else "DISCONNECTED",
        verified=connected,
        detail=detail,
    )


def build_operational_status(
    *,
    controller: WorkbenchController,
    planning_chat: PlanningChatService | None,
) -> OperationalStatus:
    primary = bool(planning_chat and planning_chat.primary_connected and controller.model.connected)
    fallback = bool(planning_chat and planning_chat.fallback_connected)
    repositories = bool(controller.repository_ids)
    return OperationalStatus(
        backend=_state(True, "Authenticated private FastAPI request completed on loopback."),
        provider=_state(primary, "OpenAI Responses qualification is required before connection."),
        primary_model=_state(primary, f"{FoundationModel.SOL.value} standard/high"),
        fallback_model=_state(
            fallback,
            f"{FoundationModel.TERRA.value} read-only transient-failure fallback only",
        ),
        runner=_state(False, "No qualified process transport is injected."),
        execution=_state(
            False, "Shell, patch, Git, filesystem mutation, and deployment are disabled."
        ),
        browser=_state(False, "No active browser qualification is trusted by the server."),
        git=_state(False, "Git mutation is outside the private reasoning boundary."),
        repository=_state(repositories, "Registered repositories are read-only until task import."),
        project_workspace=_state(
            True, "Local project records use zero model calls and zero tokens."
        ),
        planning_chat=_state(primary, "Tool-free bounded planning with recorded usage and cost."),
        engineering_mode=_state(
            controller.model.connected,
            "Sol high repository reasoning is tool-free; execution remains disconnected.",
        ),
    )
