from __future__ import annotations

from typing import Protocol

from .workbench_contract import (
    CapabilityState,
    CapabilityStatus,
    WorkbenchCapability,
)


class ModelCapabilitySource(Protocol):
    @property
    def provider_name(self) -> str: ...

    @property
    def model_name(self) -> str: ...

    @property
    def connected(self) -> bool: ...


class RunnerCapabilitySource(Protocol):
    @property
    def provider_name(self) -> str: ...

    @property
    def connected(self) -> bool: ...

    @property
    def qualification_status(self) -> str: ...

    @property
    def authorization_digest(self) -> str | None: ...


def _status(
    capability: WorkbenchCapability,
    *,
    configured: bool,
    connected: bool,
    authorized: bool,
    healthy: bool,
    qualified: bool,
    blockers: tuple[str, ...],
) -> CapabilityStatus:
    operational = all((configured, connected, authorized, healthy, qualified))
    return CapabilityStatus(
        capability=capability,
        state=CapabilityState.OPERATIONAL if operational else CapabilityState.BLOCKED,
        configured=configured,
        connected=connected,
        authorized=authorized,
        healthy=healthy,
        qualified=qualified,
        operational=operational,
        blockers=() if operational else blockers,
    )


def _model_status(model: ModelCapabilitySource) -> CapabilityStatus:
    configured = model.provider_name.casefold() not in {
        "",
        "disconnected",
        "none",
    } and model.model_name.casefold() not in {"", "none"}
    connected = bool(model.connected)
    authorized = bool(getattr(model, "authorization_verified", False))
    healthy = bool(getattr(model, "health_verified", False))
    qualified = bool(getattr(model, "qualification_verified", False))
    blockers: list[str] = []
    if not configured:
        blockers.append("No live model provider and model are configured.")
    if not connected:
        blockers.append("The live model provider connection is not established.")
    if not authorized:
        blockers.append("Provider authentication and model entitlement are not verified.")
    if not healthy:
        blockers.append("Provider health and the effective returned model are not verified.")
    if not qualified:
        blockers.append("The requested model and reasoning profile have no qualification record.")
    return _status(
        WorkbenchCapability.MODEL,
        configured=configured,
        connected=connected,
        authorized=authorized,
        healthy=healthy,
        qualified=qualified,
        blockers=tuple(blockers),
    )


def _runner_status(runner: RunnerCapabilitySource) -> CapabilityStatus:
    configured = runner.provider_name.casefold() not in {"", "disconnected", "none"}
    connected = bool(runner.connected)
    authorized = runner.authorization_digest is not None
    healthy = connected
    qualified = runner.qualification_status == "qualified"
    blockers: list[str] = []
    if not configured:
        blockers.append("No bounded command runner provider is configured.")
    if not connected:
        blockers.append("The bounded command runner connection is not established.")
    if not authorized:
        blockers.append("No signed runner connection authorization is active.")
    if not healthy:
        blockers.append("Runner health is not established.")
    if not qualified:
        blockers.append("No current independent runner qualification is active.")
    return _status(
        WorkbenchCapability.RUNNER,
        configured=configured,
        connected=connected,
        authorized=authorized,
        healthy=healthy,
        qualified=qualified,
        blockers=tuple(blockers),
    )


def build_capability_statuses(
    *,
    model: ModelCapabilitySource,
    runner: RunnerCapabilitySource,
) -> tuple[CapabilityStatus, ...]:
    """Build fail-closed status records without inferring evidence that is not present."""

    return (
        _model_status(model),
        _runner_status(runner),
        CapabilityStatus(
            capability=WorkbenchCapability.CHECKPOINT,
            blockers=(
                "No external anti-rollback checkpoint is configured; local HMAC integrity "
                "is not an external checkpoint.",
            ),
        ),
        CapabilityStatus(
            capability=WorkbenchCapability.PUBLISHER,
            blockers=("No authenticated release publisher is configured or qualified.",),
        ),
        CapabilityStatus(
            capability=WorkbenchCapability.BROWSER,
            blockers=("No real-browser qualification evidence is recorded.",),
        ),
        CapabilityStatus(
            capability=WorkbenchCapability.GCP,
            blockers=("GCP access and deployment are intentionally disabled and deferred.",),
        ),
    )
