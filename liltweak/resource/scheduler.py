from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import Field, StrictStr, model_validator

from ..creator_contract import CreatorSchema, content_digest
from .catalog import ResourceCatalog
from .contracts import (
    HealthStatus,
    QualificationStatus,
    ResourceProfile,
    RiskLevel,
    WorkloadRequirements,
    WorkspacePolicy,
)
from .estimator import ResourceCostEstimate, ResourceEstimator


class EliminationStage(StrEnum):
    QUALIFICATION = "qualification"
    HEALTH = "health"
    CAPABILITY = "capability"
    AUTHORIZATION = "authorization"
    COST = "cost"


class ResourceElimination(CreatorSchema):
    runner_profile_id: StrictStr
    stage: EliminationStage
    reason: StrictStr = Field(min_length=1, max_length=512)


class RoutingDecision(CreatorSchema):
    schema_version: str = "resource-routing-decision-v1"
    requirement_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    selected_profile: ResourceProfile | None = None
    estimate: ResourceCostEstimate | None = None
    eliminations: tuple[ResourceElimination, ...]
    explanation: tuple[StrictStr, ...]
    decision_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_decision(self) -> Self:
        if (self.selected_profile is None) != (self.estimate is None):
            raise ValueError("routing selection and estimate must be present together")
        expected = content_digest(self.model_dump(mode="json", exclude={"decision_digest"}))
        if self.decision_digest != expected:
            raise ValueError("routing decision digest mismatch")
        return self


_RISK_RANK = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}

_WORKSPACE_RANK = {
    WorkspacePolicy.READ_ONLY: 0,
    WorkspacePolicy.EPHEMERAL_WRITABLE: 1,
    WorkspacePolicy.PERSISTENT_WRITABLE: 2,
}


class ResourceScheduler:
    def __init__(
        self,
        *,
        maximum_health_age_seconds: int = 300,
        maximum_qualification_age_seconds: int = 86_400,
        estimator: ResourceEstimator | None = None,
    ) -> None:
        if maximum_health_age_seconds <= 0 or maximum_qualification_age_seconds <= 0:
            raise ValueError("resource freshness limits must be positive")
        self._maximum_health_age_seconds = maximum_health_age_seconds
        self._maximum_qualification_age_seconds = maximum_qualification_age_seconds
        self._estimator = ResourceEstimator() if estimator is None else estimator

    def select(
        self,
        requirements: WorkloadRequirements,
        catalog: ResourceCatalog,
        *,
        as_of: datetime,
    ) -> RoutingDecision:
        requirements = WorkloadRequirements.model_validate(requirements.model_dump(mode="python"))
        if as_of.tzinfo is None or as_of.utcoffset() is None:
            raise ValueError("routing time must be timezone-aware")
        candidates = list(catalog.snapshot())
        eliminations: list[ResourceElimination] = []

        def apply_gate(
            stage: EliminationStage,
            checker: Callable[[ResourceProfile], str | None],
        ) -> None:
            nonlocal candidates
            retained: list[ResourceProfile] = []
            for profile in candidates:
                reason = checker(profile)
                if reason is None:
                    retained.append(profile)
                else:
                    eliminations.append(
                        ResourceElimination(
                            runner_profile_id=profile.runner_profile_id,
                            stage=stage,
                            reason=reason,
                        )
                    )
            candidates = retained

        apply_gate(
            EliminationStage.QUALIFICATION,
            lambda item: self._qualification_reason(item, as_of),
        )
        apply_gate(EliminationStage.HEALTH, lambda item: self._health_reason(item, as_of))
        apply_gate(
            EliminationStage.CAPABILITY,
            lambda item: self._capability_reason(item, requirements),
        )
        apply_gate(
            EliminationStage.AUTHORIZATION,
            lambda item: self._authorization_reason(item, requirements),
        )

        estimates: dict[str, ResourceCostEstimate] = {}

        def cost_reason(profile: ResourceProfile) -> str | None:
            estimate = self._estimator.estimate(requirements, profile)
            estimates[profile.runner_profile_id] = estimate
            if estimate.net_cost_microusd > requirements.authority.maximum_authorized_cost_microusd:
                return "estimated net cost exceeds the authorized cost ceiling"
            return None

        apply_gate(EliminationStage.COST, cost_reason)
        if not candidates:
            return self._decision(
                requirements=requirements,
                selected=None,
                estimate=None,
                eliminations=eliminations,
                explanation=("no qualified healthy capable authorized resource is within cost",),
            )

        selected = min(
            candidates,
            key=lambda profile: (
                0 if estimates[profile.runner_profile_id].net_cost_microusd == 0 else 1,
                estimates[profile.runner_profile_id].net_cost_microusd,
                _RISK_RANK[profile.risk_surface],
                profile.priority,
                profile.provider.value,
                profile.runner_profile_id,
            ),
        )
        estimate = estimates[selected.runner_profile_id]
        explanation = (
            "eliminated unqualified, unhealthy, incapable, unauthorized, and over-budget resources",
            (
                "selected included capacity"
                if estimate.net_cost_microusd == 0
                else "selected cheapest capable qualified resource"
            ),
            f"selected runner profile {selected.runner_profile_id}",
        )
        return self._decision(
            requirements=requirements,
            selected=selected,
            estimate=estimate,
            eliminations=eliminations,
            explanation=explanation,
        )

    def _qualification_reason(self, profile: ResourceProfile, as_of: datetime) -> str | None:
        if not profile.enabled:
            return "resource profile is disabled"
        if profile.qualification_status is not QualificationStatus.QUALIFIED:
            return "resource profile is not qualified"
        if profile.last_qualified_at is None:
            return "resource qualification time is missing"
        age = (as_of - profile.last_qualified_at).total_seconds()
        if age < 0 or age > self._maximum_qualification_age_seconds:
            return "resource qualification is stale"
        return None

    def _health_reason(self, profile: ResourceProfile, as_of: datetime) -> str | None:
        if profile.health_status is not HealthStatus.HEALTHY:
            return "resource profile is not healthy"
        if profile.last_verified_at is None:
            return "resource health verification time is missing"
        age = (as_of - profile.last_verified_at).total_seconds()
        if age < 0 or age > self._maximum_health_age_seconds:
            return "resource health verification is stale"
        return None

    @staticmethod
    def _capability_reason(
        profile: ResourceProfile,
        requirements: WorkloadRequirements,
    ) -> str | None:
        if requirements.shared_memory_required:
            if profile.single_machine_cpu < requirements.required_cpu:
                return "single-machine CPU is below the shared workload requirement"
            if profile.single_machine_memory_mb < requirements.required_memory_mb:
                return "single-machine memory is below the shared workload requirement"
        else:
            if profile.aggregate_parallel_cpu < requirements.required_cpu:
                return "aggregate parallel CPU is below the workload requirement"
            if profile.aggregate_parallel_memory_mb < requirements.required_memory_mb:
                return "aggregate parallel memory is below the workload requirement"
        if profile.single_machine_disk_mb < requirements.required_disk_mb:
            return "single-machine disk is below the workload requirement"
        if (
            _WORKSPACE_RANK[profile.workspace_policy]
            < _WORKSPACE_RANK[requirements.workspace_policy]
        ):
            return "resource workspace policy is below the workload requirement"
        if requirements.desired_parallelism > profile.parallel_limit:
            return "requested parallelism exceeds the resource limit"
        if requirements.estimated_duration_seconds > profile.maximum_duration_seconds:
            return "estimated duration exceeds the resource limit"
        checks = (
            (requirements.gpu_required, profile.gpu, "GPU"),
            (requirements.browser_required, profile.browser, "browser"),
            (requirements.docker_required, profile.docker, "Docker"),
            (
                requirements.package_install_required,
                profile.package_install_capability,
                "package installation",
            ),
            (
                requirements.persistent_workspace_required,
                profile.persistent_workspace,
                "persistent workspace",
            ),
            (requirements.secrets_required, profile.secrets_capability, "secrets"),
            (
                requirements.production_access_required,
                profile.production_access_capability,
                "production access",
            ),
            (
                requirements.source_write_required,
                profile.source_write_capability,
                "source write",
            ),
            (requirements.deployment_required, profile.deployment_capability, "deployment"),
        )
        for required, capable, label in checks:
            if required and not capable:
                return f"resource does not support required {label} capability"
        if requirements.network_policy.network_required:
            if not profile.network_capability:
                return "resource does not support required network access"
            allowed = {item.casefold() for item in profile.allowed_destinations}
            requested = {
                item.casefold() for item in requirements.network_policy.allowed_destinations
            }
            if not requested <= allowed:
                return "resource network destinations do not cover the approved policy"
        return None

    @staticmethod
    def _authorization_reason(
        profile: ResourceProfile,
        requirements: WorkloadRequirements,
    ) -> str | None:
        if (
            _RISK_RANK[profile.risk_surface]
            > _RISK_RANK[requirements.authority.maximum_resource_risk]
        ):
            return "resource risk surface exceeds server authorization"
        return None

    @staticmethod
    def _decision(
        *,
        requirements: WorkloadRequirements,
        selected: ResourceProfile | None,
        estimate: ResourceCostEstimate | None,
        eliminations: list[ResourceElimination],
        explanation: tuple[str, ...],
    ) -> RoutingDecision:
        values: dict[str, Any] = {
            "requirement_digest": requirements.requirements_digest,
            "selected_profile": selected,
            "estimate": estimate,
            "eliminations": tuple(eliminations),
            "explanation": explanation,
        }
        draft = RoutingDecision.model_construct(**values, decision_digest="0" * 64)
        values["decision_digest"] = content_digest(
            draft.model_dump(mode="json", exclude={"decision_digest"})
        )
        return RoutingDecision.model_validate(values)
