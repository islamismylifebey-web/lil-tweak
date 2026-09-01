from __future__ import annotations

from typing import Literal

from pydantic import Field, StrictInt, StrictStr

from ..creator_contract import CreatorSchema
from .contracts import ResourceProfile, ResourceProvider, WorkloadRequirements


class ResourceCostEstimate(CreatorSchema):
    schema_version: Literal["resource-cost-estimate-v1"] = "resource-cost-estimate-v1"
    runner_profile_id: StrictStr
    provider: ResourceProvider
    duration_seconds: StrictInt = Field(ge=1)
    cpu_cost_microusd: StrictInt = Field(ge=0)
    memory_cost_microusd: StrictInt = Field(ge=0)
    storage_cost_microusd: StrictInt = Field(ge=0)
    gross_cost_microusd: StrictInt = Field(ge=0)
    included_allowance_applied_microusd: StrictInt = Field(ge=0)
    net_cost_microusd: StrictInt = Field(ge=0)


class ResourceEstimator:
    @staticmethod
    def estimate(
        requirements: WorkloadRequirements,
        profile: ResourceProfile,
    ) -> ResourceCostEstimate:
        duration = requirements.estimated_duration_seconds
        cpu_cost = requirements.required_cpu * duration * profile.estimated_cpu_microusd_per_second
        memory_numerator = (
            requirements.required_memory_mb
            * duration
            * profile.estimated_memory_microusd_per_gb_second
        )
        storage_numerator = (
            requirements.required_disk_mb
            * duration
            * profile.estimated_storage_microusd_per_gb_second
        )
        memory_cost = (memory_numerator + 1_023) // 1_024
        storage_cost = (storage_numerator + 1_023) // 1_024
        gross = cpu_cost + memory_cost + storage_cost
        remaining_allowance = max(
            profile.included_allowance_microusd - profile.current_usage_microusd,
            0,
        )
        allowance_applied = min(gross, remaining_allowance)
        return ResourceCostEstimate(
            runner_profile_id=profile.runner_profile_id,
            provider=profile.provider,
            duration_seconds=duration,
            cpu_cost_microusd=cpu_cost,
            memory_cost_microusd=memory_cost,
            storage_cost_microusd=storage_cost,
            gross_cost_microusd=gross,
            included_allowance_applied_microusd=allowance_applied,
            net_cost_microusd=gross - allowance_applied,
        )
