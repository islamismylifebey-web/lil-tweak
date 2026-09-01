from __future__ import annotations

from typing import Literal

from pydantic import Field, StrictBool, StrictStr

from ..creator_contract import CreatorSchema
from .contracts import (
    ModelWorkloadSuggestion,
    NetworkPolicy,
    VerificationLevel,
    WorkloadAuthority,
    WorkloadRequirements,
)


class ServerWorkloadContext(CreatorSchema):
    source: Literal["authenticated_server_context"] = "authenticated_server_context"
    requirement_id: StrictStr = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    job_id: StrictStr = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    authority: WorkloadAuthority
    secrets_required: StrictBool = False
    production_access_required: StrictBool = False
    source_write_required: StrictBool = False
    deployment_required: StrictBool = False
    verification_level: VerificationLevel = VerificationLevel.FULL


class WorkloadClassifier:
    @staticmethod
    def classify(
        suggestion: ModelWorkloadSuggestion,
        context: ServerWorkloadContext,
    ) -> WorkloadRequirements:
        if suggestion.network_required and not context.authority.network_policy.network_required:
            raise ValueError("model requested network access outside server authority")
        network_policy = (
            context.authority.network_policy if suggestion.network_required else NetworkPolicy()
        )
        return WorkloadRequirements(
            requirement_id=context.requirement_id,
            job_id=context.job_id,
            required_cpu=suggestion.required_cpu,
            required_memory_mb=suggestion.required_memory_mb,
            required_disk_mb=suggestion.required_disk_mb,
            shared_memory_required=suggestion.shared_memory_required,
            gpu_required=suggestion.gpu_required,
            browser_required=suggestion.browser_required,
            docker_required=suggestion.docker_required,
            network_policy=network_policy,
            package_install_required=suggestion.package_install_required,
            workspace_policy=suggestion.workspace_policy,
            persistent_workspace_required=suggestion.persistent_workspace_required,
            secrets_required=context.secrets_required,
            production_access_required=context.production_access_required,
            source_write_required=context.source_write_required,
            deployment_required=context.deployment_required,
            estimated_duration_seconds=suggestion.estimated_duration_seconds,
            parallelizable=suggestion.parallelizable,
            desired_parallelism=suggestion.desired_parallelism,
            verification_level=context.verification_level,
            authority=context.authority,
        )
