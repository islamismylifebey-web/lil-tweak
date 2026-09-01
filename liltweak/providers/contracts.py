from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal, Protocol, Self, runtime_checkable

from pydantic import Field, StrictBool, StrictStr, model_validator

from ..creator_contract import CreatorSchema
from ..resource.contracts import (
    HealthStatus,
    QualificationStatus,
    ResourceExecutionContractV2,
    ResourceProfile,
    ResourceProvider,
    ResourceType,
    WorkloadRequirements,
)
from ..resource.estimator import ResourceCostEstimate
from ..resource.leases import ExecutionLease


class ProviderExecutionStatus(StrEnum):
    BLOCKED = "blocked"
    PROVISIONED = "provisioned"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"
    DESTROYED = "destroyed"


class VerificationOutcome(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"


class ProviderRuntimeState(CreatorSchema):
    source: Literal["authenticated_server_context"] = "authenticated_server_context"
    qualification_status: QualificationStatus = QualificationStatus.UNQUALIFIED
    health_status: HealthStatus = HealthStatus.UNKNOWN
    connected: StrictBool = False
    active: StrictBool = False
    last_verified_at: datetime | None = None

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if self.active and not self.connected:
            raise ValueError("active provider must be connected")
        if self.active and self.qualification_status is not QualificationStatus.QUALIFIED:
            raise ValueError("active provider must be qualified")
        if self.active and self.health_status is not HealthStatus.HEALTHY:
            raise ValueError("active provider must be healthy")
        if self.health_status is HealthStatus.HEALTHY and (
            self.last_verified_at is None
            or self.last_verified_at.tzinfo is None
            or self.last_verified_at.utcoffset() is None
        ):
            raise ValueError("healthy provider requires a verified timestamp")
        return self


class ProviderQualification(CreatorSchema):
    provider: ResourceProvider
    qualified: StrictBool
    blockers: tuple[StrictStr, ...]

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.qualified == bool(self.blockers):
            raise ValueError("provider qualification result is inconsistent")
        return self


class ProviderCapabilities(CreatorSchema):
    provider: ResourceProvider
    resource_types: tuple[ResourceType, ...] = Field(min_length=1)
    builder: StrictBool
    independent_verifier: StrictBool
    preview_only: StrictBool
    production_deployment: StrictBool


class ProviderHealth(CreatorSchema):
    provider: ResourceProvider
    status: HealthStatus
    connected: StrictBool
    active: StrictBool
    last_verified_at: datetime | None = None


class ProviderOperationResult(CreatorSchema):
    provider: ResourceProvider
    execution_id: StrictStr = Field(min_length=1, max_length=128)
    status: ProviderExecutionStatus
    operation_id: StrictStr | None = Field(default=None, min_length=1, max_length=256)
    reason: StrictStr = Field(min_length=1, max_length=512)
    verification_outcome: VerificationOutcome = VerificationOutcome.NOT_APPLICABLE
    evidence_digest: StrictStr | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.verification_outcome is VerificationOutcome.VERIFIED and (
            self.status is not ProviderExecutionStatus.SUCCEEDED or self.evidence_digest is None
        ):
            raise ValueError("verified provider result requires successful evidence")
        return self


@runtime_checkable
class ExecutionProvider(Protocol):
    def qualify(self) -> ProviderQualification: ...

    def capabilities(self) -> ProviderCapabilities: ...

    def health(self) -> ProviderHealth: ...

    def estimate(
        self,
        requirements: WorkloadRequirements,
        profile: ResourceProfile,
    ) -> ResourceCostEstimate: ...

    async def provision(
        self,
        *,
        contract: ResourceExecutionContractV2,
        lease: ExecutionLease,
    ) -> ProviderOperationResult: ...

    async def execute(
        self,
        *,
        contract: ResourceExecutionContractV2,
        lease: ExecutionLease,
    ) -> ProviderOperationResult: ...

    async def status(self, execution_id: str) -> ProviderOperationResult: ...

    async def collect(self, execution_id: str) -> ProviderOperationResult: ...

    async def cancel(self, execution_id: str) -> ProviderOperationResult: ...

    async def destroy(self, execution_id: str) -> ProviderOperationResult: ...
