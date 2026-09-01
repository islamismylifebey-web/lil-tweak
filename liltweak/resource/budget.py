from __future__ import annotations

from datetime import datetime
from typing import Literal, Self

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator

from ..creator_contract import CreatorSchema
from .estimator import ResourceCostEstimate


class ResourceBudgetError(ValueError):
    pass


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


class ResourceReservation(CreatorSchema):
    schema_version: Literal["resource-reservation-v1"] = "resource-reservation-v1"
    execution_id: StrictStr = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    estimate: ResourceCostEstimate
    reserved_cost_microusd: StrictInt = Field(ge=0)
    maximum_authorized_cost_microusd: StrictInt = Field(ge=0)
    chosen_reason: StrictStr = Field(min_length=1, max_length=512)
    reserved_at: datetime

    @model_validator(mode="after")
    def validate_reservation(self) -> Self:
        if not _aware(self.reserved_at):
            raise ValueError("reservation time must be timezone-aware")
        if self.reserved_cost_microusd != self.estimate.net_cost_microusd:
            raise ValueError("reservation must equal the estimated net cost")
        return self


class ResourceSettlement(CreatorSchema):
    schema_version: Literal["resource-settlement-v1"] = "resource-settlement-v1"
    execution_id: StrictStr = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    provider: StrictStr
    runner_profile_id: StrictStr
    reserved_cost_microusd: StrictInt = Field(ge=0)
    actual_duration_seconds: StrictInt = Field(ge=0)
    actual_billable_units: StrictInt = Field(ge=0)
    actual_metered_cost_microusd: StrictInt = Field(ge=0)
    included_discount_microusd: StrictInt = Field(ge=0)
    actual_net_cost_microusd: StrictInt = Field(ge=0)
    variance_microusd: StrictInt
    ceiling_exceeded: StrictBool
    settled_at: datetime

    @model_validator(mode="after")
    def validate_settlement(self) -> Self:
        if not _aware(self.settled_at):
            raise ValueError("settlement time must be timezone-aware")
        if self.included_discount_microusd > self.actual_metered_cost_microusd:
            raise ValueError("included discount cannot exceed metered cost")
        return self


class ResourceLedger:
    def __init__(self, *, monthly_limit_microusd: int) -> None:
        if isinstance(monthly_limit_microusd, bool) or monthly_limit_microusd < 0:
            raise ValueError("monthly resource limit must be a non-negative integer")
        self._monthly_limit = monthly_limit_microusd
        self._reservations: dict[str, ResourceReservation] = {}
        self._settlements: dict[str, ResourceSettlement] = {}

    @property
    def month_to_date_actual_microusd(self) -> int:
        return sum(item.actual_net_cost_microusd for item in self._settlements.values())

    @property
    def outstanding_reserved_microusd(self) -> int:
        return sum(
            item.reserved_cost_microusd
            for execution_id, item in self._reservations.items()
            if execution_id not in self._settlements
        )

    def reserve(
        self,
        *,
        execution_id: str,
        estimate: ResourceCostEstimate,
        maximum_authorized_cost_microusd: int,
        chosen_reason: str,
        reserved_at: datetime,
    ) -> ResourceReservation:
        if execution_id in self._reservations:
            raise ResourceBudgetError("execution already has a resource reservation")
        if estimate.net_cost_microusd > maximum_authorized_cost_microusd:
            raise ResourceBudgetError("estimated cost exceeds the execution cost ceiling")
        projected = (
            self.month_to_date_actual_microusd
            + self.outstanding_reserved_microusd
            + estimate.net_cost_microusd
        )
        if projected > self._monthly_limit:
            raise ResourceBudgetError("monthly resource cost ceiling would be exceeded")
        reservation = ResourceReservation(
            execution_id=execution_id,
            estimate=estimate,
            reserved_cost_microusd=estimate.net_cost_microusd,
            maximum_authorized_cost_microusd=maximum_authorized_cost_microusd,
            chosen_reason=chosen_reason,
            reserved_at=reserved_at,
        )
        self._reservations[execution_id] = reservation
        return reservation

    def settle(
        self,
        *,
        execution_id: str,
        actual_duration_seconds: int,
        actual_billable_units: int,
        actual_metered_cost_microusd: int,
        included_discount_microusd: int,
        settled_at: datetime,
    ) -> ResourceSettlement:
        if execution_id in self._settlements:
            raise ResourceBudgetError("execution resource reservation is already settled")
        try:
            reservation = self._reservations[execution_id]
        except KeyError as exc:
            raise ResourceBudgetError("execution resource reservation is missing") from exc
        if included_discount_microusd > actual_metered_cost_microusd:
            raise ResourceBudgetError("included discount cannot exceed metered cost")
        actual_net = actual_metered_cost_microusd - included_discount_microusd
        settlement = ResourceSettlement(
            execution_id=execution_id,
            provider=reservation.estimate.provider.value,
            runner_profile_id=reservation.estimate.runner_profile_id,
            reserved_cost_microusd=reservation.reserved_cost_microusd,
            actual_duration_seconds=actual_duration_seconds,
            actual_billable_units=actual_billable_units,
            actual_metered_cost_microusd=actual_metered_cost_microusd,
            included_discount_microusd=included_discount_microusd,
            actual_net_cost_microusd=actual_net,
            variance_microusd=actual_net - reservation.reserved_cost_microusd,
            ceiling_exceeded=actual_net > reservation.maximum_authorized_cost_microusd,
            settled_at=settled_at,
        )
        self._settlements[execution_id] = settlement
        return settlement
