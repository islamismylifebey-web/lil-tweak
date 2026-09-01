from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Self

from pydantic import Field, StrictInt, StrictStr, model_validator

from ..creator_contract import CreatorSchema, content_digest
from .contracts import HealthStatus, ResourceProfile


class ResourceHealthError(ValueError):
    pass


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


class ResourceHealthRecord(CreatorSchema):
    schema_version: Literal["resource-health-v1"] = "resource-health-v1"
    runner_profile_id: StrictStr = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    status: HealthStatus
    checked_at: datetime
    expires_at: datetime
    sequence: StrictInt = Field(ge=0)
    evidence_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    record_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        if not _aware(self.checked_at) or not _aware(self.expires_at):
            raise ValueError("resource health timestamps must be timezone-aware")
        if self.expires_at <= self.checked_at:
            raise ValueError("resource health record must expire after its check")
        expected = content_digest(self.model_dump(mode="json", exclude={"record_digest"}))
        if self.record_digest != expected:
            raise ValueError("resource health record digest mismatch")
        return self


class ResourceHealthRegistry:
    def __init__(self) -> None:
        self._records: dict[str, ResourceHealthRecord] = {}

    def record(
        self,
        *,
        runner_profile_id: str,
        status: HealthStatus,
        checked_at: datetime,
        expires_at: datetime,
        sequence: int,
        evidence_digest: str,
    ) -> ResourceHealthRecord:
        previous = self._records.get(runner_profile_id)
        if previous is not None and sequence <= previous.sequence:
            raise ResourceHealthError("resource health sequence must increase")
        values: dict[str, Any] = {
            "runner_profile_id": runner_profile_id,
            "status": status,
            "checked_at": checked_at,
            "expires_at": expires_at,
            "sequence": sequence,
            "evidence_digest": evidence_digest,
        }
        draft = ResourceHealthRecord.model_construct(**values, record_digest="0" * 64)
        values["record_digest"] = content_digest(
            draft.model_dump(mode="json", exclude={"record_digest"})
        )
        record = ResourceHealthRecord.model_validate(values)
        self._records[runner_profile_id] = record
        return record

    def apply(self, profile: ResourceProfile, *, as_of: datetime) -> ResourceProfile:
        if not _aware(as_of):
            raise ValueError("resource health evaluation time must be timezone-aware")
        record = self._records.get(profile.runner_profile_id)
        if record is None or as_of < record.checked_at or as_of >= record.expires_at:
            return profile.model_copy(
                update={"health_status": HealthStatus.UNKNOWN, "last_verified_at": None}
            )
        return profile.model_copy(
            update={"health_status": record.status, "last_verified_at": record.checked_at}
        )
