from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime
from typing import Any, Literal, Self

from pydantic import Field, StrictInt, StrictStr, model_validator

from ..creator_contract import CreatorSchema, content_digest
from .contracts import (
    ImmutableSourceBinding,
    NetworkPolicy,
    ResourceExecutionContractV2,
    ResourceProvider,
)

_LEASE_SIGNATURE_DOMAIN = b"liltweak:resource-execution-lease:v1\0"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SAFE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"


class ExecutionLeaseError(ValueError):
    pass


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


class ExecutionLease(CreatorSchema):
    schema_version: Literal["resource-execution-lease-v1"] = "resource-execution-lease-v1"
    lease_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    execution_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    job_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    contract_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    source: ImmutableSourceBinding
    provider: ResourceProvider
    runner_profile_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    commands_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    network_policy: NetworkPolicy
    secret_scope: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=32)
    cpu_ceiling: StrictInt = Field(ge=1)
    memory_mb_ceiling: StrictInt = Field(ge=128)
    disk_mb_ceiling: StrictInt = Field(ge=1)
    timeout_seconds: StrictInt = Field(ge=1, le=604_800)
    maximum_cost_microusd: StrictInt = Field(ge=0)
    approval_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    policy_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    issued_at: datetime
    expires_at: datetime
    attempt_nonce: StrictStr = Field(pattern=_SHA256_PATTERN)
    authorization_sequence: StrictInt = Field(ge=0)
    revocation_epoch: StrictInt = Field(ge=1)
    lease_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    signature: StrictStr = Field(pattern=_SHA256_PATTERN)

    @classmethod
    def issue(
        cls,
        *,
        lease_id: str,
        execution_id: str,
        contract: ResourceExecutionContractV2,
        attempt_nonce: str,
        authorization_sequence: int,
        revocation_epoch: int,
        issued_at: datetime,
        expires_at: datetime,
        signing_key: bytes,
        secret_scope: tuple[str, ...] = (),
    ) -> ExecutionLease:
        if not isinstance(signing_key, bytes) or len(signing_key) != 32:
            raise ValueError("execution lease signing key must contain exactly 32 bytes")
        if issued_at < contract.issued_at:
            raise ValueError("execution lease cannot begin before its resource contract")
        if expires_at > contract.expires_at:
            raise ValueError("execution lease cannot outlive its resource contract")
        if secret_scope and not (
            contract.secrets_required and contract.requirements.authority.secrets_authorized
        ):
            raise ValueError("execution lease cannot grant an unauthorized secret scope")
        values: dict[str, Any] = {
            "lease_id": lease_id,
            "execution_id": execution_id,
            "job_id": contract.requirements.job_id,
            "contract_digest": contract.contract_digest,
            "source": contract.source,
            "provider": contract.provider,
            "runner_profile_id": contract.runner_profile_id,
            "commands_digest": contract.commands_digest,
            "network_policy": contract.network_policy,
            "secret_scope": secret_scope,
            "cpu_ceiling": contract.cpu_ceiling,
            "memory_mb_ceiling": contract.memory_mb_ceiling,
            "disk_mb_ceiling": contract.disk_mb_ceiling,
            "timeout_seconds": contract.max_wall_clock_seconds,
            "maximum_cost_microusd": contract.maximum_authorized_cost_microusd,
            "approval_digest": contract.approval.approval_digest,
            "policy_digest": contract.approval.policy_digest,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "attempt_nonce": attempt_nonce,
            "authorization_sequence": authorization_sequence,
            "revocation_epoch": revocation_epoch,
        }
        draft = cls.model_construct(**values, lease_digest="0" * 64, signature="0" * 64)
        lease_digest = content_digest(
            draft.model_dump(mode="json", exclude={"lease_digest", "signature"})
        )
        values["lease_digest"] = lease_digest
        values["signature"] = hmac.new(
            signing_key,
            _LEASE_SIGNATURE_DOMAIN + lease_digest.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return cls.model_validate(values)

    @model_validator(mode="after")
    def validate_lease(self) -> Self:
        if not _aware(self.issued_at) or not _aware(self.expires_at):
            raise ValueError("execution lease timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("execution lease must expire after issuance")
        if len({item.casefold() for item in self.secret_scope}) != len(self.secret_scope):
            raise ValueError("execution lease secret scope entries must be unique")
        expected = content_digest(
            self.model_dump(mode="json", exclude={"lease_digest", "signature"})
        )
        if self.lease_digest != expected:
            raise ValueError("execution lease digest mismatch")
        return self


class LeaseConsumption(CreatorSchema):
    schema_version: Literal["resource-lease-consumption-v1"] = "resource-lease-consumption-v1"
    lease_id: StrictStr
    execution_id: StrictStr
    lease_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    attempt_nonce: StrictStr = Field(pattern=_SHA256_PATTERN)
    consumed_at: datetime


class ExecutionLeaseRegistry:
    def __init__(self) -> None:
        self._consumed_digests: set[str] = set()
        self._consumed_nonces: set[str] = set()

    def consume(
        self,
        lease: ExecutionLease,
        *,
        contract: ResourceExecutionContractV2,
        signing_key: bytes,
        now: datetime,
        minimum_authorization_sequence: int,
        revocation_epoch: int,
    ) -> LeaseConsumption:
        if lease.source != contract.source:
            raise ExecutionLeaseError("execution lease contract source mismatch")
        bindings = (
            (lease.contract_digest, contract.contract_digest, "contract digest"),
            (lease.job_id, contract.requirements.job_id, "job"),
            (lease.provider, contract.provider, "provider"),
            (lease.runner_profile_id, contract.runner_profile_id, "runner profile"),
            (lease.commands_digest, contract.commands_digest, "commands digest"),
            (
                lease.approval_digest,
                contract.approval.approval_digest,
                "approval digest",
            ),
            (lease.policy_digest, contract.approval.policy_digest, "policy digest"),
            (lease.cpu_ceiling, contract.cpu_ceiling, "CPU ceiling"),
            (lease.memory_mb_ceiling, contract.memory_mb_ceiling, "memory ceiling"),
            (lease.disk_mb_ceiling, contract.disk_mb_ceiling, "disk ceiling"),
            (lease.timeout_seconds, contract.max_wall_clock_seconds, "timeout"),
            (
                lease.maximum_cost_microusd,
                contract.maximum_authorized_cost_microusd,
                "cost ceiling",
            ),
        )
        for observed, expected, label in bindings:
            if observed != expected:
                raise ExecutionLeaseError(f"execution lease {label} mismatch")
        if not isinstance(signing_key, bytes) or len(signing_key) != 32:
            raise ExecutionLeaseError("execution lease signing key is invalid")
        expected_digest = content_digest(
            lease.model_dump(mode="json", exclude={"lease_digest", "signature"})
        )
        if not secrets.compare_digest(lease.lease_digest, expected_digest):
            raise ExecutionLeaseError("execution lease digest mismatch")
        expected_signature = hmac.new(
            signing_key,
            _LEASE_SIGNATURE_DOMAIN + lease.lease_digest.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        if not secrets.compare_digest(lease.signature, expected_signature):
            raise ExecutionLeaseError("execution lease signature mismatch")
        if not _aware(now) or now < lease.issued_at:
            raise ExecutionLeaseError("execution lease evaluation time is invalid")
        if now >= lease.expires_at:
            raise ExecutionLeaseError("execution lease is expired")
        if lease.authorization_sequence < minimum_authorization_sequence:
            raise ExecutionLeaseError("execution lease authorization sequence is stale")
        if lease.revocation_epoch != revocation_epoch:
            raise ExecutionLeaseError("execution lease revocation epoch mismatch")
        if (
            lease.lease_digest in self._consumed_digests
            or lease.attempt_nonce in self._consumed_nonces
        ):
            raise ExecutionLeaseError("execution lease replay detected")
        self._consumed_digests.add(lease.lease_digest)
        self._consumed_nonces.add(lease.attempt_nonce)
        return LeaseConsumption(
            lease_id=lease.lease_id,
            execution_id=lease.execution_id,
            lease_digest=lease.lease_digest,
            attempt_nonce=lease.attempt_nonce,
            consumed_at=now,
        )
