from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, model_validator


class ToolRegistryError(RuntimeError):
    """A named tool or invocation failed the server-owned authority policy."""


class ToolAuthority(StrEnum):
    READ = "read"
    MUTATE_TASK_WORKSPACE = "mutate_task_workspace"
    TEST = "test"
    VERIFY = "verify"
    PUBLISH_OWNER_TREE = "publish_owner_tree"


class ToolNetworkPolicy(StrEnum):
    DENIED = "denied"
    EXACT_GRANT_REQUIRED = "exact_grant_required"


class ToolSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def canonical_digest(value: object) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", exclude_none=False)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class ArgumentConstraint(ToolSchema):
    name: StrictStr = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    pattern: StrictStr = Field(min_length=1, max_length=512)
    required: StrictBool = True
    repeated: StrictBool = False
    maximum_items: StrictInt = Field(default=1, ge=1, le=128)

    @model_validator(mode="after")
    def valid_pattern(self) -> ArgumentConstraint:
        try:
            re.compile(self.pattern)
        except re.error as exc:
            raise ValueError("tool argument pattern is invalid") from exc
        if not self.repeated and self.maximum_items != 1:
            raise ValueError("non-repeated arguments must allow exactly one item")
        return self


class ToolDefinition(ToolSchema):
    schema_version: Literal["tool-definition-v1"] = "tool-definition-v1"
    tool_id: StrictStr = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    implementation_id: StrictStr = Field(pattern=r"^[a-z][a-z0-9_.:-]{2,127}$")
    implementation_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    authority: ToolAuthority
    description: StrictStr = Field(min_length=1, max_length=512)
    arguments: tuple[ArgumentConstraint, ...] = Field(default_factory=tuple, max_length=32)
    network: ToolNetworkPolicy = ToolNetworkPolicy.DENIED
    mutates: StrictBool = False
    evidence_required: StrictBool = True
    cancellation_required: StrictBool = True
    rollback_required: StrictBool = False

    @model_validator(mode="after")
    def authority_matches_effect(self) -> ToolDefinition:
        names = tuple(item.name for item in self.arguments)
        if len(names) != len(set(names)):
            raise ValueError("tool argument names must be unique")
        mutation_authorities = {
            ToolAuthority.MUTATE_TASK_WORKSPACE,
            ToolAuthority.PUBLISH_OWNER_TREE,
        }
        if self.mutates != (self.authority in mutation_authorities):
            raise ValueError("tool mutation flag contradicts its authority")
        if self.mutates and not self.rollback_required:
            raise ValueError("mutating tools require an explicit rollback contract")
        return self

    @property
    def definition_digest(self) -> str:
        return canonical_digest(self)


class ExactNetworkGrant(ToolSchema):
    schema_version: Literal["exact-network-grant-v1"] = "exact-network-grant-v1"
    destination_host: StrictStr = Field(pattern=r"^[A-Za-z0-9.-]{1,253}$")
    destination_port: StrictInt = Field(ge=1, le=65_535)
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
    expires_at: datetime
    grant_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def digest_matches(self) -> ExactNetworkGrant:
        expected = canonical_digest(self.model_dump(mode="json", exclude={"grant_digest"}))
        if self.grant_digest != expected:
            raise ValueError("network grant digest mismatch")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("network grant expiry must be timezone-aware")
        return self


class ToolInvocation(ToolSchema):
    schema_version: Literal["tool-invocation-v1"] = "tool-invocation-v1"
    invocation_id: StrictStr = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    tool_id: StrictStr = Field(pattern=r"^[a-z][a-z0-9_.-]{2,127}$")
    tool_definition_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    registry_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    task_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    plan_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    opaque_workspace_id: StrictStr = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    attempt: StrictInt = Field(ge=1, le=100)
    arguments: dict[StrictStr, StrictStr | tuple[StrictStr, ...]]
    network_grant: ExactNetworkGrant | None = None
    nonce: StrictStr = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")
    expires_at: datetime

    @model_validator(mode="after")
    def expiry_is_aware(self) -> ToolInvocation:
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("tool invocation expiry must be timezone-aware")
        return self

    @property
    def invocation_digest(self) -> str:
        return canonical_digest(self)


class ToolRegistry:
    """Immutable named-tool registry; it never executes tools itself."""

    schema_version = "tool-registry-v1"

    def __init__(self, definitions: tuple[ToolDefinition, ...]) -> None:
        if not definitions:
            raise ValueError("tool registry requires at least one definition")
        ids = tuple(item.tool_id for item in definitions)
        if len(ids) != len(set(ids)):
            raise ValueError("tool registry identifiers must be unique")
        self._definitions = tuple(sorted(definitions, key=lambda item: item.tool_id))
        self._by_id = {item.tool_id: item for item in self._definitions}
        self.registry_digest = canonical_digest(self.export())

    def export(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "tools": [item.model_dump(mode="json") for item in self._definitions],
        }

    def definition(self, tool_id: str) -> ToolDefinition:
        try:
            return self._by_id[tool_id]
        except KeyError as exc:
            raise ToolRegistryError("tool registry has no such definition") from exc

    def authorize(self, invocation: ToolInvocation, *, now: datetime) -> ToolDefinition:
        if invocation.registry_digest != self.registry_digest:
            raise ToolRegistryError("tool invocation uses a stale registry")
        try:
            definition = self.definition(invocation.tool_id)
        except ToolRegistryError as exc:
            raise ToolRegistryError("tool invocation names an unknown tool") from exc
        if invocation.tool_definition_digest != definition.definition_digest:
            raise ToolRegistryError("tool invocation uses a stale tool definition")
        if now.tzinfo is None or now.utcoffset() is None or now >= invocation.expires_at:
            raise ToolRegistryError("tool invocation is expired")
        expected_names = {item.name for item in definition.arguments}
        supplied_names = set(invocation.arguments)
        required_names = {item.name for item in definition.arguments if item.required}
        if not required_names.issubset(supplied_names) or not supplied_names.issubset(
            expected_names
        ):
            raise ToolRegistryError("tool invocation arguments do not match its schema")
        constraints = {item.name: item for item in definition.arguments}
        for name, raw_value in invocation.arguments.items():
            constraint = constraints[name]
            values = raw_value if isinstance(raw_value, tuple) else (raw_value,)
            if (not constraint.repeated and len(values) != 1) or len(
                values
            ) > constraint.maximum_items:
                raise ToolRegistryError("tool invocation argument cardinality is invalid")
            if any(
                not value
                or len(value) > 2_048
                or "\x00" in value
                or "\n" in value
                or "\r" in value
                or re.fullmatch(constraint.pattern, value) is None
                for value in values
            ):
                raise ToolRegistryError("tool invocation argument value is invalid")
        if definition.network == ToolNetworkPolicy.DENIED and invocation.network_grant is not None:
            raise ToolRegistryError("network is denied for this tool")
        if definition.network == ToolNetworkPolicy.EXACT_GRANT_REQUIRED:
            grant = invocation.network_grant
            if grant is None or now >= grant.expires_at:
                raise ToolRegistryError("an active exact network grant is required")
        return definition


def default_tool_registry() -> ToolRegistry:
    """Safe planning-stage tools. Mutation/publisher tools stay absent until qualification."""
    module_root = Path(__file__).resolve().parent
    source_digest = hashlib.sha256(
        (module_root / "workbench_repository.py").read_bytes()
    ).hexdigest()
    verifier_digest = hashlib.sha256(
        (module_root / "workbench_executor.py").read_bytes()
    ).hexdigest()
    relative_path = ArgumentConstraint(
        name="path",
        pattern=r"^(?!/)(?!.*(?:^|/)\.git(?:/|$))(?!.*(?:^|/)\.\.(?:/|$))[^\\\x00-\x1f]+$",
    )
    return ToolRegistry(
        (
            ToolDefinition(
                tool_id="repository.read_file",
                implementation_id="control-plane:repository-reader:v1",
                implementation_sha256=source_digest,
                authority=ToolAuthority.READ,
                description="Read one secret-screened repository-relative text file.",
                arguments=(relative_path,),
                cancellation_required=False,
            ),
            ToolDefinition(
                tool_id="verification.run_named_check",
                implementation_id="runner:verification-broker:v1",
                implementation_sha256=verifier_digest,
                authority=ToolAuthority.VERIFY,
                description="Run one server-configured verification check by stable identifier.",
                arguments=(
                    ArgumentConstraint(
                        name="check_id",
                        pattern=r"^[a-z][a-z0-9_.-]{2,127}$",
                    ),
                ),
            ),
        )
    )
