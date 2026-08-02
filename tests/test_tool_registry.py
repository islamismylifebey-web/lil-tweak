from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from liltweak.tool_registry import (
    ArgumentConstraint,
    ToolAuthority,
    ToolDefinition,
    ToolInvocation,
    ToolRegistryError,
    canonical_digest,
    default_tool_registry,
)

DIGEST = "a" * 64


def invocation(**updates: object) -> ToolInvocation:
    registry = default_tool_registry()
    definition = registry.definition("repository.read_file")
    values: dict[str, object] = {
        "invocation_id": "invocation:0123456789abcdef",
        "tool_id": definition.tool_id,
        "tool_definition_digest": definition.definition_digest,
        "registry_digest": registry.registry_digest,
        "task_digest": DIGEST,
        "plan_digest": DIGEST,
        "opaque_workspace_id": "workspace:one",
        "attempt": 1,
        "arguments": {"path": "liltweak/service.py"},
        "nonce": "nonce:0123456789abcdef",
        "expires_at": datetime.now(UTC) + timedelta(minutes=1),
    }
    values.update(updates)
    return ToolInvocation(**values)


def test_default_registry_authorizes_only_exact_named_schema() -> None:
    registry = default_tool_registry()
    request = invocation(registry_digest=registry.registry_digest)

    definition = registry.authorize(request, now=datetime.now(UTC))

    assert definition.tool_id == "repository.read_file"
    assert definition.authority == ToolAuthority.READ
    assert definition.network.value == "denied"
    assert registry.export()["schema_version"] == "tool-registry-v1"


@pytest.mark.parametrize(
    "arguments",
    (
        {"path": "../outside"},
        {"path": ".git/config"},
        {"path": "/etc/passwd"},
        {"path": "ok.py", "executable": "bash"},
        {"path": "ok.py\n--config=evil"},
    ),
)
def test_registry_rejects_path_escape_shell_shaping_and_extra_authority(
    arguments: dict[str, str],
) -> None:
    registry = default_tool_registry()
    request = invocation(registry_digest=registry.registry_digest, arguments=arguments)

    with pytest.raises(ToolRegistryError):
        registry.authorize(request, now=datetime.now(UTC))


def test_registry_rejects_stale_definition_registry_and_expiry() -> None:
    registry = default_tool_registry()
    now = datetime.now(UTC)
    with pytest.raises(ToolRegistryError, match="stale registry"):
        registry.authorize(invocation(registry_digest="b" * 64), now=now)
    with pytest.raises(ToolRegistryError, match="stale tool definition"):
        registry.authorize(
            invocation(
                registry_digest=registry.registry_digest,
                tool_definition_digest="b" * 64,
            ),
            now=now,
        )
    with pytest.raises(ToolRegistryError, match="expired"):
        registry.authorize(
            invocation(
                registry_digest=registry.registry_digest,
                expires_at=now - timedelta(seconds=1),
            ),
            now=now,
        )


def test_mutating_definition_requires_rollback_and_exact_effect_flag() -> None:
    with pytest.raises(ValidationError, match="rollback contract"):
        ToolDefinition(
            tool_id="workspace.apply_patch",
            implementation_id="runner:patch:v1",
            implementation_sha256=DIGEST,
            authority=ToolAuthority.MUTATE_TASK_WORKSPACE,
            description="Apply a content-addressed patch.",
            mutates=True,
            rollback_required=False,
        )
    with pytest.raises(ValidationError, match="contradicts"):
        ToolDefinition(
            tool_id="repository.read_file",
            implementation_id="control-plane:read:v1",
            implementation_sha256=DIGEST,
            authority=ToolAuthority.READ,
            description="Read one file.",
            mutates=True,
            rollback_required=True,
        )


def test_argument_and_registry_digests_are_deterministic() -> None:
    argument = ArgumentConstraint(name="path", pattern=r"^[a-z]+$")
    assert canonical_digest(argument) == canonical_digest(argument.model_dump(mode="json"))
    assert default_tool_registry().registry_digest == default_tool_registry().registry_digest


def test_registered_implementation_digests_bind_real_source_modules() -> None:
    module_root = Path(__file__).parents[1] / "liltweak"
    registry = default_tool_registry()

    assert (
        registry.definition("repository.read_file").implementation_sha256
        == hashlib.sha256((module_root / "workbench_repository.py").read_bytes()).hexdigest()
    )
    assert (
        registry.definition("verification.run_named_check").implementation_sha256
        == hashlib.sha256((module_root / "workbench_executor.py").read_bytes()).hexdigest()
    )
