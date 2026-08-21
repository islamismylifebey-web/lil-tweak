from __future__ import annotations

import hashlib
import json

from liltweak.reasoning_contract import ReasoningRole, ToolAuthority
from liltweak.reasoning_prompts import (
    PROMPT_DEFINITIONS,
    PROMPT_OUTPUT_TYPES,
    PROMPT_REGISTRY,
    PROMPT_REGISTRY_DIGEST,
    PROMPT_REGISTRY_VERSION,
    STABLE_REASONING_PREFIX,
    PromptName,
    render_prompt,
)


def schema_digest(output_type: type) -> str:
    encoded = json.dumps(
        output_type.model_json_schema(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def test_prompt_registry_is_complete_versioned_and_schema_bound() -> None:
    assert PROMPT_REGISTRY.schema_version == PROMPT_REGISTRY_VERSION
    assert set(PROMPT_DEFINITIONS) == set(PromptName)
    assert set(PROMPT_OUTPUT_TYPES) == set(PromptName)

    for name, definition in PROMPT_DEFINITIONS.items():
        output_type = PROMPT_OUTPUT_TYPES[name]
        assert definition.stable_prefix == STABLE_REASONING_PREFIX
        assert definition.instructions.startswith(STABLE_REASONING_PREFIX)
        assert definition.output_schema_name == output_type.__name__
        assert definition.output_schema_digest == schema_digest(output_type)
        assert definition.tool_authority == ToolAuthority.NONE
        assert hashlib.sha256(definition.instructions.encode()).hexdigest() == (
            definition.instructions_digest
        )

    encoded = json.dumps(
        PROMPT_REGISTRY.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == PROMPT_REGISTRY_DIGEST


def test_prompts_bind_separate_roles_without_tool_or_completion_authority() -> None:
    assert PROMPT_DEFINITIONS[PromptName.ENGINEERING_PLAN].role == ReasoningRole.PLANNER
    assert PROMPT_DEFINITIONS[PromptName.CANDIDATE_MANIFEST].role == (ReasoningRole.IMPLEMENTER)
    assert PROMPT_DEFINITIONS[PromptName.PLAN_CRITIQUE].role == ReasoningRole.CRITIC
    assert PROMPT_DEFINITIONS[PromptName.CANDIDATE_CRITIQUE].role == ReasoningRole.CRITIC
    assert PROMPT_DEFINITIONS[PromptName.VERIFICATION_DECISION].role == ReasoningRole.VERIFIER
    assert PROMPT_DEFINITIONS[PromptName.COGNITIVE_FINALIZATION].role == (ReasoningRole.FINALIZER)

    folded = STABLE_REASONING_PREFIX.casefold()
    assert "no tools" in folded
    assert "hidden chain-of-thought" in folded
    assert "completion authority" in folded
    assert "never claim" in folded


def test_rendered_prompt_keeps_volatile_input_after_stable_instructions_and_digests_both() -> None:
    first = render_prompt(PromptName.ENGINEERING_PLAN, '{"task":"first"}')
    second = render_prompt(PromptName.ENGINEERING_PLAN, '{"task":"second"}')

    assert first.instructions == second.instructions
    assert first.instructions_digest == second.instructions_digest
    assert "first" not in first.instructions
    assert first.input_digest != second.input_digest
    assert first.provider_bound_prompt_digest != second.provider_bound_prompt_digest
    assert first.tool_authority == ToolAuthority.NONE

    provider_bound = (
        f"{first.instructions}\n\nBEGIN_UNTRUSTED_INPUT\n{first.input_payload}\nEND_UNTRUSTED_INPUT"
    )
    assert hashlib.sha256(provider_bound.encode()).hexdigest() == (
        first.provider_bound_prompt_digest
    )
