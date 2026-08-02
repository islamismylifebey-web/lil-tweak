from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError

from liltweak.reasoning_contract import (
    ProviderQualificationState,
    ReasoningRole,
    ToolAuthority,
)
from liltweak.reasoning_policy import (
    BENCHMARK_VARIANTS,
    MODEL_REGISTRY,
    PROFILE_REGISTRY,
    REASONING_POLICY,
    REASONING_POLICY_DIGEST,
    REASONING_POLICY_VERSION,
    ROLE_PROFILE_REGISTRY,
    CanonicalReasoningPolicy,
    ContextMode,
    FoundationModel,
    ReasoningEffort,
    ReasoningProfileName,
    ReasoningProfileUnavailable,
    ReasoningRequestMode,
    profile_for_role,
    require_primary_engineering_model,
    require_production_profile,
)


def test_model_registry_is_sol_primary_with_bounded_terra_and_luna_roles() -> None:
    assert set(MODEL_REGISTRY) == {
        FoundationModel.SOL,
        FoundationModel.TERRA,
        FoundationModel.LUNA,
    }

    sol = MODEL_REGISTRY[FoundationModel.SOL]
    assert sol.primary_engineering_model is True
    assert sol.degraded_fallback_only is False
    assert ReasoningRole.IMPLEMENTER in sol.allowed_roles

    terra = MODEL_REGISTRY[FoundationModel.TERRA]
    assert terra.primary_engineering_model is False
    assert terra.degraded_fallback_only is True
    assert ReasoningRole.IMPLEMENTER not in terra.allowed_roles

    luna = MODEL_REGISTRY[FoundationModel.LUNA]
    assert luna.low_risk_classification_only is True
    assert set(luna.allowed_roles) == {
        ReasoningRole.CLASSIFIER,
        ReasoningRole.DIAGNOSTIC,
    }
    assert all("ultra" not in model.value for model in FoundationModel)


def test_active_engineering_model_cannot_bypass_primary_policy() -> None:
    assert require_primary_engineering_model("gpt-5.6-sol") == FoundationModel.SOL
    with pytest.raises(ReasoningProfileUnavailable, match="canonical primary"):
        require_primary_engineering_model("gpt-5.6-luna")
    with pytest.raises(ReasoningProfileUnavailable, match="not registered"):
        require_primary_engineering_model("unregistered-model")


def test_named_profiles_bind_explicit_standard_max_and_pro_semantics() -> None:
    assert set(PROFILE_REGISTRY) == {
        ReasoningProfileName.INTAKE,
        ReasoningProfileName.ORDINARY,
        ReasoningProfileName.DEEP_ARCHITECTURE,
        ReasoningProfileName.APEX,
        ReasoningProfileName.CRITIC,
        ReasoningProfileName.VERIFIER,
        ReasoningProfileName.FINALIZER,
        ReasoningProfileName.TERRA_DEGRADED_READ_ONLY,
    }

    intake = PROFILE_REGISTRY[ReasoningProfileName.INTAKE]
    ordinary = PROFILE_REGISTRY[ReasoningProfileName.ORDINARY]
    deep = PROFILE_REGISTRY[ReasoningProfileName.DEEP_ARCHITECTURE]
    apex = PROFILE_REGISTRY[ReasoningProfileName.APEX]
    critic = PROFILE_REGISTRY[ReasoningProfileName.CRITIC]
    verifier = PROFILE_REGISTRY[ReasoningProfileName.VERIFIER]
    finalizer = PROFILE_REGISTRY[ReasoningProfileName.FINALIZER]

    assert (intake.variant.request_mode, intake.variant.effort) == (
        ReasoningRequestMode.STANDARD,
        ReasoningEffort.HIGH,
    )
    assert ordinary.variant == intake.variant
    assert (deep.variant.request_mode, deep.variant.effort) == (
        ReasoningRequestMode.STANDARD,
        ReasoningEffort.XHIGH,
    )
    assert (apex.variant.request_mode, apex.variant.effort) == (
        ReasoningRequestMode.PRO,
        ReasoningEffort.MAX,
    )
    assert critic.variant == apex.variant
    assert verifier.variant == apex.variant
    assert finalizer.variant == intake.variant

    assert critic.context_mode == ContextMode.FRESH
    assert verifier.context_mode == ContextMode.FRESH
    assert finalizer.context_mode == ContextMode.FRESH
    assert all(
        profile.tool_authority == ToolAuthority.NONE for profile in PROFILE_REGISTRY.values()
    )
    assert all(profile.live_qualification_required for profile in PROFILE_REGISTRY.values())


def test_benchmark_matrix_covers_standard_and_pro_high_xhigh_and_max() -> None:
    observed = {(variant.request_mode, variant.effort) for variant in BENCHMARK_VARIANTS}
    assert observed == {
        (mode, effort)
        for mode in ReasoningRequestMode
        for effort in (ReasoningEffort.HIGH, ReasoningEffort.XHIGH, ReasoningEffort.MAX)
    }


def test_terra_degraded_mode_is_explicit_read_only_and_never_a_default() -> None:
    degraded = PROFILE_REGISTRY[ReasoningProfileName.TERRA_DEGRADED_READ_ONLY]
    assert degraded.model == FoundationModel.TERRA
    assert degraded.degraded_read_only is True
    assert degraded.authoritative is False
    assert degraded.candidate_generation_allowed is False
    assert ReasoningRole.IMPLEMENTER not in degraded.allowed_roles
    assert ReasoningProfileName.TERRA_DEGRADED_READ_ONLY not in ROLE_PROFILE_REGISTRY.values()

    with pytest.raises(ReasoningProfileUnavailable, match="live qualification"):
        require_production_profile(
            ReasoningProfileName.ORDINARY,
            ProviderQualificationState.OFFLINE_CONTRACT_ONLY,
            mutation_capable_task=False,
        )
    with pytest.raises(ReasoningProfileUnavailable, match="mutation-capable"):
        require_production_profile(
            ReasoningProfileName.TERRA_DEGRADED_READ_ONLY,
            ProviderQualificationState.LIVE_QUALIFIED,
            mutation_capable_task=True,
        )

    assert (
        require_production_profile(
            ReasoningProfileName.TERRA_DEGRADED_READ_ONLY,
            ProviderQualificationState.LIVE_QUALIFIED,
            mutation_capable_task=False,
        )
        == degraded
    )


def test_role_defaults_never_silently_select_degraded_mode() -> None:
    assert profile_for_role(ReasoningRole.ARCHITECT).name == (
        ReasoningProfileName.DEEP_ARCHITECTURE
    )
    assert profile_for_role(ReasoningRole.PLANNER).name == ReasoningProfileName.ORDINARY
    assert profile_for_role(ReasoningRole.IMPLEMENTER).name == ReasoningProfileName.ORDINARY
    assert profile_for_role(ReasoningRole.CRITIC).name == ReasoningProfileName.CRITIC
    assert profile_for_role(ReasoningRole.VERIFIER).name == ReasoningProfileName.VERIFIER

    with pytest.raises(ReasoningProfileUnavailable, match="no default"):
        profile_for_role(ReasoningRole.CLASSIFIER)


def test_policy_is_strict_versioned_digestible_and_contains_no_price_data() -> None:
    assert REASONING_POLICY.schema_version == REASONING_POLICY_VERSION
    assert REASONING_POLICY.primary_model == FoundationModel.SOL
    assert REASONING_POLICY.silent_fallback_prohibited is True
    assert REASONING_POLICY.approval_invalidation_on_model_or_profile_change is True
    assert REASONING_POLICY.maximum_full_repairs == 2
    assert REASONING_POLICY.price_registry_is_separate is True

    serialized = json.dumps(
        REASONING_POLICY.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    assert hashlib.sha256(serialized).hexdigest() == REASONING_POLICY_DIGEST
    serialized_policy = serialized.decode("utf-8").casefold()
    assert "usd" not in serialized_policy
    assert "per_million" not in serialized_policy

    invalid = REASONING_POLICY.model_dump(mode="python") | {"unknown": True}
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        CanonicalReasoningPolicy.model_validate(invalid)
