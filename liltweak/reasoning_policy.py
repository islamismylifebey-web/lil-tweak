from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, StrictStr, model_validator

from .reasoning_contract import (
    ProviderQualificationState,
    ReasoningRole,
    ToolAuthority,
)

REASONING_POLICY_VERSION: Final[Literal["1.0.0"]] = "1.0.0"


class PolicySchema(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class FoundationModel(StrEnum):
    SOL = "gpt-5.6-sol"
    TERRA = "gpt-5.6-terra"
    LUNA = "gpt-5.6-luna"


class ReasoningRequestMode(StrEnum):
    STANDARD = "standard"
    PRO = "pro"


class ReasoningEffort(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"
    MAX = "max"


class ReasoningProfileName(StrEnum):
    INTAKE = "intake"
    ORDINARY = "ordinary"
    DEEP_ARCHITECTURE = "deep_architecture"
    APEX = "apex"
    CRITIC = "critic"
    VERIFIER = "verifier"
    FINALIZER = "finalizer"
    TERRA_DEGRADED_READ_ONLY = "terra_degraded_read_only"


class ContextMode(StrEnum):
    CURRENT_TURN = "current_turn"
    STABLE_ALL_TURNS = "stable_all_turns"
    FRESH = "fresh"


class ModelDefinition(PolicySchema):
    model_id: FoundationModel
    primary_engineering_model: StrictBool
    degraded_fallback_only: StrictBool
    low_risk_classification_only: StrictBool
    allowed_roles: tuple[ReasoningRole, ...]


class ReasoningVariant(PolicySchema):
    request_mode: ReasoningRequestMode
    effort: ReasoningEffort


class ReasoningProfileDefinition(PolicySchema):
    profile_id: StrictStr
    profile_version: Literal["1.0.0"]
    name: ReasoningProfileName
    model: FoundationModel
    variant: ReasoningVariant
    allowed_roles: tuple[ReasoningRole, ...]
    context_mode: ContextMode
    tool_authority: Literal[ToolAuthority.NONE]
    candidate_generation_allowed: StrictBool
    authoritative: StrictBool
    degraded_read_only: StrictBool
    live_qualification_required: Literal[True]
    maximum_full_repairs: StrictInt
    approval_change_invalidates: Literal[True]

    @model_validator(mode="after")
    def validate_profile(self) -> ReasoningProfileDefinition:
        if not self.profile_id or len(self.profile_id) > 128:
            raise ValueError("reasoning profile id is invalid")
        if not self.allowed_roles:
            raise ValueError("reasoning profile must allow at least one role")
        if len(set(self.allowed_roles)) != len(self.allowed_roles):
            raise ValueError("reasoning profile roles must be unique")
        if self.maximum_full_repairs < 0 or self.maximum_full_repairs > 2:
            raise ValueError("reasoning profile repair limit must be between zero and two")
        if self.degraded_read_only:
            if self.authoritative or self.candidate_generation_allowed:
                raise ValueError("degraded read-only profile cannot be authoritative or implement")
            if ReasoningRole.IMPLEMENTER in self.allowed_roles:
                raise ValueError("degraded read-only profile cannot serve the implementer role")
        if (
            self.context_mode == ContextMode.FRESH
            and ReasoningRole.IMPLEMENTER in self.allowed_roles
        ):
            raise ValueError("implementer profile cannot discard its approved bounded context")
        return self


class RoleProfileBinding(PolicySchema):
    role: ReasoningRole
    default_profile: ReasoningProfileName


class CanonicalReasoningPolicy(PolicySchema):
    schema_version: Literal["1.0.0"]
    policy_id: Literal["lil-tweak.reasoning-policy"]
    policy_version: Literal["1.0.0"]
    primary_model: Literal[FoundationModel.SOL]
    models: tuple[ModelDefinition, ...]
    profiles: tuple[ReasoningProfileDefinition, ...]
    role_defaults: tuple[RoleProfileBinding, ...]
    benchmark_variants: tuple[ReasoningVariant, ...]
    explicit_degraded_profile: Literal[ReasoningProfileName.TERRA_DEGRADED_READ_ONLY]
    live_qualification_required: Literal[True]
    tool_free_gate_required: Literal[True]
    reasoning_tools_authorized: Literal[False]
    silent_fallback_prohibited: Literal[True]
    approval_invalidation_on_model_or_profile_change: Literal[True]
    maximum_full_repairs: Literal[2]
    price_registry_is_separate: Literal[True]

    @model_validator(mode="after")
    def validate_registry(self) -> CanonicalReasoningPolicy:
        model_ids = [model.model_id for model in self.models]
        if len(model_ids) != len(set(model_ids)):
            raise ValueError("model registry contains duplicate model ids")
        if set(model_ids) != set(FoundationModel):
            raise ValueError("model registry must contain exactly Sol, Terra, and Luna")
        primary = [model for model in self.models if model.primary_engineering_model]
        if len(primary) != 1 or primary[0].model_id != FoundationModel.SOL:
            raise ValueError("Sol must be the only primary engineering model")

        profile_names = [profile.name for profile in self.profiles]
        if len(profile_names) != len(set(profile_names)):
            raise ValueError("reasoning profile registry contains duplicate names")
        required_profiles = {
            ReasoningProfileName.INTAKE,
            ReasoningProfileName.ORDINARY,
            ReasoningProfileName.DEEP_ARCHITECTURE,
            ReasoningProfileName.APEX,
            ReasoningProfileName.CRITIC,
            ReasoningProfileName.VERIFIER,
            ReasoningProfileName.FINALIZER,
            ReasoningProfileName.TERRA_DEGRADED_READ_ONLY,
        }
        if set(profile_names) != required_profiles:
            raise ValueError("reasoning profile registry is incomplete")

        profiles = {profile.name: profile for profile in self.profiles}
        degraded = profiles[self.explicit_degraded_profile]
        if degraded.model != FoundationModel.TERRA or not degraded.degraded_read_only:
            raise ValueError("the explicit degraded profile must be Terra read-only")
        for profile in self.profiles:
            if (
                profile.name != self.explicit_degraded_profile
                and profile.model != self.primary_model
            ):
                raise ValueError("authoritative reasoning profiles must use the primary model")

        model_roles = {model.model_id: set(model.allowed_roles) for model in self.models}
        for profile in self.profiles:
            if not set(profile.allowed_roles) <= model_roles[profile.model]:
                raise ValueError("profile grants a role that its model policy denies")

        default_roles = [binding.role for binding in self.role_defaults]
        if len(default_roles) != len(set(default_roles)):
            raise ValueError("role defaults contain duplicate roles")
        for binding in self.role_defaults:
            if binding.default_profile == self.explicit_degraded_profile:
                raise ValueError("Terra degraded mode can never be a role default")
            if binding.role not in profiles[binding.default_profile].allowed_roles:
                raise ValueError("role default targets an incompatible profile")

        variants = {(variant.request_mode, variant.effort) for variant in self.benchmark_variants}
        required_variants = {
            (ReasoningRequestMode.STANDARD, ReasoningEffort.HIGH),
            (ReasoningRequestMode.STANDARD, ReasoningEffort.XHIGH),
            (ReasoningRequestMode.STANDARD, ReasoningEffort.MAX),
            (ReasoningRequestMode.PRO, ReasoningEffort.HIGH),
            (ReasoningRequestMode.PRO, ReasoningEffort.XHIGH),
            (ReasoningRequestMode.PRO, ReasoningEffort.MAX),
        }
        if variants != required_variants:
            raise ValueError("reasoning benchmark matrix is incomplete")
        return self


class ReasoningProfileUnavailable(RuntimeError):
    pass


_ENGINEERING_ROLES: Final[tuple[ReasoningRole, ...]] = (
    ReasoningRole.INTAKE,
    ReasoningRole.RETRIEVER,
    ReasoningRole.ANALYST,
    ReasoningRole.ARCHITECT,
    ReasoningRole.PLANNER,
    ReasoningRole.IMPLEMENTER,
    ReasoningRole.CRITIC,
    ReasoningRole.VERIFIER,
    ReasoningRole.FINALIZER,
)

_READ_ONLY_ENGINEERING_ROLES: Final[tuple[ReasoningRole, ...]] = (
    ReasoningRole.INTAKE,
    ReasoningRole.RETRIEVER,
    ReasoningRole.ANALYST,
    ReasoningRole.ARCHITECT,
    ReasoningRole.PLANNER,
    ReasoningRole.CRITIC,
    ReasoningRole.VERIFIER,
    ReasoningRole.FINALIZER,
    ReasoningRole.DIAGNOSTIC,
)

MODELS: Final[tuple[ModelDefinition, ...]] = (
    ModelDefinition(
        model_id=FoundationModel.SOL,
        primary_engineering_model=True,
        degraded_fallback_only=False,
        low_risk_classification_only=False,
        allowed_roles=_ENGINEERING_ROLES,
    ),
    ModelDefinition(
        model_id=FoundationModel.TERRA,
        primary_engineering_model=False,
        degraded_fallback_only=True,
        low_risk_classification_only=False,
        allowed_roles=_READ_ONLY_ENGINEERING_ROLES,
    ),
    ModelDefinition(
        model_id=FoundationModel.LUNA,
        primary_engineering_model=False,
        degraded_fallback_only=False,
        low_risk_classification_only=True,
        allowed_roles=(ReasoningRole.CLASSIFIER, ReasoningRole.DIAGNOSTIC),
    ),
)


def _variant(mode: ReasoningRequestMode, effort: ReasoningEffort) -> ReasoningVariant:
    return ReasoningVariant(request_mode=mode, effort=effort)


PROFILES: Final[tuple[ReasoningProfileDefinition, ...]] = (
    ReasoningProfileDefinition(
        profile_id="lil-tweak.reasoning.intake.v1",
        profile_version=REASONING_POLICY_VERSION,
        name=ReasoningProfileName.INTAKE,
        model=FoundationModel.SOL,
        variant=_variant(ReasoningRequestMode.STANDARD, ReasoningEffort.HIGH),
        allowed_roles=(ReasoningRole.INTAKE, ReasoningRole.RETRIEVER),
        context_mode=ContextMode.CURRENT_TURN,
        tool_authority=ToolAuthority.NONE,
        candidate_generation_allowed=False,
        authoritative=True,
        degraded_read_only=False,
        live_qualification_required=True,
        maximum_full_repairs=0,
        approval_change_invalidates=True,
    ),
    ReasoningProfileDefinition(
        profile_id="lil-tweak.reasoning.ordinary.v1",
        profile_version=REASONING_POLICY_VERSION,
        name=ReasoningProfileName.ORDINARY,
        model=FoundationModel.SOL,
        variant=_variant(ReasoningRequestMode.STANDARD, ReasoningEffort.HIGH),
        allowed_roles=(
            ReasoningRole.ANALYST,
            ReasoningRole.PLANNER,
            ReasoningRole.IMPLEMENTER,
        ),
        context_mode=ContextMode.STABLE_ALL_TURNS,
        tool_authority=ToolAuthority.NONE,
        candidate_generation_allowed=True,
        authoritative=True,
        degraded_read_only=False,
        live_qualification_required=True,
        maximum_full_repairs=2,
        approval_change_invalidates=True,
    ),
    ReasoningProfileDefinition(
        profile_id="lil-tweak.reasoning.deep-architecture.v1",
        profile_version=REASONING_POLICY_VERSION,
        name=ReasoningProfileName.DEEP_ARCHITECTURE,
        model=FoundationModel.SOL,
        variant=_variant(ReasoningRequestMode.STANDARD, ReasoningEffort.XHIGH),
        allowed_roles=(
            ReasoningRole.ARCHITECT,
            ReasoningRole.PLANNER,
            ReasoningRole.IMPLEMENTER,
        ),
        context_mode=ContextMode.STABLE_ALL_TURNS,
        tool_authority=ToolAuthority.NONE,
        candidate_generation_allowed=True,
        authoritative=True,
        degraded_read_only=False,
        live_qualification_required=True,
        maximum_full_repairs=2,
        approval_change_invalidates=True,
    ),
    ReasoningProfileDefinition(
        profile_id="lil-tweak.reasoning.apex.v1",
        profile_version=REASONING_POLICY_VERSION,
        name=ReasoningProfileName.APEX,
        model=FoundationModel.SOL,
        variant=_variant(ReasoningRequestMode.PRO, ReasoningEffort.MAX),
        allowed_roles=(
            ReasoningRole.ARCHITECT,
            ReasoningRole.PLANNER,
            ReasoningRole.IMPLEMENTER,
        ),
        context_mode=ContextMode.STABLE_ALL_TURNS,
        tool_authority=ToolAuthority.NONE,
        candidate_generation_allowed=True,
        authoritative=True,
        degraded_read_only=False,
        live_qualification_required=True,
        maximum_full_repairs=2,
        approval_change_invalidates=True,
    ),
    ReasoningProfileDefinition(
        profile_id="lil-tweak.reasoning.critic.v1",
        profile_version=REASONING_POLICY_VERSION,
        name=ReasoningProfileName.CRITIC,
        model=FoundationModel.SOL,
        variant=_variant(ReasoningRequestMode.PRO, ReasoningEffort.MAX),
        allowed_roles=(ReasoningRole.CRITIC,),
        context_mode=ContextMode.FRESH,
        tool_authority=ToolAuthority.NONE,
        candidate_generation_allowed=False,
        authoritative=True,
        degraded_read_only=False,
        live_qualification_required=True,
        maximum_full_repairs=2,
        approval_change_invalidates=True,
    ),
    ReasoningProfileDefinition(
        profile_id="lil-tweak.reasoning.verifier.v1",
        profile_version=REASONING_POLICY_VERSION,
        name=ReasoningProfileName.VERIFIER,
        model=FoundationModel.SOL,
        variant=_variant(ReasoningRequestMode.PRO, ReasoningEffort.MAX),
        allowed_roles=(ReasoningRole.VERIFIER,),
        context_mode=ContextMode.FRESH,
        tool_authority=ToolAuthority.NONE,
        candidate_generation_allowed=False,
        authoritative=True,
        degraded_read_only=False,
        live_qualification_required=True,
        maximum_full_repairs=2,
        approval_change_invalidates=True,
    ),
    ReasoningProfileDefinition(
        profile_id="lil-tweak.reasoning.finalizer.v1",
        profile_version=REASONING_POLICY_VERSION,
        name=ReasoningProfileName.FINALIZER,
        model=FoundationModel.SOL,
        variant=_variant(ReasoningRequestMode.STANDARD, ReasoningEffort.HIGH),
        allowed_roles=(ReasoningRole.FINALIZER,),
        context_mode=ContextMode.FRESH,
        tool_authority=ToolAuthority.NONE,
        candidate_generation_allowed=False,
        authoritative=True,
        degraded_read_only=False,
        live_qualification_required=True,
        maximum_full_repairs=0,
        approval_change_invalidates=True,
    ),
    ReasoningProfileDefinition(
        profile_id="lil-tweak.reasoning.terra-degraded-read-only.v1",
        profile_version=REASONING_POLICY_VERSION,
        name=ReasoningProfileName.TERRA_DEGRADED_READ_ONLY,
        model=FoundationModel.TERRA,
        variant=_variant(ReasoningRequestMode.STANDARD, ReasoningEffort.HIGH),
        allowed_roles=_READ_ONLY_ENGINEERING_ROLES,
        context_mode=ContextMode.FRESH,
        tool_authority=ToolAuthority.NONE,
        candidate_generation_allowed=False,
        authoritative=False,
        degraded_read_only=True,
        live_qualification_required=True,
        maximum_full_repairs=0,
        approval_change_invalidates=True,
    ),
)

ROLE_DEFAULTS: Final[tuple[RoleProfileBinding, ...]] = (
    RoleProfileBinding(role=ReasoningRole.INTAKE, default_profile=ReasoningProfileName.INTAKE),
    RoleProfileBinding(role=ReasoningRole.RETRIEVER, default_profile=ReasoningProfileName.INTAKE),
    RoleProfileBinding(role=ReasoningRole.ANALYST, default_profile=ReasoningProfileName.ORDINARY),
    RoleProfileBinding(
        role=ReasoningRole.ARCHITECT,
        default_profile=ReasoningProfileName.DEEP_ARCHITECTURE,
    ),
    RoleProfileBinding(
        role=ReasoningRole.PLANNER,
        default_profile=ReasoningProfileName.ORDINARY,
    ),
    RoleProfileBinding(
        role=ReasoningRole.IMPLEMENTER,
        default_profile=ReasoningProfileName.ORDINARY,
    ),
    RoleProfileBinding(role=ReasoningRole.CRITIC, default_profile=ReasoningProfileName.CRITIC),
    RoleProfileBinding(role=ReasoningRole.VERIFIER, default_profile=ReasoningProfileName.VERIFIER),
    RoleProfileBinding(
        role=ReasoningRole.FINALIZER, default_profile=ReasoningProfileName.FINALIZER
    ),
)

BENCHMARK_VARIANTS: Final[tuple[ReasoningVariant, ...]] = tuple(
    _variant(mode, effort)
    for mode in ReasoningRequestMode
    for effort in (ReasoningEffort.HIGH, ReasoningEffort.XHIGH, ReasoningEffort.MAX)
)

REASONING_POLICY: Final = CanonicalReasoningPolicy(
    schema_version=REASONING_POLICY_VERSION,
    policy_id="lil-tweak.reasoning-policy",
    policy_version=REASONING_POLICY_VERSION,
    primary_model=FoundationModel.SOL,
    models=MODELS,
    profiles=PROFILES,
    role_defaults=ROLE_DEFAULTS,
    benchmark_variants=BENCHMARK_VARIANTS,
    explicit_degraded_profile=ReasoningProfileName.TERRA_DEGRADED_READ_ONLY,
    live_qualification_required=True,
    tool_free_gate_required=True,
    reasoning_tools_authorized=False,
    silent_fallback_prohibited=True,
    approval_invalidation_on_model_or_profile_change=True,
    maximum_full_repairs=2,
    price_registry_is_separate=True,
)

MODEL_REGISTRY: Final = MappingProxyType({model.model_id: model for model in MODELS})
PROFILE_REGISTRY: Final = MappingProxyType({profile.name: profile for profile in PROFILES})
ROLE_PROFILE_REGISTRY: Final = MappingProxyType(
    {binding.role: binding.default_profile for binding in ROLE_DEFAULTS}
)


def _policy_digest(policy: CanonicalReasoningPolicy) -> str:
    encoded = json.dumps(
        policy.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


REASONING_POLICY_DIGEST: Final[str] = _policy_digest(REASONING_POLICY)


def profile_for_role(role: ReasoningRole) -> ReasoningProfileDefinition:
    try:
        return PROFILE_REGISTRY[ROLE_PROFILE_REGISTRY[role]]
    except KeyError as exc:
        raise ReasoningProfileUnavailable(
            f"no default reasoning profile for role {role.value}"
        ) from exc


def require_primary_engineering_model(model_id: str | FoundationModel) -> FoundationModel:
    """Reject scattered engineering-model overrides outside the canonical policy."""

    try:
        model = FoundationModel(model_id)
    except ValueError as exc:
        raise ReasoningProfileUnavailable(
            "engineering model is not registered in the canonical reasoning policy"
        ) from exc
    if model != REASONING_POLICY.primary_model:
        raise ReasoningProfileUnavailable("engineering calls must use the canonical primary model")
    return model


def require_production_profile(
    profile_name: ReasoningProfileName,
    qualification_state: ProviderQualificationState,
    *,
    mutation_capable_task: bool,
) -> ReasoningProfileDefinition:
    """Fail closed unless an explicitly selected profile is live-qualified for production use."""

    profile = PROFILE_REGISTRY[profile_name]
    if qualification_state != ProviderQualificationState.LIVE_QUALIFIED:
        raise ReasoningProfileUnavailable(
            f"profile {profile_name.value} is blocked until live qualification succeeds"
        )
    if mutation_capable_task and profile.degraded_read_only:
        raise ReasoningProfileUnavailable(
            "Terra degraded read-only mode cannot serve a mutation-capable task"
        )
    return profile
