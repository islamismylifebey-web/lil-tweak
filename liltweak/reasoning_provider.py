from __future__ import annotations

import asyncio
import hashlib
import json
import os
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal, TypeVar, cast

import openai
from openai import AsyncOpenAI
from openai.lib._parsing._responses import type_to_text_format_param
from openai.types.responses.response_input_param import ResponseInputParam
from openai.types.shared_params.reasoning import Reasoning
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from .reasoning_contract import (
    EvidenceMode,
    OutcomeStatus,
    ProviderHealthState,
    ProviderQualification,
    ProviderQualificationState,
    ReasoningRole,
)
from .reasoning_policy import (
    PROFILE_REGISTRY,
    ContextMode,
    ReasoningEffort,
    ReasoningProfileDefinition,
    ReasoningProfileName,
    ReasoningRequestMode,
)
from .repository import secret_rule_ids

TOutput = TypeVar("TOutput", bound=BaseModel)


class ProviderFailureKind(StrEnum):
    NOT_CONFIGURED = "not_configured"
    AUTHENTICATION = "authentication"
    ENTITLEMENT = "entitlement"
    QUOTA = "quota"
    RATE_LIMIT = "rate_limit"
    TIMEOUT = "timeout"
    CANCELED = "canceled"
    REFUSAL = "refusal"
    INCOMPLETE = "incomplete"
    MALFORMED_OUTPUT = "malformed_output"
    MODEL_MISMATCH = "model_mismatch"
    USAGE_INVALID = "usage_invalid"
    SENSITIVE_INPUT = "sensitive_input"
    SERVICE = "service"
    INVALID_REQUEST = "invalid_request"
    BLOCKED_PROFILE = "blocked_profile"


class ReasoningProviderError(RuntimeError):
    def __init__(
        self,
        kind: ProviderFailureKind,
        message: str,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        response_id_digest: str | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.response_id_digest = response_id_digest


class ReasoningProviderCanceled(asyncio.CancelledError, ReasoningProviderError):
    """Cancellation remains observable both as provider status and task cancellation."""

    def __init__(self, message: str) -> None:
        ReasoningProviderError.__init__(self, ProviderFailureKind.CANCELED, message)


class ProviderEvidenceSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ProviderCallEvidence(ProviderEvidenceSchema):
    schema_version: Literal["reasoning-provider-evidence-v2"] = "reasoning-provider-evidence-v2"
    call_id: StrictStr = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    provider: str = "openai-responses"
    role: ReasoningRole
    profile_name: ReasoningProfileName
    profile_version: StrictStr
    requested_model: StrictStr
    effective_model: StrictStr
    request_mode: StrictStr
    reasoning_effort: StrictStr
    prompt_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    input_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    provider_input_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    response_id_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    output_item_digests: tuple[StrictStr, ...]
    parsed_output_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    provider_counted_input_tokens: StrictInt = Field(ge=0)
    input_tokens: StrictInt = Field(ge=0)
    cached_input_tokens: StrictInt = Field(ge=0)
    output_tokens: StrictInt = Field(ge=0)
    reasoning_tokens: StrictInt = Field(ge=0)
    total_tokens: StrictInt = Field(ge=0)
    store_disabled: StrictBool
    sensitive_tracing_disabled: StrictBool
    tools_supplied: StrictBool
    continuation_items_preserved: StrictBool
    status: str


@dataclass(frozen=True)
class ProviderCallResult:
    output: BaseModel
    evidence: ProviderCallEvidence
    replay_items: tuple[dict[str, Any], ...]


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest_json(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _provider_reasoning_mode(
    mode: ReasoningRequestMode,
) -> Literal["standard", "pro"]:
    if mode == ReasoningRequestMode.STANDARD:
        return "standard"
    if mode == ReasoningRequestMode.PRO:
        return "pro"
    raise AssertionError("unsupported reasoning request mode")


def _provider_reasoning_effort(
    effort: ReasoningEffort,
) -> Literal["none", "low", "medium", "high", "xhigh", "max"]:
    if effort == ReasoningEffort.NONE:
        return "none"
    if effort == ReasoningEffort.LOW:
        return "low"
    if effort == ReasoningEffort.MEDIUM:
        return "medium"
    if effort == ReasoningEffort.HIGH:
        return "high"
    if effort == ReasoningEffort.XHIGH:
        return "xhigh"
    if effort == ReasoningEffort.MAX:
        return "max"
    raise AssertionError("unsupported reasoning effort")


def _provider_item(value: object) -> object:
    """Remove SDK-only parsed helpers while preserving every provider-created field."""
    if isinstance(value, dict):
        return {
            key: _provider_item(item)
            for key, item in value.items()
            if key not in {"parsed", "parsed_arguments"}
        }
    if isinstance(value, list):
        return [_provider_item(item) for item in value]
    return value


def _replay_item(value: dict[str, Any]) -> dict[str, Any]:
    """Convert an output item to the current Responses input-item contract."""
    replay = dict(value)
    if replay.get("type") == "reasoning":
        # The 2.48.0 SDK response model exposes this output-only field in its nominal input type,
        # but the Responses endpoint rejects it when encrypted reasoning is replayed.
        replay.pop("status", None)
    return replay


class OpenAIResponsesReasoningProvider:
    """Explicit, tool-free Responses boundary for canonical reasoning roles.

    Production calls require the selected profile to have been live-qualified. Qualification
    calls use the same boundary but may only return structured proposals and have no tools.
    """

    def __init__(
        self,
        *,
        client: AsyncOpenAI | None = None,
        qualifications: tuple[ProviderQualification, ...] = (),
        maximum_concurrency: int = 2,
    ) -> None:
        if maximum_concurrency < 1 or maximum_concurrency > 8:
            raise ValueError("reasoning provider concurrency limit is invalid")
        if client is None and not os.getenv("OPENAI_API_KEY"):
            raise ReasoningProviderError(
                ProviderFailureKind.NOT_CONFIGURED,
                "OpenAI provider credentials are not configured",
            )
        self._client = client or AsyncOpenAI(max_retries=0)
        qualified: dict[ReasoningProfileName, ProviderQualification] = {}
        for qualification in qualifications:
            profile_name = self.validate_live_qualification(qualification)
            if profile_name in qualified:
                raise ValueError("reasoning provider qualification profiles must be unique")
            qualified[profile_name] = qualification
        self._qualifications = MappingProxyType(qualified)
        self._semaphore = asyncio.Semaphore(maximum_concurrency)

    def profile_is_qualified(self, profile_name: ReasoningProfileName) -> bool:
        """Return only the immutable qualification admission supplied at construction.

        The application factory never derives this value from environment configuration. A
        production composition must explicitly inject a provider whose qualified profile set was
        built from its external qualification workflow.
        """

        return profile_name in self._qualifications

    def qualification_for_profile(
        self,
        profile_name: ReasoningProfileName,
    ) -> ProviderQualification | None:
        return self._qualifications.get(profile_name)

    @staticmethod
    def validate_live_qualification(
        qualification: ProviderQualification,
    ) -> ReasoningProfileName:
        try:
            profile_name = ReasoningProfileName(qualification.profile_name)
            profile = PROFILE_REGISTRY[profile_name]
        except (KeyError, ValueError) as exc:
            raise ValueError("provider qualification names an unknown reasoning profile") from exc
        feature_gates = (
            qualification.strict_schema_qualified,
            qualification.refusal_qualified,
            qualification.incomplete_qualified,
            qualification.continuation_qualified,
            qualification.compaction_qualified,
            qualification.timeout_qualified,
            qualification.cancellation_qualified,
            qualification.concurrency_qualified,
            qualification.usage_reconciliation_qualified,
            qualification.caching_telemetry_qualified,
        )
        if (
            qualification.status != OutcomeStatus.PASSED
            or qualification.provider != "openai-responses"
            or not qualification.configured
            or not qualification.connected
            or qualification.requested_model != profile.model.value
            or qualification.effective_model != profile.model.value
            or qualification.profile_version != profile.profile_version
            or qualification.request_mode != profile.variant.request_mode.value
            or qualification.reasoning_effort != profile.variant.effort.value
            or qualification.health_state != ProviderHealthState.HEALTHY
            or qualification.qualification_state != ProviderQualificationState.LIVE_QUALIFIED
            or qualification.evidence_mode != EvidenceMode.LIVE
            or not all(feature_gates)
            or not qualification.store_disabled
            or not qualification.sensitive_tracing_disabled
            or not qualification.scenarios
            or any(
                scenario.status != OutcomeStatus.PASSED or not scenario.live
                for scenario in qualification.scenarios
            )
            or qualification.usage.requests < 1
            or qualification.qualified_at is None
        ):
            raise ValueError(
                "production reasoning qualification is incomplete or profile-mismatched"
            )
        return profile_name

    async def call(
        self,
        *,
        call_id: str,
        role: ReasoningRole,
        profile_name: ReasoningProfileName,
        instructions: str,
        input_text: str,
        output_type: type[TOutput],
        input_token_ceiling: int,
        output_token_ceiling: int,
        timeout_seconds: float,
        qualification_call: bool = False,
        replay_items: tuple[dict[str, Any], ...] = (),
        qualification_request_mode: ReasoningRequestMode | None = None,
        qualification_effort: ReasoningEffort | None = None,
    ) -> ProviderCallResult:
        profile = PROFILE_REGISTRY[profile_name]
        self._validate_request(
            role=role,
            profile=profile,
            instructions=instructions,
            input_text=input_text,
            input_token_ceiling=input_token_ceiling,
            output_token_ceiling=output_token_ceiling,
            timeout_seconds=timeout_seconds,
            qualification_call=qualification_call,
            qualification_request_mode=qualification_request_mode,
            qualification_effort=qualification_effort,
            replay_items=replay_items,
        )
        request_mode = qualification_request_mode or profile.variant.request_mode
        reasoning_effort = qualification_effort or profile.variant.effort
        reasoning = Reasoning(
            mode=_provider_reasoning_mode(request_mode),
            effort=_provider_reasoning_effort(reasoning_effort),
            context=(
                "all_turns"
                if profile.context_mode == ContextMode.STABLE_ALL_TURNS
                else "current_turn"
            ),
            summary="auto",
        )
        provider_input: str | ResponseInputParam = input_text
        if replay_items:
            provider_input = cast(
                ResponseInputParam,
                [
                    *replay_items,
                    {"role": "user", "content": input_text},
                ],
            )
        try:
            async with asyncio.timeout(timeout_seconds):
                async with self._semaphore:
                    counted = await self._client.responses.input_tokens.count(
                        model=profile.model.value,
                        instructions=instructions,
                        input=provider_input,
                        reasoning=reasoning,
                        text={"format": type_to_text_format_param(output_type)},
                        parallel_tool_calls=False,
                        tools=[],
                    )
                    if counted.input_tokens > input_token_ceiling:
                        raise ReasoningProviderError(
                            ProviderFailureKind.USAGE_INVALID,
                            "provider-counted input exceeds the profile ceiling",
                        )
                    response = await self._client.responses.parse(
                        model=profile.model.value,
                        instructions=instructions,
                        input=provider_input,
                        text_format=output_type,
                        max_output_tokens=output_token_ceiling,
                        reasoning=reasoning,
                        include=["reasoning.encrypted_content"],
                        parallel_tool_calls=False,
                        tools=[],
                        store=False,
                        timeout=timeout_seconds,
                    )
        except ReasoningProviderError:
            raise
        except TimeoutError as exc:
            raise ReasoningProviderError(
                ProviderFailureKind.TIMEOUT,
                "reasoning provider request timed out",
            ) from exc
        except asyncio.CancelledError as exc:
            raise ReasoningProviderCanceled("reasoning provider request was canceled") from exc
        except Exception as exc:
            raise self._classify_exception(exc) from exc
        return self._validate_response(
            call_id=call_id,
            role=role,
            profile=profile,
            instructions=instructions,
            input_text=input_text,
            provider_input=provider_input,
            output_type=output_type,
            counted_input_tokens=counted.input_tokens,
            input_token_ceiling=input_token_ceiling,
            output_token_ceiling=output_token_ceiling,
            response=response,
            continuation_items_preserved=bool(replay_items),
            request_mode=request_mode.value,
            reasoning_effort=reasoning_effort.value,
        )

    def _validate_request(
        self,
        *,
        role: ReasoningRole,
        profile: ReasoningProfileDefinition,
        instructions: str,
        input_text: str,
        input_token_ceiling: int,
        output_token_ceiling: int,
        timeout_seconds: float,
        qualification_call: bool,
        qualification_request_mode: ReasoningRequestMode | None,
        qualification_effort: ReasoningEffort | None,
        replay_items: tuple[dict[str, Any], ...],
    ) -> None:
        if role not in profile.allowed_roles:
            raise ReasoningProviderError(
                ProviderFailureKind.BLOCKED_PROFILE,
                "reasoning role is not allowed by the selected profile",
            )
        if not qualification_call and profile.name not in self._qualifications:
            raise ReasoningProviderError(
                ProviderFailureKind.BLOCKED_PROFILE,
                "reasoning profile has not passed live qualification",
            )
        if (qualification_request_mode is None) != (qualification_effort is None):
            raise ValueError("qualification variant requires both mode and effort")
        if qualification_request_mode is not None and not qualification_call:
            raise ReasoningProviderError(
                ProviderFailureKind.BLOCKED_PROFILE,
                "reasoning variants may be overridden only by the qualification harness",
            )
        if input_token_ceiling < 1 or output_token_ceiling < 1:
            raise ValueError("reasoning token ceilings must be positive")
        if timeout_seconds <= 0 or timeout_seconds > 600:
            raise ValueError("reasoning provider timeout is invalid")
        payload = f"{instructions}\n{input_text}".encode()
        if secret_rule_ids(payload):
            raise ReasoningProviderError(
                ProviderFailureKind.SENSITIVE_INPUT,
                "reasoning input contains credential-shaped material",
            )
        if replay_items:
            try:
                replay_payload = json.dumps(
                    replay_items,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode()
            except (TypeError, ValueError) as exc:
                raise ReasoningProviderError(
                    ProviderFailureKind.MALFORMED_OUTPUT,
                    "reasoning replay items are not canonical JSON",
                ) from exc
            if secret_rule_ids(replay_payload):
                raise ReasoningProviderError(
                    ProviderFailureKind.SENSITIVE_INPUT,
                    "reasoning replay input contains credential-shaped material",
                )

    def _validate_response(
        self,
        *,
        call_id: str,
        role: ReasoningRole,
        profile: ReasoningProfileDefinition,
        instructions: str,
        input_text: str,
        provider_input: str | ResponseInputParam,
        output_type: type[TOutput],
        counted_input_tokens: int,
        input_token_ceiling: int,
        output_token_ceiling: int,
        response: Any,
        continuation_items_preserved: bool,
        request_mode: str,
        reasoning_effort: str,
    ) -> ProviderCallResult:
        if response.error is not None:
            raise self._response_error(
                ProviderFailureKind.SERVICE,
                "reasoning provider returned an error response",
                response,
            )
        if response.status != "completed":
            raise self._response_error(
                ProviderFailureKind.INCOMPLETE,
                "reasoning provider returned an incomplete response",
                response,
            )
        provider_items = tuple(
            cast(
                dict[str, Any],
                _provider_item(item.model_dump(mode="json", warnings=False)),
            )
            for item in response.output
        )
        replay_items = tuple(_replay_item(item) for item in provider_items)
        if self._contains_refusal(provider_items):
            raise self._response_error(
                ProviderFailureKind.REFUSAL,
                "reasoning provider refused the structured request",
                response,
            )
        if response.model != profile.model.value:
            raise self._response_error(
                ProviderFailureKind.MODEL_MISMATCH,
                "reasoning provider effective model differs from the requested model",
                response,
            )
        try:
            parsed = response.output_parsed
            output = (
                parsed if isinstance(parsed, output_type) else output_type.model_validate(parsed)
            )
        except Exception as exc:
            raise self._response_error(
                ProviderFailureKind.MALFORMED_OUTPUT,
                "reasoning provider output failed strict schema validation",
                response,
            ) from exc
        serialized_output = output.model_dump_json()
        if secret_rule_ids(serialized_output.encode("utf-8")):
            raise self._response_error(
                ProviderFailureKind.SENSITIVE_INPUT,
                "reasoning provider output contains credential-shaped material",
                response,
            )
        usage = response.usage
        if usage is None:
            raise self._response_error(
                ProviderFailureKind.USAGE_INVALID,
                "reasoning provider omitted usage accounting",
                response,
            )
        cached_tokens = usage.input_tokens_details.cached_tokens
        reasoning_tokens = usage.output_tokens_details.reasoning_tokens
        if (
            usage.input_tokens < 0
            or usage.input_tokens > input_token_ceiling
            or usage.output_tokens < 0
            or usage.output_tokens > output_token_ceiling
            or usage.total_tokens < usage.input_tokens + usage.output_tokens
            or cached_tokens < 0
            or cached_tokens > usage.input_tokens
            or reasoning_tokens < 0
            or not response.id
        ):
            raise self._response_error(
                ProviderFailureKind.USAGE_INVALID,
                "reasoning provider usage accounting is invalid",
                response,
            )
        evidence = ProviderCallEvidence(
            call_id=call_id,
            role=role,
            profile_name=profile.name,
            profile_version=profile.profile_version,
            requested_model=profile.model.value,
            effective_model=response.model,
            request_mode=request_mode,
            reasoning_effort=reasoning_effort,
            prompt_digest=_digest_text(instructions),
            input_digest=_digest_text(input_text),
            provider_input_digest=(
                _digest_text(provider_input)
                if isinstance(provider_input, str)
                else _digest_json(provider_input)
            ),
            response_id_digest=_digest_text(response.id),
            output_item_digests=tuple(_digest_json(item) for item in provider_items),
            parsed_output_digest=_digest_json(output.model_dump(mode="json")),
            provider_counted_input_tokens=counted_input_tokens,
            input_tokens=usage.input_tokens,
            cached_input_tokens=cached_tokens,
            output_tokens=usage.output_tokens,
            reasoning_tokens=reasoning_tokens,
            total_tokens=usage.total_tokens,
            store_disabled=True,
            sensitive_tracing_disabled=True,
            tools_supplied=False,
            continuation_items_preserved=continuation_items_preserved,
            status=response.status,
        )
        return ProviderCallResult(output=output, evidence=evidence, replay_items=replay_items)

    @staticmethod
    def _response_error(
        kind: ProviderFailureKind,
        message: str,
        response: Any,
    ) -> ReasoningProviderError:
        """Preserve sanitized billable usage when semantic response validation fails."""

        usage = getattr(response, "usage", None)
        raw_input_tokens = getattr(usage, "input_tokens", 0)
        raw_output_tokens = getattr(usage, "output_tokens", 0)
        input_tokens = (
            raw_input_tokens
            if isinstance(raw_input_tokens, int)
            and not isinstance(raw_input_tokens, bool)
            and raw_input_tokens >= 0
            else 0
        )
        output_tokens = (
            raw_output_tokens
            if isinstance(raw_output_tokens, int)
            and not isinstance(raw_output_tokens, bool)
            and raw_output_tokens >= 0
            else 0
        )
        response_id = getattr(response, "id", None)
        response_id_digest = (
            _digest_text(response_id) if isinstance(response_id, str) and response_id else None
        )
        return ReasoningProviderError(
            kind,
            message,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            response_id_digest=response_id_digest,
        )

    @staticmethod
    def _contains_refusal(items: tuple[dict[str, Any], ...]) -> bool:
        return any(
            content.get("type") == "refusal"
            for item in items
            if item.get("type") == "message"
            for content in item.get("content", ())
            if isinstance(content, dict)
        )

    @staticmethod
    def _classify_exception(exc: Exception) -> ReasoningProviderError:
        if isinstance(exc, openai.AuthenticationError):
            kind = ProviderFailureKind.AUTHENTICATION
        elif isinstance(exc, openai.PermissionDeniedError):
            kind = ProviderFailureKind.ENTITLEMENT
        elif isinstance(exc, openai.RateLimitError):
            message = str(exc).casefold()
            kind = (
                ProviderFailureKind.QUOTA if "quota" in message else ProviderFailureKind.RATE_LIMIT
            )
        elif isinstance(exc, (openai.APITimeoutError, openai.APIConnectionError)):
            kind = ProviderFailureKind.TIMEOUT
        elif isinstance(exc, (openai.BadRequestError, openai.NotFoundError)):
            # Request/model errors are not availability failures and must never
            # become eligible for degraded fallback.
            kind = ProviderFailureKind.INVALID_REQUEST
        elif isinstance(exc, openai.APIStatusError) and exc.status_code < 500:
            kind = ProviderFailureKind.INVALID_REQUEST
        else:
            kind = ProviderFailureKind.SERVICE
        return ReasoningProviderError(kind, "reasoning provider request failed closed")
