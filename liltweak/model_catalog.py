from __future__ import annotations

import hashlib
import json
from datetime import date
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from .reasoning_policy import (
    FoundationModel,
    ReasoningEffort,
    ReasoningRequestMode,
)

MODEL_CATALOG_VERSION = "2026-08-02.1"
PRICE_REGISTRY_VERSION = "openai-standard-2026-08-02.1"


class CatalogSchema(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class FactScope(StrEnum):
    IDENTITY = "identity"
    LIMITS = "limits"
    CAPABILITIES = "capabilities"
    REASONING = "reasoning"
    PRICING = "pricing"


class ProcessingTier(StrEnum):
    STANDARD = "standard"


class ReasoningContextMode(StrEnum):
    CURRENT_TURN = "current_turn"
    ALL_TURNS = "all_turns"


class OfficialSource(CatalogSchema):
    source_id: StrictStr = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")
    title: StrictStr = Field(min_length=1, max_length=256)
    url: HttpUrl
    accessed_on: date
    scopes: tuple[FactScope, ...]


class ModelCapabilities(CatalogSchema):
    context_window_tokens: StrictInt = Field(gt=0)
    maximum_output_tokens: StrictInt = Field(gt=0)
    knowledge_cutoff: date
    reasoning_efforts: tuple[ReasoningEffort, ...]
    reasoning_request_modes: tuple[ReasoningRequestMode, ...]
    default_reasoning_effort: ReasoningEffort
    default_reasoning_context: ReasoningContextMode
    reasoning_context_modes: tuple[ReasoningContextMode, ...]
    responses_api: StrictBool
    chat_completions_api: StrictBool
    structured_outputs: StrictBool
    function_calling: StrictBool
    streaming: StrictBool
    text_input: StrictBool
    text_output: StrictBool
    image_input: StrictBool
    audio_input: StrictBool
    video_input: StrictBool
    fine_tuning: StrictBool
    source_ids: tuple[StrictStr, ...]


class TokenPriceBand(CatalogSchema):
    input_per_million_usd: Decimal = Field(ge=0)
    cached_input_per_million_usd: Decimal = Field(ge=0)
    cache_write_per_million_usd: Decimal = Field(ge=0)
    output_per_million_usd: Decimal = Field(ge=0)


class TextTokenPricing(CatalogSchema):
    registry_version: Literal[PRICE_REGISTRY_VERSION]
    processing_tier: Literal[ProcessingTier.STANDARD]
    currency: Literal["USD"]
    unit_tokens: Literal[1_000_000]
    long_context_threshold_input_tokens: StrictInt = Field(gt=0)
    threshold_is_exclusive: Literal[True]
    short_context: TokenPriceBand
    long_context: TokenPriceBand
    regional_processing_uplift_included: Literal[False]
    source_ids: tuple[StrictStr, ...]


class ModelCatalogEntry(CatalogSchema):
    model_id: FoundationModel
    display_name: StrictStr = Field(min_length=1, max_length=128)
    family_role: StrictStr = Field(min_length=1, max_length=512)
    capabilities: ModelCapabilities
    pricing: TextTokenPricing


class ModelCatalog(CatalogSchema):
    schema_version: Literal[MODEL_CATALOG_VERSION]
    catalog_id: Literal["openai.gpt-5.6.model-catalog"]
    updated_on: date
    sources: tuple[OfficialSource, ...]
    models: tuple[ModelCatalogEntry, ...]

    @model_validator(mode="after")
    def validate_catalog(self) -> ModelCatalog:
        source_ids = [source.source_id for source in self.sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("model catalog source ids must be unique")
        model_ids = [model.model_id for model in self.models]
        if len(model_ids) != len(set(model_ids)) or set(model_ids) != set(FoundationModel):
            raise ValueError("model catalog must contain exactly Sol, Terra, and Luna")
        known_sources = set(source_ids)
        for model in self.models:
            referenced = {*model.capabilities.source_ids, *model.pricing.source_ids}
            if not referenced <= known_sources:
                raise ValueError("model catalog entry references an unknown official source")
        if self.updated_on < max(source.accessed_on for source in self.sources):
            raise ValueError("model catalog update date predates its source retrieval")
        return self

    def model(self, model_id: FoundationModel) -> ModelCatalogEntry:
        for entry in self.models:
            if entry.model_id == model_id:
                return entry
        raise KeyError(model_id)

    def price_band(
        self,
        model_id: FoundationModel,
        *,
        input_tokens: int,
    ) -> TokenPriceBand:
        if input_tokens < 0:
            raise ValueError("input token count cannot be negative")
        pricing = self.model(model_id).pricing
        if input_tokens > pricing.long_context_threshold_input_tokens:
            return pricing.long_context
        return pricing.short_context


OFFICIAL_SOURCES: Final[tuple[OfficialSource, ...]] = (
    OfficialSource(
        source_id="openai-model-guidance-gpt-5.6",
        title="OpenAI API model guidance — GPT-5.6",
        url="https://developers.openai.com/api/docs/guides/latest-model",
        accessed_on=date(2026, 8, 2),
        scopes=(FactScope.IDENTITY, FactScope.REASONING, FactScope.CAPABILITIES),
    ),
    OfficialSource(
        source_id="openai-reasoning-guide",
        title="OpenAI API reasoning models guide",
        url="https://developers.openai.com/api/docs/guides/reasoning",
        accessed_on=date(2026, 8, 2),
        scopes=(FactScope.REASONING, FactScope.CAPABILITIES),
    ),
    OfficialSource(
        source_id="openai-model-gpt-5.6-sol",
        title="GPT-5.6 Sol model reference",
        url="https://developers.openai.com/api/docs/models/gpt-5.6-sol",
        accessed_on=date(2026, 8, 2),
        scopes=(
            FactScope.IDENTITY,
            FactScope.LIMITS,
            FactScope.CAPABILITIES,
            FactScope.PRICING,
        ),
    ),
    OfficialSource(
        source_id="openai-model-gpt-5.6-terra",
        title="GPT-5.6 Terra model reference",
        url="https://developers.openai.com/api/docs/models/gpt-5.6-terra",
        accessed_on=date(2026, 8, 2),
        scopes=(
            FactScope.IDENTITY,
            FactScope.LIMITS,
            FactScope.CAPABILITIES,
            FactScope.PRICING,
        ),
    ),
    OfficialSource(
        source_id="openai-model-gpt-5.6-luna",
        title="GPT-5.6 Luna model reference",
        url="https://developers.openai.com/api/docs/models/gpt-5.6-luna",
        accessed_on=date(2026, 8, 2),
        scopes=(
            FactScope.IDENTITY,
            FactScope.LIMITS,
            FactScope.CAPABILITIES,
            FactScope.PRICING,
        ),
    ),
    OfficialSource(
        source_id="openai-api-pricing",
        title="OpenAI API pricing",
        url="https://developers.openai.com/api/docs/pricing",
        accessed_on=date(2026, 8, 2),
        scopes=(FactScope.PRICING,),
    ),
)

_REASONING_EFFORTS: Final[tuple[ReasoningEffort, ...]] = (
    ReasoningEffort.NONE,
    ReasoningEffort.LOW,
    ReasoningEffort.MEDIUM,
    ReasoningEffort.HIGH,
    ReasoningEffort.XHIGH,
    ReasoningEffort.MAX,
)

_REQUEST_MODES: Final[tuple[ReasoningRequestMode, ...]] = (
    ReasoningRequestMode.STANDARD,
    ReasoningRequestMode.PRO,
)

_CONTEXT_MODES: Final[tuple[ReasoningContextMode, ...]] = (
    ReasoningContextMode.CURRENT_TURN,
    ReasoningContextMode.ALL_TURNS,
)


def _capabilities(model_source_id: str) -> ModelCapabilities:
    return ModelCapabilities(
        context_window_tokens=1_050_000,
        maximum_output_tokens=128_000,
        knowledge_cutoff=date(2026, 2, 16),
        reasoning_efforts=_REASONING_EFFORTS,
        reasoning_request_modes=_REQUEST_MODES,
        default_reasoning_effort=ReasoningEffort.MEDIUM,
        default_reasoning_context=ReasoningContextMode.ALL_TURNS,
        reasoning_context_modes=_CONTEXT_MODES,
        responses_api=True,
        chat_completions_api=True,
        structured_outputs=True,
        function_calling=True,
        streaming=True,
        text_input=True,
        text_output=True,
        image_input=True,
        audio_input=False,
        video_input=False,
        fine_tuning=False,
        source_ids=(
            model_source_id,
            "openai-model-guidance-gpt-5.6",
            "openai-reasoning-guide",
        ),
    )


def _pricing(
    *,
    short_input: str,
    short_cached: str,
    short_cache_write: str,
    short_output: str,
    long_input: str,
    long_cached: str,
    long_cache_write: str,
    long_output: str,
    model_source_id: str,
) -> TextTokenPricing:
    return TextTokenPricing(
        registry_version=PRICE_REGISTRY_VERSION,
        processing_tier=ProcessingTier.STANDARD,
        currency="USD",
        unit_tokens=1_000_000,
        long_context_threshold_input_tokens=272_000,
        threshold_is_exclusive=True,
        short_context=TokenPriceBand(
            input_per_million_usd=Decimal(short_input),
            cached_input_per_million_usd=Decimal(short_cached),
            cache_write_per_million_usd=Decimal(short_cache_write),
            output_per_million_usd=Decimal(short_output),
        ),
        long_context=TokenPriceBand(
            input_per_million_usd=Decimal(long_input),
            cached_input_per_million_usd=Decimal(long_cached),
            cache_write_per_million_usd=Decimal(long_cache_write),
            output_per_million_usd=Decimal(long_output),
        ),
        regional_processing_uplift_included=False,
        source_ids=(model_source_id, "openai-api-pricing"),
    )


MODEL_CATALOG: Final = ModelCatalog(
    schema_version=MODEL_CATALOG_VERSION,
    catalog_id="openai.gpt-5.6.model-catalog",
    updated_on=date(2026, 8, 2),
    sources=OFFICIAL_SOURCES,
    models=(
        ModelCatalogEntry(
            model_id=FoundationModel.SOL,
            display_name="GPT-5.6 Sol",
            family_role="Frontier model for complex professional work.",
            capabilities=_capabilities("openai-model-gpt-5.6-sol"),
            pricing=_pricing(
                short_input="5.00",
                short_cached="0.50",
                short_cache_write="6.25",
                short_output="30.00",
                long_input="10.00",
                long_cached="1.00",
                long_cache_write="12.50",
                long_output="45.00",
                model_source_id="openai-model-gpt-5.6-sol",
            ),
        ),
        ModelCatalogEntry(
            model_id=FoundationModel.TERRA,
            display_name="GPT-5.6 Terra",
            family_role="Model that balances intelligence and cost.",
            capabilities=_capabilities("openai-model-gpt-5.6-terra"),
            pricing=_pricing(
                short_input="2.00",
                short_cached="0.20",
                short_cache_write="2.50",
                short_output="12.00",
                long_input="4.00",
                long_cached="0.40",
                long_cache_write="5.00",
                long_output="18.00",
                model_source_id="openai-model-gpt-5.6-terra",
            ),
        ),
        ModelCatalogEntry(
            model_id=FoundationModel.LUNA,
            display_name="GPT-5.6 Luna",
            family_role="Model optimized for cost-sensitive, high-volume workloads.",
            capabilities=_capabilities("openai-model-gpt-5.6-luna"),
            pricing=_pricing(
                short_input="0.20",
                short_cached="0.02",
                short_cache_write="0.25",
                short_output="1.20",
                long_input="0.40",
                long_cached="0.04",
                long_cache_write="0.50",
                long_output="1.80",
                model_source_id="openai-model-gpt-5.6-luna",
            ),
        ),
    ),
)

MODEL_CAPABILITY_REGISTRY: Final = MappingProxyType(
    {entry.model_id: entry.capabilities for entry in MODEL_CATALOG.models}
)
MODEL_PRICE_REGISTRY: Final = MappingProxyType(
    {entry.model_id: entry.pricing for entry in MODEL_CATALOG.models}
)


def _catalog_digest(catalog: ModelCatalog) -> str:
    encoded = json.dumps(
        catalog.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


MODEL_CATALOG_DIGEST: Final[str] = _catalog_digest(MODEL_CATALOG)
