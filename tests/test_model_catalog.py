from __future__ import annotations

import hashlib
import json
from datetime import date
from decimal import Decimal

from liltweak.model_catalog import (
    MODEL_CAPABILITY_REGISTRY,
    MODEL_CATALOG,
    MODEL_CATALOG_DIGEST,
    MODEL_CATALOG_VERSION,
    MODEL_PRICE_REGISTRY,
    PRICE_REGISTRY_VERSION,
    ReasoningContextMode,
)
from liltweak.reasoning_policy import (
    FoundationModel,
    ReasoningEffort,
    ReasoningRequestMode,
)


def test_catalog_is_versioned_current_and_bound_only_to_official_sources() -> None:
    assert MODEL_CATALOG.schema_version == MODEL_CATALOG_VERSION
    assert MODEL_CATALOG.updated_on == date(2026, 8, 2)
    assert set(MODEL_CAPABILITY_REGISTRY) == set(FoundationModel)
    assert set(MODEL_PRICE_REGISTRY) == set(FoundationModel)

    source_ids = {source.source_id for source in MODEL_CATALOG.sources}
    assert len(source_ids) == len(MODEL_CATALOG.sources)
    for source in MODEL_CATALOG.sources:
        assert str(source.url).startswith("https://developers.openai.com/")
        assert source.accessed_on == date(2026, 8, 2)
    for entry in MODEL_CATALOG.models:
        assert set(entry.capabilities.source_ids) <= source_ids
        assert set(entry.pricing.source_ids) <= source_ids

    encoded = json.dumps(
        MODEL_CATALOG.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    assert hashlib.sha256(encoded).hexdigest() == MODEL_CATALOG_DIGEST


def test_current_gpt_56_capability_limits_and_reasoning_modes_are_explicit() -> None:
    expected_efforts = (
        ReasoningEffort.NONE,
        ReasoningEffort.LOW,
        ReasoningEffort.MEDIUM,
        ReasoningEffort.HIGH,
        ReasoningEffort.XHIGH,
        ReasoningEffort.MAX,
    )
    for capabilities in MODEL_CAPABILITY_REGISTRY.values():
        assert capabilities.context_window_tokens == 1_050_000
        assert capabilities.maximum_output_tokens == 128_000
        assert capabilities.knowledge_cutoff == date(2026, 2, 16)
        assert capabilities.reasoning_efforts == expected_efforts
        assert capabilities.reasoning_request_modes == (
            ReasoningRequestMode.STANDARD,
            ReasoningRequestMode.PRO,
        )
        assert capabilities.default_reasoning_effort == ReasoningEffort.MEDIUM
        assert capabilities.default_reasoning_context == ReasoningContextMode.ALL_TURNS
        assert capabilities.responses_api is True
        assert capabilities.structured_outputs is True
        assert capabilities.function_calling is True
        assert capabilities.fine_tuning is False


def test_current_standard_short_and_long_context_prices_are_exact() -> None:
    expected = {
        FoundationModel.SOL: (
            ("5.00", "0.50", "6.25", "30.00"),
            ("10.00", "1.00", "12.50", "45.00"),
        ),
        FoundationModel.TERRA: (
            ("2.00", "0.20", "2.50", "12.00"),
            ("4.00", "0.40", "5.00", "18.00"),
        ),
        FoundationModel.LUNA: (
            ("0.20", "0.02", "0.25", "1.20"),
            ("0.40", "0.04", "0.50", "1.80"),
        ),
    }
    for model, (short_values, long_values) in expected.items():
        pricing = MODEL_PRICE_REGISTRY[model]
        assert pricing.registry_version == PRICE_REGISTRY_VERSION
        assert pricing.long_context_threshold_input_tokens == 272_000
        assert pricing.threshold_is_exclusive is True
        assert pricing.regional_processing_uplift_included is False
        short = pricing.short_context
        long = pricing.long_context
        assert (
            short.input_per_million_usd,
            short.cached_input_per_million_usd,
            short.cache_write_per_million_usd,
            short.output_per_million_usd,
        ) == tuple(Decimal(value) for value in short_values)
        assert (
            long.input_per_million_usd,
            long.cached_input_per_million_usd,
            long.cache_write_per_million_usd,
            long.output_per_million_usd,
        ) == tuple(Decimal(value) for value in long_values)


def test_long_context_threshold_is_strictly_greater_than_272k() -> None:
    model = FoundationModel.SOL
    pricing = MODEL_PRICE_REGISTRY[model]
    assert MODEL_CATALOG.price_band(model, input_tokens=272_000) == pricing.short_context
    assert MODEL_CATALOG.price_band(model, input_tokens=272_001) == pricing.long_context
