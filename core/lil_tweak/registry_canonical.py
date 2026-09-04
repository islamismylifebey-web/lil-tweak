"""Deterministic canonical serialization and digest binding for registry records."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Mapping

from .registry_types import DecisionRequest


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SECRET_TERMS = ("password", "token", "secret", "credential")


class CanonicalizationError(ValueError):
    """Raised when a value cannot safely enter the canonical registry form."""


def _secret_bearing_name(name: str) -> bool:
    collapsed = "".join(char for char in name.lower() if char.isalnum())
    return any(term in collapsed for term in _SECRET_TERMS)


def _normalize(value: object) -> object:
    if isinstance(value, StrEnum):
        return value.value
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        raise CanonicalizationError("floats are not supported")
    if isinstance(value, bytes):
        raise CanonicalizationError("bytes are not supported")
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise CanonicalizationError("naive timestamps are not supported")
        utc_value = value.astimezone(timezone.utc)
        return utc_value.isoformat().replace("+00:00", "Z")
    if is_dataclass(value) and not isinstance(value, type):
        normalized: dict[str, object] = {}
        for field in fields(value):
            if _secret_bearing_name(field.name):
                raise CanonicalizationError("secret-bearing field name is not supported")
            normalized[field.name] = _normalize(getattr(value, field.name))
        return normalized
    if isinstance(value, Mapping):
        normalized_mapping: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("dictionary keys must be strings")
            if _secret_bearing_name(key):
                raise CanonicalizationError("secret-bearing field name is not supported")
            normalized_mapping[key] = _normalize(item)
        return normalized_mapping
    if isinstance(value, tuple):
        return [_normalize(item) for item in value]
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    raise CanonicalizationError(f"unsupported canonical value: {type(value).__name__}")


def canonical_json(value: object) -> bytes:
    """Return the single deterministic ASCII JSON representation of ``value``."""

    normalized = _normalize(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def sha256_digest(value: object) -> str:
    """Return the lowercase SHA-256 digest of the canonical representation."""

    return hashlib.sha256(canonical_json(value)).hexdigest()


def decision_binding(
    request: DecisionRequest,
    contract_digests: tuple[str, ...],
) -> str:
    """Bind a complete decision request to contract digests in caller-supplied order."""

    if not isinstance(request, DecisionRequest):
        raise CanonicalizationError("request must be DecisionRequest")
    if not isinstance(contract_digests, tuple):
        raise CanonicalizationError("contract_digests must be a tuple")
    for digest in contract_digests:
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise CanonicalizationError(
                "contract digests must be lowercase SHA-256 values"
            )
    return sha256_digest(
        {
            "request": request,
            "contract_digests": contract_digests,
        }
    )
