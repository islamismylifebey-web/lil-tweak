"""Canonical request signing and verification for the private service protocol."""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from collections.abc import Callable, Mapping
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit


_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AuthenticationError(ValueError):
    """An intentionally detail-free authentication failure."""

    code = "authentication_failed"

    def __init__(self) -> None:
        super().__init__("authentication failed")


class ReplayError(ValueError):
    code = "request_replayed"

    def __init__(self) -> None:
        super().__init__("request replayed")


def _canonical_target(path_and_query: str) -> str:
    if not path_and_query.startswith("/") or "\n" in path_and_query or "\r" in path_and_query:
        raise ValueError("invalid request target")
    parsed = urlsplit(path_and_query)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise ValueError("invalid request target")
    pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=False)
    pairs.sort(key=lambda pair: (pair[0], pair[1]))
    query = "&".join(
        f"{quote(key, safe='~-._')}={quote(value, safe='~-._')}" for key, value in pairs
    )
    return urlunsplit(("", "", parsed.path or "/", query, ""))


def _field(value: object, label: str) -> str:
    rendered = str(value)
    if not rendered or "\n" in rendered or "\r" in rendered:
        raise ValueError(f"invalid {label}")
    return rendered


def _optional_field(value: object, label: str) -> str:
    rendered = str(value)
    if "\n" in rendered or "\r" in rendered:
        raise ValueError(f"invalid {label}")
    return rendered


def canonical_request(
    *,
    key_id: str,
    method: str,
    path_and_query: str,
    timestamp: str | int,
    nonce: str,
    body_sha256: str,
    request_id: str,
    idempotency_key: str,
    owner_id: str,
) -> str:
    """Return the exact v2 canonical signing message."""

    key_value = _field(key_id, "key id")
    method_value = _field(method, "method").upper()
    timestamp_value = _field(timestamp, "timestamp")
    nonce_value = _field(nonce, "nonce")
    digest_value = _field(body_sha256, "body digest").lower()
    request_value = _field(request_id, "request id")
    idempotency_value = _optional_field(idempotency_key, "idempotency key")
    owner_value = _field(owner_id, "owner id")
    if not _HEX_SHA256.fullmatch(digest_value):
        raise ValueError("invalid body digest")
    return "\n".join(
        (
            "v2",
            key_value,
            method_value,
            _canonical_target(path_and_query),
            timestamp_value,
            nonce_value,
            digest_value,
            request_value,
            idempotency_value,
            owner_value,
        )
    )


def sign_request(secret: bytes | str, **fields: object) -> str:
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    if not key:
        raise ValueError("signing key is empty")
    message = canonical_request(**fields).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_request(
    *,
    key_id: str,
    signature: str,
    body: bytes,
    keys: Mapping[str, bytes | str],
    consume_nonce: Callable[[str, str, int], bool],
    now: int | float | None = None,
    max_clock_skew: int = 300,
    **fields: object,
) -> bool:
    """Verify request bytes and atomically consume the authenticated nonce.

    The replay hook must return true only when it inserted a previously unseen
    ``(key_id, nonce)`` tuple. It runs after all authentication checks so forged
    traffic cannot consume legitimate nonce values.
    """

    try:
        timestamp = int(str(fields["timestamp"]))
        supplied_digest = str(fields["body_sha256"]).lower()
        actual_digest = hashlib.sha256(body).hexdigest()
        key = keys[key_id]
        expected = sign_request(key, key_id=key_id, **fields)
        current = int(time.time() if now is None else now)
        valid = (
            max_clock_skew >= 0
            and abs(current - timestamp) <= max_clock_skew
            and hmac.compare_digest(actual_digest, supplied_digest)
            and hmac.compare_digest(expected, signature.lower())
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        raise AuthenticationError() from None
    if not valid:
        raise AuthenticationError()
    nonce = str(fields["nonce"])
    if not consume_nonce(key_id, nonce, timestamp):
        raise ReplayError()
    return True
