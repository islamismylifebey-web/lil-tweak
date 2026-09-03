"""Bounded, fail-open, read-only GALOR context adapter."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)


@dataclass(frozen=True, slots=True)
class GalorResult:
    context: dict[str, Any] | None
    error: str | None


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any,
                         newurl: str) -> None:
        del req, fp, code, msg, headers, newurl
        return None


def _safe_opener() -> Any:
    # Ignore ambient HTTP(S)_PROXY variables and never follow a response away
    # from the exact operator-configured read-only endpoint.
    return build_opener(ProxyHandler({}), _NoRedirectHandler())


def _sanitize(value: Any, *, depth: int = 0) -> Any:
    if depth > 4:
        return None
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:2048]
    if isinstance(value, list):
        return [_sanitize(item, depth=depth + 1) for item in value[:50]]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key in sorted(value)[:50]:
            if isinstance(key, str) and len(key) <= 100:
                result[key] = _sanitize(value[key], depth=depth + 1)
        return result
    return None


class GalorClient:
    MAX_RESPONSE_BYTES = 64 * 1024

    def __init__(self, base_url: str, *, opener: Any = None, timeout: float = 2.0):
        parsed = urlsplit(base_url)
        host = parsed.hostname
        if (
            not parsed.netloc
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or (parsed.path and not parsed.path.startswith("/"))
            or parsed.scheme != "https"
        ):
            raise ValueError("invalid GALOR URL")
        self.base_url = base_url
        self.opener = _safe_opener() if opener is None else opener
        self.timeout = min(max(float(timeout), 0.1), 2.0)

    def fetch(self, project_context: dict[str, Any]) -> GalorResult:
        project_id = project_context.get("projectId")
        if not isinstance(project_id, str) or not project_id:
            return GalorResult(None, None)
        try:
            parsed = urlsplit(self.base_url)
            query = urlencode({"projectId": project_id[:200]})
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))
            request = Request(
                url,
                method="GET",
                headers={"Accept": "application/json"},
            )
            open_request = getattr(self.opener, "open", self.opener)
            with open_request(request, timeout=self.timeout) as response:
                body = response.read(self.MAX_RESPONSE_BYTES + 1)
            if len(body) > self.MAX_RESPONSE_BYTES:
                raise ValueError("GALOR response too large")
            decoded = json.loads(body)
            context = _sanitize(decoded)
            if not isinstance(context, dict):
                raise ValueError("invalid GALOR response")
            return GalorResult(context, None)
        except Exception:
            return GalorResult(None, "galor_unavailable")
