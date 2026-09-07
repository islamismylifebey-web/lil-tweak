from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

ASGIApp = Callable[[dict[str, Any], Callable[[], Awaitable[dict[str, Any]]], Callable[[dict[str, Any]], Awaitable[None]]], Awaitable[None]]

_PROTECTED_DEPLOYMENT = re.compile(
    r"^lil-tweak-[a-z0-9]+-galor-web-works\.vercel\.app$"
)
_SESSION_COOKIE = b"liltweak_owner_session="


def _host(value: str | None) -> str:
    if not value:
        return ""
    candidate = value.strip().lower()
    if "://" in candidate:
        candidate = urlsplit(candidate).hostname or ""
    if candidate.startswith("["):
        return candidate
    return candidate.split(":", 1)[0]


def trusted_vercel_deployment_host(
    request_host: str | None,
    deployment_host: str | None,
) -> bool:
    observed = _host(request_host)
    deployed = _host(deployment_host)
    return bool(
        observed
        and observed == deployed
        and _PROTECTED_DEPLOYMENT.fullmatch(observed)
    )


def _header_map(headers: list[tuple[bytes, bytes]]) -> dict[bytes, bytes]:
    return {name.lower(): value for name, value in headers}


def _replace_header(
    headers: list[tuple[bytes, bytes]], name: bytes, value: bytes | None
) -> list[tuple[bytes, bytes]]:
    lowered = name.lower()
    result = [(key, item) for key, item in headers if key.lower() != lowered]
    if value is not None:
        result.append((lowered, value))
    return result


class VercelOwnerBoundary:
    """Translate Vercel's SSO-protected deployment host into Tweak's local owner boundary."""

    def __init__(self, app: ASGIApp, *, owner_key: str, deployment_host: str | None) -> None:
        if not owner_key:
            raise ValueError("owner key is required")
        self.app = app
        self.owner_key = owner_key
        self.deployment_host = deployment_host

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = list(scope.get("headers", []))
        mapped = _header_map(headers)
        request_host = mapped.get(b"host", b"").decode("latin-1")
        if not trusted_vercel_deployment_host(request_host, self.deployment_host):
            await self.app(scope, receive, send)
            return

        internal = dict(scope)
        internal_headers = _replace_header(headers, b"host", b"127.0.0.1")
        origin = mapped.get(b"origin")
        expected_origin = f"https://{_host(self.deployment_host)}".encode("ascii")
        if origin is not None and origin.rstrip(b"/").lower() == expected_origin:
            internal_headers = _replace_header(internal_headers, b"origin", b"https://127.0.0.1")
        internal["headers"] = internal_headers

        cookie = mapped.get(b"cookie", b"")
        if (
            scope.get("method") == "GET"
            and scope.get("path") == "/v1/workbench/session"
            and _SESSION_COOKIE not in cookie
        ):
            await self._establish_owner_session(internal, send)
            return
        await self.app(internal, receive, send)

    async def _establish_owner_session(self, scope: dict[str, Any], send: Any) -> None:
        body = json.dumps({"owner_key": self.owner_key}, separators=(",", ":")).encode()
        internal = dict(scope)
        internal["method"] = "POST"
        headers = list(internal.get("headers", []))
        headers = _replace_header(headers, b"content-type", b"application/json")
        headers = _replace_header(headers, b"content-length", str(len(body)).encode("ascii"))
        internal["headers"] = headers
        delivered = False

        async def receive() -> dict[str, Any]:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(internal, receive, send)
