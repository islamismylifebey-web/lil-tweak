"""Signed owner-only ASGI routes for durable Tueiq Test Worlds."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import parse_qs

from .api import ApiProblem, _headers, _json_body, _read_body
from .signing import AuthenticationError, ReplayError, verify_request
from .test_world import (
    TestCheck,
    TestWorld,
    TestWorldAttempt,
    TestWorldConflict,
    TestWorldLimitReached,
    TestWorldNotFound,
    TestWorldStore,
    valid_world_id,
)


TEST_WORLD_BODY_LIMIT = 64 * 1024
_WORLD_PATH = re.compile(r"^/v1/test-worlds/(world:[0-9a-f]{32})$")
_ATTEMPTS_PATH = re.compile(r"^/v1/test-worlds/(world:[0-9a-f]{32})/attempts$")
_OWNER_SCOPE = re.compile(r"^[0-9a-f]{32}$")


def _attempt_json(attempt: TestWorldAttempt) -> dict[str, Any]:
    return {
        "id": attempt.id,
        "worldId": attempt.world_id,
        "worldFingerprint": attempt.world_fingerprint,
        "judgeVersion": attempt.judge_version,
        "number": attempt.number,
        "status": attempt.status.value,
        "outcome": attempt.outcome,
        "previousAttemptId": attempt.previous_attempt_id,
        "feedback": [dict(item) for item in attempt.feedback],
        "plan": attempt.plan,
        "summary": attempt.summary,
        "tests": attempt.tests,
        "usage": {
            "modelCalls": attempt.model_calls,
            "inputTokens": attempt.input_tokens,
            "outputTokens": attempt.output_tokens,
            "totalTokens": attempt.total_tokens,
        },
        "execution": {
            "durationMs": attempt.duration_ms,
            "judgeDurationMs": attempt.judge_duration_ms,
            "checksRun": len(attempt.feedback),
        },
        "createdAt": attempt.created_at,
        "startedAt": attempt.started_at,
        "finishedAt": attempt.finished_at,
    }


def _world_json(world: TestWorld, attempts: list[TestWorldAttempt]) -> dict[str, Any]:
    return {
        "id": world.id,
        "name": world.name,
        "objective": world.objective,
        "status": world.status.value,
        "fingerprint": world.fingerprint,
        "judgeVersion": world.judge_version,
        "source": {
            "kind": "git",
            "repositoryUrl": world.repository_url,
            "commit": world.commit,
        },
        "checks": [
            {
                "name": item.name,
                "command": list(item.command),
                "timeoutSeconds": item.timeout_seconds,
            }
            for item in world.checks
        ],
        "maxAttempts": world.max_attempts,
        "attemptCount": len(attempts),
        "attempts": [_attempt_json(item) for item in attempts],
        "createdAt": world.created_at,
        "updatedAt": world.updated_at,
    }


def _summary_json(world: TestWorld, attempt_count: int) -> dict[str, Any]:
    return {
        "id": world.id,
        "name": world.name,
        "objective": world.objective,
        "status": world.status.value,
        "fingerprint": world.fingerprint,
        "judgeVersion": world.judge_version,
        "source": {
            "kind": "git",
            "repositoryUrl": world.repository_url,
            "commit": world.commit,
        },
        "maxAttempts": world.max_attempts,
        "attemptCount": attempt_count,
        "createdAt": world.created_at,
        "updatedAt": world.updated_at,
    }


def _parse_checks(value: Any) -> tuple[TestCheck, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 8:
        raise ApiProblem(400, "invalid_request")
    result: list[TestCheck] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"name", "command", "timeoutSeconds"}:
            raise ApiProblem(400, "invalid_request")
        name = item["name"]
        command = item["command"]
        timeout_seconds = item["timeoutSeconds"]
        if not isinstance(command, list):
            raise ApiProblem(400, "invalid_request")
        try:
            result.append(TestCheck(name, tuple(command), timeout_seconds))
        except (TypeError, ValueError):
            raise ApiProblem(400, "invalid_request") from None
    return tuple(result)


def _list_limit(query: str) -> int:
    try:
        parsed = parse_qs(query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise ApiProblem(400, "invalid_request") from None
    if set(parsed) - {"limit"} or any(len(values) != 1 for values in parsed.values()):
        raise ApiProblem(400, "invalid_request")
    values = parsed.get("limit")
    if values is None:
        return 20
    try:
        limit = int(values[0], 10)
    except (TypeError, ValueError):
        raise ApiProblem(400, "invalid_request") from None
    if str(limit) != values[0] or not 1 <= limit <= 100:
        raise ApiProblem(400, "invalid_request")
    return limit


class TestWorldApi:
    """Route Test World calls while delegating every other request unchanged."""

    def __init__(
        self,
        *,
        fallback: Any,
        nonce_store: Any,
        world_store: TestWorldStore,
        signing_keys: Mapping[str, bytes | str],
        canonical_owner_id: str,
        clock: Callable[[], float] = time.time,
        on_attempt_queued: Callable[[str, str], None] | None = None,
    ) -> None:
        if (
            not callable(fallback)
            or not signing_keys
            or not isinstance(canonical_owner_id, str)
            or _OWNER_SCOPE.fullmatch(canonical_owner_id) is None
        ):
            raise ValueError("fallback, signing keys, and canonical owner are required")
        if not callable(getattr(nonce_store, "consume_nonce", None)):
            raise ValueError("nonce store must support replay protection")
        self.fallback = fallback
        self.nonce_store = nonce_store
        self.world_store = world_store
        self.signing_keys = dict(signing_keys)
        self.canonical_owner_id = canonical_owner_id
        self.clock = clock
        self.on_attempt_queued = on_attempt_queued

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.fallback(scope, receive, send)
            return
        path = str(scope.get("path", ""))
        if path != "/v1/test-worlds" and _WORLD_PATH.fullmatch(path) is None and _ATTEMPTS_PATH.fullmatch(path) is None:
            await self.fallback(scope, receive, send)
            return
        try:
            method = str(scope.get("method", "")).upper()
            query = bytes(scope.get("query_string", b"")).decode("ascii", "strict")
            target = path + (f"?{query}" if query else "")
            headers = _headers(scope)
            body = await _read_body(receive, TEST_WORLD_BODY_LIMIT)
            owner_id, idempotency_key = self._authenticate(
                method,
                target,
                body,
                headers,
                mutation=method in {"POST", "PUT", "PATCH", "DELETE"},
            )

            if path == "/v1/test-worlds":
                if method == "POST":
                    await self._create_world(send, owner_id, idempotency_key, body, query)
                    return
                if method == "GET":
                    if body:
                        raise ApiProblem(400, "invalid_request")
                    limit = _list_limit(query)
                    worlds = self.world_store.list_worlds(owner_id, limit=limit)
                    payload = {
                        "worlds": [
                            _summary_json(world, len(self.world_store.list_attempts(world.id, owner_id)))
                            for world in worlds
                        ]
                    }
                    await self._respond(send, 200, payload)
                    return
                raise ApiProblem(405, "method_not_allowed")

            world_match = _WORLD_PATH.fullmatch(path)
            if world_match is not None:
                if method != "GET" or query or body:
                    raise ApiProblem(405 if method != "GET" else 400, "method_not_allowed" if method != "GET" else "invalid_request")
                world = self.world_store.get_world(world_match.group(1), owner_id)
                if world is None:
                    raise ApiProblem(404, "world_not_found")
                attempts = self.world_store.list_attempts(world.id, owner_id)
                await self._respond(send, 200, _world_json(world, attempts))
                return

            attempt_match = _ATTEMPTS_PATH.fullmatch(path)
            if attempt_match is not None:
                if method != "POST" or query:
                    raise ApiProblem(405 if method != "POST" else 400, "method_not_allowed" if method != "POST" else "invalid_request")
                payload = _json_body(body)
                if payload:
                    raise ApiProblem(400, "invalid_request")
                world_id = attempt_match.group(1)
                if not valid_world_id(world_id):
                    raise ApiProblem(404, "world_not_found")
                try:
                    attempt = self.world_store.enqueue_attempt(
                        world_id,
                        owner_id,
                        idempotency_key=idempotency_key,
                    )
                except TestWorldNotFound:
                    raise ApiProblem(404, "world_not_found") from None
                except TestWorldLimitReached:
                    raise ApiProblem(409, "attempt_limit_reached") from None
                except TestWorldConflict:
                    raise ApiProblem(409, "world_conflict") from None
                if self.on_attempt_queued is not None:
                    self.on_attempt_queued(attempt.id, owner_id)
                await self._respond(send, 202, _attempt_json(attempt))
                return

            raise ApiProblem(404, "not_found")
        except ApiProblem as problem:
            await self._respond(send, problem.status, {"error": {"code": problem.code}})
        except (UnicodeError, ValueError):
            await self._respond(send, 400, {"error": {"code": "invalid_request"}})
        except Exception:
            await self._respond(send, 500, {"error": {"code": "internal_error"}})

    async def _create_world(
        self,
        send: Any,
        owner_id: str,
        idempotency_key: str,
        body: bytes,
        query: str,
    ) -> None:
        if query:
            raise ApiProblem(400, "invalid_request")
        payload = _json_body(body)
        allowed = {"name", "objective", "repositoryUrl", "commit", "checks", "maxAttempts"}
        if set(payload) != allowed:
            raise ApiProblem(400, "invalid_request")
        checks = _parse_checks(payload["checks"])
        try:
            world = self.world_store.create_world(
                owner_id,
                idempotency_key=idempotency_key,
                name=payload["name"],
                objective=payload["objective"],
                repository_url=payload["repositoryUrl"],
                commit=payload["commit"],
                checks=checks,
                max_attempts=payload["maxAttempts"],
            )
        except TestWorldConflict:
            raise ApiProblem(409, "idempotency_conflict") from None
        attempts = self.world_store.list_attempts(world.id, owner_id)
        await self._respond(send, 201, _world_json(world, attempts))

    def _authenticate(
        self,
        method: str,
        target: str,
        body: bytes,
        headers: Mapping[str, str],
        *,
        mutation: bool,
    ) -> tuple[str, str]:
        key_id = headers.get("x-lil-tweak-key-id", "")
        supplied_owner = headers.get("x-lil-tweak-owner")
        signed_owner = supplied_owner or self.canonical_owner_id
        idempotency_key = headers.get("idempotency-key", "")
        try:
            verify_request(
                key_id=key_id,
                signature=headers.get("x-lil-tweak-signature", ""),
                body=body,
                keys=self.signing_keys,
                consume_nonce=self.nonce_store.consume_nonce,
                now=self.clock(),
                method=method,
                path_and_query=target,
                timestamp=headers.get("x-lil-tweak-timestamp", ""),
                nonce=headers.get("x-lil-tweak-nonce", ""),
                body_sha256=headers.get("x-lil-tweak-body-sha256", ""),
                request_id=headers.get("x-lil-tweak-request-id", ""),
                idempotency_key=idempotency_key,
                owner_id=signed_owner,
            )
        except AuthenticationError:
            raise ApiProblem(401, "authentication_failed") from None
        except ReplayError:
            raise ApiProblem(409, "request_replayed") from None
        if supplied_owner is not None and supplied_owner != self.canonical_owner_id:
            raise ApiProblem(403, "owner_forbidden")
        if mutation and (not idempotency_key or len(idempotency_key.encode("utf-8")) > 200):
            raise ApiProblem(400, "invalid_idempotency_key")
        return self.canonical_owner_id, idempotency_key

    @staticmethod
    async def _respond(send: Any, status: int, payload: Mapping[str, Any]) -> None:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json; charset=utf-8"),
                    (b"cache-control", b"no-store"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
