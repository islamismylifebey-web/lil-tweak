from __future__ import annotations

import json
import secrets
import time
from collections.abc import Callable, Mapping
from typing import cast

import httpx

from .config import RunnerCredentials
from .protocol import Operation, canonical_json, sign_runner_request

MAX_RESPONSE_BYTES = 128_000


class ControlPlaneError(RuntimeError):
    """Fail closed when the bounded control plane rejects or malforms a request."""


class ControlPlaneClient:
    def __init__(
        self,
        credentials: RunnerCredentials,
        *,
        transport: httpx.BaseTransport | None = None,
        clock_ms: Callable[[], int] | None = None,
        nonce: Callable[[], bytes] | None = None,
    ) -> None:
        self._credentials = credentials
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)
        self._nonce = nonce or (lambda: secrets.token_bytes(32))
        self._client = httpx.Client(
            base_url=credentials.control_plane_url,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {credentials.runner_bearer_token}",
                "CF-Access-Client-Id": credentials.cf_access_client_id,
                "CF-Access-Client-Secret": credentials.cf_access_client_secret,
            },
            follow_redirects=False,
            timeout=httpx.Timeout(15.0),
            transport=transport,
            trust_env=False,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> ControlPlaneClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _request(
        self,
        operation: Operation,
        path: str,
        payload: Mapping[str, object],
    ) -> httpx.Response:
        envelope = sign_runner_request(
            operation=operation,
            payload=payload,
            private_key=self._credentials.runner_private_key,
            issued_at_ms=self._clock_ms(),
            request_nonce=self._nonce(),
        )
        return self._client.post(path, content=canonical_json(envelope).encode("utf-8"))

    @staticmethod
    def _json_object(response: httpx.Response, label: str) -> Mapping[str, object]:
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise ControlPlaneError(f"{label} response exceeded its limit")
        try:
            value = json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ControlPlaneError(f"{label} response is not valid JSON") from exc
        if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
            raise ControlPlaneError(f"{label} response is not an object")
        return cast(Mapping[str, object], value)

    def poll(self) -> Mapping[str, object] | None:
        response = self._request("poll", "/v1/runners/galor-tweak-runner-01/next", {})
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise ControlPlaneError("poll rejected by the control plane")
        return self._json_object(response, "poll")

    def claim(self, *, execution_id: str, attempt_nonce: str) -> Mapping[str, object]:
        response = self._request(
            "claim",
            "/v1/runners/galor-tweak-runner-01/claim",
            {"execution_id": execution_id, "attempt_nonce": attempt_nonce},
        )
        if response.status_code != 200:
            raise ControlPlaneError("claim rejected by the control plane")
        value = self._json_object(response, "claim")
        if value.get("execution_id") != execution_id or value.get("status") != "CLAIMED":
            raise ControlPlaneError("claim response is not bound to the execution")
        return value

    def status(self, *, execution_id: str) -> Mapping[str, object]:
        response = self._request(
            "status",
            "/v1/runners/galor-tweak-runner-01/status",
            {"execution_id": execution_id},
        )
        if response.status_code != 200:
            raise ControlPlaneError("status rejected by the control plane")
        value = self._json_object(response, "status")
        if value.get("execution_id") != execution_id:
            raise ControlPlaneError("status response is not bound to the execution")
        return value

    def submit_evidence(
        self,
        *,
        execution_id: str,
        attempt_nonce: str,
        evidence: Mapping[str, object],
    ) -> Mapping[str, object]:
        response = self._request(
            "evidence",
            "/v1/runners/galor-tweak-runner-01/evidence",
            {
                "execution_id": execution_id,
                "attempt_nonce": attempt_nonce,
                "evidence": dict(evidence),
            },
        )
        if response.status_code != 202:
            raise ControlPlaneError("evidence rejected by the control plane")
        value = self._json_object(response, "evidence")
        if value.get("execution_id") != execution_id or value.get("status") != "EVIDENCE_RECORDED":
            raise ControlPlaneError("evidence receipt is not bound to the execution")
        return value
