from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Mapping
from typing import Protocol

from .execution import ExecutionResult
from .offer import VerifiedOffer, verify_offer
from .protocol import canonical_json


class RunnerClient(Protocol):
    def poll(self) -> Mapping[str, object] | None: ...

    def claim(self, *, execution_id: str, attempt_nonce: str) -> Mapping[str, object]: ...

    def status(self, *, execution_id: str) -> Mapping[str, object]: ...

    def submit_evidence(
        self,
        *,
        execution_id: str,
        attempt_nonce: str,
        evidence: dict[str, object],
    ) -> Mapping[str, object]: ...


class JobExecutor(Protocol):
    def execute(
        self,
        offer: VerifiedOffer,
        *,
        cancellation_requested: Callable[[], bool],
    ) -> ExecutionResult: ...


class RunnerService:
    def __init__(
        self,
        *,
        client: RunnerClient,
        executor: JobExecutor,
        controller_key_id: str,
        controller_public_key: bytes,
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        self._client = client
        self._executor = executor
        self._controller_key_id = controller_key_id
        self._controller_public_key = controller_public_key
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)

    def _cancellation_check(self, execution_id: str) -> bool:
        status = self._client.status(execution_id=execution_id)
        state = status.get("status")
        if state == "CANCEL_REQUESTED":
            return True
        if state != "CLAIMED":
            raise RuntimeError("execution is no longer in an executable state")
        return False

    @staticmethod
    def _evidence(offer: VerifiedOffer, result: ExecutionResult) -> dict[str, object]:
        if not 0 <= result.exit_code <= 255:
            raise RuntimeError("executor returned an invalid exit code")
        if result.started_at_ms > result.finished_at_ms:
            raise RuntimeError("executor returned invalid timestamps")
        return {
            "schema_version": "lil-tweak.runner-evidence/v1",
            "outcome": result.outcome,
            "operation_digest": offer.commands_digest,
            "stdout_digest": hashlib.sha256(result.stdout).hexdigest(),
            "stderr_digest": hashlib.sha256(result.stderr).hexdigest(),
            "receipt_digest": hashlib.sha256(
                canonical_json(dict(result.receipt)).encode("utf-8")
            ).hexdigest(),
            "exit_code": result.exit_code,
            "started_at_ms": result.started_at_ms,
            "finished_at_ms": result.finished_at_ms,
        }

    def run_once(self) -> bool:
        candidate = self._client.poll()
        if candidate is None:
            return False
        offer = verify_offer(
            candidate,
            expected_key_id=self._controller_key_id,
            controller_public_key=self._controller_public_key,
            now_ms=self._clock_ms(),
        )
        self._client.claim(
            execution_id=offer.execution_id,
            attempt_nonce=offer.attempt_nonce,
        )
        if self._cancellation_check(offer.execution_id):
            now = self._clock_ms()
            result = ExecutionResult(
                outcome="cancelled",
                exit_code=0,
                stdout=b"",
                stderr=b"",
                receipt={"cancelled_before_execution": True},
                started_at_ms=now,
                finished_at_ms=now,
            )
        else:
            result = self._executor.execute(
                offer,
                cancellation_requested=lambda: self._cancellation_check(offer.execution_id),
            )
        self._client.submit_evidence(
            execution_id=offer.execution_id,
            attempt_nonce=offer.attempt_nonce,
            evidence=self._evidence(offer, result),
        )
        return True
