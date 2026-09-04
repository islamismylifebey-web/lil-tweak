"""Durable scheduler for queued Tueiq Test World attempts."""

from __future__ import annotations

import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import nullcontext
from typing import Any

from .test_world import TestWorldConflict, TestWorldLease, TestWorldStore


class TestWorldScheduler:
    """Continuously generation-claims, heartbeats, and executes one attempt."""

    def __init__(
        self,
        store: TestWorldStore,
        runner: Any,
        *,
        worker_id: str,
        lease_seconds: int,
        poll_interval: float = 1.0,
        clock: Any = time.time,
        execution_guard: Any = None,
        executor: Any = None,
    ) -> None:
        if not worker_id or lease_seconds <= 0 or poll_interval <= 0:
            raise ValueError("invalid Test World scheduler configuration")
        self.store = store
        self.runner = runner
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds
        self.poll_interval = poll_interval
        self.clock = clock
        self.execution_guard = execution_guard
        self._executor = executor or ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="lil-tweak-test-world"
        )
        self._owns_executor = executor is None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._active_lock = threading.Lock()
        self._active = False

    @property
    def has_capacity(self) -> bool:
        with self._active_lock:
            return not self._active and not self._stop.is_set()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._loop,
            name="lil-tweak-test-world-scheduler",
            daemon=True,
        )
        self._thread.start()

    def notify(self, *_: Any) -> None:
        self._wake.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:
                # Durable state remains authoritative. A transient store/runtime
                # failure must not terminate future admission.
                pass
            self._wake.wait(self.poll_interval)
            self._wake.clear()

    def poll_once(self) -> int:
        now = self.clock()
        self.store.reconcile_active_attempts(now=now, limit=100)
        with self._active_lock:
            if self._active or self._stop.is_set():
                return 0
            attempts = self.store.list_schedulable_attempts(now=now, limit=1)
            if not attempts:
                return 0
            attempt = attempts[0]
            lease = self.store.claim_attempt(
                attempt.id,
                self.worker_id,
                lease_seconds=self.lease_seconds,
                now=now,
            )
            if lease is None:
                return 0
            self._active = True

        try:
            future = self._executor.submit(
                self._execute,
                attempt.id,
                attempt.owner_id,
                lease,
            )
        except Exception:
            self.store.release_attempt(lease)
            self._release_active()
            raise

        heartbeat_stop = threading.Event()
        future.add_done_callback(
            lambda _future, bound=lease, stopped=heartbeat_stop: self._finished(
                bound, stopped
            )
        )
        if not future.done():
            threading.Thread(
                target=self._heartbeat,
                args=(lease, future, heartbeat_stop),
                name=f"lil-tweak-test-world-lease-{attempt.id[-8:]}",
                daemon=True,
            ).start()
        return 1

    def _execute(self, attempt_id: str, owner_id: str, lease: TestWorldLease) -> Any:
        guard = self.execution_guard() if self.execution_guard is not None else nullcontext()
        with guard:
            return self.runner.run_attempt(attempt_id, owner_id, lease=lease)

    def _heartbeat(
        self,
        lease: TestWorldLease,
        future: Future[Any],
        stopped: threading.Event,
    ) -> None:
        interval = max(0.05, self.lease_seconds / 3)
        current = lease
        while not future.done() and not stopped.wait(interval):
            try:
                current = self.store.renew_attempt(
                    current,
                    lease_seconds=self.lease_seconds,
                    now=self.clock(),
                )
            except TestWorldConflict:
                return
            except Exception:
                # Retry while the last known generation remains valid. If the
                # lease is lost, generation fencing rejects stale completion.
                continue

    def _finished(self, lease: TestWorldLease, stopped: threading.Event) -> None:
        stopped.set()
        self.store.release_attempt(lease)
        self._release_active()
        self.notify()

    def _release_active(self) -> None:
        with self._active_lock:
            self._active = False

    def shutdown(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.poll_interval * 2))
            self._thread = None
        if self._owns_executor:
            self._executor.shutdown(wait=True, cancel_futures=False)
            self._owns_executor = False
