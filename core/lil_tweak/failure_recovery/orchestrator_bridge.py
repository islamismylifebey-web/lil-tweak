"""Opt-in recovery evidence bridge for the current engineering orchestrator."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..contracts import JobState
from ..orchestrator import EngineeringOrchestrator
from ..store import Job, JobLease, JobNotFound, JobStore
from .contracts import FailureCode, FailureSignal, RecoveryContext, RecoveryDecision
from .controller import FailureRecoveryController


_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class _FailureObservingAgent:
    """Observe one model failure without deciding recovery before source binding."""

    def __init__(self, delegate: Any) -> None:
        self._delegate = delegate
        self.error: Exception | None = None

    @property
    def tools(self) -> Any:
        return getattr(self._delegate, "tools", None)

    def run(self, **kwargs: Any) -> Any:
        try:
            return self._delegate.run(**kwargs)
        except Exception as error:
            self.error = error
            raise


class RecoveryAwareEngineeringOrchestrator:
    """Record recovery decisions after authoritative orchestration has settled."""

    def __init__(
        self,
        *,
        store: JobStore,
        agent: Any,
        evidence_store: Any,
        recovery_controller: FailureRecoveryController,
        clock: Any = None,
        monotonic: Any = None,
        job_timeout_seconds: int = 20 * 60,
        lease: JobLease | None = None,
        lease_seconds: int = 60,
    ) -> None:
        self.store = store
        self.agent = agent
        self.evidence_store = evidence_store
        self.recovery_controller = recovery_controller
        self.clock = clock
        self.monotonic = monotonic
        self.job_timeout_seconds = job_timeout_seconds
        self.lease = lease
        self.lease_seconds = lease_seconds
        self.last_recovery_decision: RecoveryDecision | None = None
        self.recovery_unavailable = False

    def run_job(
        self,
        job_id: str,
        owner_id: str,
        *,
        source_inventory: tuple[str, ...] = (),
        workspace: str | Path | None = None,
    ) -> Job:
        initial = self.store.get_job(job_id, owner_id)
        if initial is None:
            raise JobNotFound("job not found")
        self.last_recovery_decision = None
        self.recovery_unavailable = False
        observing_agent = _FailureObservingAgent(self.agent)
        kwargs: dict[str, Any] = {
            "store": self.store,
            "agent": observing_agent,
            "evidence_store": self.evidence_store,
            "job_timeout_seconds": self.job_timeout_seconds,
            "lease": self.lease,
            "lease_seconds": self.lease_seconds,
        }
        if self.clock is not None:
            kwargs["clock"] = self.clock
        if self.monotonic is not None:
            kwargs["monotonic"] = self.monotonic
        orchestrator = EngineeringOrchestrator(**kwargs)
        try:
            result = orchestrator.run_job(
                job_id,
                owner_id,
                source_inventory=source_inventory,
                workspace=workspace,
            )
        except Exception as error:
            latest = self.store.get_job(job_id, owner_id) or initial
            self._record_error(error, latest)
            raise

        if result.state is JobState.TIMED_OUT:
            if observing_agent.error is not None:
                self._record_error(observing_agent.error, result)
            else:
                self._record_signal(
                    FailureSignal(
                        code=FailureCode.TIMEOUT,
                        exception_type="ObservedCommandTimeout",
                        failed_checks=("command_timeout",),
                        transient=True,
                    ),
                    result,
                )
        elif result.state is JobState.FAILED:
            if observing_agent.error is not None:
                self._record_error(observing_agent.error, result)
            else:
                self._record_signal(
                    FailureSignal(
                        code=FailureCode.UNKNOWN_FAILURE,
                        exception_type="OrchestratorTerminalFailure",
                    ),
                    result,
                )
        return result

    def _record_error(self, error: BaseException, job: Job) -> None:
        try:
            signal = self.recovery_controller.signal_from_exception(error)
        except Exception:
            self.last_recovery_decision = None
            self.recovery_unavailable = True
            return
        self._record_signal(signal, job)

    def _record_signal(self, signal: FailureSignal, job: Job) -> None:
        try:
            self.last_recovery_decision = self.recovery_controller.decide(
                signal, self._context(job)
            )
        except Exception:
            self.last_recovery_decision = None
            self.recovery_unavailable = True

    def _context(self, job: Job) -> RecoveryContext:
        source_revision = None
        if job.source_digest is not None and _REVISION.fullmatch(job.source_digest):
            source_revision = job.source_digest
        elif job.git_source is not None and _REVISION.fullmatch(job.git_source.commit):
            source_revision = job.git_source.commit
        attempt = self.lease.generation if self.lease is not None else 1
        lease_id = None
        if self.lease is not None:
            lease_id = f"{self.lease.worker_id}:{self.lease.generation}"
        return RecoveryContext(
            owner_id=job.owner_id,
            task_id=job.id,
            dag_run_id=f"job:{job.id}",
            node_id="executing",
            source_revision=source_revision,
            attempt=attempt,
            plan_digest=job.proposal_digest,
            execution_id=job.id,
            lease_id=lease_id,
            resource_id="current-runner",
            approval_present=job.approval_consumed,
        )
