"""Opt-in recovery evidence bridge for the current engineering orchestrator."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..orchestrator import EngineeringOrchestrator
from ..store import Job, JobLease, JobNotFound, JobStore
from .contracts import RecoveryContext, RecoveryDecision
from .controller import FailureRecoveryController


_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


class _RecoveryCapturingAgent:
    def __init__(
        self,
        delegate: Any,
        controller: FailureRecoveryController,
        context: RecoveryContext,
    ) -> None:
        self._delegate = delegate
        self._controller = controller
        self._context = context
        self.decision: RecoveryDecision | None = None
        self.recovery_unavailable = False

    @property
    def tools(self) -> Any:
        return getattr(self._delegate, "tools", None)

    def run(self, **kwargs: Any) -> Any:
        try:
            return self._delegate.run(**kwargs)
        except Exception as error:
            try:
                self.decision = self._controller.decide(
                    self._controller.signal_from_exception(error), self._context
                )
            except Exception:
                self.recovery_unavailable = True
            raise


class RecoveryAwareEngineeringOrchestrator:
    """Drop-in orchestrator adapter that records, but never executes, recovery."""

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
        galor: Any = None,
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
        self.galor = galor
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
        job = self.store.get_job(job_id, owner_id)
        if job is None:
            raise JobNotFound("job not found")
        context = self._context(job)
        capturing_agent = _RecoveryCapturingAgent(
            self.agent, self.recovery_controller, context
        )
        kwargs: dict[str, Any] = {
            "store": self.store,
            "agent": capturing_agent,
            "evidence_store": self.evidence_store,
            "job_timeout_seconds": self.job_timeout_seconds,
            "galor": self.galor,
            "lease": self.lease,
            "lease_seconds": self.lease_seconds,
        }
        if self.clock is not None:
            kwargs["clock"] = self.clock
        if self.monotonic is not None:
            kwargs["monotonic"] = self.monotonic
        result = EngineeringOrchestrator(**kwargs).run_job(
            job_id,
            owner_id,
            source_inventory=source_inventory,
            workspace=workspace,
        )
        self.last_recovery_decision = capturing_agent.decision
        self.recovery_unavailable = capturing_agent.recovery_unavailable
        return result

    def _context(self, job: Job) -> RecoveryContext:
        source_revision = None
        if job.git_source is not None and _REVISION.fullmatch(job.git_source.commit):
            source_revision = job.git_source.commit
        elif job.source_digest is not None and _REVISION.fullmatch(job.source_digest):
            source_revision = job.source_digest
        attempt = self.lease.generation if self.lease is not None else max(1, job.revision + 1)
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
            approval_present=job.approval_consumed or bool(job.approval_proposal),
        )
