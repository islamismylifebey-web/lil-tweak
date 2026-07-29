from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from liltweak.agent import DeterministicPlanner
from liltweak.costs import CostGuard
from liltweak.evidence import EvidenceChainError
from liltweak.models import TaskCreate
from liltweak.service import LilTweakService
from liltweak.store import SQLiteStore


def test_evidence_payload_tampering_is_detected(tmp_path: Path) -> None:
    database = tmp_path / "evidence.db"
    service = LilTweakService(
        store=SQLiteStore(database),
        planner=DeterministicPlanner(),
        cost_guard=CostGuard(monthly_limit_usd=250, job_default_limit_usd=5),
        evidence_signing_key=b"evidence-test-signing-key-000000",
    )
    job = service.create_job(
        TaskCreate(
            task_id="evidence-test",
            requested_by="owner",
            organization_id="owner",
            project_id="lil-tweak",
            objective="Prepare a plan.",
        ),
        "evidence-idempotency-0001",
    )
    assert service.evidence.verify(job.id)

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE evidence SET payload_json = ? WHERE job_id = ? AND sequence = 1",
            ('{"tampered":true}', job.id),
        )
        connection.commit()

    with pytest.raises(EvidenceChainError):
        service.evidence.verify(job.id)


def test_evidence_tail_deletion_and_empty_chain_are_detected(tmp_path: Path) -> None:
    database = tmp_path / "evidence-tail.db"
    service = LilTweakService(
        store=SQLiteStore(database),
        planner=DeterministicPlanner(),
        cost_guard=CostGuard(monthly_limit_usd=250, job_default_limit_usd=5),
        evidence_signing_key=b"evidence-test-signing-key-000000",
    )
    job = service.create_job(
        TaskCreate(
            task_id="evidence-tail-test",
            requested_by="owner",
            organization_id="owner",
            project_id="lil-tweak",
            objective="Prepare a plan.",
        ),
        "evidence-tail-idempotency-0001",
    )
    service.evidence.append(job.id, "second_event", {"safe": True})

    with sqlite3.connect(database) as connection:
        connection.execute(
            "DELETE FROM evidence WHERE job_id = ? AND sequence = 2",
            (job.id,),
        )
        connection.commit()
    with pytest.raises(EvidenceChainError, match="anchor"):
        service.evidence.verify(job.id)

    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM evidence WHERE job_id = ?", (job.id,))
        connection.execute("DELETE FROM evidence_anchors WHERE job_id = ?", (job.id,))
        connection.commit()
    with pytest.raises(EvidenceChainError, match="missing"):
        service.evidence.verify(job.id)
