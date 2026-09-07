"""The Bellows: explicit knowledge exchange between Forge and mastery systems."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .model import BellowsEvent, BellowsEventKind, Discovery, Novelty
from .vault import ForgeVault


@dataclass(frozen=True, slots=True)
class MasteryIntake:
    discovery_id: str
    mechanism_id: str
    name: str
    solution_summary: str
    evidence_ids: tuple[str, ...]


class MasterySink(Protocol):
    def accept_discovery(self, intake: MasteryIntake) -> str: ...


def discovery_to_mastery_intake(discovery: Discovery) -> MasteryIntake:
    verified = ", ".join(discovery.verified_applications)
    candidates = ", ".join(discovery.candidate_applications) if discovery.candidate_applications else "none"
    questions = " | ".join(discovery.questions)
    summary = (
        f"Mechanism: {discovery.mechanism.name}\n"
        f"Principle: {discovery.mechanism.principle}\n"
        f"Verified applications: {verified}\n"
        f"Candidate applications: {candidates}\n"
        f"Questions: {questions}\n"
        "Candidate applications are hypotheses and require Forge Crucible evidence before being treated as verified knowledge."
    )
    return MasteryIntake(
        discovery_id=discovery.discovery_id,
        mechanism_id=discovery.mechanism.mechanism_id,
        name=discovery.mechanism.name,
        solution_summary=summary,
        evidence_ids=discovery.evidence_ids,
    )


class Bellows:
    def __init__(self, vault: ForgeVault) -> None:
        self.vault = vault

    def publish_discovery(self, discovery: Discovery, sink: MasterySink) -> BellowsEvent:
        self.vault.store_discovery(discovery)
        intake = discovery_to_mastery_intake(discovery)
        receipt = sink.accept_discovery(intake)
        if not isinstance(receipt, str) or not receipt.strip():
            raise ValueError("mastery sink returned invalid receipt")
        event = BellowsEvent.create(
            kind=BellowsEventKind.FORGE_DISCOVERY,
            subject_id=discovery.discovery_id,
            evidence_ids=discovery.evidence_ids,
            payload=(("mastery_receipt", receipt.strip()), ("mechanism_id", discovery.mechanism.mechanism_id)),
        )
        self.vault.store_bellows_event(event)
        return event

    def receive_novelty(self, novelty: Novelty) -> BellowsEvent:
        event = BellowsEvent.create(
            kind=BellowsEventKind.NOVELTY_CANDIDATE,
            subject_id=novelty.novelty_id,
            evidence_ids=novelty.supporting_evidence_ids,
            payload=(("source", novelty.source), ("summary", novelty.summary)),
        )
        self.vault.store_bellows_event(event)
        return event
