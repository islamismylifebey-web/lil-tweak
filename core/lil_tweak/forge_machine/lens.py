"""The Lens: generalize proven mechanisms without confusing hypotheses for facts."""
from __future__ import annotations

from .model import Discovery, Mechanism

SECONDARY_USE_QUESTION = "What else can the mechanism inside this Piece do?"


def secondary_use_questions(mechanism: Mechanism) -> tuple[str, ...]:
    return (
        SECONDARY_USE_QUESTION,
        "Which assumptions belong only to the original project and can be removed?",
        "What other problems share this mechanism's structural shape?",
        "Where does this mechanism stop working or become a poor fit?",
        "What new capability appears if this mechanism is combined with another proven mechanism?",
        f"Which other domain exhibits: {', '.join(mechanism.structural_signature)}?",
    )


def build_discovery(
    *,
    mechanism: Mechanism,
    origin_piece_hash: str,
    verified_applications: tuple[str, ...],
    candidate_applications: tuple[str, ...],
    evidence_ids: tuple[str, ...],
) -> Discovery:
    return Discovery.create(
        mechanism=mechanism,
        origin_piece_hash=origin_piece_hash,
        verified_applications=verified_applications,
        candidate_applications=candidate_applications,
        questions=secondary_use_questions(mechanism),
        evidence_ids=evidence_ids,
    )
