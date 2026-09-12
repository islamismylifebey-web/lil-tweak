"""Evidence-governed Piece registration and maturity promotion."""
from __future__ import annotations

from .model import EvidenceBundle, ForgePromotionBlocked, Maturity, PieceArtifact
from .vault import ForgeVault

_TEMPERED_GATES = ("contract_compliance", "correctness", "security", "reproducibility")
_ORDER = {
    Maturity.RAW: 0,
    Maturity.CANDIDATE: 1,
    Maturity.TEMPERED: 2,
    Maturity.PROVEN: 3,
    Maturity.RELIC: 4,
}


def _check_map(evidence: EvidenceBundle) -> dict[str, bool]:
    return {item.name: item.passed for item in evidence.checks}


def _passes_tempered(evidence: EvidenceBundle) -> bool:
    checks = _check_map(evidence)
    return evidence.trustworthy and all(checks.get(name) is True for name in _TEMPERED_GATES)


class ForgeEngine:
    """Trusted deterministic core; creativity lives outside this class."""

    def __init__(self, vault: ForgeVault) -> None:
        self.vault = vault

    def register(self, artifact: PieceArtifact) -> str:
        return self.vault.store_piece(artifact)

    def record_evidence(self, evidence: EvidenceBundle) -> str:
        return self.vault.store_evidence(evidence)

    def promote(self, piece_hash: str, target: Maturity, evidence_ids: tuple[str, ...]) -> Maturity:
        current = self.vault.maturity(piece_hash)
        if _ORDER[target] != _ORDER[current] + 1:
            raise ForgePromotionBlocked(f"invalid maturity transition: {current.value} -> {target.value}")

        evidence = tuple(self.vault.load_evidence(item) for item in evidence_ids)
        if any(item.piece_hash != piece_hash for item in evidence):
            raise ForgePromotionBlocked("promotion evidence belongs to another Piece")

        if target is Maturity.CANDIDATE:
            if evidence_ids:
                raise ForgePromotionBlocked("candidate promotion does not accept evidence claims")
        elif target is Maturity.TEMPERED:
            if not evidence or not any(_passes_tempered(item) for item in evidence):
                raise ForgePromotionBlocked("tempered requires trustworthy core-gate evidence")
        elif target is Maturity.PROVEN:
            if len(evidence) < 2 or any(not _passes_tempered(item) for item in evidence):
                raise ForgePromotionBlocked("proven requires at least two trustworthy core-gate experiments")
            if len({item.experiment_id for item in evidence}) < 2:
                raise ForgePromotionBlocked("proven requires independent experiments")
            if len({item.environment_fingerprint for item in evidence}) < 2:
                raise ForgePromotionBlocked("proven requires distinct environment fingerprints")
            if not any(_check_map(item).get("clean_clone") is True for item in evidence):
                raise ForgePromotionBlocked("proven requires a clean-clone proof")
        elif target is Maturity.RELIC:
            if evidence_ids:
                raise ForgePromotionBlocked("relic transition is archival, not an evidence claim")
        else:
            raise ForgePromotionBlocked("raw is not a promotion target")

        return self.vault.record_promotion(piece_hash, target, evidence_ids)
