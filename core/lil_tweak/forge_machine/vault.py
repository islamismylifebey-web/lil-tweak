"""Append-only content-addressed storage for Tueeq's Forge Machine."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .model import (
    BellowsEvent,
    CloneReceipt,
    Discovery,
    EvidenceBundle,
    ForgeConflict,
    Maturity,
    PieceArtifact,
    canonical,
    contains_secret_like,
)

_MATURITY_ORDER = {
    Maturity.RAW: 0,
    Maturity.CANDIDATE: 1,
    Maturity.TEMPERED: 2,
    Maturity.PROVEN: 3,
    Maturity.RELIC: 4,
}


class ForgeVault:
    """Durable write-once records with immutable Piece identity/version refs."""

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise ValueError("Forge Vault root must be a Path")
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, *parts: str) -> Path:
        path = self.root.joinpath(*parts).resolve()
        if path != self.root and self.root not in path.parents:
            raise ValueError("invalid Forge Vault path")
        return path

    def _write_once(self, path: Path, payload: dict[str, object]) -> None:
        data = canonical(payload)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if path.read_bytes() != data:
                raise ForgeConflict(f"immutable Forge record conflict: {path.name}") from None
            return
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

    @staticmethod
    def _read(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise KeyError(path.name) from None
        if not isinstance(value, dict):
            raise ValueError("invalid Forge Vault record")
        return value

    def store_piece(self, artifact: PieceArtifact) -> str:
        if contains_secret_like(artifact):
            raise ValueError("secret-like material is forbidden in the Forge Vault")
        piece_path = self._path("pieces", f"{artifact.artifact_hash}.json")
        self._write_once(piece_path, artifact.to_dict())
        ref_path = self._path("refs", *artifact.forge_id.split("."), f"{artifact.version}.json")
        self._write_once(ref_path, {"artifact_hash": artifact.artifact_hash})
        return artifact.artifact_hash

    def load_piece(self, artifact_hash: str) -> PieceArtifact:
        value = self._read(self._path("pieces", f"{artifact_hash}.json"))
        artifact = PieceArtifact.from_dict(value)
        if artifact.artifact_hash != artifact_hash:
            raise ValueError("stored Piece hash mismatch")
        return artifact

    def store_evidence(self, evidence: EvidenceBundle) -> str:
        self.load_piece(evidence.piece_hash)
        self._write_once(self._path("evidence", f"{evidence.evidence_id}.json"), evidence.to_dict())
        return evidence.evidence_id

    def load_evidence(self, evidence_id: str) -> EvidenceBundle:
        return EvidenceBundle.from_dict(self._read(self._path("evidence", f"{evidence_id}.json")))

    def record_promotion(self, piece_hash: str, maturity: Maturity, evidence_ids: tuple[str, ...]) -> Maturity:
        self.load_piece(piece_hash)
        number = _MATURITY_ORDER[maturity]
        if number == 0:
            raise ValueError("raw maturity is implicit")
        self._write_once(
            self._path("promotions", piece_hash, f"{number}-{maturity.value}.json"),
            {"piece_hash": piece_hash, "maturity": maturity.value, "evidence_ids": list(evidence_ids)},
        )
        return maturity

    def maturity(self, piece_hash: str) -> Maturity:
        self.load_piece(piece_hash)
        directory = self._path("promotions", piece_hash)
        if not directory.exists():
            return Maturity.RAW
        best = Maturity.RAW
        for candidate, order in _MATURITY_ORDER.items():
            if order == 0:
                continue
            if (directory / f"{order}-{candidate.value}.json").exists() and order > _MATURITY_ORDER[best]:
                best = candidate
        return best

    def store_discovery(self, discovery: Discovery) -> str:
        self.load_piece(discovery.origin_piece_hash)
        self._write_once(self._path("discoveries", f"{discovery.discovery_id}.json"), discovery.to_dict())
        return discovery.discovery_id

    def load_discovery(self, discovery_id: str) -> Discovery:
        return Discovery.from_dict(self._read(self._path("discoveries", f"{discovery_id}.json")))

    def store_bellows_event(self, event: BellowsEvent) -> str:
        self._write_once(self._path("bellows", f"{event.event_id}.json"), event.to_dict())
        return event.event_id

    def load_bellows_event(self, event_id: str) -> BellowsEvent:
        return BellowsEvent.from_dict(self._read(self._path("bellows", f"{event_id}.json")))

    def store_clone_receipt(self, receipt: CloneReceipt) -> str:
        self.load_piece(receipt.piece_hash)
        self._write_once(self._path("clones", f"{receipt.receipt_id}.json"), receipt.to_dict())
        return receipt.receipt_id

    def load_clone_receipt(self, receipt_id: str) -> CloneReceipt:
        return CloneReceipt.from_dict(self._read(self._path("clones", f"{receipt_id}.json")))
