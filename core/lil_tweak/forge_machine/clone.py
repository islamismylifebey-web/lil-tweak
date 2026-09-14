"""Explicit, authorization-gated cloning of proven Forge Pieces."""
from __future__ import annotations

from pathlib import Path

from .model import (
    ClonePlan,
    CloneReceipt,
    ForgeAuthorizationError,
    ForgeConflict,
    PieceArtifact,
    contains_secret_like,
)
from .vault import ForgeVault


class CloneEngine:
    def __init__(self, vault: ForgeVault) -> None:
        self.vault = vault

    def plan(self, artifact: PieceArtifact, target_root: Path) -> ClonePlan:
        root = target_root.resolve()
        files: list[str] = []
        conflicts: list[str] = []
        for item in artifact.files:
            destination = (root / item.path).resolve()
            if destination != root and root not in destination.parents:
                raise ValueError("unsafe clone destination")
            files.append(item.path)
            if destination.exists():
                conflicts.append(item.path)
        return ClonePlan(
            piece_hash=artifact.artifact_hash,
            target_root=str(root),
            files=tuple(files),
            conflicts=tuple(conflicts),
        )

    def clone(self, artifact: PieceArtifact, target_root: Path, *, authorized: bool) -> CloneReceipt:
        if authorized is not True:
            raise ForgeAuthorizationError("Forge clone requires explicit authorization")
        if contains_secret_like(artifact):
            raise ValueError("secret-like material cannot be cloned")
        self.vault.load_piece(artifact.artifact_hash)
        plan = self.plan(artifact, target_root)
        if plan.conflicts:
            raise ForgeConflict("clone target already contains: " + ", ".join(plan.conflicts))

        root = Path(plan.target_root)
        created: list[Path] = []
        try:
            for item in artifact.files:
                destination = (root / item.path).resolve()
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("x", encoding="utf-8", newline="") as handle:
                    handle.write(item.content)
                created.append(destination)
        except Exception:
            for path in reversed(created):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            raise

        receipt = CloneReceipt.create(
            piece_hash=artifact.artifact_hash,
            target_root=str(root),
            files_created=tuple(item.path for item in artifact.files),
        )
        self.vault.store_clone_receipt(receipt)
        return receipt
