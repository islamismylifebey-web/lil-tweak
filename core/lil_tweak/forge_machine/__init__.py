"""Tueeq Forge Machine V1: prove, compare, generalize, learn, and safely reuse inventions."""
from .bellows import Bellows, MasteryIntake, MasterySink, discovery_to_mastery_intake
from .clone import CloneEngine
from .crucible import CrucibleExperiment, TestWorldCrucible
from .engine import ForgeEngine
from .lens import SECONDARY_USE_QUESTION, build_discovery, secondary_use_questions
from .model import (
    ArtifactFile,
    BellowsEvent,
    BellowsEventKind,
    CheckEvidence,
    ClonePlan,
    CloneReceipt,
    ComparisonResult,
    Discovery,
    EvidenceBundle,
    ForgeAuthorizationError,
    ForgeConflict,
    ForgeError,
    ForgePromotionBlocked,
    Maturity,
    Mechanism,
    Novelty,
    OptimizationProfile,
    PieceArtifact,
    PieceContract,
    TrialMetric,
)
from .scale import compare_candidates
from .vault import ForgeVault

__all__ = [
    "ArtifactFile",
    "Bellows",
    "BellowsEvent",
    "BellowsEventKind",
    "CheckEvidence",
    "CloneEngine",
    "ClonePlan",
    "CloneReceipt",
    "ComparisonResult",
    "CrucibleExperiment",
    "Discovery",
    "EvidenceBundle",
    "ForgeAuthorizationError",
    "ForgeConflict",
    "ForgeEngine",
    "ForgeError",
    "ForgePromotionBlocked",
    "ForgeVault",
    "MasteryIntake",
    "MasterySink",
    "Maturity",
    "Mechanism",
    "Novelty",
    "OptimizationProfile",
    "PieceArtifact",
    "PieceContract",
    "SECONDARY_USE_QUESTION",
    "TestWorldCrucible",
    "TrialMetric",
    "build_discovery",
    "compare_candidates",
    "discovery_to_mastery_intake",
    "secondary_use_questions",
]
