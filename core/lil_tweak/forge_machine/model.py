"""Immutable domain contracts for Tueeq's Forge Machine."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Any

_FORGE_ID = re.compile(r"^forge(?:\.[a-z0-9][a-z0-9-]*)+$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_SECRET_PATTERNS = (
    re.compile(r"OPENAI_API_KEY\s*=", re.IGNORECASE),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?:^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"(?:^|[^A-Za-z0-9])ghp_[A-Za-z0-9]{8,}"),
)


class ForgeError(RuntimeError):
    """Base Forge contract failure."""


class ForgeConflict(ForgeError):
    """Immutable state or clone conflict."""


class ForgeAuthorizationError(ForgeError):
    """Requested mutation lacks explicit authorization."""


class ForgePromotionBlocked(ForgeError):
    """Evidence is insufficient for the requested maturity."""


class Maturity(str, Enum):
    RAW = "raw"
    CANDIDATE = "candidate"
    TEMPERED = "tempered"
    PROVEN = "proven"
    RELIC = "relic"


class BellowsEventKind(str, Enum):
    FORGE_DISCOVERY = "forge_discovery"
    NOVELTY_CANDIDATE = "novelty_candidate"


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest(namespace: str, value: object) -> str:
    return hashlib.sha256(namespace.encode("utf-8") + b"\0" + canonical(value)).hexdigest()


def _text(value: str, *, limit: int = 16_000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > limit:
        raise ValueError("invalid Forge text")
    return value.strip()


def _texts(values: tuple[str, ...], *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(values, tuple) or (not allow_empty and not values):
        raise ValueError("invalid Forge text tuple")
    checked = tuple(_text(item, limit=4096) for item in values)
    if len(set(checked)) != len(checked):
        raise ValueError("duplicate Forge values")
    return checked


def _pairs(values: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    if not isinstance(values, tuple):
        raise ValueError("invalid Forge pairs")
    checked: list[tuple[str, str]] = []
    for item in values:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ValueError("invalid Forge pair")
        checked.append((_text(item[0], limit=256), _text(item[1], limit=4096)))
    if len({key for key, _ in checked}) != len(checked):
        raise ValueError("duplicate Forge pair key")
    return tuple(checked)


def _hash(value: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise ValueError("invalid Forge hash")
    return value


def safe_artifact_path(value: str) -> str:
    checked = _text(value, limit=1024)
    path = PurePosixPath(checked)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("invalid Forge artifact path")
    return path.as_posix()


@dataclass(frozen=True, slots=True)
class ArtifactFile:
    path: str
    content: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", safe_artifact_path(self.path))
        if not isinstance(self.content, str) or len(self.content.encode("utf-8")) > 2 * 1024 * 1024:
            raise ValueError("invalid Forge artifact content")

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path, "content": self.content}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ArtifactFile:
        return cls(path=str(value["path"]), content=str(value["content"]))


@dataclass(frozen=True, slots=True)
class PieceContract:
    problem: str
    intended_use: str
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    guarantees: tuple[str, ...]
    failure_modes: tuple[str, ...]
    side_effects: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "problem", _text(self.problem))
        object.__setattr__(self, "intended_use", _text(self.intended_use))
        object.__setattr__(self, "inputs", _texts(self.inputs))
        object.__setattr__(self, "outputs", _texts(self.outputs))
        object.__setattr__(self, "guarantees", _texts(self.guarantees))
        object.__setattr__(self, "failure_modes", _texts(self.failure_modes))
        object.__setattr__(self, "side_effects", _texts(self.side_effects, allow_empty=True))
        object.__setattr__(self, "dependencies", _texts(self.dependencies, allow_empty=True))

    def to_dict(self) -> dict[str, object]:
        return {
            "problem": self.problem,
            "intended_use": self.intended_use,
            "inputs": list(self.inputs),
            "outputs": list(self.outputs),
            "guarantees": list(self.guarantees),
            "failure_modes": list(self.failure_modes),
            "side_effects": list(self.side_effects),
            "dependencies": list(self.dependencies),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> PieceContract:
        return cls(
            problem=str(value["problem"]),
            intended_use=str(value["intended_use"]),
            inputs=tuple(str(item) for item in value["inputs"]),
            outputs=tuple(str(item) for item in value["outputs"]),
            guarantees=tuple(str(item) for item in value["guarantees"]),
            failure_modes=tuple(str(item) for item in value["failure_modes"]),
            side_effects=tuple(str(item) for item in value.get("side_effects", [])),
            dependencies=tuple(str(item) for item in value.get("dependencies", [])),
        )


@dataclass(frozen=True, slots=True)
class PieceArtifact:
    forge_id: str
    name: str
    version: str
    contract: PieceContract
    files: tuple[ArtifactFile, ...]
    tests: tuple[str, ...]
    provenance: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.forge_id, str) or _FORGE_ID.fullmatch(self.forge_id) is None:
            raise ValueError("invalid Forge id")
        object.__setattr__(self, "name", _text(self.name, limit=240))
        if not isinstance(self.version, str) or _SEMVER.fullmatch(self.version) is None:
            raise ValueError("invalid Forge semantic version")
        if not isinstance(self.contract, PieceContract):
            raise ValueError("invalid Piece contract")
        if not isinstance(self.files, tuple) or not self.files or any(not isinstance(item, ArtifactFile) for item in self.files):
            raise ValueError("invalid Piece files")
        if len({item.path for item in self.files}) != len(self.files):
            raise ValueError("duplicate Piece file path")
        object.__setattr__(self, "tests", _texts(self.tests))
        object.__setattr__(self, "provenance", _pairs(self.provenance))

    @property
    def artifact_hash(self) -> str:
        return digest("tueiq-forge-piece-v1", self.to_dict())

    def to_dict(self) -> dict[str, object]:
        return {
            "forge_id": self.forge_id,
            "name": self.name,
            "version": self.version,
            "contract": self.contract.to_dict(),
            "files": [item.to_dict() for item in self.files],
            "tests": list(self.tests),
            "provenance": [[key, value] for key, value in self.provenance],
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> PieceArtifact:
        contract_value = value["contract"]
        if not isinstance(contract_value, dict):
            raise ValueError("invalid stored Piece contract")
        return cls(
            forge_id=str(value["forge_id"]),
            name=str(value["name"]),
            version=str(value["version"]),
            contract=PieceContract.from_dict(contract_value),
            files=tuple(ArtifactFile.from_dict(dict(item)) for item in value["files"]),
            tests=tuple(str(item) for item in value["tests"]),
            provenance=tuple((str(item[0]), str(item[1])) for item in value["provenance"]),
        )


def contains_secret_like(artifact: PieceArtifact) -> bool:
    for item in artifact.files:
        if any(pattern.search(item.content) is not None for pattern in _SECRET_PATTERNS):
            return True
    return False


@dataclass(frozen=True, slots=True)
class CheckEvidence:
    name: str
    passed: bool
    detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _text(self.name, limit=200))
        if not isinstance(self.passed, bool) or not isinstance(self.detail, str):
            raise ValueError("invalid check evidence")
        if len(self.detail.encode("utf-8")) > 16_000:
            raise ValueError("check evidence detail too large")

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> CheckEvidence:
        return cls(str(value["name"]), bool(value["passed"]), str(value.get("detail", "")))


@dataclass(frozen=True, slots=True)
class TrialMetric:
    name: str
    value: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _text(self.name, limit=200))
        if not isinstance(self.value, (int, float)) or isinstance(self.value, bool):
            raise ValueError("invalid trial metric")
        value = float(self.value)
        if value != value or value in {float("inf"), float("-inf")}:
            raise ValueError("non-finite trial metric")
        object.__setattr__(self, "value", value)

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "value": self.value}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> TrialMetric:
        return cls(str(value["name"]), float(value["value"]))


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    piece_hash: str
    experiment_id: str
    environment_fingerprint: str
    checks: tuple[CheckEvidence, ...]
    metrics: tuple[TrialMetric, ...]
    observation: str
    trustworthy: bool
    evidence_id: str

    @classmethod
    def create(
        cls,
        *,
        piece_hash: str,
        experiment_id: str,
        environment_fingerprint: str,
        checks: tuple[CheckEvidence, ...],
        metrics: tuple[TrialMetric, ...],
        observation: str,
        trustworthy: bool,
    ) -> EvidenceBundle:
        _hash(piece_hash)
        experiment_id = _text(experiment_id, limit=512)
        environment_fingerprint = _text(environment_fingerprint, limit=512)
        if not checks or any(not isinstance(item, CheckEvidence) for item in checks):
            raise ValueError("invalid evidence checks")
        if any(not isinstance(item, TrialMetric) for item in metrics):
            raise ValueError("invalid evidence metrics")
        if len({item.name for item in checks}) != len(checks) or len({item.name for item in metrics}) != len(metrics):
            raise ValueError("duplicate evidence names")
        observation = _text(observation, limit=16_000)
        if not isinstance(trustworthy, bool):
            raise ValueError("invalid evidence trust flag")
        payload = {
            "piece_hash": piece_hash,
            "experiment_id": experiment_id,
            "environment_fingerprint": environment_fingerprint,
            "checks": [item.to_dict() for item in checks],
            "metrics": [item.to_dict() for item in metrics],
            "observation": observation,
            "trustworthy": trustworthy,
        }
        evidence_id = "evidence:" + digest("tueiq-forge-evidence-v1", payload)
        return cls(piece_hash, experiment_id, environment_fingerprint, checks, metrics, observation, trustworthy, evidence_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "piece_hash": self.piece_hash,
            "experiment_id": self.experiment_id,
            "environment_fingerprint": self.environment_fingerprint,
            "checks": [item.to_dict() for item in self.checks],
            "metrics": [item.to_dict() for item in self.metrics],
            "observation": self.observation,
            "trustworthy": self.trustworthy,
            "evidence_id": self.evidence_id,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> EvidenceBundle:
        created = cls.create(
            piece_hash=str(value["piece_hash"]),
            experiment_id=str(value["experiment_id"]),
            environment_fingerprint=str(value["environment_fingerprint"]),
            checks=tuple(CheckEvidence.from_dict(dict(item)) for item in value["checks"]),
            metrics=tuple(TrialMetric.from_dict(dict(item)) for item in value["metrics"]),
            observation=str(value["observation"]),
            trustworthy=bool(value["trustworthy"]),
        )
        if created.evidence_id != value.get("evidence_id"):
            raise ValueError("evidence identity mismatch")
        return created


@dataclass(frozen=True, slots=True)
class OptimizationProfile:
    name: str
    hard_gates: tuple[str, ...]
    weights: tuple[tuple[str, float], ...]
    directions: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _text(self.name, limit=200))
        object.__setattr__(self, "hard_gates", _texts(self.hard_gates))
        if not self.weights or not isinstance(self.weights, tuple):
            raise ValueError("invalid optimization weights")
        weights: list[tuple[str, float]] = []
        for name, weight in self.weights:
            checked_name = _text(name, limit=200)
            checked_weight = float(weight)
            if checked_weight <= 0 or checked_weight != checked_weight:
                raise ValueError("invalid optimization weight")
            weights.append((checked_name, checked_weight))
        if len({name for name, _ in weights}) != len(weights):
            raise ValueError("duplicate optimization metric")
        directions: list[tuple[str, str]] = []
        for name, direction in self.directions:
            checked_name = _text(name, limit=200)
            if direction not in {"min", "max"}:
                raise ValueError("invalid optimization direction")
            directions.append((checked_name, direction))
        if dict(directions).keys() != dict(weights).keys():
            raise ValueError("optimization direction mismatch")
        object.__setattr__(self, "weights", tuple(weights))
        object.__setattr__(self, "directions", tuple(directions))


@dataclass(frozen=True, slots=True)
class ComparisonResult:
    profile_name: str
    winner_piece_hashes: tuple[str, ...]
    scores: tuple[tuple[str, float], ...]
    rejected: tuple[tuple[str, str], ...]
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Mechanism:
    mechanism_id: str
    name: str
    principle: str
    assumptions: tuple[str, ...]
    structural_signature: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        name: str,
        principle: str,
        assumptions: tuple[str, ...],
        structural_signature: tuple[str, ...],
    ) -> Mechanism:
        name = _text(name, limit=240)
        principle = _text(principle)
        assumptions = _texts(assumptions)
        structural_signature = _texts(structural_signature)
        payload = {
            "name": name,
            "principle": principle,
            "assumptions": list(assumptions),
            "structural_signature": list(structural_signature),
        }
        return cls("mechanism:" + digest("tueiq-forge-mechanism-v1", payload), name, principle, assumptions, structural_signature)

    def to_dict(self) -> dict[str, object]:
        return {
            "mechanism_id": self.mechanism_id,
            "name": self.name,
            "principle": self.principle,
            "assumptions": list(self.assumptions),
            "structural_signature": list(self.structural_signature),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Mechanism:
        created = cls.create(
            name=str(value["name"]),
            principle=str(value["principle"]),
            assumptions=tuple(str(item) for item in value["assumptions"]),
            structural_signature=tuple(str(item) for item in value["structural_signature"]),
        )
        if created.mechanism_id != value.get("mechanism_id"):
            raise ValueError("mechanism identity mismatch")
        return created


@dataclass(frozen=True, slots=True)
class Discovery:
    discovery_id: str
    mechanism: Mechanism
    origin_piece_hash: str
    verified_applications: tuple[str, ...]
    candidate_applications: tuple[str, ...]
    questions: tuple[str, ...]
    evidence_ids: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        mechanism: Mechanism,
        origin_piece_hash: str,
        verified_applications: tuple[str, ...],
        candidate_applications: tuple[str, ...],
        questions: tuple[str, ...],
        evidence_ids: tuple[str, ...],
    ) -> Discovery:
        _hash(origin_piece_hash)
        verified_applications = _texts(verified_applications)
        candidate_applications = _texts(candidate_applications, allow_empty=True)
        questions = _texts(questions)
        evidence_ids = _texts(evidence_ids)
        if set(verified_applications) & set(candidate_applications):
            raise ValueError("candidate application already verified")
        payload = {
            "mechanism": mechanism.to_dict(),
            "origin_piece_hash": origin_piece_hash,
            "verified_applications": list(verified_applications),
            "candidate_applications": list(candidate_applications),
            "questions": list(questions),
            "evidence_ids": list(evidence_ids),
        }
        return cls(
            "discovery:" + digest("tueiq-forge-discovery-v1", payload),
            mechanism,
            origin_piece_hash,
            verified_applications,
            candidate_applications,
            questions,
            evidence_ids,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "discovery_id": self.discovery_id,
            "mechanism": self.mechanism.to_dict(),
            "origin_piece_hash": self.origin_piece_hash,
            "verified_applications": list(self.verified_applications),
            "candidate_applications": list(self.candidate_applications),
            "questions": list(self.questions),
            "evidence_ids": list(self.evidence_ids),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Discovery:
        mechanism_value = value["mechanism"]
        if not isinstance(mechanism_value, dict):
            raise ValueError("invalid stored mechanism")
        created = cls.create(
            mechanism=Mechanism.from_dict(mechanism_value),
            origin_piece_hash=str(value["origin_piece_hash"]),
            verified_applications=tuple(str(item) for item in value["verified_applications"]),
            candidate_applications=tuple(str(item) for item in value["candidate_applications"]),
            questions=tuple(str(item) for item in value["questions"]),
            evidence_ids=tuple(str(item) for item in value["evidence_ids"]),
        )
        if created.discovery_id != value.get("discovery_id"):
            raise ValueError("discovery identity mismatch")
        return created


@dataclass(frozen=True, slots=True)
class Novelty:
    novelty_id: str
    source: str
    summary: str
    supporting_evidence_ids: tuple[str, ...]

    @classmethod
    def create(cls, *, source: str, summary: str, supporting_evidence_ids: tuple[str, ...]) -> Novelty:
        source = _text(source, limit=240)
        summary = _text(summary)
        supporting_evidence_ids = _texts(supporting_evidence_ids)
        payload = {"source": source, "summary": summary, "supporting_evidence_ids": list(supporting_evidence_ids)}
        return cls("novelty:" + digest("tueiq-forge-novelty-v1", payload), source, summary, supporting_evidence_ids)


@dataclass(frozen=True, slots=True)
class BellowsEvent:
    event_id: str
    kind: BellowsEventKind
    subject_id: str
    evidence_ids: tuple[str, ...]
    payload: tuple[tuple[str, str], ...]

    @classmethod
    def create(
        cls,
        *,
        kind: BellowsEventKind,
        subject_id: str,
        evidence_ids: tuple[str, ...],
        payload: tuple[tuple[str, str], ...],
    ) -> BellowsEvent:
        subject_id = _text(subject_id, limit=512)
        evidence_ids = _texts(evidence_ids, allow_empty=True)
        payload = _pairs(payload)
        body = {
            "kind": kind.value,
            "subject_id": subject_id,
            "evidence_ids": list(evidence_ids),
            "payload": [[key, value] for key, value in payload],
        }
        return cls("event:" + digest("tueiq-forge-bellows-v1", body), kind, subject_id, evidence_ids, payload)

    def to_dict(self) -> dict[str, object]:
        return {
            "event_id": self.event_id,
            "kind": self.kind.value,
            "subject_id": self.subject_id,
            "evidence_ids": list(self.evidence_ids),
            "payload": [[key, value] for key, value in self.payload],
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> BellowsEvent:
        created = cls.create(
            kind=BellowsEventKind(str(value["kind"])),
            subject_id=str(value["subject_id"]),
            evidence_ids=tuple(str(item) for item in value["evidence_ids"]),
            payload=tuple((str(item[0]), str(item[1])) for item in value["payload"]),
        )
        if created.event_id != value.get("event_id"):
            raise ValueError("Bellows event identity mismatch")
        return created


@dataclass(frozen=True, slots=True)
class ClonePlan:
    piece_hash: str
    target_root: str
    files: tuple[str, ...]
    conflicts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CloneReceipt:
    receipt_id: str
    piece_hash: str
    target_root: str
    files_created: tuple[str, ...]

    @classmethod
    def create(cls, *, piece_hash: str, target_root: str, files_created: tuple[str, ...]) -> CloneReceipt:
        _hash(piece_hash)
        target_root = _text(target_root, limit=4096)
        files_created = _texts(files_created)
        payload = {"piece_hash": piece_hash, "target_root": target_root, "files_created": list(files_created)}
        return cls("clone:" + digest("tueiq-forge-clone-v1", payload), piece_hash, target_root, files_created)

    def to_dict(self) -> dict[str, object]:
        return {
            "receipt_id": self.receipt_id,
            "piece_hash": self.piece_hash,
            "target_root": self.target_root,
            "files_created": list(self.files_created),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> CloneReceipt:
        created = cls.create(
            piece_hash=str(value["piece_hash"]),
            target_root=str(value["target_root"]),
            files_created=tuple(str(item) for item in value["files_created"]),
        )
        if created.receipt_id != value.get("receipt_id"):
            raise ValueError("clone receipt identity mismatch")
        return created
