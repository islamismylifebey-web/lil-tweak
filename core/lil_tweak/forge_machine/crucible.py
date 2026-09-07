"""Forge Crucible adapter over Tueeq's durable Test World contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..test_world import AttemptStatus, TestCheck, TestWorld, TestWorldAttempt, TestWorldStore
from .model import CheckEvidence, EvidenceBundle, PieceArtifact, TrialMetric


@dataclass(frozen=True, slots=True)
class CrucibleExperiment:
    piece_hash: str
    world_id: str
    attempt_id: str


class TestWorldCrucible:
    """Creates Forge-specific Test Worlds and converts judge truth into evidence."""

    def __init__(self, store: TestWorldStore) -> None:
        self.store = store

    def open_experiment(
        self,
        artifact: PieceArtifact,
        *,
        owner_id: str,
        repository_url: str,
        commit: str,
        checks: tuple[TestCheck, ...],
        max_attempts: int = 3,
    ) -> CrucibleExperiment:
        prefix = artifact.artifact_hash[:24]
        objective = (
            "Forge Crucible experiment. "
            f"Evaluate exact Piece hash {artifact.artifact_hash}. "
            "No external actions. Network access remains disabled. "
            "The trusted Test World judge, not agent self-report, decides results. "
            "Do not mutate canonical Forge artifacts; experiment only inside the disposable workspace."
        )
        world = self.store.create_world(
            owner_id,
            idempotency_key=f"forge-world-{prefix}",
            name=f"Forge: {artifact.name}",
            objective=objective,
            repository_url=repository_url,
            commit=commit,
            checks=checks,
            max_attempts=max_attempts,
        )
        attempt = self.store.enqueue_attempt(
            world.id,
            owner_id,
            idempotency_key=f"forge-attempt-{prefix}-1",
        )
        return CrucibleExperiment(artifact.artifact_hash, world.id, attempt.id)

    def capture_evidence(
        self,
        artifact: PieceArtifact,
        world: TestWorld,
        attempt: TestWorldAttempt,
    ) -> EvidenceBundle:
        if attempt.world_id != world.id or attempt.world_fingerprint != world.fingerprint:
            raise ValueError("attempt does not belong to supplied Test World")
        terminal = {AttemptStatus.PASSED, AttemptStatus.FAILED, AttemptStatus.ERROR}
        if attempt.status not in terminal:
            raise ValueError("Forge evidence requires a terminal judged attempt")

        checks: list[CheckEvidence] = []
        for raw in attempt.feedback:
            check = raw.get("check")
            passed = raw.get("passed")
            if not isinstance(check, str) or not isinstance(passed, bool):
                continue
            detail = self._feedback_detail(raw)
            checks.append(CheckEvidence(check, passed, detail))

        if not checks:
            checks.append(CheckEvidence("attempt_runtime", False, attempt.outcome or attempt.status.value))

        metrics = (
            TrialMetric("duration_ms", float(attempt.duration_ms)),
            TrialMetric("judge_duration_ms", float(attempt.judge_duration_ms)),
            TrialMetric("model_calls", float(attempt.model_calls)),
            TrialMetric("total_tokens", float(attempt.total_tokens)),
        )
        trustworthy = attempt.status in {AttemptStatus.PASSED, AttemptStatus.FAILED}
        observation = attempt.summary.strip() if attempt.summary.strip() else (attempt.outcome or attempt.status.value)
        return EvidenceBundle.create(
            piece_hash=artifact.artifact_hash,
            experiment_id=f"test-world:{world.id}:{attempt.id}",
            environment_fingerprint=world.fingerprint,
            checks=tuple(checks),
            metrics=metrics,
            observation=observation,
            trustworthy=trustworthy,
        )

    @staticmethod
    def _feedback_detail(value: Any) -> str:
        if not isinstance(value, dict):
            try:
                value = dict(value)
            except Exception:
                return ""
        parts: list[str] = []
        for key in ("exitCode", "timedOut", "truncated", "stdout", "stderr", "code"):
            item = value.get(key)
            if item not in (None, "", False):
                parts.append(f"{key}={item}")
        return "; ".join(parts)[:16_000]
