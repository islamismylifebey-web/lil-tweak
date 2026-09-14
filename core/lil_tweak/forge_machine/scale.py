"""The Scale: hard-gate filtering and explicit profile comparison."""
from __future__ import annotations

from collections import defaultdict

from .model import ComparisonResult, EvidenceBundle, OptimizationProfile


def _average(values: tuple[float, ...]) -> float:
    return sum(values) / len(values)


def compare_candidates(
    profile: OptimizationProfile,
    evidence: tuple[EvidenceBundle, ...],
) -> ComparisonResult:
    if not evidence:
        raise ValueError("comparison requires evidence")

    grouped: dict[str, list[EvidenceBundle]] = defaultdict(list)
    for item in evidence:
        grouped[item.piece_hash].append(item)

    rejected: list[tuple[str, str]] = []
    accepted: dict[str, dict[str, float]] = {}
    directions = dict(profile.directions)
    required_metrics = tuple(name for name, _ in profile.weights)

    for piece_hash in sorted(grouped):
        bundles = grouped[piece_hash]
        failure: str | None = None
        for gate in profile.hard_gates:
            for bundle in bundles:
                checks = {item.name: item.passed for item in bundle.checks}
                if not bundle.trustworthy:
                    failure = "untrustworthy evidence"
                    break
                if checks.get(gate) is not True:
                    failure = f"hard gate failed: {gate}"
                    break
            if failure is not None:
                break
        if failure is not None:
            rejected.append((piece_hash, failure))
            continue

        metrics: dict[str, list[float]] = defaultdict(list)
        for bundle in bundles:
            for trial_metric in bundle.metrics:
                metrics[trial_metric.name].append(trial_metric.value)
        missing = [name for name in required_metrics if not metrics.get(name)]
        if missing:
            rejected.append((piece_hash, "missing metric: " + ", ".join(missing)))
            continue
        accepted[piece_hash] = {name: _average(tuple(metrics[name])) for name in required_metrics}

    if not accepted:
        return ComparisonResult(
            profile.name,
            (),
            (),
            tuple(rejected),
            tuple(item.evidence_id for item in evidence),
        )

    weights = dict(profile.weights)
    total_weight = sum(weights.values())
    ranges: dict[str, tuple[float, float]] = {}
    for metric_name in required_metrics:
        values = tuple(candidate[metric_name] for candidate in accepted.values())
        ranges[metric_name] = (min(values), max(values))

    scores: list[tuple[str, float]] = []
    for piece_hash in sorted(accepted):
        score = 0.0
        for metric_name, weight in profile.weights:
            value = accepted[piece_hash][metric_name]
            low, high = ranges[metric_name]
            if high == low:
                normalized = 1.0
            elif directions[metric_name] == "min":
                normalized = (high - value) / (high - low)
            else:
                normalized = (value - low) / (high - low)
            score += (weight / total_weight) * normalized
        scores.append((piece_hash, score))

    best = max(score for _, score in scores)
    winners = tuple(piece_hash for piece_hash, score in scores if abs(score - best) <= 1e-12)
    return ComparisonResult(
        profile.name,
        winners,
        tuple(scores),
        tuple(rejected),
        tuple(item.evidence_id for item in evidence),
    )
