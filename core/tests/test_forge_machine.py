from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from core.lil_tweak.forge_machine import (
    ArtifactFile,
    Bellows,
    BellowsEventKind,
    CheckEvidence,
    CloneEngine,
    EvidenceBundle,
    ForgeAuthorizationError,
    ForgeConflict,
    ForgeEngine,
    ForgePromotionBlocked,
    ForgeVault,
    Maturity,
    Mechanism,
    Novelty,
    OptimizationProfile,
    PieceArtifact,
    PieceContract,
    TestWorldCrucible,
    TrialMetric,
    build_discovery,
    compare_candidates,
    secondary_use_questions,
)
from core.lil_tweak.test_world import MemoryTestWorldStore, TestCheck


OWNER = "0123456789abcdef0123456789abcdef"
COMMIT = "a" * 40


def piece(*, version: str = "1.0.0", source: str = "def resolve(x):\n    return x\n") -> PieceArtifact:
    return PieceArtifact(
        forge_id="forge.optimization.contract-registry",
        name="Optimization Contract Registry",
        version=version,
        contract=PieceContract(
            problem="Resolve competing optimization objectives deterministically.",
            intended_use="Multi-objective arbitration inside agent DAGs.",
            inputs=("optimization contract", "runtime constraints"),
            outputs=("resolved policy", "decision evidence"),
            guarantees=("deterministic for identical inputs",),
            failure_modes=("invalid contract", "unsatisfiable contract"),
            side_effects=(),
            dependencies=(),
        ),
        files=(ArtifactFile("contract_registry.py", source),),
        tests=("python3 -m unittest",),
        provenance=(("origin_project", "tueiq-dag"),),
    )


def evidence(
    artifact: PieceArtifact,
    *,
    experiment_id: str,
    environment: str,
    latency: float,
    memory: float,
    security: bool = True,
    clean_clone: bool = False,
    trustworthy: bool = True,
) -> EvidenceBundle:
    checks = (
        CheckEvidence("contract_compliance", True),
        CheckEvidence("correctness", True),
        CheckEvidence("security", security),
        CheckEvidence("reproducibility", True),
        CheckEvidence("clean_clone", clean_clone),
    )
    return EvidenceBundle.create(
        piece_hash=artifact.artifact_hash,
        experiment_id=experiment_id,
        environment_fingerprint=environment,
        checks=checks,
        metrics=(TrialMetric("latency_ms", latency), TrialMetric("memory_mb", memory)),
        observation="judge-completed trial",
        trustworthy=trustworthy,
    )


class ForgeMachineContractTests(unittest.TestCase):
    def test_vault_refuses_identity_repoint_and_preserves_original_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = ForgeVault(Path(directory))
            original = piece()
            vault.store_piece(original)
            changed = piece(source="def resolve(x):\n    return {'changed': x}\n")

            with self.assertRaises(ForgeConflict):
                vault.store_piece(changed)

            loaded = vault.load_piece(original.artifact_hash)
            self.assertEqual(loaded.artifact_hash, original.artifact_hash)
            self.assertEqual(loaded.files[0].content, original.files[0].content)

    def test_secret_like_material_cannot_enter_vault(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = ForgeVault(Path(directory))
            contaminated = replace(
                piece(),
                version="1.0.1",
                files=(ArtifactFile("config.txt", "OPENAI_API_KEY=sk-example-secret"),),
            )
            with self.assertRaises(ValueError):
                vault.store_piece(contaminated)

    def test_proven_requires_independent_trusted_evidence_and_clean_clone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = ForgeVault(Path(directory))
            engine = ForgeEngine(vault)
            artifact = piece()
            engine.register(artifact)
            self.assertEqual(engine.promote(artifact.artifact_hash, Maturity.CANDIDATE, ()), Maturity.CANDIDATE)

            first = evidence(
                artifact,
                experiment_id="exp-1",
                environment="env-a",
                latency=5.0,
                memory=30.0,
            )
            engine.record_evidence(first)
            self.assertEqual(
                engine.promote(artifact.artifact_hash, Maturity.TEMPERED, (first.evidence_id,)),
                Maturity.TEMPERED,
            )

            with self.assertRaises(ForgePromotionBlocked):
                engine.promote(artifact.artifact_hash, Maturity.PROVEN, (first.evidence_id,))

            second = evidence(
                artifact,
                experiment_id="exp-2",
                environment="env-b",
                latency=6.0,
                memory=28.0,
                clean_clone=True,
            )
            engine.record_evidence(second)
            self.assertEqual(
                engine.promote(
                    artifact.artifact_hash,
                    Maturity.PROVEN,
                    (first.evidence_id, second.evidence_id),
                ),
                Maturity.PROVEN,
            )
            self.assertEqual(vault.maturity(artifact.artifact_hash), Maturity.PROVEN)

    def test_scale_rejects_hard_gate_failure_before_weighted_score(self) -> None:
        fast = piece(version="1.0.0")
        safe = piece(version="1.1.0")
        fast_evidence = evidence(
            fast,
            experiment_id="fast",
            environment="env-fast",
            latency=1.0,
            memory=20.0,
            security=False,
        )
        safe_evidence = evidence(
            safe,
            experiment_id="safe",
            environment="env-safe",
            latency=15.0,
            memory=20.0,
            security=True,
        )
        profile = OptimizationProfile(
            name="latency-first",
            hard_gates=("correctness", "security"),
            weights=(("latency_ms", 1.0),),
            directions=(("latency_ms", "min"),),
        )

        result = compare_candidates(profile, (fast_evidence, safe_evidence))

        self.assertEqual(result.winner_piece_hashes, (safe.artifact_hash,))
        self.assertIn(fast.artifact_hash, dict(result.rejected))
        self.assertIn("security", dict(result.rejected)[fast.artifact_hash])

    def test_scale_can_select_different_winners_for_different_profiles(self) -> None:
        low_latency = piece(version="2.0.0")
        low_memory = piece(version="2.1.0")
        a = evidence(
            low_latency,
            experiment_id="a",
            environment="env-a",
            latency=5.0,
            memory=100.0,
        )
        b = evidence(
            low_memory,
            experiment_id="b",
            environment="env-b",
            latency=10.0,
            memory=20.0,
        )
        latency_profile = OptimizationProfile(
            name="latency",
            hard_gates=("correctness", "security"),
            weights=(("latency_ms", 1.0),),
            directions=(("latency_ms", "min"),),
        )
        edge_profile = OptimizationProfile(
            name="edge",
            hard_gates=("correctness", "security"),
            weights=(("latency_ms", 0.2), ("memory_mb", 0.8)),
            directions=(("latency_ms", "min"), ("memory_mb", "min")),
        )

        self.assertEqual(compare_candidates(latency_profile, (a, b)).winner_piece_hashes, (low_latency.artifact_hash,))
        self.assertEqual(compare_candidates(edge_profile, (a, b)).winner_piece_hashes, (low_memory.artifact_hash,))

    def test_lens_always_asks_secondary_use_question_and_separates_hypotheses(self) -> None:
        artifact = piece()
        mechanism = Mechanism.create(
            name="Declarative multi-objective arbitration",
            principle="Hard constraints before weighted soft objectives.",
            assumptions=("objectives can be represented declaratively",),
            structural_signature=("competing objectives", "hard constraints", "deterministic resolver"),
        )

        questions = secondary_use_questions(mechanism)
        discovery = build_discovery(
            mechanism=mechanism,
            origin_piece_hash=artifact.artifact_hash,
            verified_applications=("DAG optimization",),
            candidate_applications=("model routing", "memory prioritization"),
            evidence_ids=("evidence:abc",),
        )

        self.assertIn("What else can the mechanism inside this Piece do?", questions)
        self.assertEqual(discovery.verified_applications, ("DAG optimization",))
        self.assertEqual(discovery.candidate_applications, ("model routing", "memory prioritization"))
        self.assertNotIn("model routing", discovery.verified_applications)

    def test_bellows_publishes_discovery_but_keeps_novelty_as_candidate(self) -> None:
        artifact = piece()
        mechanism = Mechanism.create(
            name="Declarative multi-objective arbitration",
            principle="Hard constraints before weighted objectives.",
            assumptions=("explicit objectives",),
            structural_signature=("competition", "constraints", "resolution"),
        )
        discovery = build_discovery(
            mechanism=mechanism,
            origin_piece_hash=artifact.artifact_hash,
            verified_applications=("DAG optimization",),
            candidate_applications=("model routing",),
            evidence_ids=("evidence:abc",),
        )

        class Sink:
            def __init__(self) -> None:
                self.items = []

            def accept_discovery(self, intake):
                self.items.append(intake)
                return "mastery-intake-1"

        with tempfile.TemporaryDirectory() as directory:
            vault = ForgeVault(Path(directory))
            bellows = Bellows(vault)
            sink = Sink()
            event = bellows.publish_discovery(discovery, sink)
            self.assertEqual(event.kind, BellowsEventKind.FORGE_DISCOVERY)
            self.assertEqual(len(sink.items), 1)
            self.assertIn("DAG optimization", sink.items[0].solution_summary)
            self.assertIn("Candidate applications", sink.items[0].solution_summary)

            novelty = Novelty.create(
                source="skill-mastery",
                summary="Dynamic objectives may require a temporal arbitration policy.",
                supporting_evidence_ids=("mastery-evidence-1",),
            )
            novelty_event = bellows.receive_novelty(novelty)
            self.assertEqual(novelty_event.kind, BellowsEventKind.NOVELTY_CANDIDATE)
            self.assertEqual(vault.load_bellows_event(novelty_event.event_id).subject_id, novelty.novelty_id)

    def test_crucible_uses_test_world_and_converts_judged_attempt_to_evidence(self) -> None:
        store = MemoryTestWorldStore(clock=lambda: 100.0)
        crucible = TestWorldCrucible(store)
        artifact = piece()
        experiment = crucible.open_experiment(
            artifact,
            owner_id=OWNER,
            repository_url="https://github.com/example/repo",
            commit=COMMIT,
            checks=(TestCheck("unit", ("python3", "-m", "unittest"), 30),),
            max_attempts=2,
        )
        world = store.get_world(experiment.world_id, OWNER)
        attempt = store.get_attempt(experiment.attempt_id, OWNER)
        self.assertIsNotNone(world)
        self.assertIsNotNone(attempt)
        assert world is not None and attempt is not None
        self.assertIn(artifact.artifact_hash, world.objective)
        self.assertIn("No external actions", world.objective)

        lease = store.claim_attempt(attempt.id, "forge-test-worker", lease_seconds=30, now=100.0)
        assert lease is not None
        finished = store.complete_attempt(
            lease,
            passed=True,
            feedback=(
                {
                    "check": "unit",
                    "passed": True,
                    "exitCode": 0,
                    "timedOut": False,
                    "truncated": False,
                    "stdout": "ok",
                    "stderr": "",
                },
            ),
            cumulative_patch="",
            plan="",
            summary="",
            tests="",
            model_calls=0,
            input_tokens=0,
            output_tokens=0,
            total_tokens=0,
            duration_ms=10,
            judge_duration_ms=5,
            now=101.0,
        )

        captured = crucible.capture_evidence(artifact, world, finished)
        self.assertTrue(captured.trustworthy)
        self.assertEqual(captured.environment_fingerprint, world.fingerprint)
        self.assertEqual(captured.checks[0].name, "unit")
        self.assertTrue(captured.checks[0].passed)

    def test_clone_requires_authorization_never_overwrites_and_emits_receipt(self) -> None:
        artifact = piece()
        with tempfile.TemporaryDirectory() as vault_dir, tempfile.TemporaryDirectory() as target_dir:
            vault = ForgeVault(Path(vault_dir))
            vault.store_piece(artifact)
            cloner = CloneEngine(vault)
            target = Path(target_dir)

            with self.assertRaises(ForgeAuthorizationError):
                cloner.clone(artifact, target, authorized=False)

            receipt = cloner.clone(artifact, target, authorized=True)
            self.assertEqual((target / "contract_registry.py").read_text(), artifact.files[0].content)
            self.assertEqual(receipt.piece_hash, artifact.artifact_hash)
            self.assertEqual(vault.load_clone_receipt(receipt.receipt_id).piece_hash, artifact.artifact_hash)

            with self.assertRaises(ForgeConflict):
                cloner.clone(artifact, target, authorized=True)


if __name__ == "__main__":
    unittest.main()
