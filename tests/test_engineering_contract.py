from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from liltweak.engineering_contract import (
    EngineeringAnalysis,
    EngineeringContractError,
    EngineeringEvidencePacket,
    validate_engineering_analysis,
)


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def _packet() -> EngineeringEvidencePacket:
    first = "The create workflow writes the job and request key in separate transactions."
    second = "Concurrent duplicates produced eight jobs for one request key."
    third = "The request-key table has a unique organization/key constraint."
    return EngineeringEvidencePacket.model_validate(
        {
            "schema_version": "1.0",
            "case_id": "atomicity-race",
            "objective": "Identify the durable cause and smallest safe repair.",
            "evidence_items": [
                {
                    "id": "E1",
                    "kind": "source_excerpt",
                    "path": "liltweak/service.py",
                    "symbol": "LilTweakService.create_job",
                    "line_start": 135,
                    "line_end": 170,
                    "content": first,
                    "sha256": _digest(first),
                },
                {
                    "id": "E2",
                    "kind": "test_result",
                    "path": "tests/test_jobs.py",
                    "symbol": "test_duplicate_create",
                    "content": second,
                    "sha256": _digest(second),
                },
                {
                    "id": "E3",
                    "kind": "constraint",
                    "path": "liltweak/store.py",
                    "symbol": "SQLiteStore.create_job_idempotently",
                    "content": third,
                    "sha256": _digest(third),
                },
            ],
            "required_invariants": [
                {"id": "I1", "statement": "One request key commits at most one job."},
                {"id": "I2", "statement": "Matching duplicates return the same job."},
            ],
        }
    )


def _analysis() -> EngineeringAnalysis:
    return EngineeringAnalysis.model_validate(
        {
            "schema_version": "1.0",
            "case_id": "atomicity-race",
            "objective": "Identify the durable cause and smallest safe repair.",
            "trace": [
                {"evidence_id": "E1", "interpretation": "Writes cross a commit boundary."},
                {"evidence_id": "E2", "interpretation": "The race creates durable orphans."},
                {"evidence_id": "E3", "interpretation": "The key constraint selects one winner."},
            ],
            "hypotheses": [
                {
                    "id": "H1",
                    "statement": "Split commits permit orphan job rows.",
                    "mechanism": "atomicity_violation",
                    "confidence": 0.96,
                    "evidence_ids": ["E1", "E2", "E3"],
                    "contradicting_evidence_ids": [],
                    "falsification": "A single transaction still creates multiple jobs.",
                },
                {
                    "id": "H2",
                    "statement": "The client sends different keys.",
                    "mechanism": "other",
                    "confidence": 0.04,
                    "evidence_ids": ["E2"],
                    "contradicting_evidence_ids": ["E3"],
                    "falsification": "Capture identical keys at the service boundary.",
                },
            ],
            "selected_hypothesis_id": "H1",
            "causal_chain": [
                "Concurrent callers observe no committed key binding.",
                "Each commits a job before one wins the unique key insert.",
                "Losing callers leave orphan jobs.",
            ],
            "minimal_changes": [
                {
                    "path": "liltweak/store.py",
                    "symbol": "SQLiteStore.create_job_idempotently",
                    "change": "Commit the key lookup, job insert, and key binding together.",
                    "evidence_ids": ["E1", "E2", "E3"],
                }
            ],
            "rejected_alternatives": [
                {
                    "hypothesis_id": "H2",
                    "reason": "The unique key observation contradicts different client keys.",
                    "evidence_ids": ["E2", "E3"],
                }
            ],
            "proof_tests": [
                {
                    "name": "concurrent duplicate commit",
                    "setup": "Start eight callers with one payload and request key.",
                    "action": "Release all callers at one barrier.",
                    "expected": "Every caller receives one shared job identifier.",
                    "invariant_ids": ["I1", "I2"],
                    "evidence_ids": ["E1", "E2", "E3"],
                }
            ],
            "insufficient_evidence": False,
            "missing_evidence": [],
            "execution_claimed": False,
            "confidence": 0.96,
        }
    )


def test_valid_analysis_is_digest_bound() -> None:
    packet = _packet()
    analysis = _analysis()
    report = validate_engineering_analysis(packet, analysis)
    assert report.valid
    assert report.packet_digest == packet.digest
    assert report.analysis_digest == analysis.digest
    assert report.covered_invariant_ids == ["I1", "I2"]


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (lambda value: value["trace"].append(value["trace"][0]), "duplicate_trace_citation"),
        (
            lambda value: value["trace"].append(
                {"evidence_id": "E9", "interpretation": "Invented."}
            ),
            "unknown_trace_citation",
        ),
        (
            lambda value: value["minimal_changes"][0].update({"path": "../escape.py"}),
            "invalid_change_path",
        ),
        (
            lambda value: value["minimal_changes"][0].update({"path": "unknown.py"}),
            "unknown_change_path",
        ),
        (
            lambda value: value["minimal_changes"][0].update({"symbol": "invented"}),
            "unknown_change_symbol",
        ),
        (
            lambda value: value.update({"execution_claimed": True}),
            "unsupported_execution_claim",
        ),
        (
            lambda value: value["proof_tests"][0].update({"invariant_ids": ["I9"]}),
            "unknown_test_invariant",
        ),
    ],
)
def test_invalid_analysis_is_rejected(mutation, error: str) -> None:
    packet = _packet()
    payload = _analysis().model_dump(mode="json")
    mutation(payload)
    analysis = EngineeringAnalysis.model_validate(payload)
    with pytest.raises(EngineeringContractError, match=error):
        validate_engineering_analysis(packet, analysis)


def test_generic_template_baseline_is_rejected() -> None:
    packet = _packet()
    payload = _analysis().model_dump(mode="json")
    payload["minimal_changes"] = []
    payload["proof_tests"] = []
    payload["rejected_alternatives"] = []
    analysis = EngineeringAnalysis.model_validate(payload)
    with pytest.raises(EngineeringContractError, match="missing_minimal_change"):
        validate_engineering_analysis(packet, analysis)


def test_insufficient_evidence_requires_no_change_and_discriminator() -> None:
    packet = _packet()
    payload = _analysis().model_dump(mode="json")
    payload["insufficient_evidence"] = True
    payload["minimal_changes"] = []
    payload["proof_tests"] = []
    payload["rejected_alternatives"] = []
    payload["missing_evidence"] = ["A transaction trace from both concurrent callers."]
    analysis = EngineeringAnalysis.model_validate(payload)
    report = validate_engineering_analysis(packet, analysis)
    assert report.change_count == 0


def test_packet_rejects_digest_mismatch() -> None:
    payload = _packet().model_dump(mode="json")
    payload["evidence_items"][0]["content"] = "changed"
    with pytest.raises(ValidationError, match="digest mismatch"):
        EngineeringEvidencePacket.model_validate(payload)


def test_packet_rejects_casefold_path_collision() -> None:
    payload = _packet().model_dump(mode="json")
    payload["evidence_items"][1]["path"] = "LILTWEAK/SERVICE.PY"
    with pytest.raises(ValidationError, match="colliding"):
        EngineeringEvidencePacket.model_validate(payload)


def test_packet_rejects_late_credential_like_material() -> None:
    payload = _packet().model_dump(mode="json")
    marker = "sk-" + "proj-" + ("X" * 32)
    payload["evidence_items"][-1]["content"] = marker
    payload["evidence_items"][-1]["sha256"] = _digest(marker)
    with pytest.raises(ValidationError, match="credential-like"):
        EngineeringEvidencePacket.model_validate(payload)


def test_packet_rejects_sensitive_path_case_insensitively() -> None:
    payload = _packet().model_dump(mode="json")
    payload["evidence_items"][0]["path"] = "config/.ENV.LOCAL"
    with pytest.raises(ValidationError, match="sensitive paths"):
        EngineeringEvidencePacket.model_validate(payload)


def test_packet_rejects_oversized_evidence() -> None:
    payload = _packet().model_dump(mode="json")
    payload["evidence_items"][0]["content"] = "x" * 12_001
    payload["evidence_items"][0]["sha256"] = _digest(payload["evidence_items"][0]["content"])
    with pytest.raises(ValidationError, match="at most 12000"):
        EngineeringEvidencePacket.model_validate(payload)


def test_analysis_rejects_fabricated_past_execution_claim() -> None:
    packet = _packet()
    payload = _analysis().model_dump(mode="json")
    payload["causal_chain"][0] = "We ran the full suite before selecting this cause."
    analysis = EngineeringAnalysis.model_validate(payload)
    with pytest.raises(EngineeringContractError, match="unsupported_execution_claim"):
        validate_engineering_analysis(packet, analysis)
