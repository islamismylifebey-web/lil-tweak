from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from liltweak.creator import (
    AdaptiveRouter,
    CreatorEnvelopeError,
    CreatorInputError,
    CreatorLearningError,
    CreatorService,
    outcome_digest_for_fixture,
)
from liltweak.creator_contract import (
    CreatorBriefEnvelope,
    CreatorCompileRequest,
    CreatorContextItem,
    LearningCandidate,
    ModelTier,
    RoutePreviewRequest,
    RouteStatus,
    VerificationCheck,
    VerifiedOutcome,
    WorkKind,
    content_digest,
)
from liltweak.store import SQLiteStore

SIGNING_KEY = b"C" * 32


def creator_service(path: Path | str = ":memory:") -> CreatorService:
    return CreatorService(
        store=SQLiteStore(path),
        signing_key=SIGNING_KEY,
        durable_signatures=True,
    )


def test_compiler_preserves_founder_direction_and_server_authority() -> None:
    service = creator_service()
    direction = "Build Lil Tweak as a Creator Model API. Keep execution disconnected."
    envelope = service.compile(
        CreatorCompileRequest(direction=direction),
        actor_id="maurice-pennington-bey",
    )
    assert envelope.brief.direction == direction
    assert envelope.brief.objective == direction
    assert envelope.brief.work_kind == WorkKind.ENGINEERING
    assert envelope.brief.authority.actor_id == "maurice-pennington-bey"
    assert envelope.brief.authority.source == "authenticated_server_context"
    assert envelope.brief.authority.permitted_actions == ("compile", "route_preview")
    assert "execution" in envelope.brief.authority.prohibited_actions
    assert envelope.brief.creator_cycle[-1] == "retain_verified_causal_learning"
    assert envelope.brief.input_digest == content_digest(CreatorCompileRequest(direction=direction))


def test_visual_subjective_language_becomes_controls_and_negatives() -> None:
    service = creator_service()
    envelope = service.compile(
        CreatorCompileRequest(
            direction=(
                "Make this image shine more and feel electric, but do not wash out the blue."
            ),
            context=(CreatorContextItem(label="image_asset", value="attached"),),
        ),
        actor_id="owner",
    )
    brief = envelope.brief
    assert brief.work_kind == WorkKind.VISUAL
    assert brief.material_questions == ()
    assert len(brief.quality_controls) == 2
    qualities = " ".join(
        quality for control in brief.quality_controls for quality in control.controllable_qualities
    )
    failures = " ".join(
        failure for control in brief.quality_controls for failure in control.failure_conditions
    )
    assert "specular highlights" in qualities
    assert "saturated accents" in qualities
    assert "clipped highlights" in failures
    assert any("do not wash out the blue" in item.casefold() for item in brief.negative_constraints)


def test_compiler_asks_only_when_target_choice_is_material() -> None:
    service = creator_service()
    unresolved = service.prepare(
        CreatorCompileRequest(direction="Fix it and verify the tests."),
        actor_id="owner",
    )
    assert unresolved.envelope.brief.material_questions == (
        "Which project or repository is the target?",
    )
    assert unresolved.route.status == RouteStatus.NEEDS_INPUT

    resolved = service.prepare(
        CreatorCompileRequest(
            direction="Fix the login bug and verify the tests.",
            context=(CreatorContextItem(label="repository", value="flowsplit"),),
        ),
        actor_id="owner",
    )
    assert resolved.envelope.brief.material_questions == ()
    assert resolved.route.status == RouteStatus.READY


def test_adaptive_router_selects_least_cost_capable_tier() -> None:
    service = creator_service()
    simple = service.prepare(
        CreatorCompileRequest(direction="Write a short project status update."),
        actor_id="owner",
    )
    engineering = service.prepare(
        CreatorCompileRequest(
            direction="Build an API with typed inputs and regression tests.",
        ),
        actor_id="owner",
    )
    complex_engineering = service.prepare(
        CreatorCompileRequest(
            direction=(
                "Design a distributed API architecture with concurrency control, "
                "security invariants, migration recovery, and adversarial tests."
            ),
        ),
        actor_id="owner",
    )
    assert simple.route.selected_tier == ModelTier.ECONOMY
    assert engineering.route.selected_tier == ModelTier.STANDARD
    assert complex_engineering.route.selected_tier == ModelTier.FRONTIER
    for preview in (simple, engineering, complex_engineering):
        assert preview.route.preview_only is True
        assert preview.route.model_call_authorized is False
        assert preview.route.tool_use_authorized is False
        assert preview.route.spend_authorized is False
        assert preview.route.execution_authorized is False


def test_high_stakes_route_requires_trusted_harness_evidence() -> None:
    service = creator_service()
    preview = service.prepare(
        CreatorCompileRequest(
            direction="Recommend a medical treatment and a legal motion for a patient."
        ),
        actor_id="owner",
    )
    assert preview.route.status == RouteStatus.BLOCKED
    assert preview.route.selected_tier is None
    assert preview.route.synthetic_cost_units == 0
    assert preview.envelope.brief.trusted_prerequisites
    assert "trusted harness" in preview.route.blocked_reasons[0]


def test_caller_cannot_add_authority_or_assert_routing_evidence() -> None:
    with pytest.raises(ValueError):
        CreatorCompileRequest.model_validate(
            {
                "direction": "Build the API.",
                "authority": {"permitted_actions": ["execution"]},
            }
        )

    service = creator_service()
    envelope = service.compile(
        CreatorCompileRequest(direction="Write a short summary."),
        actor_id="owner",
    )
    with pytest.raises(ValueError):
        RoutePreviewRequest.model_validate(
            {
                "envelope": envelope.model_dump(mode="json"),
                "evidence": {"execution_is_approved": True},
            }
        )


def test_credential_shaped_input_is_rejected_without_storage() -> None:
    service = creator_service()
    fake_key = "sk-" + "proj-" + ("Q" * 32)
    with pytest.raises(CreatorInputError):
        service.compile(
            CreatorCompileRequest(direction=f"Use {fake_key} to build the app."),
            actor_id="owner",
        )
    assert service.list_learning("anything") == []


def test_digest_bound_brief_rejects_tampering() -> None:
    service = creator_service()
    envelope = service.compile(
        CreatorCompileRequest(direction="Write a short summary."),
        actor_id="owner",
    )
    changed = envelope.brief.model_copy(update={"direction": "Deploy to production."})
    forged = CreatorBriefEnvelope(
        brief=changed,
        brief_digest=changed.brief_digest,
        signature=envelope.signature,
    )
    with pytest.raises(CreatorEnvelopeError):
        service.route(RoutePreviewRequest(envelope=forged))


def test_route_boundary_recomputes_digest_after_model_copy() -> None:
    service = creator_service()
    envelope = service.compile(
        CreatorCompileRequest(direction="Write a short summary."),
        actor_id="owner",
    )
    changed = envelope.brief.model_copy(update={"direction": "Deploy to production."})
    forged = CreatorBriefEnvelope.model_construct(
        brief=changed,
        brief_digest=envelope.brief_digest,
        signature=envelope.signature,
    )
    request = RoutePreviewRequest.model_construct(envelope=forged)

    with pytest.raises(CreatorEnvelopeError, match="brief digest is invalid"):
        service.route(request)


def test_route_boundary_rejects_non_ascii_digest_as_envelope_error() -> None:
    service = creator_service()
    envelope = service.compile(
        CreatorCompileRequest(direction="Write a short summary."),
        actor_id="owner",
    )
    forged = CreatorBriefEnvelope.model_construct(
        brief=envelope.brief,
        brief_digest="é" * 64,
        signature=envelope.signature,
    )

    with pytest.raises(CreatorEnvelopeError, match="brief digest is invalid"):
        service.route(RoutePreviewRequest.model_construct(envelope=forged))


def test_custom_router_override_remains_in_control() -> None:
    class RecordingRouter(AdaptiveRouter):
        def __init__(self) -> None:
            self.called = False

        def route(self, brief):
            self.called = True
            return super().route(brief)

    service = creator_service()
    router = RecordingRouter()
    service.router = router
    envelope = service.compile(
        CreatorCompileRequest(direction="Write a short summary."),
        actor_id="owner",
    )

    service.route(RoutePreviewRequest(envelope=envelope))

    assert router.called is True


def test_instance_router_override_remains_in_control() -> None:
    service = creator_service()
    router = AdaptiveRouter()
    original = router.route
    calls = 0

    def route(brief):
        nonlocal calls
        calls += 1
        return original(brief)

    router.route = route
    service.router = router
    envelope = service.compile(
        CreatorCompileRequest(direction="Write a short summary."),
        actor_id="owner",
    )

    service.route(RoutePreviewRequest(envelope=envelope))

    assert calls == 1


def test_compile_and_route_reuse_only_freshly_verified_digest(monkeypatch) -> None:
    import liltweak.creator as creator_module
    import liltweak.creator_contract as contract_module

    original = contract_module.content_digest
    calls: list[object] = []

    def counted(value: object) -> str:
        calls.append(value)
        return original(value)

    monkeypatch.setattr(contract_module, "content_digest", counted)
    monkeypatch.setattr(creator_module, "content_digest", counted)

    service = creator_service()
    envelope = service.compile(
        CreatorCompileRequest(direction="Build a typed API and targeted tests."),
        actor_id="owner",
    )
    service.route(RoutePreviewRequest(envelope=envelope))

    assert len(calls) == 7


def test_only_signed_observed_outcomes_enter_causal_learning(tmp_path: Path) -> None:
    database = tmp_path / "creator-learning.db"
    service = creator_service(database)
    intervention = outcome_digest_for_fixture("intervention-a")
    outcome = VerifiedOutcome(
        problem_signature="oauth-token-disappears",
        intervention_digest=intervention,
        checks=(
            VerificationCheck(
                check_id="regression-test",
                evidence_digest=outcome_digest_for_fixture("test-output"),
                passed=True,
            ),
            VerificationCheck(
                check_id="browser-observation",
                evidence_digest=outcome_digest_for_fixture("browser-output"),
                passed=True,
            ),
        ),
        executor_session_id="sandbox-session-1",
    )
    candidate = LearningCandidate(
        problem_signature="oauth-token-disappears",
        intervention_digest=intervention,
        causal_claim="Persist the token only on the server after verified callback completion.",
        confounders=("browser cache",),
        reusable_when=("OAuth callback succeeds but the credential is absent after reload",),
    )
    verified = service.verification_authority_for_trusted_harness.sign(outcome)
    record = service.retain_learning(candidate, verified)
    assert record.outcome == "verified_success"
    assert service.retain_learning(candidate, verified).id == record.id

    reopened = creator_service(database)
    retained = reopened.list_learning("oauth-token-disappears")
    assert [item.record_digest for item in retained] == [record.record_digest]


def test_learning_rejects_unsigned_or_mismatched_outcomes() -> None:
    service = creator_service()
    intervention = outcome_digest_for_fixture("intervention-b")
    candidate = LearningCandidate(
        problem_signature="problem-a",
        intervention_digest=intervention,
        causal_claim="A verified fix.",
        reusable_when=("the same invariant fails",),
    )
    outcome = VerifiedOutcome(
        problem_signature="problem-b",
        intervention_digest=intervention,
        checks=(
            VerificationCheck(
                check_id="test",
                evidence_digest=outcome_digest_for_fixture("evidence"),
                passed=False,
            ),
        ),
        executor_session_id="sandbox-session-2",
    )
    verified = service.verification_authority_for_trusted_harness.sign(outcome)
    with pytest.raises(CreatorLearningError):
        service.retain_learning(candidate, verified)

    forged = verified.model_copy(update={"verifier_signature": "0" * 64})
    matching_candidate = candidate.model_copy(update={"problem_signature": "problem-b"})
    with pytest.raises(CreatorLearningError):
        service.retain_learning(matching_candidate, forged)


def test_verified_failure_is_retained_as_failure_not_success() -> None:
    service = creator_service()
    intervention = outcome_digest_for_fixture("intervention-c")
    candidate = LearningCandidate(
        problem_signature="failing-intervention",
        intervention_digest=intervention,
        causal_claim="This intervention does not repair the invariant.",
        reusable_when=("the same rejected intervention is proposed",),
    )
    outcome = VerifiedOutcome(
        problem_signature=candidate.problem_signature,
        intervention_digest=intervention,
        checks=(
            VerificationCheck(
                check_id="targeted-test",
                evidence_digest=outcome_digest_for_fixture("failed-test-output"),
                passed=False,
            ),
        ),
        executor_session_id="sandbox-session-3",
    )
    verified = service.verification_authority_for_trusted_harness.sign(outcome)
    record = service.retain_learning(candidate, verified)
    assert record.outcome == "verified_failure"


def test_causal_learning_detects_database_tampering(tmp_path: Path) -> None:
    database = tmp_path / "creator-tamper.db"
    service = creator_service(database)
    intervention = outcome_digest_for_fixture("intervention-tamper")
    candidate = LearningCandidate(
        problem_signature="tamper-case",
        intervention_digest=intervention,
        causal_claim="Verified claim.",
        reusable_when=("same case",),
    )
    outcome = VerifiedOutcome(
        problem_signature=candidate.problem_signature,
        intervention_digest=intervention,
        checks=(
            VerificationCheck(
                check_id="test",
                evidence_digest=outcome_digest_for_fixture("tamper-evidence"),
                passed=True,
            ),
        ),
        executor_session_id="sandbox-session-tamper",
    )
    verified = service.verification_authority_for_trusted_harness.sign(outcome)
    service.retain_learning(candidate, verified)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE creator_learning SET record_json = ? WHERE problem_signature = ?",
            ("{}", candidate.problem_signature),
        )
    with pytest.raises(CreatorLearningError):
        service.list_learning(candidate.problem_signature)
