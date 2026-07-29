from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import uuid
from dataclasses import dataclass
from typing import Final

from .creator_contract import (
    AuthorityGrant,
    CausalLearningRecord,
    CreatorBrief,
    CreatorBriefEnvelope,
    CreatorCompileRequest,
    CreatorHealth,
    CreatorRunPreview,
    LearningCandidate,
    ModelTier,
    QualityControl,
    ReasoningEffort,
    RiskDomain,
    RouteDecision,
    RoutePreviewRequest,
    RouteStatus,
    VerifiedOutcome,
    VerifiedOutcomeEnvelope,
    WorkKind,
    canonical_json,
    content_digest,
)
from .repository import secret_rule_ids
from .store import SQLiteStore

CREATOR_CYCLE: Final[tuple[str, ...]] = (
    "perceive_reality",
    "identify_functional_gap",
    "discover_constraints",
    "determine_what_must_exist",
    "create_smallest_effective_intervention",
    "test_against_reality",
    "verify_causality",
    "retain_verified_causal_learning",
)


class CreatorInputError(ValueError):
    pass


class CreatorEnvelopeError(ValueError):
    pass


class CreatorLearningError(ValueError):
    pass


def _unique(items: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(item.strip() for item in items if item.strip()))


def _contains_any(text: str, terms: tuple[str, ...]) -> bool:
    return any(term in text for term in terms)


def _extract_sentences(direction: str) -> list[str]:
    return [item.strip() for item in re.split(r"(?<=[.!?])\s+|\n+", direction) if item.strip()]


_KIND_TERMS: Final[dict[WorkKind, tuple[str, ...]]] = {
    WorkKind.ENGINEERING: (
        "api",
        "app",
        "bug",
        "build",
        "code",
        "connector",
        "deploy",
        "engine",
        "fix",
        "implementation",
        "repository",
        "software",
        "test",
        "website",
    ),
    WorkKind.VISUAL: (
        "art",
        "brand",
        "color",
        "design",
        "fez",
        "graphic",
        "image",
        "logo",
        "make it shine",
        "photo",
        "poster",
        "visual",
    ),
    WorkKind.RESEARCH: (
        "deep research",
        "evidence",
        "find sources",
        "look up",
        "research",
        "sources",
        "verify facts",
    ),
    WorkKind.WRITING: (
        "article",
        "book",
        "caption",
        "draft",
        "email",
        "letter",
        "post",
        "prompt",
        "rewrite",
        "write",
    ),
    WorkKind.OPERATIONS: (
        "campaign",
        "crm",
        "customer",
        "email campaign",
        "lead",
        "operations",
        "publish",
        "sales",
        "workflow",
    ),
    WorkKind.ANALYSIS: (
        "analyze",
        "audit",
        "compare",
        "diagnose",
        "evaluate",
        "explain",
        "review",
    ),
}


_RISK_TERMS: Final[dict[RiskDomain, tuple[str, ...]]] = {
    RiskDomain.MEDICAL: (
        "diagnosis",
        "dose",
        "health",
        "medical",
        "medicine",
        "patient",
        "prescription",
        "treatment",
    ),
    RiskDomain.LEGAL: (
        "court",
        "law",
        "legal",
        "lawsuit",
        "motion",
        "probation",
        "statute",
    ),
    RiskDomain.FINANCIAL: (
        "apr",
        "bank",
        "debt",
        "financial",
        "investment",
        "loan",
        "money movement",
        "tax",
        "trade",
    ),
    RiskDomain.SAFETY_CRITICAL: (
        "critical infrastructure",
        "emergency",
        "firearm",
        "life safety",
        "safety-critical",
    ),
    RiskDomain.CREDENTIALS: (
        "api key",
        "credential",
        "oauth secret",
        "password",
        "private key",
        "token",
    ),
    RiskDomain.PRODUCTION: (
        "live database",
        "production",
        "public dns",
        "real customers",
    ),
}


_QUALITY_TRANSLATIONS: Final[dict[str, tuple[tuple[str, ...], tuple[str, ...]]]] = {
    "shine": (
        (
            "controlled specular highlights",
            "luminous contrast",
            "clean edge definition",
            "purposeful glow hierarchy",
        ),
        (
            "no clipped highlights",
            "no muddy midtones",
            "no bloom that obscures text or symbols",
        ),
    ),
    "electric": (
        (
            "high-energy saturated accents",
            "strong local contrast",
            "crisp luminous separation",
        ),
        (
            "no uncontrolled color clipping",
            "no loss of subject legibility",
        ),
    ),
    "clean": (
        (
            "clear hierarchy",
            "consistent spacing",
            "minimal visual noise",
        ),
        (
            "no crowded controls",
            "no ambiguous navigation",
        ),
    ),
    "fast": (
        (
            "least-cost capable route",
            "bounded context and turns",
            "early deterministic checks",
        ),
        (
            "no unnecessary model escalation",
            "no repeated paid attempt without new evidence",
        ),
    ),
    "secure": (
        (
            "least privilege",
            "server-owned authority",
            "credential redaction",
            "evidence-backed approval boundaries",
        ),
        (
            "no secrets in prompts or logs",
            "no caller-asserted authority",
        ),
    ),
    "fluid": (
        (
            "continuous task flow",
            "clear next actions",
            "compact progressive disclosure",
        ),
        (
            "no dead ends",
            "no oversized controls",
        ),
    ),
}


def _safe_request_text(request: CreatorCompileRequest) -> None:
    serialized = request.model_dump_json().encode("utf-8")
    if secret_rule_ids(serialized):
        raise CreatorInputError("creator input contains credential-shaped material")


class PromptCompiler:
    def compile(
        self,
        request: CreatorCompileRequest,
        *,
        actor_id: str,
    ) -> CreatorBrief:
        _safe_request_text(request)
        direction = request.direction.strip()
        lowered = direction.casefold()
        sentences = _extract_sentences(direction)

        kind_scores = {
            kind: sum(1 for term in terms if term in lowered) for kind, terms in _KIND_TERMS.items()
        }
        best_kind, best_score = max(kind_scores.items(), key=lambda item: item[1])
        work_kind = best_kind if best_score else WorkKind.GENERAL

        risk_domains = _unique(
            [domain.value for domain, terms in _RISK_TERMS.items() if _contains_any(lowered, terms)]
        )
        typed_risk_domains = tuple(RiskDomain(item) for item in risk_domains)

        constraints: list[str] = []
        negatives: list[str] = []
        for sentence in sentences:
            normalized = sentence.casefold()
            if _contains_any(normalized, ("must ", "need ", "require", "only ", "keep ")):
                constraints.append(sentence)
            if _contains_any(
                normalized,
                ("do not", "don't", "never ", "without ", " no ", "cannot ", "can't "),
            ) or normalized.startswith("no "):
                negatives.append(sentence)

        quality_controls: list[QualityControl] = []
        for phrase, (qualities, failures) in _QUALITY_TRANSLATIONS.items():
            if phrase in lowered:
                quality_controls.append(
                    QualityControl(
                        source_phrase=phrase,
                        controllable_qualities=qualities,
                        failure_conditions=failures,
                    )
                )

        deliverables = self._deliverables(work_kind, lowered, request.desired_output)
        material_questions = self._material_questions(request, work_kind, lowered)
        prerequisites = self._trusted_prerequisites(typed_risk_domains)
        acceptance = self._acceptance_criteria(
            work_kind,
            deliverables,
            quality_controls,
            typed_risk_domains,
        )

        return CreatorBrief(
            input_digest=content_digest(request),
            direction=direction,
            work_kind=work_kind,
            objective=direction,
            deliverables=deliverables,
            constraints=_unique(constraints),
            negative_constraints=_unique(negatives),
            quality_controls=tuple(quality_controls),
            acceptance_criteria=acceptance,
            material_questions=material_questions,
            risk_domains=typed_risk_domains,
            trusted_prerequisites=prerequisites,
            untrusted_context_labels=tuple(item.label for item in request.context),
            creator_cycle=CREATOR_CYCLE,
            authority=AuthorityGrant(actor_id=actor_id),
        )

    @staticmethod
    def _deliverables(
        work_kind: WorkKind,
        lowered: str,
        desired_output: str | None,
    ) -> tuple[str, ...]:
        requested = [desired_output] if desired_output else []
        by_kind: dict[WorkKind, list[str]] = {
            WorkKind.ENGINEERING: [
                "working implementation or exact bounded change set",
                "targeted automated tests",
                "verification record tied to observed results",
                "rollback or recovery path",
            ],
            WorkKind.VISUAL: [
                "finished visual direction with controllable qualities",
                "negative constraints that protect legibility and intent",
                "render-ready production prompt or edited asset",
            ],
            WorkKind.RESEARCH: [
                "source-backed findings",
                "explicit facts, inferences, and unresolved uncertainty",
                "actionable conclusion within the available evidence",
            ],
            WorkKind.WRITING: [
                "publication-ready draft preserving the requested voice and purpose",
                "final formatting suited to the requested channel",
            ],
            WorkKind.OPERATIONS: [
                "executable operating brief",
                "approval and side-effect boundaries",
                "observable success and failure criteria",
            ],
            WorkKind.ANALYSIS: [
                "evidence-backed diagnosis",
                "ranked causes or options",
                "smallest justified next action",
            ],
            WorkKind.GENERAL: [
                "completed requested outcome",
                "evidence of correctness appropriate to the task",
            ],
        }
        requested.extend(by_kind[work_kind])
        api_contract = "API contract with typed inputs, outputs, and errors"
        if "api" in lowered and api_contract not in requested:
            requested.append(api_contract)
        return _unique(requested)

    @staticmethod
    def _material_questions(
        request: CreatorCompileRequest,
        work_kind: WorkKind,
        lowered: str,
    ) -> tuple[str, ...]:
        context_labels = " ".join(item.label.casefold() for item in request.context)
        questions: list[str] = []
        if work_kind == WorkKind.ENGINEERING and _contains_any(
            lowered, ("build", "fix", "implement", "deploy", "edit")
        ):
            target_present = _contains_any(
                lowered + " " + context_labels,
                ("repository", "repo", "project", "site", "app", "api", ".com", ".works"),
            )
            if not target_present:
                questions.append("Which project or repository is the target?")
        if work_kind == WorkKind.VISUAL and _contains_any(
            lowered, ("edit", "change", "make it", "this image")
        ):
            target_present = _contains_any(
                context_labels,
                ("asset", "image", "logo", "photo", "visual"),
            )
            if not target_present:
                questions.append("Which visual asset should be changed?")
        return _unique(questions)

    @staticmethod
    def _trusted_prerequisites(
        risk_domains: tuple[RiskDomain, ...],
    ) -> tuple[str, ...]:
        if not risk_domains:
            return ()
        prerequisites = [
            "validated current sources supplied by the trusted harness",
            "explicit safety constraints supplied by the trusted harness",
            "approved authority scope supplied by the trusted harness",
        ]
        if any(
            domain
            in {
                RiskDomain.MEDICAL,
                RiskDomain.LEGAL,
                RiskDomain.FINANCIAL,
                RiskDomain.SAFETY_CRITICAL,
            }
            for domain in risk_domains
        ):
            prerequisites.append("qualified domain review recorded by the trusted harness")
        return tuple(prerequisites)

    @staticmethod
    def _acceptance_criteria(
        work_kind: WorkKind,
        deliverables: tuple[str, ...],
        quality_controls: list[QualityControl],
        risk_domains: tuple[RiskDomain, ...],
    ) -> tuple[str, ...]:
        criteria = [
            "The result satisfies the preserved direction without expanding authority.",
            "Every success claim is tied to observable evidence.",
            "Unknowns are labeled and drive discovery rather than fabricated certainty.",
            "The intervention is the smallest one that can satisfy the verified gap.",
        ]
        if work_kind == WorkKind.ENGINEERING:
            criteria.extend(
                [
                    "Baseline and targeted regression checks are defined before completion.",
                    (
                        "No source write, execution, spend, or deployment occurs "
                        "without a separate gate."
                    ),
                ]
            )
        if quality_controls:
            criteria.append("All translated quality controls and failure conditions are checked.")
        if risk_domains:
            criteria.append("Trusted high-stakes prerequisites are present before model routing.")
        criteria.append(f"All {len(deliverables)} declared deliverables are accounted for.")
        return _unique(criteria)


@dataclass(frozen=True)
class ModelProfile:
    tier: ModelTier
    max_complexity: int
    capabilities: frozenset[str]
    context_tokens: int
    max_turns: int
    synthetic_cost_units: float


MODEL_PROFILES: Final[tuple[ModelProfile, ...]] = (
    ModelProfile(
        tier=ModelTier.ECONOMY,
        max_complexity=3,
        capabilities=frozenset({"text", "structured_output"}),
        context_tokens=16_000,
        max_turns=4,
        synthetic_cost_units=1.0,
    ),
    ModelProfile(
        tier=ModelTier.STANDARD,
        max_complexity=7,
        capabilities=frozenset(
            {"text", "structured_output", "code_reasoning", "vision", "long_context"}
        ),
        context_tokens=64_000,
        max_turns=8,
        synthetic_cost_units=3.2,
    ),
    ModelProfile(
        tier=ModelTier.FRONTIER,
        max_complexity=10,
        capabilities=frozenset(
            {
                "text",
                "structured_output",
                "code_reasoning",
                "vision",
                "long_context",
                "deep_reasoning",
                "high_stakes_review",
            }
        ),
        context_tokens=128_000,
        max_turns=12,
        synthetic_cost_units=8.0,
    ),
)


class AdaptiveRouter:
    def route(self, brief: CreatorBrief) -> RouteDecision:
        complexity = self._complexity(brief)
        capabilities = self._required_capabilities(brief)
        blocked_reasons: list[str] = []
        status = RouteStatus.READY
        if brief.material_questions:
            status = RouteStatus.NEEDS_INPUT
            blocked_reasons.append("material choices remain unresolved")
        if brief.trusted_prerequisites:
            status = RouteStatus.BLOCKED
            blocked_reasons.append("high-stakes prerequisites must come from the trusted harness")

        profile = next(
            (
                item
                for item in MODEL_PROFILES
                if complexity <= item.max_complexity and set(capabilities) <= item.capabilities
            ),
            MODEL_PROFILES[-1],
        )
        if status != RouteStatus.READY:
            selected_tier = None
            reasoning_effort = None
            context_tokens = 0
            max_turns = 0
            cost = 0.0
        else:
            selected_tier = profile.tier
            reasoning_effort = self._effort(complexity)
            context_tokens = profile.context_tokens
            max_turns = profile.max_turns
            cost = profile.synthetic_cost_units

        values = {
            "brief_digest": brief.brief_digest,
            "status": status,
            "selected_tier": selected_tier,
            "reasoning_effort": reasoning_effort,
            "context_token_ceiling": context_tokens,
            "max_turns": max_turns,
            "complexity_score": complexity,
            "required_capabilities": capabilities,
            "suggested_tools": self._suggested_tools(brief),
            "blocked_reasons": tuple(blocked_reasons),
            "escalation_triggers": (
                "a deterministic check falsifies the current hypothesis",
                "required evidence cannot fit the selected context ceiling",
                "the selected tier fails one validated attempt",
                "new risk evidence raises the task classification",
            ),
            "deescalation_triggers": (
                "the uncertainty has been resolved by deterministic evidence",
                "remaining work is mechanical or schema-bound",
                "verification can complete without further model reasoning",
            ),
            "synthetic_cost_units": cost,
        }
        unsigned = RouteDecision.model_construct(
            **values,
            decision_digest="0" * 64,
        )
        return RouteDecision(
            **values,
            decision_digest=content_digest(
                unsigned.model_dump(mode="json", exclude={"decision_digest"})
            ),
        )

    @staticmethod
    def _complexity(brief: CreatorBrief) -> int:
        score = 1
        if brief.work_kind == WorkKind.ENGINEERING:
            score += 3
        elif brief.work_kind in {
            WorkKind.RESEARCH,
            WorkKind.ANALYSIS,
            WorkKind.OPERATIONS,
            WorkKind.VISUAL,
        }:
            score += 2
        score += min(2, max(0, len(brief.deliverables) - 2))
        if len(brief.direction) > 1_500:
            score += 1
        lowered = brief.direction.casefold()
        if _contains_any(
            lowered,
            (
                "architecture",
                "concurrency",
                "distributed",
                "migration",
                "security",
                "unknown problem",
            ),
        ):
            score += 2
        if brief.risk_domains:
            score = max(score, 8)
        return min(10, score)

    @staticmethod
    def _required_capabilities(brief: CreatorBrief) -> tuple[str, ...]:
        capabilities = ["text", "structured_output"]
        if brief.work_kind == WorkKind.ENGINEERING:
            capabilities.append("code_reasoning")
        if brief.work_kind == WorkKind.VISUAL:
            capabilities.append("vision")
        if len(brief.direction) > 1_500:
            capabilities.append("long_context")
        if brief.risk_domains:
            capabilities.extend(("deep_reasoning", "high_stakes_review"))
        return _unique(capabilities)

    @staticmethod
    def _suggested_tools(brief: CreatorBrief) -> tuple[str, ...]:
        by_kind = {
            WorkKind.ENGINEERING: ("repository_inspection", "sandbox", "test_runner"),
            WorkKind.VISUAL: ("image_input", "image_generation"),
            WorkKind.RESEARCH: ("validated_search", "source_reader"),
            WorkKind.WRITING: (),
            WorkKind.OPERATIONS: ("approved_connector",),
            WorkKind.ANALYSIS: ("data_reader",),
            WorkKind.GENERAL: (),
        }
        return by_kind[brief.work_kind]

    @staticmethod
    def _effort(complexity: int) -> ReasoningEffort:
        if complexity <= 3:
            return ReasoningEffort.LOW
        if complexity <= 6:
            return ReasoningEffort.MEDIUM
        if complexity <= 8:
            return ReasoningEffort.HIGH
        return ReasoningEffort.XHIGH


class VerificationAuthority:
    """Trusted-harness signer. It is never exposed through the public API."""

    def __init__(self, signing_key: bytes) -> None:
        if len(signing_key) != 32:
            raise ValueError("verification signing key must contain exactly 32 bytes")
        self._key = signing_key

    def sign(self, outcome: VerifiedOutcome) -> VerifiedOutcomeEnvelope:
        digest = outcome.outcome_digest
        signature = hmac.new(
            self._key,
            f"creator-outcome-v1:{digest}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return VerifiedOutcomeEnvelope(
            outcome=outcome,
            outcome_digest=digest,
            verifier_signature=signature,
        )


class CreatorService:
    def __init__(
        self,
        *,
        store: SQLiteStore,
        signing_key: bytes | None = None,
        durable_signatures: bool = False,
    ) -> None:
        if signing_key is None:
            signing_key = secrets.token_bytes(32)
            durable_signatures = False
        if len(signing_key) != 32:
            raise ValueError("creator signing key must contain exactly 32 bytes")
        self.store = store
        self._signing_key = signing_key
        self._durable_signatures = durable_signatures
        self.compiler = PromptCompiler()
        self.router = AdaptiveRouter()

    def health(
        self,
        *,
        model_calls_enabled: bool = False,
        hosted_sandbox_probe_ready: bool = False,
    ) -> CreatorHealth:
        return CreatorHealth(
            durable_brief_signatures=self._durable_signatures,
            model_calls_enabled=model_calls_enabled,
            hosted_sandbox_probe_ready=hosted_sandbox_probe_ready,
        )

    def compile(
        self,
        request: CreatorCompileRequest,
        *,
        actor_id: str,
    ) -> CreatorBriefEnvelope:
        brief = self.compiler.compile(request, actor_id=actor_id)
        signature = self._sign_digest(brief.brief_digest, domain="creator-brief-v1")
        return CreatorBriefEnvelope(
            brief=brief,
            brief_digest=brief.brief_digest,
            signature=signature,
        )

    def route(self, request: RoutePreviewRequest) -> RouteDecision:
        self._verify_brief_envelope(request.envelope)
        return self.router.route(request.envelope.brief)

    def prepare(
        self,
        request: CreatorCompileRequest,
        *,
        actor_id: str,
    ) -> CreatorRunPreview:
        envelope = self.compile(request, actor_id=actor_id)
        route = self.route(RoutePreviewRequest(envelope=envelope))
        if route.status == RouteStatus.READY:
            next_action = (
                "Obtain a separate model/spend approval or continue with deterministic work only."
            )
        elif route.status == RouteStatus.NEEDS_INPUT:
            next_action = "Resolve only the listed material questions, then recompile."
        else:
            next_action = "Supply the trusted prerequisites through the control plane."
        return CreatorRunPreview(
            envelope=envelope,
            route=route,
            next_action=next_action,
        )

    def retain_learning(
        self,
        candidate: LearningCandidate,
        verified: VerifiedOutcomeEnvelope,
    ) -> CausalLearningRecord:
        self._verify_outcome_envelope(verified)
        outcome = verified.outcome
        if candidate.problem_signature != outcome.problem_signature:
            raise CreatorLearningError("learning problem signature does not match verification")
        if candidate.intervention_digest != outcome.intervention_digest:
            raise CreatorLearningError("learning intervention does not match verification")
        if not outcome.checks:
            raise CreatorLearningError("verified learning requires at least one check")

        evidence_digests = tuple(item.evidence_digest for item in outcome.checks)
        status = (
            "verified_success"
            if all(item.passed for item in outcome.checks)
            else "verified_failure"
        )
        record = CausalLearningRecord(
            id=f"learn_{uuid.uuid4().hex}",
            problem_signature=candidate.problem_signature,
            intervention_digest=candidate.intervention_digest,
            outcome_digest=outcome.outcome_digest,
            outcome=status,
            causal_claim=candidate.causal_claim,
            confounders=candidate.confounders,
            reusable_when=candidate.reusable_when,
            evidence_digests=evidence_digests,
        )
        stored = self.store.append_creator_learning(
            record_id=record.id,
            problem_signature=record.problem_signature,
            intervention_digest=record.intervention_digest,
            outcome_digest=record.outcome_digest,
            record_json=record.model_dump_json(),
            record_hash=record.record_digest,
            created_at=record.created_at.isoformat(),
        )
        if not stored:
            existing_entry = self.store.get_creator_learning_by_outcome(record.outcome_digest)
            if existing_entry is None:
                raise CreatorLearningError("verified learning could not be retained")
            existing = self._validated_learning_entry(existing_entry)
            return existing
        return record

    def list_learning(
        self,
        problem_signature: str,
        *,
        limit: int = 20,
    ) -> list[CausalLearningRecord]:
        if not problem_signature or len(problem_signature) > 512:
            raise CreatorLearningError("problem signature is invalid")
        return [
            self._validated_learning_entry(entry)
            for entry in self.store.list_creator_learning(problem_signature, limit=limit)
        ]

    def _verify_brief_envelope(self, envelope: CreatorBriefEnvelope) -> None:
        if envelope.brief.brief_digest != envelope.brief_digest:
            raise CreatorEnvelopeError("creator brief digest is invalid")
        expected = self._sign_digest(envelope.brief_digest, domain="creator-brief-v1")
        if not secrets.compare_digest(expected, envelope.signature):
            raise CreatorEnvelopeError("creator brief signature is invalid")
        if envelope.brief.authority.source != "authenticated_server_context":
            raise CreatorEnvelopeError("creator brief authority is invalid")

    def _verify_outcome_envelope(self, envelope: VerifiedOutcomeEnvelope) -> None:
        if envelope.outcome.outcome_digest != envelope.outcome_digest:
            raise CreatorLearningError("verified outcome digest is invalid")
        expected = self._sign_digest(envelope.outcome_digest, domain="creator-outcome-v1")
        if not secrets.compare_digest(expected, envelope.verifier_signature):
            raise CreatorLearningError("verified outcome signature is invalid")

    def _sign_digest(self, digest: str, *, domain: str) -> str:
        return hmac.new(
            self._signing_key,
            f"{domain}:{digest}".encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _validated_learning_entry(entry: tuple[str, str]) -> CausalLearningRecord:
        payload, stored_hash = entry
        try:
            record = CausalLearningRecord.model_validate_json(payload)
        except Exception as exc:
            raise CreatorLearningError("causal learning record is invalid") from exc
        if not secrets.compare_digest(record.record_digest, stored_hash):
            raise CreatorLearningError("causal learning record integrity failed")
        return record

    @property
    def verification_authority_for_trusted_harness(self) -> VerificationAuthority:
        return VerificationAuthority(self._signing_key)

    def configuration_digest(self) -> str:
        profiles = [
            {
                "tier": item.tier.value,
                "max_complexity": item.max_complexity,
                "capabilities": sorted(item.capabilities),
                "context_tokens": item.context_tokens,
                "max_turns": item.max_turns,
                "synthetic_cost_units": item.synthetic_cost_units,
            }
            for item in MODEL_PROFILES
        ]
        return content_digest(
            {
                "creator_cycle": CREATOR_CYCLE,
                "profiles": profiles,
                "version": "0.6.0",
            }
        )


def outcome_digest_for_fixture(label: str) -> str:
    """Deterministic helper for offline test and evaluation evidence."""
    return hashlib.sha256(canonical_json({"fixture": label}).encode("utf-8")).hexdigest()
