"""Fail-closed registry for machine-readable engineering contracts."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any


class ContractRegistryError(ValueError):
    pass


class ContractCategory(StrEnum):
    BEHAVIORAL = "BEHAVIORAL"
    INTERFACE = "INTERFACE"
    SECURITY = "SECURITY"
    DATA = "DATA"
    OPERATIONAL = "OPERATIONAL"
    VERIFICATION = "VERIFICATION"
    COMPLETION = "COMPLETION"


class ContractStatus(StrEnum):
    ACTIVE = "ACTIVE"
    PROPOSED = "PROPOSED"
    DEPRECATED = "DEPRECATED"
    SUPERSEDED = "SUPERSEDED"
    BLOCKED = "BLOCKED"


class AuthorityLevel(StrEnum):
    INFERRED = "INFERRED"
    REFERENCED = "REFERENCED"
    DESIGNATED_DOCUMENTATION = "DESIGNATED_DOCUMENTATION"
    AUTHORITATIVE = "AUTHORITATIVE"


class DerivationMode(StrEnum):
    DIRECT = "direct"
    COMPILED = "compiled"
    INFERRED = "inferred"
    REFERENCED = "referenced"


class VerificationState(StrEnum):
    VERIFIED = "VERIFIED"
    UNVERIFIABLE = "UNVERIFIABLE"
    FAILED = "FAILED"


class EnforcementDecision(StrEnum):
    ALLOW = "ALLOW"
    ALLOW_WITH_WARNINGS = "ALLOW_WITH_WARNINGS"
    REQUIRE_REVIEW = "REQUIRE_REVIEW"
    BLOCK = "BLOCK"


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=lambda item: item.isoformat() if isinstance(item, datetime) else str(item),
    )


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class ContractSource:
    source_type: str
    locator: str
    provenance: dict[str, Any] = field(default_factory=dict)
    authority_level: AuthorityLevel = AuthorityLevel.AUTHORITATIVE
    derivation_mode: DerivationMode = DerivationMode.DIRECT
    verification_state: VerificationState = VerificationState.VERIFIED
    checksum: str | None = None
    parser_version: str | None = None

    def authoritative(self) -> bool:
        return self.authority_level == AuthorityLevel.AUTHORITATIVE


@dataclass(frozen=True)
class ContractVersion:
    contract_id: str
    version: str
    name: str
    category: ContractCategory
    repository: str
    description: str
    source_of_truth: tuple[ContractSource, ...]
    scope: str = ""
    paths: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()
    routes: tuple[str, ...] = ()
    schemas: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    risk_level: str = "LOW"
    authority: str = "authoritative"
    requirements: tuple[str, ...] = ()
    prohibited_changes: tuple[str, ...] = ()
    allowed_changes: tuple[str, ...] = ()
    required_tests: tuple[str, ...] = ()
    required_evidence: tuple[str, ...] = ()
    approval_policy: tuple[str, ...] = ()
    verification_policy: tuple[str, ...] = ()
    compatibility_policy: str | None = None
    failure_behavior: str = "BLOCK"
    supersedes: str | None = None
    superseded_by: str | None = None
    status: ContractStatus = ContractStatus.PROPOSED
    owner: str | None = None
    reviewers: tuple[str, ...] = ()
    applies_to_change_types: tuple[str, ...] = ()
    protected_surfaces: tuple[str, ...] = ()
    required_independent_verifier: bool = False
    digest_algorithm: str = "sha256"
    authority_level: AuthorityLevel = AuthorityLevel.AUTHORITATIVE
    enforcement_level: str = "BLOCK"
    change_control_class: str | None = None
    rationale: str | None = None
    examples: tuple[str, ...] = ()
    non_examples: tuple[str, ...] = ()
    machine_checks: tuple[str, ...] = ()
    human_review_requirements: tuple[str, ...] = ()
    provenance: dict[str, Any] = field(default_factory=dict)
    canonical_ref: str | None = None
    tags: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=_now)
    updated_at: datetime = field(default_factory=_now)

    def normalized(self) -> dict[str, Any]:
        result = asdict(self)
        for key, value in result.items():
            if isinstance(value, datetime):
                result[key] = value.isoformat()
        return result

    def validate_for_activation(self, fallback_approved: bool = False) -> None:
        if not self.source_of_truth:
            raise ContractRegistryError("ACTIVE contracts require a source of truth")
        if self.authority_level == AuthorityLevel.INFERRED or any(
            source.authority_level == AuthorityLevel.INFERRED
            or source.derivation_mode == DerivationMode.INFERRED
            for source in self.source_of_truth
        ):
            raise ContractRegistryError("inferred contracts cannot become ACTIVE authority")
        if (
            any(
                source.verification_state != VerificationState.VERIFIED
                for source in self.source_of_truth
            )
            and not fallback_approved
        ):
            raise ContractRegistryError("unverifiable sources cannot back an ACTIVE contract")


@dataclass(frozen=True)
class ContractDigest:
    digest_value: str
    contract_set: tuple[tuple[str, str], ...]
    normalization_version: str
    reasoning: tuple[str, ...]
    bound_object_type: str | None = None
    bound_object_id: str | None = None
    digest_algorithm: str = "sha256"
    created_at: datetime = field(default_factory=_now)


@dataclass(frozen=True)
class ApplicabilityRequest:
    repository: str
    changed_files: tuple[str, ...] = ()
    changed_symbols: tuple[str, ...] = ()
    changed_routes: tuple[str, ...] = ()
    changed_schemas: tuple[str, ...] = ()
    changed_dependencies: tuple[str, ...] = ()
    protected_surfaces: tuple[str, ...] = ()
    intent: str = ""


@dataclass(frozen=True)
class ApplicabilityDecision:
    applicable_contracts: tuple[ContractVersion, ...]
    blocked: bool
    reasons: tuple[str, ...]
    prohibited_actions: tuple[str, ...]
    required_tests: tuple[str, ...]
    required_evidence: tuple[str, ...]
    required_approvals: tuple[str, ...]
    required_independent_verifier: bool
    digest_preview: ContractDigest
    confidence: float


@dataclass(frozen=True)
class DiffContractAnalysis:
    touched_contracts: tuple[tuple[str, str], ...]
    violated_contracts: tuple[str, ...]
    possibly_weakened_contracts: tuple[str, ...]
    protected_surfaces: tuple[str, ...]
    interface_changes: tuple[str, ...]
    schema_changes: tuple[str, ...]
    security_changes: tuple[str, ...]
    compatibility_changes: tuple[str, ...]
    missing_tests: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    approval_escalations: tuple[str, ...]
    final_decision: EnforcementDecision
    reasoning: tuple[str, ...]


@dataclass(frozen=True)
class ApprovalRecord:
    subject_id: str
    contract_digest: str
    approver: str
    policy: str
    approved: bool = True


@dataclass(frozen=True)
class VerificationRecord:
    subject_id: str
    contract_digest: str
    verifier: str
    independent: bool
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class CompletionDecision:
    digest_match: bool
    all_required_tests_present: bool
    all_required_evidence_present: bool
    independent_verification_present: bool
    approvals_satisfied: bool
    remaining_blocks: tuple[str, ...]
    completion_status: EnforcementDecision


class ContractRegistryStore:
    """Append-only SQLite persistence for registry records and audit history."""

    _KINDS = (
        "ContractDefinition",
        "ContractVersion",
        "ContractSource",
        "ApplicabilityDecision",
        "ContractDigest",
        "DiffContractAnalysis",
        "EvidenceRecord",
        "ApprovalRecord",
        "VerificationRecord",
        "CompletionDecision",
        "AuditEvent",
    )

    def __init__(self, path: Path | str) -> None:
        self._connection = sqlite3.connect(path)
        self._connection.execute(
            """CREATE TABLE IF NOT EXISTS contract_registry_events
            (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, subject_id TEXT NOT NULL,
             payload TEXT NOT NULL, created_at TEXT NOT NULL)"""
        )
        self._connection.commit()

    def append(self, kind: str, subject_id: str, payload: object) -> None:
        if kind not in self._KINDS:
            raise ContractRegistryError("unknown registry record kind")
        value: object
        if is_dataclass(payload) and not isinstance(payload, type):
            value = asdict(payload)
        else:
            value = payload
        self._connection.execute(
            "INSERT INTO contract_registry_events"
            "(kind, subject_id, payload, created_at) VALUES(?,?,?,?)",
            (kind, subject_id, _canonical(value), _now().isoformat()),
        )
        self._connection.commit()

    def history(self, subject_id: str) -> list[dict[str, Any]]:
        return [
            {"kind": row[0], "payload": json.loads(row[1]), "created_at": row[2]}
            for row in self._connection.execute(
                "SELECT kind, payload, created_at FROM contract_registry_events "
                "WHERE subject_id = ? ORDER BY id",
                (subject_id,),
            )
        ]

    def close(self) -> None:
        self._connection.close()


class ContractRegistry:
    """Deterministic, fail-closed contract governance service."""

    NORMALIZATION_VERSION = "liltweak-contract-normalization-v1"

    def __init__(self, store: ContractRegistryStore | None = None) -> None:
        self._versions: dict[tuple[str, str], ContractVersion] = {}
        self._store = store

    def create(self, contract: ContractVersion) -> ContractVersion:
        key = (contract.contract_id, contract.version)
        if key in self._versions:
            raise ContractRegistryError("contract version already exists; contracts are immutable")
        self._versions[key] = contract
        self._audit("ContractVersion", contract.contract_id, contract)
        return contract

    def propose(self, contract: ContractVersion, actor: str) -> ContractVersion:
        if contract.status != ContractStatus.PROPOSED:
            raise ContractRegistryError("new contract changes must begin PROPOSED")
        return self.create(contract)

    def version(self, contract: ContractVersion, actor: str) -> ContractVersion:
        """Record a proposed immutable version; activation remains separately approved."""
        return self.propose(contract, actor)

    def deprecate(self, contract_id: str, version: str) -> ContractVersion:
        contract = self.lookup(contract_id, version)
        deprecated = ContractVersion(
            **{**contract.__dict__, "status": ContractStatus.DEPRECATED, "updated_at": _now()}
        )
        self._versions[(contract_id, version)] = deprecated
        self._audit("AuditEvent", contract_id, {"event": "deprecated", "version": version})
        return deprecated

    def activate(
        self,
        contract_id: str,
        version: str,
        approvals: tuple[ApprovalRecord, ...],
        *,
        fallback_approved: bool = False,
    ) -> ContractVersion:
        contract = self.lookup(contract_id, version)
        contract.validate_for_activation(fallback_approved)
        if contract.approval_policy and not any(
            approval.approved
            and approval.contract_digest == self.digest((contract,), ()).digest_value
            for approval in approvals
        ):
            raise ContractRegistryError("required contract-change approval is missing or stale")
        active = ContractVersion(
            **{**contract.__dict__, "status": ContractStatus.ACTIVE, "updated_at": _now()}
        )
        self._versions[(contract_id, version)] = active
        self._audit("AuditEvent", contract_id, {"event": "activated", "version": version})
        return active

    def supersede(
        self, old_id: str, old_version: str, successor: ContractVersion
    ) -> ContractVersion:
        old = self.lookup(old_id, old_version)
        if successor.supersedes != f"{old_id}@{old_version}":
            raise ContractRegistryError("successor must explicitly supersede the prior version")
        self.create(successor)
        self._versions[(old_id, old_version)] = ContractVersion(
            **{
                **old.__dict__,
                "status": ContractStatus.SUPERSEDED,
                "superseded_by": f"{successor.contract_id}@{successor.version}",
                "updated_at": _now(),
            }
        )
        return successor

    def lookup(self, contract_id: str, version: str | None = None) -> ContractVersion:
        choices = [
            item for (identifier, _), item in self._versions.items() if identifier == contract_id
        ]
        if version is not None:
            item = self._versions.get((contract_id, version))
            if item is None:
                raise ContractRegistryError("contract version not found")
            return item
        active = [item for item in choices if item.status == ContractStatus.ACTIVE]
        if len(active) != 1:
            raise ContractRegistryError("contract lookup is ambiguous or has no ACTIVE version")
        return active[0]

    def digest(
        self,
        contracts: tuple[ContractVersion, ...],
        reasoning: tuple[str, ...],
        bound_object_type: str | None = None,
        bound_object_id: str | None = None,
    ) -> ContractDigest:
        ordered = tuple(sorted(contracts, key=lambda item: (item.contract_id, item.version)))
        payload = {
            "normalization_version": self.NORMALIZATION_VERSION,
            "contracts": [item.normalized() for item in ordered],
            "reasoning": sorted(reasoning),
        }
        return ContractDigest(
            digest_value=hashlib.sha256(_canonical(payload).encode()).hexdigest(),
            contract_set=tuple((item.contract_id, item.version) for item in ordered),
            normalization_version=self.NORMALIZATION_VERSION,
            reasoning=tuple(sorted(reasoning)),
            bound_object_type=bound_object_type,
            bound_object_id=bound_object_id,
        )

    def applicable(self, request: ApplicabilityRequest) -> ApplicabilityDecision:
        matches: list[ContractVersion] = []
        reasons: list[str] = []
        blocked: list[str] = []
        for contract in self._versions.values():
            if (
                contract.repository != request.repository
                or contract.status != ContractStatus.ACTIVE
            ):
                continue
            direct = any(
                path == candidate or path.startswith(f"{candidate.rstrip('/')}/")
                for path in request.changed_files
                for candidate in contract.paths
            )
            declared = bool(
                set(contract.symbols) & set(request.changed_symbols)
                or set(contract.routes) & set(request.changed_routes)
                or set(contract.schemas) & set(request.changed_schemas)
                or set(contract.dependencies) & set(request.changed_dependencies)
                or set(contract.protected_surfaces) & set(request.protected_surfaces)
            )
            protected_ambiguity = bool(
                set(contract.protected_surfaces) & set(request.protected_surfaces)
            )
            if direct or declared or protected_ambiguity:
                matches.append(contract)
                reasons.append(
                    f"{contract.contract_id}@{contract.version} applies by declared scope"
                )
                if protected_ambiguity and contract.category in {
                    ContractCategory.SECURITY,
                    ContractCategory.COMPLETION,
                }:
                    reasons.append(
                        f"protected surface requires inclusion of {contract.contract_id}"
                    )
        conflicts = self._conflicts(matches)
        if conflicts:
            blocked.extend(conflicts)
        digest = self.digest(tuple(matches), tuple(reasons))
        return ApplicabilityDecision(
            tuple(matches),
            bool(blocked),
            tuple(reasons + blocked),
            tuple(sorted({x for item in matches for x in item.prohibited_changes})),
            tuple(sorted({x for item in matches for x in item.required_tests})),
            tuple(sorted({x for item in matches for x in item.required_evidence})),
            tuple(sorted({x for item in matches for x in item.approval_policy})),
            any(item.required_independent_verifier for item in matches),
            digest,
            1.0 if matches else 0.0,
        )

    def analyze_diff(
        self,
        request: ApplicabilityRequest,
        completed_tests: tuple[str, ...] = (),
        evidence: tuple[str, ...] = (),
        weakening: tuple[str, ...] = (),
    ) -> DiffContractAnalysis:
        decision = self.applicable(request)
        missing_tests = tuple(sorted(set(decision.required_tests) - set(completed_tests)))
        missing_evidence = tuple(sorted(set(decision.required_evidence) - set(evidence)))
        weakened = tuple(
            sorted(set(weakening) & {c.contract_id for c in decision.applicable_contracts})
        )
        protected = tuple(
            sorted({x for c in decision.applicable_contracts for x in c.protected_surfaces})
        )
        critical = any(
            c.contract_id in weakened
            and c.category
            in {
                ContractCategory.SECURITY,
                ContractCategory.VERIFICATION,
                ContractCategory.COMPLETION,
            }
            for c in decision.applicable_contracts
        )
        exact_commit_missing = "exact-commit-ci" in missing_evidence
        block = decision.blocked or critical or exact_commit_missing
        review = bool(missing_tests or missing_evidence or weakened)
        final = (
            EnforcementDecision.BLOCK
            if block
            else (EnforcementDecision.REQUIRE_REVIEW if review else EnforcementDecision.ALLOW)
        )
        return DiffContractAnalysis(
            decision.digest_preview.contract_set,
            weakened,
            weakened,
            protected,
            tuple(
                c.contract_id
                for c in decision.applicable_contracts
                if c.category == ContractCategory.INTERFACE
            ),
            tuple(
                c.contract_id
                for c in decision.applicable_contracts
                if c.category == ContractCategory.DATA
            ),
            tuple(
                c.contract_id
                for c in decision.applicable_contracts
                if c.category == ContractCategory.SECURITY
            ),
            tuple(c.contract_id for c in decision.applicable_contracts if c.compatibility_policy),
            missing_tests,
            missing_evidence,
            decision.required_approvals,
            final,
            tuple(decision.reasons)
            + (("protected contract weakening blocks",) if critical else ())
            + (("exact-commit CI evidence is missing",) if exact_commit_missing else ()),
        )

    def completion(
        self,
        subject_id: str,
        authorized_digest: ContractDigest,
        verification_digest: str,
        builder: str,
        approvals: tuple[ApprovalRecord, ...],
        verifications: tuple[VerificationRecord, ...],
        tests: tuple[str, ...],
        evidence: tuple[str, ...],
    ) -> CompletionDecision:
        contracts = tuple(
            self.lookup(identifier, version)
            for identifier, version in authorized_digest.contract_set
        )
        required_tests = {x for contract in contracts for x in contract.required_tests}
        required_evidence = {x for contract in contracts for x in contract.required_evidence}
        independent_required = any(contract.required_independent_verifier for contract in contracts)
        independent = any(
            record.subject_id == subject_id
            and record.contract_digest == authorized_digest.digest_value
            and record.independent
            and record.verifier != builder
            for record in verifications
        )
        approved = all(
            any(
                record.approved
                and record.subject_id == subject_id
                and record.contract_digest == authorized_digest.digest_value
                for record in approvals
            )
            for _ in ({x for contract in contracts for x in contract.approval_policy} or {""})
        )
        blocks: list[str] = []
        if verification_digest != authorized_digest.digest_value:
            blocks.append("contract digest mismatch")
        if not required_tests <= set(tests):
            blocks.append("required tests are missing")
        if not required_evidence <= set(evidence):
            blocks.append("required evidence is missing")
        if independent_required and not independent:
            blocks.append("independent verification is missing")
        if not approved:
            blocks.append("required approval is missing or stale")
        return CompletionDecision(
            verification_digest == authorized_digest.digest_value,
            required_tests <= set(tests),
            required_evidence <= set(evidence),
            not independent_required or independent,
            approved,
            tuple(blocks),
            EnforcementDecision.BLOCK if blocks else EnforcementDecision.ALLOW,
        )

    def _conflicts(self, contracts: list[ContractVersion]) -> list[str]:
        conflicts: list[str] = []
        for contract in contracts:
            authoritative = [
                source for source in contract.source_of_truth if source.authoritative()
            ]
            if len({source.checksum for source in authoritative if source.checksum}) > 1:
                conflicts.append(f"conflicting authoritative sources for {contract.contract_id}")
            if contract.status == ContractStatus.DEPRECATED and contract.superseded_by:
                conflicts.append(
                    f"deprecated contract {contract.contract_id} cannot be sole authority"
                )
        return conflicts

    def _audit(self, kind: str, subject_id: str, payload: object) -> None:
        if self._store is not None:
            self._store.append(kind, subject_id, payload)
