"""Deterministic contract selection and precedence for the registry."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .registry_canonical import decision_binding, sha256_digest
from .registry_validation import validate_approval, validate_evidence
from .registry_types import (
    Asset,
    ContractVersion,
    ContractVersionRef,
    Decision,
    DecisionRequest,
    Environment,
    ExecutionMode,
    OperationIntent,
    Principal,
    PrincipalStatus,
    ReasonCode,
)

_AUTHORITY_ORDER = {
    ExecutionMode.BLOCKED: 0,
    ExecutionMode.EXPLAIN_ONLY: 1,
    ExecutionMode.DRAFT_CODE: 2,
    ExecutionMode.PREPARE_PATCH: 3,
    ExecutionMode.APPLY_SANDBOX: 4,
    ExecutionMode.APPLY_NON_PRODUCTION: 5,
}


def _most_restrictive(modes: Iterable[ExecutionMode]) -> ExecutionMode:
    return min(modes, key=_AUTHORITY_ORDER.__getitem__)


def _utc_now(now: datetime | None) -> datetime:
    value = datetime.now(timezone.utc) if now is None else now
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("decision time must be timezone-aware")
    if value.utcoffset() != timedelta(0):
        raise ValueError("decision time must use UTC")
    return value


def _sorted_reasons(reasons: Iterable[ReasonCode]) -> tuple[ReasonCode, ...]:
    return tuple(sorted(set(reasons), key=lambda reason: reason.value))


def _make_decision(
    request: DecisionRequest,
    *,
    now: datetime,
    mode: ExecutionMode,
    reasons: Iterable[ReasonCode] = (),
    contracts: Iterable[ContractVersion] = (),
    required_approval_ids: Iterable[str] = (),
    required_evidence_types: Iterable[str] = (),
) -> Decision:
    references = tuple(
        sorted(
            (
                ContractVersionRef(
                    contract_id=contract.contract_id,
                    version=contract.version,
                    digest=sha256_digest(contract),
                )
                for contract in contracts
            ),
            key=lambda reference: (
                reference.contract_id,
                reference.version,
                reference.digest,
            ),
        )
    )
    digests = tuple(reference.digest for reference in references)
    binding = decision_binding(request, digests)
    return Decision(
        decision_id=f"decision:{binding[:24]}",
        owner_id=request.owner_id,
        request=request,
        contract_versions=references,
        contract_digests=digests,
        recommended_mode=mode,
        reason_codes=_sorted_reasons(reasons),
        required_approval_ids=tuple(sorted(set(required_approval_ids))),
        required_evidence_types=tuple(sorted(set(required_evidence_types))),
        decision_digest=binding,
        created_at=now,
        enforced=False,
    )


def _owner_records(records: Iterable[object], owner_id: str, expected_type: type) -> tuple[object, ...]:
    materialized = tuple(records)
    for record in materialized:
        if not isinstance(record, expected_type):
            raise TypeError(f"expected {expected_type.__name__} record")
        record.validate()
    return tuple(record for record in materialized if record.owner_id == owner_id)


def _has_duplicate_ids(records: Iterable[object], id_attribute: str) -> bool:
    identities = [getattr(record, id_attribute) for record in records]
    return any(count > 1 for count in Counter(identities).values())


def _matches_scope(request: DecisionRequest, contract: ContractVersion) -> bool:
    return (
        contract.owner_id == request.owner_id
        and request.requester_id in contract.requester_ids
        and request.agent_id in contract.agent_ids
        and request.asset_id in contract.asset_ids
        and request.action_class in contract.action_classes
        and request.operation_intent in contract.operation_intents
        and request.environment in contract.environments
    )


def _hard_prohibited(request: DecisionRequest) -> bool:
    if request.operation_intent in (OperationIntent.PUBLISH, OperationIntent.DEPLOY):
        return True
    if request.operation_intent is OperationIntent.APPLY and request.environment not in (
        Environment.SANDBOX,
        Environment.NON_PRODUCTION,
    ):
        return True
    if request.environment is Environment.PRODUCTION and request.operation_intent is not OperationIntent.READ:
        return True
    return False


def resolve_contracts(
    request,
    contracts,
    *,
    principals,
    assets,
    approvals=(),
    evidence=(),
    now=None,
) -> Decision:
    """Resolve the most restrictive deterministic registry decision.

    ``principals`` and ``assets`` are trusted store records.  They are resolved before
    contract matching so an absent authority record can never be mistaken for a valid
    no-match decision.
    """

    decision_time: datetime | None = None
    try:
        if not isinstance(request, DecisionRequest):
            raise TypeError("request must be DecisionRequest")
        request.validate()
        decision_time = _utc_now(now)

        owner_principals = _owner_records(principals, request.owner_id, Principal)
        owner_assets = _owner_records(assets, request.owner_id, Asset)

        if _has_duplicate_ids(owner_principals, "principal_id") or _has_duplicate_ids(owner_assets, "asset_id"):
            return _make_decision(
                request,
                now=decision_time,
                mode=ExecutionMode.BLOCKED,
                reasons=(ReasonCode.AMBIGUOUS_REQUEST,),
            )

        principals_by_id = {principal.principal_id: principal for principal in owner_principals}
        required_principals = (
            principals_by_id.get(request.requester_id),
            principals_by_id.get(request.agent_id),
        )
        if any(
            principal is None or principal.status is not PrincipalStatus.ACTIVE
            for principal in required_principals
        ):
            return _make_decision(
                request,
                now=decision_time,
                mode=ExecutionMode.BLOCKED,
                reasons=(ReasonCode.INACTIVE_PRINCIPAL,),
            )

        assets_by_id = {asset.asset_id: asset for asset in owner_assets}
        asset = assets_by_id.get(request.asset_id)
        if asset is None or not asset.active:
            return _make_decision(
                request,
                now=decision_time,
                mode=ExecutionMode.BLOCKED,
                reasons=(ReasonCode.UNKNOWN_ASSET,),
            )
        if asset.prohibited:
            return _make_decision(
                request,
                now=decision_time,
                mode=ExecutionMode.BLOCKED,
                reasons=(ReasonCode.PROHIBITED_TARGET,),
            )

        if _hard_prohibited(request):
            return _make_decision(
                request,
                now=decision_time,
                mode=ExecutionMode.BLOCKED,
                reasons=(ReasonCode.PROHIBITED_ACTION,),
            )

        materialized_contracts = tuple(contracts)
        for contract in materialized_contracts:
            if not isinstance(contract, ContractVersion):
                raise TypeError("contracts must contain ContractVersion records")
            contract.validate()

        scope_matches = tuple(
            contract for contract in materialized_contracts if _matches_scope(request, contract)
        )
        active_matches = tuple(
            contract
            for contract in scope_matches
            if contract.effective_at <= decision_time
            and (contract.expires_at is None or decision_time < contract.expires_at)
        )

        if not active_matches:
            temporal_reasons: list[ReasonCode] = []
            if any(decision_time < contract.effective_at for contract in scope_matches):
                temporal_reasons.append(ReasonCode.CONTRACT_NOT_EFFECTIVE)
            if any(
                contract.expires_at is not None and decision_time >= contract.expires_at
                for contract in scope_matches
            ):
                temporal_reasons.append(ReasonCode.CONTRACT_EXPIRED)
            if temporal_reasons:
                return _make_decision(
                    request,
                    now=decision_time,
                    mode=ExecutionMode.BLOCKED,
                    reasons=temporal_reasons,
                )
            return _make_decision(
                request,
                now=decision_time,
                mode=ExecutionMode.EXPLAIN_ONLY,
                reasons=(ReasonCode.NO_MATCHING_CONTRACT,),
            )

        active_ids = Counter(contract.contract_id for contract in active_matches)
        if any(count > 1 for count in active_ids.values()):
            return _make_decision(
                request,
                now=decision_time,
                mode=ExecutionMode.BLOCKED,
                reasons=(ReasonCode.CONFLICTING_ACTIVE_CONTRACTS,),
                contracts=active_matches,
            )

        required_approval_ids = {
            approval_id
            for contract in active_matches
            for approval_id in contract.required_approval_ids
        }
        required_evidence_types = {
            evidence_type
            for contract in active_matches
            for evidence_type in contract.required_evidence_types
        }

        if any(contract.prohibited for contract in active_matches):
            return _make_decision(
                request,
                now=decision_time,
                mode=ExecutionMode.BLOCKED,
                reasons=(ReasonCode.PROHIBITED_ACTION,),
                contracts=active_matches,
                required_approval_ids=required_approval_ids,
                required_evidence_types=required_evidence_types,
            )

        references = tuple(
            sorted(
                (ContractVersionRef(c.contract_id, c.version, sha256_digest(c)) for c in active_matches),
                key=lambda ref: (ref.contract_id, ref.version, ref.digest),
            )
        )
        decision_target = decision_binding(request, tuple(ref.digest for ref in references))
        contract_targets = {c.contract_id: sha256_digest(c) for c in active_matches}

        approval_records = tuple(approvals)
        evidence_records = tuple(evidence)
        approval_reasons: list[ReasonCode] = []
        evidence_reasons: list[ReasonCode] = []

        for contract in active_matches:
            for approval_id in contract.required_approval_ids:
                candidates = tuple(
                    record for record in approval_records
                    if getattr(record, "owner_id", None) == request.owner_id
                    and getattr(record, "approval_id", None) == approval_id
                )
                if not candidates:
                    approval_reasons.append(ReasonCode.MISSING_REQUIRED_APPROVAL)
                    continue
                if len(candidates) != 1:
                    approval_reasons.append(ReasonCode.INTEGRITY_CHECK_FAILED)
                    continue
                record = candidates[0]
                target = (
                    decision_target
                    if getattr(record, "target_digest", None) == decision_target
                    else contract_targets[contract.contract_id]
                )
                reason = validate_approval(record, request, target, decision_time)
                if reason is not None:
                    approval_reasons.append(reason)

        allowed_evidence_targets = (decision_target,) + tuple(ref.digest for ref in references)
        for evidence_type in required_evidence_types:
            candidates = tuple(
                reference for reference in evidence_records
                if getattr(reference, "owner_id", None) == request.owner_id
                and getattr(reference, "evidence_type", None) == evidence_type
            )
            if not candidates:
                evidence_reasons.append(ReasonCode.MISSING_REQUIRED_EVIDENCE)
                continue
            valid = False
            candidate_reasons: list[ReasonCode] = []
            for reference in candidates:
                target = getattr(reference, "target_digest", None)
                expected = target if target in allowed_evidence_targets else decision_target
                reason = validate_evidence(reference, request, expected)
                if reason is None:
                    valid = True
                    break
                candidate_reasons.append(reason)
            if not valid:
                evidence_reasons.append(
                    sorted(candidate_reasons, key=lambda reason: reason.value)[0]
                    if candidate_reasons
                    else ReasonCode.MISSING_REQUIRED_EVIDENCE
                )

        validation_reasons = approval_reasons + evidence_reasons
        if validation_reasons:
            return _make_decision(
                request,
                now=decision_time,
                mode=ExecutionMode.BLOCKED,
                reasons=validation_reasons,
                contracts=active_matches,
                required_approval_ids=required_approval_ids,
                required_evidence_types=required_evidence_types,
            )

        mode = _most_restrictive(contract.mode for contract in active_matches)
        return _make_decision(
            request,
            now=decision_time,
            mode=mode,
            contracts=active_matches,
            required_approval_ids=required_approval_ids,
            required_evidence_types=required_evidence_types,
        )
    except Exception:
        if isinstance(request, DecisionRequest):
            try:
                request.validate()
                safe_time = decision_time if decision_time is not None else _utc_now(now)
                return _make_decision(
                    request,
                    now=safe_time,
                    mode=ExecutionMode.BLOCKED,
                    reasons=(ReasonCode.INTEGRITY_CHECK_FAILED,),
                )
            except Exception:
                pass
        raise
