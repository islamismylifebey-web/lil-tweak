from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from core.lil_tweak.registry_canonical import sha256_digest
from core.lil_tweak.registry_decision import resolve_contracts
from core.lil_tweak.registry_types import (
    ActionClass,
    Asset,
    AssetType,
    ContractVersion,
    DecisionRequest,
    Environment,
    ExecutionMode,
    OperationIntent,
    Principal,
    PrincipalStatus,
    ReasonCode,
)

OWNER = "owner-12345678"
NOW = datetime(2026, 9, 4, 8, 0, tzinfo=timezone.utc)
REVISION = "b" * 40
REQUEST = DecisionRequest(
    owner_id=OWNER,
    requester_id="principal:requester",
    agent_id="principal:lil-tweak",
    asset_id="asset:lil-tweak",
    action_class=ActionClass.CODE_GENERATION,
    operation_intent=OperationIntent.PROPOSE,
    environment=Environment.REPOSITORY,
    source_revision=REVISION,
)
PRINCIPALS = (
    Principal(OWNER, REQUEST.requester_id, PrincipalStatus.ACTIVE),
    Principal(OWNER, REQUEST.agent_id, PrincipalStatus.ACTIVE),
)
ASSETS = (
    Asset(OWNER, REQUEST.asset_id, AssetType.REPOSITORY, "github:islamismylifebey-web/lil-tweak"),
)


def contract(
    contract_id: str,
    *,
    version: int = 1,
    mode: ExecutionMode = ExecutionMode.DRAFT_CODE,
    prohibited: bool = False,
    requester_ids: tuple[str, ...] = (REQUEST.requester_id,),
    agent_ids: tuple[str, ...] = (REQUEST.agent_id,),
    asset_ids: tuple[str, ...] = (REQUEST.asset_id,),
    action_classes: tuple[ActionClass, ...] = (REQUEST.action_class,),
    operation_intents: tuple[OperationIntent, ...] = (REQUEST.operation_intent,),
    environments: tuple[Environment, ...] = (REQUEST.environment,),
    effective_at: datetime = NOW - timedelta(hours=1),
    expires_at: datetime | None = NOW + timedelta(hours=1),
    approvals: tuple[str, ...] = (),
    evidence: tuple[str, ...] = (),
) -> ContractVersion:
    return ContractVersion(
        owner_id=OWNER,
        contract_id=contract_id,
        version=version,
        requester_ids=requester_ids,
        agent_ids=agent_ids,
        asset_ids=asset_ids,
        action_classes=action_classes,
        operation_intents=operation_intents,
        environments=environments,
        mode=mode,
        effective_at=effective_at,
        expires_at=expires_at,
        prohibited=prohibited,
        required_approval_ids=approvals,
        required_evidence_types=evidence,
    )


def resolve(request=REQUEST, contracts=(), *, principals=PRINCIPALS, assets=ASSETS, now=NOW):
    return resolve_contracts(
        request,
        contracts,
        principals=principals,
        assets=assets,
        now=now,
    )


class RegistryDecisionTests(unittest.TestCase):
    def test_valid_request_with_no_matching_contract_is_explain_only(self):
        decision = resolve()
        self.assertEqual(decision.recommended_mode, ExecutionMode.EXPLAIN_ONLY)
        self.assertEqual(decision.reason_codes, (ReasonCode.NO_MATCHING_CONTRACT,))
        self.assertEqual(decision.contract_versions, ())

    def test_explicit_prohibition_defeats_permission(self):
        decision = resolve(contracts=(contract("contract:permit"), contract("contract:deny", prohibited=True)))
        self.assertEqual(decision.recommended_mode, ExecutionMode.BLOCKED)
        self.assertEqual(decision.reason_codes, (ReasonCode.PROHIBITED_ACTION,))

    def test_lowest_authority_compatible_mode_wins(self):
        decision = resolve(
            contracts=(
                contract("contract:draft", mode=ExecutionMode.DRAFT_CODE),
                contract("contract:explain", mode=ExecutionMode.EXPLAIN_ONLY),
            )
        )
        self.assertEqual(decision.recommended_mode, ExecutionMode.EXPLAIN_ONLY)
        self.assertEqual(decision.reason_codes, ())

    def test_approval_requirements_are_unioned_and_sorted(self):
        decision = resolve(
            contracts=(
                contract("contract:b", approvals=("approval:z", "approval:a")),
                contract("contract:a", approvals=("approval:m", "approval:a")),
            )
        )
        self.assertEqual(decision.required_approval_ids, ("approval:a", "approval:m", "approval:z"))

    def test_evidence_requirements_are_unioned_and_sorted(self):
        decision = resolve(
            contracts=(
                contract("contract:b", evidence=("tests", "lint")),
                contract("contract:a", evidence=("lint",)),
            )
        )
        self.assertEqual(decision.required_evidence_types, ("lint", "tests"))

    def test_conflicting_active_versions_of_same_contract_block(self):
        decision = resolve(contracts=(contract("contract:a", version=1), contract("contract:a", version=2)))
        self.assertEqual(decision.recommended_mode, ExecutionMode.BLOCKED)
        self.assertEqual(decision.reason_codes, (ReasonCode.CONFLICTING_ACTIVE_CONTRACTS,))

    def test_contract_not_yet_effective_blocks_when_it_is_the_only_scope_match(self):
        decision = resolve(contracts=(contract("contract:future", effective_at=NOW + timedelta(minutes=1), expires_at=NOW + timedelta(hours=2)),))
        self.assertEqual(decision.recommended_mode, ExecutionMode.BLOCKED)
        self.assertEqual(decision.reason_codes, (ReasonCode.CONTRACT_NOT_EFFECTIVE,))

    def test_expired_contract_blocks_when_it_is_the_only_scope_match(self):
        decision = resolve(contracts=(contract("contract:old", effective_at=NOW - timedelta(hours=2), expires_at=NOW),))
        self.assertEqual(decision.recommended_mode, ExecutionMode.BLOCKED)
        self.assertEqual(decision.reason_codes, (ReasonCode.CONTRACT_EXPIRED,))

    def test_inactive_required_principal_blocks(self):
        principals = (
            Principal(OWNER, REQUEST.requester_id, PrincipalStatus.INACTIVE),
            Principal(OWNER, REQUEST.agent_id, PrincipalStatus.ACTIVE),
        )
        decision = resolve(principals=principals)
        self.assertEqual(decision.recommended_mode, ExecutionMode.BLOCKED)
        self.assertEqual(decision.reason_codes, (ReasonCode.INACTIVE_PRINCIPAL,))

    def test_missing_required_principal_blocks_as_inactive_principal(self):
        decision = resolve(principals=(PRINCIPALS[1],))
        self.assertEqual(decision.recommended_mode, ExecutionMode.BLOCKED)
        self.assertEqual(decision.reason_codes, (ReasonCode.INACTIVE_PRINCIPAL,))

    def test_duplicate_principal_records_are_ambiguous(self):
        decision = resolve(principals=PRINCIPALS + (PRINCIPALS[0],))
        self.assertEqual(decision.recommended_mode, ExecutionMode.BLOCKED)
        self.assertEqual(decision.reason_codes, (ReasonCode.AMBIGUOUS_REQUEST,))

    def test_unknown_or_inactive_asset_blocks(self):
        cases = (
            (),
            (replace(ASSETS[0], active=False),),
        )
        for assets in cases:
            with self.subTest(assets=assets):
                decision = resolve(assets=assets)
                self.assertEqual(decision.recommended_mode, ExecutionMode.BLOCKED)
                self.assertEqual(decision.reason_codes, (ReasonCode.UNKNOWN_ASSET,))

    def test_duplicate_asset_records_are_ambiguous(self):
        decision = resolve(assets=ASSETS + ASSETS)
        self.assertEqual(decision.recommended_mode, ExecutionMode.BLOCKED)
        self.assertEqual(decision.reason_codes, (ReasonCode.AMBIGUOUS_REQUEST,))

    def test_trusted_prohibited_asset_blocks_target_without_name_rules(self):
        assets = (replace(ASSETS[0], asset_id="asset:ordinary-name", prohibited=True),)
        request = replace(REQUEST, asset_id="asset:ordinary-name")
        decision = resolve(request=request, assets=assets)
        self.assertEqual(decision.recommended_mode, ExecutionMode.BLOCKED)
        self.assertEqual(decision.reason_codes, (ReasonCode.PROHIBITED_TARGET,))

    def test_wrong_environment_action_or_operation_intent_is_no_match(self):
        mismatches = (
            contract("contract:env", environments=(Environment.SANDBOX,)),
            contract("contract:action", action_classes=(ActionClass.ANALYSIS,)),
            contract("contract:intent", operation_intents=(OperationIntent.READ,)),
        )
        for candidate in mismatches:
            with self.subTest(candidate=candidate.contract_id):
                decision = resolve(contracts=(candidate,))
                self.assertEqual(decision.recommended_mode, ExecutionMode.EXPLAIN_ONLY)
                self.assertEqual(decision.reason_codes, (ReasonCode.NO_MATCHING_CONTRACT,))

    def test_production_publish_and_deploy_requests_always_block(self):
        cases = (
            replace(REQUEST, environment=Environment.PRODUCTION),
            replace(REQUEST, operation_intent=OperationIntent.PUBLISH),
            replace(REQUEST, operation_intent=OperationIntent.DEPLOY),
        )
        for request in cases:
            with self.subTest(request=request):
                decision = resolve(request=request)
                self.assertEqual(decision.recommended_mode, ExecutionMode.BLOCKED)
                self.assertIn(ReasonCode.PROHIBITED_ACTION, decision.reason_codes)

    def test_contract_versions_and_digest_are_deterministic(self):
        first = contract("contract:b", version=2)
        second = contract("contract:a", version=3)
        left = resolve(contracts=(first, second))
        right = resolve(contracts=(second, first))
        self.assertEqual(left.contract_versions, right.contract_versions)
        self.assertEqual(left.contract_digests, right.contract_digests)
        self.assertEqual(left.decision_digest, right.decision_digest)
        self.assertEqual(
            tuple(ref.contract_id for ref in left.contract_versions),
            ("contract:a", "contract:b"),
        )
        self.assertEqual(
            left.contract_digests,
            tuple(ref.digest for ref in left.contract_versions),
        )
        self.assertEqual(left.contract_versions[0].digest, sha256_digest(second))

    def test_broad_contract_cannot_weaken_narrower_match(self):
        broad = contract(
            "contract:broad",
            mode=ExecutionMode.APPLY_NON_PRODUCTION,
            requester_ids=(REQUEST.requester_id, "principal:other"),
            asset_ids=(REQUEST.asset_id, "asset:other"),
        )
        narrow = contract("contract:narrow", mode=ExecutionMode.EXPLAIN_ONLY)
        decision = resolve(contracts=(broad, narrow))
        self.assertEqual(decision.recommended_mode, ExecutionMode.EXPLAIN_ONLY)

    def test_internal_failure_never_becomes_explain_only(self):
        class BrokenContracts:
            def __iter__(self):
                raise RuntimeError("simulated store/iteration failure")

        decision = resolve(contracts=BrokenContracts())
        self.assertEqual(decision.recommended_mode, ExecutionMode.BLOCKED)
        self.assertEqual(decision.reason_codes, (ReasonCode.INTEGRITY_CHECK_FAILED,))


if __name__ == "__main__":
    unittest.main()
