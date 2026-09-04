from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from core.lil_tweak.registry_canonical import sha256_digest
from core.lil_tweak.registry_decision import resolve_contracts
from core.lil_tweak.registry_types import (
    ActionClass,
    ApprovalRecord,
    Asset,
    AssetType,
    ContractVersion,
    DecisionRequest,
    Environment,
    EvidenceReference,
    ExecutionMode,
    OperationIntent,
    Principal,
    PrincipalStatus,
    ReasonCode,
)
from core.lil_tweak.registry_validation import validate_approval, validate_evidence

OWNER = "owner-12345678"
NOW = datetime(2026, 9, 4, 8, 30, tzinfo=timezone.utc)
REVISION = "b" * 40
DIGEST = "a" * 64
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
VALID_APPROVAL = ApprovalRecord(
    owner_id=OWNER,
    approval_id="approval:final",
    approver_id="principal:owner-bound",
    target_digest=DIGEST,
    requester_id=REQUEST.requester_id,
    agent_id=REQUEST.agent_id,
    asset_id=REQUEST.asset_id,
    action_class=REQUEST.action_class,
    operation_intent=REQUEST.operation_intent,
    environment=REQUEST.environment,
    issued_at=NOW - timedelta(minutes=5),
    expires_at=NOW + timedelta(minutes=30),
    authenticated=True,
)


def evidence(locator_class="CORE_DB", locator="registry:evidence:1", source_system="trusted-core"):
    return EvidenceReference(
        owner_id=OWNER,
        evidence_id=f"evidence:{locator_class.lower()}",
        target_digest=DIGEST,
        digest_algorithm="sha256",
        content_digest="c" * 64,
        locator_class=locator_class,
        locator=locator,
        evidence_type="tests",
        source_system=source_system,
        created_at=NOW - timedelta(minutes=1),
        source_revision=REVISION,
        asserted_safe=True,
    )


def corrupt(record, **changes):
    for name, value in changes.items():
        object.__setattr__(record, name, value)
    return record


class RegistryValidationTests(unittest.TestCase):
    def test_valid_exact_approval(self):
        self.assertIsNone(validate_approval(VALID_APPROVAL, REQUEST, DIGEST, NOW))

    def test_revoked_approval(self):
        record = replace(VALID_APPROVAL, revoked_at=NOW - timedelta(seconds=1))
        self.assertEqual(validate_approval(record, REQUEST, DIGEST, NOW), ReasonCode.REVOKED_APPROVAL)

    def test_expired_or_future_issued_approval_is_stale(self):
        expired = replace(
            VALID_APPROVAL,
            issued_at=NOW - timedelta(hours=2),
            expires_at=NOW,
        )
        future = replace(
            VALID_APPROVAL,
            issued_at=NOW + timedelta(minutes=1),
            expires_at=NOW + timedelta(hours=1),
        )
        self.assertEqual(validate_approval(expired, REQUEST, DIGEST, NOW), ReasonCode.STALE_APPROVAL)
        self.assertEqual(validate_approval(future, REQUEST, DIGEST, NOW), ReasonCode.STALE_APPROVAL)

    def test_wrong_owner_principal_asset_action_intent_environment_or_digest(self):
        cases = (
            replace(VALID_APPROVAL, owner_id="owner-other"),
            replace(VALID_APPROVAL, requester_id="principal:other"),
            replace(VALID_APPROVAL, asset_id="asset:other"),
            replace(VALID_APPROVAL, action_class=ActionClass.ANALYSIS),
            replace(VALID_APPROVAL, operation_intent=OperationIntent.READ),
            replace(VALID_APPROVAL, environment=Environment.SANDBOX),
            replace(VALID_APPROVAL, target_digest="0" * 64),
        )
        for record in cases:
            with self.subTest(record=record):
                self.assertEqual(validate_approval(record, REQUEST, DIGEST, NOW), ReasonCode.WRONG_DIGEST_BINDING)

    def test_approval_for_superseded_contract_version_is_stale(self):
        superseded_at = VALID_APPROVAL.issued_at + timedelta(seconds=1)
        self.assertEqual(
            validate_approval(VALID_APPROVAL, REQUEST, DIGEST, NOW, superseded_at=superseded_at),
            ReasonCode.STALE_APPROVAL,
        )

    def test_display_name_without_authenticated_binding_is_inactive_principal(self):
        record = replace(VALID_APPROVAL, authenticated=False)
        self.assertEqual(validate_approval(record, REQUEST, DIGEST, NOW), ReasonCode.INACTIVE_PRINCIPAL)

    def test_malformed_approval_returns_integrity_failure(self):
        record = replace(VALID_APPROVAL)
        corrupt(record, target_digest="not-a-digest")
        self.assertEqual(validate_approval(record, REQUEST, DIGEST, NOW), ReasonCode.INTEGRITY_CHECK_FAILED)

    def test_valid_core_r2_and_github_evidence_references(self):
        cases = (
            evidence("CORE_DB", "registry:evidence:1", "trusted-core"),
            evidence("R2_IMMUTABLE", "r2://registry/evidence/1", "r2"),
            evidence("GITHUB_EXACT_COMMIT", "github:islamismylifebey-web/lil-tweak@" + REVISION, "github"),
        )
        for reference in cases:
            with self.subTest(locator_class=reference.locator_class):
                self.assertIsNone(validate_evidence(reference, REQUEST, DIGEST))

    def test_unsupported_locator_missing_source_invalid_digest_or_unrecognized_type_fails_integrity(self):
        cases = (
            corrupt(evidence(), locator_class="HTTP"),
            corrupt(evidence(), source_system=""),
            corrupt(evidence(), content_digest="BAD"),
            corrupt(evidence(), evidence_type="unrecognized-v1-evidence"),
        )
        for reference in cases:
            with self.subTest(reference=reference):
                self.assertEqual(validate_evidence(reference, REQUEST, DIGEST), ReasonCode.INTEGRITY_CHECK_FAILED)

    def test_wrong_target_or_source_revision_returns_wrong_digest_binding(self):
        wrong_target = replace(evidence(), target_digest="0" * 64)
        wrong_revision = replace(evidence(), source_revision="1" * 40)
        self.assertEqual(validate_evidence(wrong_target, REQUEST, DIGEST), ReasonCode.WRONG_DIGEST_BINDING)
        self.assertEqual(validate_evidence(wrong_revision, REQUEST, DIGEST), ReasonCode.WRONG_DIGEST_BINDING)

    def test_missing_creation_time_or_asserted_safe_false_fails_integrity(self):
        missing_time = corrupt(evidence(), created_at=None)
        unsafe = replace(evidence(), asserted_safe=False)
        self.assertEqual(validate_evidence(missing_time, REQUEST, DIGEST), ReasonCode.INTEGRITY_CHECK_FAILED)
        self.assertEqual(validate_evidence(unsafe, REQUEST, DIGEST), ReasonCode.INTEGRITY_CHECK_FAILED)

    def test_missing_required_approval_and_evidence_block_resolution(self):
        contract = ContractVersion(
            owner_id=OWNER,
            contract_id="contract:guarded",
            version=1,
            requester_ids=(REQUEST.requester_id,),
            agent_ids=(REQUEST.agent_id,),
            asset_ids=(REQUEST.asset_id,),
            action_classes=(REQUEST.action_class,),
            operation_intents=(REQUEST.operation_intent,),
            environments=(REQUEST.environment,),
            mode=ExecutionMode.DRAFT_CODE,
            effective_at=NOW - timedelta(hours=1),
            expires_at=NOW + timedelta(hours=1),
            required_approval_ids=("approval:final",),
            required_evidence_types=("tests",),
        )
        principals = (
            Principal(OWNER, REQUEST.requester_id, PrincipalStatus.ACTIVE),
            Principal(OWNER, REQUEST.agent_id, PrincipalStatus.ACTIVE),
        )
        assets = (Asset(OWNER, REQUEST.asset_id, AssetType.REPOSITORY, "github:repo"),)
        decision = resolve_contracts(
            REQUEST,
            (contract,),
            principals=principals,
            assets=assets,
            approvals=(),
            evidence=(),
            now=NOW,
        )
        self.assertEqual(decision.recommended_mode, ExecutionMode.BLOCKED)
        self.assertEqual(
            decision.reason_codes,
            (ReasonCode.MISSING_REQUIRED_APPROVAL, ReasonCode.MISSING_REQUIRED_EVIDENCE),
        )

    def test_exact_required_approval_and_evidence_allow_resolution(self):
        contract = ContractVersion(
            owner_id=OWNER,
            contract_id="contract:guarded",
            version=1,
            requester_ids=(REQUEST.requester_id,),
            agent_ids=(REQUEST.agent_id,),
            asset_ids=(REQUEST.asset_id,),
            action_classes=(REQUEST.action_class,),
            operation_intents=(REQUEST.operation_intent,),
            environments=(REQUEST.environment,),
            mode=ExecutionMode.DRAFT_CODE,
            effective_at=NOW - timedelta(hours=1),
            expires_at=NOW + timedelta(hours=1),
            required_approval_ids=("approval:final",),
            required_evidence_types=("tests",),
        )
        target = sha256_digest(contract)
        approval = replace(VALID_APPROVAL, target_digest=target)
        reference = replace(evidence(), target_digest=target)
        principals = (
            Principal(OWNER, REQUEST.requester_id, PrincipalStatus.ACTIVE),
            Principal(OWNER, REQUEST.agent_id, PrincipalStatus.ACTIVE),
        )
        assets = (Asset(OWNER, REQUEST.asset_id, AssetType.REPOSITORY, "github:repo"),)
        decision = resolve_contracts(
            REQUEST,
            (contract,),
            principals=principals,
            assets=assets,
            approvals=(approval,),
            evidence=(reference,),
            now=NOW,
        )
        self.assertEqual(decision.recommended_mode, ExecutionMode.DRAFT_CODE)
        self.assertEqual(decision.reason_codes, ())


if __name__ == "__main__":
    unittest.main()
