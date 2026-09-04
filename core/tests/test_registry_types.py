from __future__ import annotations

import dataclasses
import unittest
from datetime import datetime, timedelta, timezone

from core.lil_tweak.registry_types import (
    ActionClass,
    ApprovalRecord,
    Asset,
    AssetType,
    AuditEvent,
    ContractVersion,
    Decision,
    DecisionRequest,
    Environment,
    EvidenceReference,
    ExceptionVersion,
    ExecutionMode,
    OperationIntent,
    Principal,
    PrincipalStatus,
    ReasonCode,
    RegistryValidationError,
)


UTC_NOW = datetime(2026, 9, 4, 6, 30, tzinfo=timezone.utc)
LATER = UTC_NOW + timedelta(hours=1)
DIGEST = "a" * 64
REVISION = "b" * 40
OWNER = "owner-12345678"


class RegistryTypesTests(unittest.TestCase):
    def test_governed_vocabularies_are_closed(self):
        with self.assertRaises(ValueError):
            Environment("staging-ish")
        with self.assertRaises(ValueError):
            ReasonCode("maybe_allowed")
        with self.assertRaises(ValueError):
            ExecutionMode("EXECUTE_ANYWHERE")
        with self.assertRaises(ValueError):
            ActionClass("SHELL")
        with self.assertRaises(ValueError):
            OperationIntent("MERGE")

    def test_reason_code_registry_is_exact(self):
        self.assertEqual(
            {value.value for value in ReasonCode},
            {
                "no_matching_contract",
                "invalid_request",
                "ambiguous_request",
                "inactive_principal",
                "unknown_asset",
                "contract_not_effective",
                "contract_expired",
                "conflicting_active_contracts",
                "missing_required_approval",
                "stale_approval",
                "revoked_approval",
                "wrong_digest_binding",
                "missing_required_evidence",
                "prohibited_target",
                "prohibited_action",
                "audit_persist_failed",
                "integrity_check_failed",
            },
        )

    def test_decision_request_requires_exact_revision_for_repository_work(self):
        with self.assertRaises(RegistryValidationError):
            DecisionRequest(
                owner_id=OWNER,
                requester_id="principal:requester",
                agent_id="principal:lil-tweak",
                asset_id="asset:lil-tweak",
                action_class=ActionClass.CODE_GENERATION,
                operation_intent=OperationIntent.PROPOSE,
                environment=Environment.REPOSITORY,
                source_revision=None,
            )
        with self.assertRaises(RegistryValidationError):
            DecisionRequest(
                owner_id=OWNER,
                requester_id="principal:requester",
                agent_id="principal:lil-tweak",
                asset_id="asset:lil-tweak",
                action_class=ActionClass.CODE_GENERATION,
                operation_intent=OperationIntent.PROPOSE,
                environment=Environment.REPOSITORY,
                source_revision="main",
            )

    def test_document_only_analysis_may_omit_source_revision(self):
        request = DecisionRequest(
            owner_id=OWNER,
            requester_id="principal:requester",
            agent_id="principal:lil-tweak",
            asset_id="asset:design",
            action_class=ActionClass.ANALYSIS,
            operation_intent=OperationIntent.READ,
            environment=Environment.DOCUMENT_ONLY,
            source_revision=None,
        )
        self.assertIs(request.validate(), request)

    def test_ids_are_non_empty_and_bounded(self):
        for bad in ("", "   ", "x" * 129):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(RegistryValidationError):
                    Principal(owner_id=OWNER, principal_id=bad, status=PrincipalStatus.ACTIVE)
        with self.assertRaises(RegistryValidationError):
            Principal(owner_id=" ", principal_id="principal:a", status=PrincipalStatus.ACTIVE)

    def test_records_reject_free_form_enum_strings(self):
        with self.assertRaises(RegistryValidationError):
            Principal(owner_id=OWNER, principal_id="principal:a", status="ACTIVE")  # type: ignore[arg-type]
        with self.assertRaises(RegistryValidationError):
            DecisionRequest(
                owner_id=OWNER,
                requester_id="principal:requester",
                agent_id="principal:lil-tweak",
                asset_id="asset:lil-tweak",
                action_class="CODE_GENERATION",  # type: ignore[arg-type]
                operation_intent=OperationIntent.PROPOSE,
                environment=Environment.REPOSITORY,
                source_revision=REVISION,
            )

    def test_timestamps_must_be_utc_aware(self):
        naive = UTC_NOW.replace(tzinfo=None)
        offset = datetime(2026, 9, 4, 1, 30, tzinfo=timezone(timedelta(hours=-5)))
        for invalid in (naive, offset):
            with self.subTest(invalid=invalid):
                with self.assertRaises(RegistryValidationError):
                    ContractVersion(
                        owner_id=OWNER,
                        contract_id="contract:a",
                        version=1,
                        requester_ids=("principal:requester",),
                        agent_ids=("principal:lil-tweak",),
                        asset_ids=("asset:lil-tweak",),
                        action_classes=(ActionClass.CODE_GENERATION,),
                        operation_intents=(OperationIntent.PROPOSE,),
                        environments=(Environment.REPOSITORY,),
                        mode=ExecutionMode.DRAFT_CODE,
                        effective_at=invalid,
                        expires_at=LATER,
                    )

    def test_effective_and_expiry_ordering_is_strict(self):
        with self.assertRaises(RegistryValidationError):
            ContractVersion(
                owner_id=OWNER,
                contract_id="contract:a",
                version=1,
                requester_ids=("principal:requester",),
                agent_ids=("principal:lil-tweak",),
                asset_ids=("asset:lil-tweak",),
                action_classes=(ActionClass.CODE_GENERATION,),
                operation_intents=(OperationIntent.PROPOSE,),
                environments=(Environment.REPOSITORY,),
                mode=ExecutionMode.DRAFT_CODE,
                effective_at=UTC_NOW,
                expires_at=UTC_NOW,
            )

    def test_sha256_values_must_be_lowercase_hex(self):
        for invalid in ("a" * 63, "A" * 64, "g" * 64):
            with self.subTest(invalid=invalid):
                with self.assertRaises(RegistryValidationError):
                    ApprovalRecord(
                        owner_id=OWNER,
                        approval_id="approval:a",
                        approver_id="principal:approver",
                        target_digest=invalid,
                        requester_id="principal:requester",
                        agent_id="principal:lil-tweak",
                        asset_id="asset:lil-tweak",
                        action_class=ActionClass.CODE_GENERATION,
                        operation_intent=OperationIntent.PROPOSE,
                        environment=Environment.REPOSITORY,
                        issued_at=UTC_NOW,
                        expires_at=LATER,
                        authenticated=True,
                    )

    def test_all_governed_records_are_frozen_and_slotted(self):
        request = DecisionRequest(
            owner_id=OWNER,
            requester_id="principal:requester",
            agent_id="principal:lil-tweak",
            asset_id="asset:lil-tweak",
            action_class=ActionClass.CODE_GENERATION,
            operation_intent=OperationIntent.PROPOSE,
            environment=Environment.REPOSITORY,
            source_revision=REVISION,
        )
        records = (
            Principal(OWNER, "principal:a", PrincipalStatus.ACTIVE),
            Asset(OWNER, "asset:a", AssetType.REPOSITORY, "github:owner/repo"),
            ContractVersion(
                owner_id=OWNER,
                contract_id="contract:a",
                version=1,
                requester_ids=("principal:requester",),
                agent_ids=("principal:lil-tweak",),
                asset_ids=("asset:lil-tweak",),
                action_classes=(ActionClass.CODE_GENERATION,),
                operation_intents=(OperationIntent.PROPOSE,),
                environments=(Environment.REPOSITORY,),
                mode=ExecutionMode.DRAFT_CODE,
                effective_at=UTC_NOW,
                expires_at=LATER,
            ),
            request,
            Decision(
                decision_id="decision:a",
                owner_id=OWNER,
                request=request,
                contract_digests=(DIGEST,),
                recommended_mode=ExecutionMode.DRAFT_CODE,
                reason_codes=(),
                required_approval_ids=(),
                required_evidence_types=(),
                decision_digest=DIGEST,
                created_at=UTC_NOW,
            ),
            ApprovalRecord(
                owner_id=OWNER,
                approval_id="approval:a",
                approver_id="principal:approver",
                target_digest=DIGEST,
                requester_id="principal:requester",
                agent_id="principal:lil-tweak",
                asset_id="asset:lil-tweak",
                action_class=ActionClass.CODE_GENERATION,
                operation_intent=OperationIntent.PROPOSE,
                environment=Environment.REPOSITORY,
                issued_at=UTC_NOW,
                expires_at=LATER,
                authenticated=True,
            ),
            EvidenceReference(
                owner_id=OWNER,
                evidence_id="evidence:a",
                target_digest=DIGEST,
                digest_algorithm="sha256",
                content_digest=DIGEST,
                locator_class="CORE_DB",
                locator="evidence:1",
                evidence_type="tests",
                source_system="trusted-core",
                created_at=UTC_NOW,
                source_revision=REVISION,
                asserted_safe=True,
            ),
            ExceptionVersion(
                owner_id=OWNER,
                exception_id="exception:a",
                version=1,
                target_digest=DIGEST,
                requester_id="principal:requester",
                agent_id="principal:lil-tweak",
                asset_id="asset:lil-tweak",
                action_class=ActionClass.PATCH_APPLICATION,
                operation_intent=OperationIntent.APPLY,
                environment=Environment.SANDBOX,
                compensating_controls=("approval:final",),
                approval_ids=("approval:final",),
                effective_at=UTC_NOW,
                expires_at=LATER,
            ),
            AuditEvent(
                event_id="event:a",
                owner_id=OWNER,
                sequence=1,
                subject_type="contract",
                subject_id="contract:a",
                event_type="contract.created",
                payload_digest=DIGEST,
                previous_hash=None,
                event_hash=DIGEST,
                actor_id="principal:a",
                recorded_at=UTC_NOW,
            ),
        )
        for record in records:
            with self.subTest(record=type(record).__name__):
                self.assertTrue(dataclasses.is_dataclass(record))
                self.assertFalse(hasattr(record, "__dict__"))
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    record.owner_id = "owner:changed"  # type: ignore[misc]

    def test_decision_owner_must_match_request_owner(self):
        request = DecisionRequest(
            owner_id=OWNER,
            requester_id="principal:requester",
            agent_id="principal:lil-tweak",
            asset_id="asset:lil-tweak",
            action_class=ActionClass.CODE_GENERATION,
            operation_intent=OperationIntent.PROPOSE,
            environment=Environment.REPOSITORY,
            source_revision=REVISION,
        )
        with self.assertRaises(RegistryValidationError):
            Decision(
                decision_id="decision:a",
                owner_id="owner-other",
                request=request,
                contract_digests=(DIGEST,),
                recommended_mode=ExecutionMode.DRAFT_CODE,
                reason_codes=(),
                required_approval_ids=(),
                required_evidence_types=(),
                decision_digest=DIGEST,
                created_at=UTC_NOW,
            )


if __name__ == "__main__":
    unittest.main()
