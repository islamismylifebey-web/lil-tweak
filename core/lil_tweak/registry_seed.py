"""Deterministic, idempotent Registry V1 seed for Lil' Tweak.

The seed creates a bounded explain-only default and explicit permanent blocks
for runner and deployment assets. Authority is bound only to stable principal
IDs supplied by the caller; display names are never consulted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .registry_store import ContractRegistryStore
from .registry_types import (
    ActionClass,
    Asset,
    AssetType,
    ContractVersion,
    Environment,
    ExecutionMode,
    OperationIntent,
    Principal,
    PrincipalStatus,
)


SEED_EFFECTIVE_AT = datetime(2026, 9, 4, 0, 0, 0, tzinfo=timezone.utc)
LIL_TWEAK_PRINCIPAL_ID = "principal:lil-tweak"
REPOSITORY_ASSET_ID = "asset:github:islamismylifebey-web/lil-tweak"
RUNNER_ASSET_ID = "asset:runner-surfaces"
DEPLOYMENT_ASSET_ID = "asset:deployment-surfaces"
DEFAULT_CONTRACT_ID = "contract:lil-tweak:explain-only-default"
RUNNER_BLOCK_CONTRACT_ID = "contract:lil-tweak:block-runner-surfaces"
DEPLOYMENT_BLOCK_CONTRACT_ID = "contract:lil-tweak:block-deployment-surfaces"


@dataclass(frozen=True, slots=True)
class RegistrySeedResult:
    principals: tuple[Principal, ...]
    assets: tuple[Asset, ...]
    contracts: tuple[ContractVersion, ...]


def _all(enum_type: type) -> tuple:
    return tuple(enum_type)


def seed_registry_v1(
    store: ContractRegistryStore,
    *,
    owner_id: str,
    approver_principal_id: str,
) -> RegistrySeedResult:
    """Replay the canonical V1 seed safely.

    Repeating this function with the same owner and bound approver is a no-op.
    A different payload for an existing immutable identity is rejected by the
    store rather than silently replacing authority.
    """

    if not owner_id.strip():
        raise ValueError("owner_id is required")
    if not approver_principal_id.strip():
        raise ValueError("approver_principal_id is required")

    principals = (
        Principal(
            owner_id=owner_id,
            principal_id=approver_principal_id,
            status=PrincipalStatus.ACTIVE,
        ),
        Principal(
            owner_id=owner_id,
            principal_id=LIL_TWEAK_PRINCIPAL_ID,
            status=PrincipalStatus.ACTIVE,
        ),
    )

    assets = (
        Asset(
            owner_id=owner_id,
            asset_id=REPOSITORY_ASSET_ID,
            asset_type=AssetType.REPOSITORY,
            canonical_locator="github:islamismylifebey-web/lil-tweak",
        ),
        Asset(
            owner_id=owner_id,
            asset_id=RUNNER_ASSET_ID,
            asset_type=AssetType.PIPELINE,
            canonical_locator="galor:runner-surfaces",
        ),
        Asset(
            owner_id=owner_id,
            asset_id=DEPLOYMENT_ASSET_ID,
            asset_type=AssetType.ENVIRONMENT,
            canonical_locator="galor:deployment-surfaces",
        ),
    )

    shared = {
        "owner_id": owner_id,
        "version": 1,
        "requester_ids": (approver_principal_id,),
        "agent_ids": (LIL_TWEAK_PRINCIPAL_ID,),
        "action_classes": _all(ActionClass),
        "effective_at": SEED_EFFECTIVE_AT,
        "expires_at": None,
        "required_approval_ids": (),
        "required_evidence_types": (),
        "supersedes_digest": None,
    }

    contracts = (
        ContractVersion(
            **shared,
            contract_id=DEFAULT_CONTRACT_ID,
            asset_ids=(REPOSITORY_ASSET_ID,),
            operation_intents=(OperationIntent.READ, OperationIntent.PROPOSE),
            environments=(Environment.DOCUMENT_ONLY, Environment.REPOSITORY),
            mode=ExecutionMode.EXPLAIN_ONLY,
            prohibited=False,
        ),
        ContractVersion(
            **shared,
            contract_id=RUNNER_BLOCK_CONTRACT_ID,
            asset_ids=(RUNNER_ASSET_ID,),
            operation_intents=_all(OperationIntent),
            environments=_all(Environment),
            mode=ExecutionMode.BLOCKED,
            prohibited=True,
        ),
        ContractVersion(
            **shared,
            contract_id=DEPLOYMENT_BLOCK_CONTRACT_ID,
            asset_ids=(DEPLOYMENT_ASSET_ID,),
            operation_intents=_all(OperationIntent),
            environments=_all(Environment),
            mode=ExecutionMode.BLOCKED,
            prohibited=True,
        ),
    )

    for principal in principals:
        store.put_principal(principal)
    for registry_asset in assets:
        store.put_asset(registry_asset)
    for registry_contract in contracts:
        store.put_contract_version(registry_contract)

    return RegistrySeedResult(principals=principals, assets=assets, contracts=contracts)


seed_lil_tweak_registry = seed_registry_v1
seed_engineering_contract_registry = seed_registry_v1
