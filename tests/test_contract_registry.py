from __future__ import annotations

import pytest

from liltweak.contract_registry import (
    ApplicabilityRequest,
    ApprovalRecord,
    AuthorityLevel,
    ContractCategory,
    ContractRegistry,
    ContractRegistryError,
    ContractSource,
    ContractStatus,
    ContractVersion,
    EnforcementDecision,
    VerificationRecord,
    VerificationState,
)


def _contract(
    *,
    identifier: str = "AUTH_BOUNDARY",
    category: ContractCategory = ContractCategory.SECURITY,
    status: ContractStatus = ContractStatus.ACTIVE,
    checksum: str = "a" * 64,
    independent: bool = True,
) -> ContractVersion:
    return ContractVersion(
        contract_id=identifier,
        version="1.0.0",
        name=identifier,
        category=category,
        repository="github:islamismylifebey-web/lil-tweak",
        description="Authentication boundaries fail closed.",
        source_of_truth=(
            ContractSource("security_policy", "liltweak/policy.py", checksum=checksum),
        ),
        paths=("liltweak/auth",),
        protected_surfaces=("auth_boundary",),
        required_tests=("tests/test_auth.py",),
        required_evidence=("exact-commit-ci",),
        approval_policy=("security-review",),
        required_independent_verifier=independent,
        status=status,
    )


def _active(registry: ContractRegistry, contract: ContractVersion) -> ContractVersion:
    registry.create(ContractVersion(**{**contract.__dict__, "status": ContractStatus.PROPOSED}))
    digest = registry.digest((registry.lookup(contract.contract_id, contract.version),), ())
    return registry.activate(
        contract.contract_id,
        contract.version,
        (ApprovalRecord("proposal", digest.digest_value, "reviewer", "security-review"),),
    )


def test_active_contract_requires_verified_explicit_source() -> None:
    registry = ContractRegistry()
    invalid = ContractVersion(
        **{
            **_contract().__dict__,
            "source_of_truth": (
                ContractSource(
                    "doc",
                    "README.md",
                    authority_level=AuthorityLevel.INFERRED,
                    verification_state=VerificationState.UNVERIFIABLE,
                ),
            ),
        }
    )
    registry.create(ContractVersion(**{**invalid.__dict__, "status": ContractStatus.PROPOSED}))

    with pytest.raises(ContractRegistryError, match="inferred"):
        registry.activate(invalid.contract_id, invalid.version, ())


def test_protected_security_contract_is_included_and_weakening_blocks() -> None:
    registry = ContractRegistry()
    _active(registry, _contract())

    request = ApplicabilityRequest(
        repository="github:islamismylifebey-web/lil-tweak",
        protected_surfaces=("auth_boundary",),
    )
    result = registry.analyze_diff(request, weakening=("AUTH_BOUNDARY",))

    assert result.final_decision == EnforcementDecision.BLOCK
    assert result.possibly_weakened_contracts == ("AUTH_BOUNDARY",)


def test_digest_is_deterministic_and_digest_mismatch_blocks_completion() -> None:
    registry = ContractRegistry()
    active = _active(registry, _contract())
    digest = registry.digest((active,), ("scope match",), "plan", "plan-1")
    assert digest.digest_value == registry.digest((active,), ("scope match",)).digest_value

    completion = registry.completion(
        "plan-1",
        digest,
        "0" * 64,
        "builder",
        (ApprovalRecord("plan-1", digest.digest_value, "reviewer", "security-review"),),
        (),
        ("tests/test_auth.py",),
        ("exact-commit-ci",),
    )

    assert completion.completion_status == EnforcementDecision.BLOCK
    assert "contract digest mismatch" in completion.remaining_blocks


def test_completion_rejects_builder_as_independent_verifier() -> None:
    registry = ContractRegistry()
    active = _active(registry, _contract())
    digest = registry.digest((active,), ())

    completion = registry.completion(
        "change-1",
        digest,
        digest.digest_value,
        "builder",
        (ApprovalRecord("change-1", digest.digest_value, "reviewer", "security-review"),),
        (VerificationRecord("change-1", digest.digest_value, "builder", True),),
        ("tests/test_auth.py",),
        ("exact-commit-ci",),
    )

    assert completion.completion_status == EnforcementDecision.BLOCK
    assert "independent verification is missing" in completion.remaining_blocks


def test_conflicting_authoritative_sources_block_applicability() -> None:
    registry = ContractRegistry()
    conflicting = ContractVersion(
        **{
            **_contract().__dict__,
            "source_of_truth": (
                ContractSource("policy", "one.py", checksum="a" * 64),
                ContractSource("policy", "two.py", checksum="b" * 64),
            ),
        }
    )
    _active(registry, conflicting)

    decision = registry.applicable(
        ApplicabilityRequest(
            repository="github:islamismylifebey-web/lil-tweak",
            protected_surfaces=("auth_boundary",),
        )
    )

    assert decision.blocked
    assert "conflicting authoritative sources" in decision.reasons[-1]


def test_missing_exact_commit_ci_evidence_blocks() -> None:
    registry = ContractRegistry()
    _active(registry, _contract())

    result = registry.analyze_diff(
        ApplicabilityRequest(
            repository="github:islamismylifebey-web/lil-tweak",
            protected_surfaces=("auth_boundary",),
        ),
        completed_tests=("tests/test_auth.py",),
    )

    assert result.final_decision == EnforcementDecision.BLOCK
