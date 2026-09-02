from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from liltweak.cloudflare_runner_qualification import CloudflareRunnerQualificationProof
from liltweak.private_runner_activation import (
    GALOR_TWEAK_PROFILE_SPEC_DIGEST,
    IndependentVerificationReceipt,
    PrivateRunnerActivationError,
    PrivateRunnerApproval,
    PrivateRunnerQualificationEvidence,
    PrivateRunnerQualificationOrchestrator,
    ProtectedControllerConfig,
    QualifiedRunnerScope,
    SourceEvidence,
    load_protected_controller_config,
)
from liltweak.providers.contracts import (
    ProviderExecutionStatus,
    ProviderOperationResult,
    VerificationOutcome,
)
from liltweak.providers.self_hosted.galor_tweak_runner import (
    SignedRunnerEvidenceEnvelope,
)
from liltweak.providers.self_hosted.qualification_manifest import (
    QualificationBoundedWriteManifest,
    QualificationReadOnlyManifest,
    QualificationSource,
)
from liltweak.resource.budget import ResourceLedger
from liltweak.resource.contracts import ResourceProvider, WorkspacePolicy
from liltweak.resource.dispatch import dispatch_issuer_key_id
from runner.protocol import canonical_json, sign_runner_request

NOW = datetime(2026, 9, 1, 20, 0, tzinfo=UTC)


def _proof(**changes: object) -> CloudflareRunnerQualificationProof:
    values: dict[str, object] = {
        "runner_id": "galor-tweak-runner-01",
        "runner_role": "role-tweak-runner",
        "repository_id": "github:islamismylifebey-web/lil-tweak",
        "repository_commit": "f" * 40,
        "repository_tree": "e" * 40,
        "runner_key_id": "2" * 64,
        "profile_spec_digest": GALOR_TWEAK_PROFILE_SPEC_DIGEST,
        "qualification_id": "rq_" + "1" * 32,
        "qualification_evidence_digest": "3" * 64,
        "qualification_verified_at": NOW,
        "authorization_id": "lra_" + "2" * 32,
        "authorization_evidence_digest": "5" * 64,
        "authorization_sequence": 5,
        "authorization_revocation_epoch": 1,
        "host_report_digest": "6" * 64,
        "local_decision_digest": "7" * 64,
        "cloudflare_poll_observation_digest": "8" * 64,
        "cloudflare_poll_observed_at": NOW,
        "valid_until": NOW + timedelta(minutes=5),
    }
    values.update(changes)
    draft = CloudflareRunnerQualificationProof.model_construct(**values, proof_digest="0" * 64)
    values["proof_digest"] = __import__(
        "liltweak.creator_contract", fromlist=["content_digest"]
    ).content_digest(draft.model_dump(mode="json", exclude={"proof_digest"}))
    return CloudflareRunnerQualificationProof(**values)  # type: ignore[arg-type]


def _evidence(**changes: object) -> PrivateRunnerQualificationEvidence:
    values: dict[str, object] = {
        "runner_id": "galor-tweak-runner-01",
        "runner_role": "role-tweak-runner",
        "repository_id": "github:islamismylifebey-web/lil-tweak",
        "profile_spec_digest": GALOR_TWEAK_PROFILE_SPEC_DIGEST,
        "qualified": True,
        "healthy": True,
        "qualified_scopes": (QualifiedRunnerScope.JOB_A, QualifiedRunnerScope.JOB_B),
        "gate3_contract_digest": "a" * 64,
        "qualification_evidence_digest": "3" * 64,
        "authorization_evidence_digest": "5" * 64,
        "proof": _proof(),
    }
    values.update(changes)
    return PrivateRunnerQualificationEvidence(**values)  # type: ignore[arg-type]


def _approval(**changes: object) -> PrivateRunnerApproval:
    values: dict[str, object] = {
        "approval_id": "founder-approval-pr12",
        "requested_by": "maurice-pennington-bey",
        "approved": True,
        "approval_digest": "a" * 64,
        "policy_digest": "b" * 64,
        "maximum_execution_cost_microusd": 50_000,
    }
    values.update(changes)
    return PrivateRunnerApproval(**values)  # type: ignore[arg-type]


def _source() -> SourceEvidence:
    return SourceEvidence(
        commit_sha="f" * 40,
        tree_sha="e" * 40,
        source_archive_digest="c" * 64,
    )


def _manifest_a() -> QualificationReadOnlyManifest:
    return QualificationReadOnlyManifest(
        source=QualificationSource(commit_sha="f" * 40, tree_sha="e" * 40),
        timeout_seconds=300,
    )


def _manifest_b() -> QualificationBoundedWriteManifest:
    return QualificationBoundedWriteManifest(
        source=QualificationSource(commit_sha="f" * 40, tree_sha="e" * 40),
        timeout_seconds=300,
        qualification_branch="qualification/galor-tweak-runner-01/pr12-proof",
    )


class RecordingProvider:
    def __init__(self) -> None:
        self.provisioned: list[object] = []
        self.executed: list[object] = []
        self.status_result = ProviderOperationResult(
            provider=ResourceProvider.SELF_HOSTED,
            execution_id="placeholder",
            status=ProviderExecutionStatus.RUNNING,
            reason="evidence pending",
            verification_outcome=VerificationOutcome.PENDING,
        )
        self.evidence: SignedRunnerEvidenceEnvelope | None = None

    async def provision(self, *, contract: object, lease: object) -> ProviderOperationResult:
        self.provisioned.append((contract, lease))
        return ProviderOperationResult(
            provider=ResourceProvider.SELF_HOSTED,
            execution_id=lease.execution_id,  # type: ignore[attr-defined]
            status=ProviderExecutionStatus.PROVISIONED,
            reason="eligible",
        )

    async def execute(
        self, *, contract: object, lease: object, manifest: object
    ) -> ProviderOperationResult:
        self.executed.append((contract, lease, manifest))
        return ProviderOperationResult(
            provider=ResourceProvider.SELF_HOSTED,
            execution_id=lease.execution_id,  # type: ignore[attr-defined]
            status=ProviderExecutionStatus.RUNNING,
            operation_id="runner-offer:test",
            reason="offered",
            verification_outcome=VerificationOutcome.PENDING,
        )

    async def collect(self, execution_id: str) -> ProviderOperationResult:
        return self.status_result.model_copy(update={"execution_id": execution_id})

    async def cancel(self, execution_id: str) -> ProviderOperationResult:
        return ProviderOperationResult(
            provider=ResourceProvider.SELF_HOSTED,
            execution_id=execution_id,
            status=ProviderExecutionStatus.CANCELED,
            reason="cancelled",
            verification_outcome=VerificationOutcome.FAILED,
            evidence_digest="d" * 64,
        )

    def evidence_for(self, execution_id: str) -> SignedRunnerEvidenceEnvelope | None:
        del execution_id
        return self.evidence


def _orchestrator(provider: RecordingProvider, *, monthly_limit: int = 100_000):
    return PrivateRunnerQualificationOrchestrator(
        provider=provider,  # type: ignore[arg-type]
        lease_signing_key=b"L" * 32,
        resource_ledger=ResourceLedger(monthly_limit_microusd=monthly_limit),
        clock=lambda: NOW + timedelta(seconds=1),
        identifier_factory=lambda label: f"{label}-001",
        nonce_factory=lambda: "1" * 64,
    )


def _recorded_runner_evidence(
    provider: RecordingProvider,
) -> tuple[SignedRunnerEvidenceEnvelope, str]:
    contract, lease, _ = provider.executed[0]
    receipt = {
        "runner_id": "galor-tweak-runner-01",
        "runtime_image": (
            "python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
        ),
        "seccomp_sha256": ("50eeb8b4cb2c33284f09453c8dd64c5895f5e1a2fa6b7a7440dfbac175fe1c23"),
        "apparmor_profile": "liltweak-runner-job",
        "network_denied": True,
        "package_install_allowed": False,
        "production_access_allowed": False,
        "deploy_allowed": False,
        "workspace_cleaned": True,
        "cgroup_cleaned": True,
        "candidate_sha": None,
        "source_commit": contract.source.source_commit,
        "source_tree": contract.source.source_tree,
        "source_mutated": False,
    }
    evidence = {
        "schema_version": "lil-tweak.runner-evidence/v2",
        "outcome": "succeeded",
        "operation_digest": contract.commands_digest,
        "stdout_digest": "1" * 64,
        "stderr_digest": "2" * 64,
        "receipt_digest": hashlib.sha256(canonical_json(receipt).encode()).hexdigest(),
        "receipt": receipt,
        "exit_code": 0,
        "started_at_ms": int((NOW + timedelta(seconds=1)).timestamp() * 1_000),
        "finished_at_ms": int((NOW + timedelta(seconds=2)).timestamp() * 1_000),
    }
    envelope = SignedRunnerEvidenceEnvelope.model_validate(
        sign_runner_request(
            operation="evidence",
            payload={
                "execution_id": lease.execution_id,
                "attempt_nonce": base64.urlsafe_b64encode(bytes.fromhex(lease.attempt_nonce))
                .decode("ascii")
                .rstrip("="),
                "evidence": evidence,
            },
            private_key=Ed25519PrivateKey.from_private_bytes(b"R" * 32),
            issued_at_ms=int((NOW + timedelta(seconds=2)).timestamp() * 1_000),
            request_nonce=b"N" * 32,
        )
    )
    return envelope, hashlib.sha256(canonical_json(evidence).encode()).hexdigest()


@pytest.mark.asyncio
async def test_routes_exact_job_a_through_director_contract_lease_and_provider() -> None:
    provider = RecordingProvider()
    receipt = await _orchestrator(provider).offer(
        manifest=_manifest_a(),
        source=_source(),
        approval=_approval(),
        qualification=_evidence(),
    )

    assert receipt.runner_profile_id == "galor-tweak-runner-01"
    assert receipt.route_digest
    assert receipt.commands_digest == _manifest_a().commands_digest
    assert receipt.independent_verification_required is True
    assert len(provider.provisioned) == len(provider.executed) == 1
    contract, lease, manifest = provider.executed[0]
    assert contract.selected_profile.runner_profile_id == "galor-tweak-runner-01"
    assert contract.workspace_policy is WorkspacePolicy.READ_ONLY
    assert contract.commands_digest == manifest.commands_digest == lease.commands_digest


@pytest.mark.asyncio
async def test_collect_requires_and_returns_verified_signed_runner_evidence() -> None:
    provider = RecordingProvider()
    orchestrator = _orchestrator(provider)
    receipt = await orchestrator.offer(
        manifest=_manifest_a(),
        source=_source(),
        approval=_approval(),
        qualification=_evidence(),
    )
    envelope, evidence_digest = _recorded_runner_evidence(provider)
    provider.status_result = ProviderOperationResult(
        provider=ResourceProvider.SELF_HOSTED,
        execution_id=receipt.execution_id,
        status=ProviderExecutionStatus.RUNNING,
        reason="evidence recorded",
        verification_outcome=VerificationOutcome.PENDING,
        evidence_digest=evidence_digest,
    )

    with pytest.raises(PrivateRunnerActivationError, match="signed runner evidence"):
        await orchestrator.collect(receipt)

    provider.evidence = envelope
    collected = await orchestrator.collect(receipt)

    assert collected.runner_evidence_digest == evidence_digest
    assert collected.runner_evidence_envelope == envelope


@pytest.mark.asyncio
async def test_job_b_is_only_the_fixed_bounded_manifest_and_needs_verified_job_a() -> None:
    provider = RecordingProvider()
    orchestrator = _orchestrator(provider)
    with pytest.raises(PrivateRunnerActivationError, match="Job A independent verification"):
        await orchestrator.offer(
            manifest=_manifest_b(),
            source=_source(),
            approval=_approval(),
            qualification=_evidence(),
        )

    verification = IndependentVerificationReceipt(
        job_type="read_only",
        runner_execution_id="execution-previous",
        source_commit="f" * 40,
        runner_evidence_digest="d" * 64,
        github_evidence_digest="e" * 64,
        verification_outcome=VerificationOutcome.VERIFIED,
    )
    receipt = await orchestrator.offer(
        manifest=_manifest_b(),
        source=_source(),
        approval=_approval(),
        qualification=_evidence(),
        prior_job_a_verification=verification,
    )

    contract, lease, manifest = provider.executed[0]
    assert receipt.job_type == "bounded_write"
    assert contract.workspace_policy is WorkspacePolicy.EPHEMERAL_WRITABLE
    assert contract.source_write_authorized is True
    assert manifest.artifact.path == "docs/runner-qualification/galor-tweak-runner-01.md"
    assert lease.secret_scope == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("evidence", "message"),
    [
        (_evidence(qualified=False), "qualified"),
        (_evidence(healthy=False), "healthy"),
        (
            _evidence(proof=_proof(qualification_verified_at=NOW - timedelta(days=2))),
            "stale",
        ),
        (
            _evidence(qualified_scopes=(QualifiedRunnerScope.JOB_A,)),
            "scope",
        ),
    ],
)
async def test_unqualified_stale_unhealthy_or_incapable_runner_never_reaches_provider(
    evidence: PrivateRunnerQualificationEvidence,
    message: str,
) -> None:
    provider = RecordingProvider()
    manifest = _manifest_b() if message == "scope" else _manifest_a()
    prior = None
    if message == "scope":
        prior = IndependentVerificationReceipt(
            job_type="read_only",
            runner_execution_id="execution-previous",
            source_commit="f" * 40,
            runner_evidence_digest="d" * 64,
            github_evidence_digest="e" * 64,
            verification_outcome=VerificationOutcome.VERIFIED,
        )
    with pytest.raises(PrivateRunnerActivationError, match=message):
        await _orchestrator(provider).offer(
            manifest=manifest,
            source=_source(),
            approval=_approval(),
            qualification=evidence,
            prior_job_a_verification=prior,
        )
    assert provider.executed == []


def test_identity_profile_and_evidence_bindings_fail_closed() -> None:
    base = _evidence().model_dump(mode="python")
    with pytest.raises(ValidationError, match="runner_id"):
        PrivateRunnerQualificationEvidence(**{**base, "runner_id": "wrong-runner"})
    with pytest.raises(ValidationError, match="profile spec"):
        PrivateRunnerQualificationEvidence(**{**base, "profile_spec_digest": "0" * 64})
    with pytest.raises(ValidationError, match="qualification evidence"):
        PrivateRunnerQualificationEvidence(**{**base, "qualification_evidence_digest": "0" * 64})


@pytest.mark.asyncio
async def test_approval_and_budget_fail_before_provider_dispatch() -> None:
    provider = RecordingProvider()
    with pytest.raises(PrivateRunnerActivationError, match="approval"):
        await _orchestrator(provider).offer(
            manifest=_manifest_a(),
            source=_source(),
            approval=_approval(approved=False),
            qualification=_evidence(),
        )
    with pytest.raises(PrivateRunnerActivationError, match="budget"):
        await _orchestrator(provider, monthly_limit=1).offer(
            manifest=_manifest_a(),
            source=_source(),
            approval=_approval(),
            qualification=_evidence(),
        )
    assert provider.executed == []


@pytest.mark.asyncio
async def test_provider_lease_failure_cancellation_and_failed_independent_verification() -> None:
    provider = RecordingProvider()
    orchestrator = _orchestrator(provider)
    receipt = await orchestrator.offer(
        manifest=_manifest_a(),
        source=_source(),
        approval=_approval(),
        qualification=_evidence(),
    )
    provider.status_result = ProviderOperationResult(
        provider=ResourceProvider.SELF_HOSTED,
        execution_id=receipt.execution_id,
        status=ProviderExecutionStatus.FAILED,
        reason="execution lease was rejected",
        verification_outcome=VerificationOutcome.FAILED,
    )
    with pytest.raises(PrivateRunnerActivationError, match="lease"):
        await orchestrator.collect(receipt)

    cancelled = await orchestrator.cancel(receipt)
    assert cancelled.status is ProviderExecutionStatus.CANCELED
    with pytest.raises(PrivateRunnerActivationError, match="independent verification"):
        orchestrator.accept_independent_verification(
            receipt,
            IndependentVerificationReceipt(
                job_type="read_only",
                runner_execution_id=receipt.execution_id,
                source_commit="f" * 40,
                runner_evidence_digest="d" * 64,
                github_evidence_digest="e" * 64,
                verification_outcome=VerificationOutcome.FAILED,
            ),
        )


def test_protected_controller_config_loader_never_exposes_private_values(tmp_path) -> None:
    private_key_bytes = b"K" * 32
    private_key = base64.urlsafe_b64encode(private_key_bytes).decode().rstrip("=")
    public_key_bytes = (
        Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        .public_key()
        .public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )
    payload = {
        "version": 1,
        "endpoint": "https://runner-control.liltweak.galorweb.works",
        "runner": {"runnerId": "galor-tweak-runner-01"},
        "control": {
            "bearerToken": "control-bearer-value",
            "accessClientId": "control-access-id-value",
            "accessClientSecret": "control-access-secret-value",
        },
        "dispatch": {
            "privateKey": private_key,
            "publicKey": base64.urlsafe_b64encode(public_key_bytes).decode().rstrip("="),
            "keyId": dispatch_issuer_key_id(public_key_bytes),
        },
    }
    path = tmp_path / "controller.dpapi"
    path.write_bytes(b"encrypted")
    path.chmod(0o600)
    config = load_protected_controller_config(
        path,
        decrypt=lambda _: __import__("json").dumps(payload).encode(),
    )

    assert isinstance(config, ProtectedControllerConfig)
    rendered = repr(config) + config.model_dump_json()
    assert "control-bearer-value" not in repr(config)
    assert "control-access-secret-value" not in repr(config)
    assert config.dispatch_private_key.get_secret_value() == b"K" * 32
    assert "control-bearer-value" not in rendered
    assert "control-access-secret-value" not in rendered
