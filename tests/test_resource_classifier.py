import pytest
from pydantic import ValidationError

from liltweak.resource.classifier import ServerWorkloadContext, WorkloadClassifier
from liltweak.resource.contracts import (
    ModelWorkloadSuggestion,
    NetworkPolicy,
    RiskLevel,
    VerificationLevel,
    WorkloadAuthority,
)


def test_classifier_combines_model_technical_hints_with_server_authority() -> None:
    suggestion = ModelWorkloadSuggestion(
        required_cpu=4,
        required_memory_mb=8_192,
        required_disk_mb=16_384,
        shared_memory_required=False,
        browser_required=True,
        network_required=True,
        estimated_duration_seconds=900,
        parallelizable=True,
        desired_parallelism=4,
    )
    authority = WorkloadAuthority(
        requested_by="owner",
        risk_level=RiskLevel.HIGH,
        maximum_authorized_cost_microusd=200_000,
        approval_digest="a" * 64,
        policy_digest="b" * 64,
        secrets_authorized=True,
        network_policy=NetworkPolicy(
            network_required=True,
            allowed_destinations=("api.github.com",),
        ),
    )
    context = ServerWorkloadContext(
        requirement_id="req_classifier",
        job_id="job_classifier",
        authority=authority,
        secrets_required=True,
        verification_level=VerificationLevel.INDEPENDENT,
    )

    requirements = WorkloadClassifier().classify(suggestion, context)

    assert requirements.required_cpu == 4
    assert requirements.browser_required is True
    assert requirements.network_policy.allowed_destinations == ("api.github.com",)
    assert requirements.secrets_required is True
    assert requirements.production_access_required is False
    assert requirements.authority is authority
    assert requirements.verification_level is VerificationLevel.INDEPENDENT


def test_browser_payload_cannot_submit_provider_or_authority_source() -> None:
    with pytest.raises(ValidationError):
        ServerWorkloadContext.model_validate(
            {
                "source": "browser",
                "requirement_id": "req_browser",
                "job_id": "job_browser",
                "provider": "github",
                "authority": {
                    "requested_by": "owner",
                    "risk_level": "low",
                    "maximum_authorized_cost_microusd": 0,
                    "approval_digest": "a" * 64,
                    "policy_digest": "b" * 64,
                },
            }
        )


def test_model_cannot_submit_network_destination_authority() -> None:
    with pytest.raises(ValidationError):
        ModelWorkloadSuggestion.model_validate(
            {
                "required_cpu": 2,
                "required_memory_mb": 2_048,
                "required_disk_mb": 4_096,
                "network_policy": {
                    "network_required": True,
                    "allowed_destinations": ("attacker.example",),
                },
            }
        )
