from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from liltweak.reasoning_contract import (
    DIRECTIVE_MACHINE_CONTRACTS,
    REASONING_CONTRACT_VERSION,
    ROLE_OUTPUT_CONTRACTS,
    CapabilityClassification,
    CapabilityDimensions,
    CapabilityState,
    CompletionArtifact,
    CompletionCommand,
    CompletionCounts,
    CompletionReport,
    CompletionVerdict,
    EvidenceMode,
    OutcomeStatus,
    PolicyBinding,
    ProviderHealthState,
    ProviderQualification,
    ProviderQualificationState,
    ProviderUsage,
    QualificationScenario,
    ReasoningRole,
    RequirementDecision,
    RiskClass,
    SourceBinding,
    TaskIntake,
    TokenAccounting,
    TokenMeasurement,
    ToolAuthority,
    ToolIntent,
)

SHA = "a" * 64


def source_binding() -> SourceBinding:
    return SourceBinding(
        repository_id="repo",
        branch="main",
        base_commit=SHA,
        source_tree_digest=SHA,
        worktree_digest=SHA,
        source_fingerprint=SHA,
    )


def policy_binding() -> PolicyBinding:
    return PolicyBinding(
        policy_version="1.0.0",
        policy_digest=SHA,
        prompt_version="1.0.0",
        prompt_digest=SHA,
        profile_name="ordinary",
        profile_version="1.0.0",
        model_id="gpt-5.6-sol",
        request_mode="standard",
        reasoning_effort="high",
    )


def test_all_directive_machine_contracts_are_strict_versioned_and_fully_required() -> None:
    expected = {
        "TaskIntake",
        "RetrievalPlan",
        "ContextManifest",
        "EngineeringPlan",
        "PlanCritique",
        "CandidateManifest",
        "CandidateCritique",
        "VerificationDecision",
        "ProviderQualification",
        "CapabilityClassification",
        "CompletionReport",
    }
    assert {contract.__name__ for contract in DIRECTIVE_MACHINE_CONTRACTS} == expected

    for contract in DIRECTIVE_MACHINE_CONTRACTS:
        schema = contract.model_json_schema()
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])
        assert "schema_version" in schema["properties"]

    for contract in ROLE_OUTPUT_CONTRACTS:
        assert "role" in contract.model_fields
        assert "tool_authority" in contract.model_fields


def test_task_intake_rejects_unknown_fields_wrong_version_and_coercion() -> None:
    valid = {
        "schema_version": REASONING_CONTRACT_VERSION,
        "role": ReasoningRole.INTAKE,
        "tool_authority": ToolAuthority.NONE,
        "task_id": "task",
        "objective": "Build a bounded reasoning contract.",
        "non_goals": (),
        "requirements": ("Strict schemas",),
        "constraints": ("No execution",),
        "prohibited_actions": ("No approval issuance",),
        "source_binding": source_binding(),
        "expected_artifacts": ("reasoning contract",),
        "acceptance_criteria": ("Unknown fields fail",),
        "stop_conditions": ("Source binding changes",),
        "risk_class": "low",
        "status": OutcomeStatus.PASSED,
        "status_reasons": (),
    }
    with pytest.raises(ValidationError):
        TaskIntake.model_validate(valid)

    valid["risk_class"] = RiskClass.LOW
    task = TaskIntake.model_validate(valid)
    assert task.schema_version == REASONING_CONTRACT_VERSION

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        TaskIntake.model_validate(valid | {"unexpected": "value"})
    with pytest.raises(ValidationError):
        TaskIntake.model_validate(valid | {"schema_version": "0.9.0"})


def test_status_contracts_distinguish_unknown_blocked_failed_and_passed() -> None:
    common = {
        "requirement_id": "req",
        "statement": "The strict schema is valid.",
        "evidence_ids": ("evidence",),
    }
    for status in (
        OutcomeStatus.UNKNOWN,
        OutcomeStatus.NOT_APPLICABLE,
        OutcomeStatus.BLOCKED,
        OutcomeStatus.FAILED,
    ):
        result = RequirementDecision(
            **common,
            status=status,
            status_reasons=("explicit reason",),
        )
        assert result.status == status

    with pytest.raises(ValidationError, match="requires at least one"):
        RequirementDecision(**common, status=OutcomeStatus.BLOCKED, status_reasons=())
    with pytest.raises(ValidationError, match="PASSED cannot carry"):
        RequirementDecision(
            **common,
            status=OutcomeStatus.PASSED,
            status_reasons=("not allowed",),
        )


def test_tool_intent_binds_exact_normalized_arguments() -> None:
    arguments = '{"path":"src/app.py"}'
    digest = hashlib.sha256(arguments.encode()).hexdigest()
    intent = ToolIntent(
        intent_id="intent",
        tool_id="read_file",
        tool_schema_version="1.0.0",
        authority=ToolAuthority.READ_ONLY_BROKERED,
        operation="read",
        normalized_arguments_json=arguments,
        arguments_digest=digest,
        purpose="Inspect the exact source file.",
        approval_purpose=None,
    )
    assert intent.arguments_digest == digest

    with pytest.raises(ValidationError, match="digest does not match"):
        ToolIntent.model_validate(intent.model_dump() | {"arguments_digest": SHA})


def test_token_accounting_requires_verified_measurement_and_reserves() -> None:
    accounting = TokenAccounting(
        measurement=TokenMeasurement.PROVIDER_TOKENIZER,
        tokenizer_model="gpt-5.6-sol",
        stable_prompt_tokens=100,
        context_tokens=500,
        reserved_reasoning_tokens=200,
        reserved_tool_tokens=0,
        reserved_output_tokens=200,
        total_context_limit=1_000,
    )
    assert accounting.context_tokens == 500

    with pytest.raises(ValidationError, match="exceed"):
        TokenAccounting.model_validate(accounting.model_dump() | {"total_context_limit": 999})


def offline_provider_qualification() -> ProviderQualification:
    scenario = QualificationScenario(
        scenario_id="strict-schema",
        live=False,
        response_id_digest=None,
        evidence_digest=SHA,
        status=OutcomeStatus.PASSED,
        status_reasons=(),
    )
    return ProviderQualification(
        schema_version=REASONING_CONTRACT_VERSION,
        qualification_id="qualification",
        provider="openai",
        configured=False,
        connected=False,
        requested_model="gpt-5.6-sol",
        effective_model=None,
        profile_name="ordinary",
        profile_version="1.0.0",
        request_mode="standard",
        reasoning_effort="high",
        health_state=ProviderHealthState.MISSING_KEY,
        qualification_state=ProviderQualificationState.OFFLINE_CONTRACT_ONLY,
        evidence_mode=EvidenceMode.OFFLINE,
        strict_schema_qualified=True,
        refusal_qualified=True,
        incomplete_qualified=True,
        continuation_qualified=True,
        compaction_qualified=True,
        timeout_qualified=True,
        cancellation_qualified=True,
        concurrency_qualified=True,
        usage_reconciliation_qualified=True,
        caching_telemetry_qualified=True,
        store_disabled=True,
        sensitive_tracing_disabled=True,
        approved_data_controls="Not live-qualified; no data-control claim.",
        scenarios=(scenario,),
        usage=ProviderUsage(
            requests=0,
            input_tokens=0,
            cached_input_tokens=0,
            output_tokens=0,
            reasoning_tokens=0,
            total_tokens=0,
            estimated_cost_usd=None,
        ),
        qualified_at=None,
        status=OutcomeStatus.BLOCKED,
        status_reasons=("No authorized provider credential is connected.",),
    )


def test_live_provider_qualification_cannot_be_claimed_from_offline_evidence() -> None:
    offline = offline_provider_qualification()
    with pytest.raises(ValidationError, match="LIVE_QUALIFIED"):
        ProviderQualification.model_validate(
            offline.model_dump()
            | {
                "qualification_state": ProviderQualificationState.LIVE_QUALIFIED,
                "status": OutcomeStatus.PASSED,
                "status_reasons": (),
            }
        )


def test_completion_report_blocks_operational_verdict_without_live_unmocked_evidence() -> None:
    capability = CapabilityClassification(
        schema_version=REASONING_CONTRACT_VERSION,
        capability_id="reasoning",
        name="Canonical reasoning policy",
        state=CapabilityState.OFFLINE_TESTED,
        dimensions=CapabilityDimensions(
            installed=OutcomeStatus.PASSED,
            configured=OutcomeStatus.PASSED,
            connected=OutcomeStatus.BLOCKED,
            healthy=OutcomeStatus.UNKNOWN,
            qualified=OutcomeStatus.BLOCKED,
            authorized=OutcomeStatus.BLOCKED,
            operational=OutcomeStatus.BLOCKED,
        ),
        evidence_mode=EvidenceMode.OFFLINE,
        evidence_references=(),
        blockers=("Live qualification is unavailable.",),
        last_checked_at=datetime.now(UTC),
        status=OutcomeStatus.BLOCKED,
        status_reasons=("Live qualification is unavailable.",),
    )
    command = CompletionCommand(
        command_id="pytest",
        purpose="Run focused tests.",
        command_digest=SHA,
        exit_code=0,
        evidence_digest=SHA,
    )
    artifact = CompletionArtifact(
        artifact_id="contracts",
        kind="source",
        path="liltweak/reasoning_contract.py",
        digest=SHA,
        evidence_mode=EvidenceMode.OFFLINE,
    )
    base = {
        "schema_version": REASONING_CONTRACT_VERSION,
        "role": ReasoningRole.FINALIZER,
        "tool_authority": ToolAuthority.NONE,
        "report_id": "report",
        "verdict": CompletionVerdict.ARCHITECTURE_ONLY,
        "repository_id": "repo",
        "branch": "main",
        "baseline_commit": SHA,
        "tested_tree_digest": SHA,
        "candidate_commit": None,
        "environment": "offline unit test",
        "policy_binding": policy_binding(),
        "commands": (command,),
        "counts": CompletionCounts(
            tests_collected=1,
            tests_passed=1,
            tests_failed=0,
            tests_skipped=0,
            capabilities_passed=0,
            capabilities_blocked=1,
            capabilities_failed=0,
        ),
        "artifacts": (artifact,),
        "evidence_digests": (SHA,),
        "provider_qualification_digest": None,
        "capabilities": (capability,),
        "live_evidence_present": False,
        "mocked_evidence_present": False,
        "unverified_conditions": ("Live provider behavior",),
        "remaining_blockers": ("Live qualification is unavailable.",),
        "completed_at": datetime.now(UTC),
        "status": OutcomeStatus.BLOCKED,
        "status_reasons": ("Live qualification is unavailable.",),
    }
    report = CompletionReport.model_validate(base)
    assert report.verdict == CompletionVerdict.ARCHITECTURE_ONLY

    with pytest.raises(ValidationError, match="operational verdict"):
        CompletionReport.model_validate(
            base
            | {
                "verdict": CompletionVerdict.PLANNING_ONLY,
                "status": OutcomeStatus.PASSED,
                "status_reasons": (),
            }
        )
