from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from liltweak.creator_contract import content_digest
from liltweak.providers.github.runner_v3_contracts import (
    RUNNER_V3_PROFILE_ID,
    RunnerV3Action,
    RunnerV3HostCapacity,
    RunnerV3JobManifest,
    RunnerV3Outcome,
    RunnerV3Patch,
    RunnerV3ProviderConfig,
    RunnerV3Receipt,
    RunnerV3StepReceipt,
    RunnerV3WorkflowSnapshot,
    RunnerV3WorkspaceMode,
)

NOW = datetime(2026, 9, 2, 16, 0, tzinfo=UTC)
PATCH_TEXT = """diff --git a/docs/runner-v3-fixture.txt b/docs/runner-v3-fixture.txt
new file mode 100644
index 0000000..ce01362
--- /dev/null
+++ b/docs/runner-v3-fixture.txt
@@ -0,0 +1 @@
+hello
"""


def _manifest(
    *,
    workspace_mode: RunnerV3WorkspaceMode = RunnerV3WorkspaceMode.READ_ONLY,
    source_write_authorized: bool = False,
    patch: RunnerV3Patch | None = None,
    actions: tuple[RunnerV3Action, ...] = (
        RunnerV3Action.INSPECT_SOURCE,
        RunnerV3Action.GIT_DIFF,
    ),
) -> RunnerV3JobManifest:
    return RunnerV3JobManifest.issue(
        execution_id="execution_runner_v3_contracts",
        attempt_nonce="1" * 64,
        repository_id="github:islamismylifebey-web/lil-tweak",
        source_commit="f" * 40,
        source_tree="e" * 40,
        contract_digest="c" * 64,
        lease_digest="d" * 64,
        commands_digest="a" * 64,
        approval_digest="b" * 64,
        policy_digest="9" * 64,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        cpu_ceiling=2,
        memory_mb_ceiling=2_048,
        disk_mb_ceiling=4_096,
        timeout_seconds=300,
        output_byte_limit=128_000,
        workspace_mode=workspace_mode,
        source_write_authorized=source_write_authorized,
        actions=actions,
        patch=patch,
    )


def test_manifest_issue_binds_exact_profile_and_canonical_digest() -> None:
    manifest = _manifest()

    assert manifest.runner_profile_id == RUNNER_V3_PROFILE_ID
    assert manifest.manifest_digest == content_digest(
        manifest.model_dump(mode="json", exclude={"manifest_digest"})
    )


def test_manifest_rejects_unknown_fields() -> None:
    payload = _manifest().model_dump(mode="python")
    payload["raw_command"] = "bash -c anything"

    with pytest.raises(ValidationError, match="extra_forbidden"):
        RunnerV3JobManifest.model_validate(payload)


def test_manifest_rejects_duplicate_actions() -> None:
    with pytest.raises(ValidationError, match="unique"):
        _manifest(
            actions=(
                RunnerV3Action.INSPECT_SOURCE,
                RunnerV3Action.INSPECT_SOURCE,
            )
        )


def test_manifest_rejects_naive_or_reversed_timestamps() -> None:
    payload = _manifest().model_dump(mode="python")
    payload["issued_at"] = datetime(2026, 9, 2, 16, 0)

    with pytest.raises(ValidationError, match="timezone-aware"):
        RunnerV3JobManifest.model_validate(payload)

    payload = _manifest().model_dump(mode="python")
    payload["expires_at"] = NOW
    with pytest.raises(ValidationError, match="expire"):
        RunnerV3JobManifest.model_validate(payload)


def test_read_only_manifest_rejects_patch() -> None:
    patch = RunnerV3Patch.issue(
        text=PATCH_TEXT,
        authorized_paths=("docs/runner-v3-fixture.txt",),
    )

    with pytest.raises(ValidationError, match="read-only"):
        _manifest(patch=patch)


def test_patch_mode_requires_source_write_authority_and_patch() -> None:
    patch = RunnerV3Patch.issue(
        text=PATCH_TEXT,
        authorized_paths=("docs/runner-v3-fixture.txt",),
    )

    with pytest.raises(ValidationError, match="source-write"):
        _manifest(workspace_mode=RunnerV3WorkspaceMode.EPHEMERAL_PATCH, patch=patch)

    with pytest.raises(ValidationError, match="requires a patch"):
        _manifest(
            workspace_mode=RunnerV3WorkspaceMode.EPHEMERAL_PATCH,
            source_write_authorized=True,
        )


def test_patch_rejects_forged_digest_and_unsafe_paths() -> None:
    patch = RunnerV3Patch.issue(
        text=PATCH_TEXT,
        authorized_paths=("docs/runner-v3-fixture.txt",),
    )
    payload = patch.model_dump(mode="python")
    payload["patch_digest"] = "0" * 64

    with pytest.raises(ValidationError, match="digest"):
        RunnerV3Patch.model_validate(payload)

    for path in ("../escape.txt", "/absolute.txt", ".git/config", "a//b.txt", "a\\b.txt"):
        with pytest.raises(ValidationError, match="path"):
            RunnerV3Patch.issue(text=PATCH_TEXT, authorized_paths=(path,))


def test_patch_rejects_excessive_bytes_and_duplicate_paths() -> None:
    with pytest.raises(ValidationError, match="262144"):
        RunnerV3Patch.issue(
            text="x" * 262_145,
            authorized_paths=("docs/runner-v3-fixture.txt",),
        )

    with pytest.raises(ValidationError, match="unique"):
        RunnerV3Patch.issue(
            text=PATCH_TEXT,
            authorized_paths=(
                "docs/runner-v3-fixture.txt",
                "docs/runner-v3-fixture.txt",
            ),
        )


def test_manifest_rejects_forged_digest() -> None:
    payload = _manifest().model_dump(mode="python")
    payload["manifest_digest"] = "0" * 64

    with pytest.raises(ValidationError, match="digest"):
        RunnerV3JobManifest.model_validate(payload)


def test_manifest_rejects_patch_action_mismatch() -> None:
    patch = RunnerV3Patch.issue(
        text=PATCH_TEXT,
        authorized_paths=("docs/runner-v3-fixture.txt",),
    )

    with pytest.raises(ValidationError, match="git_diff"):
        _manifest(
            workspace_mode=RunnerV3WorkspaceMode.EPHEMERAL_PATCH,
            source_write_authorized=True,
            patch=patch,
            actions=(RunnerV3Action.INSPECT_SOURCE,),
        )


def test_receipt_issue_binds_steps_capacity_and_digest() -> None:
    manifest = _manifest()
    step = RunnerV3StepReceipt(
        action=RunnerV3Action.INSPECT_SOURCE,
        outcome=RunnerV3Outcome.SUCCEEDED,
        exit_code=0,
        stdout_digest=hashlib.sha256(b"source-ok").hexdigest(),
        stderr_digest=hashlib.sha256(b"").hexdigest(),
        started_at_ms=1_000,
        finished_at_ms=1_010,
        output_truncated=False,
    )
    capacity = RunnerV3HostCapacity(
        cpu_count=2,
        memory_mb=7_000,
        free_disk_mb=14_000,
        runner_os="Linux",
        runner_arch="X64",
        runner_name="GitHub Actions 1",
        runner_label="ubuntu-24.04",
    )

    receipt = RunnerV3Receipt.issue(
        manifest=manifest,
        host_capacity=capacity,
        steps=(step,),
        outcome=RunnerV3Outcome.SUCCEEDED,
        source_commit_after=manifest.source_commit,
        source_tree_after=manifest.source_tree,
        workspace_changed=False,
        changed_paths=(),
        candidate_patch_digest=None,
        started_at_ms=1_000,
        finished_at_ms=1_010,
    )

    assert receipt.manifest_digest == manifest.manifest_digest
    assert receipt.receipt_digest == content_digest(
        receipt.model_dump(mode="json", exclude={"receipt_digest"})
    )


def test_receipt_rejects_inconsistent_mutation_evidence() -> None:
    manifest = _manifest()
    capacity = RunnerV3HostCapacity(
        cpu_count=2,
        memory_mb=7_000,
        free_disk_mb=14_000,
        runner_os="Linux",
        runner_arch="X64",
        runner_name="GitHub Actions 1",
        runner_label="ubuntu-24.04",
    )

    with pytest.raises(ValidationError, match="changed paths"):
        RunnerV3Receipt.issue(
            manifest=manifest,
            host_capacity=capacity,
            steps=(),
            outcome=RunnerV3Outcome.SUCCEEDED,
            source_commit_after=manifest.source_commit,
            source_tree_after=manifest.source_tree,
            workspace_changed=False,
            changed_paths=("docs/runner-v3-fixture.txt",),
            candidate_patch_digest=None,
            started_at_ms=1_000,
            finished_at_ms=1_010,
        )


def test_provider_config_is_builder_only() -> None:
    config = RunnerV3ProviderConfig(
        repository_id="github:islamismylifebey-web/lil-tweak",
        workflow_path=".github/workflows/runner-v3.yml",
        runner_profile_id=RUNNER_V3_PROFILE_ID,
    )

    assert config.provider_role == "builder"


def test_workflow_snapshot_requires_exact_completed_evidence() -> None:
    snapshot = RunnerV3WorkflowSnapshot(
        run_id="run_1",
        source_commit="f" * 40,
        source_tree="e" * 40,
        manifest_digest="a" * 64,
        status="completed",
        conclusion="success",
        outcome=RunnerV3Outcome.SUCCEEDED,
        receipt_digest="b" * 64,
    )
    assert snapshot.receipt_digest == "b" * 64

    with pytest.raises(ValidationError, match="receipt"):
        RunnerV3WorkflowSnapshot(
            run_id="run_2",
            source_commit="f" * 40,
            source_tree="e" * 40,
            manifest_digest="a" * 64,
            status="completed",
            conclusion="success",
            outcome=RunnerV3Outcome.SUCCEEDED,
            receipt_digest=None,
        )
