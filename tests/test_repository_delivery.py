from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from liltweak.repository_delivery import (
    HARDENED_GIT_ENVIRONMENT_DIGEST,
    ApplyPatchApproval,
    ContentKind,
    DeliveryApprovalPurpose,
    DisabledRepositoryPublisherClient,
    EphemeralTestRepositoryPublisher,
    FinalTreeEntry,
    FinalTreeManifest,
    LocalCommitApproval,
    PatchManifest,
    PublisherStatus,
    RepositoryDeliveryConflict,
    RepositoryDeliveryFailed,
    RepositoryPublisherClient,
    RepositoryPublisherUnavailable,
    RepositoryState,
    RollbackApproval,
    StructuredGitCommand,
    hardened_git_environment,
)
from liltweak.workbench_contract import content_digest

REPOSITORY_ID = "github:owner/repository"
HEAD = "1" * 40
TREE = "2" * 40


def initial_state() -> RepositoryState:
    return RepositoryState.create(
        repository_id=REPOSITORY_ID,
        branch="main",
        head_commit=HEAD,
        head_tree=TREE,
        worktree_manifest_digest="3" * 64,
        index_tree_digest="4" * 64,
        worktree_status_digest="5" * 64,
        clean=True,
    )


def delivery_artifacts(
    state: RepositoryState,
    *,
    binary: bool = False,
) -> tuple[bytes, FinalTreeManifest, PatchManifest]:
    content = b"\x00binary" if binary else b"updated\n"
    entry = FinalTreeEntry(
        path="src/example.py",
        blob_sha256=hashlib.sha256(content).hexdigest(),
        byte_count=len(content),
        executable=False,
        content_kind=ContentKind.BINARY if binary else ContentKind.TEXT,
    )
    final_tree = FinalTreeManifest.create(
        repository_id=state.repository_id,
        base_commit=state.head_commit,
        base_tree=state.head_tree,
        entries=(entry,),
    )
    patch_bytes = b"diff --git a/src/example.py b/src/example.py\n+updated\n"
    patch = PatchManifest.create(
        repository_id=state.repository_id,
        patch_bytes=patch_bytes,
        base_state_digest=state.state_digest,
        final_tree_manifest_digest=final_tree.manifest_digest,
        changed_paths=(entry.path,),
        binary_paths=(entry.path,) if binary else (),
    )
    return patch_bytes, final_tree, patch


def _approval_times() -> tuple[datetime, datetime]:
    created = datetime.now(UTC)
    return created, created + timedelta(minutes=5)


def apply_approval(
    state: RepositoryState,
    final_tree: FinalTreeManifest,
    patch: PatchManifest,
) -> ApplyPatchApproval:
    created, expires = _approval_times()
    payload = {
        "schema_version": "apply-patch-approval-v1",
        "purpose": DeliveryApprovalPurpose.APPLY_PATCH,
        "approval_id": "approval:apply",
        "repository_id": state.repository_id,
        "approver_id": "owner",
        "nonce": "nonce:apply",
        "created_at": created,
        "expires_at": expires,
        "expected_pre_state_digest": state.state_digest,
        "patch_manifest_digest": patch.manifest_digest,
        "final_tree_manifest_digest": final_tree.manifest_digest,
        "post_apply_checks_digest": "6" * 64,
        "binary_policy_digest": None,
    }
    return ApplyPatchApproval(
        **payload,
        approval_digest=content_digest(payload),
        authorization_proof="ephemeral-test-only",
    )


def commit_approval(
    state: RepositoryState,
    final_tree: FinalTreeManifest,
    commit_message: str,
) -> LocalCommitApproval:
    created, expires = _approval_times()
    payload = {
        "schema_version": "local-commit-approval-v1",
        "purpose": DeliveryApprovalPurpose.LOCAL_COMMIT,
        "approval_id": "approval:commit",
        "repository_id": state.repository_id,
        "approver_id": "owner",
        "nonce": "nonce:commit",
        "created_at": created,
        "expires_at": expires,
        "expected_applied_state_digest": state.state_digest,
        "final_tree_manifest_digest": final_tree.manifest_digest,
        "parent_commit": state.head_commit,
        "commit_message_sha256": hashlib.sha256(commit_message.encode()).hexdigest(),
        "verification_evidence_digest": "7" * 64,
    }
    return LocalCommitApproval(
        **payload,
        approval_digest=content_digest(payload),
        authorization_proof="ephemeral-test-only",
    )


def rollback_approval(
    current: RepositoryState,
    restore: RepositoryState,
    failed_operation_id: str,
) -> RollbackApproval:
    created, expires = _approval_times()
    payload = {
        "schema_version": "rollback-approval-v1",
        "purpose": DeliveryApprovalPurpose.ROLLBACK,
        "approval_id": "approval:rollback",
        "repository_id": current.repository_id,
        "approver_id": "owner",
        "nonce": "nonce:rollback",
        "created_at": created,
        "expires_at": expires,
        "expected_current_state_digest": current.state_digest,
        "restore_state_digest": restore.state_digest,
        "failed_operation_id": failed_operation_id,
        "recovery_snapshot_digest": "8" * 64,
    }
    return RollbackApproval(
        **payload,
        approval_digest=content_digest(payload),
        authorization_proof="ephemeral-test-only",
    )


def test_manifests_are_content_addressed_sorted_and_canonical() -> None:
    state = initial_state()
    _, final_tree, patch = delivery_artifacts(state)

    assert len(final_tree.tree_digest) == 64
    assert patch.base_state_digest == state.state_digest
    with pytest.raises(ValidationError, match="manifest digest mismatch"):
        FinalTreeManifest.model_validate({**final_tree.model_dump(), "manifest_digest": "f" * 64})
    with pytest.raises(ValidationError, match="patch manifest digest mismatch"):
        PatchManifest.model_validate({**patch.model_dump(), "patch_sha256": "f" * 64})
    with pytest.raises(ValidationError, match="canonical"):
        FinalTreeEntry(
            path="../escape",
            blob_sha256="a" * 64,
            byte_count=1,
        )
    with pytest.raises(ValidationError, match="unique sorted"):
        FinalTreeManifest.create(
            repository_id=state.repository_id,
            base_commit=state.head_commit,
            base_tree=state.head_tree,
            entries=(
                FinalTreeEntry(path="z", blob_sha256="a" * 64, byte_count=1),
                FinalTreeEntry(path="a", blob_sha256="b" * 64, byte_count=1),
            ),
        )


def test_git_command_is_structured_registry_bound_and_has_no_ambient_environment() -> None:
    command = StructuredGitCommand(
        repository_handle="registered:repository",
        executable_sha256="a" * 64,
        argv=("git", "apply", "--check", "-"),
        stdin_blob_sha256="b" * 64,
    )

    assert command.environment_digest == HARDENED_GIT_ENVIRONMENT_DIGEST
    environment = hardened_git_environment()
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_VALUE_0"] == "/dev/null"
    assert environment["GIT_CONFIG_VALUE_3"] == "never"
    assert environment["GIT_CONFIG_VALUE_7"] == "/bin/false"
    assert environment["GIT_CONFIG_VALUE_8"] == "false"
    assert environment["GIT_CONFIG_VALUE_9"] == "false"
    assert environment["GIT_CONFIG_VALUE_10"] == "/dev/null"
    assert environment["GIT_ATTR_NOSYSTEM"] == "1"
    assert environment["GIT_OPTIONAL_LOCKS"] == "0"
    assert "OPENAI_API_KEY" not in environment
    with pytest.raises(ValidationError, match="allowed Git operation template"):
        StructuredGitCommand(
            repository_handle="registered:repository",
            executable_sha256="a" * 64,
            argv=("git", "push", "origin", "main"),
        )
    with pytest.raises(ValidationError, match="allowed Git operation template"):
        StructuredGitCommand(
            repository_handle="registered:repository",
            executable_sha256="a" * 64,
            argv=("sh", "-c", "git status"),
        )


@pytest.mark.parametrize(
    "argv",
    (
        ("git", "diff", "--ext-diff"),
        ("git", "diff", "--textconv"),
        ("git", "apply", "--unsafe-paths", "-"),
        ("git", "cat-file", "--filters", "HEAD:payload"),
        ("git", "commit", "--gpg-sign", "-m", "message"),
        ("git", "status", "--porcelain=v2"),
    ),
)
def test_git_command_rejects_option_level_escape_hatches(argv: tuple[str, ...]) -> None:
    with pytest.raises(ValidationError, match="allowed Git operation template"):
        StructuredGitCommand(
            repository_handle="registered:repository",
            executable_sha256="a" * 64,
            argv=argv,
            stdin_blob_sha256="b" * 64 if argv[-1] == "-" else None,
        )


def test_git_command_allows_only_exact_purpose_built_templates() -> None:
    cached_diff = StructuredGitCommand(
        repository_handle="registered:repository",
        executable_sha256="a" * 64,
        argv=(
            "git",
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--binary",
            "--full-index",
            "--no-color",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            "--",
        ),
    )
    object_read = StructuredGitCommand(
        repository_handle="registered:repository",
        executable_sha256="a" * 64,
        argv=("git", "cat-file", "-p", "HEAD^{tree}"),
    )

    assert cached_diff.stdin_blob_sha256 is None
    assert object_read.argv[-1] == "HEAD^{tree}"
    with pytest.raises(ValidationError, match="stdin binding"):
        StructuredGitCommand(
            repository_handle="registered:repository",
            executable_sha256="a" * 64,
            argv=("git", "apply", "--check", "-"),
        )


async def test_disabled_publisher_is_truthfully_blocked_and_fails_closed() -> None:
    state = initial_state()
    patch_bytes, final_tree, patch = delivery_artifacts(state)
    approval = apply_approval(state, final_tree, patch)
    publisher = DisabledRepositoryPublisherClient()

    assert isinstance(publisher, RepositoryPublisherClient)
    assert publisher.capability.status == PublisherStatus.BLOCKED
    assert publisher.capability.operational is False
    with pytest.raises(RepositoryPublisherUnavailable):
        await publisher.inspect(state.repository_id)
    with pytest.raises(RepositoryPublisherUnavailable):
        await publisher.apply_patch(
            patch_bytes=patch_bytes,
            patch_manifest=patch,
            final_tree_manifest=final_tree,
            approval=approval,
        )


def test_ephemeral_publisher_cannot_be_constructed_outside_pytest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PYTEST_CURRENT_TEST")
    state = initial_state()

    with pytest.raises(RepositoryPublisherUnavailable, match="restricted to pytest"):
        EphemeralTestRepositoryPublisher({state.repository_id: state})


async def test_exact_pre_state_mismatch_rejects_without_consuming_approval() -> None:
    state = initial_state()
    patch_bytes, final_tree, patch = delivery_artifacts(state)
    approval = apply_approval(state, final_tree, patch)
    changed = RepositoryState.create(
        **{
            **state.model_dump(exclude={"schema_version", "state_digest"}),
            "worktree_status_digest": "9" * 64,
            "clean": False,
        }
    )
    publisher = EphemeralTestRepositoryPublisher({state.repository_id: changed})

    with pytest.raises(RepositoryDeliveryConflict, match="pre-state changed"):
        await publisher.apply_patch(
            patch_bytes=patch_bytes,
            patch_manifest=patch,
            final_tree_manifest=final_tree,
            approval=approval,
        )
    assert await publisher.inspect(state.repository_id) == changed
    assert publisher.approval_consumed(approval.approval_digest) is False


async def test_patch_byte_mismatch_rejects_without_consuming_approval() -> None:
    state = initial_state()
    patch_bytes, final_tree, patch = delivery_artifacts(state)
    approval = apply_approval(state, final_tree, patch)
    publisher = EphemeralTestRepositoryPublisher({state.repository_id: state})

    with pytest.raises(RepositoryDeliveryConflict, match="patch bytes"):
        await publisher.apply_patch(
            patch_bytes=patch_bytes + b"tampered",
            patch_manifest=patch,
            final_tree_manifest=final_tree,
            approval=approval,
        )
    assert await publisher.inspect(state.repository_id) == state
    assert publisher.approval_consumed(approval.approval_digest) is False


async def test_post_apply_failure_restores_exact_pre_state_and_consumes_approval() -> None:
    state = initial_state()
    patch_bytes, final_tree, patch = delivery_artifacts(state)
    approval = apply_approval(state, final_tree, patch)
    publisher = EphemeralTestRepositoryPublisher(
        {state.repository_id: state},
        post_apply_verifier=lambda _state: False,
    )

    with pytest.raises(RepositoryDeliveryFailed, match="exact pre-state restored"):
        await publisher.apply_patch(
            patch_bytes=patch_bytes,
            patch_manifest=patch,
            final_tree_manifest=final_tree,
            approval=approval,
        )
    assert await publisher.inspect(state.repository_id) == state
    assert publisher.approval_consumed(approval.approval_digest) is True
    with pytest.raises(RepositoryDeliveryConflict, match="already consumed"):
        await publisher.apply_patch(
            patch_bytes=patch_bytes,
            patch_manifest=patch,
            final_tree_manifest=final_tree,
            approval=approval,
        )


async def test_apply_commit_and_rollback_require_separate_one_use_approvals() -> None:
    original = initial_state()
    patch_bytes, final_tree, patch = delivery_artifacts(original)
    apply_auth = apply_approval(original, final_tree, patch)
    publisher = EphemeralTestRepositoryPublisher({original.repository_id: original})

    applied = await publisher.apply_patch(
        patch_bytes=patch_bytes,
        patch_manifest=patch,
        final_tree_manifest=final_tree,
        approval=apply_auth,
    )
    assert applied.applied_state.clean is False
    with pytest.raises(RepositoryDeliveryConflict, match="purpose-bound commit approval"):
        await publisher.local_commit(
            commit_message="Apply update",
            approval=apply_auth,  # type: ignore[arg-type]
        )

    commit_auth = commit_approval(applied.applied_state, final_tree, "Apply update")
    committed = await publisher.local_commit(
        commit_message="Apply update",
        approval=commit_auth,
    )
    assert committed.committed_state.clean is True
    assert committed.committed_state.head_commit != original.head_commit

    rollback_auth = rollback_approval(
        committed.committed_state,
        original,
        committed.operation_id,
    )
    rolled_back = await publisher.rollback(
        restore_state=original,
        approval=rollback_auth,
    )
    assert rolled_back.restored_state == original
    assert await publisher.inspect(original.repository_id) == original


async def test_binary_patch_is_blocked_before_approval_consumption() -> None:
    state = initial_state()
    patch_bytes, final_tree, patch = delivery_artifacts(state, binary=True)
    approval = apply_approval(state, final_tree, patch)
    publisher = EphemeralTestRepositoryPublisher({state.repository_id: state})

    with pytest.raises(RepositoryDeliveryConflict, match="binary delivery is blocked"):
        await publisher.apply_patch(
            patch_bytes=patch_bytes,
            patch_manifest=patch,
            final_tree_manifest=final_tree,
            approval=approval,
        )
    assert await publisher.inspect(state.repository_id) == state
    assert publisher.approval_consumed(approval.approval_digest) is False
