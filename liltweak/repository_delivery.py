from __future__ import annotations

import hashlib
import os
import re
import secrets
from asyncio import Lock
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Literal, Protocol, runtime_checkable

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator

from .workbench_contract import SAFE_ID, SHA256, WorkbenchSchema, content_digest

OBJECT_ID = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
BRANCH = r"^[A-Za-z0-9._/-]{1,255}$"
REGISTERED_REPOSITORY = r"^github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
MAX_APPROVAL_LIFETIME_SECONDS = 900

_GIT_ENVIRONMENT = {
    "GIT_ASKPASS": "/bin/false",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_CONFIG_COUNT": "11",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_KEY_0": "core.hooksPath",
    "GIT_CONFIG_KEY_1": "core.fsmonitor",
    "GIT_CONFIG_KEY_2": "credential.helper",
    "GIT_CONFIG_KEY_3": "protocol.allow",
    "GIT_CONFIG_KEY_4": "protocol.file.allow",
    "GIT_CONFIG_KEY_5": "submodule.recurse",
    "GIT_CONFIG_KEY_6": "fetch.recurseSubmodules",
    "GIT_CONFIG_KEY_7": "diff.external",
    "GIT_CONFIG_KEY_8": "commit.gpgSign",
    "GIT_CONFIG_KEY_9": "tag.gpgSign",
    "GIT_CONFIG_KEY_10": "core.attributesFile",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_VALUE_0": "/dev/null",
    "GIT_CONFIG_VALUE_1": "false",
    "GIT_CONFIG_VALUE_2": "",
    "GIT_CONFIG_VALUE_3": "never",
    "GIT_CONFIG_VALUE_4": "never",
    "GIT_CONFIG_VALUE_5": "false",
    "GIT_CONFIG_VALUE_6": "false",
    "GIT_CONFIG_VALUE_7": "/bin/false",
    "GIT_CONFIG_VALUE_8": "false",
    "GIT_CONFIG_VALUE_9": "false",
    "GIT_CONFIG_VALUE_10": "/dev/null",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM": "0",
    "GIT_EDITOR": "/bin/false",
    "GIT_LFS_SKIP_SMUDGE": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_PAGER": "cat",
    "GIT_SEQUENCE_EDITOR": "/bin/false",
    "GIT_TERMINAL_PROMPT": "0",
    "LC_ALL": "C.UTF-8",
    "PAGER": "cat",
    "SSH_ASKPASS": "/bin/false",
}
HARDENED_GIT_ENVIRONMENT: Mapping[str, str] = MappingProxyType(_GIT_ENVIRONMENT)
HARDENED_GIT_ENVIRONMENT_DIGEST = content_digest(_GIT_ENVIRONMENT)

_SAFE_GIT_STDIN_TEMPLATES = frozenset(
    {
        ("git", "apply", "--check", "-"),
        ("git", "apply", "--check", "--recount", "--whitespace=error-all", "-"),
        ("git", "apply", "--index", "--recount", "--whitespace=error-all", "-"),
        ("git", "commit", "--no-verify", "--no-gpg-sign", "-F", "-"),
        ("git", "hash-object", "--stdin"),
        ("git", "hash-object", "-w", "--stdin"),
        ("git", "update-index", "--index-info"),
    }
)
_SAFE_GIT_NO_STDIN_TEMPLATES = frozenset(
    {
        (
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
        ("git", "rev-parse", "--abbrev-ref", "HEAD"),
        ("git", "write-tree"),
    }
)
_GIT_OBJECTISH = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64}|HEAD(?:\^\{(?:commit|tree)\})?)$")


def _git_command_template(argv: tuple[str, ...]) -> tuple[bool, bool]:
    """Return ``(allowed, requires_stdin)`` for an exact, non-extensible Git operation."""

    if argv in _SAFE_GIT_STDIN_TEMPLATES:
        return True, True
    if argv in _SAFE_GIT_NO_STDIN_TEMPLATES:
        return True, False
    if len(argv) == 4 and argv[:3] in {
        ("git", "cat-file", "-e"),
        ("git", "cat-file", "-p"),
        ("git", "cat-file", "-s"),
        ("git", "cat-file", "-t"),
        ("git", "read-tree", "--reset"),
        ("git", "rev-parse", "--verify"),
    }:
        return _GIT_OBJECTISH.fullmatch(argv[3]) is not None, False
    return False, False


class RepositoryDeliveryError(RuntimeError):
    pass


class RepositoryPublisherUnavailable(RepositoryDeliveryError):
    pass


class RepositoryDeliveryConflict(RepositoryDeliveryError):
    pass


class RepositoryDeliveryFailed(RepositoryDeliveryError):
    pass


class PublisherStatus(StrEnum):
    BLOCKED = "blocked"
    TEST_ONLY = "test_only"
    OPERATIONAL = "operational"
    FAILED = "failed"


class ContentKind(StrEnum):
    TEXT = "text"
    BINARY = "binary"


class DeliveryApprovalPurpose(StrEnum):
    APPLY_PATCH = "apply_patch"
    LOCAL_COMMIT = "local_commit"
    ROLLBACK = "rollback"


def hardened_git_environment() -> dict[str, str]:
    """Return the complete environment allowlist; callers must not merge ambient values."""

    return dict(HARDENED_GIT_ENVIRONMENT)


def _canonical_path(value: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise ValueError("manifest path is invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(part.casefold() == ".git" for part in path.parts)
    ):
        raise ValueError("manifest path must be canonical, relative, and outside .git")
    return value


class PublisherCapability(WorkbenchSchema):
    schema_version: Literal["repository-publisher-capability-v1"] = (
        "repository-publisher-capability-v1"
    )
    provider_id: StrictStr = Field(pattern=SAFE_ID)
    configured: StrictBool
    isolated_principal: StrictBool
    owner_tree_access: StrictBool
    exact_state_verification: StrictBool
    approval_verification: StrictBool
    operational: StrictBool
    test_only: StrictBool = False
    status: PublisherStatus
    reason_code: StrictStr = Field(pattern=SAFE_ID)

    @model_validator(mode="after")
    def status_is_truthful(self) -> PublisherCapability:
        prerequisites = (
            self.configured,
            self.isolated_principal,
            self.owner_tree_access,
            self.exact_state_verification,
            self.approval_verification,
        )
        if self.operational != all(prerequisites):
            raise ValueError("publisher operational status contradicts its prerequisites")
        if self.operational != (self.status == PublisherStatus.OPERATIONAL):
            raise ValueError("publisher status contradicts its operational flag")
        if self.test_only != (self.status == PublisherStatus.TEST_ONLY):
            raise ValueError("publisher test-only status is inconsistent")
        if self.test_only and self.operational:
            raise ValueError("test-only publisher cannot claim operational status")
        return self


class StructuredGitCommand(WorkbenchSchema):
    """A registry-bound Git invocation. It is never a shell command string."""

    schema_version: Literal["publisher-git-command-v1"] = "publisher-git-command-v1"
    repository_handle: StrictStr = Field(pattern=SAFE_ID)
    executable_registry_id: Literal["publisher.git.v1"] = "publisher.git.v1"
    executable_sha256: StrictStr = Field(pattern=SHA256)
    argv: tuple[StrictStr, ...] = Field(min_length=2, max_length=128)
    environment_digest: Literal[HARDENED_GIT_ENVIRONMENT_DIGEST] = HARDENED_GIT_ENVIRONMENT_DIGEST
    stdin_blob_sha256: StrictStr | None = Field(default=None, pattern=SHA256)
    timeout_seconds: StrictInt = Field(default=120, ge=1, le=600)

    @model_validator(mode="after")
    def structured_and_bounded(self) -> StructuredGitCommand:
        if any(
            not argument
            or len(argument) > 2_048
            or any(ord(character) < 32 or ord(character) == 127 for character in argument)
            for argument in self.argv
        ):
            raise ValueError("publisher argv contains an invalid structured argument")
        allowed, requires_stdin = _git_command_template(self.argv)
        if not allowed:
            raise ValueError("publisher command does not match an allowed Git operation template")
        if requires_stdin != (self.stdin_blob_sha256 is not None):
            raise ValueError("publisher Git operation stdin binding is invalid")
        return self


class FinalTreeEntry(WorkbenchSchema):
    path: StrictStr = Field(min_length=1, max_length=512)
    blob_sha256: StrictStr = Field(pattern=SHA256)
    byte_count: StrictInt = Field(ge=0, le=250_000_000)
    executable: StrictBool = False
    content_kind: ContentKind = ContentKind.TEXT

    @model_validator(mode="after")
    def canonical_path(self) -> FinalTreeEntry:
        _canonical_path(self.path)
        return self


class FinalTreeManifest(WorkbenchSchema):
    schema_version: Literal["repository-final-tree-manifest-v1"] = (
        "repository-final-tree-manifest-v1"
    )
    repository_id: StrictStr = Field(pattern=REGISTERED_REPOSITORY)
    base_commit: StrictStr = Field(pattern=OBJECT_ID)
    base_tree: StrictStr = Field(pattern=OBJECT_ID)
    entries: tuple[FinalTreeEntry, ...] = Field(max_length=100_000)
    tree_digest: StrictStr = Field(pattern=SHA256)
    manifest_digest: StrictStr = Field(pattern=SHA256)

    @classmethod
    def create(
        cls,
        *,
        repository_id: str,
        base_commit: str,
        base_tree: str,
        entries: tuple[FinalTreeEntry, ...],
    ) -> FinalTreeManifest:
        tree_digest = content_digest(
            {
                "schema_version": "repository-content-tree-v1",
                "entries": entries,
            }
        )
        payload = {
            "schema_version": "repository-final-tree-manifest-v1",
            "repository_id": repository_id,
            "base_commit": base_commit,
            "base_tree": base_tree,
            "entries": entries,
            "tree_digest": tree_digest,
        }
        return cls(**payload, manifest_digest=content_digest(payload))

    @model_validator(mode="after")
    def content_addresses_are_valid(self) -> FinalTreeManifest:
        paths = tuple(entry.path for entry in self.entries)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("final-tree entries must have unique sorted paths")
        expected_tree = content_digest(
            {
                "schema_version": "repository-content-tree-v1",
                "entries": self.entries,
            }
        )
        payload = self.model_dump(mode="python", exclude={"manifest_digest"})
        if not secrets.compare_digest(self.tree_digest, expected_tree):
            raise ValueError("final-tree content digest mismatch")
        if not secrets.compare_digest(self.manifest_digest, content_digest(payload)):
            raise ValueError("final-tree manifest digest mismatch")
        return self


class PatchManifest(WorkbenchSchema):
    schema_version: Literal["repository-patch-manifest-v1"] = "repository-patch-manifest-v1"
    repository_id: StrictStr = Field(pattern=REGISTERED_REPOSITORY)
    format: Literal["git-diff-v1"] = "git-diff-v1"
    patch_sha256: StrictStr = Field(pattern=SHA256)
    patch_byte_count: StrictInt = Field(ge=1, le=250_000_000)
    base_state_digest: StrictStr = Field(pattern=SHA256)
    final_tree_manifest_digest: StrictStr = Field(pattern=SHA256)
    changed_paths: tuple[StrictStr, ...] = Field(min_length=1, max_length=100_000)
    binary_paths: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=100_000)
    manifest_digest: StrictStr = Field(pattern=SHA256)

    @classmethod
    def create(
        cls,
        *,
        repository_id: str,
        patch_bytes: bytes,
        base_state_digest: str,
        final_tree_manifest_digest: str,
        changed_paths: tuple[str, ...],
        binary_paths: tuple[str, ...] = (),
    ) -> PatchManifest:
        payload = {
            "schema_version": "repository-patch-manifest-v1",
            "repository_id": repository_id,
            "format": "git-diff-v1",
            "patch_sha256": hashlib.sha256(patch_bytes).hexdigest(),
            "patch_byte_count": len(patch_bytes),
            "base_state_digest": base_state_digest,
            "final_tree_manifest_digest": final_tree_manifest_digest,
            "changed_paths": changed_paths,
            "binary_paths": binary_paths,
        }
        return cls(**payload, manifest_digest=content_digest(payload))

    @model_validator(mode="after")
    def content_addresses_are_valid(self) -> PatchManifest:
        for path in (*self.changed_paths, *self.binary_paths):
            _canonical_path(path)
        if self.changed_paths != tuple(sorted(self.changed_paths)) or len(
            self.changed_paths
        ) != len(set(self.changed_paths)):
            raise ValueError("changed paths must be unique and sorted")
        if self.binary_paths != tuple(sorted(self.binary_paths)) or len(self.binary_paths) != len(
            set(self.binary_paths)
        ):
            raise ValueError("binary paths must be unique and sorted")
        if not set(self.binary_paths).issubset(self.changed_paths):
            raise ValueError("binary paths must be included in changed paths")
        payload = self.model_dump(mode="python", exclude={"manifest_digest"})
        if not secrets.compare_digest(self.manifest_digest, content_digest(payload)):
            raise ValueError("patch manifest digest mismatch")
        return self


class RepositoryState(WorkbenchSchema):
    schema_version: Literal["repository-exact-state-v1"] = "repository-exact-state-v1"
    repository_id: StrictStr = Field(pattern=REGISTERED_REPOSITORY)
    branch: StrictStr = Field(pattern=BRANCH)
    head_commit: StrictStr = Field(pattern=OBJECT_ID)
    head_tree: StrictStr = Field(pattern=OBJECT_ID)
    worktree_manifest_digest: StrictStr = Field(pattern=SHA256)
    index_tree_digest: StrictStr = Field(pattern=SHA256)
    worktree_status_digest: StrictStr = Field(pattern=SHA256)
    clean: StrictBool
    state_digest: StrictStr = Field(pattern=SHA256)

    @classmethod
    def create(
        cls,
        *,
        repository_id: str,
        branch: str,
        head_commit: str,
        head_tree: str,
        worktree_manifest_digest: str,
        index_tree_digest: str,
        worktree_status_digest: str,
        clean: bool,
    ) -> RepositoryState:
        payload = {
            "schema_version": "repository-exact-state-v1",
            "repository_id": repository_id,
            "branch": branch,
            "head_commit": head_commit,
            "head_tree": head_tree,
            "worktree_manifest_digest": worktree_manifest_digest,
            "index_tree_digest": index_tree_digest,
            "worktree_status_digest": worktree_status_digest,
            "clean": clean,
        }
        return cls(**payload, state_digest=content_digest(payload))

    @model_validator(mode="after")
    def state_digest_is_valid(self) -> RepositoryState:
        if (
            self.branch[0] in "./"
            or self.branch[-1] in "./"
            or any(value in self.branch for value in ("..", "//", "@{", "\\"))
        ):
            raise ValueError("repository branch name is not canonical")
        payload = self.model_dump(mode="python", exclude={"state_digest"})
        if not secrets.compare_digest(self.state_digest, content_digest(payload)):
            raise ValueError("repository state digest mismatch")
        return self


class _DeliveryApproval(WorkbenchSchema):
    approval_id: StrictStr = Field(pattern=SAFE_ID)
    repository_id: StrictStr = Field(pattern=REGISTERED_REPOSITORY)
    approver_id: StrictStr = Field(pattern=SAFE_ID)
    nonce: StrictStr = Field(pattern=SAFE_ID)
    created_at: datetime
    expires_at: datetime
    approval_digest: StrictStr = Field(pattern=SHA256)
    authorization_proof: StrictStr = Field(min_length=1, max_length=8_192)

    @model_validator(mode="after")
    def approval_is_bound_and_fresh(self) -> _DeliveryApproval:
        if (
            self.created_at.tzinfo is None
            or self.created_at.utcoffset() is None
            or self.expires_at.tzinfo is None
            or self.expires_at.utcoffset() is None
        ):
            raise ValueError("delivery approval timestamps must be timezone-aware")
        lifetime = (self.expires_at - self.created_at).total_seconds()
        if lifetime <= 0 or lifetime > MAX_APPROVAL_LIFETIME_SECONDS:
            raise ValueError("delivery approval lifetime is invalid")
        payload = self.model_dump(
            mode="python",
            exclude={"approval_digest", "authorization_proof"},
        )
        if not secrets.compare_digest(self.approval_digest, content_digest(payload)):
            raise ValueError("delivery approval digest mismatch")
        return self


class ApplyPatchApproval(_DeliveryApproval):
    schema_version: Literal["apply-patch-approval-v1"] = "apply-patch-approval-v1"
    purpose: Literal[DeliveryApprovalPurpose.APPLY_PATCH] = DeliveryApprovalPurpose.APPLY_PATCH
    expected_pre_state_digest: StrictStr = Field(pattern=SHA256)
    patch_manifest_digest: StrictStr = Field(pattern=SHA256)
    final_tree_manifest_digest: StrictStr = Field(pattern=SHA256)
    post_apply_checks_digest: StrictStr = Field(pattern=SHA256)
    binary_policy_digest: None = None


class LocalCommitApproval(_DeliveryApproval):
    schema_version: Literal["local-commit-approval-v1"] = "local-commit-approval-v1"
    purpose: Literal[DeliveryApprovalPurpose.LOCAL_COMMIT] = DeliveryApprovalPurpose.LOCAL_COMMIT
    expected_applied_state_digest: StrictStr = Field(pattern=SHA256)
    final_tree_manifest_digest: StrictStr = Field(pattern=SHA256)
    parent_commit: StrictStr = Field(pattern=OBJECT_ID)
    commit_message_sha256: StrictStr = Field(pattern=SHA256)
    verification_evidence_digest: StrictStr = Field(pattern=SHA256)


class RollbackApproval(_DeliveryApproval):
    schema_version: Literal["rollback-approval-v1"] = "rollback-approval-v1"
    purpose: Literal[DeliveryApprovalPurpose.ROLLBACK] = DeliveryApprovalPurpose.ROLLBACK
    expected_current_state_digest: StrictStr = Field(pattern=SHA256)
    restore_state_digest: StrictStr = Field(pattern=SHA256)
    failed_operation_id: StrictStr = Field(pattern=SAFE_ID)
    recovery_snapshot_digest: StrictStr = Field(pattern=SHA256)


class ApplyPatchResult(WorkbenchSchema):
    schema_version: Literal["apply-patch-result-v1"] = "apply-patch-result-v1"
    operation_id: StrictStr = Field(pattern=SAFE_ID)
    approval_digest: StrictStr = Field(pattern=SHA256)
    pre_state_digest: StrictStr = Field(pattern=SHA256)
    applied_state: RepositoryState
    patch_manifest_digest: StrictStr = Field(pattern=SHA256)
    final_tree_manifest_digest: StrictStr = Field(pattern=SHA256)
    post_apply_checks_passed: Literal[True] = True


class LocalCommitResult(WorkbenchSchema):
    schema_version: Literal["local-commit-result-v1"] = "local-commit-result-v1"
    operation_id: StrictStr = Field(pattern=SAFE_ID)
    approval_digest: StrictStr = Field(pattern=SHA256)
    committed_state: RepositoryState


class RollbackResult(WorkbenchSchema):
    schema_version: Literal["rollback-result-v1"] = "rollback-result-v1"
    operation_id: StrictStr = Field(pattern=SAFE_ID)
    approval_digest: StrictStr = Field(pattern=SHA256)
    restored_state: RepositoryState


@runtime_checkable
class RepositoryPublisherClient(Protocol):
    """Isolated owner-tree publisher boundary.

    A production implementation must authenticate approval proofs with a separate owner
    authority, resolve only registered repository handles, launch structured commands with
    exactly ``hardened_git_environment()``, journal each operation durably, and never push.
    Returning from a method means the exact resulting repository state was re-inspected.
    """

    @property
    def capability(self) -> PublisherCapability: ...

    async def inspect(self, repository_id: str) -> RepositoryState: ...

    async def apply_patch(
        self,
        *,
        patch_bytes: bytes,
        patch_manifest: PatchManifest,
        final_tree_manifest: FinalTreeManifest,
        approval: ApplyPatchApproval,
    ) -> ApplyPatchResult: ...

    async def local_commit(
        self,
        *,
        commit_message: str,
        approval: LocalCommitApproval,
    ) -> LocalCommitResult: ...

    async def rollback(
        self,
        *,
        restore_state: RepositoryState,
        approval: RollbackApproval,
    ) -> RollbackResult: ...


class DisabledRepositoryPublisherClient:
    def __init__(self, *, reason_code: str = "not_configured") -> None:
        self._capability = PublisherCapability(
            provider_id="disabled",
            configured=False,
            isolated_principal=False,
            owner_tree_access=False,
            exact_state_verification=False,
            approval_verification=False,
            operational=False,
            test_only=False,
            status=PublisherStatus.BLOCKED,
            reason_code=reason_code,
        )

    @property
    def capability(self) -> PublisherCapability:
        return self._capability

    async def inspect(self, repository_id: str) -> RepositoryState:
        del repository_id
        self._unavailable()

    async def apply_patch(
        self,
        *,
        patch_bytes: bytes,
        patch_manifest: PatchManifest,
        final_tree_manifest: FinalTreeManifest,
        approval: ApplyPatchApproval,
    ) -> ApplyPatchResult:
        del patch_bytes, patch_manifest, final_tree_manifest, approval
        self._unavailable()

    async def local_commit(
        self,
        *,
        commit_message: str,
        approval: LocalCommitApproval,
    ) -> LocalCommitResult:
        del commit_message, approval
        self._unavailable()

    async def rollback(
        self,
        *,
        restore_state: RepositoryState,
        approval: RollbackApproval,
    ) -> RollbackResult:
        del restore_state, approval
        self._unavailable()

    def _unavailable(self) -> None:
        raise RepositoryPublisherUnavailable(
            f"repository publisher unavailable: {self._capability.reason_code}"
        )


class EphemeralTestRepositoryPublisher:
    """In-memory protocol exerciser. It cannot touch or qualify an owner repository."""

    def __init__(
        self,
        initial_states: Mapping[str, RepositoryState],
        *,
        post_apply_verifier: Callable[[RepositoryState], bool] | None = None,
    ) -> None:
        if "PYTEST_CURRENT_TEST" not in os.environ:
            raise RepositoryPublisherUnavailable(
                "ephemeral repository publisher is restricted to pytest"
            )
        self._states = dict(initial_states)
        if any(key != value.repository_id for key, value in self._states.items()):
            raise ValueError("ephemeral repository state key does not match repository id")
        self._post_apply_verifier = post_apply_verifier or (lambda _state: True)
        self._consumed_approvals: set[str] = set()
        self._final_manifests: dict[str, FinalTreeManifest] = {}
        self._lock = Lock()
        self._capability = PublisherCapability(
            provider_id="ephemeral-test-publisher",
            configured=False,
            isolated_principal=False,
            owner_tree_access=False,
            exact_state_verification=True,
            approval_verification=False,
            operational=False,
            test_only=True,
            status=PublisherStatus.TEST_ONLY,
            reason_code="pytest_protocol_exerciser",
        )

    @property
    def capability(self) -> PublisherCapability:
        return self._capability

    async def inspect(self, repository_id: str) -> RepositoryState:
        try:
            return self._states[repository_id]
        except KeyError as exc:
            raise RepositoryDeliveryConflict("repository is not registered") from exc

    def approval_consumed(self, approval_digest: str) -> bool:
        return approval_digest in self._consumed_approvals

    async def apply_patch(
        self,
        *,
        patch_bytes: bytes,
        patch_manifest: PatchManifest,
        final_tree_manifest: FinalTreeManifest,
        approval: ApplyPatchApproval,
    ) -> ApplyPatchResult:
        if not isinstance(approval, ApplyPatchApproval):
            raise RepositoryDeliveryConflict("apply requires a purpose-bound apply approval")
        async with self._lock:
            self._validate_authorization(approval)
            current = await self.inspect(approval.repository_id)
            if current.state_digest != approval.expected_pre_state_digest:
                raise RepositoryDeliveryConflict("owner repository pre-state changed")
            if (
                patch_manifest.repository_id != approval.repository_id
                or final_tree_manifest.repository_id != approval.repository_id
                or patch_manifest.base_state_digest != current.state_digest
                or final_tree_manifest.base_commit != current.head_commit
                or final_tree_manifest.base_tree != current.head_tree
                or approval.patch_manifest_digest != patch_manifest.manifest_digest
                or approval.final_tree_manifest_digest != final_tree_manifest.manifest_digest
                or patch_manifest.final_tree_manifest_digest != final_tree_manifest.manifest_digest
            ):
                raise RepositoryDeliveryConflict("delivery manifests or approval bindings differ")
            if (
                len(patch_bytes) != patch_manifest.patch_byte_count
                or hashlib.sha256(patch_bytes).hexdigest() != patch_manifest.patch_sha256
            ):
                raise RepositoryDeliveryConflict("patch bytes do not match their manifest")
            if patch_manifest.binary_paths or any(
                entry.content_kind == ContentKind.BINARY for entry in final_tree_manifest.entries
            ):
                raise RepositoryDeliveryConflict(
                    "binary delivery is blocked until a separate policy is qualified"
                )

            self._consume(approval.approval_digest)
            operation_id = f"apply:{approval.approval_digest[:24]}"
            candidate = RepositoryState.create(
                repository_id=current.repository_id,
                branch=current.branch,
                head_commit=current.head_commit,
                head_tree=current.head_tree,
                worktree_manifest_digest=final_tree_manifest.manifest_digest,
                index_tree_digest=current.index_tree_digest,
                worktree_status_digest=content_digest(
                    {
                        "schema_version": "ephemeral-applied-status-v1",
                        "operation_id": operation_id,
                        "patch_manifest_digest": patch_manifest.manifest_digest,
                    }
                ),
                clean=False,
            )
            self._states[current.repository_id] = candidate
            try:
                checks_passed = self._post_apply_verifier(candidate)
            except Exception as exc:
                self._states[current.repository_id] = current
                raise RepositoryDeliveryFailed(
                    "post-apply verification failed; exact pre-state restored"
                ) from exc
            if not checks_passed:
                self._states[current.repository_id] = current
                raise RepositoryDeliveryFailed(
                    "post-apply verification failed; exact pre-state restored"
                )
            self._final_manifests[current.repository_id] = final_tree_manifest
            return ApplyPatchResult(
                operation_id=operation_id,
                approval_digest=approval.approval_digest,
                pre_state_digest=current.state_digest,
                applied_state=candidate,
                patch_manifest_digest=patch_manifest.manifest_digest,
                final_tree_manifest_digest=final_tree_manifest.manifest_digest,
            )

    async def local_commit(
        self,
        *,
        commit_message: str,
        approval: LocalCommitApproval,
    ) -> LocalCommitResult:
        if not isinstance(approval, LocalCommitApproval):
            raise RepositoryDeliveryConflict("commit requires a purpose-bound commit approval")
        async with self._lock:
            self._validate_authorization(approval)
            current = await self.inspect(approval.repository_id)
            manifest = self._final_manifests.get(approval.repository_id)
            if (
                current.state_digest != approval.expected_applied_state_digest
                or current.head_commit != approval.parent_commit
                or manifest is None
                or manifest.manifest_digest != approval.final_tree_manifest_digest
                or current.worktree_manifest_digest != manifest.manifest_digest
                or hashlib.sha256(commit_message.encode("utf-8")).hexdigest()
                != approval.commit_message_sha256
            ):
                raise RepositoryDeliveryConflict("commit state, manifest, or message changed")
            self._consume(approval.approval_digest)
            operation_id = f"commit:{approval.approval_digest[:24]}"
            commit_id = content_digest(
                {
                    "schema_version": "ephemeral-local-commit-v1",
                    "parent": current.head_commit,
                    "tree": manifest.tree_digest,
                    "message_sha256": approval.commit_message_sha256,
                    "approval_digest": approval.approval_digest,
                }
            )
            committed = RepositoryState.create(
                repository_id=current.repository_id,
                branch=current.branch,
                head_commit=commit_id,
                head_tree=manifest.tree_digest,
                worktree_manifest_digest=manifest.manifest_digest,
                index_tree_digest=manifest.tree_digest,
                worktree_status_digest=content_digest(
                    {
                        "schema_version": "ephemeral-clean-status-v1",
                        "head_commit": commit_id,
                    }
                ),
                clean=True,
            )
            self._states[current.repository_id] = committed
            return LocalCommitResult(
                operation_id=operation_id,
                approval_digest=approval.approval_digest,
                committed_state=committed,
            )

    async def rollback(
        self,
        *,
        restore_state: RepositoryState,
        approval: RollbackApproval,
    ) -> RollbackResult:
        if not isinstance(approval, RollbackApproval):
            raise RepositoryDeliveryConflict("rollback requires a purpose-bound rollback approval")
        async with self._lock:
            self._validate_authorization(approval)
            current = await self.inspect(approval.repository_id)
            if (
                current.state_digest != approval.expected_current_state_digest
                or restore_state.repository_id != approval.repository_id
                or restore_state.state_digest != approval.restore_state_digest
            ):
                raise RepositoryDeliveryConflict("rollback current or restore state changed")
            self._consume(approval.approval_digest)
            self._states[approval.repository_id] = restore_state
            return RollbackResult(
                operation_id=f"rollback:{approval.approval_digest[:24]}",
                approval_digest=approval.approval_digest,
                restored_state=restore_state,
            )

    def _validate_authorization(self, approval: _DeliveryApproval) -> None:
        if approval.authorization_proof != "ephemeral-test-only":
            raise RepositoryDeliveryConflict("ephemeral approval proof is invalid")
        if datetime.now(UTC) >= approval.expires_at:
            raise RepositoryDeliveryConflict("delivery approval expired")
        if approval.approval_digest in self._consumed_approvals:
            raise RepositoryDeliveryConflict("delivery approval was already consumed")

    def _consume(self, approval_digest: str) -> None:
        if approval_digest in self._consumed_approvals:
            raise RepositoryDeliveryConflict("delivery approval was already consumed")
        self._consumed_approvals.add(approval_digest)
