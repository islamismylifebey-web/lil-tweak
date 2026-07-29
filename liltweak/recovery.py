from __future__ import annotations

import hashlib
import hmac
import io
import os
import re
import selectors
import signal
import stat
import subprocess
import tarfile
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from threading import RLock
from typing import Any

from .artifacts import EncryptedArtifactStore
from .models import (
    ArtifactKind,
    ArtifactRecord,
    JobRecord,
    RecoveryPackage,
    RecoveryStatus,
)
from .repository import (
    RepositoryAccessError,
    RepositoryInspector,
    is_sensitive_path,
    secret_rule_ids,
)
from .store import canonical_json


class RecoveryError(RuntimeError):
    pass


class RecoveryUnavailableError(RecoveryError):
    pass


class RecoveryBlockedError(RecoveryError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class RecoveryLimits:
    max_patch_bytes: int = 8_000_000
    max_tracked_files: int = 10_000
    max_tracked_file_bytes: int = 64_000_000
    max_tracked_total_bytes: int = 2_000_000_000
    max_git_object_total_bytes: int = 128_000_000
    max_untracked_files: int = 500
    max_untracked_file_bytes: int = 8_000_000
    max_untracked_total_bytes: int = 24_000_000
    max_path_bytes: int = 512
    max_path_depth: int = 32
    git_timeout_seconds: float = 15.0


@dataclass(frozen=True)
class _PreparedArtifact:
    kind: ArtifactKind
    media_type: str
    plaintext: bytes


@dataclass(frozen=True)
class _BlobEntry:
    mode: str
    oid: str


@dataclass
class _BlobCache:
    contents: dict[str, bytes]
    total_bytes: int = 0


_BIDI_CONTROLS = {
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}


class RecoveryCapture:
    """Create encrypted recovery artifacts without mutating a registered repository."""

    def __init__(
        self,
        *,
        inspector: RepositoryInspector,
        artifact_store: EncryptedArtifactStore,
        limits: RecoveryLimits | None = None,
    ) -> None:
        self.inspector = inspector
        self.artifact_store = artifact_store
        self.limits = limits or RecoveryLimits()
        self._capture_lock = RLock()

    def capture(
        self,
        job: JobRecord,
        package: RecoveryPackage,
        *,
        stop_requested: Callable[[], bool] | None = None,
    ) -> RecoveryPackage:
        if job.task.repository is None or job.inspection is None:
            raise RecoveryUnavailableError("repository inspection is required")
        reference = job.task.repository
        repository = self.inspector.registered_path(reference)
        published: list[ArtifactRecord] = []
        with self._capture_lock:
            try:
                self._require_not_stopped(stop_requested)
                before = self.inspector.inspect(reference)
                self._require_matching_snapshot(job, package, before)
                self._validate_git_boundary(repository)
                prepared, untracked_manifest = self._prepare_artifacts(
                    repository,
                    package.base_head,
                    reference.allowed_paths,
                    package.planned_artifacts,
                )
                self._require_not_stopped(stop_requested)
                after_capture = self.inspector.inspect(reference)
                if (
                    after_capture.repository_fingerprint != before.repository_fingerprint
                    or after_capture.git.head_revision != before.git.head_revision
                ):
                    raise RecoveryBlockedError(
                        "source_changed_during_capture",
                        "repository changed during recovery capture",
                    )

                for item in prepared:
                    self._require_not_stopped(stop_requested)
                    artifact = self.artifact_store.put_bytes(
                        job=job,
                        kind=item.kind,
                        media_type=item.media_type,
                        plaintext=item.plaintext,
                    )
                    published.append(artifact)

                manifest_payload = self._manifest_payload(
                    job=job,
                    package=package,
                    inspection=before,
                    after_capture_fingerprint=after_capture.repository_fingerprint,
                    artifacts=published,
                    untracked_manifest=untracked_manifest,
                )
                manifest_bytes = canonical_json(manifest_payload).encode()
                manifest_artifact = self.artifact_store.put_bytes(
                    job=job,
                    kind=ArtifactKind.RECOVERY_MANIFEST,
                    media_type="application/vnd.liltweak.recovery-manifest+json",
                    plaintext=manifest_bytes,
                )
                published.append(manifest_artifact)
                for artifact in published:
                    self.artifact_store.verify_and_decrypt(artifact)

                self._require_not_stopped(stop_requested)
                after_publish = self.inspector.inspect(reference)
                if (
                    after_publish.repository_fingerprint != before.repository_fingerprint
                    or after_publish.git.head_revision != before.git.head_revision
                ):
                    raise RecoveryBlockedError(
                        "source_changed_during_publication",
                        "repository changed while recovery artifacts were published",
                    )
            except Exception:
                for artifact in published:
                    self.artifact_store.quarantine(artifact)
                raise

        package.artifacts = published
        package.manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        package.after_fingerprint = after_publish.repository_fingerprint
        package.status = (
            RecoveryStatus.READY if package.complete_for_scope else RecoveryStatus.INCOMPLETE
        )
        return package

    @staticmethod
    def _require_not_stopped(
        stop_requested: Callable[[], bool] | None,
    ) -> None:
        if stop_requested is not None and stop_requested():
            raise RecoveryBlockedError(
                "capture_stopped",
                "recovery capture was canceled before publication completed",
            )

    def _require_matching_snapshot(
        self,
        job: JobRecord,
        package: RecoveryPackage,
        inspection,
    ) -> None:
        if not inspection.read_only_verified or not inspection.complete:
            raise RecoveryBlockedError(
                "inspection_incomplete",
                "a complete read-only inspection is required",
            )
        if inspection.git.status_truncated or not inspection.git.metadata_complete:
            raise RecoveryBlockedError(
                "git_metadata_incomplete",
                "complete Git status is required",
            )
        if inspection.git.conflicted_paths:
            raise RecoveryBlockedError(
                "unmerged_index",
                "repositories with unresolved conflicts cannot be captured",
            )
        if (
            inspection.repository_fingerprint != job.inspection.repository_fingerprint
            or inspection.repository_fingerprint != package.source_fingerprint
            or inspection.git.recovery_snapshot_digest is None
            or not hmac.compare_digest(
                inspection.git.recovery_snapshot_digest,
                package.source_snapshot_digest,
            )
            or inspection.git.head_revision != package.base_head
        ):
            raise RecoveryBlockedError(
                "stale_source_fingerprint",
                "repository state no longer matches the approved recovery action",
            )

    def _validate_git_boundary(self, repository: Path) -> None:
        try:
            self.inspector.validate_git_metadata_safety(repository)
        except RepositoryAccessError as exc:
            raise RecoveryBlockedError(
                "unsafe_git_metadata",
                "Git metadata failed recovery safety validation",
            ) from exc
        git_directory = repository / ".git"
        if not git_directory.is_dir() or git_directory.is_symlink():
            raise RecoveryBlockedError(
                "unsupported_git_layout",
                "recovery capture requires an in-repository Git directory",
            )
        alternates = git_directory / "objects" / "info" / "alternates"
        if alternates.exists() or alternates.is_symlink():
            raise RecoveryBlockedError(
                "git_object_alternates",
                "Git object alternates are not permitted during recovery capture",
            )
        configured_keys = self._run_git(
            repository,
            [
                "config",
                "--file",
                str(git_directory / "config"),
                "--no-includes",
                "--name-only",
                "--get-regexp",
                ".*",
            ],
            output_limit=64_000,
            allowed_return_codes={0, 1},
        )
        filter_suffixes = {".clean", ".smudge", ".process", ".required"}
        keys = {
            key.strip().lower()
            for key in configured_keys.decode("utf-8", errors="replace").splitlines()
        }
        if any(
            key.startswith("filter.") and any(key.endswith(suffix) for suffix in filter_suffixes)
            for key in keys
        ):
            raise RecoveryBlockedError(
                "git_filter_configuration",
                "Git content filters are not permitted during recovery capture",
            )
        unsupported_keys = {
            "core.worktree",
            "core.excludesfile",
            "core.attributesfile",
            "core.sparsecheckout",
            "core.sparsecheckoutcone",
            "extensions.worktreeconfig",
        }
        partial_clone_configured = "extensions.partialclone" in keys or any(
            key.startswith("remote.")
            and (key.endswith(".promisor") or key.endswith(".partialclonefilter"))
            for key in keys
        )
        if partial_clone_configured:
            raise RecoveryBlockedError(
                "partial_clone_not_supported",
                "partial-clone and promisor object stores are not permitted during recovery",
            )
        if keys.intersection(unsupported_keys) or any(
            key.startswith(("include.", "includeif.")) for key in keys
        ):
            raise RecoveryBlockedError(
                "unsupported_git_configuration",
                "external, partial-clone, and worktree Git controls are not permitted",
            )
        pack_directory = git_directory / "objects" / "pack"
        try:
            promisor_pack_present = False
            if pack_directory.is_dir():
                with os.scandir(pack_directory) as entries:
                    promisor_pack_present = any(item.name.endswith(".promisor") for item in entries)
        except OSError as exc:
            raise RecoveryBlockedError(
                "git_object_store_unavailable",
                "Git object storage could not be validated",
            ) from exc
        if promisor_pack_present:
            raise RecoveryBlockedError(
                "partial_clone_not_supported",
                "promisor packs are not permitted during recovery",
            )
        top = (
            self._run_git(
                repository,
                ["rev-parse", "--show-toplevel"],
                output_limit=4096,
            )
            .decode("utf-8", errors="strict")
            .strip()
        )
        if Path(top).resolve(strict=True) != repository:
            raise RecoveryBlockedError(
                "git_worktree_escape",
                "Git worktree root does not match the registered repository",
            )

    def _prepare_artifacts(
        self,
        repository: Path,
        base_head: str,
        allowed_paths: list[str],
        planned: list[ArtifactKind],
    ) -> tuple[list[_PreparedArtifact], list[dict[str, Any]]]:
        self._validate_full_capture_scope(
            repository,
            base_head,
            allowed_paths,
        )
        pathspec = ["--", *allowed_paths] if allowed_paths else ["--"]
        prepared: list[_PreparedArtifact] = []
        untracked_manifest: list[dict[str, Any]] = []

        tracked_kinds = {
            ArtifactKind.STAGED_PATCH,
            ArtifactKind.UNSTAGED_PATCH,
        }
        if any(kind in planned for kind in tracked_kinds):
            first_staged, first_unstaged = self._capture_tracked_patches(
                repository,
                base_head,
                pathspec,
            )
            second_staged, second_unstaged = self._capture_tracked_patches(
                repository,
                base_head,
                pathspec,
            )
            if not (
                hmac.compare_digest(
                    hashlib.sha256(first_staged).digest(),
                    hashlib.sha256(second_staged).digest(),
                )
                and hmac.compare_digest(
                    hashlib.sha256(first_unstaged).digest(),
                    hashlib.sha256(second_unstaged).digest(),
                )
            ):
                raise RecoveryBlockedError(
                    "tracked_changes_changed",
                    "tracked changes changed during capture",
                )

        if ArtifactKind.STAGED_PATCH in planned:
            prepared.append(
                _PreparedArtifact(
                    kind=ArtifactKind.STAGED_PATCH,
                    media_type="text/x-diff",
                    plaintext=second_staged,
                )
            )

        if ArtifactKind.UNSTAGED_PATCH in planned:
            prepared.append(
                _PreparedArtifact(
                    kind=ArtifactKind.UNSTAGED_PATCH,
                    media_type="text/x-diff",
                    plaintext=second_unstaged,
                )
            )

        if ArtifactKind.UNTRACKED_ARCHIVE in planned:
            inventory = self._untracked_inventory(repository, pathspec)
            first_archive, first_manifest = self._build_untracked_archive(
                repository,
                inventory,
            )
            second_inventory = self._untracked_inventory(repository, pathspec)
            second_archive, second_manifest = self._build_untracked_archive(
                repository,
                second_inventory,
            )
            if (
                inventory != second_inventory
                or first_manifest != second_manifest
                or not hmac.compare_digest(
                    hashlib.sha256(first_archive).digest(),
                    hashlib.sha256(second_archive).digest(),
                )
            ):
                raise RecoveryBlockedError(
                    "untracked_files_changed",
                    "untracked files changed during capture",
                )
            prepared.append(
                _PreparedArtifact(
                    kind=ArtifactKind.UNTRACKED_ARCHIVE,
                    media_type="application/x-tar",
                    plaintext=second_archive,
                )
            )
            untracked_manifest = second_manifest

        return prepared, untracked_manifest

    def _validate_full_capture_scope(
        self,
        repository: Path,
        base_head: str,
        allowed_paths: list[str],
    ) -> None:
        object_format = self._object_format(repository)
        oid_length = 40 if object_format == "sha1" else 64
        self._reject_unsupported_index_flags(repository)
        head = self._head_inventory(
            repository,
            base_head,
            ["--"],
            oid_length,
        )
        index = self._index_inventory(
            repository,
            ["--"],
            oid_length,
        )
        untracked = set(self._untracked_inventory(repository, ["--"]))
        self._reject_path_collisions(set(head).union(index).union(untracked))
        if not allowed_paths:
            return

        changed = {path for path in set(head).union(index) if head.get(path) != index.get(path)}
        removed = set(head).difference(index)
        changed_destinations = changed.difference(removed)
        missing: set[str] = set()
        modified: set[str] = set()
        total_bytes = 0
        for path, before in sorted(index.items()):
            content, metadata = self._read_relative_tracked_file(repository, path)
            if content is None or metadata is None:
                missing.add(path)
                continue
            total_bytes += len(content)
            if total_bytes > self.limits.max_tracked_total_bytes:
                raise RecoveryBlockedError(
                    "tracked_byte_limit",
                    "full-scope safety inventory exceeds the recovery limit",
                )
            after = _BlobEntry(
                mode="100755" if stat.S_IMODE(metadata.st_mode) & 0o111 else "100644",
                oid=self._git_blob_oid(content, object_format),
            )
            if before != after:
                modified.add(path)

        removed_inside = {path for path in removed if self._path_is_allowed(path, allowed_paths)}
        removed_outside = removed.difference(removed_inside)
        destination_inside = {
            path for path in changed_destinations if self._path_is_allowed(path, allowed_paths)
        }
        destination_outside = changed_destinations.difference(destination_inside)
        missing_inside = {path for path in missing if self._path_is_allowed(path, allowed_paths)}
        missing_outside = missing.difference(missing_inside)
        worktree_destinations = untracked.union(modified)
        worktree_inside = {
            path for path in worktree_destinations if self._path_is_allowed(path, allowed_paths)
        }
        worktree_outside = worktree_destinations.difference(worktree_inside)
        if (
            (removed_outside and (destination_inside or worktree_inside))
            or (removed_inside and (destination_outside or worktree_outside))
            or (missing_outside and worktree_inside)
            or (missing_inside and worktree_outside)
        ):
            raise RecoveryBlockedError(
                "cross_scope_move",
                "a cross-scope rename or move cannot be recovered within allowed_paths",
            )

    def _reject_unsupported_index_flags(self, repository: Path) -> None:
        raw = self._run_git(
            repository,
            ["ls-files", "-v", "-z", "--"],
            output_limit=self.limits.max_patch_bytes,
        )
        for record in raw.split(b"\0"):
            if not record:
                continue
            if len(record) < 3 or record[1:2] != b" ":
                raise RecoveryBlockedError(
                    "invalid_git_inventory",
                    "the Git index flag inventory is malformed",
                )
            try:
                path = record[2:].decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise RecoveryBlockedError(
                    "unsafe_path_encoding",
                    "Git index paths must use valid UTF-8",
                ) from exc
            self._validate_relative_path(path)
            if record[:1] != b"H":
                raise RecoveryBlockedError(
                    "unsupported_index_flags",
                    "skip-worktree, sparse, and assume-unchanged index flags are unsupported",
                )

    @staticmethod
    def _path_is_allowed(path: str, allowed_paths: list[str]) -> bool:
        normalized = path.rstrip("/")
        return any(
            normalized == allowed or normalized.startswith(f"{allowed}/")
            for allowed in allowed_paths
        )

    def _capture_tracked_patches(
        self,
        repository: Path,
        base_head: str,
        pathspec: list[str],
    ) -> tuple[bytes, bytes]:
        allowed_paths = pathspec[1:] if pathspec and pathspec[0] == "--" else []
        self._validate_full_capture_scope(
            repository,
            base_head,
            allowed_paths,
        )
        object_format = self._object_format(repository)
        expected_oid_length = 40 if object_format == "sha1" else 64
        if not re.fullmatch(rf"[0-9a-f]{{{expected_oid_length}}}", base_head):
            raise RecoveryBlockedError(
                "invalid_base_revision",
                "the approved base revision is not a full object identifier",
            )
        head_entries = self._head_inventory(
            repository,
            base_head,
            pathspec,
            expected_oid_length,
        )
        index_entries = self._index_inventory(
            repository,
            pathspec,
            expected_oid_length,
        )
        all_paths = set(head_entries) | set(index_entries)
        if len(all_paths) > self.limits.max_tracked_files:
            raise RecoveryBlockedError(
                "tracked_file_limit",
                "tracked file count exceeds the recovery limit",
            )
        self._reject_path_collisions(all_paths)

        blob_cache = _BlobCache(contents={})
        staged = bytearray()
        for path in sorted(all_paths):
            before = head_entries.get(path)
            after = index_entries.get(path)
            if before == after:
                continue
            self._reject_sensitive_patch_path(path)
            before_content = self._entry_content(
                repository,
                before,
                object_format,
                blob_cache,
            )
            after_content = self._entry_content(
                repository,
                after,
                object_format,
                blob_cache,
            )
            self._append_patch(
                staged,
                self._render_file_patch(
                    path,
                    before,
                    before_content,
                    after,
                    after_content,
                    object_format,
                ),
            )

        unstaged = bytearray()
        total_worktree_bytes = 0
        for path, before in sorted(index_entries.items()):
            content, metadata = self._read_relative_tracked_file(repository, path)
            if content is None:
                after = None
            else:
                total_worktree_bytes += len(content)
                if total_worktree_bytes > self.limits.max_tracked_total_bytes:
                    raise RecoveryBlockedError(
                        "tracked_byte_limit",
                        "tracked working-tree content exceeds the recovery limit",
                    )
                after = _BlobEntry(
                    mode="100755" if stat.S_IMODE(metadata.st_mode) & 0o111 else "100644",
                    oid=self._git_blob_oid(content, object_format),
                )
            if before == after:
                continue
            self._reject_sensitive_patch_path(path)
            before_content = self._entry_content(
                repository,
                before,
                object_format,
                blob_cache,
            )
            self._append_patch(
                unstaged,
                self._render_file_patch(
                    path,
                    before,
                    before_content,
                    after,
                    content,
                    object_format,
                ),
            )

        staged_bytes = bytes(staged)
        unstaged_bytes = bytes(unstaged)
        self._reject_secret_bytes(staged_bytes)
        self._reject_secret_bytes(unstaged_bytes)
        return staged_bytes, unstaged_bytes

    def _object_format(self, repository: Path) -> str:
        raw = self._run_git(
            repository,
            ["rev-parse", "--show-object-format"],
            output_limit=16,
        )
        object_format = raw.decode("ascii", errors="strict").strip()
        if object_format not in {"sha1", "sha256"}:
            raise RecoveryBlockedError(
                "unsupported_object_format",
                "the repository object format is not supported",
            )
        return object_format

    def _head_inventory(
        self,
        repository: Path,
        base_head: str,
        pathspec: list[str],
        oid_length: int,
    ) -> dict[str, _BlobEntry]:
        raw = self._run_git(
            repository,
            ["ls-tree", "-r", "-z", "--full-tree", base_head, *pathspec],
            output_limit=self.limits.max_patch_bytes,
        )
        entries: dict[str, _BlobEntry] = {}
        for record in raw.split(b"\0"):
            if not record:
                continue
            try:
                metadata, path_bytes = record.split(b"\t", 1)
                mode_bytes, object_type, oid_bytes = metadata.split(b" ", 2)
                path = path_bytes.decode("utf-8", errors="strict")
                mode = mode_bytes.decode("ascii", errors="strict")
                oid = oid_bytes.decode("ascii", errors="strict")
            except (UnicodeDecodeError, ValueError) as exc:
                raise RecoveryBlockedError(
                    "invalid_git_inventory",
                    "the Git tree inventory is malformed",
                ) from exc
            self._validate_relative_path(path)
            self._validate_blob_entry(mode, object_type, oid, oid_length)
            if path in entries:
                raise RecoveryBlockedError(
                    "invalid_git_inventory",
                    "the Git tree inventory contains duplicate paths",
                )
            entries[path] = _BlobEntry(mode=mode, oid=oid)
        return entries

    def _index_inventory(
        self,
        repository: Path,
        pathspec: list[str],
        oid_length: int,
    ) -> dict[str, _BlobEntry]:
        raw = self._run_git(
            repository,
            ["ls-files", "--stage", "-z", *pathspec],
            output_limit=self.limits.max_patch_bytes,
        )
        entries: dict[str, _BlobEntry] = {}
        zero_oid = "0" * oid_length
        for record in raw.split(b"\0"):
            if not record:
                continue
            try:
                metadata, path_bytes = record.split(b"\t", 1)
                mode_bytes, oid_bytes, stage_bytes = metadata.split(b" ", 2)
                path = path_bytes.decode("utf-8", errors="strict")
                mode = mode_bytes.decode("ascii", errors="strict")
                oid = oid_bytes.decode("ascii", errors="strict")
                stage = stage_bytes.decode("ascii", errors="strict")
            except (UnicodeDecodeError, ValueError) as exc:
                raise RecoveryBlockedError(
                    "invalid_git_inventory",
                    "the Git index inventory is malformed",
                ) from exc
            self._validate_relative_path(path)
            self._validate_blob_entry(mode, b"blob", oid, oid_length)
            if stage != "0":
                raise RecoveryBlockedError(
                    "unmerged_index",
                    "unmerged index entries cannot be captured",
                )
            if oid == zero_oid:
                raise RecoveryBlockedError(
                    "intent_to_add_not_supported",
                    "intent-to-add index entries cannot be recovered exactly",
                )
            if path in entries:
                raise RecoveryBlockedError(
                    "invalid_git_inventory",
                    "the Git index inventory contains duplicate paths",
                )
            entries[path] = _BlobEntry(mode=mode, oid=oid)
        return entries

    @staticmethod
    def _validate_blob_entry(
        mode: str,
        object_type: bytes,
        oid: str,
        oid_length: int,
    ) -> None:
        if (
            object_type != b"blob"
            or mode not in {"100644", "100755"}
            or not re.fullmatch(rf"[0-9a-f]{{{oid_length}}}", oid)
        ):
            raise RecoveryBlockedError(
                "unsupported_tracked_entry",
                "recovery supports only regular tracked files with full object identifiers",
            )

    def _entry_content(
        self,
        repository: Path,
        entry: _BlobEntry | None,
        object_format: str,
        cache: _BlobCache,
    ) -> bytes:
        if entry is None:
            return b""
        cached = cache.contents.get(entry.oid)
        if cached is not None:
            return cached
        content = self._run_git(
            repository,
            ["cat-file", "blob", entry.oid],
            output_limit=self.limits.max_tracked_file_bytes,
        )
        if cache.total_bytes + len(content) > self.limits.max_git_object_total_bytes:
            raise RecoveryBlockedError(
                "git_object_byte_limit",
                "Git object content exceeds the recovery limit",
            )
        if not hmac.compare_digest(
            self._git_blob_oid(content, object_format),
            entry.oid,
        ):
            raise RecoveryBlockedError(
                "git_object_integrity",
                "a Git object did not match its full object identifier",
            )
        cache.contents[entry.oid] = content
        cache.total_bytes += len(content)
        return content

    @staticmethod
    def _git_blob_oid(content: bytes, object_format: str) -> str:
        digest = hashlib.new(object_format)
        digest.update(f"blob {len(content)}\0".encode("ascii"))
        digest.update(content)
        return digest.hexdigest()

    def _render_file_patch(
        self,
        path: str,
        before: _BlobEntry | None,
        before_content: bytes,
        after: _BlobEntry | None,
        after_content: bytes | None,
        object_format: str,
    ) -> bytes:
        if before is None and after is None:
            return b""
        resulting_content = after_content if after_content is not None else b""
        self._validate_text_patch_content(before_content)
        self._validate_text_patch_content(resulting_content)
        if (
            before_content != resulting_content
            and len(before_content) + len(resulting_content) > self.limits.max_patch_bytes
        ):
            raise RecoveryBlockedError(
                "artifact_size_limit",
                "tracked recovery patch exceeds the recovery limit",
            )
        before_oid = (
            before.oid if before is not None else "0" * (40 if object_format == "sha1" else 64)
        )
        after_oid = (
            after.oid if after is not None else "0" * (40 if object_format == "sha1" else 64)
        )
        a_path = self._quote_patch_path(f"a/{path}")
        b_path = self._quote_patch_path(f"b/{path}")
        output = bytearray(b"diff --git " + a_path + b" " + b_path + b"\n")
        if before is None:
            output.extend(f"new file mode {after.mode}\n".encode("ascii"))
        elif after is None:
            output.extend(f"deleted file mode {before.mode}\n".encode("ascii"))
        elif before.mode != after.mode:
            output.extend(f"old mode {before.mode}\nnew mode {after.mode}\n".encode("ascii"))

        if before_content != resulting_content:
            mode_suffix = (
                f" {before.mode}"
                if before is not None and after is not None and before.mode == after.mode
                else ""
            )
            output.extend(f"index {before_oid}..{after_oid}{mode_suffix}\n".encode("ascii"))
            output.extend(b"--- " + (a_path if before is not None else b"/dev/null") + b"\n")
            output.extend(b"+++ " + (b_path if after is not None else b"/dev/null") + b"\n")
            output.extend(self._unified_hunks(before_content, resulting_content))
        elif before is None or after is None:
            output.extend(f"index {before_oid}..{after_oid}\n".encode("ascii"))
        return bytes(output)

    @staticmethod
    def _validate_text_patch_content(content: bytes) -> None:
        try:
            text = content.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise RecoveryBlockedError(
                "binary_change_not_supported",
                "tracked recovery supports only strict UTF-8 text changes",
            ) from exc
        if any(
            (unicodedata.category(character) == "Cc" and character not in {"\t", "\n", "\r"})
            or character in _BIDI_CONTROLS
            for character in text
        ):
            raise RecoveryBlockedError(
                "binary_change_not_supported",
                "tracked recovery text contains a disallowed control character",
            )

    @staticmethod
    def _quote_patch_path(value: str) -> bytes:
        raw = value.encode("utf-8")
        escaped = bytearray(b'"')
        for byte in raw:
            if 32 <= byte < 127 and byte not in {ord('"'), ord("\\")}:
                escaped.append(byte)
            elif byte == ord('"'):
                escaped.extend(b'\\"')
            elif byte == ord("\\"):
                escaped.extend(b"\\\\")
            else:
                escaped.extend(f"\\{byte:03o}".encode("ascii"))
        escaped.extend(b'"')
        return bytes(escaped)

    @classmethod
    def _unified_hunks(cls, before: bytes, after: bytes) -> bytes:
        before_lines = before.splitlines(keepends=True)
        after_lines = after.splitlines(keepends=True)
        before_range = cls._format_unified_range(0, len(before_lines))
        after_range = cls._format_unified_range(0, len(after_lines))
        output = bytearray(f"@@ -{before_range} +{after_range} @@\n".encode("ascii"))
        for line in before_lines:
            output.extend(cls._patch_line(b"-", line))
        for line in after_lines:
            output.extend(cls._patch_line(b"+", line))
        return bytes(output)

    @staticmethod
    def _format_unified_range(start: int, stop: int) -> str:
        beginning = start + 1
        length = stop - start
        if length == 1:
            return str(beginning)
        if length == 0:
            beginning -= 1
        return f"{beginning},{length}"

    @staticmethod
    def _patch_line(prefix: bytes, line: bytes) -> bytes:
        patched = prefix + line
        if line.endswith(b"\n"):
            return patched
        return patched + b"\n\\ No newline at end of file\n"

    def _append_patch(self, output: bytearray, patch: bytes) -> None:
        if len(output) + len(patch) > self.limits.max_patch_bytes:
            raise RecoveryBlockedError(
                "artifact_size_limit",
                "tracked recovery patch exceeds the recovery limit",
            )
        output.extend(patch)

    @staticmethod
    def _reject_sensitive_patch_path(path: str) -> None:
        if is_sensitive_path(path):
            raise RecoveryBlockedError(
                "sensitive_path",
                "recovery artifacts cannot include a sensitive credential path",
            )

    @staticmethod
    def _reject_path_collisions(paths: set[str]) -> None:
        collision_keys: set[str] = set()
        for path in paths:
            collision_key = unicodedata.normalize("NFC", path).casefold()
            if collision_key in collision_keys:
                raise RecoveryBlockedError(
                    "path_collision",
                    "recovery paths contain a normalized or case-fold collision",
                )
            collision_keys.add(collision_key)
        for collision_key in collision_keys:
            parts = PurePosixPath(collision_key).parts
            for length in range(1, len(parts)):
                if PurePosixPath(*parts[:length]).as_posix() in collision_keys:
                    raise RecoveryBlockedError(
                        "path_collision",
                        "recovery paths contain a file/ancestor collision",
                    )

    def _untracked_inventory(self, repository: Path, pathspec: list[str]) -> list[str]:
        raw = self._run_git(
            repository,
            ["ls-files", "--others", "-z", *pathspec],
            output_limit=self.limits.max_untracked_total_bytes,
        )
        paths = self._decode_paths(raw)
        if len(paths) > self.limits.max_untracked_files:
            raise RecoveryBlockedError(
                "untracked_file_limit",
                "untracked file count exceeds the recovery limit",
            )
        return paths

    def _decode_paths(self, raw: bytes) -> list[str]:
        values: list[str] = []
        collision_keys: set[str] = set()
        for item in raw.split(b"\0"):
            if not item:
                continue
            try:
                value = item.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise RecoveryBlockedError(
                    "unsafe_path_encoding",
                    "recovery paths must use valid UTF-8",
                ) from exc
            self._validate_relative_path(value)
            collision_key = unicodedata.normalize("NFC", value).casefold()
            if collision_key in collision_keys:
                raise RecoveryBlockedError(
                    "path_collision",
                    "recovery paths contain a normalized or case-fold collision",
                )
            collision_keys.add(collision_key)
            values.append(value)
        return sorted(values)

    def _validate_relative_path(self, value: str) -> None:
        encoded = value.encode("utf-8")
        pure = PurePosixPath(value)
        if (
            not value
            or len(encoded) > self.limits.max_path_bytes
            or pure.is_absolute()
            or "\\" in value
            or value.startswith("//")
            or re.match(r"^[A-Za-z]:", value)
            or len(pure.parts) > self.limits.max_path_depth
            or any(part in {"", ".", ".."} for part in pure.parts)
            or any(len(part.encode("utf-8")) > 255 for part in pure.parts)
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or any(character in _BIDI_CONTROLS for character in value)
        ):
            raise RecoveryBlockedError(
                "unsafe_archive_path",
                "a recovery path is not safe for archival",
            )

    def _build_untracked_archive(
        self,
        repository: Path,
        inventory: list[str],
    ) -> tuple[bytes, list[dict[str, Any]]]:
        output = io.BytesIO()
        file_manifest: list[dict[str, Any]] = []
        total = 0
        with tarfile.open(fileobj=output, mode="w:", format=tarfile.PAX_FORMAT) as archive:
            for relative in inventory:
                if is_sensitive_path(relative):
                    raise RecoveryBlockedError(
                        "sensitive_path",
                        "recovery artifacts cannot include a sensitive credential path",
                    )
                content, metadata = self._read_relative_regular_file(
                    repository,
                    relative,
                )
                total += metadata.st_size
                if total > self.limits.max_untracked_total_bytes:
                    raise RecoveryBlockedError(
                        "untracked_byte_limit",
                        "untracked content exceeds the recovery limit",
                    )
                self._reject_secret_bytes(content)
                digest = hashlib.sha256(content).hexdigest()
                info = tarfile.TarInfo(name=relative)
                info.size = len(content)
                info.mode = stat.S_IMODE(metadata.st_mode) & 0o777
                info.mtime = int(metadata.st_mtime)
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                archive.addfile(info, io.BytesIO(content))
                file_manifest.append(
                    {
                        "path": relative,
                        "sha256": digest,
                        "bytes": len(content),
                        "mode": oct(info.mode),
                    }
                )
        archive_bytes = output.getvalue()
        self._validate_archive(archive_bytes, file_manifest)
        return archive_bytes, file_manifest

    def _read_relative_regular_file(
        self,
        repository: Path,
        relative: str,
    ) -> tuple[bytes, os.stat_result]:
        content, metadata = self._read_relative_file(
            repository,
            relative,
            max_bytes=self.limits.max_untracked_file_bytes,
            missing_allowed=False,
            unsafe_code="unsafe_untracked_file",
        )
        if content is None or metadata is None:
            raise RecoveryBlockedError(
                "untracked_file_unavailable",
                "an untracked file became unavailable",
            )
        return content, metadata

    def _read_relative_tracked_file(
        self,
        repository: Path,
        relative: str,
    ) -> tuple[bytes | None, os.stat_result | None]:
        return self._read_relative_file(
            repository,
            relative,
            max_bytes=self.limits.max_tracked_file_bytes,
            missing_allowed=True,
            unsafe_code="unsafe_tracked_file",
        )

    def _read_relative_file(
        self,
        repository: Path,
        relative: str,
        *,
        max_bytes: int,
        missing_allowed: bool,
        unsafe_code: str,
    ) -> tuple[bytes | None, os.stat_result | None]:
        parts = PurePosixPath(relative).parts
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            directory_flags |= os.O_CLOEXEC
        try:
            directory_descriptor = os.open(repository, directory_flags)
        except OSError as exc:
            raise RecoveryBlockedError(
                "repository_race",
                "registered repository changed during untracked capture",
            ) from exc
        try:
            for component in parts[:-1]:
                try:
                    next_descriptor = os.open(
                        component,
                        directory_flags,
                        dir_fd=directory_descriptor,
                    )
                except FileNotFoundError:
                    if missing_allowed:
                        return None, None
                    raise RecoveryBlockedError(
                        "untracked_file_unavailable",
                        "an untracked file became unavailable",
                    ) from None
                except OSError as exc:
                    raise RecoveryBlockedError(
                        "symlink_boundary",
                        "untracked archive paths cannot contain symlinks",
                    ) from exc
                os.close(directory_descriptor)
                directory_descriptor = next_descriptor
            try:
                expected = os.stat(
                    parts[-1],
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                if missing_allowed:
                    return None, None
                raise RecoveryBlockedError(
                    "untracked_file_unavailable",
                    "an untracked file became unavailable",
                ) from None
            except OSError as exc:
                raise RecoveryBlockedError(
                    "tracked_file_unavailable" if missing_allowed else "untracked_file_unavailable",
                    "a recovery file became unavailable",
                ) from exc
            if stat.S_ISLNK(expected.st_mode):
                raise RecoveryBlockedError(
                    "symlink_boundary",
                    "untracked archive paths cannot contain symlinks",
                )
            if (
                not stat.S_ISREG(expected.st_mode)
                or expected.st_nlink != 1
                or expected.st_size > max_bytes
                or stat.S_IMODE(expected.st_mode) & ~0o777
            ):
                raise RecoveryBlockedError(
                    unsafe_code,
                    "recovery accepts only bounded regular files",
                )
            file_flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                file_flags |= os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                file_flags |= os.O_CLOEXEC
            try:
                descriptor = os.open(
                    parts[-1],
                    file_flags,
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                raise RecoveryBlockedError(
                    "untracked_file_changed",
                    "an untracked file changed before capture",
                ) from exc
            observed = os.fstat(descriptor)
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_nlink != 1
                or observed.st_dev != expected.st_dev
                or observed.st_ino != expected.st_ino
                or observed.st_size != expected.st_size
                or observed.st_mtime_ns != expected.st_mtime_ns
                or observed.st_ctime_ns != expected.st_ctime_ns
                or observed.st_mode != expected.st_mode
            ):
                os.close(descriptor)
                raise RecoveryBlockedError(
                    "untracked_file_changed",
                    "an untracked file changed before capture",
                )
            try:
                chunks: list[bytes] = []
                remaining = observed.st_size
                while remaining:
                    chunk = os.read(descriptor, min(65_536, remaining))
                    if not chunk:
                        raise RecoveryBlockedError(
                            "untracked_file_truncated",
                            "an untracked file was truncated during capture",
                        )
                    chunks.append(chunk)
                    remaining -= len(chunk)
                final = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            if (
                final.st_dev != observed.st_dev
                or final.st_ino != observed.st_ino
                or final.st_size != observed.st_size
                or final.st_mtime_ns != observed.st_mtime_ns
                or final.st_ctime_ns != observed.st_ctime_ns
                or final.st_mode != observed.st_mode
                or final.st_nlink != observed.st_nlink
            ):
                raise RecoveryBlockedError(
                    "untracked_file_changed",
                    "an untracked file changed during capture",
                )
            return b"".join(chunks), observed
        finally:
            os.close(directory_descriptor)

    def _validate_archive(
        self,
        archive_bytes: bytes,
        expected: list[dict[str, Any]],
    ) -> None:
        observed: list[dict[str, Any]] = []
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) != len(expected):
                raise RecoveryBlockedError(
                    "archive_validation_failed",
                    "untracked archive member count is invalid",
                )
            for member in members:
                self._validate_relative_path(member.name)
                if not member.isfile() or member.issym() or member.islnk():
                    raise RecoveryBlockedError(
                        "archive_validation_failed",
                        "untracked archive contains an unsafe member type",
                    )
                stream = archive.extractfile(member)
                if stream is None:
                    raise RecoveryBlockedError(
                        "archive_validation_failed",
                        "untracked archive member is unreadable",
                    )
                content = stream.read(self.limits.max_untracked_file_bytes + 1)
                if len(content) != member.size:
                    raise RecoveryBlockedError(
                        "archive_validation_failed",
                        "untracked archive member size is invalid",
                    )
                observed.append(
                    {
                        "path": member.name,
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "bytes": len(content),
                        "mode": oct(member.mode & 0o777),
                    }
                )
        if observed != expected:
            raise RecoveryBlockedError(
                "archive_validation_failed",
                "untracked archive checksums are invalid",
            )

    @staticmethod
    def _reject_secret_bytes(data: bytes) -> None:
        if secret_rule_ids(data):
            raise RecoveryBlockedError(
                "credential_material_detected",
                "recovery artifact contained detected credential material",
            )

    @staticmethod
    def _reject_unsupported_patch(data: bytes) -> None:
        if (
            re.search(rb"(?m)^(?:old mode|new mode) 160000$", data)
            or re.search(rb"(?m)^index [0-9a-f]+\.\.[0-9a-f]+ 160000$", data)
            or b"Subproject commit " in data
        ):
            raise RecoveryBlockedError(
                "submodule_change_not_supported",
                "submodule pointer changes require Git-history recovery",
            )

    def _manifest_payload(
        self,
        *,
        job: JobRecord,
        package: RecoveryPackage,
        inspection,
        after_capture_fingerprint: str,
        artifacts: list[ArtifactRecord],
        untracked_manifest: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "schema_version": "3.0",
            "package_id": package.id,
            "job_id": job.id,
            "organization_id": job.task.organization_id,
            "project_id": job.task.project_id,
            "repository_id": package.repository_id,
            "approval_id": package.approval_id,
            "action_digest": package.action_digest,
            "allowed_paths": package.allowed_paths,
            "source_fingerprint": package.source_fingerprint,
            "source_snapshot_digest": package.source_snapshot_digest,
            "capture_scope": package.capture_scope,
            "after_capture_fingerprint": after_capture_fingerprint,
            "base_head": package.base_head,
            "branch": inspection.git.branch,
            "upstream_present": inspection.git.upstream is not None,
            "ahead": inspection.git.ahead,
            "behind": inspection.git.behind,
            "complete_for_scope": package.complete_for_scope,
            "snapshot_file_count": inspection.git.snapshot_file_count,
            "snapshot_total_bytes": inspection.git.snapshot_total_bytes,
            "ignored_paths_included": inspection.git.ignored_paths_included,
            "exclusions": package.exclusions,
            "warnings": package.warnings,
            "retention_expires_at": package.retention_expires_at.isoformat(),
            "artifacts": [
                {
                    "id": item.id,
                    "kind": item.kind.value,
                    "media_type": item.media_type,
                    "sha256": item.plaintext_sha256,
                    "bytes": item.plaintext_bytes,
                    "ciphertext_sha256": item.ciphertext_sha256,
                    "storage_bytes": item.storage_bytes,
                    "encryption": item.encryption_version,
                }
                for item in artifacts
            ],
            "untracked_files": untracked_manifest,
            "restoration_order": [
                "Apply staged_patch with index semantics in a disposable clone.",
                "Apply unstaged_patch to the disposable working tree.",
                "Validate and extract untracked_archive only into the disposable clone.",
                "Never restore directly into the registered source repository.",
            ],
            "source_writes_performed": False,
            "execution_performed": False,
        }

    def _run_git(
        self,
        repository: Path,
        arguments: list[str],
        *,
        output_limit: int,
        allowed_return_codes: set[int] | None = None,
    ) -> bytes:
        git_binary = self.inspector.git_binary
        if git_binary is None:
            raise RecoveryUnavailableError("Git recovery commands are unavailable")
        command = [
            git_binary,
            "-c",
            f"safe.directory={repository}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.excludesFile=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "--literal-pathspecs",
            "--no-optional-locks",
            "-C",
            str(repository),
            *arguments,
        ]
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": "/nonexistent-liltweak-home",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_ASKPASS": "/bin/false",
            "SSH_ASKPASS": "/bin/false",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_ATTR_NOSYSTEM": "1",
            "LC_ALL": "C",
            "LANG": "C",
        }
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                start_new_session=os.name == "posix",
            )
        except OSError as exc:
            raise RecoveryUnavailableError("a bounded Git recovery command is unavailable") from exc
        if process.stdout is None or process.stderr is None:
            self._terminate_process(process)
            raise RecoveryUnavailableError("Git recovery output could not be captured")

        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        output = bytearray()
        stderr_bytes = 0
        deadline = time.monotonic() + self.limits.git_timeout_seconds
        failure_code: str | None = None
        try:
            while selector.get_map():
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    failure_code = "git_timeout"
                    break
                events = selector.select(timeout=remaining_time)
                if not events:
                    failure_code = "git_timeout"
                    break
                for key, _mask in events:
                    chunk = os.read(key.fd, 65_536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stdout":
                        if len(output) + len(chunk) > output_limit:
                            failure_code = "artifact_size_limit"
                            break
                        output.extend(chunk)
                    else:
                        stderr_bytes += len(chunk)
                        if stderr_bytes > 1_000_000:
                            failure_code = "git_error_output_limit"
                            break
                if failure_code:
                    break
        finally:
            selector.close()
        if failure_code:
            self._terminate_process(process)
        try:
            return_code = process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self._terminate_process(process)
            return_code = process.wait(timeout=1)
        process.stdout.close()
        process.stderr.close()
        if failure_code:
            raise RecoveryBlockedError(
                failure_code,
                "a bounded Git recovery command exceeded its safety limit",
            )
        accepted = allowed_return_codes or {0}
        if return_code not in accepted:
            raise RepositoryAccessError("a bounded Git recovery command failed")
        return bytes(output)

    @staticmethod
    def _terminate_process(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            return
