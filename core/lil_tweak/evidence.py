"""Deterministic evidence bundles and immutable evidence storage."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Protocol

from .archive import ArchiveError, validate_portable_path
from .limits import (
    MAX_EVIDENCE_BYTES,
    RUNNER_WORKSPACE_BYTES,
    RUNNER_WORKSPACE_INODES,
)


class EvidenceConflict(RuntimeError):
    code = "evidence_conflict"


class EvidenceTooLarge(RuntimeError):
    code = "evidence_too_large"


@dataclass(frozen=True, slots=True)
class StoredEvidence:
    key: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    files: dict[str, bytes]
    proposal_digest: str
    artifact_hashes: dict[str, str]


@dataclass(frozen=True, slots=True)
class WorkspaceSnapshot:
    files: dict[str, bytes | "SnapshotFile"]
    source_digest: str


@dataclass(frozen=True, slots=True)
class SnapshotFile:
    path: Path
    size: int
    sha256: str


class WorkspaceEvidenceError(RuntimeError):
    code = "workspace_evidence_failed"


def capture_workspace(
    root: str | os.PathLike[str],
    *,
    max_files: int = 20_000,
    max_inodes: int = RUNNER_WORKSPACE_INODES,
    max_file_bytes: int = 25 * 1024 * 1024,
    max_total_bytes: int = RUNNER_WORKSPACE_BYTES,
    staging_root: str | os.PathLike[str] | None = None,
    _scan_hook: Callable[[str], None] | None = None,
    _verification_pass: bool = True,
) -> WorkspaceSnapshot:
    """Freeze a tree through non-following dirfd-relative traversal."""

    base = Path(root).absolute()
    files: dict[str, bytes | SnapshotFile] = {}
    seen_paths: set[str] = set()
    total = 0
    inode_count = 1
    try:
        root_metadata = base.lstat()
    except OSError:
        raise WorkspaceEvidenceError("workspace_missing") from None
    if stat.S_ISLNK(root_metadata.st_mode):
        raise WorkspaceEvidenceError("workspace_root_symlink")
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise WorkspaceEvidenceError("workspace_missing")
    if max_inodes < 1:
        raise WorkspaceEvidenceError("workspace_inode_limit")
    root_identity = (root_metadata.st_dev, root_metadata.st_ino)
    stage: Path | None = None
    if staging_root is not None:
        stage = Path(staging_root).resolve()
        if stage == base or stage in base.parents or base in stage.parents:
            raise WorkspaceEvidenceError("invalid_snapshot_staging")
        stage.mkdir(parents=True, exist_ok=True)
        if any(stage.iterdir()):
            raise WorkspaceEvidenceError("snapshot_staging_not_empty")

    required_flags = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required_flags):
        raise WorkspaceEvidenceError("workspace_platform_unsupported")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK

    def identity(metadata: os.stat_result) -> tuple[int, int]:
        return metadata.st_dev, metadata.st_ino

    def signature(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            stat.S_IFMT(metadata.st_mode),
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    def bounded_names(directory_fd: int, allowance: int) -> list[str]:
        names: list[str] = []
        try:
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > allowance:
                        raise WorkspaceEvidenceError("workspace_inode_limit")
        except WorkspaceEvidenceError:
            raise
        except OSError:
            raise WorkspaceEvidenceError("workspace_changed_during_snapshot") from None
        return sorted(names)

    def visit(directory_fd: int, parts: tuple[str, ...]) -> None:
        nonlocal inode_count, total
        names = bounded_names(directory_fd, max_inodes - inode_count)
        for name in names:
            relative = PurePosixPath(*parts, name).as_posix()
            try:
                portable = validate_portable_path(relative)
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except ArchiveError:
                raise WorkspaceEvidenceError("workspace_unsafe_path") from None
            except OSError:
                raise WorkspaceEvidenceError("workspace_changed_during_snapshot") from None
            if portable != relative:
                raise WorkspaceEvidenceError("workspace_unsafe_path")
            folded = portable.casefold()
            if folded in seen_paths:
                raise WorkspaceEvidenceError("workspace_path_collision")
            seen_paths.add(folded)
            inode_count += 1
            if inode_count > max_inodes:
                raise WorkspaceEvidenceError("workspace_inode_limit")
            if stat.S_ISLNK(metadata.st_mode):
                raise WorkspaceEvidenceError("workspace_symlink")
            if stat.S_ISDIR(metadata.st_mode):
                try:
                    child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                except OSError:
                    raise WorkspaceEvidenceError("workspace_changed_during_snapshot") from None
                try:
                    opened_directory = os.fstat(child_fd)
                    if signature(opened_directory) != signature(metadata):
                        raise WorkspaceEvidenceError("workspace_changed_during_snapshot")
                    child_names_before = bounded_names(child_fd, max_inodes)
                    visit(child_fd, (*parts, name))
                    if _scan_hook is not None:
                        _scan_hook(relative)
                    if bounded_names(child_fd, max_inodes) != child_names_before:
                        raise WorkspaceEvidenceError("workspace_changed_during_snapshot")
                    final_entry = os.stat(
                        name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if signature(os.fstat(child_fd)) != signature(metadata) or signature(
                        final_entry
                    ) != signature(metadata):
                        raise WorkspaceEvidenceError("workspace_changed_during_snapshot")
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise WorkspaceEvidenceError("workspace_unsupported_type")
            if metadata.st_nlink != 1:
                raise WorkspaceEvidenceError("workspace_hardlink")
            if len(files) >= max_files:
                raise WorkspaceEvidenceError("workspace_file_limit")
            if metadata.st_size > max_file_bytes:
                raise WorkspaceEvidenceError("workspace_file_too_large")
            total += metadata.st_size
            if total > max_total_bytes:
                raise WorkspaceEvidenceError("workspace_too_large")
            target: Path | None = None
            output = None
            data = bytearray() if stage is None else None
            file_digest = hashlib.sha256()
            copied = 0
            try:
                descriptor = os.open(name, file_flags, dir_fd=directory_fd)
                opened = os.fstat(descriptor)
                if (
                    identity(opened) != identity(metadata)
                    or opened.st_size != metadata.st_size
                    or opened.st_nlink != 1
                ):
                    os.close(descriptor)
                    raise WorkspaceEvidenceError("workspace_changed_during_snapshot")
                if stage is not None:
                    target = stage.joinpath(*PurePosixPath(relative).parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    output = target.open("xb")
                with os.fdopen(descriptor, "rb") as source:
                    remaining = metadata.st_size + 1
                    while remaining and (
                        chunk := source.read(min(1024 * 1024, remaining))
                    ):
                        copied += len(chunk)
                        remaining -= len(chunk)
                        file_digest.update(chunk)
                        if output is not None:
                            output.write(chunk)
                        else:
                            assert data is not None
                            data.extend(chunk)
                    opened_after = os.fstat(source.fileno())
                final_entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (
                    copied != metadata.st_size
                    or signature(opened_after) != signature(metadata)
                    or signature(final_entry) != signature(metadata)
                ):
                    raise WorkspaceEvidenceError("workspace_changed_during_snapshot")
            except OSError:
                raise WorkspaceEvidenceError("workspace_changed_during_snapshot") from None
            finally:
                if output is not None:
                    output.close()
            if target is None:
                assert data is not None
                files[relative] = bytes(data)
            else:
                files[relative] = SnapshotFile(
                    target, metadata.st_size, file_digest.hexdigest()
                )

    try:
        root_fd = os.open(base, directory_flags)
    except OSError:
        raise WorkspaceEvidenceError("workspace_changed_during_snapshot") from None
    try:
        if identity(os.fstat(root_fd)) != root_identity:
            raise WorkspaceEvidenceError("workspace_root_changed")
        visit(root_fd, ())
        final_root = base.lstat()
        if identity(os.fstat(root_fd)) != root_identity or identity(final_root) != root_identity:
            raise WorkspaceEvidenceError("workspace_root_changed")
    except Exception:
        if stage is not None:
            for item in stage.iterdir():
                if item.is_dir() and not item.is_symlink():
                    shutil.rmtree(item)
                else:
                    item.unlink()
        raise
    finally:
        os.close(root_fd)

    digest = hashlib.sha256(b"lil-tweak-source-v1\0")
    for relative, value in sorted(files.items()):
        data = value if isinstance(value, bytes) else value.path.read_bytes()
        if not isinstance(value, bytes) and (
            len(data) != value.size or hashlib.sha256(data).hexdigest() != value.sha256
        ):
            raise WorkspaceEvidenceError("snapshot_changed")
        encoded_path = relative.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    snapshot = WorkspaceSnapshot(files, digest.hexdigest())
    if _verification_pass:
        verification = capture_workspace(
            base,
            max_files=max_files,
            max_inodes=max_inodes,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
            _verification_pass=False,
        )
        if verification.source_digest != snapshot.source_digest:
            if stage is not None:
                for item in stage.iterdir():
                    if item.is_dir() and not item.is_symlink():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
            raise WorkspaceEvidenceError("workspace_changed_during_snapshot")
    return snapshot


def _snapshot_bytes(value: bytes | SnapshotFile | None) -> bytes | None:
    if value is None or isinstance(value, bytes):
        return value
    try:
        data = value.path.read_bytes()
    except OSError:
        raise WorkspaceEvidenceError("snapshot_unavailable") from None
    if len(data) != value.size or hashlib.sha256(data).hexdigest() != value.sha256:
        raise WorkspaceEvidenceError("snapshot_changed")
    return data


def _snapshot_identity(value: bytes | SnapshotFile | None) -> tuple[int, str] | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return len(value), hashlib.sha256(value).hexdigest()
    return value.size, value.sha256


def workspace_changed_paths(
    before: WorkspaceSnapshot, after: WorkspaceSnapshot
) -> tuple[str, ...]:
    """Return the host-observed changed paths in deterministic order."""

    return tuple(
        name
        for name in sorted(set(before.files) | set(after.files))
        if _snapshot_identity(before.files.get(name))
        != _snapshot_identity(after.files.get(name))
    )


def workspace_delta_digest(
    before: WorkspaceSnapshot,
    after: WorkspaceSnapshot,
    paths: tuple[str, ...] | list[str],
) -> str:
    """Digest path-level before/after identities without trusting model claims."""

    normalized = tuple(paths)
    if normalized != tuple(sorted(set(normalized))):
        raise WorkspaceEvidenceError("invalid_delta_paths")
    entries = [
        {
            "path": name,
            "before": _snapshot_identity(before.files.get(name)),
            "after": _snapshot_identity(after.files.get(name)),
        }
        for name in normalized
    ]
    payload = json.dumps(
        entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(b"lil-tweak-workspace-delta-v1\0" + payload).hexdigest()


_EDIT_JOURNAL_FIELDS = frozenset(
    {
        "ordinal",
        "before_source_digest",
        "after_source_digest",
        "actual_changed_paths",
        "delta_digest",
        "result",
        "exit_code",
        "timed_out",
        "truncated",
        "rejection_code",
    }
)


def build_edit_journal_evidence(
    entries: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    *,
    max_entries: int = 128,
    max_paths: int = 20_000,
    max_bytes: int = 64 * 1024,
) -> dict[str, Any]:
    """Validate and digest a bounded host-derived edit journal."""

    if len(entries) > max_entries:
        raise WorkspaceEvidenceError("edit_journal_entry_limit")
    canonical: list[dict[str, Any]] = []
    path_count = 0
    for ordinal, item in enumerate(entries):
        if set(item) != _EDIT_JOURNAL_FIELDS or item.get("ordinal") != ordinal:
            raise WorkspaceEvidenceError("invalid_edit_journal")
        paths = item.get("actual_changed_paths")
        if (
            not isinstance(paths, list)
            or paths != sorted(set(paths))
            or any(not isinstance(path, str) for path in paths)
        ):
            raise WorkspaceEvidenceError("invalid_edit_journal")
        path_count += len(paths)
        if path_count > max_paths:
            raise WorkspaceEvidenceError("edit_journal_path_limit")
        if item.get("result") not in ("promoted", "rejected"):
            raise WorkspaceEvidenceError("invalid_edit_journal")
        for name in ("before_source_digest", "after_source_digest", "delta_digest"):
            value = item.get(name)
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise WorkspaceEvidenceError("invalid_edit_journal")
        if item.get("exit_code") is not None and not isinstance(item.get("exit_code"), int):
            raise WorkspaceEvidenceError("invalid_edit_journal")
        if not isinstance(item.get("timed_out"), bool) or not isinstance(
            item.get("truncated"), bool
        ):
            raise WorkspaceEvidenceError("invalid_edit_journal")
        rejection = item.get("rejection_code")
        if rejection is not None and (
            not isinstance(rejection, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", rejection)
        ):
            raise WorkspaceEvidenceError("invalid_edit_journal")
        canonical.append(dict(item))
    encoded = json.dumps(
        canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(encoded) > max_bytes:
        raise WorkspaceEvidenceError("edit_journal_too_large")
    return {
        "edit_journal": canonical,
        "edit_journal_count": len(canonical),
        "edit_journal_digest": hashlib.sha256(
            b"lil-tweak-edit-journal-v1\0" + encoded
        ).hexdigest(),
    }


def build_workspace_patch(
    baseline: WorkspaceSnapshot,
    final: WorkspaceSnapshot,
    *,
    max_bytes: int = MAX_EVIDENCE_BYTES,
) -> bytes:
    """Build a deterministic trusted diff; empty workspaces yield an empty patch."""

    if max_bytes < 0:
        raise WorkspaceEvidenceError("patch_too_large")
    encoded = bytearray()

    def append_bounded(text: str) -> None:
        chunk = text.encode("utf-8")
        if len(chunk) > max_bytes - len(encoded):
            raise WorkspaceEvidenceError("patch_too_large")
        encoded.extend(chunk)

    for name in sorted(set(baseline.files) | set(final.files)):
        before_value = baseline.files.get(name)
        after_value = final.files.get(name)
        if _snapshot_identity(before_value) == _snapshot_identity(after_value):
            continue
        before = _snapshot_bytes(before_value)
        after = _snapshot_bytes(after_value)
        if (before is not None and b"\0" in before) or (
            after is not None and b"\0" in after
        ):
            raise WorkspaceEvidenceError("binary_change_unsupported")
        try:
            before_text = "" if before is None else before.decode("utf-8")
            after_text = "" if after is None else after.decode("utf-8")
        except UnicodeDecodeError:
            raise WorkspaceEvidenceError("binary_change_unsupported") from None
        before_lines = _patch_lines(before_text)
        after_lines = _patch_lines(after_text)
        diff = difflib.unified_diff(
            before_lines,
            after_lines,
            fromfile="/dev/null" if before is None else f"a/{name}",
            tofile="/dev/null" if after is None else f"b/{name}",
            lineterm="\n",
        )
        for line in diff:
            if "\0" in line:
                append_bounded(line.replace("\0", ""))
                append_bounded("\\ No newline at end of file\n")
            else:
                append_bounded(line)
    return bytes(encoded)


def _patch_lines(text: str) -> list[str]:
    if text and not text.endswith(("\n", "\r")):
        text += "\0\n"
    return text.splitlines(keepends=True)


_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(authorization|api[_-]?key|access[_-]?key|token|password|secret)"
    r"\s*[:=]\s*(?:bearer\s+)?([^\s,;]+)"
)
_SECRET_FLAGS = frozenset(
    {
        "--api-key",
        "--access-key",
        "--authorization",
        "--password",
        "--secret",
        "--token",
    }
)
_URL_USERINFO = re.compile(r"(?i)(https?://)[^/@\s:]+(?::[^/@\s]*)?@")


def _redact_text(value: Any) -> str:
    text = str(value if value is not None else "")
    text = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}=[REDACTED]", text
    )
    return _URL_USERINFO.sub(r"\1[REDACTED]@", text)


def _bounded_utf8(value: str, limit: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", "ignore") + "…", True


def _sanitize_argv(command: list[str]) -> tuple[list[str], str, bool]:
    sanitized: list[str] = []
    redact_next = False
    for part in command:
        if redact_next:
            sanitized.append("[REDACTED]")
            redact_next = False
            continue
        rendered = _redact_text(part)
        sanitized.append(rendered)
        if part.casefold() in _SECRET_FLAGS:
            redact_next = True
    full = json.dumps(
        sanitized, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    digest = hashlib.sha256(full).hexdigest()
    displayed: list[str] = []
    truncated = False
    for part in sanitized:
        bounded, part_truncated = _bounded_utf8(part, 256)
        candidate = [*displayed, bounded]
        if len(
            json.dumps(candidate, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        ) > 2048:
            displayed.append("[TRUNCATED]")
            truncated = True
            break
        displayed.append(bounded)
        truncated = truncated or part_truncated
    return displayed, digest, truncated


def build_command_evidence(
    observations: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]],
    *,
    max_bytes: int = MAX_EVIDENCE_BYTES,
) -> tuple[bytes, dict[str, Any]]:
    """Create a bounded log and manifest fields from host-recorded executions."""

    log_parts: list[str] = []
    commands: list[list[str]] = []
    command_hashes: list[str] = []
    argv_truncated: list[bool] = []
    operations: list[str] = []
    exit_statuses: list[int | None] = []
    timeouts: list[bool] = []
    truncation: list[bool] = []
    remaining = max_bytes
    if len(observations) > 512:
        raise WorkspaceEvidenceError("too_many_command_observations")
    for observation in observations:
        operation = observation.get("operation", "run_command")
        operations.append(
            operation if operation in ("run_command", "apply_patch") else "unknown"
        )
        command = observation.get("command")
        if not isinstance(command, list) or any(
            not isinstance(part, str) for part in command
        ):
            raise WorkspaceEvidenceError("invalid_command_observation")
        displayed_command, command_hash, command_was_truncated = _sanitize_argv(
            list(command)
        )
        commands.append(displayed_command)
        command_hashes.append(command_hash)
        argv_truncated.append(command_was_truncated)
        exit_statuses.append(observation.get("exit_code"))
        timeouts.append(bool(observation.get("timed_out")))
        truncation.append(bool(observation.get("truncated")))
        entry = (
            f"$ {json.dumps(displayed_command, ensure_ascii=False, separators=(',', ':'))}\n"
            f"exit_code={observation.get('exit_code')} "
            f"timed_out={str(bool(observation.get('timed_out'))).lower()} "
            f"truncated={str(bool(observation.get('truncated'))).lower()}\n"
            f"[stdout]\n{_redact_text(observation.get('stdout', ''))}\n"
            f"[stderr]\n{_redact_text(observation.get('stderr', ''))}\n"
        ).encode("utf-8", "replace")
        if len(entry) > remaining:
            entry = entry[:remaining]
            truncation[-1] = True
        log_parts.append(entry.decode("utf-8", "ignore"))
        remaining -= len(entry)
    return "".join(log_parts).encode("utf-8"), {
        "commands": commands,
        "command_hashes": command_hashes,
        "commands_digest": hashlib.sha256(
            json.dumps(command_hashes, separators=(",", ":")).encode("ascii")
        ).hexdigest(),
        "argv_truncated": argv_truncated,
        "operations": operations,
        "exit_statuses": exit_statuses,
        "timeouts": timeouts,
        "truncation": truncation,
    }


class EvidenceStore(Protocol):
    def put(
        self, key: str, data: bytes, expected_sha256: str | None = None
    ) -> StoredEvidence: ...

    def get(self, key: str, *, max_bytes: int = MAX_EVIDENCE_BYTES) -> bytes: ...


_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _key_parts(key: str) -> tuple[str, ...]:
    if not key or "\\" in key or "\x00" in key or key.startswith("/"):
        raise ValueError("invalid evidence key")
    path = PurePosixPath(key)
    if any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("invalid evidence key")
    return path.parts


class LocalEvidenceStore:
    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._root_resolved = self.root.resolve()

    def put(
        self, key: str, data: bytes, expected_sha256: str | None = None
    ) -> StoredEvidence:
        if not isinstance(data, bytes):
            raise TypeError("evidence data must be bytes")
        parts = _key_parts(key)
        digest = hashlib.sha256(data).hexdigest()
        if expected_sha256 is not None and (
            not _HEX_DIGEST.fullmatch(expected_sha256)
            or not secrets_equal(digest, expected_sha256)
        ):
            raise ValueError("evidence digest mismatch")
        target = self.root.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        parent = target.parent.resolve()
        if parent != self._root_resolved and self._root_resolved not in parent.parents:
            raise ValueError("invalid evidence key")
        try:
            with target.open("xb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:
            raise EvidenceConflict("evidence already exists") from None
        return StoredEvidence(key, digest, len(data))

    def get(self, key: str, *, max_bytes: int = MAX_EVIDENCE_BYTES) -> bytes:
        if max_bytes < 0:
            raise ValueError("invalid evidence read limit")
        target = self.root.joinpath(*_key_parts(key))
        resolved = target.resolve(strict=True)
        if self._root_resolved not in resolved.parents:
            raise ValueError("invalid evidence key")
        with resolved.open("rb") as source:
            data = source.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise EvidenceTooLarge("evidence exceeds read limit")
        return data


def secrets_equal(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


class R2EvidenceStore:
    """Immutable S3-compatible R2 adapter; credentials remain in the client."""

    def __init__(self, client: Any, bucket: str, *, prefix: str = "") -> None:
        self.client = client
        self.bucket = bucket
        self.prefix = prefix.strip("/")

    def _key(self, key: str) -> str:
        safe = "/".join(_key_parts(key))
        return f"{self.prefix}/{safe}" if self.prefix else safe

    def put(
        self, key: str, data: bytes, expected_sha256: str | None = None
    ) -> StoredEvidence:
        digest = hashlib.sha256(data).hexdigest()
        if expected_sha256 is not None and not secrets_equal(digest, expected_sha256):
            raise ValueError("evidence digest mismatch")
        try:
            self.client.put_object(
                Bucket=self.bucket,
                Key=self._key(key),
                Body=data,
                ContentType="application/octet-stream",
                Metadata={"sha256": digest},
                IfNoneMatch="*",
            )
        except Exception as error:
            # Botocore is optional here; avoid importing it solely to classify a
            # precondition failure. Adapters may expose a stable response status.
            status = getattr(error, "response", {}).get("ResponseMetadata", {}).get(
                "HTTPStatusCode"
            )
            if status in (409, 412):
                try:
                    response = self.client.get_object(
                        Bucket=self.bucket, Key=self._key(key)
                    )
                    existing = response["Body"].read(len(data) + 1)
                except Exception:
                    raise EvidenceConflict("evidence already exists") from None
                if existing == data:
                    return StoredEvidence(key, digest, len(data))
                raise EvidenceConflict("evidence already exists") from None
            raise
        return StoredEvidence(key, digest, len(data))

    def get(self, key: str, *, max_bytes: int = MAX_EVIDENCE_BYTES) -> bytes:
        if max_bytes < 0:
            raise ValueError("invalid evidence read limit")
        response = self.client.get_object(Bucket=self.bucket, Key=self._key(key))
        body = response["Body"]
        try:
            data = body.read(max_bytes + 1)
        finally:
            close = getattr(body, "close", None)
            if callable(close):
                close()
        if not isinstance(data, bytes):
            raise TypeError("evidence body must be bytes")
        if len(data) > max_bytes:
            raise EvidenceTooLarge("evidence exceeds read limit")
        return data


def _bytes(value: str | bytes) -> bytes:
    return value if isinstance(value, bytes) else value.encode("utf-8")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def build_evidence_bundle(
    *,
    plan: str | bytes,
    patch: str | bytes,
    tests: str | bytes,
    summary: str | bytes,
    metadata: dict[str, Any] | None = None,
    max_manifest_bytes: int = MAX_EVIDENCE_BYTES,
) -> EvidenceBundle:
    files = {
        "plan.md": _bytes(plan),
        "changes.patch": _bytes(patch),
        "tests.log": _bytes(tests),
        "summary.md": _bytes(summary),
    }
    if any(len(data) > MAX_EVIDENCE_BYTES for data in files.values()):
        raise WorkspaceEvidenceError("evidence_artifact_too_large")
    artifacts = {
        name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        for name, data in sorted(files.items())
    }
    proposal = {
        "version": 1,
        "artifacts": artifacts,
        "run": metadata or {},
    }
    proposal_digest = hashlib.sha256(_canonical_json(proposal)).hexdigest()
    manifest = {**proposal, "proposal_digest": proposal_digest}
    encoded_manifest = _canonical_json(manifest) + b"\n"
    if max_manifest_bytes <= 0 or len(encoded_manifest) > min(
        max_manifest_bytes, MAX_EVIDENCE_BYTES
    ):
        raise WorkspaceEvidenceError("manifest_too_large")
    files["manifest.json"] = encoded_manifest
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    return EvidenceBundle(files, proposal_digest, hashes)
