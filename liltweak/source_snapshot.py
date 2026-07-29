from __future__ import annotations

import contextlib
import hashlib
import io
import os
import selectors
import shutil
import signal
import stat
import subprocess
import tarfile
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .creator_contract import canonical_json
from .execution_contract import SourceSnapshotManifest
from .models import RepositoryInspection, RepositoryRef
from .repository import (
    RepositoryInspector,
    is_sensitive_path,
    secret_rule_ids,
)


class SourceSnapshotError(RuntimeError):
    pass


@dataclass(frozen=True)
class _TreeEntry:
    path: str
    mode: int
    object_id: str
    data: bytes
    sha256: str


class _HashWriter:
    def __init__(self) -> None:
        self._digest = hashlib.sha256()
        self._position = 0

    def write(self, data: bytes) -> int:
        self._digest.update(data)
        self._position += len(data)
        return len(data)

    def tell(self) -> int:
        return self._position

    def flush(self) -> None:
        return None

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


class RepositorySnapshotBuilder:
    """Build a deterministic, `.git`-free snapshot from one exact committed Git tree."""

    def __init__(
        self,
        inspector: RepositoryInspector,
        *,
        max_files: int = 25_000,
        max_total_bytes: int = 200_000_000,
        max_file_bytes: int = 50_000_000,
        git_timeout_seconds: int = 60,
    ) -> None:
        if max_files < 1 or max_files > 100_000:
            raise ValueError("snapshot file limit is invalid")
        if max_total_bytes < 1 or max_total_bytes > 1_000_000_000:
            raise ValueError("snapshot byte limit is invalid")
        if max_file_bytes < 1 or max_file_bytes > max_total_bytes:
            raise ValueError("snapshot per-file limit is invalid")
        self.inspector = inspector
        self.max_files = max_files
        self.max_total_bytes = max_total_bytes
        self.max_file_bytes = max_file_bytes
        self.git_timeout_seconds = git_timeout_seconds
        git_binary = shutil.which("git", path="/usr/local/bin:/usr/bin:/bin")
        if git_binary is None:
            raise SourceSnapshotError("Git is unavailable for committed-tree snapshots")
        self.git_binary = str(Path(git_binary).resolve())

    def prepare_manifest(self, reference: RepositoryRef) -> SourceSnapshotManifest:
        inspection, _repository, entries = self._verified_entries(reference)
        repeated_inspection, _repeated_repository, repeated_entries = self._verified_entries(
            reference
        )
        first = self._archive_digest(entries)
        second = self._archive_digest(repeated_entries)
        if (
            inspection.repository_fingerprint != repeated_inspection.repository_fingerprint
            or entries != repeated_entries
            or first != second
        ):
            raise SourceSnapshotError("committed-tree snapshot generation is not deterministic")
        fresh = self.inspector.inspect(reference)
        if fresh.repository_fingerprint != inspection.repository_fingerprint:
            raise SourceSnapshotError("registered repository changed during snapshot preparation")
        return self._manifest(reference, inspection, entries, first)

    def materialize(
        self,
        reference: RepositoryRef,
        expected: SourceSnapshotManifest,
        destination: Path,
    ) -> SourceSnapshotManifest:
        try:
            inspection, _repository, entries = self._verified_entries(reference)
            repeated_inspection, _repeated_repository, repeated_entries = self._verified_entries(
                reference
            )
        except SourceSnapshotError as exc:
            raise SourceSnapshotError(
                "registered source no longer matches the approved snapshot"
            ) from exc
        first = self._archive_digest(entries)
        second = self._archive_digest(repeated_entries)
        if (
            inspection.repository_fingerprint != repeated_inspection.repository_fingerprint
            or entries != repeated_entries
            or first != second
        ):
            raise SourceSnapshotError("committed-tree snapshot generation is not deterministic")
        manifest = self._manifest(reference, inspection, entries, first)
        if manifest.model_dump(mode="json") != expected.model_dump(mode="json"):
            raise SourceSnapshotError("registered source no longer matches the approved snapshot")
        self._write_tree(entries, destination)
        observed = self._digest_materialized_tree(destination)
        if observed != manifest.tree_digest:
            raise SourceSnapshotError("materialized source digest does not match the manifest")
        return manifest

    def _verified_entries(
        self,
        reference: RepositoryRef,
    ) -> tuple[RepositoryInspection, Path, list[_TreeEntry]]:
        if reference.allowed_paths:
            raise SourceSnapshotError("Phase 7 requires a complete repository snapshot")
        inspection = self.inspector.inspect(reference)
        self._validate_inspection(inspection)
        repository = self.inspector.registered_path(reference)
        self.inspector.validate_git_metadata_safety(repository)
        revision = inspection.git.resolved_revision
        if revision is None:
            raise SourceSnapshotError("repository revision was not resolved")

        deadline = time.monotonic() + self.git_timeout_seconds
        inventory_limit = self.max_files * 640
        output = self._git(
            repository,
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            revision,
            output_limit=inventory_limit,
            deadline=deadline,
        )
        entries: list[_TreeEntry] = []
        total_bytes = 0
        collision_keys: set[str] = set()
        file_keys: set[str] = set()
        ancestor_keys: set[str] = set()
        for raw_entry in output.split(b"\0"):
            if not raw_entry:
                continue
            try:
                metadata, raw_path = raw_entry.split(b"\t", 1)
                raw_mode, raw_type, raw_oid = metadata.split(b" ", 2)
                path = raw_path.decode("utf-8", errors="strict")
                mode_text = raw_mode.decode("ascii")
                object_type = raw_type.decode("ascii")
                object_id = raw_oid.decode("ascii")
            except (ValueError, UnicodeDecodeError) as exc:
                raise SourceSnapshotError("Git tree contains an invalid entry") from exc
            if object_type != "blob" or mode_text not in {"100644", "100755"}:
                raise SourceSnapshotError("Git tree contains a non-regular source entry")
            self._validate_path(path, collision_keys, file_keys, ancestor_keys)
            if is_sensitive_path(path):
                raise SourceSnapshotError("committed tree contains a sensitive path")
            raw_size = self._git(
                repository,
                "cat-file",
                "-s",
                object_id,
                output_limit=128,
                deadline=deadline,
            )
            try:
                object_size = int(raw_size.decode("ascii").strip())
            except (UnicodeDecodeError, ValueError) as exc:
                raise SourceSnapshotError("Git blob size is invalid") from exc
            if object_size < 0 or object_size > self.max_file_bytes:
                raise SourceSnapshotError("committed tree contains an oversized file")
            if total_bytes + object_size > self.max_total_bytes:
                raise SourceSnapshotError("committed tree exceeds the snapshot byte limit")
            data = self._git(
                repository,
                "cat-file",
                "blob",
                object_id,
                output_limit=object_size,
                deadline=deadline,
            )
            if len(data) != object_size:
                raise SourceSnapshotError("Git blob size changed during snapshot preparation")
            if self._git_object_id(data, object_id) != object_id:
                raise SourceSnapshotError("Git blob content does not match its object id")
            if secret_rule_ids(data):
                raise SourceSnapshotError("committed tree contains credential-shaped material")
            total_bytes += object_size
            entries.append(
                _TreeEntry(
                    path=path,
                    mode=0o755 if mode_text == "100755" else 0o644,
                    object_id=object_id,
                    data=data,
                    sha256=hashlib.sha256(data).hexdigest(),
                )
            )
            if len(entries) > self.max_files:
                raise SourceSnapshotError("committed tree exceeds the snapshot file limit")
        if not entries:
            raise SourceSnapshotError("committed tree snapshot is empty")
        return inspection, repository, entries

    @staticmethod
    def _git_object_id(data: bytes, expected: str) -> str:
        header = f"blob {len(data)}\0".encode("ascii")
        payload = header + data
        if len(expected) == 40:
            return hashlib.sha1(payload, usedforsecurity=False).hexdigest()
        if len(expected) == 64:
            return hashlib.sha256(payload).hexdigest()
        raise SourceSnapshotError("Git blob object id uses an unsupported hash format")

    @staticmethod
    def _validate_inspection(inspection: RepositoryInspection) -> None:
        git = inspection.git
        if inspection.secret_findings:
            raise SourceSnapshotError("committed tree contains credential-shaped material")
        dirty = any(
            (
                git.staged_paths,
                git.modified_paths,
                git.deleted_paths,
                git.renamed_paths,
                git.untracked_paths,
                git.ignored_paths,
                git.conflicted_paths,
            )
        )
        if (
            not inspection.complete
            or not inspection.read_only_verified
            or inspection.limits_reached
            or inspection.symlinks
            or not git.is_repository
            or not git.metadata_complete
            or git.resolved_revision is None
            or git.head_revision != git.resolved_revision
            or git.recovery_snapshot_digest is None
            or git.shallow
            or git.submodules
            or dirty
        ):
            raise SourceSnapshotError(
                "Phase 7 requires a complete, clean, exact, secret-free Git revision"
            )

    @staticmethod
    def _validate_path(
        path: str,
        collisions: set[str],
        file_keys: set[str],
        ancestor_keys: set[str],
    ) -> None:
        try:
            encoded = path.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise SourceSnapshotError("source path is not valid UTF-8") from exc
        pure = PurePosixPath(path)
        parts = pure.parts
        if (
            not path
            or len(encoded) > 512
            or pure.is_absolute()
            or "\\" in path
            or len(parts) > 32
            or any(part in {"", ".", ".."} for part in parts)
            or any(part.casefold() == ".git" for part in parts)
            or any(len(part.encode("utf-8")) > 255 for part in parts)
        ):
            raise SourceSnapshotError("source path is unsafe")
        if any(
            ord(character) < 32
            or ord(character) == 127
            or unicodedata.bidirectional(character)
            in {"RLE", "LRE", "RLO", "LRO", "PDF", "RLI", "LRI", "FSI", "PDI"}
            for character in path
        ):
            raise SourceSnapshotError("source path contains unsafe control characters")
        normalized = unicodedata.normalize("NFC", path)
        if normalized != path:
            raise SourceSnapshotError("source path is not NFC-normalized")
        collision_key = normalized.casefold()
        if collision_key in collisions or collision_key in ancestor_keys:
            raise SourceSnapshotError("source tree contains a path collision")
        for index in range(1, len(parts)):
            ancestor = PurePosixPath(*parts[:index]).as_posix().casefold()
            if ancestor in file_keys:
                raise SourceSnapshotError("source tree contains a file/ancestor collision")
            ancestor_keys.add(ancestor)
        collisions.add(collision_key)
        file_keys.add(collision_key)

    def _manifest(
        self,
        reference: RepositoryRef,
        inspection: RepositoryInspection,
        entries: list[_TreeEntry],
        archive_digest: str,
    ) -> SourceSnapshotManifest:
        tree_digest = hashlib.sha256(
            canonical_json(
                [
                    {
                        "mode": item.mode,
                        "path": item.path,
                        "sha256": item.sha256,
                        "size": len(item.data),
                    }
                    for item in entries
                ]
            ).encode("utf-8")
        ).hexdigest()
        return SourceSnapshotManifest(
            provider=reference.provider,
            repository_id=reference.repository_id,
            resolved_revision=inspection.git.resolved_revision,
            repository_fingerprint=inspection.repository_fingerprint,
            tree_digest=tree_digest,
            archive_digest=archive_digest,
            file_count=len(entries),
            total_bytes=sum(len(item.data) for item in entries),
        )

    @staticmethod
    def _archive_digest(entries: list[_TreeEntry]) -> str:
        stream = _HashWriter()
        with tarfile.open(fileobj=stream, mode="w|", format=tarfile.GNU_FORMAT) as archive:
            for entry in entries:
                info = tarfile.TarInfo(entry.path)
                info.size = len(entry.data)
                info.mode = entry.mode
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = 0
                archive.addfile(info, io.BytesIO(entry.data))
        return stream.hexdigest()

    @staticmethod
    def _write_tree(entries: list[_TreeEntry], destination: Path) -> None:
        if destination.exists():
            if destination.is_symlink() or any(destination.iterdir()):
                raise SourceSnapshotError("snapshot destination must be a fresh empty directory")
        else:
            destination.mkdir(mode=0o700, parents=True)
        for entry in entries:
            target = destination.joinpath(*PurePosixPath(entry.path).parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as handle:
                    handle.write(entry.data)
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                os.close(descriptor)
            os.chmod(target, 0o555 if entry.mode & stat.S_IXUSR else 0o444)
        directories = sorted(
            (item for item in destination.rglob("*") if item.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        )
        for directory in directories:
            os.chmod(directory, 0o555)
        os.chmod(destination, 0o555)

    @staticmethod
    def _digest_materialized_tree(destination: Path) -> str:
        records: list[dict[str, object]] = []
        for path in sorted(destination.rglob("*")):
            metadata = path.lstat()
            relative = path.relative_to(destination).as_posix()
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                raise SourceSnapshotError("materialized source contains a non-regular file")
            data = path.read_bytes()
            records.append(
                {
                    "mode": 0o755 if metadata.st_mode & stat.S_IXUSR else 0o644,
                    "path": relative,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }
            )
        return hashlib.sha256(canonical_json(records).encode("utf-8")).hexdigest()

    def _git(
        self,
        repository: Path,
        *arguments: str,
        output_limit: int,
        deadline: float | None = None,
    ) -> bytes:
        environment = {
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
        command = [
            self.git_binary,
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "protocol.allow=never",
            "-C",
            str(repository),
            *arguments,
        ]
        process: subprocess.Popen[bytes] | None = None
        selector: selectors.BaseSelector | None = None
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=environment,
                start_new_session=True,
            )
            assert process.stdout is not None
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            operation_deadline = deadline or (time.monotonic() + self.git_timeout_seconds)
            output = bytearray()
            while True:
                remaining = operation_deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, self.git_timeout_seconds)
                events = selector.select(timeout=min(remaining, 0.25))
                if not events:
                    continue
                chunk = os.read(process.stdout.fileno(), 64 * 1024)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > output_limit:
                    raise SourceSnapshotError("bounded Git snapshot output exceeded its limit")
            return_code = process.wait(timeout=max(0.1, operation_deadline - time.monotonic()))
            if return_code != 0:
                raise SourceSnapshotError("bounded Git snapshot operation failed")
            return bytes(output)
        except SourceSnapshotError:
            if process is not None:
                self._terminate_process(process)
            raise
        except (OSError, subprocess.TimeoutExpired) as exc:
            if process is not None:
                self._terminate_process(process)
            raise SourceSnapshotError("bounded Git snapshot operation failed") from exc
        finally:
            if selector is not None:
                selector.close()
            if process is not None and process.stdout is not None:
                process.stdout.close()

    @staticmethod
    def _terminate_process(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)
