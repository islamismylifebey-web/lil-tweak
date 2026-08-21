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
from collections.abc import Buffer
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import TracebackType

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


@dataclass(frozen=True)
class _InventoryEntry:
    path: str
    mode: int
    object_id: str


@dataclass(frozen=True)
class _AdmittedEntry:
    inventory: _InventoryEntry
    size: int


class _HashWriter(io.RawIOBase):
    def __init__(self) -> None:
        self._digest = hashlib.sha256()
        self._position = 0

    def write(self, data: Buffer, /) -> int:
        view = memoryview(data)
        self._digest.update(view)
        self._position += view.nbytes
        return view.nbytes

    def tell(self) -> int:
        return self._position

    def writable(self) -> bool:
        return True

    def flush(self) -> None:
        return None

    def hexdigest(self) -> str:
        return self._digest.hexdigest()


class _GitBatchReader:
    """A single-repository, single-pass bounded Git cat-file protocol reader."""

    def __init__(
        self,
        *,
        command: list[str],
        environment: dict[str, str],
        deadline: float,
    ) -> None:
        self.command = command
        self.deadline = deadline
        self.process: subprocess.Popen[bytes] | None = None
        self.selector: selectors.BaseSelector | None = None
        self.buffer = bytearray()
        self.finished = False
        try:
            self.process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=environment,
                start_new_session=True,
            )
            assert self.process.stdin is not None
            assert self.process.stdout is not None
            os.set_blocking(self.process.stdin.fileno(), False)
            self.selector = selectors.DefaultSelector()
            self.selector.register(self.process.stdout, selectors.EVENT_READ)
        except OSError as exc:
            self.close(failed=True)
            raise SourceSnapshotError("bounded Git batch operation failed") from exc

    def __enter__(self) -> _GitBatchReader:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close(failed=exception_type is not None)

    def check(self, object_id: str) -> int:
        self._request(object_id)
        returned_id, object_type, object_size = self._read_header()
        self._validate_metadata(
            expected_id=object_id,
            returned_id=returned_id,
            object_type=object_type,
        )
        return object_size

    def read_blob(self, object_id: str, *, expected_size: int) -> bytes:
        self._request(object_id)
        returned_id, object_type, object_size = self._read_header()
        self._validate_metadata(
            expected_id=object_id,
            returned_id=returned_id,
            object_type=object_type,
        )
        if object_size != expected_size:
            raise SourceSnapshotError("Git blob size changed during snapshot preparation")
        data = self._read_exact(object_size)
        if self._read_exact(1) != b"\n":
            raise SourceSnapshotError("Git batch content delimiter is invalid")
        return data

    def close(self, *, failed: bool) -> None:
        if self.finished:
            return
        self.finished = True
        process = self.process
        selector = self.selector
        try:
            if process is None:
                return
            if failed:
                RepositorySnapshotBuilder._terminate_process(process)
                return
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
            if self.buffer:
                raise SourceSnapshotError("Git batch operation returned unexpected trailing output")
            assert process.stdout is not None
            while True:
                self._require_time()
                assert selector is not None
                events = selector.select(timeout=min(self._remaining(), 0.25))
                if not events:
                    continue
                chunk = os.read(process.stdout.fileno(), 64 * 1024)
                if not chunk:
                    break
                raise SourceSnapshotError("Git batch operation returned unexpected trailing output")
            self._require_time()
            return_code = process.wait(timeout=self._remaining())
            if return_code != 0:
                raise SourceSnapshotError("bounded Git batch operation failed")
        except SourceSnapshotError:
            if process is not None:
                RepositorySnapshotBuilder._terminate_process(process)
            raise
        except (BrokenPipeError, OSError, subprocess.TimeoutExpired) as exc:
            if process is not None:
                RepositorySnapshotBuilder._terminate_process(process)
            raise SourceSnapshotError("bounded Git batch operation failed") from exc
        finally:
            if selector is not None:
                selector.close()
            if process is not None:
                if process.stdin is not None and not process.stdin.closed:
                    with contextlib.suppress(BrokenPipeError, OSError):
                        process.stdin.close()
                if process.stdout is not None:
                    with contextlib.suppress(OSError):
                        process.stdout.close()

    def _request(self, object_id: str) -> None:
        if self.finished:
            raise SourceSnapshotError("Git batch operation is already closed")
        if not RepositorySnapshotBuilder._valid_object_id(object_id):
            raise SourceSnapshotError("Git blob object id uses an unsupported hash format")
        self._require_time()
        assert self.process is not None and self.process.stdin is not None
        descriptor = self.process.stdin.fileno()
        pending = memoryview(object_id.encode("ascii") + b"\n")
        write_selector = selectors.DefaultSelector()
        try:
            write_selector.register(descriptor, selectors.EVENT_WRITE)
            while pending:
                self._require_time()
                events = write_selector.select(timeout=min(self._remaining(), 0.25))
                if not events:
                    continue
                try:
                    written = os.write(descriptor, pending)
                except BlockingIOError:
                    continue
                if written <= 0:
                    raise BrokenPipeError
                pending = pending[written:]
        except (BrokenPipeError, OSError) as exc:
            RepositorySnapshotBuilder._terminate_process(self.process)
            raise SourceSnapshotError("bounded Git batch operation failed") from exc
        finally:
            write_selector.close()

    def _read_header(self) -> tuple[str, str, int]:
        raw_header = self._read_until_newline(limit=256)
        try:
            returned_id, object_type, raw_size = raw_header.decode("ascii").split(" ")
            if not raw_size.isdecimal() or (len(raw_size) > 1 and raw_size.startswith("0")):
                raise ValueError
            object_size = int(raw_size)
        except (UnicodeDecodeError, ValueError) as exc:
            raise SourceSnapshotError("Git batch object header is invalid") from exc
        if object_size < 0:
            raise SourceSnapshotError("Git batch object header is invalid")
        return returned_id, object_type, object_size

    @staticmethod
    def _validate_metadata(
        *,
        expected_id: str,
        returned_id: str,
        object_type: str,
    ) -> None:
        if returned_id != expected_id or object_type != "blob":
            raise SourceSnapshotError("Git batch object metadata does not match the tree")

    def _read_until_newline(self, *, limit: int) -> bytes:
        while True:
            delimiter = self.buffer.find(b"\n")
            if delimiter >= 0:
                if delimiter > limit:
                    raise SourceSnapshotError("bounded Git batch header exceeded its limit")
                line = bytes(self.buffer[:delimiter])
                del self.buffer[: delimiter + 1]
                return line
            if len(self.buffer) > limit:
                raise SourceSnapshotError("bounded Git batch header exceeded its limit")
            self._read_into_buffer(maximum=limit + 1 - len(self.buffer))

    def _read_exact(self, size: int) -> bytes:
        output = bytearray()
        while len(output) < size:
            if self.buffer:
                take = min(size - len(output), len(self.buffer))
                output.extend(self.buffer[:take])
                del self.buffer[:take]
                continue
            self._read_into_buffer(maximum=min(64 * 1024, size - len(output)))
        return bytes(output)

    def _read_into_buffer(self, *, maximum: int) -> None:
        self._require_time()
        assert self.process is not None
        assert self.process.stdout is not None
        assert self.selector is not None
        while True:
            events = self.selector.select(timeout=min(self._remaining(), 0.25))
            if events:
                break
            self._require_time()
        chunk = os.read(self.process.stdout.fileno(), max(1, maximum))
        if not chunk:
            raise SourceSnapshotError("Git batch operation ended before its response was complete")
        self.buffer.extend(chunk)

    def _remaining(self) -> float:
        return self.deadline - time.monotonic()

    def _require_time(self) -> None:
        if self._remaining() <= 0:
            raise SourceSnapshotError("bounded Git batch operation failed")


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
        inventory: list[_InventoryEntry] = []
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
            if (
                object_type != "blob"
                or mode_text not in {"100644", "100755"}
                or not self._valid_object_id(object_id)
            ):
                raise SourceSnapshotError("Git tree contains a non-regular source entry")
            self._validate_path(path, collision_keys, file_keys, ancestor_keys)
            if is_sensitive_path(path):
                raise SourceSnapshotError("committed tree contains a sensitive path")
            inventory.append(
                _InventoryEntry(
                    path=path,
                    mode=0o755 if mode_text == "100755" else 0o644,
                    object_id=object_id,
                )
            )
            if len(inventory) > self.max_files:
                raise SourceSnapshotError("committed tree exceeds the snapshot file limit")
        if not inventory:
            raise SourceSnapshotError("committed tree snapshot is empty")

        admitted: list[_AdmittedEntry] = []
        total_bytes = 0
        with self._git_batch(
            repository,
            "--batch-check",
            deadline=deadline,
        ) as size_reader:
            for item in inventory:
                object_size = size_reader.check(item.object_id)
                if object_size > self.max_file_bytes:
                    raise SourceSnapshotError("committed tree contains an oversized file")
                if total_bytes + object_size > self.max_total_bytes:
                    raise SourceSnapshotError("committed tree exceeds the snapshot byte limit")
                total_bytes += object_size
                admitted.append(_AdmittedEntry(inventory=item, size=object_size))

        entries: list[_TreeEntry] = []
        with self._git_batch(
            repository,
            "--batch",
            deadline=deadline,
        ) as content_reader:
            for admitted_entry in admitted:
                data = content_reader.read_blob(
                    admitted_entry.inventory.object_id,
                    expected_size=admitted_entry.size,
                )
                if (
                    self._git_object_id(data, admitted_entry.inventory.object_id)
                    != admitted_entry.inventory.object_id
                ):
                    raise SourceSnapshotError("Git blob content does not match its object id")
                if secret_rule_ids(data):
                    raise SourceSnapshotError("committed tree contains credential-shaped material")
                entries.append(
                    _TreeEntry(
                        path=admitted_entry.inventory.path,
                        mode=admitted_entry.inventory.mode,
                        object_id=admitted_entry.inventory.object_id,
                        data=data,
                        sha256=hashlib.sha256(data).hexdigest(),
                    )
                )
        return inspection, repository, entries

    @staticmethod
    def _valid_object_id(object_id: str) -> bool:
        return len(object_id) in {40, 64} and all(
            character in "0123456789abcdef" for character in object_id
        )

    def _git_batch(
        self,
        repository: Path,
        batch_mode: str,
        *,
        deadline: float,
    ) -> _GitBatchReader:
        if batch_mode not in {"--batch-check", "--batch"}:
            raise ValueError("unsupported Git batch mode")
        return _GitBatchReader(
            command=self._git_command(repository, "cat-file", batch_mode),
            environment=self._git_environment(),
            deadline=deadline,
        )

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
        environment = self._git_environment()
        command = self._git_command(repository, *arguments)
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
    def _git_environment() -> dict[str, str]:
        return {
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

    def _git_command(self, repository: Path, *arguments: str) -> list[str]:
        return [
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

    @staticmethod
    def _terminate_process(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)
