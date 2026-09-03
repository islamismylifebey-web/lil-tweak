"""Preflight inspection and non-following extraction for ZIP sources."""

from __future__ import annotations

import io
import hashlib
import hmac
import os
import re
import shutil
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from .limits import MAX_EXPANDED_SOURCE_BYTES
from .store import SourceSpec


class ArchiveError(ValueError):
    """A stable, content-free archive rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class SourceIntakeError(ValueError):
    def __init__(self, code: str = "source_intake_failed") -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_entries: int = 20_000
    max_depth: int = 32
    max_file_bytes: int = 25 * 1024 * 1024
    max_total_bytes: int = MAX_EXPANDED_SOURCE_BYTES
    max_compression_ratio: float = 100.0


@dataclass(frozen=True, slots=True)
class ArchiveEntry:
    path: str
    size: int
    is_directory: bool


ArchiveSource = bytes | bytearray | memoryview | str | os.PathLike[str] | BinaryIO
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_BLOCKED_SOURCE_COMPONENTS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".ssh",
        ".aws",
        ".gnupg",
        ".npmrc",
        ".pypirc",
        "credentials",
        "id_rsa",
        "id_ed25519",
    }
)


def _blocked_source_component(component: str) -> bool:
    folded = component.casefold()
    if folded in _BLOCKED_SOURCE_COMPONENTS:
        return True
    return folded == ".env" or (
        folded.startswith(".env.")
        and folded not in {".env.example", ".env.sample"}
    )


def _open_zip(source: ArchiveSource) -> zipfile.ZipFile:
    if isinstance(source, (bytes, bytearray, memoryview)):
        return zipfile.ZipFile(io.BytesIO(bytes(source)), "r")
    return zipfile.ZipFile(source, "r")


def _safe_name(raw: str, limits: ArchiveLimits) -> tuple[str, bool]:
    if (
        not raw
        or "\x00" in raw
        or any(ord(char) < 32 or ord(char) == 127 for char in raw)
    ):
        raise ArchiveError("unsafe_path")
    normalized = raw.replace("\\", "/")
    if (
        normalized.startswith("/")
        or raw.startswith("\\\\")
        or _WINDOWS_DRIVE.match(normalized)
    ):
        raise ArchiveError("unsafe_path")
    is_directory = normalized.endswith("/")
    normalized = normalized.rstrip("/")
    path = PurePosixPath(normalized)
    if not normalized or any(part in ("", ".", "..") for part in path.parts):
        raise ArchiveError("unsafe_path")
    try:
        raw.encode("utf-8")
    except UnicodeEncodeError:
        raise ArchiveError("unsafe_path") from None
    if any(
        len(part.encode("utf-8")) > 255 or _blocked_source_component(part)
        for part in path.parts
    ):
        raise ArchiveError("unsafe_path")
    if len(path.parts) > limits.max_depth:
        raise ArchiveError("path_too_deep")
    return path.as_posix(), is_directory


def validate_portable_path(
    raw: str, *, limits: ArchiveLimits = ArchiveLimits()
) -> str:
    """Validate one source path using the same contract as ZIP members."""

    path, _is_directory = _safe_name(raw, limits)
    return path


def _validate_info(
    info: zipfile.ZipInfo,
    limits: ArchiveLimits,
) -> tuple[ArchiveEntry, str]:
    path, name_is_directory = _safe_name(info.filename, limits)
    if info.flag_bits & 0x1:
        raise ArchiveError("encrypted_entry")
    mode = (info.external_attr >> 16) & 0xFFFF
    kind = stat.S_IFMT(mode)
    is_directory = info.is_dir() or name_is_directory or kind == stat.S_IFDIR
    if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise ArchiveError("unsupported_type")
    if is_directory and info.file_size:
        raise ArchiveError("unsupported_type")
    if info.file_size < 0 or info.compress_size < 0:
        raise ArchiveError("invalid_zip")
    if info.file_size > limits.max_file_bytes:
        raise ArchiveError("file_too_large")
    if info.file_size:
        if info.compress_size == 0:
            raise ArchiveError("compression_ratio")
        if info.file_size / info.compress_size > limits.max_compression_ratio:
            raise ArchiveError("compression_ratio")
    return ArchiveEntry(path, info.file_size, is_directory), path.casefold()


def inspect_zip(
    source: ArchiveSource,
    *,
    limits: ArchiveLimits = ArchiveLimits(),
) -> list[ArchiveEntry]:
    """Validate every member without writing and return a safe inventory."""

    if min(
        limits.max_entries,
        limits.max_depth,
        limits.max_file_bytes,
        limits.max_total_bytes,
    ) < 0 or limits.max_compression_ratio <= 0:
        raise ValueError("archive limits must be positive")
    try:
        with _open_zip(source) as archive:
            infos = archive.infolist()
            if len(infos) > limits.max_entries:
                raise ArchiveError("too_many_entries")
            entries: list[ArchiveEntry] = []
            seen: set[str] = set()
            entry_types: dict[str, bool] = {}
            total = 0
            for info in infos:
                entry, folded = _validate_info(info, limits)
                if folded in seen:
                    raise ArchiveError("duplicate_path")
                parent = PurePosixPath(entry.path).parent
                while parent != PurePosixPath("."):
                    existing_parent = entry_types.get(parent.as_posix().casefold())
                    if existing_parent is False:
                        raise ArchiveError("path_conflict")
                    parent = parent.parent
                if entry.is_directory is False:
                    prefix = folded + "/"
                    if any(existing.startswith(prefix) for existing in entry_types):
                        raise ArchiveError("path_conflict")
                seen.add(folded)
                entry_types[folded] = entry.is_directory
                total += entry.size
                if total > limits.max_total_bytes:
                    raise ArchiveError("archive_too_large")
                entries.append(entry)
            return entries
    except ArchiveError:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError):
        raise ArchiveError("invalid_zip") from None


def extract_zip(
    source: ArchiveSource,
    destination: str | os.PathLike[str],
    *,
    limits: ArchiveLimits = ArchiveLimits(),
) -> list[Path]:
    """Preflight the complete archive, then stream regular files safely."""

    # Bytes make the two passes independent. For seekable files we rewind; paths
    # can simply be reopened. Non-seekable streams are bounded by archive limits.
    material: ArchiveSource
    if hasattr(source, "read") and not isinstance(source, (bytes, bytearray, memoryview)):
        stream = source
        try:
            stream.seek(0)
            material = stream.read(limits.max_total_bytes + 1)
        except (AttributeError, OSError):
            material = stream.read(limits.max_total_bytes + 1)
        if len(material) > limits.max_total_bytes:
            raise ArchiveError("archive_too_large")
    else:
        material = source
    entries = inspect_zip(material, limits=limits)
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    root_resolved = root.resolve()
    extracted: list[Path] = []
    try:
        with _open_zip(material) as archive:
            for info, entry in zip(archive.infolist(), entries, strict=True):
                target = root.joinpath(*PurePosixPath(entry.path).parts)
                resolved_parent = target.parent.resolve()
                if root_resolved != resolved_parent and root_resolved not in resolved_parent.parents:
                    raise ArchiveError("unsafe_path")
                if entry.is_directory:
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(target, flags, 0o600)
                try:
                    with os.fdopen(descriptor, "wb") as output, archive.open(info, "r") as input_file:
                        copied = shutil.copyfileobj(input_file, output, length=1024 * 1024)
                        del copied
                except BaseException:
                    target.unlink(missing_ok=True)
                    raise
                if target.stat().st_size != entry.size:
                    target.unlink(missing_ok=True)
                    raise ArchiveError("invalid_zip")
                extracted.append(target)
    except ArchiveError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError):
        raise ArchiveError("extraction_failed") from None
    return extracted


def _portable_filename(filename: str) -> str:
    if (
        not filename
        or filename in (".", "..")
        or len(filename) > 255
        or "/" in filename
        or "\\" in filename
        or "\x00" in filename
        or any(ord(character) < 32 or ord(character) == 127 for character in filename)
    ):
        raise SourceIntakeError("unsafe_source_name")
    try:
        validate_portable_path(filename)
    except ArchiveError:
        raise SourceIntakeError("unsafe_source_name") from None
    return filename


def ingest_r2_sources(
    client: object,
    bucket: str,
    sources: list[SourceSpec] | tuple[SourceSpec, ...],
    destination: str | os.PathLike[str],
    *,
    expected_prefix: str | None = None,
    max_source_bytes: int = 25 * 1024 * 1024,
    max_total_bytes: int = 100 * 1024 * 1024,
    max_workspace_bytes: int = MAX_EXPANDED_SOURCE_BYTES,
    max_workspace_files: int = 20_000,
) -> list[str]:
    """Download immutable source objects, verify them, and build an inventory."""

    if (
        not bucket
        or min(
            max_source_bytes,
            max_total_bytes,
            max_workspace_bytes,
            max_workspace_files,
        )
        <= 0
    ):
        raise ValueError("invalid source intake configuration")
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    inventory: list[str] = []
    total = 0
    workspace_bytes = 0
    workspace_files = 0
    for source in sources:
        filename = _portable_filename(source.filename)
        if (
            not source.source_id
            or source.size_bytes < 0
            or source.size_bytes > max_source_bytes
        ):
            raise SourceIntakeError("invalid_source_manifest")
        prefix = expected_prefix
        if prefix is None:
            prefix = source.object_key.rsplit("/", 1)[0] + "/"
        if (
            not source.object_key.startswith(prefix)
            or source.object_key != prefix + source.source_id
            or ".." in PurePosixPath(source.object_key).parts
        ):
            raise SourceIntakeError("invalid_source_key")
        total += source.size_bytes
        if total > max_total_bytes:
            raise SourceIntakeError("sources_too_large")
        try:
            response = client.get_object(Bucket=bucket, Key=source.object_key)  # type: ignore[attr-defined]
            declared = response.get("ContentLength")
            if declared is not None and declared != source.size_bytes:
                raise SourceIntakeError("source_size_mismatch")
            body = response["Body"]
            try:
                data = body.read(max_source_bytes + 1)
            finally:
                close = getattr(body, "close", None)
                if close:
                    close()
        except SourceIntakeError:
            raise
        except Exception:
            raise SourceIntakeError("source_unavailable") from None
        if len(data) != source.size_bytes or len(data) > max_source_bytes:
            raise SourceIntakeError("source_size_mismatch")
        digest = hashlib.sha256(data).hexdigest()
        if source.sha256 is not None and not hmac.compare_digest(digest, source.sha256):
            raise SourceIntakeError("source_digest_mismatch")
        is_zip = source.media_type in (
            "application/zip",
            "application/x-zip-compressed",
        ) or filename.lower().endswith(".zip")
        try:
            if is_zip:
                entries = inspect_zip(data)
                expanded_files = [entry for entry in entries if not entry.is_directory]
                expanded_bytes = sum(entry.size for entry in expanded_files)
                if (
                    workspace_bytes + expanded_bytes > max_workspace_bytes
                    or workspace_files + len(expanded_files) > max_workspace_files
                ):
                    raise SourceIntakeError("workspace_too_large")
                extracted = extract_zip(data, root)
                inventory.extend(path.relative_to(root).as_posix() for path in extracted)
                workspace_bytes += expanded_bytes
                workspace_files += len(expanded_files)
            else:
                if (
                    workspace_bytes + len(data) > max_workspace_bytes
                    or workspace_files + 1 > max_workspace_files
                ):
                    raise SourceIntakeError("workspace_too_large")
                target = root / filename
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(target, flags, 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    output.write(data)
                inventory.append(filename)
                workspace_bytes += len(data)
                workspace_files += 1
        except ArchiveError as error:
            raise SourceIntakeError(error.code) from None
        except OSError:
            raise SourceIntakeError("source_path_conflict") from None
    return sorted(set(inventory))
