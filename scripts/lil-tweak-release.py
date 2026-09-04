#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import contextmanager
import gzip
import hashlib
import importlib.util
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
from datetime import datetime, timezone
from datetime import timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Iterable
from urllib.parse import urlsplit


COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(
    r"^(?P<registry>[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)"
    r"(?::(?P<port>[1-9][0-9]{0,4}))?/"
    r"(?P<repository>(?:[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*)"
    r"@sha256:[0-9a-f]{64}$"
)
STATE_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
STATE_VALUE = re.compile(r"^[A-Za-z0-9._/:@+-]{1,4096}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_RECEIPT_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_FIELDS = 256
MAX_RECEIPT_LINE_BYTES = 4_096
MAX_DECISION_VALIDITY_SECONDS = 3_600
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 128 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_SOURCE_FILES = 65_536
MAX_SOURCE_PATH_BYTES = 4_096
MAX_SOURCE_COMPONENT_BYTES = 255
MAX_SOURCE_DEPTH = 32
MAX_ARCHIVE_EXPANDED_BYTES = (
    MAX_SOURCE_TOTAL_BYTES
    + MAX_SOURCE_FILES * (MAX_SOURCE_PATH_BYTES + 4_096)
)
SOURCE_SCHEMA = "lil-tweak-source-manifest-v1"
RUNTIME_SCHEMA = "lil-tweak-runtime-manifest-v1"
PRODUCTION_SCHEMA = "lil-tweak-production-manifest-v1"


class ReleaseError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _BoundedReader:
    def __init__(self, source: Any, maximum: int) -> None:
        self._source = source
        self._maximum = maximum
        self._observed = 0

    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b""
        requested = 1024 * 1024 if size < 0 else min(size, 1024 * 1024)
        remaining = self._maximum - self._observed
        if remaining < 0:
            raise ReleaseError("archive_expanded_size")
        data = self._source.read(min(requested, remaining + 1))
        self._observed += len(data)
        if self._observed > self._maximum:
            raise ReleaseError("archive_expanded_size")
        return data


_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


@contextmanager
def _open_bound_parent(path: Path, error_code: str):
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ReleaseError(error_code)
    path = Path(path)
    if not path.name or any(part in {"", ".."} for part in path.parts[1:-1]):
        raise ReleaseError(error_code)
    base = Path("/") if path.is_absolute() else Path(".")
    components = path.parts[1:-1] if path.is_absolute() else path.parts[:-1]
    descriptors: list[int] = []
    links: list[tuple[int, str, int, tuple[int, int]]] = []
    try:
        base_before = base.lstat()
        root = os.open(base, _DIRECTORY_FLAGS)
        descriptors.append(root)
        base_bound = os.fstat(root)
        if (
            not stat.S_ISDIR(base_bound.st_mode)
            or (base_before.st_dev, base_before.st_ino)
            != (base_bound.st_dev, base_bound.st_ino)
        ):
            raise ReleaseError(error_code)
        current = root
        for component in components:
            if component in {"", ".", ".."}:
                raise ReleaseError(error_code)
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            linked = os.stat(component, dir_fd=current, follow_symlinks=False)
            bound = os.fstat(child)
            if (
                not stat.S_ISDIR(linked.st_mode)
                or not stat.S_ISDIR(bound.st_mode)
                or (linked.st_dev, linked.st_ino) != (bound.st_dev, bound.st_ino)
            ):
                os.close(child)
                raise ReleaseError(error_code)
            identity = (bound.st_dev, bound.st_ino)
            links.append((current, component, child, identity))
            descriptors.append(child)
            current = child

        def revalidate() -> None:
            base_after = base.lstat()
            root_after = os.fstat(root)
            if (
                (base_after.st_dev, base_after.st_ino)
                != (root_after.st_dev, root_after.st_ino)
                or (root_after.st_dev, root_after.st_ino)
                != (base_bound.st_dev, base_bound.st_ino)
            ):
                raise ReleaseError(error_code)
            for parent, component, child, identity in links:
                linked = os.stat(component, dir_fd=parent, follow_symlinks=False)
                bound = os.fstat(child)
                if (
                    not stat.S_ISDIR(linked.st_mode)
                    or (linked.st_dev, linked.st_ino) != identity
                    or (bound.st_dev, bound.st_ino) != identity
                ):
                    raise ReleaseError(error_code)

        yield current, path.name, revalidate
        revalidate()
    except ReleaseError:
        raise
    except OSError as error:
        raise ReleaseError(error_code) from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as error:
        raise ReleaseError("manifest_not_canonical") from error


def _strict_json(data: bytes) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ReleaseError("json_duplicate_key")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise ReleaseError("json_nonfinite_number")

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except ReleaseError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseError("json_invalid") from error


def _read_secure(
    path: Path,
    *,
    maximum: int,
    required_mode: int | None = None,
    require_owner: bool = True,
) -> bytes:
    path = Path(path)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        before_path = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ReleaseError("input_file_unsafe") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ReleaseError("input_file_unsafe")
        if (before_path.st_dev, before_path.st_ino) != (before.st_dev, before.st_ino):
            raise ReleaseError("input_file_changed")
        if require_owner and before.st_uid != os.geteuid():
            raise ReleaseError("input_file_owner")
        if required_mode is not None and stat.S_IMODE(before.st_mode) != required_mode:
            raise ReleaseError("input_file_mode")
        if before.st_size < 0 or before.st_size > maximum:
            raise ReleaseError("input_file_size")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ReleaseError("input_file_changed")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ReleaseError("input_file_changed")
        after = os.fstat(descriptor)
        after_path = path.lstat()
        identity = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in identity):
            raise ReleaseError("input_file_changed")
        if (after_path.st_dev, after_path.st_ino, after_path.st_mode, after_path.st_nlink) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
        ):
            raise ReleaseError("input_file_changed")
        return b"".join(chunks)
    except ReleaseError:
        raise
    except OSError as error:
        raise ReleaseError("input_file_changed") from error
    finally:
        os.close(descriptor)


@contextmanager
def _secure_file_spool(path: Path, *, maximum: int):
    path = Path(path)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = -1
    spool = None
    try:
        before_path = path.lstat()
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or (before_path.st_dev, before_path.st_ino)
            != (before.st_dev, before.st_ino)
            or before.st_size < 0
            or before.st_size > maximum
        ):
            raise ReleaseError("input_file_unsafe")
        spool = tempfile.TemporaryFile(mode="w+b")
        digest = hashlib.sha256()
        remaining = before.st_size
        copied = 0
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ReleaseError("input_file_changed")
            spool.write(chunk)
            digest.update(chunk)
            copied += len(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ReleaseError("input_file_changed")
        after = os.fstat(descriptor)
        after_path = path.lstat()
        fields = (
            "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
            "st_size", "st_mtime_ns", "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ReleaseError("input_file_changed")
        if (
            after_path.st_dev,
            after_path.st_ino,
            after_path.st_mode,
            after_path.st_nlink,
        ) != (after.st_dev, after.st_ino, after.st_mode, after.st_nlink):
            raise ReleaseError("input_file_changed")
        spool.flush()
        spool.seek(0)
        yield spool, digest.hexdigest(), copied
    except ReleaseError:
        raise
    except OSError as error:
        raise ReleaseError("input_file_unsafe") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if spool is not None:
            spool.close()


def _file_receipt(path: Path, *, required_mode: int | None = None) -> dict[str, Any]:
    data = _read_secure(path, maximum=MAX_RECEIPT_BYTES, required_mode=required_mode)
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def write_new_manifest(path: Path, payload: dict[str, Any]) -> str:
    path = Path(path)
    data = canonical_json_bytes(payload)
    temporary_name = f".{path.name}.{secrets.token_hex(12)}"
    with _open_bound_parent(path, "manifest_parent_unsafe") as (
        parent,
        name,
        revalidate,
    ):
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise ReleaseError("manifest_write_failed") from error
        else:
            raise ReleaseError("manifest_exists")
        descriptor = -1
        published_identity: tuple[int, int] | None = None
        success = False
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o444,
                dir_fd=parent,
            )
            os.fchmod(descriptor, 0o444)
            written = 0
            while written < len(data):
                written += os.write(descriptor, data[written:])
            os.fsync(descriptor)
            revalidate()
            try:
                os.link(
                    temporary_name,
                    name,
                    src_dir_fd=parent,
                    dst_dir_fd=parent,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise ReleaseError("manifest_exists") from error
            published = os.stat(name, dir_fd=parent, follow_symlinks=False)
            published_identity = (published.st_dev, published.st_ino)
            os.unlink(temporary_name, dir_fd=parent)
            temporary_name = ""
            os.fsync(parent)
            revalidate()
            success = True
        except ReleaseError:
            raise
        except OSError as error:
            raise ReleaseError("manifest_write_failed") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_name:
                try:
                    os.unlink(temporary_name, dir_fd=parent)
                except FileNotFoundError:
                    pass
            if published_identity is not None:
                try:
                    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    current = None
                if (
                    current is not None
                    and (current.st_dev, current.st_ino) == published_identity
                    and not success
                ):
                    os.unlink(name, dir_fd=parent)
                    os.fsync(parent)
    return hashlib.sha256(data).hexdigest()


def load_canonical_manifest(
    path: Path,
    expected_schema: str,
) -> tuple[dict[str, Any], str, int]:
    data = _read_secure(
        Path(path),
        maximum=MAX_MANIFEST_BYTES,
        required_mode=0o444,
    )
    payload = _strict_json(data)
    if not isinstance(payload, dict) or payload.get("schema") != expected_schema:
        raise ReleaseError("manifest_schema_invalid")
    if canonical_json_bytes(payload) != data:
        raise ReleaseError("manifest_not_canonical")
    return payload, hashlib.sha256(data).hexdigest(), len(data)


def _git(repo: Path, *arguments: str, binary: bool = False) -> str | bytes:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ReleaseError("git_contract_failed") from error
    return completed.stdout if binary else completed.stdout.decode("utf-8").strip()


def _safe_source_path(value: str) -> str:
    if not value or "\\" in value or value.startswith("/"):
        raise ReleaseError("source_path_unsafe")
    path = PurePosixPath(value)
    if (
        path.as_posix() != value
        or unicodedata.normalize("NFC", value) != value
        or len(value.encode("utf-8")) > MAX_SOURCE_PATH_BYTES
        or len(path.parts) > MAX_SOURCE_DEPTH
        or any(
            part in {"", ".", ".."}
            or len(part.encode("utf-8")) > MAX_SOURCE_COMPONENT_BYTES
            for part in path.parts
        )
    ):
        raise ReleaseError("source_path_unsafe")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ReleaseError("source_path_unsafe")
    return path.as_posix()


def _check_path_collisions(paths: Iterable[str]) -> None:
    observed: dict[str, str] = {}
    for value in sorted(paths):
        parts = PurePosixPath(value).parts
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            folded = unicodedata.normalize("NFC", prefix).casefold()
            previous = observed.get(folded)
            if previous is not None and previous != prefix:
                raise ReleaseError("source_path_collision")
            observed[folded] = prefix


def _git_inventory(repo: Path, commit: str, *, verify_checkout: bool) -> dict[str, dict[str, Any]]:
    output = _git(repo, "ls-tree", "-rz", "--full-tree", commit, binary=True)
    assert isinstance(output, bytes)
    inventory: dict[str, dict[str, Any]] = {}
    total = 0
    for record in output.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode_raw, object_type, object_id = metadata.split(b" ", 2)
            path = _safe_source_path(raw_path.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as error:
            raise ReleaseError("source_inventory_invalid") from error
        mode = mode_raw.decode("ascii")
        if object_type != b"blob" or mode not in {"100644", "100755"}:
            raise ReleaseError("source_entry_type_unsafe")
        content = _git(repo, "cat-file", "blob", object_id.decode("ascii"), binary=True)
        assert isinstance(content, bytes)
        if len(content) > MAX_SOURCE_FILE_BYTES:
            raise ReleaseError("source_file_too_large")
        total += len(content)
        if total > MAX_SOURCE_TOTAL_BYTES:
            raise ReleaseError("source_tree_too_large")
        descriptor = {
            "path": path,
            "git_mode": mode,
            "archive_mode": "0755" if mode == "100755" else "0644",
            "extracted_mode": "0755" if mode == "100755" else "0644",
            "git_blob": object_id.decode("ascii"),
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        if path in inventory:
            raise ReleaseError("source_path_collision")
        inventory[path] = descriptor
        if verify_checkout:
            candidate = repo / Path(*PurePosixPath(path).parts)
            current = candidate.parent
            while current != repo:
                try:
                    parent_stat = current.lstat()
                except OSError as error:
                    raise ReleaseError("source_path_unsafe") from error
                if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
                    raise ReleaseError("source_path_unsafe")
                current = current.parent
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            try:
                file_descriptor = os.open(candidate, flags)
            except OSError as error:
                raise ReleaseError("source_path_unsafe") from error
            try:
                file_stat = os.fstat(file_descriptor)
                if (
                    not stat.S_ISREG(file_stat.st_mode)
                    or file_stat.st_nlink != 1
                    or file_stat.st_uid != repo.stat().st_uid
                    or file_stat.st_size != len(content)
                    or bool(file_stat.st_mode & 0o111) != (mode == "100755")
                ):
                    raise ReleaseError("source_path_unsafe")
                observed = bytearray()
                remaining = len(content) + 1
                while remaining:
                    chunk = os.read(file_descriptor, min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    observed.extend(chunk)
                    remaining -= len(chunk)
                if bytes(observed) != content:
                    raise ReleaseError("source_tree_dirty")
            finally:
                os.close(file_descriptor)
    _check_path_collisions(inventory)
    return inventory


def _resolve_repo_path(repo: Path, path: Path) -> str:
    candidate = path if path.is_absolute() else repo / path
    try:
        relative = candidate.relative_to(repo)
    except ValueError as error:
        raise ReleaseError("source_path_unsafe") from error
    return _safe_source_path(relative.as_posix())


def create_source_manifest(
    *,
    repo: Path,
    base: str,
    commit: str,
    verification_receipt: Path,
    preserves: list[Path],
    output: Path,
) -> str:
    repo = Path(repo).resolve()
    if not repo.is_dir() or repo.is_symlink() or not COMMIT.fullmatch(base) or not COMMIT.fullmatch(commit):
        raise ReleaseError("source_identity_invalid")
    if _git(repo, "rev-parse", "HEAD") != commit:
        raise ReleaseError("source_commit_mismatch")
    if _git(repo, "status", "--porcelain=v1", "-z", binary=True):
        raise ReleaseError("source_tree_dirty")
    _git(repo, "merge-base", "--is-ancestor", base, commit)
    base_inventory = _git_inventory(repo, base, verify_checkout=False)
    source_inventory = _git_inventory(repo, commit, verify_checkout=True)
    verification_path = _resolve_repo_path(repo, Path(verification_receipt))
    if verification_path not in source_inventory:
        raise ReleaseError("verification_receipt_untracked")
    for required in ("package.json", "package-lock.json"):
        if required not in source_inventory:
            raise ReleaseError("package_receipt_missing")

    preserved: list[dict[str, Any]] = []
    for requested in preserves:
        prefix = _safe_source_path(PurePosixPath(requested.as_posix()).as_posix())
        before_matches = {
            path: entry
            for path, entry in base_inventory.items()
            if path == prefix or path.startswith(f"{prefix}/")
        }
        after_matches = {
            path: entry
            for path, entry in source_inventory.items()
            if path == prefix or path.startswith(f"{prefix}/")
        }
        if not before_matches or not after_matches:
            raise ReleaseError("preserved_path_missing")
        if before_matches != after_matches:
            raise ReleaseError("preserved_path_changed")
        preserved.extend(after_matches[path] for path in sorted(after_matches))

    changes: list[dict[str, Any]] = []
    for path in sorted(set(base_inventory) | set(source_inventory)):
        before = base_inventory.get(path)
        after = source_inventory.get(path)
        if before == after:
            continue
        status_value = "add" if before is None else "delete" if after is None else "modify"
        changes.append({"status": status_value, "path": path, "before": before, "after": after})

    payload = {
        "schema": SOURCE_SCHEMA,
        "official_base": {
            "commit": base,
            "tree": _git(repo, "rev-parse", f"{base}^{{tree}}"),
        },
        "source": {
            "commit": commit,
            "tree": _git(repo, "rev-parse", f"{commit}^{{tree}}"),
        },
        "archive_policy": {
            "tar_umask": "0022",
            "regular_mode": "0644",
            "executable_mode": "0755",
            "directory_mode": "0755",
        },
        "packages": {
            "package_json": source_inventory["package.json"],
            "package_lock_json": source_inventory["package-lock.json"],
        },
        "verification_receipt": source_inventory[verification_path],
        "preserved": sorted(preserved, key=lambda entry: entry["path"]),
        "changes": changes,
        "files": [source_inventory[path] for path in sorted(source_inventory)],
    }
    _validated_manifest_inventory(payload)
    return write_new_manifest(Path(output), payload)


def _validated_manifest_inventory(
    manifest: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    files = manifest.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_SOURCE_FILES:
        raise ReleaseError("manifest_inventory_invalid")
    expected_files: dict[str, dict[str, Any]] = {}
    directories: set[str] = set()
    total = 0
    for entry in files:
        if (
            not isinstance(entry, dict)
            or set(entry)
            != {
                "path", "git_mode", "archive_mode", "extracted_mode", "git_blob",
                "size", "sha256",
            }
            or not isinstance(entry.get("path"), str)
        ):
            raise ReleaseError("manifest_inventory_invalid")
        path = _safe_source_path(entry["path"])
        git_mode = entry.get("git_mode")
        expected_mode = "0755" if git_mode == "100755" else "0644"
        size = entry.get("size")
        if (
            path in expected_files
            or git_mode not in {"100644", "100755"}
            or entry.get("archive_mode") != expected_mode
            or entry.get("extracted_mode") != expected_mode
            or not isinstance(entry.get("git_blob"), str)
            or re.fullmatch(r"[0-9a-f]{40}", entry["git_blob"]) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= MAX_SOURCE_FILE_BYTES
            or not isinstance(entry.get("sha256"), str)
            or SHA256.fullmatch(entry["sha256"]) is None
        ):
            raise ReleaseError("manifest_inventory_invalid")
        total += size
        if total > MAX_SOURCE_TOTAL_BYTES:
            raise ReleaseError("manifest_inventory_invalid")
        expected_files[path] = entry
        parent = PurePosixPath(path).parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    if set(expected_files) & directories:
        raise ReleaseError("manifest_inventory_invalid")
    if len(expected_files) + len(directories) > MAX_SOURCE_FILES:
        raise ReleaseError("manifest_inventory_invalid")
    _check_path_collisions([*expected_files, *directories])
    return expected_files, sorted(
        directories,
        key=lambda value: (value.count("/"), value),
    )


def _source_stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _verify_source_directory(
    source_dir: Path,
    manifest: dict[str, Any],
) -> None:
    if any(
        not hasattr(os, name)
        for name in ("O_CLOEXEC", "O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    ):
        raise ReleaseError("runtime_install_rejected")
    expected_files, directories = _validated_manifest_inventory(manifest)
    if manifest.get("archive_policy") != {
        "tar_umask": "0022",
        "regular_mode": "0644",
        "executable_mode": "0755",
        "directory_mode": "0755",
    }:
        raise ReleaseError("runtime_install_rejected")
    expected_directories = set(directories)
    expected_entries = len(expected_files) + len(expected_directories)
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    snapshots: dict[str, tuple[int, ...]] = {}
    entries_seen = 0

    def reject() -> None:
        raise ReleaseError("runtime_install_rejected")

    def verify_directory(
        descriptor: int,
        relative: str,
        expected_mode: int,
    ) -> tuple[int, ...]:
        bound = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(bound.st_mode)
            or bound.st_uid != os.geteuid()
            or stat.S_IMODE(bound.st_mode) != expected_mode
        ):
            reject()
        identity = _source_stat_identity(bound)
        snapshots[relative] = identity
        return identity

    def walk(descriptor: int, prefix: str) -> None:
        nonlocal entries_seen
        directory_before = verify_directory(
            descriptor,
            prefix,
            0o700 if not prefix else 0o755,
        )
        with os.scandir(descriptor) as entries:
            for entry in entries:
                entries_seen += 1
                if entries_seen > expected_entries:
                    reject()
                try:
                    relative = _safe_source_path(
                        f"{prefix}/{entry.name}" if prefix else entry.name
                    )
                    linked = os.stat(
                        entry.name,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                except (OSError, ReleaseError, UnicodeError):
                    reject()
                if stat.S_ISDIR(linked.st_mode):
                    if relative not in expected_directories:
                        reject()
                    try:
                        child = os.open(entry.name, _DIRECTORY_FLAGS, dir_fd=descriptor)
                    except OSError:
                        reject()
                    try:
                        bound = os.fstat(child)
                        if (
                            (linked.st_dev, linked.st_ino)
                            != (bound.st_dev, bound.st_ino)
                            or not stat.S_ISDIR(bound.st_mode)
                        ):
                            reject()
                        observed_directories.add(relative)
                        walk(child, relative)
                        linked_after = os.stat(
                            entry.name,
                            dir_fd=descriptor,
                            follow_symlinks=False,
                        )
                        if (
                            _source_stat_identity(linked_after)
                            != _source_stat_identity(os.fstat(child))
                            or snapshots[relative]
                            != _source_stat_identity(os.fstat(child))
                        ):
                            reject()
                    finally:
                        os.close(child)
                elif stat.S_ISREG(linked.st_mode):
                    expected = expected_files.get(relative)
                    if expected is None:
                        reject()
                    flags = (
                        os.O_RDONLY
                        | os.O_CLOEXEC
                        | os.O_NOFOLLOW
                        | os.O_NONBLOCK
                    )
                    try:
                        source = os.open(entry.name, flags, dir_fd=descriptor)
                    except OSError:
                        reject()
                    try:
                        before = os.fstat(source)
                        expected_mode = int(expected["extracted_mode"], 8)
                        if (
                            not stat.S_ISREG(before.st_mode)
                            or before.st_nlink != 1
                            or before.st_uid != os.geteuid()
                            or (linked.st_dev, linked.st_ino)
                            != (before.st_dev, before.st_ino)
                            or stat.S_IMODE(before.st_mode) != expected_mode
                            or before.st_size != expected["size"]
                        ):
                            reject()
                        digest = hashlib.sha256()
                        remaining = before.st_size
                        while remaining:
                            chunk = os.read(source, min(1024 * 1024, remaining))
                            if not chunk:
                                reject()
                            digest.update(chunk)
                            remaining -= len(chunk)
                        if os.read(source, 1) or digest.hexdigest() != expected["sha256"]:
                            reject()
                        after = os.fstat(source)
                        linked_after = os.stat(
                            entry.name,
                            dir_fd=descriptor,
                            follow_symlinks=False,
                        )
                        identity = _source_stat_identity(before)
                        if (
                            _source_stat_identity(after) != identity
                            or _source_stat_identity(linked_after) != identity
                        ):
                            reject()
                        snapshots[relative] = identity
                        observed_files.add(relative)
                    finally:
                        os.close(source)
                else:
                    reject()
        if _source_stat_identity(os.fstat(descriptor)) != directory_before:
            reject()

    def revalidate(relative: str, expected: tuple[int, ...]) -> None:
        parts = PurePosixPath(relative).parts if relative else ()
        try:
            with _open_relative_directory(root_descriptor, parts[:-1]) as parent:
                observed = (
                    os.fstat(parent)
                    if not parts
                    else os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                )
        except (OSError, ReleaseError):
            reject()
        if _source_stat_identity(observed) != expected:
            reject()

    source_dir = Path(source_dir)
    try:
        with _open_bound_parent(source_dir, "runtime_install_rejected") as (
            parent,
            name,
            revalidate_parent,
        ):
            root_descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
            try:
                linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
                bound = os.fstat(root_descriptor)
                if (
                    (linked.st_dev, linked.st_ino) != (bound.st_dev, bound.st_ino)
                    or not stat.S_ISDIR(bound.st_mode)
                ):
                    reject()
                walk(root_descriptor, "")
                if (
                    observed_files != set(expected_files)
                    or observed_directories != expected_directories
                ):
                    reject()
                for relative, identity in snapshots.items():
                    revalidate(relative, identity)
                linked_after = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if _source_stat_identity(linked_after) != snapshots[""]:
                    reject()
                revalidate_parent()
            finally:
                os.close(root_descriptor)
    except ReleaseError:
        raise
    except OSError as error:
        raise ReleaseError("runtime_install_rejected") from error


@contextmanager
def _open_relative_directory(root: int, parts: tuple[str, ...]):
    descriptors = [os.dup(root)]
    try:
        current = descriptors[0]
        for component in parts:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            linked = os.stat(component, dir_fd=current, follow_symlinks=False)
            bound = os.fstat(child)
            if (
                not stat.S_ISDIR(linked.st_mode)
                or not stat.S_ISDIR(bound.st_mode)
                or (linked.st_dev, linked.st_ino) != (bound.st_dev, bound.st_ino)
            ):
                os.close(child)
                raise ReleaseError("extract_destination_changed")
            descriptors.append(child)
            current = child
        yield current
    except ReleaseError:
        raise
    except OSError as error:
        raise ReleaseError("extract_destination_changed") from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _ensure_relative_directory(root: int, value: str) -> None:
    current = os.dup(root)
    try:
        for component in PurePosixPath(value).parts:
            try:
                os.mkdir(component, 0o755, dir_fd=current)
                os.fsync(current)
            except FileExistsError:
                pass
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            linked = os.stat(component, dir_fd=current, follow_symlinks=False)
            bound = os.fstat(child)
            if (
                not stat.S_ISDIR(linked.st_mode)
                or (linked.st_dev, linked.st_ino) != (bound.st_dev, bound.st_ino)
            ):
                os.close(child)
                raise ReleaseError("extract_destination_changed")
            os.fchmod(child, 0o755)
            os.close(current)
            current = child
        os.fsync(current)
    except ReleaseError:
        raise
    except OSError as error:
        raise ReleaseError("extract_failed") from error
    finally:
        os.close(current)


def _remove_directory_contents(directory: int, budget: list[int]) -> None:
    try:
        entries = list(os.scandir(directory))
        budget[0] -= len(entries)
        if budget[0] < 0:
            raise ReleaseError("extract_cleanup_failed")
        for entry in entries:
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                child = os.open(entry.name, _DIRECTORY_FLAGS, dir_fd=directory)
                try:
                    bound = os.fstat(child)
                    if (bound.st_dev, bound.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise ReleaseError("extract_cleanup_failed")
                    _remove_directory_contents(child, budget)
                finally:
                    os.close(child)
                os.rmdir(entry.name, dir_fd=directory)
            else:
                os.unlink(entry.name, dir_fd=directory)
        os.fsync(directory)
    except ReleaseError:
        raise
    except OSError as error:
        raise ReleaseError("extract_cleanup_failed") from error


def _remove_destination(
    parent: int,
    name: str,
    identity: tuple[int, int],
) -> None:
    try:
        linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
        directory = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
        try:
            bound = os.fstat(directory)
            if (
                (linked.st_dev, linked.st_ino) != identity
                or (bound.st_dev, bound.st_ino) != identity
            ):
                raise ReleaseError("extract_cleanup_failed")
            _remove_directory_contents(
                directory,
                [MAX_SOURCE_FILES * (MAX_SOURCE_DEPTH + 1)],
            )
        finally:
            os.close(directory)
        os.rmdir(name, dir_fd=parent)
        os.fsync(parent)
    except FileNotFoundError:
        return
    except ReleaseError:
        raise
    except OSError as error:
        raise ReleaseError("extract_cleanup_failed") from error


def _stream_archive(
    spool,
    manifest: dict[str, Any],
    expected_files: dict[str, dict[str, Any]],
    ordered_directories: list[str],
    *,
    destination: int | None = None,
) -> None:
    directories = set(ordered_directories)
    observed: set[str] = set()
    observed_folded: set[str] = set()
    comment: str | None = None
    spool.seek(0)
    try:
        with gzip.GzipFile(fileobj=spool, mode="rb") as decompressed:
            bounded = _BoundedReader(decompressed, MAX_ARCHIVE_EXPANDED_BYTES)
            with tarfile.open(fileobj=bounded, mode="r|") as bundle:
                for member in bundle:
                    path = _safe_source_path(member.name.rstrip("/"))
                    folded = unicodedata.normalize("NFC", path).casefold()
                    if path in observed or folded in observed_folded:
                        raise ReleaseError("archive_entry_duplicate")
                    if len(observed) >= len(expected_files) + len(directories):
                        raise ReleaseError("archive_inventory_mismatch")
                    observed.add(path)
                    observed_folded.add(folded)
                    if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                        raise ReleaseError("archive_entry_unsafe")
                    if member.isdir():
                        if path not in directories or stat.S_IMODE(member.mode) != 0o755:
                            raise ReleaseError("archive_inventory_mismatch")
                        continue
                    if not member.isfile() or path not in expected_files:
                        raise ReleaseError("archive_entry_unsafe")
                    expected = expected_files[path]
                    if (
                        stat.S_IMODE(member.mode) != int(expected["archive_mode"], 8)
                        or member.size != expected["size"]
                    ):
                        raise ReleaseError("archive_mode_mismatch")
                    extracted = bundle.extractfile(member)
                    if extracted is None:
                        raise ReleaseError("archive_entry_unsafe")
                    output = -1
                    if destination is not None:
                        relative = PurePosixPath(path)
                        with _open_relative_directory(destination, relative.parts[:-1]) as parent:
                            output = os.open(
                                relative.name,
                                os.O_WRONLY
                                | os.O_CREAT
                                | os.O_EXCL
                                | getattr(os, "O_CLOEXEC", 0)
                                | getattr(os, "O_NOFOLLOW", 0),
                                int(expected["extracted_mode"], 8),
                                dir_fd=parent,
                            )
                    digest = hashlib.sha256()
                    remaining = expected["size"]
                    try:
                        while remaining:
                            chunk = extracted.read(min(1024 * 1024, remaining))
                            if not chunk:
                                raise ReleaseError("archive_content_mismatch")
                            digest.update(chunk)
                            if output >= 0:
                                written = 0
                                while written < len(chunk):
                                    written += os.write(output, chunk[written:])
                            remaining -= len(chunk)
                        if extracted.read(1):
                            raise ReleaseError("archive_content_mismatch")
                        if digest.hexdigest() != expected["sha256"]:
                            raise ReleaseError("archive_content_mismatch")
                        if output >= 0:
                            os.fchmod(output, int(expected["extracted_mode"], 8))
                            os.fsync(output)
                    finally:
                        if output >= 0:
                            os.close(output)
                comment = bundle.pax_headers.get("comment")
    except ReleaseError:
        raise
    except (OSError, tarfile.TarError, KeyError, TypeError, ValueError) as error:
        raise ReleaseError("archive_invalid") from error
    if comment != manifest.get("source", {}).get("commit"):
        raise ReleaseError("archive_commit_mismatch")
    if observed != set(expected_files) | directories:
        raise ReleaseError("archive_inventory_mismatch")


def _archive_inventory(
    archive: Path,
    manifest: dict[str, Any],
) -> tuple[str, int, list[str]]:
    expected_files, ordered_directories = _validated_manifest_inventory(manifest)
    with _secure_file_spool(Path(archive), maximum=MAX_ARCHIVE_BYTES) as (
        spool,
        archive_digest,
        archive_size,
    ):
        _stream_archive(
            spool,
            manifest,
            expected_files,
            ordered_directories,
        )
    return archive_digest, archive_size, ordered_directories


def verify_extract(archive: Path, source_manifest: Path, destination: Path) -> str:
    manifest, _, _ = load_canonical_manifest(Path(source_manifest), SOURCE_SCHEMA)
    expected_files, directories = _validated_manifest_inventory(manifest)
    destination = Path(destination)
    with _secure_file_spool(Path(archive), maximum=MAX_ARCHIVE_BYTES) as (
        spool,
        digest,
        _archive_size,
    ):
        _stream_archive(spool, manifest, expected_files, directories)
        with _open_bound_parent(destination, "extract_parent_unsafe") as (
            parent,
            name,
            revalidate,
        ):
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError as error:
                raise ReleaseError("extract_failed") from error
            else:
                raise ReleaseError("extract_destination_exists")
            destination_descriptor = -1
            destination_identity: tuple[int, int] | None = None
            success = False
            try:
                revalidate()
                os.mkdir(name, 0o700, dir_fd=parent)
                destination_descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
                linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
                bound = os.fstat(destination_descriptor)
                if (linked.st_dev, linked.st_ino) != (bound.st_dev, bound.st_ino):
                    raise ReleaseError("extract_destination_changed")
                destination_identity = (bound.st_dev, bound.st_ino)
                os.fchmod(destination_descriptor, 0o700)
                for directory in directories:
                    _ensure_relative_directory(destination_descriptor, directory)
                _stream_archive(
                    spool,
                    manifest,
                    expected_files,
                    directories,
                    destination=destination_descriptor,
                )
                os.fsync(destination_descriptor)
                os.fsync(parent)
                revalidate()
                success = True
            except ReleaseError:
                raise
            except OSError as error:
                raise ReleaseError("extract_failed") from error
            finally:
                if destination_descriptor >= 0:
                    os.close(destination_descriptor)
                if destination_identity is not None and not success:
                    _remove_destination(parent, name, destination_identity)
    return digest


def _image_reference_valid(reference: str) -> bool:
    match = IMAGE.fullmatch(reference)
    if match is None:
        return False
    port = match.group("port")
    return port is None or 1 <= int(port) <= 65535


def _image_descriptor(reference: str) -> dict[str, str]:
    if not _image_reference_valid(reference):
        raise ReleaseError("image_reference_invalid")
    return {"reference": reference, "digest": reference.rsplit("@", 1)[1]}


def _decision_receipt(
    path: Path,
    expected: list[tuple[str, str]],
    error_code: str,
) -> dict[str, Any]:
    data = _read_secure(Path(path), maximum=MAX_RECEIPT_BYTES, required_mode=0o600)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReleaseError(error_code) from error
    if not data.endswith(b"\n"):
        raise ReleaseError(error_code)
    lines = text.splitlines()
    expected_names = [name for name, _value in expected] + [
        "issued_at",
        "expires_at",
        "nonce",
    ]
    if len(lines) != len(expected_names) or len(lines) > MAX_RECEIPT_FIELDS:
        raise ReleaseError(error_code)
    values: dict[str, str] = {}
    for expected_name, line in zip(expected_names, lines, strict=True):
        if not line or len(line.encode("ascii")) > MAX_RECEIPT_LINE_BYTES or line.count("=") != 1:
            raise ReleaseError(error_code)
        key, value = line.split("=", 1)
        if (
            key != expected_name
            or key in values
            or not value
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ReleaseError(error_code)
        values[key] = value
    if any(values.get(name) != value for name, value in expected):
        raise ReleaseError(error_code)
    timestamp_pattern = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
    if (
        re.fullmatch(timestamp_pattern, values["issued_at"]) is None
        or re.fullmatch(timestamp_pattern, values["expires_at"]) is None
        or re.fullmatch(r"[0-9a-f]{32}", values["nonce"]) is None
    ):
        raise ReleaseError(error_code)
    try:
        issued_at = datetime.strptime(
            values["issued_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        expires_at = datetime.strptime(
            values["expires_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise ReleaseError(error_code) from error
    now = datetime.now(timezone.utc)
    validity = (expires_at - issued_at).total_seconds()
    if (
        issued_at > now
        or expires_at < now
        or not 0 < validity <= MAX_DECISION_VALIDITY_SECONDS
    ):
        raise ReleaseError(error_code)
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def _base_image_receipt(path: Path, expected: list[str]) -> dict[str, Any]:
    data = _read_secure(Path(path), maximum=MAX_RECEIPT_BYTES, required_mode=0o600)
    try:
        lines = [line for line in data.decode("ascii").splitlines() if line]
    except UnicodeDecodeError as error:
        raise ReleaseError("base_image_receipt_invalid") from error
    observed: dict[str, str] = {}
    for line in lines:
        parts = line.split(" ")
        if len(parts) != 2 or parts[0] in observed or not _image_reference_valid(parts[0]):
            raise ReleaseError("base_image_receipt_invalid")
        if parts[1] != parts[0].rsplit("@", 1)[1]:
            raise ReleaseError("base_image_receipt_invalid")
        observed[parts[0]] = parts[1]
    if set(observed) != set(expected):
        raise ReleaseError("base_image_receipt_invalid")
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def _scan_receipt(path: Path) -> dict[str, Any]:
    data = _read_secure(Path(path), maximum=MAX_RECEIPT_BYTES, required_mode=0o600)
    required = {"core.sbom.json", "runner.sbom.json", "core.grype.json", "runner.grype.json"}
    artifacts: list[dict[str, Any]] = []
    observed: set[str] = set()
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ReleaseError("image_scan_receipt_invalid") from error
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise ReleaseError("image_scan_receipt_invalid")
        source = Path(match.group(2))
        name = source.name
        if name in observed or name not in required or source.resolve().parent != Path(path).resolve().parent:
            raise ReleaseError("image_scan_receipt_invalid")
        artifact = _file_receipt(source)
        if artifact["sha256"] != match.group(1):
            raise ReleaseError("image_scan_receipt_invalid")
        observed.add(name)
        artifacts.append({"name": name, **artifact})
    if observed != required:
        raise ReleaseError("image_scan_receipt_invalid")
    return {
        "receipt_sha256": hashlib.sha256(data).hexdigest(),
        "receipt_size": len(data),
        "artifacts": sorted(artifacts, key=lambda entry: entry["name"]),
    }


def create_runtime_manifest(
    *,
    source_manifest: Path,
    source_archive: Path,
    host_go_receipt: Path,
    core_image: str,
    runner_image: str,
    postgres_image: str,
    python_base_image: str,
    runner_base_image: str,
    base_image_receipt: Path,
    image_scan_hashes: Path,
    output: Path,
    activation_verification_receipt: Path | None = None,
) -> str:
    source, source_digest, source_manifest_size = load_canonical_manifest(
        Path(source_manifest), SOURCE_SCHEMA
    )
    archive_digest, archive_size, _ = _archive_inventory(Path(source_archive), source)
    images = {
        "core": _image_descriptor(core_image),
        "runner": _image_descriptor(runner_image),
        "postgres": _image_descriptor(postgres_image),
        "python_base": _image_descriptor(python_base_image),
        "runner_base": _image_descriptor(runner_base_image),
    }
    base_images = _base_image_receipt(
        Path(base_image_receipt),
        [python_base_image, runner_base_image, postgres_image],
    )
    image_scans = _scan_receipt(Path(image_scan_hashes))
    host_expected = [
            ("schema", "lil-tweak-host-go-receipt-v3" if activation_verification_receipt is not None else "lil-tweak-host-go-receipt-v2"),
            ("decision", "GO"),
            ("source_commit", source["source"]["commit"]),
            ("source_tree", source["source"]["tree"]),
            ("source_manifest_sha256", source_digest),
            ("source_archive_sha256", archive_digest),
            ("core_image", core_image),
            ("runner_image", runner_image),
            ("postgres_image", postgres_image),
            ("python_base_image", python_base_image),
            ("runner_base_image", runner_base_image),
            ("base_image_receipt_sha256", base_images["sha256"]),
            ("image_scan_receipt_sha256", image_scans["receipt_sha256"]),
        ]
    if activation_verification_receipt is not None:
        a = _activation_helper()
        verification = a.read_json(activation_verification_receipt)
        a.validate_verification(verification, source["source"]["commit"], source["source"]["tree"], source_digest, archive_digest)
        host_expected.append(("activation_verification_sha256", hashlib.sha256(a.read_bytes(activation_verification_receipt)).hexdigest()))
    host_go = _decision_receipt(Path(host_go_receipt), host_expected, "host_go_receipt_rejected")
    payload = {
        "schema": RUNTIME_SCHEMA,
        "source": {
            "commit": source["source"]["commit"],
            "tree": source["source"]["tree"],
            "manifest_sha256": source_digest,
            "manifest_size": source_manifest_size,
            "archive_sha256": archive_digest,
            "archive_size": archive_size,
        },
        "images": images,
        "receipts": {
            "host_go": host_go,
            "base_images": base_images,
            "image_scans": image_scans,
        },
    }
    return write_new_manifest(Path(output), payload)


def _parse_state(path: Path) -> dict[str, str]:
    data = _read_secure(Path(path), maximum=MAX_RECEIPT_BYTES, required_mode=0o600)
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ReleaseError("release_state_invalid") from error
    values: dict[str, str] = {}
    for line in lines:
        if not line or "=" not in line:
            raise ReleaseError("release_state_invalid")
        key, value = line.split("=", 1)
        if (
            not STATE_KEY.fullmatch(key)
            or key in values
            or not STATE_VALUE.fullmatch(value)
            or any(word in key for word in ("PASSWORD", "SECRET", "TOKEN", "CREDENTIAL", "REGISTRY_AUTH"))
        ):
            raise ReleaseError("release_state_invalid")
        values[key] = value
    return values


def _required_state(values: dict[str, str], name: str) -> str:
    value = values.get(name)
    if value is None:
        raise ReleaseError("release_state_missing")
    return value


def _https_origin(value: str) -> str:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ReleaseError("origin_invalid") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ReleaseError("origin_invalid")
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port is None else f"{host}:{port}"
    canonical = f"https://{netloc}"
    if value not in {canonical, f"{canonical}/"}:
        raise ReleaseError("origin_invalid")
    return canonical


def _identifier(values: dict[str, str], name: str) -> str:
    value = _required_state(values, name)
    if not IDENTIFIER.fullmatch(value):
        raise ReleaseError("release_state_invalid")
    return value


def _decimal(values: dict[str, str], name: str) -> int:
    value = _required_state(values, name)
    if DECIMAL.fullmatch(value) is None:
        raise ReleaseError("sites_access_rejected")
    return int(value)


def _runtime_size(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _runtime_receipt(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"sha256", "size"}
        and isinstance(value.get("sha256"), str)
        and SHA256.fullmatch(value["sha256"]) is not None
        and _runtime_size(value.get("size"))
    )


def _validated_runtime_manifest(runtime: Any) -> dict[str, Any]:
    if (
        not isinstance(runtime, dict)
        or set(runtime) != {"schema", "source", "images", "receipts"}
        or runtime.get("schema") != RUNTIME_SCHEMA
    ):
        raise ReleaseError("runtime_manifest_mismatch")

    source = runtime.get("source")
    if (
        not isinstance(source, dict)
        or set(source)
        != {
            "commit",
            "tree",
            "manifest_sha256",
            "manifest_size",
            "archive_sha256",
            "archive_size",
        }
        or not isinstance(source.get("commit"), str)
        or COMMIT.fullmatch(source["commit"]) is None
        or not isinstance(source.get("tree"), str)
        or COMMIT.fullmatch(source["tree"]) is None
        or not isinstance(source.get("manifest_sha256"), str)
        or SHA256.fullmatch(source["manifest_sha256"]) is None
        or not _runtime_size(source.get("manifest_size"))
        or not isinstance(source.get("archive_sha256"), str)
        or SHA256.fullmatch(source["archive_sha256"]) is None
        or not _runtime_size(source.get("archive_size"))
    ):
        raise ReleaseError("runtime_manifest_mismatch")

    images = runtime.get("images")
    image_roles = {"core", "runner", "postgres", "python_base", "runner_base"}
    if not isinstance(images, dict) or set(images) != image_roles:
        raise ReleaseError("runtime_manifest_mismatch")
    for descriptor in images.values():
        if (
            not isinstance(descriptor, dict)
            or set(descriptor) != {"reference", "digest"}
            or not isinstance(descriptor.get("reference"), str)
            or not _image_reference_valid(descriptor["reference"])
            or not isinstance(descriptor.get("digest"), str)
            or descriptor["digest"] != descriptor["reference"].rsplit("@", 1)[1]
        ):
            raise ReleaseError("runtime_manifest_mismatch")

    receipts = runtime.get("receipts")
    if (
        not isinstance(receipts, dict)
        or set(receipts) != {"host_go", "base_images", "image_scans"}
        or not _runtime_receipt(receipts.get("host_go"))
        or not _runtime_receipt(receipts.get("base_images"))
    ):
        raise ReleaseError("runtime_manifest_mismatch")
    scans = receipts.get("image_scans")
    if (
        not isinstance(scans, dict)
        or set(scans) != {"receipt_sha256", "receipt_size", "artifacts"}
        or not isinstance(scans.get("receipt_sha256"), str)
        or SHA256.fullmatch(scans["receipt_sha256"]) is None
        or not _runtime_size(scans.get("receipt_size"))
        or not isinstance(scans.get("artifacts"), list)
    ):
        raise ReleaseError("runtime_manifest_mismatch")
    expected_artifacts = [
        "core.grype.json",
        "core.sbom.json",
        "runner.grype.json",
        "runner.sbom.json",
    ]
    artifacts = scans["artifacts"]
    if len(artifacts) != len(expected_artifacts):
        raise ReleaseError("runtime_manifest_mismatch")
    for expected_name, artifact in zip(expected_artifacts, artifacts, strict=True):
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {"name", "sha256", "size"}
            or artifact.get("name") != expected_name
            or not isinstance(artifact.get("sha256"), str)
            or SHA256.fullmatch(artifact["sha256"]) is None
            or not _runtime_size(artifact.get("size"))
        ):
            raise ReleaseError("runtime_manifest_mismatch")
    return runtime


def _activation_helper():
    spec = importlib.util.spec_from_file_location("release_activation", Path(__file__).with_name("lil-tweak-activation-finalizer.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def owner_flow_expected(runtime, runtime_digest, sites, job_digest, deployed_at):
    return [
        ("schema", "lil-tweak-owner-flow-receipt-v3"), ("decision", "PASS"),
        ("runtime_manifest_sha256", runtime_digest), ("source_commit", runtime["source"]["commit"]), ("source_tree", runtime["source"]["tree"]),
        ("sites_version_id", sites["version_id"]), ("sites_version_number", str(sites["version_number"])),
        ("sites_deployment_id", sites["deployment_id"]), ("sites_archive_sha256", sites["archive_sha256"]),
        ("sites_deployed_at", deployed_at), ("owner_flow_job_sha256", job_digest), ("production_url", sites["production_url"]),
    ]


def _owner_job_binding(state):
    a = _activation_helper()
    path = Path(_required_state(state, "OWNER_FLOW_JOB"))
    try:
        job = a.validate_owner_job(a.read_json(path))
        deployed_at = _required_state(state, "SITES_DEPLOYED_AT")
        if not a.timestamp(deployed_at) <= a.timestamp(job["checkedAt"]) <= datetime.now(timezone.utc).timestamp():
            raise ReleaseError("owner_flow_receipt_rejected")
        a.fresh(deployed_at); a.fresh(job["checkedAt"])
    except Exception:
        raise ReleaseError("owner_flow_receipt_rejected") from None
    return job, hashlib.sha256(a.read_bytes(path)).hexdigest(), deployed_at


def create_owner_flow_receipt(runtime_manifest, release_state, owner_flow_job, output):
    runtime, digest, _ = load_canonical_manifest(Path(runtime_manifest), RUNTIME_SCHEMA)
    _validated_runtime_manifest(runtime)
    state = _parse_state(Path(release_state))
    if Path(_required_state(state, "OWNER_FLOW_JOB")) != Path(owner_flow_job):
        raise ReleaseError("owner_flow_receipt_rejected")
    job, job_digest, deployed_at = _owner_job_binding(state)
    if (_required_state(state, "RUNTIME_MANIFEST_SHA256") != digest
        or _required_state(state, "SOURCE_COMMIT") != runtime["source"]["commit"]
        or _required_state(state, "SOURCE_TREE") != runtime["source"]["tree"]
        or _required_state(state, "SITES_SOURCE_COMMIT") != runtime["source"]["commit"]):
        raise ReleaseError("owner_flow_receipt_rejected")
    sites = {"version_id": _identifier(state, "SITES_VERSION_ID"), "version_number": _decimal(state, "SITES_VERSION_NUMBER"),
        "deployment_id": _identifier(state, "SITES_DEPLOYMENT_ID"), "archive_sha256": _required_state(state, "SITES_ARCHIVE_HASH"), "production_url": _https_origin(_required_state(state, "PRODUCTION_URL"))}
    if not SHA256.fullmatch(sites["archive_sha256"]): raise ReleaseError("owner_flow_receipt_rejected")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    if _activation_helper().timestamp(job["checkedAt"]) > now.timestamp(): raise ReleaseError("owner_flow_receipt_rejected")
    values = owner_flow_expected(runtime, digest, sites, job_digest, deployed_at) + [
        ("issued_at", now.strftime("%Y-%m-%dT%H:%M:%SZ")), ("expires_at", (now + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")), ("nonce", secrets.token_hex(16))]
    return _activation_helper().publish(Path(output), raw="".join(k + "=" + v + "\n" for k, v in values).encode("ascii"))


def create_production_manifest(
    runtime_manifest: Path,
    release_state: Path,
    owner_flow_receipt: Path,
    output: Path,
) -> str:
    runtime, runtime_digest, _ = load_canonical_manifest(
        Path(runtime_manifest), RUNTIME_SCHEMA
    )
    _validated_runtime_manifest(runtime)
    state = _parse_state(Path(release_state))
    if Path(_required_state(state, "RUNTIME_MANIFEST")) != Path(runtime_manifest):
        raise ReleaseError("runtime_manifest_mismatch")
    if _required_state(state, "RUNTIME_MANIFEST_SHA256") != runtime_digest:
        raise ReleaseError("runtime_manifest_mismatch")
    source = runtime.get("source")
    if not isinstance(source, dict):
        raise ReleaseError("runtime_manifest_mismatch")
    source_commit = _required_state(state, "SOURCE_COMMIT")
    source_tree = _required_state(state, "SOURCE_TREE")
    if source.get("commit") != source_commit or source.get("tree") != source_tree:
        raise ReleaseError("runtime_manifest_mismatch")
    sites_source = _required_state(state, "SITES_SOURCE_COMMIT")
    if sites_source != source_commit:
        raise ReleaseError("sites_source_mismatch")
    production_url = _https_origin(_required_state(state, "PRODUCTION_URL"))
    if _https_origin(_required_state(state, "PUBLIC_ORIGIN")) != production_url:
        raise ReleaseError("production_origin_mismatch")
    core_origin = _https_origin(_required_state(state, "CORE_ORIGIN"))
    access_mode = _required_state(state, "SITES_ACCESS_MODE")
    owner_count = _decimal(state, "SITES_ALLOWED_OWNER_COUNT")
    group_count = _decimal(state, "SITES_ALLOWED_GROUP_COUNT")
    visitor_count = _decimal(state, "SITES_ALLOWED_VISITOR_COUNT")
    version_number = _decimal(state, "SITES_VERSION_NUMBER")
    prior_version = _decimal(state, "PRIOR_SITES_VERSION_NUMBER")
    if (access_mode, owner_count, group_count, visitor_count) != ("custom", 1, 0, 0):
        raise ReleaseError("sites_access_rejected")
    archive_hash = _required_state(state, "SITES_ARCHIVE_HASH")
    if not SHA256.fullmatch(archive_hash):
        raise ReleaseError("release_state_invalid")
    sites_version_id = _identifier(state, "SITES_VERSION_ID")
    sites_deployment_id = _identifier(state, "SITES_DEPLOYMENT_ID")
    job, owner_flow_job_digest, deployed_at = _owner_job_binding(state)
    owner_flow = _decision_receipt(
        Path(owner_flow_receipt),
        owner_flow_expected(runtime, runtime_digest, {"version_id": sites_version_id, "version_number": version_number,
            "deployment_id": sites_deployment_id, "archive_sha256": archive_hash, "production_url": production_url}, owner_flow_job_digest, deployed_at),
        "owner_flow_receipt_rejected",
    )
    owner_times = dict(line.split("=", 1) for line in _read_secure(Path(owner_flow_receipt), maximum=MAX_RECEIPT_BYTES, required_mode=0o600).decode("ascii").splitlines())
    a = _activation_helper()
    if not a.timestamp(deployed_at) <= a.timestamp(job["checkedAt"]) <= a.timestamp(owner_times["issued_at"]):
        raise ReleaseError("owner_flow_receipt_rejected")
    payload = {
        "schema": PRODUCTION_SCHEMA,
        "runtime": {
            "manifest_sha256": runtime_digest,
            "source_commit": source_commit,
            "source_tree": source_tree,
        },
        "cloudflare": {
            "d1": {
                "database_id": _identifier(state, "D1_DATABASE_ID"),
                "schema_revision": _identifier(state, "D1_SCHEMA_REVISION"),
                "binding_revision": _identifier(state, "D1_BINDING_REVISION"),
            },
            "r2": {
                "account_id": _identifier(state, "R2_ACCOUNT_ID"),
                "bucket_name": _identifier(state, "R2_BUCKET_NAME"),
                "binding_revision": _identifier(state, "R2_BINDING_REVISION"),
            },
            "ingress": {
                "core_origin": core_origin,
                "tunnel_id": _identifier(state, "LIL_TWEAK_TUNNEL_ID"),
                "access_application_id": _identifier(state, "ACCESS_APPLICATION_ID"),
                "access_policy_id": _identifier(state, "ACCESS_POLICY_ID"),
                "access_policy_revision": _identifier(state, "ACCESS_POLICY_REVISION"),
                "managed_rule_id": _identifier(state, "MANAGED_INGRESS_RULE_ID"),
                "managed_rule_revision": _identifier(state, "MANAGED_INGRESS_REVISION"),
            },
        },
        "sites": {
            "source_commit": sites_source,
            "version_id": sites_version_id,
            "version_number": version_number,
            "deployment_id": sites_deployment_id,
            "archive_sha256": archive_hash,
            "environment_revision": _identifier(state, "SITES_ENVIRONMENT_REVISION"),
            "access_revision": _identifier(state, "SITES_ACCESS_REVISION"),
            "access_mode": access_mode,
            "allowed_owner_count": owner_count,
            "allowed_group_count": group_count,
            "allowed_visitor_count": visitor_count,
            "production_url": production_url,
            "prior_version_number": prior_version,
        },
        "owner_flow_receipt": owner_flow,
        "owner_flow_job_sha256": owner_flow_job_digest,
    }
    return write_new_manifest(Path(output), payload)


def verify_runtime_install(
    *,
    runtime_manifest: Path,
    runtime_manifest_sha256: str,
    source_manifest: Path,
    source_dir: Path,
    rollback_manifest: Path,
    rollback_manifest_sha256: str,
    core_image: str,
    postgres_image: str,
    runner_image: str,
) -> None:
    if (
        SHA256.fullmatch(runtime_manifest_sha256) is None
        or SHA256.fullmatch(rollback_manifest_sha256) is None
    ):
        raise ReleaseError("runtime_install_rejected")
    runtime, observed_runtime_digest, _runtime_size = load_canonical_manifest(
        Path(runtime_manifest), RUNTIME_SCHEMA
    )
    if observed_runtime_digest != runtime_manifest_sha256:
        raise ReleaseError("runtime_install_rejected")
    _validated_runtime_manifest(runtime)
    supplied_images = {
        "core": core_image,
        "postgres": postgres_image,
        "runner": runner_image,
    }
    if any(not _image_reference_valid(reference) for reference in supplied_images.values()):
        raise ReleaseError("runtime_install_rejected")
    if any(
        runtime["images"][role]["reference"] != reference
        for role, reference in supplied_images.items()
    ):
        raise ReleaseError("runtime_install_rejected")

    source, source_digest, source_size = load_canonical_manifest(
        Path(source_manifest), SOURCE_SCHEMA
    )
    source_identity = source.get("source")
    if (
        source_digest != runtime["source"]["manifest_sha256"]
        or source_size != runtime["source"]["manifest_size"]
        or not isinstance(source_identity, dict)
        or set(source_identity) != {"commit", "tree"}
        or not isinstance(source_identity.get("commit"), str)
        or COMMIT.fullmatch(source_identity["commit"]) is None
        or not isinstance(source_identity.get("tree"), str)
        or COMMIT.fullmatch(source_identity["tree"]) is None
        or source_identity["commit"] != runtime["source"]["commit"]
        or source_identity["tree"] != runtime["source"]["tree"]
    ):
        raise ReleaseError("runtime_install_rejected")
    _verify_source_directory(Path(source_dir), source)

    rollback_data = _read_secure(
        Path(rollback_manifest),
        maximum=MAX_MANIFEST_BYTES,
        required_mode=0o600,
    )
    if hashlib.sha256(rollback_data).hexdigest() != rollback_manifest_sha256:
        raise ReleaseError("runtime_install_rejected")
    rollback = _strict_json(rollback_data)
    rollback_keys = {
        "schema",
        "hostname",
        "captured_at",
        "captured_at_iso",
        "source_commit",
        "source_prefix",
        "identities",
        "managed_paths",
        "units",
        "podman_objects",
        "image_references",
        "listeners",
        "linger",
    }
    if (
        not isinstance(rollback, dict)
        or set(rollback) != rollback_keys
        or rollback.get("schema") != "lil-tweak-rollback-receipt-v1"
        or canonical_json_bytes(rollback) != rollback_data
        or not isinstance(rollback.get("source_commit"), str)
        or COMMIT.fullmatch(rollback["source_commit"]) is None
        or rollback.get("source_prefix") != rollback["source_commit"][:12]
        or rollback["source_commit"] != runtime["source"]["commit"]
    ):
        raise ReleaseError("runtime_install_rejected")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lil-tweak-release.py")
    subcommands = parser.add_subparsers(dest="command", required=True)
    source = subcommands.add_parser("source-manifest")
    source.add_argument("--repo", type=Path, required=True)
    source.add_argument("--base", required=True)
    source.add_argument("--commit", required=True)
    source.add_argument("--verification-receipt", type=Path, required=True)
    source.add_argument("--preserve", type=Path, action="append", default=[])
    source.add_argument("--output", type=Path, required=True)
    extract = subcommands.add_parser("verify-extract")
    extract.add_argument("--archive", type=Path, required=True)
    extract.add_argument("--source-manifest", type=Path, required=True)
    extract.add_argument("--destination", type=Path, required=True)
    runtime = subcommands.add_parser("runtime-manifest")
    for argument in (
        "source-manifest",
        "source-archive",
        "host-go-receipt",
        "base-image-receipt",
        "image-scan-hashes",
        "output",
    ):
        runtime.add_argument(f"--{argument}", type=Path, required=True)
    for argument in ("core-image", "runner-image", "postgres-image", "python-base-image", "runner-base-image"):
        runtime.add_argument(f"--{argument}", required=True)
    runtime.add_argument("--activation-verification-receipt", type=Path)
    production = subcommands.add_parser("production-manifest")
    production.add_argument("--runtime-manifest", type=Path, required=True)
    production.add_argument("--release-state", type=Path, required=True)
    production.add_argument("--owner-flow-receipt", type=Path, required=True)
    production.add_argument("--output", type=Path, required=True)
    owner_flow = subcommands.add_parser("owner-flow-receipt")
    for name in ("runtime-manifest", "release-state", "owner-flow-job", "output"):
        owner_flow.add_argument("--" + name, type=Path, required=True)
    verify_runtime = subcommands.add_parser("verify-runtime-install")
    verify_runtime.add_argument("--runtime-manifest", type=Path, required=True)
    verify_runtime.add_argument("--runtime-manifest-sha256", required=True)
    verify_runtime.add_argument("--source-manifest", type=Path, required=True)
    verify_runtime.add_argument("--source-dir", type=Path, required=True)
    verify_runtime.add_argument("--rollback-manifest", type=Path, required=True)
    verify_runtime.add_argument("--rollback-manifest-sha256", required=True)
    verify_runtime.add_argument("--core-image", required=True)
    verify_runtime.add_argument("--postgres-image", required=True)
    verify_runtime.add_argument("--runner-image", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "source-manifest":
            digest = create_source_manifest(
                repo=arguments.repo,
                base=arguments.base,
                commit=arguments.commit,
                verification_receipt=arguments.verification_receipt,
                preserves=arguments.preserve,
                output=arguments.output,
            )
        elif arguments.command == "verify-extract":
            digest = verify_extract(arguments.archive, arguments.source_manifest, arguments.destination)
        elif arguments.command == "runtime-manifest":
            digest = create_runtime_manifest(
                source_manifest=arguments.source_manifest,
                source_archive=arguments.source_archive,
                host_go_receipt=arguments.host_go_receipt,
                core_image=arguments.core_image,
                runner_image=arguments.runner_image,
                postgres_image=arguments.postgres_image,
                python_base_image=arguments.python_base_image,
                runner_base_image=arguments.runner_base_image,
                base_image_receipt=arguments.base_image_receipt,
                image_scan_hashes=arguments.image_scan_hashes,
                activation_verification_receipt=arguments.activation_verification_receipt,
                output=arguments.output,
            )
        elif arguments.command == "production-manifest":
            digest = create_production_manifest(
                arguments.runtime_manifest,
                arguments.release_state,
                arguments.owner_flow_receipt,
                arguments.output,
            )
        elif arguments.command == "owner-flow-receipt":
            digest = create_owner_flow_receipt(arguments.runtime_manifest, arguments.release_state, arguments.owner_flow_job, arguments.output)
        else:
            verify_runtime_install(
                runtime_manifest=arguments.runtime_manifest,
                runtime_manifest_sha256=arguments.runtime_manifest_sha256,
                source_manifest=arguments.source_manifest,
                source_dir=arguments.source_dir,
                rollback_manifest=arguments.rollback_manifest,
                rollback_manifest_sha256=arguments.rollback_manifest_sha256,
                core_image=arguments.core_image,
                postgres_image=arguments.postgres_image,
                runner_image=arguments.runner_image,
            )
            return 0
    except ReleaseError as error:
        if arguments.command == "verify-runtime-install":
            return 1
        print(f"lil-tweak-release: {error.code}", file=sys.stderr)
        return 1
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
