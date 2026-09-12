#!/usr/bin/env python3
"""Validate and freeze Lil Tweak installer secrets before host mutation."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from collections.abc import Sequence
from urllib.parse import urlsplit


CORE_ENV_NAME = "core.env"
ADMIN_PASSWORD_NAME = "postgres-admin-password"
APP_PASSWORD_NAME = "postgres-app-password"
MIGRATOR_PASSWORD_NAME = "postgres-migrator-password"
SECRET_NAMES = (
    CORE_ENV_NAME,
    ADMIN_PASSWORD_NAME,
    APP_PASSWORD_NAME,
    MIGRATOR_PASSWORD_NAME,
)
CORE_ENV_MAX_BYTES = 65_536
PASSWORD_MIN_BYTES = 33
PASSWORD_MAX_BYTES = 129
REQUIRED_CORE_KEYS = frozenset(
    {
        "LIL_TWEAK_DATABASE_URL",
        "LIL_TWEAK_SIGNING_KEYS_JSON",
        "LIL_TWEAK_CANONICAL_OWNER_ID",
        "OPENAI_API_KEY",
        "LIL_TWEAK_OPENAI_MODEL",
        "LIL_TWEAK_RUNNER_IMAGE",
        "LIL_TWEAK_EXECUTION_BACKEND",
        "LIL_TWEAK_WORK_ROOT",
        "LIL_TWEAK_WORK_ROOT_INODES",
        "LIL_TWEAK_MAX_ADMITTED_JOBS",
        "LIL_TWEAK_JOB_TIMEOUT_SECONDS",
        "LIL_TWEAK_EVIDENCE_BUCKET",
        "LIL_TWEAK_EVIDENCE_ENDPOINT",
        "LIL_TWEAK_R2_ACCESS_KEY_ID",
        "LIL_TWEAK_R2_SECRET_ACCESS_KEY",
    }
)
OPTIONAL_CORE_KEYS = frozenset(
    {
        "LIL_TWEAK_GIT_ALLOWED_HOSTS",
        "LIL_TWEAK_GITHUB_REPOSITORY",
        "LIL_TWEAK_GITHUB_TOKEN",
    }
)
ALLOWED_CORE_KEYS = REQUIRED_CORE_KEYS | OPTIONAL_CORE_KEYS
CANONICAL_OWNER_SCOPE = "ab43c7488fb38a90c7bb9c4bcc0e23e5"
IMAGE_PATTERN = re.compile(
    r"(?P<registry>[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)"
    r"(?::(?P<port>[1-9][0-9]{0,4}))?/"
    r"(?P<repository>(?:[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*)"
    r"@sha256:[0-9a-f]{64}\Z"
)
DATABASE_PATTERN = re.compile(
    r"postgresql://lil_tweak_app:([A-Za-z0-9_-]{32,128})"
    r"@lil-tweak-postgres:5432/lil_tweak\Z"
)
PASSWORD_PATTERN = re.compile(rb"[A-Za-z0-9_-]{32,128}\n\Z")
ASSIGNMENT_PATTERN = re.compile(r"([A-Z][A-Z0-9_]*)=(.+)\Z")
SIGNING_KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
GITHUB_REPOSITORY_COMPONENT_PATTERN = re.compile(r"[A-Za-z0-9_.-]+\Z")
STABLE_FIELDS = (
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
DIRECTORY_STABLE_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_uid",
    "st_gid",
    "st_mtime_ns",
    "st_ctime_ns",
)


class SnapshotError(Exception):
    """A deliberately non-disclosing validation error."""


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _input_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _output_flags() -> int:
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _same_metadata(before: os.stat_result, after: os.stat_result, fields: Sequence[str]) -> bool:
    return all(getattr(before, field) == getattr(after, field) for field in fields)


def _canonical_absolute_components(path: str) -> tuple[str, ...]:
    if not path.startswith("/") or path.startswith("//") or "\x00" in path:
        raise SnapshotError
    if path != "/" and path.endswith("/"):
        raise SnapshotError
    components = tuple(path[1:].split("/")) if path != "/" else ()
    if any(component in {"", ".", ".."} for component in components):
        raise SnapshotError
    return components


def _open_directory(path: str) -> tuple[int, os.stat_result]:
    components = _canonical_absolute_components(path)
    current = os.open("/", _directory_flags())
    try:
        for component in components:
            following = os.open(component, _directory_flags(), dir_fd=current)
            os.close(current)
            current = following
        metadata = os.fstat(current)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise SnapshotError
        return current, metadata
    except BaseException:
        os.close(current)
        raise


def _read_stable_file(
    directory_fd: int,
    name: str,
    minimum_size: int,
    maximum_size: int,
    expected_identity: tuple[int, int] | None = None,
) -> bytes:
    descriptor = os.open(name, _input_flags(), dir_fd=directory_fd)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size < minimum_size
            or before.st_size > maximum_size
            or (
                expected_identity is not None
                and (before.st_dev, before.st_ino) != expected_identity
            )
        ):
            raise SnapshotError

        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise SnapshotError
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) != b"":
            raise SnapshotError
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(data) != before.st_size or not _same_metadata(before, after, STABLE_FIELDS):
            raise SnapshotError
        return data
    finally:
        os.close(descriptor)


def _contains_noncharacter(value: str) -> bool:
    return any(
        0xFDD0 <= ord(character) <= 0xFDEF
        or (ord(character) & 0xFFFF) in {0xFFFE, 0xFFFF}
        for character in value
    )


def _parse_core_environment(data: bytes, app_password: str) -> str:
    if not data.endswith(b"\n") or data.endswith(b"\n\n"):
        raise SnapshotError
    text = data.decode("utf-8", errors="strict")
    if "\ufeff" in text or _contains_noncharacter(text):
        raise SnapshotError
    if "CHANGE_ME" in text:
        raise SnapshotError

    values: dict[str, str] = {}
    for line in text[:-1].split("\n"):
        if "\\" in line or any(ord(character) < 32 or ord(character) == 127 for character in line):
            raise SnapshotError
        if line == "" or line.startswith("#"):
            continue
        match = ASSIGNMENT_PATTERN.fullmatch(line)
        if match is None:
            raise SnapshotError
        name, value = match.groups()
        if (
            name in values
            or value[0] in {"'", '"'}
            or value[0] in {" ", "\t"}
            or value[-1] in {" ", "\t"}
        ):
            raise SnapshotError
        values[name] = value

    if not REQUIRED_CORE_KEYS.issubset(values) or not set(values).issubset(ALLOWED_CORE_KEYS):
        raise SnapshotError
    if "LIL_TWEAK_GALOR_READONLY_URL" in values:
        raise SnapshotError

    runner_image = values["LIL_TWEAK_RUNNER_IMAGE"]
    if not _valid_image_reference(runner_image):
        raise SnapshotError
    if values["LIL_TWEAK_WORK_ROOT"] != "/var/lib/lil-tweak/work":
        raise SnapshotError
    if values["LIL_TWEAK_WORK_ROOT_INODES"] != "204800":
        raise SnapshotError
    if values["LIL_TWEAK_MAX_ADMITTED_JOBS"] != "1":
        raise SnapshotError
    if values["LIL_TWEAK_JOB_TIMEOUT_SECONDS"] != "1200":
        raise SnapshotError
    if values["LIL_TWEAK_CANONICAL_OWNER_ID"] != CANONICAL_OWNER_SCOPE:
        raise SnapshotError
    if not _valid_signing_keys(values["LIL_TWEAK_SIGNING_KEYS_JSON"]):
        raise SnapshotError
    if not _valid_https_endpoint(values["LIL_TWEAK_EVIDENCE_ENDPOINT"]):
        raise SnapshotError
    if "LIL_TWEAK_GIT_ALLOWED_HOSTS" in values and not _valid_git_hosts(
        values["LIL_TWEAK_GIT_ALLOWED_HOSTS"]
    ):
        raise SnapshotError
    backend = values["LIL_TWEAK_EXECUTION_BACKEND"]
    repository = values.get("LIL_TWEAK_GITHUB_REPOSITORY")
    token = values.get("LIL_TWEAK_GITHUB_TOKEN")
    if backend == "github_actions":
        if (
            repository is None
            or not _valid_github_repository(repository)
            or token is None
            or len(token.encode("utf-8")) < 32
        ):
            raise SnapshotError
    elif backend != "local_podman" or repository is not None or token is not None:
        raise SnapshotError
    database = DATABASE_PATTERN.fullmatch(values["LIL_TWEAK_DATABASE_URL"])
    if database is None or database.group(1) != app_password:
        raise SnapshotError
    return runner_image


def _validate_password(data: bytes) -> str:
    if PASSWORD_PATTERN.fullmatch(data) is None:
        raise SnapshotError
    return data[:-1].decode("ascii")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotError
        result[key] = value
    return result


def _valid_signing_keys(value: str) -> bool:
    try:
        document = json.loads(value, object_pairs_hook=_unique_json_object)
    except (json.JSONDecodeError, SnapshotError):
        return False
    return (
        isinstance(document, dict)
        and bool(document)
        and all(
            isinstance(key, str)
            and SIGNING_KEY_ID_PATTERN.fullmatch(key) is not None
            and isinstance(secret, str)
            and len(secret.encode("utf-8")) >= 32
            for key, secret in document.items()
        )
    )


def _valid_image_reference(value: str) -> bool:
    match = IMAGE_PATTERN.fullmatch(value)
    if match is None:
        return False
    port = match.group("port")
    return port is None or 1 <= int(port) <= 65_535


def _valid_https_endpoint(value: str) -> bool:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or (port is not None and not 1 <= port <= 65_535)
    ):
        return False
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port is None else f"{host}:{port}"
    canonical = f"https://{netloc}"
    return value in {canonical, f"{canonical}/"}


def _valid_git_hosts(value: str) -> bool:
    hosts = tuple(item.strip().lower() for item in value.split(",") if item.strip())
    return all(
        re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host) is not None
        and not host.startswith(".")
        and not host.endswith(".")
        for host in hosts
    )


def _valid_github_repository(value: str) -> bool:
    components = value.split("/")
    return (
        len(components) == 2
        and all(component not in {".", ".."} for component in components)
        and all(
            GITHUB_REPOSITORY_COMPONENT_PATTERN.fullmatch(component)
            for component in components
        )
    )


def _write_all(descriptor: int, data: bytes) -> None:
    written = 0
    while written < len(data):
        count = os.write(descriptor, data[written:])
        if count <= 0:
            raise SnapshotError
        written += count


def _write_snapshot(
    directory_fd: int,
    name: str,
    data: bytes,
    created: dict[str, tuple[int, int]],
) -> None:
    descriptor = os.open(name, _output_flags(), 0o600, dir_fd=directory_fd)
    try:
        opened = os.fstat(descriptor)
        created[name] = (opened.st_dev, opened.st_ino)
        os.fchmod(descriptor, 0o600)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size != 0
            or before.st_dev != opened.st_dev
            or before.st_ino != opened.st_ino
        ):
            raise SnapshotError
        _write_all(descriptor, data)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_uid != os.geteuid()
            or stat.S_IMODE(after.st_mode) != 0o600
            or after.st_nlink != 1
            or after.st_size != len(data)
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_uid != after.st_uid
            or before.st_gid != after.st_gid
        ):
            raise SnapshotError
    finally:
        os.close(descriptor)


def _remove_created(directory_fd: int, created: dict[str, tuple[int, int]]) -> None:
    cleanup_failed = False
    for name, identity in reversed(tuple(created.items())):
        descriptor: int | None = None
        try:
            descriptor = os.open(name, _input_flags(), dir_fd=directory_fd)
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) != identity:
                cleanup_failed = True
                continue
            os.close(descriptor)
            descriptor = None
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            continue
        except OSError:
            cleanup_failed = True
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    cleanup_failed = True
    try:
        os.fsync(directory_fd)
    except OSError:
        cleanup_failed = True
    try:
        if any(name in created for name in os.listdir(directory_fd)):
            cleanup_failed = True
    except OSError:
        cleanup_failed = True
    if cleanup_failed:
        raise SnapshotError("snapshot_cleanup_failed")


def snapshot_secrets(source: str, destination: str) -> str:
    source_fd, source_before = _open_directory(source)
    try:
        destination_fd, destination_before = _open_directory(destination)
        try:
            if (source_before.st_dev, source_before.st_ino) == (
                destination_before.st_dev,
                destination_before.st_ino,
            ):
                raise SnapshotError
            if os.listdir(destination_fd):
                raise SnapshotError

            data = {
                CORE_ENV_NAME: _read_stable_file(source_fd, CORE_ENV_NAME, 1, CORE_ENV_MAX_BYTES),
                ADMIN_PASSWORD_NAME: _read_stable_file(
                    source_fd, ADMIN_PASSWORD_NAME, PASSWORD_MIN_BYTES, PASSWORD_MAX_BYTES
                ),
                APP_PASSWORD_NAME: _read_stable_file(
                    source_fd, APP_PASSWORD_NAME, PASSWORD_MIN_BYTES, PASSWORD_MAX_BYTES
                ),
                MIGRATOR_PASSWORD_NAME: _read_stable_file(
                    source_fd, MIGRATOR_PASSWORD_NAME, PASSWORD_MIN_BYTES, PASSWORD_MAX_BYTES
                ),
            }
            admin_password = _validate_password(data[ADMIN_PASSWORD_NAME])
            app_password = _validate_password(data[APP_PASSWORD_NAME])
            migrator_password = _validate_password(data[MIGRATOR_PASSWORD_NAME])
            if (
                not admin_password
                or not migrator_password
                or len({admin_password, app_password, migrator_password}) != 3
            ):
                raise SnapshotError
            runner_image = _parse_core_environment(data[CORE_ENV_NAME], app_password)

            source_after = os.fstat(source_fd)
            destination_after_reads = os.fstat(destination_fd)
            if not _same_metadata(source_before, source_after, DIRECTORY_STABLE_FIELDS):
                raise SnapshotError
            if not _same_metadata(
                destination_before, destination_after_reads, DIRECTORY_STABLE_FIELDS
            ):
                raise SnapshotError
            if os.listdir(destination_fd):
                raise SnapshotError

            created: dict[str, tuple[int, int]] = {}
            try:
                for name in SECRET_NAMES:
                    _write_snapshot(destination_fd, name, data[name], created)
                os.fsync(destination_fd)
                if set(os.listdir(destination_fd)) != set(SECRET_NAMES):
                    raise SnapshotError
                destination_final = os.fstat(destination_fd)
                if (
                    destination_final.st_dev != destination_before.st_dev
                    or destination_final.st_ino != destination_before.st_ino
                    or destination_final.st_uid != os.geteuid()
                    or stat.S_IMODE(destination_final.st_mode) != 0o700
                ):
                    raise SnapshotError
                for name in SECRET_NAMES:
                    frozen = _read_stable_file(
                        destination_fd,
                        name,
                        len(data[name]),
                        len(data[name]),
                        expected_identity=created[name],
                    )
                    if frozen != data[name]:
                        raise SnapshotError
            except BaseException:
                _remove_created(destination_fd, created)
                raise
            return runner_image
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lil-tweak-secret-snapshot.py")
    subparsers = parser.add_subparsers(dest="command", required=True)
    snapshot = subparsers.add_parser("snapshot")
    snapshot.add_argument("--source", required=True)
    snapshot.add_argument("--destination", required=True)
    images = subparsers.add_parser("validate-images")
    images.add_argument("--image", action="append", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--check"]:
        print("lil-tweak-secret-snapshot check: ok")
        return 0
    try:
        namespace = _parser().parse_args(arguments)
        if namespace.command == "validate-images":
            if not 1 <= len(namespace.image) <= 3 or any(
                not _valid_image_reference(reference) for reference in namespace.image
            ):
                raise SnapshotError
            return 0
        if namespace.command != "snapshot":
            raise SnapshotError
        runner_image = snapshot_secrets(namespace.source, namespace.destination)
    except Exception:
        print("lil-tweak-secret-snapshot: invalid secret inputs", file=sys.stderr)
        return 1
    print(runner_image)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
