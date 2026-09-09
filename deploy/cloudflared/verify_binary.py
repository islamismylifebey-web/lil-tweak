#!/usr/bin/python3
"""Verify the fixed cloudflared binary without trusting mutable path lookups."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from collections.abc import Callable, Sequence
from pathlib import Path


CLOUDFLARED_COMPONENTS = ("usr", "bin", "cloudflared")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_BINARY_BYTES = 256 * 1024 * 1024
READ_BYTES = 1024 * 1024
FILE_STABLE_FIELDS = (
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
DIRECTORY_STABLE_FIELDS = FILE_STABLE_FIELDS


class BinaryVerificationError(ValueError):
    pass


def _required_open_flags() -> tuple[int, int]:
    required = ("O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK", "O_DIRECTORY")
    if any(not hasattr(os, name) for name in required):
        raise BinaryVerificationError
    common = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    return common | os.O_DIRECTORY, common


def _same_fields(
    left: os.stat_result,
    right: os.stat_result,
    fields: Sequence[str],
) -> bool:
    return all(getattr(left, field) == getattr(right, field) for field in fields)


def _secure_directory(
    value: os.stat_result,
    *,
    expected_uid: int,
    expected_gid: int,
) -> bool:
    return (
        stat.S_ISDIR(value.st_mode)
        and value.st_uid == expected_uid
        and value.st_gid == expected_gid
        and value.st_nlink >= 1
        and stat.S_IMODE(value.st_mode) & 0o022 == 0
    )


def _entry_status(parent_fd: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)


def _hash_descriptor(descriptor: int, size: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = os.read(descriptor, min(remaining, READ_BYTES))
        if not chunk:
            raise BinaryVerificationError
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise BinaryVerificationError
    return digest.hexdigest()


def _open_verified_under_anchor(
    anchor: Path,
    components: Sequence[str],
    expected_sha256: str,
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
    _test_hook: Callable[[str], None] | None = None,
) -> int:
    """Return a verified executable fd; the production CLI fixes anchor/path."""

    if (
        DIGEST.fullmatch(expected_sha256) is None
        or not components
        or any(
            not isinstance(component, str)
            or not component
            or component in {".", ".."}
            or "/" in component
            or "\x00" in component
            for component in components
        )
        or type(expected_uid) is not int
        or type(expected_gid) is not int
        or expected_uid < 0
        or expected_gid < 0
    ):
        raise BinaryVerificationError

    directory_flags, file_flags = _required_open_flags()
    descriptors: list[int] = []
    directory_bindings: list[
        tuple[int | None, str | None, int, os.stat_result]
    ] = []
    try:
        linked_anchor = anchor.lstat()
        anchor_fd = os.open(anchor, directory_flags)
        descriptors.append(anchor_fd)
        anchor_status = os.fstat(anchor_fd)
        if (
            not _secure_directory(
                anchor_status,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
            or not _same_fields(
                linked_anchor, anchor_status, DIRECTORY_STABLE_FIELDS
            )
        ):
            raise BinaryVerificationError
        directory_bindings.append((None, None, anchor_fd, anchor_status))

        parent_fd = anchor_fd
        for component in components[:-1]:
            linked = _entry_status(parent_fd, component)
            descriptor = os.open(component, directory_flags, dir_fd=parent_fd)
            descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            if (
                not _secure_directory(
                    opened,
                    expected_uid=expected_uid,
                    expected_gid=expected_gid,
                )
                or not _same_fields(linked, opened, DIRECTORY_STABLE_FIELDS)
            ):
                raise BinaryVerificationError
            directory_bindings.append((parent_fd, component, descriptor, opened))
            parent_fd = descriptor

        binary_name = components[-1]
        linked_binary = _entry_status(parent_fd, binary_name)
        binary_fd = os.open(binary_name, file_flags, dir_fd=parent_fd)
        descriptors.append(binary_fd)
        before = os.fstat(binary_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_gid != expected_gid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o755
            or not 1 <= before.st_size <= MAX_BINARY_BYTES
            or not _same_fields(linked_binary, before, FILE_STABLE_FIELDS)
        ):
            raise BinaryVerificationError

        initial_digest = _hash_descriptor(binary_fd, before.st_size)

        if _test_hook is not None:
            _test_hook("after_hash")

        verified_digest = _hash_descriptor(binary_fd, before.st_size)
        after = os.fstat(binary_fd)
        linked_after = _entry_status(parent_fd, binary_name)
        if (
            not _same_fields(before, after, FILE_STABLE_FIELDS)
            or not _same_fields(linked_after, after, FILE_STABLE_FIELDS)
            or initial_digest != expected_sha256
            or verified_digest != expected_sha256
        ):
            raise BinaryVerificationError

        for bound_parent, name, descriptor, original in reversed(directory_bindings):
            current = os.fstat(descriptor)
            if not _same_fields(original, current, DIRECTORY_STABLE_FIELDS):
                raise BinaryVerificationError
            if bound_parent is not None and name is not None:
                linked_current = _entry_status(bound_parent, name)
                if not _same_fields(
                    linked_current, current, DIRECTORY_STABLE_FIELDS
                ):
                    raise BinaryVerificationError
        descriptors.remove(binary_fd)
        return binary_fd
    except BinaryVerificationError:
        raise
    except (OSError, TypeError, ValueError) as error:
        raise BinaryVerificationError from error
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _verify_under_anchor(
    anchor: Path,
    components: Sequence[str],
    expected_sha256: str,
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
    _test_hook: Callable[[str], None] | None = None,
) -> None:
    descriptor = _open_verified_under_anchor(
        anchor,
        components,
        expected_sha256,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        _test_hook=_test_hook,
    )
    os.close(descriptor)


def _validate_arguments(arguments: Sequence[str]) -> list[str]:
    values = list(arguments)
    if (
        not 1 <= len(values) <= 64
        or any(
            not isinstance(value, str)
            or not value
            or "\x00" in value
            or len(value.encode("utf-8")) > 4096
            for value in values
        )
        or sum(len(value.encode("utf-8")) for value in values) > 65_536
    ):
        raise BinaryVerificationError
    return values


def _execute_under_anchor(
    anchor: Path,
    components: Sequence[str],
    expected_sha256: str,
    arguments: Sequence[str],
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
    _before_exec_hook: Callable[[], None] | None = None,
) -> None:
    values = _validate_arguments(arguments)
    descriptor = _open_verified_under_anchor(
        anchor,
        components,
        expected_sha256,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    try:
        if _before_exec_hook is not None:
            _before_exec_hook()
        os.execve(
            descriptor,
            ["/usr/bin/cloudflared", *values],
            dict(os.environ),
        )
        raise BinaryVerificationError
    finally:
        os.close(descriptor)


def verify_cloudflared(expected_sha256: str) -> None:
    _verify_under_anchor(
        Path("/"),
        CLOUDFLARED_COMPONENTS,
        expected_sha256,
        expected_uid=0,
        expected_gid=0,
    )


def execute_cloudflared(expected_sha256: str, arguments: Sequence[str]) -> None:
    _execute_under_anchor(
        Path("/"),
        CLOUDFLARED_COMPONENTS,
        expected_sha256,
        arguments,
        expected_uid=0,
        expected_gid=0,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="verify_binary.py")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--expected-sha256")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("cloudflared_arguments", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        if arguments.check:
            if arguments.execute or arguments.cloudflared_arguments:
                raise BinaryVerificationError
            _required_open_flags()
            if os.execve not in os.supports_fd:
                raise BinaryVerificationError
            return 0
        values = arguments.cloudflared_arguments
        if values[:1] == ["--"]:
            values = values[1:]
        if arguments.execute:
            execute_cloudflared(arguments.expected_sha256, values)
        elif values:
            raise BinaryVerificationError
        else:
            verify_cloudflared(arguments.expected_sha256)
    except (BinaryVerificationError, OSError, TypeError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
