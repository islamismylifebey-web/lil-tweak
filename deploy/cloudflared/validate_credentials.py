"""Validate and freeze a locally managed Tunnel credential without printing it."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path


UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
ACCOUNT = re.compile(r"^[0-9a-f]{32}$")
MAX_CREDENTIAL_BYTES = 16_384
STABLE_FIELDS = (
    "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
    "st_size", "st_mtime_ns", "st_ctime_ns",
)


class CredentialError(ValueError):
    pass


def _strict_json(data: bytes) -> object:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise CredentialError
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise CredentialError

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except CredentialError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CredentialError from error


def _read_private_regular(path: Path) -> tuple[bytes, os.stat_result]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = -1
    try:
        linked_before = path.lstat()
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= MAX_CREDENTIAL_BYTES
            or (linked_before.st_dev, linked_before.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            raise CredentialError
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise CredentialError
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CredentialError
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        linked_after = path.lstat()
        if (
            any(getattr(before, field) != getattr(after, field) for field in STABLE_FIELDS)
            or (linked_after.st_dev, linked_after.st_ino, linked_after.st_mode, linked_after.st_nlink)
            != (after.st_dev, after.st_ino, after.st_mode, after.st_nlink)
        ):
            raise CredentialError
        return data, after
    except CredentialError:
        raise
    except OSError as error:
        raise CredentialError from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validate_document(data: bytes, tunnel_id: str) -> None:
    payload = _strict_json(data)
    if not isinstance(payload, dict) or set(payload) != {
        "AccountTag", "TunnelSecret", "TunnelID",
    }:
        raise CredentialError
    account = payload["AccountTag"]
    secret = payload["TunnelSecret"]
    observed_tunnel = payload["TunnelID"]
    if (
        not isinstance(account, str)
        or ACCOUNT.fullmatch(account) is None
        or not isinstance(observed_tunnel, str)
        or observed_tunnel != tunnel_id
        or not isinstance(secret, str)
        or not 1 <= len(secret.encode("utf-8")) <= 4096
        or secret != secret.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in secret)
    ):
        raise CredentialError


def _write_snapshot(path: Path, data: bytes, source: os.stat_result) -> None:
    flags = (
        os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = -1
    write_started = False
    try:
        linked_before = path.lstat()
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size != 0
            or (linked_before.st_dev, linked_before.st_ino)
            != (before.st_dev, before.st_ino)
            or (before.st_dev, before.st_ino) == (source.st_dev, source.st_ino)
        ):
            raise CredentialError
        write_started = True
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise CredentialError
            written += count
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        linked_after = path.lstat()
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or after.st_uid != os.geteuid()
            or stat.S_IMODE(after.st_mode) != 0o600
            or after.st_size != len(data)
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or (linked_after.st_dev, linked_after.st_ino, linked_after.st_mode, linked_after.st_nlink)
            != (after.st_dev, after.st_ino, after.st_mode, after.st_nlink)
        ):
            raise CredentialError
    except (CredentialError, OSError) as error:
        if write_started and descriptor >= 0:
            try:
                current = os.fstat(descriptor)
                linked = path.lstat()
                if (
                    not stat.S_ISREG(current.st_mode)
                    or (current.st_dev, current.st_ino)
                    != (before.st_dev, before.st_ino)
                    or (linked.st_dev, linked.st_ino)
                    != (before.st_dev, before.st_ino)
                ):
                    raise OSError("snapshot identity changed")
                os.ftruncate(descriptor, 0)
                os.fsync(descriptor)
                cleared = os.fstat(descriptor)
                if cleared.st_size != 0:
                    raise OSError("snapshot cleanup incomplete")
            except OSError as cleanup_error:
                raise CredentialError("snapshot_cleanup_failed") from cleanup_error
        raise CredentialError from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def validate_and_snapshot(source: Path, tunnel_id: str, snapshot: Path) -> None:
    if UUID.fullmatch(tunnel_id) is None:
        raise CredentialError
    data, source_status = _read_private_regular(Path(source))
    _validate_document(data, tunnel_id)
    _write_snapshot(Path(snapshot), data, source_status)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="validate_credentials.py")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tunnel-id", required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        validate_and_snapshot(arguments.source, arguments.tunnel_id, arguments.snapshot)
    except CredentialError:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
