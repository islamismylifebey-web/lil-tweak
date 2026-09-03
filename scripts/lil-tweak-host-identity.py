#!/usr/bin/env python3
"""Fail-closed validation for Lil Tweak's dedicated host identities."""

from __future__ import annotations

import argparse
import grp
import os
import pwd
import re
import stat
import sys
from pathlib import Path, PurePosixPath


MAX_DATABASE_BYTES = 4 * 1024 * 1024
MAX_ID = (1 << 32) - 2
SUBORDINATE_COUNT = 65_536
DYNAMIC_ID_MIN = 61_184
DYNAMIC_ID_MAX = 65_519
NAME = re.compile(r"[A-Za-z0-9_.-]+")
DECIMAL = re.compile(r"0|[1-9][0-9]*")
EXPECTED = {
    "lil-tweak": {
        "home": "/var/lib/lil-tweak",
        "other": "lil-tweak-tunnel",
        "subordinates": True,
    },
    "lil-tweak-tunnel": {
        "home": "/var/lib/lil-tweak-tunnel",
        "other": "lil-tweak",
        "subordinates": False,
    },
}
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_STABLE_FIELDS = (
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


class IdentityError(Exception):
    pass


def _decimal(value: str) -> int:
    if DECIMAL.fullmatch(value) is None:
        raise IdentityError
    number = int(value)
    if number > MAX_ID:
        raise IdentityError
    return number


def _open_root(path: Path) -> int:
    if not path.is_absolute() or PurePosixPath(path.as_posix()).as_posix() != path.as_posix():
        raise IdentityError
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            if component in ("", ".", ".."):
                raise IdentityError
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        status = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(status.st_mode)
            or status.st_uid != 0
            or stat.S_IMODE(status.st_mode) & 0o022
        ):
            raise IdentityError
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_database(
    root: int,
    relative: str,
    *,
    sensitive_gids: set[int] | None = None,
) -> bytes:
    components = relative.split("/")
    parent = os.dup(root)
    descriptor = -1
    try:
        for component in components[:-1]:
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent)
            child_status = os.fstat(child)
            if (
                not stat.S_ISDIR(child_status.st_mode)
                or child_status.st_uid != 0
                or stat.S_IMODE(child_status.st_mode) & 0o022
            ):
                os.close(child)
                raise IdentityError
            os.close(parent)
            parent = child
        descriptor = os.open(components[-1], _FILE_FLAGS, dir_fd=parent)
        before = os.fstat(descriptor)
        linked = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
            or before.st_uid != 0
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > MAX_DATABASE_BYTES
        ):
            raise IdentityError
        mode = stat.S_IMODE(before.st_mode)
        if sensitive_gids is None:
            if mode != 0o644 or before.st_gid != 0:
                raise IdentityError
        elif mode not in {0o600, 0o640} or before.st_gid not in sensitive_gids:
            raise IdentityError
        chunks: list[bytes] = []
        remaining = before.st_size + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        current = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
        if (
            len(data) != before.st_size
            or any(getattr(before, field) != getattr(after, field) for field in _STABLE_FIELDS)
            or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise IdentityError
        return data
    except (OSError, UnicodeError) as error:
        raise IdentityError from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _lines(data: bytes) -> list[str]:
    if not data.endswith(b"\n") or b"\x00" in data or b"\r" in data:
        raise IdentityError
    try:
        lines = data[:-1].decode("ascii").split("\n")
    except UnicodeDecodeError as error:
        raise IdentityError from error
    if any(not line or len(line) > 4096 for line in lines):
        raise IdentityError
    return lines


def _passwd(lines: list[str]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for line in lines:
        fields = line.split(":")
        if len(fields) != 7 or NAME.fullmatch(fields[0]) is None:
            raise IdentityError
        records.append(
            {
                "name": fields[0],
                "password": fields[1],
                "uid": _decimal(fields[2]),
                "gid": _decimal(fields[3]),
                "home": fields[5],
                "shell": fields[6],
            }
        )
    return records


def _groups(lines: list[str]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for line in lines:
        fields = line.split(":")
        if len(fields) != 4 or NAME.fullmatch(fields[0]) is None:
            raise IdentityError
        members = [] if fields[3] == "" else fields[3].split(",")
        if any(NAME.fullmatch(member) is None for member in members) or len(members) != len(set(members)):
            raise IdentityError
        records.append(
            {
                "name": fields[0],
                "password": fields[1],
                "gid": _decimal(fields[2]),
                "members": members,
            }
        )
    return records


def _shadow(lines: list[str]) -> list[tuple[str, str]]:
    records: list[tuple[str, str]] = []
    for line in lines:
        fields = line.split(":")
        if len(fields) != 9 or NAME.fullmatch(fields[0]) is None:
            raise IdentityError
        records.append((fields[0], fields[1]))
    return records


def _gshadow(lines: list[str]) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for line in lines:
        fields = line.split(":")
        if len(fields) != 4 or NAME.fullmatch(fields[0]) is None:
            raise IdentityError
        admins = [] if fields[2] == "" else fields[2].split(",")
        members = [] if fields[3] == "" else fields[3].split(",")
        if (
            any(NAME.fullmatch(value) is None for value in admins + members)
            or len(admins) != len(set(admins))
            or len(members) != len(set(members))
        ):
            raise IdentityError
        records.append(
            {
                "name": fields[0],
                "password": fields[1],
                "admins": admins,
                "members": members,
            }
        )
    return records


def _subordinates(
    lines: list[str],
    user: str,
    user_id: int,
    occupied_ids: set[int],
) -> None:
    records: list[tuple[str, int, int]] = []
    for line in lines:
        fields = line.split(":")
        if len(fields) != 3 or NAME.fullmatch(fields[0]) is None:
            raise IdentityError
        start = _decimal(fields[1])
        count = _decimal(fields[2])
        if count == 0 or start + count - 1 > MAX_ID:
            raise IdentityError
        records.append((fields[0], start, count))
    aliases = {user, str(user_id)}
    selected = [record for record in records if record[0] in aliases]
    if len(selected) != 1 or selected[0][0] != user:
        raise IdentityError
    _, selected_start, selected_count = selected[0]
    if selected_start < SUBORDINATE_COUNT or selected_count != SUBORDINATE_COUNT:
        raise IdentityError
    selected_end = selected_start + selected_count
    if any(selected_start <= value < selected_end for value in occupied_ids):
        raise IdentityError
    for owner, start, count in records:
        if owner == user and start == selected_start and count == selected_count:
            continue
        if max(selected_start, start) < min(selected_end, start + count):
            raise IdentityError


def _validate_local_nss(data: bytes) -> None:
    if not data.endswith(b"\n") or b"\x00" in data or b"\r" in data:
        raise IdentityError
    try:
        source = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise IdentityError from error
    selected: dict[str, list[str]] = {}
    for physical in source.splitlines():
        logical = physical.split("#", 1)[0].strip()
        if not logical:
            continue
        key, separator, values = logical.partition(":")
        if not separator:
            raise IdentityError
        key = key.strip()
        if key not in {"passwd", "group", "shadow", "gshadow", "initgroups"}:
            continue
        if key in selected:
            raise IdentityError
        tokens = values.split()
        if (
            not tokens
            or tokens[0] != "files"
            or len(tokens) != len(set(tokens))
            or any(token not in {"files", "systemd"} for token in tokens)
        ):
            raise IdentityError
        selected[key] = tokens
    if not {"passwd", "group", "shadow", "gshadow"}.issubset(selected) or set(
        selected
    ) - {"passwd", "group", "shadow", "gshadow", "initgroups"}:
        raise IdentityError


def _validate_effective_nss(
    user: str,
    expected_home: str,
    uid: int,
    gid: int,
) -> None:
    try:
        effective = pwd.getpwnam(user)
        primary = grp.getgrnam(user)
        passwd_records = pwd.getpwall()
        group_records = grp.getgrall()
        effective_groups = sorted(set(os.getgrouplist(user, gid)))
    except (KeyError, OSError) as error:
        raise IdentityError from error
    if (
        effective.pw_uid != uid
        or effective.pw_gid != gid
        or effective.pw_dir != expected_home
        or effective.pw_shell != "/usr/sbin/nologin"
        or primary.gr_gid != gid
        or list(primary.gr_mem) != []
        or sum(record.pw_uid == uid for record in passwd_records) != 1
        or sum(record.pw_gid == gid for record in passwd_records) != 1
        or sum(record.gr_gid == gid for record in group_records) != 1
        or any(user in record.gr_mem for record in group_records)
        or effective_groups != [gid]
    ):
        raise IdentityError


def validate_identity(user: str, database_root: Path = Path("/")) -> None:
    if os.geteuid() != 0 or user not in EXPECTED:
        raise IdentityError
    expected = EXPECTED[user]
    root = _open_root(database_root)
    try:
        passwd = _passwd(_lines(_read_database(root, "etc/passwd")))
        groups = _groups(_lines(_read_database(root, "etc/group")))
        shadow_groups = [record for record in groups if record["name"] == "shadow"]
        if len(shadow_groups) != 1 or shadow_groups[0]["members"] != []:
            raise IdentityError
        shadow_gid = int(shadow_groups[0]["gid"])
        sensitive_gids = {0, shadow_gid}
        shadow = _shadow(
            _lines(
                _read_database(root, "etc/shadow", sensitive_gids=sensitive_gids)
            )
        )
        gshadow = _gshadow(
            _lines(
                _read_database(root, "etc/gshadow", sensitive_gids=sensitive_gids)
            )
        )
        shadow_private = [record for record in gshadow if record["name"] == "shadow"]
        if (
            len(shadow_private) != 1
            or not shadow_private[0]["password"].startswith(("!", "*"))
            or shadow_private[0]["admins"] != []
            or shadow_private[0]["members"] != []
        ):
            raise IdentityError
        _validate_local_nss(_read_database(root, "etc/nsswitch.conf"))
        target_users = [record for record in passwd if record["name"] == user]
        if len(target_users) != 1:
            raise IdentityError
        target_uid = int(target_users[0]["uid"])
        if expected["subordinates"]:
            _subordinates(
                _lines(_read_database(root, "etc/subuid")),
                user,
                target_uid,
                {int(record["uid"]) for record in passwd},
            )
            _subordinates(
                _lines(_read_database(root, "etc/subgid")),
                user,
                target_uid,
                {int(record["gid"]) for record in passwd}
                | {int(record["gid"]) for record in groups},
            )
    finally:
        os.close(root)

    users = [record for record in passwd if record["name"] == user]
    named_groups = [record for record in groups if record["name"] == user]
    private_groups = [record for record in gshadow if record["name"] == user]
    passwords = [password for name, password in shadow if name == user]
    if (
        len(users) != 1
        or len(named_groups) != 1
        or len(private_groups) != 1
        or len(passwords) != 1
    ):
        raise IdentityError
    account = users[0]
    primary = named_groups[0]
    private_group = private_groups[0]
    uid = account["uid"]
    gid = account["gid"]
    if (
        uid == 0
        or gid == 0
        or DYNAMIC_ID_MIN <= uid <= DYNAMIC_ID_MAX
        or DYNAMIC_ID_MIN <= gid <= DYNAMIC_ID_MAX
        or account["password"] != "x"
        or account["home"] != expected["home"]
        or account["shell"] != "/usr/sbin/nologin"
        or primary["gid"] != gid
        or primary["password"] != "x"
        or primary["members"] != []
        or not private_group["password"].startswith(("!", "*"))
        or private_group["admins"] != []
        or private_group["members"] != primary["members"]
        or not passwords[0].startswith(("!", "*"))
        or sum(record["uid"] == uid for record in passwd) != 1
        or sum(record["gid"] == gid for record in passwd) != 1
        or sum(record["gid"] == gid for record in groups) != 1
        or any(user in record["members"] for record in groups)
        or any(
            user in record["admins"] or user in record["members"]
            for record in gshadow
        )
    ):
        raise IdentityError

    other = [record for record in passwd if record["name"] == expected["other"]]
    if len(other) > 1:
        raise IdentityError
    if other and (other[0]["uid"] == uid or other[0]["gid"] == gid):
        raise IdentityError
    if database_root == Path("/"):
        _validate_effective_nss(user, str(expected["home"]), int(uid), int(gid))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lil-tweak-host-identity.py")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--user", choices=sorted(EXPECTED))
    parser.add_argument("--database-root", type=Path, default=Path("/"))
    arguments = parser.parse_args(argv)
    if arguments.check:
        if arguments.user is not None or arguments.database_root != Path("/"):
            parser.error("--check does not accept validation options")
        print("lil-tweak-host-identity check: ok")
        return 0
    if arguments.user is None:
        parser.error("--user is required")
    try:
        validate_identity(arguments.user, arguments.database_root)
    except (IdentityError, OSError, ValueError):
        print("lil-tweak-host-identity: invalid dedicated service identity", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
