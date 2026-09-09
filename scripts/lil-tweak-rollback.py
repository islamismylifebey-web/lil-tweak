#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import errno
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
import pwd
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable


with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    import spwd


EXPECTED_HOST = "galor-tweak-runner-01"
RECEIPT_ROOT = PurePosixPath("/var/lib/lil-tweak-release-rollback")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_REFERENCE = re.compile(
    r"^[a-z0-9._-]+(?:[.:][a-z0-9._-]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$"
)
RECEIPT_NAME = re.compile(r"^([0-9]{8}T[0-9]{6}Z)-([0-9a-f]{12})$")
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_MANAGED_FILE_BYTES = 16 * 1024 * 1024
SCHEMA = "lil-tweak-rollback-receipt-v1"
FORWARD_SCHEMA = "lil-tweak-forward-state-v3"
ROLLBACK_LEASE_ENV = "LIL_TWEAK_ROLLBACK_LEASE_FD"
MAX_LEASE_COMMAND_ARGUMENTS = 128
MAX_LEASE_COMMAND_BYTES = 64 * 1024
MAX_LEASE_SCAN_PROCESSES = 32_768
MAX_LEASE_SCAN_DESCRIPTORS = 1_048_576
PIDFD_GETFD_SYSCALL = 438
MAX_IDENTITY_GROUPS = 64
MAX_IMAGE_REFERENCE_BYTES = 512
MAX_IMAGE_REPOSITORY_DIGEST_BYTES = 64 * 1024
MAX_IMAGE_REPOSITORY_DIGESTS = 128
MAX_QUARANTINE_BYTES = 64 * 1024 * 1024
MAX_QUARANTINE_DEPTH = 32
MAX_QUARANTINE_ENTRIES = 4096
MAX_QUARANTINE_SYMLINK_BYTES = 4096
IMAGE_ROLES = ("core", "postgres", "runner")
HOST_COMMAND_PATHS = {
    "podman": "/usr/bin/podman",
    "ss": "/usr/bin/ss",
    "systemctl": "/usr/bin/systemctl",
}
ROOT_COMMAND_ENVIRONMENT = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
}
HOST_IDENTITY_HELPER = Path(__file__).resolve().with_name(
    "lil-tweak-host-identity.py"
)
TARGET_HELPER = Path(__file__).resolve().with_name(
    "lil-tweak-digitalocean-target.py"
)


MANAGED_PATHS: tuple[tuple[str, str, bool], ...] = (
    ("/var/lib/lil-tweak/.config/containers/systemd", "directory", False),
    ("/var/lib/lil-tweak/.config/containers/systemd/lil-tweak-core.container", "regular", False),
    ("/var/lib/lil-tweak/.config/containers/systemd/lil-tweak-postgres.container", "regular", False),
    ("/var/lib/lil-tweak/.config/containers/systemd/lil-tweak.network", "regular", False),
    ("/var/lib/lil-tweak/.config/containers/systemd/lil-tweak-data.volume", "regular", False),
    ("/var/lib/lil-tweak/.config/containers/systemd/lil-tweak-postgres-data.volume", "regular", False),
    ("/var/lib/lil-tweak/.config/lil-tweak", "directory", False),
    ("/var/lib/lil-tweak/.config/lil-tweak/core.env", "regular", True),
    ("/var/lib/lil-tweak/.config/systemd/user/lil-tweak-core.service.d", "directory", False),
    ("/var/lib/lil-tweak/.config/systemd/user/lil-tweak-core.service.d/hardening.conf", "regular", False),
    ("/var/lib/lil-tweak/.config/systemd/user/lil-tweak-postgres.service.d", "directory", False),
    ("/var/lib/lil-tweak/.config/systemd/user/lil-tweak-postgres.service.d/hardening.conf", "regular", False),
    ("/var/lib/lil-tweak/.local/share/lil-tweak/migrations", "directory", False),
    ("/var/lib/lil-tweak/.local/share/lil-tweak/migrations/001_initial.sql", "regular", False),
    ("/var/lib/lil-tweak/.local/share/lil-tweak/migrations/002_fencing.sql", "regular", False),
    ("/var/lib/lil-tweak/.local/share/lil-tweak/migrations/003_test_world.sql", "regular", False),
    ("/var/lib/lil-tweak/.local/share/lil-tweak/migrations/postgres-bootstrap.sql", "regular", False),
    ("/var/lib/lil-tweak/.local/share/lil-tweak/migrations/postgres-grants.sql", "regular", False),
    ("/usr/local/libexec/lil-tweak", "directory", False),
    ("/usr/local/libexec/lil-tweak/cloudflared-verify-exec.py", "regular", False),
    ("/etc/lil-tweak-cloudflared", "directory", False),
    ("/etc/lil-tweak-cloudflared/tunnel.json", "regular", True),
    ("/etc/lil-tweak-cloudflared/config.yml", "regular", False),
    ("/etc/systemd/system/lil-tweak-cloudflared.service", "regular", False),
)

UNIT_NAMES: tuple[tuple[str, str], ...] = (
    ("system", "lil-tweak-cloudflared.service"),
    ("system", "user@lil-tweak.service"),
    ("user", "podman.socket"),
    ("user", "lil-tweak-core.service"),
    ("user", "lil-tweak-postgres.service"),
    ("user", "lil-tweak-network.service"),
    ("user", "lil-tweak-data-volume.service"),
    ("user", "lil-tweak-postgres-data-volume.service"),
)

PODMAN_NAMES: tuple[tuple[str, str], ...] = (
    ("container", "lil-tweak-core"),
    ("container", "lil-tweak-postgres"),
    ("network", "lil-tweak-private"),
    ("volume", "lil-tweak-data"),
    ("volume", "lil-tweak-postgres-data"),
    ("secret", "lil-tweak-postgres-admin-password"),
)

RETAINED_IDENTITY_POLICY = {
    "lil-tweak": ("/var/lib/lil-tweak", "lil-tweak", "/usr/sbin/nologin"),
    "lil-tweak-tunnel": (
        "/var/lib/lil-tweak-tunnel",
        "lil-tweak-tunnel",
        "/usr/sbin/nologin",
    ),
}


class RollbackError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _load_target_helper() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_lil_tweak_digitalocean_target_for_rollback",
        TARGET_HELPER,
    )
    if spec is None or spec.loader is None:
        raise RollbackError("target_helper_invalid")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise RollbackError("target_helper_invalid") from error
    return module


_TARGET_HELPER_MODULE = _load_target_helper()


def _verify_exact_target() -> None:
    try:
        _TARGET_HELPER_MODULE.verify_target()
    except Exception:
        raise RollbackError("target_verification_failed") from None


def _check_exact_target_helper() -> None:
    try:
        _TARGET_HELPER_MODULE.offline_check()
    except Exception:
        raise RollbackError("target_helper_check_failed") from None


def _valid_image_reference(reference: Any) -> bool:
    if not isinstance(reference, str):
        return False
    try:
        encoded = reference.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return (
        len(encoded) <= MAX_IMAGE_REFERENCE_BYTES
        and IMAGE_REFERENCE.fullmatch(reference) is not None
    )


def _valid_object_descriptor(value: Any, kind: str, name: str) -> bool:
    if (
        not isinstance(value, dict)
        or set(value) != {"kind", "name", "state", "id", "identity"}
        or value.get("kind") != kind
        or value.get("name") != name
    ):
        return False
    if value.get("state") == "absent":
        return value.get("id") is None and value.get("identity") is None
    if (
        value.get("state") != "present"
        or not isinstance(value.get("id"), str)
        or not value["id"]
        or len(value["id"]) > 512
        or not isinstance(value.get("identity"), str)
        or not value["identity"]
        or len(value["identity"]) > 512
    ):
        return False
    if kind == "container":
        return IMAGE_REFERENCE.fullmatch(value["identity"]) is not None
    return value["identity"] == name


def _valid_image_descriptor(
    descriptor: Any,
    reference: str,
) -> bool:
    if (
        not isinstance(descriptor, dict)
        or set(descriptor) != {"reference", "state", "id", "identity"}
        or descriptor.get("reference") != reference
    ):
        return False
    if descriptor.get("state") == "absent":
        return descriptor.get("id") is None and descriptor.get("identity") is None
    return (
        descriptor.get("state") == "present"
        and isinstance(descriptor.get("id"), str)
        and SHA256.fullmatch(descriptor["id"]) is not None
        and descriptor.get("identity") == reference
    )


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
        raise RollbackError("receipt_not_canonical") from error


def _strict_json(data: bytes) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise RollbackError("receipt_duplicate_key")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise RollbackError("receipt_nonfinite_number")

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except RollbackError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RollbackError("receipt_json_invalid") from error


def _physical(root: Path, logical: str | PurePosixPath) -> Path:
    path = PurePosixPath(logical)
    if not path.is_absolute() or ".." in path.parts:
        raise RollbackError("managed_path_invalid")
    return Path(root) / Path(*path.parts[1:])


_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


def _require_nofollow_support() -> None:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise RollbackError("safe_path_operations_unavailable")


@contextmanager
def _open_managed_parent(
    root: Path,
    logical: str,
    *,
    create: bool,
):
    _require_nofollow_support()
    path = PurePosixPath(logical)
    if not path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
        raise RollbackError("managed_path_invalid")
    root_path = Path(root)
    descriptors: list[int] = []
    links: list[tuple[int, str, int, tuple[int, int]]] = []
    try:
        root_before = root_path.lstat()
        root_descriptor = os.open(root_path, _DIRECTORY_FLAGS)
        descriptors.append(root_descriptor)
        root_bound = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(root_bound.st_mode)
            or (root_before.st_dev, root_before.st_ino) != (root_bound.st_dev, root_bound.st_ino)
        ):
            raise RollbackError("managed_path_unsafe")
        current = root_descriptor
        missing = False
        for component in path.parts[1:-1]:
            try:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    missing = True
                    break
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                    os.fsync(current)
                    child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
                except OSError as error:
                    raise RollbackError("rollback_restore_failed") from error
            except OSError as error:
                raise RollbackError("managed_path_unsafe") from error
            entry = os.stat(component, dir_fd=current, follow_symlinks=False)
            bound = os.fstat(child)
            if (
                not stat.S_ISDIR(entry.st_mode)
                or not stat.S_ISDIR(bound.st_mode)
                or (entry.st_dev, entry.st_ino) != (bound.st_dev, bound.st_ino)
            ):
                os.close(child)
                raise RollbackError("managed_path_unsafe")
            links.append((current, component, child, (bound.st_dev, bound.st_ino)))
            descriptors.append(child)
            current = child
        yield (None if missing else current), path.name
        root_after = root_path.lstat()
        root_final = os.fstat(root_descriptor)
        if (
            (root_after.st_dev, root_after.st_ino) != (root_final.st_dev, root_final.st_ino)
            or (root_final.st_dev, root_final.st_ino) != (root_bound.st_dev, root_bound.st_ino)
        ):
            raise RollbackError("managed_path_changed")
        for parent, component, child, identity in links:
            entry = os.stat(component, dir_fd=parent, follow_symlinks=False)
            bound = os.fstat(child)
            if (
                not stat.S_ISDIR(entry.st_mode)
                or (entry.st_dev, entry.st_ino) != identity
                or (bound.st_dev, bound.st_ino) != identity
            ):
                raise RollbackError("managed_path_changed")
    except RollbackError:
        raise
    except OSError as error:
        raise RollbackError("managed_path_unsafe") from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read_regular_at(
    parent: int,
    name: str,
) -> tuple[bytes, os.stat_result, tuple[int, int]]:
    try:
        entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as error:
        raise RollbackError("managed_path_unsafe") from error
    identity = (entry.st_dev, entry.st_ino)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except OSError as error:
        raise RollbackError("managed_path_unsafe") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino) != identity
            or before.st_size < 0
            or before.st_size > MAX_MANAGED_FILE_BYTES
        ):
            raise RollbackError("managed_path_unsafe")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise RollbackError("managed_path_changed")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RollbackError("managed_path_changed")
        after = os.fstat(descriptor)
        final_entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
        fields = (
            "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
            "st_size", "st_mtime_ns", "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise RollbackError("managed_path_changed")
        if (final_entry.st_dev, final_entry.st_ino) != identity:
            raise RollbackError("managed_path_changed")
        return b"".join(chunks), after, identity
    finally:
        os.close(descriptor)


def _descriptor_at(parent: int | None, name: str) -> tuple[dict[str, Any], tuple[int, int] | None]:
    if parent is None:
        return {"state": "absent"}, None
    try:
        entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return {"state": "absent"}, None
    except OSError as error:
        raise RollbackError("managed_path_unsafe") from error
    identity = (entry.st_dev, entry.st_ino)
    if stat.S_ISREG(entry.st_mode):
        data, after, identity = _read_regular_at(parent, name)
        return {
            "state": "present",
            "type": "regular",
            "mode": f"{stat.S_IMODE(after.st_mode):04o}",
            "uid": after.st_uid,
            "gid": after.st_gid,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }, identity
    if stat.S_ISDIR(entry.st_mode):
        return {
            "state": "present",
            "type": "directory",
            "mode": f"{stat.S_IMODE(entry.st_mode):04o}",
            "uid": entry.st_uid,
            "gid": entry.st_gid,
        }, identity
    return {"state": "present", "type": "unsafe"}, identity


def _read_regular(
    path: Path,
    *,
    maximum: int,
    required_mode: int | None = None,
    required_owner: int | None = None,
) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before_path = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RollbackError("managed_path_unsafe") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RollbackError("managed_path_unsafe")
        if (before_path.st_dev, before_path.st_ino) != (before.st_dev, before.st_ino):
            raise RollbackError("managed_path_changed")
        if required_mode is not None and stat.S_IMODE(before.st_mode) != required_mode:
            raise RollbackError("receipt_mode_invalid")
        if required_owner is not None and before.st_uid != required_owner:
            raise RollbackError("receipt_owner_invalid")
        if before.st_size < 0 or before.st_size > maximum:
            raise RollbackError("managed_path_size")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise RollbackError("managed_path_changed")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RollbackError("managed_path_changed")
        after = os.fstat(descriptor)
        after_path = path.lstat()
        identity = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, value) != getattr(after, value) for value in identity):
            raise RollbackError("managed_path_changed")
        if (after_path.st_dev, after_path.st_ino, after_path.st_mode, after_path.st_nlink) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
        ):
            raise RollbackError("managed_path_changed")
        return b"".join(chunks), after
    except RollbackError:
        raise
    except OSError as error:
        raise RollbackError("managed_path_changed") from error
    finally:
        os.close(descriptor)


def _write_new(path: Path, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as error:
        raise RollbackError("receipt_write_failed") from error
    try:
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise RollbackError("receipt_write_failed")
            written += count
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    except OSError as error:
        raise RollbackError("receipt_write_failed") from error
    finally:
        os.close(descriptor)


def _replace_canonical(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    data = canonical_json_bytes(value)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, mode)
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise RollbackError("receipt_write_failed")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except OSError as error:
        raise RollbackError("receipt_write_failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _identity(name: str) -> dict[str, Any]:
    try:
        record = pwd.getpwnam(name)
    except KeyError:
        return {
            "name": name,
            "state": "absent",
            "uid": None,
            "gid": None,
            "home": None,
            "primary_group": None,
            "shell": None,
            "password_locked": None,
            "supplementary_groups": None,
        }
    try:
        primary = grp.getgrgid(record.pw_gid).gr_name
        password = spwd.getspnam(name).sp_pwdp
        group_ids = os.getgrouplist(name, record.pw_gid)
        if len(group_ids) > MAX_IDENTITY_GROUPS + 1:
            raise RollbackError("host_state_invalid")
        supplementary_groups = sorted(
            {
                grp.getgrgid(group_id).gr_name
                for group_id in group_ids
                if group_id != record.pw_gid
            }
        )
        if (
            not isinstance(password, str)
            or not password
            or len(password) > 4096
            or len(supplementary_groups) > MAX_IDENTITY_GROUPS
            or any(
                not isinstance(group_name, str)
                or re.fullmatch(r"[a-z_][a-z0-9_.-]{0,127}", group_name) is None
                for group_name in supplementary_groups
            )
        ):
            raise RollbackError("host_state_invalid")
        return {
            "name": name,
            "state": "present",
            "uid": record.pw_uid,
            "gid": record.pw_gid,
            "home": record.pw_dir,
            "primary_group": primary,
            "shell": record.pw_shell,
            "password_locked": password.startswith(("!", "*")),
            "supplementary_groups": supplementary_groups,
        }
    except RollbackError:
        raise
    except KeyError as error:
        raise RollbackError("host_state_invalid") from error
    except OSError as error:
        raise RollbackError("host_state_command_failed") from error


def _snapshot_path(
    root: Path,
    receipt: Path,
    logical: str,
    expected_type: str,
    sensitive: bool,
    payload_index: int,
) -> tuple[dict[str, Any], int]:
    absent = {
        "path": logical,
        "state": "absent",
        "type": None,
        "mode": None,
        "uid": None,
        "gid": None,
        "size": None,
        "sha256": None,
        "payload": None,
        "sensitive": sensitive,
    }
    with _open_managed_parent(root, logical, create=False) as (parent, name):
        if parent is None:
            return absent, payload_index
        try:
            status = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return absent, payload_index
        except OSError as error:
            raise RollbackError("managed_path_unsafe") from error
        if expected_type == "directory":
            try:
                child = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
            except OSError as error:
                raise RollbackError("managed_path_unsafe") from error
            try:
                bound = os.fstat(child)
                linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(bound.st_mode)
                    or (bound.st_dev, bound.st_ino) != (linked.st_dev, linked.st_ino)
                ):
                    raise RollbackError("managed_path_unsafe")
                return {
                    "path": logical,
                    "state": "present",
                    "type": "directory",
                    "mode": f"{stat.S_IMODE(bound.st_mode):04o}",
                    "uid": bound.st_uid,
                    "gid": bound.st_gid,
                    "size": None,
                    "sha256": None,
                    "payload": None,
                    "sensitive": sensitive,
                }, payload_index
            finally:
                os.close(child)
        data, bound, _identity_value = _read_regular_at(parent, name)
    payload_name = f"payload/{payload_index:04d}.bin"
    _write_new(receipt / payload_name, data, 0o600)
    return {
        "path": logical,
        "state": "present",
        "type": "regular",
        "mode": f"{stat.S_IMODE(bound.st_mode):04o}",
        "uid": bound.st_uid,
        "gid": bound.st_gid,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "payload": payload_name,
        "sensitive": sensitive,
    }, payload_index + 1


class SystemExecutor:
    def __init__(self) -> None:
        try:
            before = pwd.getpwnam("lil-tweak")
        except KeyError:
            self.service_uid = None
            return
        try:
            result = subprocess.run(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    str(HOST_IDENTITY_HELPER),
                    "--user",
                    "lil-tweak",
                ],
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=20,
                check=False,
                env=dict(ROOT_COMMAND_ENVIRONMENT),
                cwd="/",
            )
            after = pwd.getpwnam("lil-tweak")
        except (KeyError, OSError, subprocess.TimeoutExpired) as error:
            raise RollbackError("host_identity_invalid") from error
        fields = ("pw_uid", "pw_gid", "pw_dir", "pw_shell")
        if result.returncode != 0 or any(
            getattr(before, field) != getattr(after, field) for field in fields
        ):
            raise RollbackError("host_identity_invalid")
        self.service_uid = after.pw_uid

    def _command(self, arguments: list[str], *, user: bool = False) -> subprocess.CompletedProcess[str]:
        if not arguments or arguments[0] not in HOST_COMMAND_PATHS:
            raise RollbackError("host_state_command_failed")
        resolved = [HOST_COMMAND_PATHS[arguments[0]], *arguments[1:]]
        command = resolved
        environment = dict(ROOT_COMMAND_ENVIRONMENT)
        if user:
            if self.service_uid is None:
                return subprocess.CompletedProcess(arguments, 1, "", "")
            command = [
                "/usr/sbin/runuser",
                "--user",
                "lil-tweak",
                "--",
                "/usr/bin/env",
                "-i",
                "HOME=/var/lib/lil-tweak",
                "USER=lil-tweak",
                "LOGNAME=lil-tweak",
                "PATH=/usr/bin:/bin",
                "LC_ALL=C",
                f"XDG_RUNTIME_DIR=/run/user/{self.service_uid}",
                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{self.service_uid}/bus",
                *resolved,
            ]
        try:
            return subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=20,
                check=False,
                env=environment,
                cwd="/",
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RollbackError("host_state_command_failed") from error

    @staticmethod
    def _require_success(result: subprocess.CompletedProcess[str]) -> None:
        if result.returncode != 0:
            raise RollbackError("host_state_command_failed")

    def _linger_enabled(self) -> bool:
        if self.service_uid is None:
            return False
        path = Path("/var/lib/systemd/linger/lil-tweak")
        try:
            status = path.lstat()
        except FileNotFoundError:
            return False
        except OSError as error:
            raise RollbackError("host_state_command_failed") from error
        if not stat.S_ISREG(status.st_mode) or stat.S_ISLNK(status.st_mode):
            raise RollbackError("host_state_invalid")
        return True

    def _unit_state(self, scope: str, name: str) -> dict[str, Any]:
        if scope == "user" and self.service_uid is None:
            return {
                "scope": scope,
                "name": name,
                "load_state": "not-found",
                "unit_file_state": "disabled",
                "active_state": "inactive",
                "sub_state": "dead",
            }
        if name == "user@lil-tweak.service" and self.service_uid is None:
            return {
                "scope": scope,
                "name": name,
                "load_state": "not-found",
                "unit_file_state": "disabled",
                "active_state": "inactive",
                "sub_state": "dead",
            }
        actual_name = f"user@{self.service_uid}.service" if name == "user@lil-tweak.service" and self.service_uid is not None else name
        result = self._command(
            [
                "systemctl",
                *( ["--user"] if scope == "user" else [] ),
                "show",
                actual_name,
                "--property=LoadState,UnitFileState,ActiveState,SubState",
                "--no-pager",
            ],
            user=scope == "user",
        )
        values = {"LoadState": "not-found", "UnitFileState": "disabled", "ActiveState": "inactive", "SubState": "dead"}
        for line in result.stdout[:65536].splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                if key in values and value and len(value) <= 128:
                    values[key] = value
        if result.returncode not in (0, 4) or (
            result.returncode == 4 and values["LoadState"] != "not-found"
        ):
            raise RollbackError("host_state_command_failed")
        return {
            "scope": scope,
            "name": name,
            "load_state": values["LoadState"],
            "unit_file_state": values["UnitFileState"],
            "active_state": values["ActiveState"],
            "sub_state": values["SubState"],
        }

    def current_object(self, kind: str, name: str) -> dict[str, Any]:
        if self.service_uid is None:
            return {"kind": kind, "name": name, "state": "absent", "id": None, "identity": None}
        exists = self._command(["podman", kind, "exists", name], user=True)
        if exists.returncode == 1:
            return {"kind": kind, "name": name, "state": "absent", "id": None, "identity": None}
        if exists.returncode != 0:
            raise RollbackError("host_state_command_failed")
        if kind == "container":
            format_value = "{{.Id}}|{{.ImageName}}"
        elif kind == "network":
            format_value = "{{.ID}}|{{.Name}}"
        elif kind == "volume":
            format_value = (
                "{{.Name}}|{{.Driver}}|{{.Scope}}|"
                "{{.Mountpoint}}|{{.CreatedAt}}"
            )
        elif kind == "secret":
            format_value = "{{.ID}}|{{.Spec.Name}}"
        else:
            raise RollbackError("host_state_invalid")
        result = self._command(["podman", kind, "inspect", "--format", format_value, name], user=True)
        if result.returncode != 0:
            raise RollbackError("host_state_command_failed")
        output = result.stdout.strip()
        if len(output) > 512 or "\n" in output:
            raise RollbackError("host_state_invalid")
        if kind == "volume":
            fields = output.split("|")
            if (
                len(fields) != 5
                or fields[0] != name
                or any(not field for field in fields[1:])
            ):
                raise RollbackError("host_state_invalid")
            return {
                "kind": kind,
                "name": name,
                "state": "present",
                "id": hashlib.sha256(output.encode("utf-8")).hexdigest(),
                "identity": name,
            }
        object_id, separator, identity = output.partition("|")
        if (
            separator != "|"
            or not object_id
            or not identity
            or "|" in identity
            or (kind != "container" and identity != name)
        ):
            raise RollbackError("host_state_invalid")
        return {
            "kind": kind,
            "name": name,
            "state": "present",
            "id": object_id,
            "identity": identity,
        }

    def current_image(self, reference: str) -> dict[str, Any]:
        if not _valid_image_reference(reference):
            raise RollbackError("host_state_invalid")
        absent = {
            "reference": reference,
            "state": "absent",
            "id": None,
            "identity": None,
        }
        if self.service_uid is None:
            return absent
        exists = self._command(["podman", "image", "exists", reference], user=True)
        if exists.returncode == 1:
            return absent
        if exists.returncode != 0:
            raise RollbackError("host_state_command_failed")
        format_value = "{{.Id}}|{{.Digest}}"
        result = self._command(
            ["podman", "image", "inspect", "--format", format_value, reference],
            user=True,
        )
        if result.returncode != 0:
            raise RollbackError("host_state_command_failed")
        raw_output = result.stdout
        try:
            output_bytes = raw_output.encode("utf-8")
        except UnicodeEncodeError as error:
            raise RollbackError("host_state_invalid") from error
        if (
            len(output_bytes) > MAX_IMAGE_REFERENCE_BYTES
            or "\r" in raw_output
            or raw_output.count("\n") > 1
            or ("\n" in raw_output and not raw_output.endswith("\n"))
        ):
            raise RollbackError("host_state_invalid")
        output = raw_output[:-1] if raw_output.endswith("\n") else raw_output
        image_id, separator, digest = output.partition("|")
        expected_digest = "sha256:" + reference.rsplit("@sha256:", 1)[1]
        if (
            separator != "|"
            or "|" in digest
            or SHA256.fullmatch(image_id) is None
            or digest != expected_digest
        ):
            raise RollbackError("host_state_invalid")
        repository_result = self._command(
            [
                "podman",
                "image",
                "inspect",
                "--format",
                "{{range .RepoDigests}}{{println .}}{{end}}",
                reference,
            ],
            user=True,
        )
        if repository_result.returncode != 0:
            raise RollbackError("host_state_command_failed")
        repository_output = repository_result.stdout
        try:
            repository_bytes = repository_output.encode("utf-8")
        except UnicodeEncodeError as error:
            raise RollbackError("host_state_invalid") from error
        if (
            not repository_output.endswith("\n")
            or len(repository_bytes) > MAX_IMAGE_REPOSITORY_DIGEST_BYTES
            or "\r" in repository_output
            or "\x00" in repository_output
        ):
            raise RollbackError("host_state_invalid")
        repository_digests = repository_output[:-1].split("\n")
        if (
            not 1 <= len(repository_digests) <= MAX_IMAGE_REPOSITORY_DIGESTS
            or len(repository_digests) != len(set(repository_digests))
            or any(
                not _valid_image_reference(value)
                for value in repository_digests
            )
            or reference not in repository_digests
        ):
            raise RollbackError("host_state_invalid")
        return {
            "reference": reference,
            "state": "present",
            "id": image_id,
            "identity": reference,
        }

    def capture_state(self) -> dict[str, Any]:
        units = [self._unit_state(scope, name) for scope, name in UNIT_NAMES]
        objects = [self.current_object(kind, name) for kind, name in PODMAN_NAMES]
        listeners = self._command(["ss", "--listening", "--tcp", "--numeric"])
        self._require_success(listeners)
        return {
            "units": units,
            "podman_objects": objects,
            "image_references": sorted(
                {
                    value["identity"]
                    for value in objects
                    if value["kind"] == "container"
                    and value["state"] == "present"
                    and isinstance(value.get("identity"), str)
                }
            ),
            "listeners": {"loopback_8017": "127.0.0.1:8017" in listeners.stdout[:65536]},
            "linger": self._linger_enabled(),
        }

    def stop_for_restore(self) -> None:
        tunnel = self._unit_state("system", "lil-tweak-cloudflared.service")
        if tunnel["load_state"] != "not-found":
            self._require_success(
                self._command(["systemctl", "disable", "--now", "lil-tweak-cloudflared.service"])
            )
            stopped_tunnel = self._unit_state("system", "lil-tweak-cloudflared.service")
            if stopped_tunnel["active_state"] == "active":
                raise RollbackError("host_state_command_failed")
        if self.service_uid is not None:
            for name in (
                "lil-tweak-core.service",
                "lil-tweak-postgres.service",
                "lil-tweak-network.service",
            ):
                unit = self._unit_state("user", name)
                if unit["load_state"] != "not-found":
                    self._require_success(
                        self._command(["systemctl", "--user", "stop", name], user=True)
                    )
                    stopped = self._unit_state("user", name)
                    if stopped["active_state"] == "active":
                        raise RollbackError("host_state_command_failed")

    def remove_object(self, entry: dict[str, Any]) -> None:
        if not isinstance(entry, dict):
            raise RollbackError("podman_restore_failed")
        kind = entry.get("kind")
        name = entry.get("name")
        if kind == "volume":
            raise RollbackError("volume_removal_forbidden")
        if (
            not isinstance(kind, str)
            or not isinstance(name, str)
            or not _valid_object_descriptor(entry, kind, name)
            or entry.get("state") != "present"
        ):
            raise RollbackError("podman_restore_failed")
        current = self.current_object(kind, name)
        if (
            _valid_object_descriptor(current, kind, name)
            and current.get("state") == "absent"
        ):
            return
        if current != entry:
            raise RollbackError("podman_restore_failed")
        action = "rm" if kind in {"container", "secret"} else "remove"
        result = self._command(["podman", kind, action, entry["id"]], user=True)
        if result.returncode != 0:
            raise RollbackError("podman_restore_failed")
        removed = self.current_object(kind, name)
        if (
            not _valid_object_descriptor(removed, kind, name)
            or removed.get("state") != "absent"
        ):
            raise RollbackError("podman_restore_failed")

    def remove_image(self, entry: dict[str, Any]) -> None:
        reference = entry.get("reference") if isinstance(entry, dict) else None
        if (
            not _valid_image_reference(reference)
            or not _valid_image_descriptor(entry, reference)
            or entry.get("state") != "present"
        ):
            raise RollbackError("podman_restore_failed")
        result = self._command(
            ["podman", "image", "rm", "--no-prune", reference],
            user=True,
        )
        if result.returncode != 0:
            raise RollbackError("podman_restore_failed")

    def restore_units(self, units: list[dict[str, Any]], linger: bool | None = None) -> None:
        self._require_success(self._command(["systemctl", "daemon-reload"]))
        if self.service_uid is not None:
            self._require_success(
                self._command(["systemctl", "--user", "daemon-reload"], user=True)
            )
        ordered_units = [
            unit for unit in units if unit["name"] != "user@lil-tweak.service"
        ] + [
            unit for unit in units if unit["name"] == "user@lil-tweak.service"
        ]
        manager_baseline = next(
            (unit for unit in units if unit["name"] == "user@lil-tweak.service"),
            None,
        )
        fresh_service_identity = (
            manager_baseline is not None
            and manager_baseline.get("load_state") == "not-found"
        )
        for unit in ordered_units:
            scope = unit["scope"]
            name = unit["name"]
            if name == "user@lil-tweak.service" and fresh_service_identity:
                for user_unit in (value for value in units if value["scope"] == "user"):
                    current_user_unit = self._unit_state("user", user_unit["name"])
                    if (
                        current_user_unit["unit_file_state"] != "disabled"
                        or current_user_unit["active_state"] != "inactive"
                        or (
                            user_unit["name"] != "podman.socket"
                            and current_user_unit["load_state"] != "not-found"
                        )
                    ):
                        raise RollbackError("rollback_verification_failed")
            actual_name = f"user@{self.service_uid}.service" if name == "user@lil-tweak.service" and self.service_uid is not None else name
            user = scope == "user"
            prefix = ["systemctl", *( ["--user"] if user else [] )]
            if unit["load_state"] == "not-found":
                current = self._unit_state(scope, name)
                if current["load_state"] != "not-found":
                    self._require_success(
                        self._command([*prefix, "disable", "--now", actual_name], user=user)
                    )
                continue
            enabled = unit["unit_file_state"] in {"enabled", "enabled-runtime"}
            active = unit["active_state"] == "active"
            if unit["unit_file_state"] not in {"static", "indirect", "generated", "transient"}:
                self._require_success(
                    self._command([*prefix, "enable" if enabled else "disable", actual_name], user=user)
                )
            self._require_success(
                self._command([*prefix, "start" if active else "stop", actual_name], user=user)
            )
        if linger is not None and self.service_uid is not None:
            self._require_success(
                self._command(
                    ["loginctl", "enable-linger" if linger else "disable-linger", "lil-tweak"]
                )
            )

    def verify_restored(
        self,
        manifest: dict[str, Any],
        retained_objects: dict[tuple[str, str], dict[str, Any]] | None = None,
    ) -> None:
        retained_objects = retained_objects or {}
        baseline_identities = {
            value["name"]: value for value in manifest["identities"]
        }
        current_identities = {
            name: _identity(name) for name in baseline_identities
        }
        present_identities = [
            value
            for value in current_identities.values()
            if value["state"] == "present"
        ]
        if (
            any(
                isinstance(value.get("uid"), bool)
                or not isinstance(value.get("uid"), int)
                or value["uid"] <= 0
                or isinstance(value.get("gid"), bool)
                or not isinstance(value.get("gid"), int)
                or value["gid"] <= 0
                for value in present_identities
            )
            or len({value["uid"] for value in present_identities})
            != len(present_identities)
            or len({value["gid"] for value in present_identities})
            != len(present_identities)
        ):
            raise RollbackError("rollback_verification_failed")
        for name, expected in baseline_identities.items():
            current_identity = current_identities[name]
            if expected["state"] == "present":
                if current_identity != expected:
                    raise RollbackError("rollback_verification_failed")
                continue
            if current_identity["state"] == "absent":
                continue
            retained = RETAINED_IDENTITY_POLICY[name]
            if (
                current_identity["state"] != "present"
                or (
                    current_identity["home"],
                    current_identity["primary_group"],
                    current_identity["shell"],
                )
                != retained
                or current_identity["password_locked"] is not True
                or current_identity["supplementary_groups"] != []
            ):
                raise RollbackError("rollback_verification_failed")
        service_was_absent = baseline_identities["lil-tweak"]["state"] == "absent"
        for expected in manifest["units"]:
            if expected["scope"] == "user" and service_was_absent:
                continue
            current = self._unit_state(expected["scope"], expected["name"])
            if expected["name"] == "user@lil-tweak.service" and service_was_absent:
                if current["active_state"] != "inactive":
                    raise RollbackError("rollback_verification_failed")
                continue
            for field in ("load_state", "unit_file_state", "active_state"):
                if current[field] != expected[field]:
                    raise RollbackError("rollback_verification_failed")
        if self._linger_enabled() is not manifest["linger"]:
            raise RollbackError("rollback_verification_failed")
        listeners = self._command(["ss", "--listening", "--tcp", "--numeric"])
        self._require_success(listeners)
        actual_listener = "127.0.0.1:8017" in listeners.stdout[:65536]
        if actual_listener is not manifest["listeners"]["loopback_8017"]:
            raise RollbackError("rollback_verification_failed")
        for reference in manifest["image_references"]:
            result = self._command(["podman", "image", "exists", reference], user=True)
            if result.returncode != 0:
                raise RollbackError("rollback_verification_failed")
        for expected in manifest["podman_objects"]:
            current = self.current_object(expected["kind"], expected["name"])
            if expected["state"] == "present":
                if (
                    current.get("state") != "present"
                    or current.get("id") != expected.get("id")
                    or current.get("identity") != expected.get("identity")
                ):
                    raise RollbackError("rollback_verification_failed")
            elif (expected["kind"], expected["name"]) in retained_objects:
                if current != retained_objects[(expected["kind"], expected["name"])]:
                    raise RollbackError("rollback_verification_failed")
            elif current.get("state") != "absent":
                raise RollbackError("rollback_verification_failed")


def _validate_receipt_name(output: Path, source_commit: str, root: Path) -> tuple[str, str]:
    if not COMMIT.fullmatch(source_commit):
        raise RollbackError("source_commit_invalid")
    expected_parent = _physical(root, RECEIPT_ROOT)
    if output.parent != expected_parent:
        raise RollbackError("receipt_path_invalid")
    match = RECEIPT_NAME.fullmatch(output.name)
    if match is None or match.group(2) != source_commit[:12]:
        raise RollbackError("receipt_name_invalid")
    try:
        parsed = datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise RollbackError("receipt_name_invalid") from error
    return match.group(1), parsed.isoformat().replace("+00:00", "Z")


def _validate_parent(parent: Path) -> None:
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    status = parent.lstat()
    if not stat.S_ISDIR(status.st_mode) or stat.S_ISLNK(status.st_mode) or status.st_uid != os.geteuid():
        raise RollbackError("receipt_parent_unsafe")
    os.chmod(parent, 0o700)
    if stat.S_IMODE(parent.stat().st_mode) != 0o700:
        raise RollbackError("receipt_parent_unsafe")


def capture_receipt(
    *,
    output: Path,
    source_commit: str,
    root: Path = Path("/"),
    hostname_getter: Callable[[], str] = lambda: socket.gethostname().split(".", 1)[0],
    executor: Any | None = None,
) -> str:
    _verify_exact_target()
    output = Path(output)
    root = Path(root).resolve()
    captured_at, captured_iso = _validate_receipt_name(output, source_commit, root)
    if hostname_getter() != EXPECTED_HOST:
        raise RollbackError("hostname_mismatch")
    _validate_parent(output.parent)
    with _receipt_lock(output):
        return _capture_receipt_locked(
            output=output,
            source_commit=source_commit,
            root=root,
            captured_at=captured_at,
            captured_iso=captured_iso,
            executor=executor,
        )


def _capture_receipt_locked(
    *,
    output: Path,
    source_commit: str,
    root: Path,
    captured_at: str,
    captured_iso: str,
    executor: Any | None,
) -> str:
    if output.exists() or output.is_symlink():
        raise RollbackError("receipt_exists")
    if executor is None:
        executor = SystemExecutor()
    created_identity: tuple[int, int] | None = None
    try:
        output.mkdir(mode=0o700)
        os.chmod(output, 0o700)
        created_status = output.lstat()
        created_identity = (created_status.st_dev, created_status.st_ino)
        (output / "payload").mkdir(mode=0o700)
        managed: list[dict[str, Any]] = []
        payload_index = 0
        for logical, expected_type, sensitive in MANAGED_PATHS:
            entry, payload_index = _snapshot_path(
                root,
                output,
                logical,
                expected_type,
                sensitive,
                payload_index,
            )
            managed.append(entry)
        runtime_state = executor.capture_state()
        payload = {
            "schema": SCHEMA,
            "hostname": EXPECTED_HOST,
            "captured_at": captured_at,
            "captured_at_iso": captured_iso,
            "source_commit": source_commit,
            "source_prefix": source_commit[:12],
            "identities": [_identity("lil-tweak"), _identity("lil-tweak-tunnel")],
            "managed_paths": managed,
            "units": runtime_state["units"],
            "podman_objects": runtime_state["podman_objects"],
            "image_references": runtime_state["image_references"],
            "listeners": runtime_state["listeners"],
            "linger": runtime_state["linger"],
        }
        manifest_bytes = canonical_json_bytes(payload)
        _write_new(output / "manifest.json", manifest_bytes, 0o600)
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        forward = {
            "schema": FORWARD_SCHEMA,
            "baseline_manifest_sha256": manifest_digest,
            "transaction_state": "open",
            "rollback_outcome": "clean",
            "files": {},
            "directories": {},
            "objects": {},
            "images": {},
        }
        _write_new(output / "forward-state.json", canonical_json_bytes(forward), 0o600)
        parent = os.open(output, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        receipt_parent = os.open(output.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(receipt_parent)
        finally:
            os.close(receipt_parent)
        return manifest_digest
    except Exception as error:
        if created_identity is not None:
            try:
                current = output.lstat()
                if (
                    stat.S_ISDIR(current.st_mode)
                    and not stat.S_ISLNK(current.st_mode)
                    and (current.st_dev, current.st_ino) == created_identity
                ):
                    shutil.rmtree(output)
            except FileNotFoundError:
                pass
        if isinstance(error, RollbackError):
            raise
        raise RollbackError("receipt_capture_failed") from error


def _validate_manifest_payload(payload: Any) -> None:
    expected_keys = {
        "schema", "hostname", "captured_at", "captured_at_iso", "source_commit",
        "source_prefix", "identities", "managed_paths", "units", "podman_objects",
        "image_references", "listeners", "linger",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys or payload.get("schema") != SCHEMA:
        raise RollbackError("receipt_manifest_invalid")
    source_commit = payload.get("source_commit")
    if not isinstance(source_commit, str) or COMMIT.fullmatch(source_commit) is None:
        raise RollbackError("receipt_manifest_invalid")
    identities = payload.get("identities")
    if not isinstance(identities, list) or [item.get("name") for item in identities if isinstance(item, dict)] != [
        "lil-tweak", "lil-tweak-tunnel"
    ]:
        raise RollbackError("receipt_manifest_invalid")
    identity_keys = {
        "name",
        "state",
        "uid",
        "gid",
        "home",
        "primary_group",
        "shell",
        "password_locked",
        "supplementary_groups",
    }
    for identity in identities:
        if not isinstance(identity, dict) or set(identity) != identity_keys:
            raise RollbackError("receipt_manifest_invalid")
        if identity["state"] == "absent":
            if any(
                identity[field] is not None
                for field in (
                    "uid",
                    "gid",
                    "home",
                    "primary_group",
                    "shell",
                    "password_locked",
                    "supplementary_groups",
                )
            ):
                raise RollbackError("receipt_manifest_invalid")
        elif identity["state"] == "present":
            if (
                isinstance(identity["uid"], bool)
                or not isinstance(identity["uid"], int)
                or identity["uid"] <= 0
                or isinstance(identity["gid"], bool)
                or not isinstance(identity["gid"], int)
                or identity["gid"] <= 0
                or not isinstance(identity["home"], str)
                or not identity["home"].startswith("/")
                or not isinstance(identity["primary_group"], str)
                or not identity["primary_group"]
                or not isinstance(identity["shell"], str)
                or not identity["shell"].startswith("/")
                or not isinstance(identity["password_locked"], bool)
                or not isinstance(identity["supplementary_groups"], list)
                or len(identity["supplementary_groups"]) > MAX_IDENTITY_GROUPS
                or any(
                    not isinstance(group_name, str)
                    or re.fullmatch(r"[a-z_][a-z0-9_.-]{0,127}", group_name) is None
                    for group_name in identity["supplementary_groups"]
                )
                or identity["supplementary_groups"]
                != sorted(set(identity["supplementary_groups"]))
            ):
                raise RollbackError("receipt_manifest_invalid")
        else:
            raise RollbackError("receipt_manifest_invalid")
    present_identities = [
        identity for identity in identities if identity["state"] == "present"
    ]
    if (
        len({identity["uid"] for identity in present_identities})
        != len(present_identities)
        or len({identity["gid"] for identity in present_identities})
        != len(present_identities)
    ):
        raise RollbackError("receipt_manifest_invalid")
    units = payload.get("units")
    if not isinstance(units, list) or [
        (item.get("scope"), item.get("name")) for item in units if isinstance(item, dict)
    ] != list(UNIT_NAMES):
        raise RollbackError("receipt_manifest_invalid")
    unit_keys = {"scope", "name", "load_state", "unit_file_state", "active_state", "sub_state"}
    for unit in units:
        if (
            not isinstance(unit, dict)
            or set(unit) != unit_keys
            or any(
                not isinstance(unit[field], str) or not unit[field] or len(unit[field]) > 128
                for field in unit_keys
            )
        ):
            raise RollbackError("receipt_manifest_invalid")
    objects = payload.get("podman_objects")
    if not isinstance(objects, list) or [
        (item.get("kind"), item.get("name")) for item in objects if isinstance(item, dict)
    ] != list(PODMAN_NAMES):
        raise RollbackError("receipt_manifest_invalid")
    object_keys = {"kind", "name", "state", "id", "identity"}
    for object_value in objects:
        if not isinstance(object_value, dict) or set(object_value) != object_keys:
            raise RollbackError("receipt_manifest_invalid")
        if object_value["state"] == "absent":
            if object_value["id"] is not None or object_value["identity"] is not None:
                raise RollbackError("receipt_manifest_invalid")
        elif object_value["state"] == "present":
            if (
                not isinstance(object_value["id"], str)
                or not object_value["id"]
                or len(object_value["id"]) > 512
                or not isinstance(object_value["identity"], str)
                or not object_value["identity"]
                or len(object_value["identity"]) > 512
                or (
                    object_value["kind"] == "container"
                    and IMAGE_REFERENCE.fullmatch(object_value["identity"]) is None
                )
                or (
                    object_value["kind"] != "container"
                    and object_value["identity"] != object_value["name"]
                )
            ):
                raise RollbackError("receipt_manifest_invalid")
        else:
            raise RollbackError("receipt_manifest_invalid")
    image_references = payload.get("image_references")
    if (
        not isinstance(image_references, list)
        or image_references != sorted(set(image_references))
        or any(not isinstance(value, str) or IMAGE_REFERENCE.fullmatch(value) is None for value in image_references)
    ):
        raise RollbackError("receipt_manifest_invalid")
    if payload.get("listeners") not in ({"loopback_8017": False}, {"loopback_8017": True}):
        raise RollbackError("receipt_manifest_invalid")
    if not isinstance(payload.get("linger"), bool):
        raise RollbackError("receipt_manifest_invalid")


def _load_manifest(receipt: Path, expected_sha256: str | None) -> tuple[dict[str, Any], str]:
    data, _ = _read_regular(
        receipt / "manifest.json",
        maximum=MAX_MANIFEST_BYTES,
        required_mode=0o600,
        required_owner=os.geteuid(),
    )
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and (not SHA256.fullmatch(expected_sha256) or digest != expected_sha256):
        raise RollbackError("receipt_manifest_mismatch")
    payload = _strict_json(data)
    _validate_manifest_payload(payload)
    if canonical_json_bytes(payload) != data:
        raise RollbackError("receipt_manifest_invalid")
    match = RECEIPT_NAME.fullmatch(receipt.name)
    if (
        match is None
        or payload.get("captured_at") != match.group(1)
        or payload.get("source_prefix") != match.group(2)
        or payload.get("source_commit", "")[:12] != match.group(2)
        or payload.get("hostname") != EXPECTED_HOST
    ):
        raise RollbackError("receipt_identity_mismatch")
    return payload, digest


def _load_forward(receipt: Path, manifest_digest: str) -> dict[str, Any]:
    data, _ = _read_regular(
        receipt / "forward-state.json",
        maximum=MAX_MANIFEST_BYTES,
        required_mode=0o600,
        required_owner=os.geteuid(),
    )
    value = _strict_json(data)
    if (
        not isinstance(value, dict)
        or set(value) != {
            "schema", "baseline_manifest_sha256", "transaction_state",
            "rollback_outcome", "files", "directories", "objects", "images"
        }
        or value.get("schema") != FORWARD_SCHEMA
        or value.get("baseline_manifest_sha256") != manifest_digest
        or value.get("transaction_state") not in {"open", "completed"}
        or canonical_json_bytes(value) != data
        or not isinstance(value.get("files"), dict)
        or not isinstance(value.get("directories"), dict)
        or not isinstance(value.get("objects"), dict)
        or not isinstance(value.get("images"), dict)
        or value.get("rollback_outcome") not in {
            "clean",
            "quarantined",
            "acknowledged",
            "retained-data",
        }
    ):
        raise RollbackError("forward_state_invalid")
    allowed_files = {path for path, kind, _sensitive in MANAGED_PATHS if kind == "regular"}
    if not set(value["files"]).issubset(allowed_files) or value["directories"]:
        raise RollbackError("forward_state_invalid")
    for path, descriptor in value["files"].items():
        if (
            not isinstance(path, str)
            or not isinstance(descriptor, dict)
            or set(descriptor) != {"type", "mode", "uid", "gid", "size", "sha256"}
            or descriptor.get("type") != "regular"
            or not isinstance(descriptor.get("mode"), str)
            or re.fullmatch(r"[0-7]{4}", descriptor["mode"]) is None
            or isinstance(descriptor.get("uid"), bool)
            or not isinstance(descriptor.get("uid"), int)
            or descriptor["uid"] < 0
            or isinstance(descriptor.get("gid"), bool)
            or not isinstance(descriptor.get("gid"), int)
            or descriptor["gid"] < 0
            or isinstance(descriptor.get("size"), bool)
            or not isinstance(descriptor.get("size"), int)
            or not 0 <= descriptor["size"] <= MAX_MANAGED_FILE_BYTES
            or not isinstance(descriptor.get("sha256"), str)
            or SHA256.fullmatch(descriptor["sha256"]) is None
        ):
            raise RollbackError("forward_state_invalid")
    allowed_objects = {
        f"{kind}:{name}": (kind, name)
        for kind, name in PODMAN_NAMES
        if kind != "volume"
    }
    if not set(value["objects"]).issubset(allowed_objects):
        raise RollbackError("forward_state_invalid")
    for key, descriptor in value["objects"].items():
        expected_kind, expected_name = allowed_objects[key]
        if (
            not isinstance(descriptor, dict)
            or set(descriptor) != {"kind", "name", "state", "id", "identity"}
            or descriptor.get("kind") != expected_kind
            or descriptor.get("name") != expected_name
            or descriptor.get("state") not in {"intent", "finalized"}
            or (
                descriptor.get("state") == "intent"
                and descriptor.get("id") is not None
            )
            or (
                descriptor.get("state") == "finalized"
                and (
                    not isinstance(descriptor.get("id"), str)
                    or not descriptor["id"]
                    or len(descriptor["id"]) > 512
                )
            )
            or not isinstance(descriptor.get("identity"), str)
            or (
                expected_kind == "container"
                and IMAGE_REFERENCE.fullmatch(descriptor["identity"]) is None
            )
            or (
                expected_kind != "container"
                and descriptor["identity"] != expected_name
            )
        ):
            raise RollbackError("forward_state_invalid")
    image_roles = set(value["images"])
    if image_roles not in (set(), set(IMAGE_ROLES)):
        raise RollbackError("forward_state_invalid")
    duplicate_references: dict[str, dict[str, Any]] = {}
    for role in IMAGE_ROLES:
        if role not in value["images"]:
            continue
        descriptor = value["images"][role]
        reference = descriptor.get("reference") if isinstance(descriptor, dict) else None
        if (
            not _valid_image_reference(reference)
            or not _valid_image_descriptor(descriptor, reference)
        ):
            raise RollbackError("forward_state_invalid")
        prior = duplicate_references.get(reference)
        if prior is not None and prior != descriptor:
            raise RollbackError("forward_state_invalid")
        duplicate_references[reference] = descriptor
    return value


def _require_open_transaction(forward: dict[str, Any]) -> None:
    if forward["transaction_state"] != "open":
        raise RollbackError("transaction_closed")
    if forward["rollback_outcome"] != "clean":
        raise RollbackError("rollback_drift_quarantined")


@contextmanager
def _receipt_lock(receipt: Path):
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    receipt = Path(receipt)
    parent_descriptor = -1
    expected_descriptor = -1
    try:
        parent_before = receipt.parent.lstat()
        parent_descriptor = os.open(receipt.parent, _DIRECTORY_FLAGS)
        parent_status = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent_status.st_mode)
            or stat.S_ISLNK(parent_before.st_mode)
            or (parent_before.st_dev, parent_before.st_ino)
            != (parent_status.st_dev, parent_status.st_ino)
            or parent_status.st_uid != os.geteuid()
            or stat.S_IMODE(parent_status.st_mode) != 0o700
        ):
            raise RollbackError("receipt_lock_invalid")
        expected_descriptor = os.open(
            ".transaction.lock",
            flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        expected_status = os.fstat(expected_descriptor)
        linked_status = os.stat(
            ".transaction.lock",
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            (expected_status.st_dev, expected_status.st_ino)
            != (linked_status.st_dev, linked_status.st_ino)
        ):
            raise RollbackError("receipt_lock_invalid")
    except RollbackError:
        if expected_descriptor >= 0:
            os.close(expected_descriptor)
        raise
    except OSError as error:
        if expected_descriptor >= 0:
            os.close(expected_descriptor)
        raise RollbackError("receipt_lock_invalid") from error
    finally:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
    inherited_value = os.environ.get(ROLLBACK_LEASE_ENV)
    inherited = inherited_value is not None
    if inherited:
        if (
            len(inherited_value) > 10
            or re.fullmatch(r"(?:0|[1-9][0-9]*)", inherited_value) is None
        ):
            os.close(expected_descriptor)
            raise RollbackError("receipt_lock_invalid")
        descriptor = int(inherited_value)
        try:
            try:
                status = os.fstat(descriptor)
            except (OSError, OverflowError) as error:
                raise RollbackError("receipt_lock_invalid") from error
            if (
                (status.st_dev, status.st_ino)
                != (expected_status.st_dev, expected_status.st_ino)
            ):
                raise RollbackError("receipt_lock_invalid")
        finally:
            os.close(expected_descriptor)
    else:
        descriptor = expected_descriptor
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or status.st_uid != os.geteuid()
            or stat.S_IMODE(status.st_mode) != 0o600
            or status.st_size != 0
            or (fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE) != os.O_RDWR
        ):
            raise RollbackError("receipt_lock_invalid")
        fcntl.flock(
            descriptor,
            fcntl.LOCK_EX | (fcntl.LOCK_NB if inherited else 0),
        )
        yield descriptor
    except OSError as error:
        raise RollbackError("receipt_lock_invalid") from error
    finally:
        if not inherited:
            os.close(descriptor)


def _validate_lease_command(command: list[str] | tuple[str, ...]) -> list[str]:
    if (
        not isinstance(command, (list, tuple))
        or not 1 <= len(command) <= MAX_LEASE_COMMAND_ARGUMENTS
    ):
        raise RollbackError("lease_command_invalid")
    normalized: list[str] = []
    total_bytes = 0
    for argument in command:
        if not isinstance(argument, str) or not argument or "\x00" in argument:
            raise RollbackError("lease_command_invalid")
        try:
            argument_bytes = argument.encode("utf-8")
        except UnicodeEncodeError as error:
            raise RollbackError("lease_command_invalid") from error
        if len(argument_bytes) > MAX_LEASE_COMMAND_BYTES:
            raise RollbackError("lease_command_invalid")
        total_bytes += len(argument_bytes) + 1
        if total_bytes > MAX_LEASE_COMMAND_BYTES:
            raise RollbackError("lease_command_invalid")
        normalized.append(argument)
    return normalized


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError as error:
        raise RollbackError("lease_command_failed") from error


def _terminate_residual_process_group(process_group: int) -> None:
    if not _process_group_exists(process_group):
        return
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError as error:
        raise RollbackError("lease_command_failed") from error
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if not _process_group_exists(process_group):
            return
        time.sleep(0.01)
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError as error:
        raise RollbackError("lease_command_failed") from error
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if not _process_group_exists(process_group):
            return
        time.sleep(0.01)
    raise RollbackError("lease_command_failed")


def _same_open_file_description(
    descriptor: int,
    process_id: int,
    candidate_descriptor: int,
) -> bool:
    pidfd = -1
    duplicate = -1
    try:
        pidfd = os.pidfd_open(process_id, 0)
        libc = ctypes.CDLL(None, use_errno=True)
        duplicate = int(
            libc.syscall(
                PIDFD_GETFD_SYSCALL,
                pidfd,
                candidate_descriptor,
                0,
            )
        )
        if duplicate < 0:
            failure = ctypes.get_errno()
            if failure in {errno.ESRCH, errno.EBADF}:
                return False
            raise RollbackError("lease_command_failed")
        original = os.lseek(descriptor, 0, os.SEEK_CUR)
        candidate_original = os.lseek(duplicate, 0, os.SEEK_CUR)
        marker = original + 1_048_583
        if marker == candidate_original:
            marker += 1
        os.lseek(descriptor, marker, os.SEEK_SET)
        same = os.lseek(duplicate, 0, os.SEEK_CUR) == marker
        os.lseek(descriptor, original, os.SEEK_SET)
        return same
    except RollbackError:
        raise
    except (OSError, OverflowError) as error:
        raise RollbackError("lease_command_failed") from error
    finally:
        if duplicate >= 0:
            os.close(duplicate)
        if pidfd >= 0:
            os.close(pidfd)


def _lease_holder_pids(descriptor: int) -> set[int]:
    try:
        expected = os.fstat(descriptor)
        holders: set[int] = set()
        process_count = 0
        descriptor_count = 0
        with os.scandir("/proc") as processes:
            for process in processes:
                if not process.name.isascii() or not process.name.isdecimal():
                    continue
                process_count += 1
                if process_count > MAX_LEASE_SCAN_PROCESSES:
                    raise RollbackError("lease_command_failed")
                try:
                    status_descriptor = os.open(
                        f"/proc/{process.name}/status",
                        os.O_RDONLY
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                    )
                    try:
                        status_bytes = os.read(status_descriptor, 65_537)
                    finally:
                        os.close(status_descriptor)
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    continue
                if len(status_bytes) > 65_536:
                    raise RollbackError("lease_command_failed")
                namespace_lines = [
                    line for line in status_bytes.splitlines() if line.startswith(b"NSpid:")
                ]
                if len(namespace_lines) > 1:
                    raise RollbackError("lease_command_failed")
                if namespace_lines:
                    namespace_values = namespace_lines[0][len(b"NSpid:") :].split()
                    if (
                        not namespace_values
                        or len(namespace_values) > 32
                        or any(
                            not value.isascii() or not value.isdigit()
                            for value in namespace_values
                        )
                    ):
                        raise RollbackError("lease_command_failed")
                    pid = int(namespace_values[-1])
                else:
                    pid = int(process.name)
                if pid == os.getpid():
                    continue
                try:
                    with os.scandir(f"/proc/{process.name}/fd") as descriptors:
                        for candidate in descriptors:
                            descriptor_count += 1
                            if descriptor_count > MAX_LEASE_SCAN_DESCRIPTORS:
                                raise RollbackError("lease_command_failed")
                            try:
                                status = os.stat(candidate.path)
                            except (FileNotFoundError, ProcessLookupError):
                                continue
                            except PermissionError:
                                continue
                            if (status.st_dev, status.st_ino) == (
                                expected.st_dev,
                                expected.st_ino,
                            ) and _same_open_file_description(
                                descriptor,
                                pid,
                                int(candidate.name),
                            ):
                                holders.add(pid)
                                break
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    continue
        return holders
    except RollbackError:
        raise
    except OSError as error:
        raise RollbackError("lease_command_failed") from error


def _terminate_residual_lease_holders(descriptor: int) -> None:
    holders = _lease_holder_pids(descriptor)
    if any(pid <= 1 for pid in holders):
        raise RollbackError("lease_command_failed")
    for pid in sorted(holders):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError as error:
            raise RollbackError("lease_command_failed") from error
    deadline = time.monotonic() + 1.0
    while holders and time.monotonic() < deadline:
        time.sleep(0.01)
        holders = _lease_holder_pids(descriptor)
    for pid in sorted(holders):
        if pid <= 1:
            raise RollbackError("lease_command_failed")
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as error:
            raise RollbackError("lease_command_failed") from error
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        holders = _lease_holder_pids(descriptor)
        if not holders:
            return
        time.sleep(0.01)
    raise RollbackError("lease_command_failed")


def lease_exec(
    receipt: Path,
    expected_manifest_sha256: str,
    command: list[str] | tuple[str, ...],
) -> int:
    _verify_exact_target()
    receipt = Path(receipt)
    normalized_command = _validate_lease_command(command)
    with _receipt_lock(receipt) as descriptor:
        digest = verify_receipt(receipt, expected_manifest_sha256)
        _require_open_transaction(_load_forward(receipt, digest))
        environment = dict(os.environ)
        environment[ROLLBACK_LEASE_ENV] = str(descriptor)
        process: subprocess.Popen[Any] | None = None
        pending_signal: int | None = None
        previous_handlers: dict[int, Any] = {}

        def forward_signal(signum: int, _frame: Any) -> None:
            nonlocal pending_signal
            if pending_signal is not None:
                return
            pending_signal = signum
            if process is not None:
                try:
                    os.killpg(process.pid, signum)
                except ProcessLookupError:
                    pass

        try:
            os.set_inheritable(descriptor, True)
            for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                previous_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, forward_signal)
            process = subprocess.Popen(
                normalized_command,
                env=environment,
                pass_fds=(descriptor,),
                start_new_session=True,
            )
            if pending_signal is not None:
                os.killpg(process.pid, pending_signal)
            while True:
                try:
                    returncode = process.wait(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    continue
            _terminate_residual_process_group(process.pid)
        except (OSError, ValueError) as error:
            raise RollbackError("lease_command_failed") from error
        finally:
            cleanup_error: RollbackError | None = None
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
            try:
                _terminate_residual_lease_holders(descriptor)
            except RollbackError as error:
                cleanup_error = error
            for signum, previous_handler in previous_handlers.items():
                signal.signal(signum, previous_handler)
            try:
                os.set_inheritable(descriptor, False)
            except OSError as error:
                raise RollbackError("receipt_lock_invalid") from error
            if cleanup_error is not None:
                raise cleanup_error
        return returncode


def verify_receipt(
    receipt: Path,
    expected_manifest_sha256: str | None = None,
    *,
    hostname_getter: Callable[[], str] | None = None,
) -> str:
    receipt = Path(receipt)
    try:
        status = receipt.lstat()
    except OSError as error:
        raise RollbackError("receipt_path_invalid") from error
    if (
        not stat.S_ISDIR(status.st_mode)
        or stat.S_ISLNK(status.st_mode)
        or stat.S_IMODE(status.st_mode) != 0o700
        or status.st_uid != os.geteuid()
    ):
        raise RollbackError("receipt_path_invalid")
    manifest, digest = _load_manifest(receipt, expected_manifest_sha256)
    if hostname_getter is not None and hostname_getter() != manifest["hostname"]:
        raise RollbackError("hostname_mismatch")
    expected_payloads: set[str] = set()
    managed = manifest.get("managed_paths")
    if not isinstance(managed, list) or [entry.get("path") for entry in managed] != [path for path, _, _ in MANAGED_PATHS]:
        raise RollbackError("receipt_inventory_invalid")
    entry_keys = {
        "path", "state", "type", "mode", "uid", "gid", "size", "sha256",
        "payload", "sensitive",
    }
    for entry, (_path, expected_type, expected_sensitive) in zip(managed, MANAGED_PATHS):
        if (
            not isinstance(entry, dict)
            or set(entry) != entry_keys
            or entry.get("sensitive") is not expected_sensitive
        ):
            raise RollbackError("receipt_inventory_invalid")
        if entry.get("state") == "absent":
            if any(entry.get(field) is not None for field in ("type", "mode", "uid", "gid", "size", "sha256", "payload")):
                raise RollbackError("receipt_inventory_invalid")
            continue
        if entry.get("state") != "present" or entry.get("type") != expected_type:
            raise RollbackError("receipt_inventory_invalid")
        if (
            not isinstance(entry.get("mode"), str)
            or re.fullmatch(r"[0-7]{4}", entry["mode"]) is None
            or isinstance(entry.get("uid"), bool)
            or not isinstance(entry.get("uid"), int)
            or entry["uid"] < 0
            or isinstance(entry.get("gid"), bool)
            or not isinstance(entry.get("gid"), int)
            or entry["gid"] < 0
        ):
            raise RollbackError("receipt_inventory_invalid")
        if expected_type == "regular":
            payload_name = entry.get("payload")
            if (
                not isinstance(payload_name, str)
                or not re.fullmatch(r"payload/[0-9]{4}\.bin", payload_name)
                or isinstance(entry.get("size"), bool)
                or not isinstance(entry.get("size"), int)
                or not 0 <= entry["size"] <= MAX_MANAGED_FILE_BYTES
                or not isinstance(entry.get("sha256"), str)
                or SHA256.fullmatch(entry["sha256"]) is None
            ):
                raise RollbackError("receipt_inventory_invalid")
            data, _ = _read_regular(
                receipt / payload_name,
                maximum=MAX_MANAGED_FILE_BYTES,
                required_mode=0o600,
                required_owner=os.geteuid(),
            )
            if len(data) != entry.get("size") or hashlib.sha256(data).hexdigest() != entry.get("sha256"):
                raise RollbackError("receipt_payload_mismatch")
            expected_payloads.add(payload_name)
        elif any(entry.get(field) is not None for field in ("size", "sha256", "payload")):
            raise RollbackError("receipt_inventory_invalid")
    payload_directory = receipt / "payload"
    try:
        payload_status = payload_directory.lstat()
    except OSError as error:
        raise RollbackError("receipt_payload_mismatch") from error
    if (
        not stat.S_ISDIR(payload_status.st_mode)
        or stat.S_ISLNK(payload_status.st_mode)
        or stat.S_IMODE(payload_status.st_mode) != 0o700
        or payload_status.st_uid != os.geteuid()
    ):
        raise RollbackError("receipt_payload_mismatch")
    actual_payloads: set[str] = set()
    try:
        with os.scandir(payload_directory) as payload_entries:
            for index, payload_entry in enumerate(payload_entries):
                if index > len(expected_payloads):
                    raise RollbackError("receipt_payload_mismatch")
                entry_status = payload_entry.stat(follow_symlinks=False)
                if (
                    not stat.S_ISREG(entry_status.st_mode)
                    or stat.S_ISLNK(entry_status.st_mode)
                    or entry_status.st_nlink != 1
                ):
                    raise RollbackError("receipt_payload_mismatch")
                actual_payloads.add(f"payload/{payload_entry.name}")
    except RollbackError:
        raise
    except OSError as error:
        raise RollbackError("receipt_payload_mismatch") from error
    if actual_payloads != expected_payloads:
        raise RollbackError("receipt_payload_mismatch")
    _load_forward(receipt, digest)
    required_names = {"manifest.json", "forward-state.json", "payload"}
    allowed_names = required_names | {"rollback.lock", "quarantine"}
    receipt_names: set[str] = set()
    try:
        with os.scandir(receipt) as receipt_entries:
            for index, receipt_entry in enumerate(receipt_entries):
                if index >= len(allowed_names):
                    raise RollbackError("receipt_inventory_invalid")
                receipt_names.add(receipt_entry.name)
    except RollbackError:
        raise
    except OSError as error:
        raise RollbackError("receipt_inventory_invalid") from error
    if not required_names.issubset(receipt_names) or not receipt_names.issubset(allowed_names):
        raise RollbackError("receipt_inventory_invalid")
    if "rollback.lock" in receipt_names:
        lock_data, _ = _read_regular(
            receipt / "rollback.lock",
            maximum=0,
            required_mode=0o600,
            required_owner=os.geteuid(),
        )
        if lock_data:
            raise RollbackError("receipt_lock_invalid")
    if "quarantine" in receipt_names:
        quarantine_status = (receipt / "quarantine").lstat()
        if (
            not stat.S_ISDIR(quarantine_status.st_mode)
            or stat.S_ISLNK(quarantine_status.st_mode)
            or stat.S_IMODE(quarantine_status.st_mode) != 0o700
            or quarantine_status.st_uid != os.geteuid()
        ):
            raise RollbackError("receipt_inventory_invalid")
    return digest


def authorize_file(
    receipt: Path,
    expected_manifest_sha256: str,
    logical_path: str,
    source: Path,
    mode: int,
    uid: int,
    gid: int,
) -> None:
    _verify_exact_target()
    receipt = Path(receipt)
    allowed = {path for path, expected_type, _ in MANAGED_PATHS if expected_type == "regular"}
    if logical_path not in allowed or mode < 0 or mode > 0o7777 or uid < 0 or gid < 0:
        raise RollbackError("forward_state_invalid")
    data, _ = _read_regular(Path(source), maximum=MAX_MANAGED_FILE_BYTES)
    with _receipt_lock(receipt):
        digest = verify_receipt(receipt, expected_manifest_sha256)
        forward = _load_forward(receipt, digest)
        _require_open_transaction(forward)
        forward["files"][logical_path] = {
            "type": "regular",
            "mode": f"{mode:04o}",
            "uid": uid,
            "gid": gid,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        _replace_canonical(receipt / "forward-state.json", forward)


def authorize_object(
    receipt: Path,
    expected_manifest_sha256: str,
    kind: str,
    name: str,
    identity: str,
    *,
    executor: Any | None = None,
) -> None:
    _verify_exact_target()
    receipt = Path(receipt)
    allowed = {(object_kind, object_name) for object_kind, object_name in PODMAN_NAMES}
    if (kind, name) not in allowed or kind == "volume":
        raise RollbackError("forward_state_invalid")
    if kind == "container":
        if not IMAGE_REFERENCE.fullmatch(identity):
            raise RollbackError("forward_state_invalid")
    elif identity != name:
        raise RollbackError("forward_state_invalid")
    with _receipt_lock(receipt):
        digest = verify_receipt(receipt, expected_manifest_sha256)
        manifest, _ = _load_manifest(receipt, digest)
        forward = _load_forward(receipt, digest)
        _require_open_transaction(forward)
        if executor is None:
            executor = SystemExecutor()
        baseline = next(
            value
            for value in manifest["podman_objects"]
            if value["kind"] == kind and value["name"] == name
        )
        current = executor.current_object(kind, name)
        if not _valid_object_descriptor(current, kind, name) or current != baseline:
            raise RollbackError("host_state_invalid")
        key = f"{kind}:{name}"
        intent = {
            "kind": kind,
            "name": name,
            "state": "intent",
            "id": None,
            "identity": identity,
        }
        existing = forward["objects"].get(key)
        if existing is not None:
            if existing != intent:
                raise RollbackError("forward_state_invalid")
            return
        forward["objects"][key] = intent
        _replace_canonical(receipt / "forward-state.json", forward)


def finalize_object(
    receipt: Path,
    expected_manifest_sha256: str,
    kind: str,
    name: str,
    identity: str,
    *,
    executor: Any | None = None,
) -> None:
    _verify_exact_target()
    receipt = Path(receipt)
    allowed = {(object_kind, object_name) for object_kind, object_name in PODMAN_NAMES}
    if (kind, name) not in allowed or kind == "volume":
        raise RollbackError("forward_state_invalid")
    if kind == "container":
        if IMAGE_REFERENCE.fullmatch(identity) is None:
            raise RollbackError("forward_state_invalid")
    elif identity != name:
        raise RollbackError("forward_state_invalid")
    with _receipt_lock(receipt):
        digest = verify_receipt(receipt, expected_manifest_sha256)
        forward = _load_forward(receipt, digest)
        _require_open_transaction(forward)
        key = f"{kind}:{name}"
        intent = forward["objects"].get(key)
        if (
            not isinstance(intent, dict)
            or intent.get("kind") != kind
            or intent.get("name") != name
            or intent.get("identity") != identity
            or intent.get("state") not in {"intent", "finalized"}
        ):
            raise RollbackError("forward_state_invalid")
        if executor is None:
            executor = SystemExecutor()
        current = executor.current_object(kind, name)
        if (
            not _valid_object_descriptor(current, kind, name)
            or current.get("state") != "present"
            or current.get("identity") != identity
        ):
            raise RollbackError("host_state_invalid")
        if intent["state"] == "finalized":
            if intent.get("id") != current.get("id"):
                raise RollbackError("host_state_invalid")
            return
        forward["objects"][key] = {
            "kind": kind,
            "name": name,
            "state": "finalized",
            "id": current["id"],
            "identity": identity,
        }
        _replace_canonical(receipt / "forward-state.json", forward)


def authorize_images(
    receipt: Path,
    expected_manifest_sha256: str,
    references: dict[str, str],
    *,
    executor: Any | None = None,
) -> None:
    _verify_exact_target()
    if (
        not isinstance(references, dict)
        or set(references) != set(IMAGE_ROLES)
        or any(not _valid_image_reference(references[role]) for role in IMAGE_ROLES)
    ):
        raise RollbackError("forward_state_invalid")
    receipt = Path(receipt)
    if executor is None:
        executor = SystemExecutor()
    with _receipt_lock(receipt):
        digest = verify_receipt(receipt, expected_manifest_sha256)
        forward = _load_forward(receipt, digest)
        _require_open_transaction(forward)
        if forward["images"]:
            existing_references = {
                role: forward["images"][role]["reference"]
                for role in IMAGE_ROLES
            }
            if existing_references != references:
                raise RollbackError("forward_state_invalid")
            return
        current_by_reference: dict[str, dict[str, Any]] = {}
        ledger: dict[str, dict[str, Any]] = {}
        for role in IMAGE_ROLES:
            reference = references[role]
            if reference not in current_by_reference:
                current = executor.current_image(reference)
                if not _valid_image_descriptor(current, reference):
                    raise RollbackError("host_state_invalid")
                current_by_reference[reference] = dict(current)
            ledger[role] = dict(current_by_reference[reference])
        forward["images"] = ledger
        _replace_canonical(receipt / "forward-state.json", forward)


def mark_completed(
    receipt: Path,
    expected_manifest_sha256: str,
) -> None:
    _verify_exact_target()
    receipt = Path(receipt)
    with _receipt_lock(receipt):
        digest = verify_receipt(receipt, expected_manifest_sha256)
        forward = _load_forward(receipt, digest)
        if forward["transaction_state"] == "completed":
            return
        _require_open_transaction(forward)
        required_files = {
            path for path, expected_type, _sensitive in MANAGED_PATHS
            if expected_type == "regular"
        }
        required_objects = {
            f"{kind}:{name}" for kind, name in PODMAN_NAMES if kind != "volume"
        }
        if (
            set(forward["files"]) != required_files
            or set(forward["images"]) != set(IMAGE_ROLES)
            or set(forward["objects"]) != required_objects
            or any(
                descriptor.get("state") != "finalized"
                for descriptor in forward["objects"].values()
            )
        ):
            raise RollbackError("transaction_incomplete")
        forward["transaction_state"] = "completed"
        _replace_canonical(receipt / "forward-state.json", forward)


def _unit_is_fresh(unit: Any) -> bool:
    return (
        isinstance(unit, dict)
        and unit.get("load_state") == "not-found"
        and unit.get("unit_file_state") == "disabled"
        and unit.get("active_state") == "inactive"
        and unit.get("sub_state") == "dead"
    )


def _runtime_state_is_fresh(state: Any) -> bool:
    if not isinstance(state, dict):
        return False
    units = state.get("units")
    objects = state.get("podman_objects")
    return (
        isinstance(units, list)
        and len(units) == len(UNIT_NAMES)
        and [
            (unit.get("scope"), unit.get("name"))
            for unit in units
            if isinstance(unit, dict)
        ] == list(UNIT_NAMES)
        and all(_unit_is_fresh(unit) for unit in units)
        and isinstance(objects, list)
        and len(objects) == len(PODMAN_NAMES)
        and [
            (value.get("kind"), value.get("name"))
            for value in objects
            if isinstance(value, dict)
        ] == list(PODMAN_NAMES)
        and all(
            isinstance(value, dict)
            and value.get("state") == "absent"
            and value.get("id") is None
            and value.get("identity") is None
            for value in objects
        )
        and state.get("listeners") == {"loopback_8017": False}
        and state.get("linger") is False
    )


def verify_fresh_install(
    receipt: Path,
    expected_manifest_sha256: str,
    *,
    root: Path = Path("/"),
    hostname_getter: Callable[[], str] = lambda: socket.gethostname().split(".", 1)[0],
    executor: Any | None = None,
) -> str:
    _verify_exact_target()
    receipt = Path(receipt)
    root = Path(root).resolve()
    if executor is None:
        executor = SystemExecutor()
    with _receipt_lock(receipt):
        digest = verify_receipt(
            receipt,
            expected_manifest_sha256,
            hostname_getter=hostname_getter,
        )
        manifest, _ = _load_manifest(receipt, digest)
        forward = _load_forward(receipt, digest)
        _require_open_transaction(forward)
        if (
            any(entry.get("state") != "absent" for entry in manifest["managed_paths"])
            or any(identity.get("state") != "absent" for identity in manifest["identities"])
            or not _runtime_state_is_fresh(
                {
                    "units": manifest["units"],
                    "podman_objects": manifest["podman_objects"],
                    "listeners": manifest["listeners"],
                    "linger": manifest["linger"],
                }
            )
        ):
            raise RollbackError("fresh_install_required")

        try:
            for logical_path, _expected_type, _sensitive in MANAGED_PATHS:
                with _open_managed_parent(root, logical_path, create=False) as (
                    parent,
                    name,
                ):
                    current, _identity_value = _descriptor_at(parent, name)
                if current.get("state") != "absent":
                    raise RollbackError("fresh_install_required")
        except RollbackError as error:
            if error.code == "fresh_install_required":
                raise
            raise RollbackError("fresh_install_required") from error

        if any(_identity(name).get("state") != "absent" for name in (
            "lil-tweak",
            "lil-tweak-tunnel",
        )):
            raise RollbackError("fresh_install_required")
        if not _runtime_state_is_fresh(executor.capture_state()):
            raise RollbackError("fresh_install_required")
        return digest


def acknowledge_quarantine(
    receipt: Path,
    expected_manifest_sha256: str,
) -> None:
    _verify_exact_target()
    receipt = Path(receipt)
    with _receipt_lock(receipt):
        digest = verify_receipt(receipt, expected_manifest_sha256)
        forward = _load_forward(receipt, digest)
        if forward["rollback_outcome"] in {"clean", "retained-data"}:
            raise RollbackError("quarantine_not_pending")
        if forward["rollback_outcome"] == "acknowledged":
            return
        forward["rollback_outcome"] = "acknowledged"
        _replace_canonical(receipt / "forward-state.json", forward)


def _matches(current: dict[str, Any], expected: dict[str, Any] | None) -> bool:
    if expected is None or current.get("state") != "present":
        return False
    fields = ("type", "mode", "uid", "gid")
    if any(current.get(field) != expected.get(field) for field in fields):
        return False
    if expected.get("type") == "regular":
        return current.get("size") == expected.get("size") and current.get("sha256") == expected.get("sha256")
    return True


def _baseline_descriptor(entry: dict[str, Any]) -> dict[str, Any] | None:
    if entry["state"] != "present":
        return None
    result = {field: entry[field] for field in ("type", "mode", "uid", "gid")}
    if entry["type"] == "regular":
        result.update(size=entry["size"], sha256=entry["sha256"])
    return result


def _mark_quarantined(receipt: Path, forward: dict[str, Any]) -> None:
    if forward["rollback_outcome"] == "quarantined":
        return
    forward["rollback_outcome"] = "quarantined"
    _replace_canonical(receipt / "forward-state.json", forward)


_QUARANTINE_STAT_FIELDS = (
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


def _quarantine_signature(status: os.stat_result) -> tuple[int, ...]:
    return tuple(getattr(status, field) for field in _QUARANTINE_STAT_FIELDS)


def _remove_copied_quarantine_at(
    parent: int,
    name: str,
    snapshot: dict[str, Any],
) -> None:
    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != snapshot["destination_identity"]:
        raise RollbackError("rollback_quarantine_failed")
    if snapshot["kind"] != "directory":
        os.unlink(name, dir_fd=parent)
        os.fsync(parent)
        return
    child = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
    try:
        bound = os.fstat(child)
        if (bound.st_dev, bound.st_ino) != snapshot["destination_identity"]:
            raise RollbackError("rollback_quarantine_failed")
        actual_names = sorted(os.listdir(child))
        expected_names = sorted(snapshot["children"])
        if actual_names != expected_names:
            raise RollbackError("rollback_quarantine_failed")
        for child_name in expected_names:
            _remove_copied_quarantine_at(
                child,
                child_name,
                snapshot["children"][child_name],
            )
    finally:
        os.close(child)
    os.rmdir(name, dir_fd=parent)
    os.fsync(parent)


def _quarantine_copy_at(
    source_parent: int,
    source_name: str,
    destination_parent: int,
    destination_name: str,
    *,
    depth: int,
    budget: dict[str, int],
) -> dict[str, Any]:
    if depth > MAX_QUARANTINE_DEPTH:
        raise RollbackError("rollback_quarantine_failed")
    budget["entries"] += 1
    if budget["entries"] > MAX_QUARANTINE_ENTRIES:
        raise RollbackError("rollback_quarantine_failed")
    source_entry = os.stat(
        source_name,
        dir_fd=source_parent,
        follow_symlinks=False,
    )
    if source_entry.st_dev != budget["device"]:
        raise RollbackError("rollback_quarantine_failed")
    source_signature = _quarantine_signature(source_entry)

    if stat.S_ISREG(source_entry.st_mode):
        if source_entry.st_nlink != 1 or source_entry.st_size < 0:
            raise RollbackError("rollback_quarantine_failed")
        budget["bytes"] += source_entry.st_size
        if budget["bytes"] > MAX_QUARANTINE_BYTES:
            raise RollbackError("rollback_quarantine_failed")
        source_descriptor = -1
        destination_descriptor = -1
        destination_identity: tuple[int, int] | None = None
        try:
            source_descriptor = os.open(
                source_name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=source_parent,
            )
            source_before = os.fstat(source_descriptor)
            if (
                not stat.S_ISREG(source_before.st_mode)
                or _quarantine_signature(source_before) != source_signature
            ):
                raise RollbackError("managed_path_changed")
            destination_descriptor = os.open(
                destination_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=destination_parent,
            )
            destination_status = os.fstat(destination_descriptor)
            destination_identity = (
                destination_status.st_dev,
                destination_status.st_ino,
            )
            remaining = source_before.st_size
            content_digest = hashlib.sha256()
            while remaining:
                chunk = os.read(source_descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise RollbackError("managed_path_changed")
                content_digest.update(chunk)
                offset = 0
                while offset < len(chunk):
                    written = os.write(destination_descriptor, chunk[offset:])
                    if written <= 0:
                        raise RollbackError("rollback_quarantine_failed")
                    offset += written
                remaining -= len(chunk)
            if os.read(source_descriptor, 1):
                raise RollbackError("managed_path_changed")
            source_after = os.fstat(source_descriptor)
            linked_after = os.stat(
                source_name,
                dir_fd=source_parent,
                follow_symlinks=False,
            )
            if (
                _quarantine_signature(source_after) != source_signature
                or _quarantine_signature(linked_after) != source_signature
            ):
                raise RollbackError("managed_path_changed")
            os.fchown(destination_descriptor, source_before.st_uid, source_before.st_gid)
            os.fchmod(destination_descriptor, stat.S_IMODE(source_before.st_mode))
            os.utime(
                destination_descriptor,
                ns=(source_before.st_atime_ns, source_before.st_mtime_ns),
            )
            os.fsync(destination_descriptor)
            copied = os.fstat(destination_descriptor)
            if (
                copied.st_size != source_before.st_size
                or copied.st_uid != source_before.st_uid
                or copied.st_gid != source_before.st_gid
                or stat.S_IMODE(copied.st_mode)
                != stat.S_IMODE(source_before.st_mode)
            ):
                raise RollbackError("rollback_quarantine_failed")
            os.fsync(destination_parent)
            return {
                "kind": "regular",
                "source_signature": source_signature,
                "sha256": content_digest.hexdigest(),
                "destination_identity": destination_identity,
            }
        except Exception:
            if destination_descriptor >= 0:
                os.close(destination_descriptor)
                destination_descriptor = -1
            if destination_identity is not None:
                try:
                    partial = os.stat(
                        destination_name,
                        dir_fd=destination_parent,
                        follow_symlinks=False,
                    )
                    if (partial.st_dev, partial.st_ino) == destination_identity:
                        os.unlink(destination_name, dir_fd=destination_parent)
                        os.fsync(destination_parent)
                except OSError:
                    pass
            raise
        finally:
            if destination_descriptor >= 0:
                os.close(destination_descriptor)
            if source_descriptor >= 0:
                os.close(source_descriptor)

    if stat.S_ISLNK(source_entry.st_mode):
        if source_entry.st_nlink != 1:
            raise RollbackError("rollback_quarantine_failed")
        target = os.readlink(source_name, dir_fd=source_parent)
        try:
            target_size = len(target.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise RollbackError("rollback_quarantine_failed") from error
        budget["bytes"] += target_size
        if (
            target_size > MAX_QUARANTINE_SYMLINK_BYTES
            or budget["bytes"] > MAX_QUARANTINE_BYTES
        ):
            raise RollbackError("rollback_quarantine_failed")
        destination_identity = None
        try:
            os.symlink(target, destination_name, dir_fd=destination_parent)
            destination_status = os.stat(
                destination_name,
                dir_fd=destination_parent,
                follow_symlinks=False,
            )
            destination_identity = (
                destination_status.st_dev,
                destination_status.st_ino,
            )
            os.chown(
                destination_name,
                source_entry.st_uid,
                source_entry.st_gid,
                dir_fd=destination_parent,
                follow_symlinks=False,
            )
            destination_after = os.stat(
                destination_name,
                dir_fd=destination_parent,
                follow_symlinks=False,
            )
            if (
                (destination_after.st_dev, destination_after.st_ino)
                != destination_identity
                or destination_after.st_uid != source_entry.st_uid
                or destination_after.st_gid != source_entry.st_gid
                or not stat.S_ISLNK(destination_after.st_mode)
            ):
                raise RollbackError("rollback_quarantine_failed")
            linked_after = os.stat(
                source_name,
                dir_fd=source_parent,
                follow_symlinks=False,
            )
            if (
                _quarantine_signature(linked_after) != source_signature
                or os.readlink(source_name, dir_fd=source_parent) != target
            ):
                raise RollbackError("managed_path_changed")
            os.fsync(destination_parent)
            return {
                "kind": "symlink",
                "source_signature": source_signature,
                "target": target,
                "destination_identity": destination_identity,
            }
        except Exception:
            if destination_identity is not None:
                try:
                    partial = os.stat(
                        destination_name,
                        dir_fd=destination_parent,
                        follow_symlinks=False,
                    )
                    if (partial.st_dev, partial.st_ino) == destination_identity:
                        os.unlink(destination_name, dir_fd=destination_parent)
                        os.fsync(destination_parent)
                except OSError:
                    pass
            raise

    if not stat.S_ISDIR(source_entry.st_mode):
        raise RollbackError("rollback_quarantine_failed")
    source_descriptor = -1
    destination_descriptor = -1
    destination_identity = None
    children: dict[str, dict[str, Any]] = {}
    try:
        source_descriptor = os.open(
            source_name,
            _DIRECTORY_FLAGS,
            dir_fd=source_parent,
        )
        source_before = os.fstat(source_descriptor)
        if (
            not stat.S_ISDIR(source_before.st_mode)
            or _quarantine_signature(source_before) != source_signature
        ):
            raise RollbackError("managed_path_changed")
        os.mkdir(destination_name, 0o700, dir_fd=destination_parent)
        destination_descriptor = os.open(
            destination_name,
            _DIRECTORY_FLAGS,
            dir_fd=destination_parent,
        )
        destination_status = os.fstat(destination_descriptor)
        destination_identity = (
            destination_status.st_dev,
            destination_status.st_ino,
        )
        source_names = sorted(os.listdir(source_descriptor))
        if len(source_names) + budget["entries"] > MAX_QUARANTINE_ENTRIES:
            raise RollbackError("rollback_quarantine_failed")
        for child_name in source_names:
            children[child_name] = _quarantine_copy_at(
                source_descriptor,
                child_name,
                destination_descriptor,
                child_name,
                depth=depth + 1,
                budget=budget,
            )
        if sorted(os.listdir(source_descriptor)) != source_names:
            raise RollbackError("managed_path_changed")
        source_after = os.fstat(source_descriptor)
        linked_after = os.stat(
            source_name,
            dir_fd=source_parent,
            follow_symlinks=False,
        )
        if (
            _quarantine_signature(source_after) != source_signature
            or _quarantine_signature(linked_after) != source_signature
        ):
            raise RollbackError("managed_path_changed")
        os.fchown(destination_descriptor, source_before.st_uid, source_before.st_gid)
        os.fchmod(destination_descriptor, stat.S_IMODE(source_before.st_mode))
        os.utime(
            destination_descriptor,
            ns=(source_before.st_atime_ns, source_before.st_mtime_ns),
        )
        os.fsync(destination_descriptor)
        os.fsync(destination_parent)
        return {
            "kind": "directory",
            "source_signature": source_signature,
            "children": children,
            "destination_identity": destination_identity,
        }
    except Exception:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
            destination_descriptor = -1
        if destination_identity is not None:
            partial_snapshot = {
                "kind": "directory",
                "children": children,
                "destination_identity": destination_identity,
            }
            try:
                _remove_copied_quarantine_at(
                    destination_parent,
                    destination_name,
                    partial_snapshot,
                )
            except (OSError, RollbackError):
                pass
        raise
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        if source_descriptor >= 0:
            os.close(source_descriptor)


def _verify_quarantine_source_at(
    parent: int,
    name: str,
    snapshot: dict[str, Any],
) -> None:
    entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if _quarantine_signature(entry) != snapshot["source_signature"]:
        raise RollbackError("managed_path_changed")
    if snapshot["kind"] == "symlink":
        if os.readlink(name, dir_fd=parent) != snapshot["target"]:
            raise RollbackError("managed_path_changed")
        return
    if snapshot["kind"] == "regular":
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent,
        )
        try:
            bound = os.fstat(descriptor)
            if _quarantine_signature(bound) != snapshot["source_signature"]:
                raise RollbackError("managed_path_changed")
            remaining = bound.st_size
            digest = hashlib.sha256()
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise RollbackError("managed_path_changed")
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1) or digest.hexdigest() != snapshot["sha256"]:
                raise RollbackError("managed_path_changed")
            linked_after = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                _quarantine_signature(os.fstat(descriptor))
                != snapshot["source_signature"]
                or _quarantine_signature(linked_after)
                != snapshot["source_signature"]
            ):
                raise RollbackError("managed_path_changed")
        finally:
            os.close(descriptor)
        return
    child = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
    try:
        if _quarantine_signature(os.fstat(child)) != snapshot["source_signature"]:
            raise RollbackError("managed_path_changed")
        actual_names = sorted(os.listdir(child))
        expected_names = sorted(snapshot["children"])
        if actual_names != expected_names:
            raise RollbackError("managed_path_changed")
        for child_name in expected_names:
            _verify_quarantine_source_at(
                child,
                child_name,
                snapshot["children"][child_name],
            )
    finally:
        os.close(child)


def _rebind_quarantine_source_after_rename(
    parent: int,
    name: str,
    snapshot: dict[str, Any],
) -> None:
    entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
    previous = snapshot["source_signature"]
    current = _quarantine_signature(entry)
    if previous[:-1] != current[:-1]:
        raise RollbackError("managed_path_changed")
    snapshot["source_signature"] = current
    _verify_quarantine_source_at(parent, name, snapshot)


def _delete_quarantine_source_at(
    parent: int,
    name: str,
    snapshot: dict[str, Any],
) -> None:
    entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if _quarantine_signature(entry) != snapshot["source_signature"]:
        raise RollbackError("managed_path_changed")
    if snapshot["kind"] != "directory":
        _verify_quarantine_source_at(parent, name, snapshot)
        os.unlink(name, dir_fd=parent)
        os.fsync(parent)
        return
    child = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
    try:
        if _quarantine_signature(os.fstat(child)) != snapshot["source_signature"]:
            raise RollbackError("managed_path_changed")
        actual_names = sorted(os.listdir(child))
        expected_names = sorted(snapshot["children"])
        if actual_names != expected_names:
            raise RollbackError("managed_path_changed")
        for child_name in expected_names:
            _delete_quarantine_source_at(
                child,
                child_name,
                snapshot["children"][child_name],
            )
    finally:
        os.close(child)
    os.rmdir(name, dir_fd=parent)
    os.fsync(parent)


def _cross_device_quarantine_at(
    source_parent: int,
    source_name: str,
    destination_parent: int,
    destination_name: str,
    identity: tuple[int, int],
) -> None:
    source_status = os.stat(
        source_name,
        dir_fd=source_parent,
        follow_symlinks=False,
    )
    if (source_status.st_dev, source_status.st_ino) != identity:
        raise RollbackError("managed_path_changed")
    temporary_name = f".partial-{secrets.token_hex(12)}"
    stage_name = f".delete-stage-{secrets.token_hex(12)}"
    snapshot: dict[str, Any] | None = None
    published = False
    try:
        snapshot = _quarantine_copy_at(
            source_parent,
            source_name,
            destination_parent,
            temporary_name,
            depth=0,
            budget={"device": source_status.st_dev, "entries": 0, "bytes": 0},
        )
        _verify_quarantine_source_at(source_parent, source_name, snapshot)
        os.rename(
            temporary_name,
            destination_name,
            src_dir_fd=destination_parent,
            dst_dir_fd=destination_parent,
        )
        published = True
        os.fsync(destination_parent)
        os.rename(
            source_name,
            stage_name,
            src_dir_fd=source_parent,
            dst_dir_fd=source_parent,
        )
        os.fsync(source_parent)
        _rebind_quarantine_source_after_rename(source_parent, stage_name, snapshot)
        _delete_quarantine_source_at(source_parent, stage_name, snapshot)
    except Exception:
        if not published and snapshot is not None:
            try:
                _remove_copied_quarantine_at(
                    destination_parent,
                    temporary_name,
                    snapshot,
                )
            except (OSError, RollbackError):
                pass
        raise


def _quarantine_at(
    receipt: Path,
    logical: str,
    parent: int,
    name: str,
    identity: tuple[int, int],
    *,
    delete_if_matches: dict[str, Any] | None = None,
) -> bool:
    receipt_descriptor = -1
    quarantine_descriptor = -1
    destination_name = (
        f"{hashlib.sha256(logical.encode()).hexdigest()[:16]}-"
        f"{name}-{secrets.token_hex(6)}"
    )
    try:
        receipt_descriptor = os.open(receipt, _DIRECTORY_FLAGS)
        receipt_status = os.fstat(receipt_descriptor)
        if receipt_status.st_uid != os.geteuid() or stat.S_IMODE(receipt_status.st_mode) != 0o700:
            raise RollbackError("rollback_quarantine_failed")
        try:
            os.mkdir("quarantine", 0o700, dir_fd=receipt_descriptor)
            os.fsync(receipt_descriptor)
        except FileExistsError:
            pass
        quarantine_descriptor = os.open("quarantine", _DIRECTORY_FLAGS, dir_fd=receipt_descriptor)
        quarantine_status = os.fstat(quarantine_descriptor)
        if quarantine_status.st_uid != os.geteuid() or stat.S_IMODE(quarantine_status.st_mode) != 0o700:
            raise RollbackError("rollback_quarantine_failed")
        source_status = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (source_status.st_dev, source_status.st_ino) != identity:
            raise RollbackError("managed_path_changed")
        copied_cross_device = False
        try:
            os.rename(
                name,
                destination_name,
                src_dir_fd=parent,
                dst_dir_fd=quarantine_descriptor,
            )
        except OSError as error:
            if error.errno != errno.EXDEV:
                raise
            _cross_device_quarantine_at(
                parent,
                name,
                quarantine_descriptor,
                destination_name,
                identity,
            )
            copied_cross_device = True
        moved_status = os.stat(
            destination_name,
            dir_fd=quarantine_descriptor,
            follow_symlinks=False,
        )
        if (
            not copied_cross_device
            and (moved_status.st_dev, moved_status.st_ino) != identity
        ):
            raise RollbackError("rollback_quarantine_failed")
        os.fsync(parent)
        os.fsync(quarantine_descriptor)
        if delete_if_matches is not None:
            moved, _ = _descriptor_at(quarantine_descriptor, destination_name)
            if _matches(moved, delete_if_matches):
                os.unlink(destination_name, dir_fd=quarantine_descriptor)
                os.fsync(quarantine_descriptor)
                return False
        return True
    except RollbackError:
        raise
    except OSError as error:
        raise RollbackError("rollback_quarantine_failed") from error
    finally:
        if quarantine_descriptor >= 0:
            os.close(quarantine_descriptor)
        if receipt_descriptor >= 0:
            os.close(receipt_descriptor)


def _restore_regular_at(receipt: Path, root: Path, entry: dict[str, Any]) -> None:
    payload, _ = _read_regular(
        receipt / entry["payload"],
        maximum=MAX_MANAGED_FILE_BYTES,
        required_mode=0o600,
        required_owner=os.geteuid(),
    )
    with _open_managed_parent(root, entry["path"], create=True) as (parent, name):
        if parent is None:
            raise RollbackError("rollback_restore_failed")
        temporary_name = f".{name}.rollback.{secrets.token_hex(8)}"
        descriptor = -1
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent,
            )
            written = 0
            while written < len(payload):
                count = os.write(descriptor, payload[written:])
                if count <= 0:
                    raise RollbackError("rollback_restore_failed")
                written += count
            os.fchmod(descriptor, int(entry["mode"], 8))
            os.fchown(descriptor, entry["uid"], entry["gid"])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(
                temporary_name,
                name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
            )
            os.fsync(parent)
        except OSError as error:
            raise RollbackError("rollback_restore_failed") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=parent)
            except FileNotFoundError:
                pass


def restore_receipt(
    receipt: Path,
    expected_manifest_sha256: str,
    *,
    root: Path = Path("/"),
    hostname_getter: Callable[[], str] = lambda: socket.gethostname().split(".", 1)[0],
    executor: Any | None = None,
) -> None:
    _verify_exact_target()
    receipt = Path(receipt)
    if executor is None:
        executor = SystemExecutor()
    with _receipt_lock(receipt):
        digest = verify_receipt(
            receipt,
            expected_manifest_sha256,
            hostname_getter=hostname_getter,
        )
        manifest, _ = _load_manifest(receipt, digest)
        forward = _load_forward(receipt, digest)
        if forward["rollback_outcome"] == "quarantined":
            raise RollbackError("rollback_drift_quarantined")
        quarantined_drift = False
        unresolved_drift = False
        objects_to_remove: list[dict[str, Any]] = []
        retained_objects: dict[tuple[str, str], dict[str, Any]] = {}
        images_to_remove: dict[str, dict[str, Any]] = {}
        image_baselines: dict[str, dict[str, Any]] = {}
        for baseline_object in manifest["podman_objects"]:
            kind = baseline_object["kind"]
            name = baseline_object["name"]
            current_object = executor.current_object(kind, name)
            if baseline_object.get("state") == "present":
                if (
                    current_object.get("state") != "present"
                    or current_object.get("id") != baseline_object.get("id")
                    or current_object.get("identity") != baseline_object.get("identity")
                ):
                    unresolved_drift = True
                continue
            if current_object.get("state") == "absent":
                continue
            if current_object.get("state") != "present":
                unresolved_drift = True
                continue
            if kind == "volume":
                if (
                    current_object.get("identity") != name
                    or not isinstance(current_object.get("id"), str)
                    or not current_object["id"]
                    or len(current_object["id"]) > 512
                ):
                    unresolved_drift = True
                    continue
                retained_objects[(kind, name)] = dict(current_object)
                continue
            authorized_object = forward["objects"].get(f"{kind}:{name}")
            if (
                not isinstance(authorized_object, dict)
                or authorized_object.get("state") != "finalized"
                or current_object.get("id") != authorized_object.get("id")
                or current_object.get("identity") != authorized_object.get("identity")
            ):
                unresolved_drift = True
                continue
            objects_to_remove.append(current_object)

        for role in IMAGE_ROLES:
            if role not in forward["images"]:
                continue
            baseline_image = forward["images"][role]
            reference = baseline_image["reference"]
            prior_baseline = image_baselines.get(reference)
            if prior_baseline is not None:
                continue
            image_baselines[reference] = baseline_image
            current_image = executor.current_image(reference)
            if not _valid_image_descriptor(current_image, reference):
                unresolved_drift = True
                continue
            if baseline_image["state"] == "present":
                if current_image != baseline_image:
                    unresolved_drift = True
                continue
            if current_image["state"] == "present":
                images_to_remove[reference] = current_image

        if unresolved_drift:
            raise RollbackError("rollback_incomplete")
        executor.stop_for_restore()
        if retained_objects and forward["rollback_outcome"] != "retained-data":
            forward["rollback_outcome"] = "retained-data"
            _replace_canonical(receipt / "forward-state.json", forward)
        for current_object in objects_to_remove:
            executor.remove_object(current_object)
        for current_image in images_to_remove.values():
            executor.remove_image(current_image)

        entries = manifest["managed_paths"]
        expected_kinds = {path: kind for path, kind, _sensitive in MANAGED_PATHS}
        directory_entries = [
            item for item in entries if expected_kinds.get(item["path"]) == "directory"
        ]

        for entry in sorted(
            (item for item in directory_entries if item["state"] == "present"),
            key=lambda item: item["path"].count("/"),
        ):
            with _open_managed_parent(root, entry["path"], create=True) as (parent, name):
                if parent is None:
                    raise RollbackError("rollback_restore_failed")
                current, identity = _descriptor_at(parent, name)
                if current.get("state") == "present" and current.get("type") != "directory":
                    if identity is None:
                        raise RollbackError("managed_path_changed")
                    _mark_quarantined(receipt, forward)
                    quarantined_drift |= _quarantine_at(
                        receipt,
                        entry["path"],
                        parent,
                        name,
                        identity,
                    )
                    current = {"state": "absent"}
                if current.get("state") == "absent":
                    try:
                        os.mkdir(name, int(entry["mode"], 8), dir_fd=parent)
                        os.fsync(parent)
                    except OSError as error:
                        raise RollbackError("rollback_restore_failed") from error
                try:
                    child = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
                except OSError as error:
                    raise RollbackError("managed_path_unsafe") from error
                try:
                    bound = os.fstat(child)
                    linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if (bound.st_dev, bound.st_ino) != (linked.st_dev, linked.st_ino):
                        raise RollbackError("managed_path_changed")
                    os.fchmod(child, int(entry["mode"], 8))
                    os.fchown(child, entry["uid"], entry["gid"])
                    os.fsync(child)
                    os.fsync(parent)
                except OSError as error:
                    raise RollbackError("rollback_restore_failed") from error
                finally:
                    os.close(child)

        for entry in (
            item for item in entries if expected_kinds.get(item["path"]) == "regular"
        ):
            baseline = _baseline_descriptor(entry)
            authorized = forward["files"].get(entry["path"])
            with _open_managed_parent(
                root,
                entry["path"],
                create=entry["state"] == "present",
            ) as (parent, name):
                current, identity = _descriptor_at(parent, name)
                if entry["state"] == "present":
                    if _matches(current, baseline):
                        continue
                    if current.get("state") == "present":
                        if parent is None or identity is None:
                            raise RollbackError("managed_path_changed")
                        if not _matches(current, authorized):
                            _mark_quarantined(receipt, forward)
                        quarantined_drift |= _quarantine_at(
                            receipt,
                            entry["path"],
                            parent,
                            name,
                            identity,
                            delete_if_matches=authorized,
                        )
                    _restore_regular_at(receipt, root, entry)
                elif current.get("state") == "present":
                    if parent is None or identity is None:
                        raise RollbackError("managed_path_changed")
                    if not _matches(current, authorized):
                        _mark_quarantined(receipt, forward)
                    quarantined_drift |= _quarantine_at(
                        receipt,
                        entry["path"],
                        parent,
                        name,
                        identity,
                        delete_if_matches=authorized,
                    )

        for entry in sorted(
            (item for item in directory_entries if item["state"] == "absent"),
            key=lambda item: item["path"].count("/"),
            reverse=True,
        ):
            with _open_managed_parent(root, entry["path"], create=False) as (parent, name):
                current, identity = _descriptor_at(parent, name)
                if current.get("state") == "absent":
                    continue
                if parent is None or identity is None:
                    raise RollbackError("managed_path_changed")
                if current.get("type") == "directory":
                    try:
                        child = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
                    except OSError as error:
                        raise RollbackError("managed_path_unsafe") from error
                    try:
                        iterator = os.scandir(child)
                        try:
                            empty = next(iterator, None) is None
                        finally:
                            iterator.close()
                    finally:
                        os.close(child)
                    if empty:
                        try:
                            os.rmdir(name, dir_fd=parent)
                            os.fsync(parent)
                        except OSError as error:
                            raise RollbackError("rollback_restore_failed") from error
                        continue
                _mark_quarantined(receipt, forward)
                quarantined_drift |= _quarantine_at(
                    receipt,
                    entry["path"],
                    parent,
                    name,
                    identity,
                )

        for entry in entries:
            baseline = _baseline_descriptor(entry)
            with _open_managed_parent(root, entry["path"], create=False) as (parent, name):
                current, _identity = _descriptor_at(parent, name)
            if entry["state"] == "absent":
                if current.get("state") != "absent":
                    unresolved_drift = True
            elif not _matches(current, baseline):
                unresolved_drift = True

        if unresolved_drift:
            raise RollbackError("rollback_incomplete")
        executor.restore_units(manifest["units"], manifest["linger"])
        for reference, baseline_image in image_baselines.items():
            current_image = executor.current_image(reference)
            if (
                not _valid_image_descriptor(current_image, reference)
                or current_image != baseline_image
            ):
                raise RollbackError("rollback_verification_failed")
        if hasattr(executor, "verify_restored"):
            executor.verify_restored(
                manifest,
                retained_objects=retained_objects,
            )
        if quarantined_drift:
            raise RollbackError("rollback_drift_quarantined")
        if retained_objects:
            raise RollbackError("rollback_incomplete")
        if forward["rollback_outcome"] == "retained-data":
            forward["rollback_outcome"] = "clean"
            _replace_canonical(receipt / "forward-state.json", forward)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lil-tweak-rollback.py")
    parser.add_argument("--check", action="store_true")
    commands = parser.add_subparsers(dest="command")
    capture = commands.add_parser("capture")
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--source-commit", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--expected-manifest-sha256")
    verify_fresh = commands.add_parser("verify-fresh-install")
    verify_fresh.add_argument("--receipt", type=Path, required=True)
    verify_fresh.add_argument("--expected-manifest-sha256", required=True)
    authorize = commands.add_parser("authorize-file")
    authorize.add_argument("--receipt", type=Path, required=True)
    authorize.add_argument("--expected-manifest-sha256", required=True)
    authorize.add_argument("--path", required=True)
    authorize.add_argument("--source", type=Path, required=True)
    authorize.add_argument("--mode", required=True)
    authorize.add_argument("--uid", type=int, required=True)
    authorize.add_argument("--gid", type=int, required=True)
    authorize_object_parser = commands.add_parser("authorize-object")
    authorize_object_parser.add_argument("--receipt", type=Path, required=True)
    authorize_object_parser.add_argument("--expected-manifest-sha256", required=True)
    authorize_object_parser.add_argument("--kind", required=True)
    authorize_object_parser.add_argument("--name", required=True)
    authorize_object_parser.add_argument("--identity", required=True)
    finalize_object_parser = commands.add_parser("finalize-object")
    finalize_object_parser.add_argument("--receipt", type=Path, required=True)
    finalize_object_parser.add_argument(
        "--expected-manifest-sha256", required=True
    )
    finalize_object_parser.add_argument("--kind", required=True)
    finalize_object_parser.add_argument("--name", required=True)
    finalize_object_parser.add_argument("--identity", required=True)
    authorize_images_parser = commands.add_parser("authorize-images")
    authorize_images_parser.add_argument("--receipt", type=Path, required=True)
    authorize_images_parser.add_argument(
        "--expected-manifest-sha256", required=True
    )
    authorize_images_parser.add_argument("--core-reference", required=True)
    authorize_images_parser.add_argument("--postgres-reference", required=True)
    authorize_images_parser.add_argument("--runner-reference", required=True)
    acknowledge = commands.add_parser("acknowledge-quarantine")
    acknowledge.add_argument("--receipt", type=Path, required=True)
    acknowledge.add_argument("--expected-manifest-sha256", required=True)
    completed = commands.add_parser("mark-completed")
    completed.add_argument("--receipt", type=Path, required=True)
    completed.add_argument("--expected-manifest-sha256", required=True)
    lease = commands.add_parser("lease-exec")
    lease.add_argument("--receipt", type=Path, required=True)
    lease.add_argument("--expected-manifest-sha256", required=True)
    lease.add_argument("lease_command", nargs=argparse.REMAINDER)
    restore = commands.add_parser("restore")
    restore.add_argument("--receipt", type=Path, required=True)
    restore.add_argument("--expected-manifest-sha256", required=True)
    return parser


def _require_production() -> None:
    if os.geteuid() != 0:
        raise RollbackError("root_required")
    if socket.gethostname().split(".", 1)[0] != EXPECTED_HOST:
        raise RollbackError("hostname_mismatch")


def _require_production_receipt_path(receipt: Path) -> None:
    receipt = Path(receipt)
    if (
        not receipt.is_absolute()
        or receipt.parent != Path(RECEIPT_ROOT)
        or RECEIPT_NAME.fullmatch(receipt.name) is None
    ):
        raise RollbackError("receipt_path_invalid")
    with _open_managed_parent(Path("/"), f"{receipt}/manifest.json", create=False) as (
        parent,
        _name,
    ):
        if parent is None:
            raise RollbackError("receipt_path_invalid")
        status = os.fstat(parent)
        if status.st_uid != 0 or stat.S_IMODE(status.st_mode) != 0o700:
            raise RollbackError("receipt_path_invalid")


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.check:
            _check_exact_target_helper()
            print("lil-tweak-rollback check: ok")
            return 0
        if not arguments.command:
            raise RollbackError("command_required")
        _require_production()
        if arguments.command == "capture":
            value = capture_receipt(output=arguments.output, source_commit=arguments.source_commit)
        elif arguments.command == "verify":
            _require_production_receipt_path(arguments.receipt)
            value = verify_receipt(
                arguments.receipt,
                arguments.expected_manifest_sha256,
                hostname_getter=lambda: socket.gethostname().split(".", 1)[0],
            )
        elif arguments.command == "verify-fresh-install":
            _require_production_receipt_path(arguments.receipt)
            value = verify_fresh_install(
                arguments.receipt,
                arguments.expected_manifest_sha256,
            )
        elif arguments.command == "authorize-file":
            _require_production_receipt_path(arguments.receipt)
            try:
                mode = int(arguments.mode, 8)
            except ValueError as error:
                raise RollbackError("forward_state_invalid") from error
            authorize_file(
                arguments.receipt,
                arguments.expected_manifest_sha256,
                arguments.path,
                arguments.source,
                mode,
                arguments.uid,
                arguments.gid,
            )
            value = arguments.expected_manifest_sha256
        elif arguments.command == "authorize-object":
            _require_production_receipt_path(arguments.receipt)
            authorize_object(
                arguments.receipt,
                arguments.expected_manifest_sha256,
                arguments.kind,
                arguments.name,
                arguments.identity,
            )
            value = arguments.expected_manifest_sha256
        elif arguments.command == "finalize-object":
            _require_production_receipt_path(arguments.receipt)
            finalize_object(
                arguments.receipt,
                arguments.expected_manifest_sha256,
                arguments.kind,
                arguments.name,
                arguments.identity,
            )
            value = arguments.expected_manifest_sha256
        elif arguments.command == "authorize-images":
            _require_production_receipt_path(arguments.receipt)
            authorize_images(
                arguments.receipt,
                arguments.expected_manifest_sha256,
                {
                    "core": arguments.core_reference,
                    "postgres": arguments.postgres_reference,
                    "runner": arguments.runner_reference,
                },
            )
            value = arguments.expected_manifest_sha256
        elif arguments.command == "acknowledge-quarantine":
            _require_production_receipt_path(arguments.receipt)
            acknowledge_quarantine(
                arguments.receipt,
                arguments.expected_manifest_sha256,
            )
            value = arguments.expected_manifest_sha256
        elif arguments.command == "mark-completed":
            _require_production_receipt_path(arguments.receipt)
            mark_completed(
                arguments.receipt,
                arguments.expected_manifest_sha256,
            )
            value = arguments.expected_manifest_sha256
        elif arguments.command == "lease-exec":
            _require_production_receipt_path(arguments.receipt)
            lease_command = list(arguments.lease_command)
            if lease_command[:1] == ["--"]:
                lease_command = lease_command[1:]
            return lease_exec(
                arguments.receipt,
                arguments.expected_manifest_sha256,
                lease_command,
            )
        else:
            _require_production_receipt_path(arguments.receipt)
            restore_receipt(arguments.receipt, arguments.expected_manifest_sha256)
            value = arguments.expected_manifest_sha256
    except RollbackError as error:
        print(f"lil-tweak-rollback: {error.code}", file=sys.stderr)
        return 1
    print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
