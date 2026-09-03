#!/usr/bin/env python3
"""Install Lil Tweak service files without following service-owned paths."""

from __future__ import annotations

import argparse
import os
import re
import secrets
import stat
import sys
from collections.abc import Callable, Sequence


SERVICE_HOME = "/var/lib/lil-tweak"
RUNTIME_PARENT = "/run/user"
MAX_SOURCE_BYTES = 1_048_576
INVENTORY = (
    (".config/lil-tweak/core.env", 0o600),
    (".local/share/lil-tweak/migrations/001_initial.sql", 0o400),
    (".local/share/lil-tweak/migrations/002_fencing.sql", 0o400),
    (".local/share/lil-tweak/migrations/postgres-bootstrap.sql", 0o400),
    (".local/share/lil-tweak/migrations/postgres-grants.sql", 0o400),
    (".config/containers/systemd/lil-tweak-core.container", 0o644),
    (".config/containers/systemd/lil-tweak-postgres.container", 0o644),
    (".config/containers/systemd/lil-tweak.network", 0o644),
    (".config/containers/systemd/lil-tweak-data.volume", 0o644),
    (".config/containers/systemd/lil-tweak-postgres-data.volume", 0o644),
    (".config/systemd/user/lil-tweak-core.service.d/hardening.conf", 0o644),
    (".config/systemd/user/lil-tweak-postgres.service.d/hardening.conf", 0o644),
)
STABLE_FILE_FIELDS = (
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


class ServiceFilesError(Exception):
    """A deliberately non-disclosing controller failure."""


def _required_flag(name: str) -> int:
    value = getattr(os, name, None)
    if not isinstance(value, int) or value == 0:
        raise ServiceFilesError
    return value


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | _required_flag("O_CLOEXEC")
        | _required_flag("O_DIRECTORY")
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_NONBLOCK")
    )


def _input_flags() -> int:
    return (
        os.O_RDONLY
        | _required_flag("O_CLOEXEC")
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_NONBLOCK")
    )


def _output_flags() -> int:
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | _required_flag("O_CLOEXEC")
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_NONBLOCK")
    )


def check_platform() -> None:
    _directory_flags()
    _input_flags()
    _output_flags()
    for name in ("open", "mkdir", "rename", "stat", "unlink"):
        if getattr(os, name) not in os.supports_dir_fd:
            raise ServiceFilesError
    if os.stat not in os.supports_follow_symlinks:
        raise ServiceFilesError


def _components(path: str) -> tuple[str, ...]:
    if not path.startswith("/") or path.startswith("//") or path.endswith("/"):
        raise ServiceFilesError
    result = tuple(path[1:].split("/"))
    if not result or any(part in {"", ".", ".."} or "\x00" in part for part in result):
        raise ServiceFilesError
    return result


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _same_file_metadata(left: os.stat_result, right: os.stat_result) -> bool:
    return all(getattr(left, field) == getattr(right, field) for field in STABLE_FILE_FIELDS)


class _DirectoryGraph:
    def __init__(self, root_fd: int) -> None:
        self.fds = [root_fd]
        self.edges: list[tuple[int, str, int]] = []

    def open_child(self, parent_fd: int, name: str) -> int:
        descriptor = os.open(name, _directory_flags(), dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise ServiceFilesError
        self.fds.append(descriptor)
        self.edges.append((parent_fd, name, descriptor))
        return descriptor

    def validate(self) -> None:
        for parent_fd, name, child_fd in self.edges:
            held = os.fstat(child_fd)
            entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(held.st_mode)
                or not stat.S_ISDIR(entry.st_mode)
                or not _same_identity(held, entry)
            ):
                raise ServiceFilesError

    def close(self) -> None:
        for descriptor in reversed(self.fds):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _open_absolute_directory(path: str) -> tuple[_DirectoryGraph, int]:
    graph = _DirectoryGraph(os.open("/", _directory_flags()))
    current = graph.fds[0]
    try:
        for component in _components(path):
            current = graph.open_child(current, component)
        graph.validate()
        return graph, current
    except BaseException:
        graph.close()
        raise


def _read_regular_file(
    directory_fd: int,
    name: str,
    expected_mode: int,
    maximum_size: int = MAX_SOURCE_BYTES,
) -> bytes:
    descriptor = os.open(name, _input_flags(), dir_fd=directory_fd)
    try:
        before = os.fstat(descriptor)
        entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(entry.st_mode)
            or not _same_identity(before, entry)
            or before.st_uid != 0
            or before.st_gid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != expected_mode
            or before.st_size < 1
            or before.st_size > maximum_size
        ):
            raise ServiceFilesError
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise ServiceFilesError
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) != b"":
            raise ServiceFilesError
        after = os.fstat(descriptor)
        if not _same_file_metadata(before, after):
            raise ServiceFilesError
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _expected_tree() -> dict[str, set[str]]:
    children: dict[str, set[str]] = {"": set()}
    for relative, _mode in INVENTORY:
        parts = relative.split("/")
        parent = ""
        for index, part in enumerate(parts):
            children.setdefault(parent, set()).add(part)
            if index != len(parts) - 1:
                parent = f"{parent}/{part}" if parent else part
                children.setdefault(parent, set())
    return children


def _validate_root_directory(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ServiceFilesError


def _bounded_names(descriptor: int, maximum: int) -> set[str]:
    names: set[str] = set()
    with os.scandir(descriptor) as entries:
        for entry in entries:
            if len(names) >= maximum or entry.name in names:
                raise ServiceFilesError
            names.add(entry.name)
    return names


def _read_staging_tree(path: str) -> dict[str, bytes]:
    graph, root_fd = _open_absolute_directory(path)
    expected = _expected_tree()
    directory_fds = {"": root_fd}
    try:
        _validate_root_directory(os.fstat(root_fd))
        for relative in sorted(expected, key=lambda value: (value.count("/"), value)):
            descriptor = directory_fds[relative]
            metadata = os.fstat(descriptor)
            _validate_root_directory(metadata)
            if _bounded_names(descriptor, len(expected[relative]) + 1) != expected[relative]:
                raise ServiceFilesError
            for child in expected[relative]:
                child_relative = f"{relative}/{child}" if relative else child
                if child_relative in expected:
                    directory_fds[child_relative] = graph.open_child(descriptor, child)
        contents: dict[str, bytes] = {}
        for relative, mode in INVENTORY:
            parent, name = relative.rsplit("/", 1)
            contents[relative] = _read_regular_file(directory_fds[parent], name, mode)
        graph.validate()
        return contents
    except (OSError, UnicodeError, ValueError) as error:
        raise ServiceFilesError from error
    finally:
        graph.close()


class ServiceFileController:
    """Descriptor-relative controller; test_root is intentionally not a CLI option."""

    def __init__(
        self,
        *,
        test_root: str = "/",
        test_filesystem_ids: tuple[int, int] | None = None,
        hook: Callable[[str, object], None] | None = None,
        write_func: Callable[[int, bytes], int] = os.write,
        rename_func: Callable[..., None] = os.rename,
    ) -> None:
        self.root = test_root
        if test_filesystem_ids is not None and test_root == "/":
            raise ServiceFilesError
        self.test_filesystem_ids = test_filesystem_ids
        self.hook = hook
        self.write_func = write_func
        self.rename_func = rename_func

    def _event(self, name: str, details: object = None) -> None:
        if self.hook is not None:
            self.hook(name, details)

    def _open_controller_root(self) -> tuple[_DirectoryGraph, int]:
        if self.root == "/":
            descriptor = os.open("/", _directory_flags())
            return _DirectoryGraph(descriptor), descriptor
        return _open_absolute_directory(self.root)

    @staticmethod
    def _require_root_anchor(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ServiceFilesError

    @staticmethod
    def _require_owned_directory(descriptor: int, uid: int, gid: int, mode: int) -> None:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (uid, gid)
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise ServiceFilesError

    def _open_anchor(self, components: Sequence[str]) -> tuple[_DirectoryGraph, int]:
        graph, current = self._open_controller_root()
        try:
            self._require_root_anchor(current)
            for component in components:
                current = graph.open_child(current, component)
                self._require_root_anchor(current)
            graph.validate()
            return graph, current
        except BaseException:
            graph.close()
            raise

    def _open_owned_child(
        self,
        graph: _DirectoryGraph,
        parent_fd: int,
        name: str,
        uid: int,
        gid: int,
        *,
        create: bool,
    ) -> int:
        created = False
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
                created = True
            except FileExistsError:
                pass
        descriptor = graph.open_child(parent_fd, name)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ServiceFilesError
        if created:
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, 0o700)
        elif (metadata.st_uid, metadata.st_gid) != (uid, gid):
            raise ServiceFilesError
        else:
            os.fchmod(descriptor, 0o700)
        self._require_owned_directory(descriptor, uid, gid, 0o700)
        return descriptor

    def _write_file(
        self,
        graph: _DirectoryGraph,
        directory_fd: int,
        final_name: str,
        contents: bytes,
        mode: int,
        uid: int,
        gid: int,
    ) -> None:
        temporary_name = ""
        descriptor = -1
        try:
            for _attempt in range(32):
                temporary_name = f".lil-tweak-tmp-{secrets.token_hex(8)}"
                try:
                    descriptor = os.open(
                        temporary_name, _output_flags(), mode, dir_fd=directory_fd
                    )
                    break
                except FileExistsError:
                    continue
            if descriptor < 0:
                raise ServiceFilesError
            written = 0
            while written < len(contents):
                count = self.write_func(descriptor, contents[written:])
                if count <= 0 or count > len(contents) - written:
                    raise ServiceFilesError
                written += count
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            ready = os.fstat(descriptor)
            if (
                not stat.S_ISREG(ready.st_mode)
                or ready.st_nlink != 1
                or ready.st_size != len(contents)
                or (ready.st_uid, ready.st_gid) != (uid, gid)
                or stat.S_IMODE(ready.st_mode) != mode
            ):
                raise ServiceFilesError
            self._event("before_publish", final_name)
            graph.validate()
            temporary_entry = os.stat(
                temporary_name, dir_fd=directory_fd, follow_symlinks=False
            )
            if not stat.S_ISREG(temporary_entry.st_mode) or not _same_identity(
                ready, temporary_entry
            ):
                raise ServiceFilesError
            self.rename_func(
                temporary_name,
                final_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            temporary_name = ""
            self._event("after_publish", final_name)
            final_entry = os.stat(final_name, dir_fd=directory_fd, follow_symlinks=False)
            final_held = os.fstat(descriptor)
            if (
                not stat.S_ISREG(final_entry.st_mode)
                or not _same_identity(final_held, final_entry)
                or final_held.st_nlink != 1
                or final_held.st_size != len(contents)
                or (final_held.st_uid, final_held.st_gid) != (uid, gid)
                or stat.S_IMODE(final_held.st_mode) != mode
            ):
                raise ServiceFilesError
            os.fsync(directory_fd)
            graph.validate()
        except (OSError, ValueError) as error:
            raise ServiceFilesError from error
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if temporary_name:
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except OSError as error:
                    raise ServiceFilesError from error

    @staticmethod
    def _validate_ids(uid: int, gid: int) -> None:
        if (
            not isinstance(uid, int)
            or not isinstance(gid, int)
            or not (0 < uid < 2**31)
            or not (0 < gid < 2**31)
        ):
            raise ServiceFilesError

    def _filesystem_ids(self, uid: int, gid: int) -> tuple[int, int]:
        return self.test_filesystem_ids if self.test_filesystem_ids is not None else (uid, gid)

    def install_tree(self, staging: str, uid: int, gid: int) -> None:
        self._validate_ids(uid, gid)
        filesystem_uid, filesystem_gid = self._filesystem_ids(uid, gid)
        contents = _read_staging_tree(staging)
        graph, parent_fd = self._open_anchor(("var", "lib"))
        try:
            try:
                home_fd = self._open_owned_child(
                    graph,
                    parent_fd,
                    "lil-tweak",
                    filesystem_uid,
                    filesystem_gid,
                    create=True,
                )
                directory_fds = {"": home_fd}
                expected = _expected_tree()
                for relative in sorted(expected, key=lambda value: (value.count("/"), value)):
                    if not relative:
                        continue
                    parent, name = relative.rsplit("/", 1) if "/" in relative else ("", relative)
                    directory_fds[relative] = self._open_owned_child(
                        graph,
                        directory_fds[parent],
                        name,
                        filesystem_uid,
                        filesystem_gid,
                        create=True,
                    )
                graph.validate()
                for relative, mode in INVENTORY:
                    parent, name = relative.rsplit("/", 1)
                    self._write_file(
                        graph,
                        directory_fds[parent],
                        name,
                        contents[relative],
                        mode,
                        filesystem_uid,
                        filesystem_gid,
                    )
                graph.validate()
            except (OSError, ValueError) as error:
                raise ServiceFilesError from error
        finally:
            graph.close()

    def stage_runtime_auth(self, source: str, uid: int, gid: int) -> str:
        self._validate_ids(uid, gid)
        filesystem_uid, filesystem_gid = self._filesystem_ids(uid, gid)
        source_components = _components(source)
        source_parent_path = "/" + "/".join(source_components[:-1])
        source_graph, source_parent_fd = _open_absolute_directory(source_parent_path)
        try:
            contents = _read_regular_file(source_parent_fd, source_components[-1], 0o600, 65_536)
            source_graph.validate()
        except (OSError, ValueError) as error:
            raise ServiceFilesError from error
        finally:
            source_graph.close()

        graph, runtime_parent_fd = self._open_anchor(("run", "user"))
        runtime_fd = -1
        cleanup_name = ""
        descriptor = -1
        try:
            runtime_fd = self._open_owned_child(
                graph,
                runtime_parent_fd,
                str(uid),
                filesystem_uid,
                filesystem_gid,
                create=False,
            )
            self._event("before_runtime_create", uid)
            graph.validate()
            temporary_name = f".lil-tweak-tmp-{secrets.token_hex(8)}"
            cleanup_name = temporary_name
            descriptor = os.open(
                temporary_name, _output_flags(), 0o600, dir_fd=runtime_fd
            )
            written = 0
            while written < len(contents):
                count = self.write_func(descriptor, contents[written:])
                if count <= 0 or count > len(contents) - written:
                    raise ServiceFilesError
                written += count
            os.fchown(descriptor, filesystem_uid, filesystem_gid)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            held = os.fstat(descriptor)
            temporary_entry = os.stat(
                temporary_name, dir_fd=runtime_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(held.st_mode)
                or not stat.S_ISREG(temporary_entry.st_mode)
                or not _same_identity(held, temporary_entry)
                or held.st_nlink != 1
                or held.st_size != len(contents)
                or (held.st_uid, held.st_gid) != (filesystem_uid, filesystem_gid)
                or stat.S_IMODE(held.st_mode) != 0o600
            ):
                raise ServiceFilesError
            final_name = (
                f"lil-tweak-registry-auth.{secrets.token_hex(8)}."
                f"{held.st_dev:x}.{held.st_ino:x}"
            )
            graph.validate()
            self.rename_func(
                temporary_name,
                final_name,
                src_dir_fd=runtime_fd,
                dst_dir_fd=runtime_fd,
            )
            cleanup_name = final_name
            self._event("after_runtime_publish", final_name)
            final_entry = os.stat(
                final_name, dir_fd=runtime_fd, follow_symlinks=False
            )
            final_held = os.fstat(descriptor)
            if (
                not stat.S_ISREG(final_entry.st_mode)
                or not _same_identity(final_held, final_entry)
                or final_held.st_nlink != 1
                or final_held.st_size != len(contents)
                or (final_held.st_uid, final_held.st_gid)
                != (filesystem_uid, filesystem_gid)
                or stat.S_IMODE(final_held.st_mode) != 0o600
            ):
                raise ServiceFilesError
            os.fsync(runtime_fd)
            graph.validate()
            prefix = "" if self.root == "/" else self.root
            result = f"{prefix}/run/user/{uid}/{final_name}"
            cleanup_name = ""
            return result
        except (OSError, ValueError) as error:
            raise ServiceFilesError from error
        finally:
            cleanup_error: BaseException | None = None
            if cleanup_name and runtime_fd >= 0:
                try:
                    entry = os.stat(
                        cleanup_name, dir_fd=runtime_fd, follow_symlinks=False
                    )
                    held = os.fstat(descriptor)
                    if not _same_identity(entry, held):
                        raise ServiceFilesError
                    os.unlink(cleanup_name, dir_fd=runtime_fd)
                except OSError as error:
                    cleanup_error = error
                except ServiceFilesError as error:
                    cleanup_error = error
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            graph.close()
            if cleanup_error is not None:
                raise ServiceFilesError from cleanup_error

    def remove_runtime_auth(self, path: str, uid: int, gid: int) -> None:
        self._validate_ids(uid, gid)
        filesystem_uid, filesystem_gid = self._filesystem_ids(uid, gid)
        prefix = "" if self.root == "/" else re.escape(self.root)
        match = re.fullmatch(
            rf"{prefix}/run/user/{uid}/"
            r"(?P<name>lil-tweak-registry-auth\.[0-9a-f]{16}\."
            r"(?P<device>[0-9a-f]+)\.(?P<inode>[0-9a-f]+))",
            path,
        )
        if match is None:
            raise ServiceFilesError
        expected_identity = (int(match.group("device"), 16), int(match.group("inode"), 16))
        name = match.group("name")
        graph, runtime_parent_fd = self._open_anchor(("run", "user"))
        descriptor = -1
        try:
            runtime_fd = self._open_owned_child(
                graph,
                runtime_parent_fd,
                str(uid),
                filesystem_uid,
                filesystem_gid,
                create=False,
            )
            descriptor = os.open(name, _input_flags(), dir_fd=runtime_fd)
            held = os.fstat(descriptor)
            entry = os.stat(name, dir_fd=runtime_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(held.st_mode)
                or not stat.S_ISREG(entry.st_mode)
                or not _same_identity(held, entry)
                or (held.st_dev, held.st_ino) != expected_identity
                or held.st_nlink != 1
                or (held.st_uid, held.st_gid) != (filesystem_uid, filesystem_gid)
                or stat.S_IMODE(held.st_mode) != 0o600
            ):
                raise ServiceFilesError
            self._event("before_runtime_unlink", name)
            graph.validate()
            entry = os.stat(name, dir_fd=runtime_fd, follow_symlinks=False)
            if not _same_identity(held, entry):
                raise ServiceFilesError
            os.unlink(name, dir_fd=runtime_fd)
            os.fsync(runtime_fd)
            try:
                os.stat(name, dir_fd=runtime_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ServiceFilesError
            graph.validate()
        except (OSError, ValueError) as error:
            raise ServiceFilesError from error
        finally:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            graph.close()


class _SilentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise ServiceFilesError


def _parser() -> argparse.ArgumentParser:
    parser = _SilentParser(add_help=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    install = subparsers.add_parser("install-tree", add_help=False)
    install.add_argument("--staging", required=True)
    install.add_argument("--uid", required=True, type=int)
    install.add_argument("--gid", required=True, type=int)
    runtime = subparsers.add_parser("stage-runtime-auth", add_help=False)
    runtime.add_argument("--source", required=True)
    runtime.add_argument("--uid", required=True, type=int)
    runtime.add_argument("--gid", required=True, type=int)
    remove = subparsers.add_parser("remove-runtime-auth", add_help=False)
    remove.add_argument("--path", required=True)
    remove.add_argument("--uid", required=True, type=int)
    remove.add_argument("--gid", required=True, type=int)
    return parser


def main(argv: Sequence[str]) -> int:
    try:
        check_platform()
        if list(argv) == ["--check"]:
            print("lil-tweak-service-files check: ok")
            return 0
        arguments = _parser().parse_args(argv)
        if os.geteuid() != 0:
            raise ServiceFilesError
        controller = ServiceFileController()
        if arguments.command == "install-tree":
            controller.install_tree(arguments.staging, arguments.uid, arguments.gid)
        elif arguments.command == "stage-runtime-auth":
            result = controller.stage_runtime_auth(
                arguments.source, arguments.uid, arguments.gid
            )
            print(result)
        else:
            controller.remove_runtime_auth(arguments.path, arguments.uid, arguments.gid)
        return 0
    except (ServiceFilesError, OSError, UnicodeError, ValueError):
        print("lil-tweak-service-files: operation failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
