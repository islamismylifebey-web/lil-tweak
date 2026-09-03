"""Rootless Podman command boundary for disposable engineering workspaces."""

from __future__ import annotations

import ctypes
import errno
import os
import re
import selectors
import stat
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .limits import RUNNER_WORKSPACE_BYTES, RUNNER_WORKSPACE_INODES


WORKSPACE_TMPFS_BYTES = RUNNER_WORKSPACE_BYTES
WORKSPACE_TMPFS_INODES = RUNNER_WORKSPACE_INODES
MAX_EPHEMERAL_BATCH_COMMANDS = 32
RUNNER_CLEANUP_GRACE_SECONDS = 60


class CommandRejected(ValueError):
    code = "command_rejected"

    def __init__(self) -> None:
        super().__init__("command rejected")


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    cpus: int = 1
    memory: str = "1g"
    pids: int = 256
    nofile: int = 1024
    wall_timeout_seconds: int = 20 * 60
    command_timeout_seconds: int = 10 * 60
    max_output_bytes: int = 2 * 1024 * 1024
    uid: int = 65532
    gid: int = 65532


@dataclass(frozen=True, slots=True)
class CommandResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False


_ALLOWED_EXECUTABLES = frozenset(
    {
        "python",
        "python3",
        "pytest",
        "node",
        "npm",
        "npx",
        "go",
        "cargo",
        "rustc",
        "patch",
        "make",
        "cmake",
        "java",
        "javac",
    }
)
_RUNNER_LABEL = "io.lil-tweak.runner=code-engineer-v1"
_CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
_SAFE_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")
_SECRET = re.compile(
    r"(?i)(authorization|api[_-]?key|token|password|secret)\s*[:=]\s*"
    r"(?:bearer\s+)?([^\s,;]+)"
)


def atomic_exchange_directories(
    left: str | os.PathLike[str], right: str | os.PathLike[str]
) -> None:
    """Invoke the single Linux RENAME_EXCHANGE promotion commit point."""

    left_path = Path(left).absolute()
    right_path = Path(right).absolute()
    if left_path.parent != right_path.parent or left_path == right_path:
        raise OSError(errno.EXDEV, "directory exchange requires siblings")
    left_before = left_path.lstat()
    right_before = right_path.lstat()
    if (
        not stat.S_ISDIR(left_before.st_mode)
        or stat.S_ISLNK(left_before.st_mode)
        or not stat.S_ISDIR(right_before.st_mode)
        or stat.S_ISLNK(right_before.st_mode)
        or left_before.st_dev != right_before.st_dev
    ):
        raise OSError(errno.EINVAL, "invalid directory exchange")
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    parent_descriptor = os.open(left_path.parent, parent_flags)
    try:
        library = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(library, "renameat2", None)
        if renameat2 is None:
            raise OSError(errno.ENOSYS, "renameat2 unavailable")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        if renameat2(
            parent_descriptor,
            os.fsencode(left_path.name),
            parent_descriptor,
            os.fsencode(right_path.name),
            2,  # RENAME_EXCHANGE
        ) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
    finally:
        os.close(parent_descriptor)


def atomic_publish_noreplace(
    source: str | os.PathLike[str], destination: str | os.PathLike[str]
) -> None:
    """Atomically publish one sibling marker without replacing an existing one."""

    source_path = Path(source).absolute()
    destination_path = Path(destination).absolute()
    if source_path.parent != destination_path.parent or source_path == destination_path:
        raise OSError(errno.EXDEV, "marker publication requires siblings")
    parent_descriptor = os.open(
        source_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        library = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(library, "renameat2", None)
        if renameat2 is None:
            raise OSError(errno.ENOSYS, "renameat2 unavailable")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        if renameat2(
            parent_descriptor,
            os.fsencode(source_path.name),
            parent_descriptor,
            os.fsencode(destination_path.name),
            1,  # RENAME_NOREPLACE
        ) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
    finally:
        os.close(parent_descriptor)


def _validate_command(command: Sequence[str]) -> list[str]:
    if isinstance(command, (str, bytes)) or not command:
        raise CommandRejected()
    argv = list(command)
    if any(not isinstance(part, str) or not part or "\x00" in part for part in argv):
        raise CommandRejected()
    executable = argv[0]
    if "/" in executable or "\\" in executable or executable not in _ALLOWED_EXECUTABLES:
        raise CommandRejected()
    return argv


def build_podman_argv(
    *,
    image: str,
    workspace: str | os.PathLike[str],
    name: str,
    command: Sequence[str],
    limits: SandboxLimits = SandboxLimits(),
    holder_timeout_seconds: int | None = None,
) -> list[str]:
    _validate_command(command)
    if not image or any(char.isspace() for char in image):
        raise ValueError("invalid image")
    if not _SAFE_NAME.fullmatch(name):
        raise ValueError("invalid container name")
    root = Path(workspace)
    if not root.is_absolute():
        raise ValueError("workspace must be absolute")
    if min(
        limits.cpus,
        limits.pids,
        limits.nofile,
        limits.wall_timeout_seconds,
        limits.command_timeout_seconds,
        limits.max_output_bytes,
        limits.uid,
        limits.gid,
    ) <= 0:
        raise ValueError("sandbox limits must be positive")
    holder_timeout = (
        limits.wall_timeout_seconds + RUNNER_CLEANUP_GRACE_SECONDS
        if holder_timeout_seconds is None
        else holder_timeout_seconds
    )
    if type(holder_timeout) is not int or holder_timeout <= 0:
        raise ValueError("holder timeout must be positive")
    return [
        "podman",
        "create",
        f"--name={name}",
        "--rm",
        "--pull=never",
        "--network=none",
        "--http-proxy=false",
        "--read-only",
        "--read-only-tmpfs=false",
        "--image-volume=ignore",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--pid=private",
        "--ipc=private",
        f"--pids-limit={limits.pids}",
        f"--memory={limits.memory}",
        f"--memory-swap={limits.memory}",
        f"--cpus={limits.cpus}",
        f"--ulimit=nofile={limits.nofile}:{limits.nofile}",
        f"--user={limits.uid}:{limits.gid}",
        f"--userns=keep-id:uid={limits.uid},gid={limits.gid}",
        "--workdir=/workspace",
        f"--label={_RUNNER_LABEL}",
        (
            "--tmpfs=/workspace:rw,exec,nosuid,nodev,notmpcopyup,"
            f"size={WORKSPACE_TMPFS_BYTES},nr_inodes={WORKSPACE_TMPFS_INODES},"
            f"uid={limits.uid},gid={limits.gid},mode=0700"
        ),
        "--tmpfs=/tmp:rw,exec,nosuid,nodev,size=64m,nr_inodes=8192",
        "--entrypoint=python3",
        image,
        "-I",
        "-c",
        f"import time; time.sleep({holder_timeout})",
    ]


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


def _bound_and_redact(value: str | bytes | None, limit: int) -> tuple[str, bool]:
    redacted = _SECRET.sub(lambda match: f"{match.group(1)}=[REDACTED]", _text(value))
    encoded = redacted.encode("utf-8")
    if len(encoded) <= limit:
        return redacted, False
    bounded = encoded[:limit].decode("utf-8", "ignore")
    return bounded, True


class _LifecycleFailure(RuntimeError):
    pass


class PodmanSandbox:
    def __init__(
        self,
        *,
        image: str,
        workspace: str | os.PathLike[str],
        name: str,
        limits: SandboxLimits = SandboxLimits(),
        executor: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.image = image
        self.workspace = Path(workspace)
        self.name = name
        self.limits = limits
        self._executor = executor
        self._clock = clock
        self._deadline = clock() + limits.wall_timeout_seconds
        self._lifecycle_failed = False

    @property
    def lifecycle_failed(self) -> bool:
        return self._lifecycle_failed

    def _remaining_wall_time(self) -> int:
        return int(self._deadline - self._clock())

    def _control(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        remaining = self._remaining_wall_time()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(argv, 0)
        completed = self._executor(
            argv,
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=remaining,
            check=False,
        )
        if completed.returncode != 0:
            raise _LifecycleFailure()
        return completed

    def _seed_workspace(self) -> None:
        if not self.workspace.is_dir() or self.workspace.is_symlink():
            raise _LifecycleFailure()
        self._control(
            [
                "podman",
                "cp",
                f"{self.workspace.resolve()}/.",
                f"{self.name}:/workspace",
            ]
        )

    def _completed_result(
        self,
        completed: subprocess.CompletedProcess[str],
        *,
        max_output_bytes: int | None = None,
    ) -> CommandResult:
        output_limit = (
            self.limits.max_output_bytes
            if max_output_bytes is None
            else max_output_bytes
        )
        stdout, stdout_cut = _bound_and_redact(
            completed.stdout, output_limit
        )
        remaining = max(
            0, output_limit - len(stdout.encode("utf-8"))
        )
        stderr, stderr_cut = _bound_and_redact(completed.stderr, remaining)
        truncated = stdout_cut or stderr_cut
        return CommandResult(
            completed.returncode,
            stdout,
            stderr,
            truncated=truncated,
        )

    def _timeout_result(
        self, error: subprocess.TimeoutExpired, *, max_output_bytes: int | None = None
    ) -> CommandResult:
        output_limit = (
            self.limits.max_output_bytes
            if max_output_bytes is None
            else max_output_bytes
        )
        stdout, stdout_cut = _bound_and_redact(
            error.output, output_limit
        )
        remaining = max(
            0, output_limit - len(stdout.encode("utf-8"))
        )
        stderr, stderr_cut = _bound_and_redact(error.stderr, remaining)
        return CommandResult(
            None,
            stdout,
            stderr,
            timed_out=True,
            truncated=stdout_cut or stderr_cut,
        )

    def _execute_bounded(
        self, argv: list[str], *, timeout: int, max_output_bytes: int | None = None
    ) -> CommandResult:
        output_limit = (
            self.limits.max_output_bytes
            if max_output_bytes is None
            else max_output_bytes
        )
        if self._executor is not subprocess.run:
            try:
                completed = self._executor(
                    argv,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                return self._timeout_result(error, max_output_bytes=output_limit)
            return self._completed_result(completed, max_output_bytes=output_limit)

        process = subprocess.Popen(
            argv,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        streams = (process.stdout, process.stderr)
        if any(stream is None for stream in streams):
            process.kill()
            process.wait()
            raise _LifecycleFailure()

        captured = {"stdout": bytearray(), "stderr": bytearray()}
        total = 0
        timed_out = False
        truncated = False
        deadline = self._clock() + timeout
        selector = selectors.DefaultSelector()
        try:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - self._clock()
                if remaining <= 0:
                    timed_out = True
                    break
                for key, _ in selector.select(min(0.1, remaining)):
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    room = output_limit - total
                    if room > 0:
                        captured[key.data].extend(chunk[:room])
                        total += min(room, len(chunk))
                    if len(chunk) > room:
                        truncated = True
                        break
                if truncated:
                    break
        finally:
            selector.close()

        if timed_out or truncated:
            process.kill()
        process.wait()
        for stream in streams:
            stream.close()

        completed = subprocess.CompletedProcess(
            argv,
            process.returncode,
            bytes(captured["stdout"]),
            bytes(captured["stderr"]),
        )
        result = self._completed_result(completed, max_output_bytes=output_limit)
        if timed_out:
            return CommandResult(
                None,
                result.stdout,
                result.stderr,
                timed_out=True,
                truncated=result.truncated,
            )
        if truncated:
            return CommandResult(
                None,
                result.stdout,
                result.stderr,
                truncated=True,
            )
        return result

    def _lifecycle_failure_result(self) -> CommandResult:
        self._lifecycle_failed = True
        stderr, truncated = _bound_and_redact(
            "sandbox lifecycle failed", self.limits.max_output_bytes
        )
        return CommandResult(None, "", stderr, truncated=truncated)

    def run_ephemeral(
        self, command: Sequence[str], *, timeout: int | None = None
    ) -> CommandResult:
        return self.run_ephemeral_batch(((command, timeout),))[0]

    def run_ephemeral_batch(
        self,
        commands: Sequence[tuple[Sequence[str], int | None]],
    ) -> tuple[CommandResult, ...]:
        """Run a bounded command batch in one disposable container."""

        if not 1 <= len(commands) <= MAX_EPHEMERAL_BATCH_COMMANDS:
            raise ValueError("invalid ephemeral batch size")
        validated = [(_validate_command(command), timeout) for command, timeout in commands]
        remaining_wall_time = self._remaining_wall_time()
        if remaining_wall_time <= 0:
            results = (
                CommandResult(
                    None,
                    "",
                    "sandbox wall-clock limit exceeded",
                    timed_out=True,
                ),
            )
            try:
                self._strict_remove()
            except _LifecycleFailure:
                return (self._lifecycle_failure_result(),)
            return results
        create_argv = build_podman_argv(
            image=self.image,
            workspace=self.workspace,
            name=self.name,
            command=validated[0][0],
            limits=self.limits,
            holder_timeout_seconds=(
                remaining_wall_time + RUNNER_CLEANUP_GRACE_SECONDS
            ),
        )
        for _command, timeout in validated:
            if timeout is not None and timeout <= 0:
                raise ValueError("timeout must be positive")
        results: list[CommandResult] = []
        remaining_output = self.limits.max_output_bytes
        try:
            self._control(create_argv)
            self._control(["podman", "start", self.name])
            self._seed_workspace()
            for command, timeout in validated:
                if remaining_output <= 0:
                    break
                bounded_timeout = min(
                    timeout
                    if timeout is not None
                    else self.limits.command_timeout_seconds,
                    self.limits.command_timeout_seconds,
                    self._remaining_wall_time(),
                )
                if bounded_timeout <= 0:
                    results.append(
                        CommandResult(
                            None,
                            "",
                            "sandbox wall-clock limit exceeded",
                            timed_out=True,
                        )
                    )
                    break
                result = self._execute_bounded(
                    ["podman", "exec", self.name, *command],
                    timeout=bounded_timeout,
                    max_output_bytes=remaining_output,
                )
                results.append(result)
                remaining_output -= len(result.stdout.encode("utf-8")) + len(
                    result.stderr.encode("utf-8")
                )
                if result.timed_out or result.truncated:
                    break
        except subprocess.TimeoutExpired as error:
            results.append(self._timeout_result(error))
        except Exception:
            results.append(self._lifecycle_failure_result())
        try:
            self._strict_remove()
        except _LifecycleFailure:
            return (self._lifecycle_failure_result(),)
        return tuple(results)

    def stage_patch_candidate(
        self,
        patch_file: str | os.PathLike[str],
        candidate_root: str | os.PathLike[str],
        *,
        timeout: int | None = None,
    ) -> CommandResult:
        """Apply one host-selected patch and copy out only an exact-success candidate."""

        source = Path(patch_file).absolute()
        candidate = Path(candidate_root).absolute()
        try:
            source_metadata = source.lstat()
            candidate_metadata = candidate.lstat()
            workspace_metadata = self.workspace.lstat()
        except OSError:
            return self._lifecycle_failure_result()
        if (
            not stat.S_ISREG(source_metadata.st_mode)
            or source_metadata.st_nlink != 1
            or not stat.S_ISDIR(candidate_metadata.st_mode)
            or stat.S_ISLNK(candidate_metadata.st_mode)
            or any(candidate.iterdir())
            or not stat.S_ISDIR(workspace_metadata.st_mode)
            or stat.S_ISLNK(workspace_metadata.st_mode)
            or candidate_metadata.st_dev != workspace_metadata.st_dev
        ):
            return self._lifecycle_failure_result()
        command = [
            "patch",
            "--batch",
            "--forward",
            "--strip=1",
            "--no-backup-if-mismatch",
            "--reject-file=-",
            "--input=/tmp/lil-tweak.patch",
        ]
        remaining_wall_time = self._remaining_wall_time()
        bounded_timeout = min(
            timeout if timeout is not None else self.limits.command_timeout_seconds,
            self.limits.command_timeout_seconds,
            remaining_wall_time,
        )
        if bounded_timeout <= 0 or remaining_wall_time <= 0:
            result = CommandResult(
                None,
                "",
                "sandbox wall-clock limit exceeded",
                timed_out=True,
            )
            try:
                self._strict_remove()
            except _LifecycleFailure:
                return self._lifecycle_failure_result()
            return result
        create_argv = build_podman_argv(
            image=self.image,
            workspace=self.workspace,
            name=self.name,
            command=command,
            limits=self.limits,
            holder_timeout_seconds=(
                remaining_wall_time + RUNNER_CLEANUP_GRACE_SECONDS
            ),
        )
        result: CommandResult
        try:
            self._control(create_argv)
            self._control(["podman", "start", self.name])
            self._seed_workspace()
            self._control(
                [
                    "podman",
                    "cp",
                    str(source),
                    f"{self.name}:/tmp/lil-tweak.patch",
                ]
            )
            bounded_timeout = min(bounded_timeout, self._remaining_wall_time())
            if bounded_timeout <= 0:
                result = CommandResult(
                    None,
                    "",
                    "sandbox wall-clock limit exceeded",
                    timed_out=True,
                )
            else:
                result = self._execute_bounded(
                    ["podman", "exec", self.name, *command], timeout=bounded_timeout
                )
                if (
                    result.exit_code == 0
                    and not result.timed_out
                    and not result.truncated
                ):
                    self._control(
                        ["podman", "cp", f"{self.name}:/workspace/.", str(candidate)]
                    )
        except subprocess.TimeoutExpired as error:
            result = self._timeout_result(error)
        except Exception:
            result = self._lifecycle_failure_result()
        try:
            self._strict_remove()
        except _LifecycleFailure:
            return self._lifecycle_failure_result()
        return result

    def _strict_remove(self) -> None:
        try:
            completed = self._executor(
                ["podman", "rm", "--force", "--ignore", self.name],
                shell=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=RUNNER_CLEANUP_GRACE_SECONDS,
                check=False,
            )
            if completed.returncode != 0:
                raise _LifecycleFailure()
        except _LifecycleFailure:
            self._lifecycle_failed = True
            raise
        except Exception:
            self._lifecycle_failed = True
            raise _LifecycleFailure() from None

    def teardown(self) -> None:
        try:
            self._strict_remove()
        except _LifecycleFailure:
            raise RuntimeError("sandbox lifecycle failed") from None

    @classmethod
    def cleanup_stale(
        cls,
        *,
        executor: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        try:
            completed = executor(
                [
                    "podman",
                    "ps",
                    "--all",
                    "--quiet",
                    "--no-trunc",
                    f"--filter=label={_RUNNER_LABEL}",
                ],
                shell=False,
                capture_output=True,
                text=True,
                timeout=RUNNER_CLEANUP_GRACE_SECONDS,
                check=False,
            )
            if completed.returncode != 0:
                raise _LifecycleFailure()
            for container_id in _text(completed.stdout).splitlines():
                if not _CONTAINER_ID.fullmatch(container_id):
                    raise _LifecycleFailure()
                removed = executor(
                    ["podman", "rm", "--force", "--ignore", container_id],
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=RUNNER_CLEANUP_GRACE_SECONDS,
                    check=False,
                )
                if removed.returncode != 0:
                    raise _LifecycleFailure()
        except Exception:
            raise RuntimeError("sandbox lifecycle failed") from None
