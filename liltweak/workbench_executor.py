from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import re
import shutil
import signal
import tempfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from .workbench_contract import (
    NetworkMode,
    ToolKind,
    ToolRequest,
    ToolRunRecord,
)
from .workbench_security import (
    SecurityBoundaryError,
    WorkspacePathGuard,
    private_directory,
    redact,
)


class ExecutorUnavailableError(RuntimeError):
    pass


class ToolExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProcessResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    canceled: bool


class ProcessTransport(Protocol):
    @property
    def connected(self) -> bool: ...

    async def run(
        self,
        *,
        executable: str,
        args: tuple[str, ...],
        cwd: Path,
        timeout_seconds: int,
        output_byte_limit: int,
        network: NetworkMode,
        cancel_event: asyncio.Event,
    ) -> ProcessResult: ...


class DisconnectedProcessTransport:
    connected = False

    async def run(self, **_: object) -> ProcessResult:
        raise ExecutorUnavailableError("qualified command runner is not connected")


class QualifiedProcessTransport:
    """Candidate transport. Construct only after independent runner qualification."""

    def __init__(
        self,
        *,
        sandbox_prefix: tuple[str, ...],
        qualification_digest: str,
        network_namespace_enforced: bool,
    ) -> None:
        if (
            not sandbox_prefix
            or len(sandbox_prefix) > 32
            or re.fullmatch(r"[0-9a-f]{64}", qualification_digest) is None
        ):
            raise ValueError("qualified transport requires pinned sandbox bindings")
        if Path(sandbox_prefix[0]).name.casefold() in {
            "bash",
            "sh",
            "cmd",
            "powershell",
            "pwsh",
        }:
            raise ValueError("qualified transport prefix cannot be a shell")
        if any(
            not value
            or "\x00" in value
            or "\n" in value
            or "\r" in value
            or value.casefold() in {"-c", "/c", "-command"}
            for value in sandbox_prefix
        ):
            raise ValueError("qualified transport prefix is invalid")
        if not network_namespace_enforced:
            raise ValueError("qualified transport requires enforced network namespaces")
        self._prefix = sandbox_prefix
        self._qualification_digest = qualification_digest
        self._connected = True

    @property
    def connected(self) -> bool:
        return self._connected

    async def run(
        self,
        *,
        executable: str,
        args: tuple[str, ...],
        cwd: Path,
        timeout_seconds: int,
        output_byte_limit: int,
        network: NetworkMode,
        cancel_event: asyncio.Event,
    ) -> ProcessResult:
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": str(cwd / ".task-home"),
            "TMPDIR": str(cwd / ".tmp"),
            "LILTWEAK_RUNNER_QUALIFICATION_DIGEST": self._qualification_digest,
            "LILTWEAK_NETWORK_MODE": network.value,
        }
        Path(environment["HOME"]).mkdir(mode=0o700, exist_ok=True)
        Path(environment["TMPDIR"]).mkdir(mode=0o700, exist_ok=True)
        process = await asyncio.create_subprocess_exec(
            *self._prefix,
            executable,
            *args,
            cwd=cwd,
            env=environment,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        if process.stdout is None or process.stderr is None:
            self._terminate_tree(process.pid)
            raise ToolExecutionError("bounded output pipes were not created")
        budget = {"remaining": output_byte_limit}
        budget_lock = asyncio.Lock()
        overflow = asyncio.Event()
        stdout_capture = asyncio.create_task(
            self._capture(process.stdout, budget, budget_lock, overflow)
        )
        stderr_capture = asyncio.create_task(
            self._capture(process.stderr, budget, budget_lock, overflow)
        )
        process_wait = asyncio.create_task(process.wait())
        cancel_wait = asyncio.create_task(cancel_event.wait())
        overflow_wait = asyncio.create_task(overflow.wait())
        timed_out = False
        canceled = False
        try:
            done, _ = await asyncio.wait(
                {process_wait, cancel_wait, overflow_wait},
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if process_wait not in done:
                timed_out = not cancel_event.is_set() and not overflow.is_set()
                canceled = cancel_event.is_set()
                await self._terminate_and_wait(process)
            stdout, stderr = await asyncio.gather(stdout_capture, stderr_capture)
        finally:
            cancel_wait.cancel()
            overflow_wait.cancel()
            if not process_wait.done():
                process_wait.cancel()
        if overflow.is_set():
            stderr += b"\n[OUTPUT LIMIT REACHED]"
            if process.returncode in {0, None}:
                return ProcessResult(125, stdout, stderr, timed_out, canceled)
        return ProcessResult(process.returncode, stdout, stderr, timed_out, canceled)

    @staticmethod
    async def _capture(
        stream: asyncio.StreamReader,
        budget: dict[str, int],
        lock: asyncio.Lock,
        overflow: asyncio.Event,
    ) -> bytes:
        captured = bytearray()
        while True:
            chunk = await stream.read(16_384)
            if not chunk:
                return bytes(captured)
            async with lock:
                remaining = budget["remaining"]
                if remaining <= 0:
                    overflow.set()
                    continue
                admitted = chunk[:remaining]
                budget["remaining"] = remaining - len(admitted)
                captured.extend(admitted)
                if len(admitted) != len(chunk):
                    overflow.set()

    @classmethod
    async def _terminate_and_wait(cls, process: asyncio.subprocess.Process) -> None:
        cls._terminate_tree(process.pid)
        try:
            await asyncio.wait_for(process.wait(), timeout=2)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            await process.wait()

    @staticmethod
    def _terminate_tree(process_id: int) -> None:
        try:
            os.killpg(process_id, signal.SIGTERM)
        except ProcessLookupError:
            return


class TaskWorkspaceManager:
    def __init__(
        self,
        root: Path,
        *,
        max_files: int = 10_000,
        max_bytes: int = 250_000_000,
    ) -> None:
        self.root = private_directory(root.resolve())
        self.max_files = max_files
        self.max_bytes = max_bytes

    def task_root(self, task_id: str) -> Path:
        if not task_id or any(value in task_id for value in ("/", "\\", "..")):
            raise SecurityBoundaryError("task identifier is invalid")
        return private_directory(self.root / task_id)

    def guard(self, task_id: str) -> WorkspacePathGuard:
        root = self.task_root(task_id)
        return WorkspacePathGuard(root, max_files=self.max_files, max_bytes=self.max_bytes)

    def snapshot(self, task_id: str, attempt: int) -> tuple[Path, str]:
        source = self.task_root(task_id)
        guard = self.guard(task_id)
        guard.inventory()
        recovery = private_directory(self.root / "_recovery")
        destination = recovery / f"{task_id}-{attempt}"
        if destination.exists():
            raise ToolExecutionError("recovery snapshot already exists for this attempt")
        shutil.copytree(source, destination, symlinks=False)
        digest = self.tree_digest(destination)
        return destination, digest

    def rollback(self, task_id: str, snapshot: Path) -> str:
        target = self.task_root(task_id)
        if not snapshot.resolve().is_relative_to((self.root / "_recovery").resolve()):
            raise SecurityBoundaryError("rollback snapshot is outside the recovery root")
        staged = Path(tempfile.mkdtemp(prefix=f"{task_id}-rollback-", dir=self.root))
        try:
            shutil.copytree(snapshot, staged / "tree", dirs_exist_ok=True)
            old = self.root / f".{task_id}.old"
            if old.exists():
                shutil.rmtree(old)
            os.replace(target, old)
            os.replace(staged / "tree", target)
            shutil.rmtree(old)
        finally:
            shutil.rmtree(staged, ignore_errors=True)
        return self.tree_digest(target)

    def discard_snapshot(self, snapshot: Path) -> None:
        recovery_root = (self.root / "_recovery").resolve()
        resolved = snapshot.resolve()
        if not resolved.is_relative_to(recovery_root) or resolved == recovery_root:
            raise SecurityBoundaryError("snapshot deletion target is invalid")
        shutil.rmtree(resolved)

    @staticmethod
    def tree_digest(root: Path) -> str:
        digest = hashlib.sha256()
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise SecurityBoundaryError("symlink found while hashing task workspace")
            if path.is_file():
                digest.update(b"file\0")
                digest.update(relative.encode())
                digest.update(b"\0")
                digest.update(path.read_bytes())
            elif path.is_dir():
                digest.update(b"dir\0")
                digest.update(relative.encode())
                digest.update(b"\0")
            else:
                raise SecurityBoundaryError("special file found while hashing task workspace")
        return digest.hexdigest()


class BoundedToolExecutor:
    def __init__(self, workspaces: TaskWorkspaceManager, transport: ProcessTransport) -> None:
        self.workspaces = workspaces
        self.transport = transport
        self._cancel_events: dict[str, asyncio.Event] = {}

    @property
    def connected(self) -> bool:
        return self.transport.connected

    def cancel(self, task_id: str) -> None:
        self._cancel_events.setdefault(task_id, asyncio.Event()).set()

    async def execute(
        self,
        *,
        task_id: str,
        attempt: int,
        request: ToolRequest,
        evidence_id: str,
    ) -> ToolRunRecord:
        started = datetime.now(UTC)
        cancel_event = self._cancel_events.setdefault(task_id, asyncio.Event())
        guard = self.workspaces.guard(task_id)
        exit_code: int | None = 0
        timed_out = False
        canceled = cancel_event.is_set()
        network = NetworkMode.DENIED
        output = ""
        success = False
        executable: str | None = None
        args: tuple[str, ...] = ()
        working_directory = "."
        try:
            if canceled:
                raise ToolExecutionError("task was canceled before tool execution")
            if request.kind == ToolKind.COMMAND:
                if request.command is None:
                    raise ToolExecutionError("command payload is missing")
                if not self.transport.connected:
                    raise ExecutorUnavailableError("qualified command runner is disconnected")
                command = request.command
                cwd = guard.resolve(command.working_directory)
                if not cwd.is_dir():
                    raise ToolExecutionError("command working directory does not exist")
                executable = command.executable
                args = command.args
                working_directory = command.working_directory
                network = command.network
                process = await self.transport.run(
                    executable=executable,
                    args=args,
                    cwd=cwd,
                    timeout_seconds=command.timeout_seconds,
                    output_byte_limit=command.output_byte_limit,
                    network=command.network,
                    cancel_event=cancel_event,
                )
                exit_code = process.exit_code
                timed_out = process.timed_out
                canceled = process.canceled
                output = (
                    "STDOUT\n"
                    + process.stdout.decode("utf-8", errors="replace")
                    + "\nSTDERR\n"
                    + process.stderr.decode("utf-8", errors="replace")
                )
                success = exit_code == 0 and not timed_out and not canceled
            else:
                output = self._file_operation(guard, request)
                success = True
            guard.inventory()
        except Exception as exc:
            output = f"{type(exc).__name__}: {exc}"
            if exit_code == 0:
                exit_code = 1
        ended = datetime.now(UTC)
        redacted = redact(output)
        return ToolRunRecord(
            id=f"run:{uuid.uuid4().hex}",
            task_id=task_id,
            attempt=attempt,
            tool_id=request.tool_id,
            request_digest=request.request_digest,
            executable=executable,
            args=args,
            working_directory=working_directory,
            started_at=started,
            ended_at=ended,
            exit_code=exit_code,
            timed_out=timed_out,
            canceled=canceled,
            output_digest=hashlib.sha256(output.encode("utf-8")).hexdigest(),
            redacted_output=redacted,
            network_status=network,
            evidence_id=evidence_id,
            success=success,
        )

    @staticmethod
    def _file_operation(guard: WorkspacePathGuard, request: ToolRequest) -> str:
        if request.file is None:
            raise ToolExecutionError("file payload is missing")
        target = guard.resolve(
            request.file.path,
            allow_missing=request.kind in {ToolKind.WRITE_FILE, ToolKind.APPLY_PATCH},
        )
        if request.kind == ToolKind.LIST_FILES:
            if not target.is_dir():
                raise ToolExecutionError("list target is not a directory")
            files = sorted(path.relative_to(guard.root).as_posix() for path in target.rglob("*"))
            return "\n".join(files[:10_000])
        if request.kind == ToolKind.READ_FILE:
            if not target.is_file():
                raise ToolExecutionError("read target is not a regular file")
            return target.read_text(encoding="utf-8")
        if request.file.content is None:
            raise ToolExecutionError("write operation requires content")
        if request.kind == ToolKind.APPLY_PATCH and request.file.expected_sha256 is None:
            raise ToolExecutionError("conditional patch requires the expected source digest")
        if target.exists() and request.file.expected_sha256 is not None:
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
            if actual != request.file.expected_sha256:
                raise ToolExecutionError("target changed since the approved plan")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".liltweak-", dir=target.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(request.file.content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, target)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)
        return f"atomic write completed: {request.file.path}"
