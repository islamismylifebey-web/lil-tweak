from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from .repository import secret_rule_ids
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

    @property
    def provider_name(self) -> str: ...

    @property
    def qualification_status(self) -> str: ...

    @property
    def authorization_digest(self) -> str | None: ...

    @property
    def server_authorized(self) -> bool: ...

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
    provider_name = "none"
    qualification_status = "unavailable"
    authorization_digest = None
    server_authorized = False
    disconnect_reason = "No qualified bounded command runner is configured."

    async def run(self, **_: object) -> ProcessResult:
        raise ExecutorUnavailableError("qualified command runner is not connected")


class QualifiedProcessTransport:
    """Dormant transport descriptor; it cannot authorize a runner connection.

    A caller-supplied digest and assertion are not runner qualification. A future provider must
    verify an independently signed qualification decision and enforce the bound sandbox and
    network policy before it may implement ``ProcessTransport.connected`` as true.
    """

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
        self.sandbox_prefix = sandbox_prefix
        self.qualification_digest = qualification_digest
        self.network_namespace_enforced = network_namespace_enforced

    provider_name = "dormant-qualified-descriptor"
    qualification_status = "unqualified"
    authorization_digest = None
    server_authorized = False
    disconnect_reason = (
        "No independently qualified Workbench runner provider is implemented; the runner remains "
        "disconnected."
    )

    @property
    def connected(self) -> bool:
        return False

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
        raise ExecutorUnavailableError(
            "no independently qualified Workbench runner provider is implemented"
        )


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

    def discard_task_workspace(self, task_id: str) -> None:
        target = (self.root / task_id).resolve()
        if target == self.root or not target.is_relative_to(self.root):
            raise SecurityBoundaryError("task workspace deletion target is invalid")
        if target.exists():
            if target.is_symlink() or not target.is_dir():
                raise SecurityBoundaryError("task workspace deletion target is unsafe")
            shutil.rmtree(target)

    def expected_artifacts(
        self, task_id: str, paths: tuple[str, ...]
    ) -> tuple[dict[str, object], ...]:
        guard = self.guard(task_id)
        verified: list[dict[str, object]] = []
        for relative in paths:
            target = guard.resolve(relative)
            if not target.is_file():
                raise ToolExecutionError(f"expected artifact is missing: {relative}")
            if target.stat().st_size > 50_000_000:
                raise ToolExecutionError(f"expected artifact exceeds the size limit: {relative}")
            data = target.read_bytes()
            verified.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                    "executable": bool(target.stat().st_mode & 0o111),
                }
            )
        return tuple(verified)

    def verify_artifacts(
        self,
        task_id: str,
        manifests: object,
    ) -> tuple[dict[str, object], ...]:
        if not isinstance(manifests, list):
            raise ToolExecutionError("authenticated artifact manifest is invalid")
        paths: list[str] = []
        expected: list[dict[str, object]] = []
        for item in manifests:
            if not isinstance(item, Mapping) or set(item) != {
                "path",
                "sha256",
                "bytes",
                "executable",
            }:
                raise ToolExecutionError("authenticated artifact manifest is invalid")
            path = item["path"]
            if not isinstance(path, str):
                raise ToolExecutionError("authenticated artifact path is invalid")
            paths.append(path)
            expected.append(dict(item))
        current = self.expected_artifacts(task_id, tuple(paths))
        if list(current) != expected:
            raise ToolExecutionError("verified artifact changed after completion")
        return current

    def discard_server_transients(self, task_id: str, snapshot: Path) -> tuple[str, ...]:
        """Remove only newly-created, server-owned Python test caches.

        Baseline paths are never removed, and the candidate cannot extend this allowlist.
        """

        source = self.task_root(task_id)
        baseline = self._file_states(snapshot)
        removed: list[str] = []
        cache_directories = [
            path
            for path in source.rglob("*")
            if path.is_dir() and path.name in {".pytest_cache", "__pycache__"}
        ]
        for directory in sorted(cache_directories, key=lambda item: len(item.parts), reverse=True):
            relative = directory.relative_to(source).as_posix()
            baseline_prefix = f"{relative}/"
            baseline_paths = {
                path for path in baseline if path == relative or path.startswith(baseline_prefix)
            }
            if not baseline_paths:
                if directory.is_symlink():
                    raise SecurityBoundaryError("symlink found while removing test transients")
                shutil.rmtree(directory)
                removed.append(relative)
                continue
            for descendant in sorted(
                directory.rglob("*"), key=lambda item: len(item.parts), reverse=True
            ):
                descendant_relative = descendant.relative_to(source).as_posix()
                if descendant.is_symlink():
                    raise SecurityBoundaryError("symlink found while removing test transients")
                if descendant.is_file() and descendant_relative not in baseline_paths:
                    descendant.unlink()
                    removed.append(descendant_relative)
                elif descendant.is_dir() and not any(
                    path.startswith(f"{descendant_relative}/") for path in baseline_paths
                ):
                    descendant.rmdir()
        for path in sorted(source.rglob("*.py[co]")):
            if path.is_symlink() or not path.is_file():
                raise SecurityBoundaryError("unsafe Python cache file found in task workspace")
            relative = path.relative_to(source).as_posix()
            if relative not in baseline:
                path.unlink()
                removed.append(relative)
        return tuple(sorted(removed))

    def generate_patch(
        self,
        task_id: str,
        attempt: int,
        snapshot: Path,
    ) -> tuple[str, str, tuple[str, ...]]:
        """Generate a private, deterministic patch against the recovery snapshot."""

        source = self.task_root(task_id)
        recovery_root = (self.root / "_recovery").resolve()
        resolved_snapshot = snapshot.resolve()
        if not resolved_snapshot.is_relative_to(recovery_root):
            raise SecurityBoundaryError("patch baseline is outside the recovery root")
        before = self._file_states(resolved_snapshot)
        after = self._file_states(source)
        changed = tuple(
            sorted(
                path for path in before.keys() | after.keys() if before.get(path) != after.get(path)
            )
        )
        for relative in changed:
            state = after.get(relative)
            if state is not None and secret_rule_ids(state[1]):
                raise ToolExecutionError(
                    f"changed file contains secret-shaped material: {relative}"
                )
        rendered = self._render_git_patch(resolved_snapshot, source, before, after)
        if len(rendered) > 8_000_000:
            raise ToolExecutionError("generated patch exceeds the private artifact limit")
        if secret_rule_ids(rendered):
            raise ToolExecutionError("generated patch contains secret-shaped material")
        self._verify_patch_round_trip(resolved_snapshot, source, rendered)
        patch_digest = hashlib.sha256(rendered).hexdigest()
        artifact_root = private_directory(self.root / "_artifacts" / task_id)
        destination = artifact_root / f"attempt-{attempt}-{patch_digest}.patch"
        self._atomic_private_write(destination, rendered)
        return destination.name, patch_digest, changed

    def read_patch(self, task_id: str, artifact_name: str, expected_digest: str) -> str:
        artifact_root = (self.root / "_artifacts" / task_id).resolve()
        if re.fullmatch(r"attempt-[1-9][0-9]*-[0-9a-f]{64}\.patch", artifact_name) is None:
            raise ToolExecutionError("private patch artifact name is invalid")
        target = (artifact_root / artifact_name).resolve()
        if not target.is_relative_to(artifact_root) or not target.is_file() or target.is_symlink():
            raise ToolExecutionError("private patch artifact is unavailable")
        if target.stat().st_size > 8_000_000:
            raise ToolExecutionError("private patch artifact exceeds its size limit")
        rendered = target.read_bytes()
        if not hmac.compare_digest(hashlib.sha256(rendered).hexdigest(), expected_digest):
            raise ToolExecutionError("private patch artifact failed authenticated digest check")
        if secret_rule_ids(rendered):
            raise ToolExecutionError("private patch artifact contains secret-shaped material")
        try:
            return rendered.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ToolExecutionError("private patch artifact encoding is invalid") from exc

    @staticmethod
    def _file_states(root: Path) -> dict[str, tuple[int, bytes]]:
        files: dict[str, tuple[int, bytes]] = {}
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            if any(part.casefold() == ".git" for part in relative.parts):
                raise SecurityBoundaryError("Git control directory found while generating patch")
            if path.is_symlink():
                raise SecurityBoundaryError("symlink found while generating patch")
            if path.is_file():
                mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                files[relative.as_posix()] = (mode, path.read_bytes())
            elif not path.is_dir():
                raise SecurityBoundaryError("special file found while generating patch")
        return files

    @staticmethod
    def _atomic_private_write(destination: Path, content: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".liltweak-", dir=destination.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, destination)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)

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
                digest.update(b"755" if path.stat().st_mode & 0o111 else b"644")
                digest.update(b"\0")
                digest.update(path.read_bytes())
            elif not path.is_dir():
                raise SecurityBoundaryError("special file found while hashing task workspace")
        return digest.hexdigest()

    def _render_git_patch(
        self,
        snapshot: Path,
        source: Path,
        before: dict[str, tuple[int, bytes]],
        after: dict[str, tuple[int, bytes]],
    ) -> bytes:
        temporary = Path(tempfile.mkdtemp(prefix=".patch-render-", dir=self.root))
        try:
            repository = temporary / "repository"
            shutil.copytree(snapshot, repository, symlinks=False)
            self._git(("init", "--quiet"), repository)
            (repository / ".git" / "info" / "attributes").write_text(
                "* -text -filter -ident !working-tree-encoding !diff\n",
                encoding="ascii",
            )
            self._git(("add", "--all"), repository)
            for child in repository.iterdir():
                if child.name == ".git":
                    continue
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child)
                else:
                    child.unlink()
            shutil.copytree(source, repository, dirs_exist_ok=True, symlinks=False)
            new_paths = sorted(after.keys() - before.keys())
            for offset in range(0, len(new_paths), 100):
                self._git(
                    ("add", "--intent-to-add", "--", *new_paths[offset : offset + 100]),
                    repository,
                )
            return self._git(
                (
                    "diff",
                    "--binary",
                    "--full-index",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-renames",
                    "--src-prefix=a/",
                    "--dst-prefix=b/",
                    "--",
                    ".",
                ),
                repository,
            )
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    def _verify_patch_round_trip(self, snapshot: Path, source: Path, patch: bytes) -> None:
        if not patch:
            if self.tree_digest(snapshot) != self.tree_digest(source):
                raise ToolExecutionError("empty patch does not reproduce the final source tree")
            return
        temporary = Path(tempfile.mkdtemp(prefix=".patch-verify-", dir=self.root))
        try:
            candidate = temporary / "candidate"
            shutil.copytree(snapshot, candidate, symlinks=False)
            self._git(("apply", "--check", "--binary", "-"), candidate, input_bytes=patch)
            self._git(("apply", "--binary", "-"), candidate, input_bytes=patch)
            if self.tree_digest(candidate) != self.tree_digest(source):
                raise ToolExecutionError("generated patch failed exact round-trip verification")
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    @staticmethod
    def _git(
        args: tuple[str, ...],
        cwd: Path,
        *,
        input_bytes: bytes | None = None,
    ) -> bytes:
        binary = shutil.which("git", path="/usr/local/bin:/usr/bin:/bin")
        if binary is None:
            raise ToolExecutionError("Git is unavailable for deterministic patch generation")
        environment = {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "LANG": "C",
            "LC_ALL": "C",
        }
        hardened_configuration = (
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "core.excludesFile=/dev/null",
            "-c",
            "protocol.allow=never",
        )
        try:
            result = subprocess.run(
                (str(Path(binary).resolve()), *hardened_configuration, *args),
                cwd=cwd,
                env=environment,
                input=input_bytes,
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolExecutionError("deterministic Git patch operation failed") from exc
        if result.returncode != 0:
            raise ToolExecutionError("deterministic Git patch operation failed")
        if len(result.stdout) > 8_000_000 or len(result.stderr) > 1_000_000:
            raise ToolExecutionError("deterministic Git patch operation exceeded output bounds")
        return result.stdout


class BoundedToolExecutor:
    def __init__(
        self,
        workspaces: TaskWorkspaceManager,
        transport: ProcessTransport,
        *,
        allow_test_transport: bool = False,
    ) -> None:
        if allow_test_transport and "PYTEST_CURRENT_TEST" not in os.environ:
            raise ValueError("test transport override is available only inside pytest")
        self.workspaces = workspaces
        self.transport = transport
        self._allow_test_transport = allow_test_transport
        self._cancel_events: dict[str, asyncio.Event] = {}

    @property
    def _transport_enabled(self) -> bool:
        return bool(
            self._allow_test_transport or getattr(self.transport, "server_authorized", False)
        )

    @property
    def connected(self) -> bool:
        return bool(
            self._transport_enabled
            and self.transport.connected
            and self.qualification_status == "qualified"
            and self.authorization_digest is not None
        )

    @property
    def provider_name(self) -> str:
        return str(getattr(self.transport, "provider_name", type(self.transport).__name__))

    @property
    def qualification_status(self) -> str:
        if not self._transport_enabled:
            if isinstance(self.transport, DisconnectedProcessTransport):
                return "unavailable"
            return "unqualified"
        value = str(getattr(self.transport, "qualification_status", "unqualified"))
        return value if value in {"qualified", "unqualified", "unavailable"} else "unqualified"

    @property
    def authorization_digest(self) -> str | None:
        if not self._transport_enabled:
            return None
        value = getattr(self.transport, "authorization_digest", None)
        return (
            value
            if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
            else None
        )

    @property
    def disconnect_reason(self) -> str:
        value = getattr(self.transport, "disconnect_reason", None)
        if isinstance(value, str) and value.strip():
            return value
        return "qualified bounded command runner is disconnected"

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
            if not self.connected:
                raise ExecutorUnavailableError(self.disconnect_reason)
            action_for_request = getattr(self.transport, "action_for_request", None)
            if callable(action_for_request):
                action_for_request(request)
            if request.kind == ToolKind.COMMAND:
                if request.command is None:
                    raise ToolExecutionError("command payload is missing")
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
