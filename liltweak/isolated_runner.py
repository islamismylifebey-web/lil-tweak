from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import shutil
import signal
import stat
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .execution_contract import (
    ExecutionRecipe,
    ProcessObservation,
    RepositoryExecutionPlan,
    RunnerAttestation,
    SandboxExecutionEvidence,
    SandboxProfile,
)
from .models import RepositoryRef
from .source_snapshot import RepositorySnapshotBuilder


class IsolationUnavailableError(RuntimeError):
    pass


class SandboxExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class _CapturedStream:
    digest: str
    byte_count: int
    limit_exceeded: bool


@dataclass
class _OutputBudget:
    limit: int
    retained: int = 0


class BubblewrapSandboxExecutor:
    """Verification-only Bubblewrap adapter. It never mounts the registered repository."""

    def __init__(
        self,
        *,
        snapshot_builder: RepositorySnapshotBuilder,
        runtime_root: Path,
        image_ref: str,
        runtime_path: Path = Path("/usr/bin/bwrap"),
        limiter_path: Path = Path("/usr/bin/prlimit"),
    ) -> None:
        self.snapshot_builder = snapshot_builder
        self.image_ref = image_ref
        self.runtime_root = self._trusted_path(runtime_root, "runtime root")
        self.runtime_path = self._trusted_path(runtime_path, "Bubblewrap runtime")
        self.limiter_path = self._trusted_path(limiter_path, "resource limiter")
        self._connected = False
        self._capability_probe_passed = False
        self._validate_host_paths()
        self._runtime_sha256 = self._file_digest(self.runtime_path)
        self._limiter_sha256 = self._file_digest(self.limiter_path)

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def capability_probe_passed(self) -> bool:
        return self._capability_probe_passed

    def profile_for(self, recipe: ExecutionRecipe) -> SandboxProfile:
        if recipe.image_ref != self.image_ref:
            raise IsolationUnavailableError("execution recipe does not match the pinned runtime")
        return SandboxProfile(
            runtime_sha256=self._runtime_sha256,
            limiter_sha256=self._limiter_sha256,
            image_ref=self.image_ref,
            container_user=recipe.container_user,
        )

    async def probe(self, recipe: ExecutionRecipe) -> bool:
        """Run a synthetic offline namespace probe before reporting connectivity."""
        profile = self.profile_for(recipe)
        probe_root = Path(tempfile.mkdtemp(prefix="liltweak-probe-", dir="/tmp"))
        os.chmod(probe_root, 0o700)
        source = probe_root / "source"
        source.mkdir(mode=0o555)
        try:
            command = self._sandbox_command(
                recipe=recipe,
                source=source,
                argv=("true",),
            )
            observation = await self._run_command(
                command_id="isolation-probe",
                command=command,
                timeout_seconds=min(10, recipe.wall_clock_seconds),
                output_budget=_OutputBudget(limit=16_384),
            )
            self._capability_probe_passed = (
                observation.exit_code == 0
                and not observation.timed_out
                and not observation.output_limit_exceeded
                and profile.network_namespace_isolated
            )
        except Exception:
            self._capability_probe_passed = False
        finally:
            self._make_removable(probe_root)
            shutil.rmtree(probe_root, ignore_errors=True)
            if probe_root.exists():
                self._capability_probe_passed = False
        # A namespace smoke check is not a production isolation qualification.
        # The 0.7 candidate adapter remains permanently disconnected.
        self._connected = False
        return False

    async def execute(
        self,
        *,
        plan: RepositoryExecutionPlan,
        recipe: ExecutionRecipe,
        reference: RepositoryRef,
    ) -> SandboxExecutionEvidence:
        if not self._connected:
            raise IsolationUnavailableError(
                "Bubblewrap isolation has not passed its capability probe"
            )
        profile = self.profile_for(recipe)
        if (
            recipe.recipe_digest != plan.recipe_digest
            or recipe.commands != plan.commands
            or profile.profile_digest != plan.sandbox_profile_digest
        ):
            raise SandboxExecutionError("execution inputs do not match the approved plan")

        session_id = f"sandbox_{uuid.uuid4().hex}"
        sandbox_root = Path(tempfile.mkdtemp(prefix="liltweak-sandbox-", dir="/tmp"))
        os.chmod(sandbox_root, 0o700)
        source = sandbox_root / "source"
        observations: list[ProcessObservation] = []
        output_budget = _OutputBudget(limit=plan.output_byte_limit)
        started = time.monotonic()
        cleanup_verified = False
        try:
            await asyncio.to_thread(
                self.snapshot_builder.materialize,
                reference,
                plan.source,
                source,
            )
            source_before = await asyncio.to_thread(
                self.snapshot_builder._digest_materialized_tree,
                source,
            )
            for command in recipe.commands:
                remaining = plan.wall_clock_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    raise SandboxExecutionError("execution exceeded the aggregate wall-clock limit")
                invocation = self._sandbox_command(
                    recipe=recipe,
                    source=source,
                    argv=command.argv,
                )
                observations.append(
                    await self._run_command(
                        command_id=command.command_id,
                        command=invocation,
                        timeout_seconds=min(command.timeout_seconds, max(1, int(remaining))),
                        output_budget=output_budget,
                    )
                )
                if observations[-1].timed_out or observations[-1].output_limit_exceeded:
                    break
            source_after = await asyncio.to_thread(
                self.snapshot_builder._digest_materialized_tree,
                source,
            )
        finally:
            await asyncio.to_thread(self._remove_tree, sandbox_root)
            cleanup_verified = not sandbox_root.exists()

        attestation = RunnerAttestation(
            attempt_nonce=plan.attempt_nonce,
            runtime_sha256=self._runtime_sha256,
            limiter_sha256=self._limiter_sha256,
            sandbox_profile_digest=profile.profile_digest,
            image_ref=self.image_ref,
            cleanup_verified=cleanup_verified,
        )
        return SandboxExecutionEvidence(
            plan_digest=plan.plan_digest,
            session_id=session_id,
            source_before_digest=source_before,
            source_after_digest=source_after,
            observations=tuple(observations),
            attestation=attestation,
        )

    def _sandbox_command(
        self,
        *,
        recipe: ExecutionRecipe,
        source: Path,
        argv: tuple[str, ...],
    ) -> tuple[str, ...]:
        memory_bytes = recipe.memory_megabytes * 1024 * 1024
        user_id, group_id = recipe.container_user.split(":", 1)
        return (
            str(self.limiter_path),
            f"--as={memory_bytes}:{memory_bytes}",
            f"--cpu={recipe.wall_clock_seconds}:{recipe.wall_clock_seconds}",
            f"--nproc={recipe.pid_limit}:{recipe.pid_limit}",
            f"--fsize={recipe.file_size_limit_bytes}:{recipe.file_size_limit_bytes}",
            "--nofile=256:256",
            "--",
            str(self.runtime_path),
            "--unshare-all",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--cap-drop",
            "ALL",
            "--uid",
            user_id,
            "--gid",
            group_id,
            "--ro-bind",
            str(self.runtime_root),
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/workspace",
            "--ro-bind",
            str(source),
            "/workspace/source",
            "--chdir",
            "/workspace/source",
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "XDG_CACHE_HOME",
            "/tmp/.cache",
            "--setenv",
            "UV_CACHE_DIR",
            "/tmp/uv-cache",
            "--setenv",
            "PYTHONDONTWRITEBYTECODE",
            "1",
            "--setenv",
            "PYTHONNOUSERSITE",
            "1",
            "--setenv",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
            "1",
            "--setenv",
            "PATH",
            "/usr/local/bin:/usr/bin:/bin",
            "--",
            *argv,
        )

    async def _run_command(
        self,
        *,
        command_id: str,
        command: tuple[str, ...],
        timeout_seconds: int,
        output_budget: _OutputBudget,
    ) -> ProcessObservation:
        started = time.monotonic()
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                },
                start_new_session=True,
            )
        except OSError as exc:
            raise IsolationUnavailableError("isolated runner process could not start") from exc
        assert process.stdout is not None
        assert process.stderr is not None
        overflow = asyncio.Event()
        stdout_task = asyncio.create_task(self._capture(process.stdout, output_budget, overflow))
        stderr_task = asyncio.create_task(self._capture(process.stderr, output_budget, overflow))
        wait_task = asyncio.create_task(process.wait())
        overflow_task = asyncio.create_task(overflow.wait())
        timed_out = False
        try:
            done, _pending = await asyncio.wait(
                {wait_task, overflow_task},
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                timed_out = True
                self._kill_process_group(process.pid)
            elif overflow_task in done and overflow.is_set() and not wait_task.done():
                self._kill_process_group(process.pid)
            await process.wait()
        except asyncio.CancelledError:
            self._kill_process_group(process.pid)
            await asyncio.shield(process.wait())
            raise
        finally:
            overflow_task.cancel()
        stdout = await stdout_task
        stderr = await stderr_task
        return_code = process.returncode
        duration_ms = min(600_000, round((time.monotonic() - started) * 1_000))
        return ProcessObservation(
            command_id=command_id,
            exit_code=return_code if return_code is not None and return_code >= 0 else None,
            signal=-return_code if return_code is not None and return_code < 0 else None,
            stdout_digest=stdout.digest,
            stderr_digest=stderr.digest,
            stdout_bytes=stdout.byte_count,
            stderr_bytes=stderr.byte_count,
            duration_ms=duration_ms,
            timed_out=timed_out,
            output_limit_exceeded=(stdout.limit_exceeded or stderr.limit_exceeded),
        )

    @staticmethod
    async def _capture(
        stream: asyncio.StreamReader,
        budget: _OutputBudget,
        overflow: asyncio.Event,
    ) -> _CapturedStream:
        digest = hashlib.sha256()
        retained = 0
        exceeded = False
        while True:
            chunk = await stream.read(64 * 1024)
            if not chunk:
                break
            remaining = max(0, budget.limit - budget.retained)
            if remaining:
                accepted = chunk[:remaining]
                digest.update(accepted)
                retained += len(accepted)
                budget.retained += len(accepted)
            if len(chunk) > remaining:
                exceeded = True
                overflow.set()
        return _CapturedStream(
            digest=digest.hexdigest(),
            byte_count=retained,
            limit_exceeded=exceeded,
        )

    @staticmethod
    def _kill_process_group(process_id: int) -> None:
        try:
            os.killpg(process_id, signal.SIGKILL)
        except ProcessLookupError:
            return

    def _validate_host_paths(self) -> None:
        for candidate, label in (
            (self.runtime_path, "Bubblewrap runtime"),
            (self.limiter_path, "resource limiter"),
        ):
            metadata = candidate.lstat()
            if (
                candidate.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or not os.access(candidate, os.X_OK)
            ):
                raise IsolationUnavailableError(f"{label} is not a trusted executable")
        if not self.runtime_root.is_dir() or self.runtime_root == Path("/"):
            raise IsolationUnavailableError("runtime root must be a dedicated pinned directory")

    @staticmethod
    def _trusted_path(candidate: Path, label: str) -> Path:
        absolute = Path(os.path.abspath(os.fspath(candidate)))
        try:
            resolved = absolute.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise IsolationUnavailableError(f"{label} is unavailable") from exc
        if absolute != resolved or absolute.is_symlink():
            raise IsolationUnavailableError(f"{label} must not traverse a symbolic link")
        return resolved

    @staticmethod
    def _file_digest(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    @classmethod
    def _make_removable(cls, root: Path) -> None:
        if not root.exists():
            return
        for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            try:
                if path.is_dir() and not path.is_symlink():
                    os.chmod(path, 0o700)
                elif not path.is_symlink():
                    os.chmod(path, 0o600)
            except OSError:
                continue
        with contextlib.suppress(OSError):
            os.chmod(root, 0o700)

    @classmethod
    def _remove_tree(cls, root: Path) -> None:
        cls._make_removable(root)
        shutil.rmtree(root, ignore_errors=True)
