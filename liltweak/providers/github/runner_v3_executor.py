from __future__ import annotations

import hashlib
import os
import platform
import re
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from ...creator_contract import canonical_json
from .runner_v3_contracts import (
    MAX_RUNNER_V3_PATCH_BYTES,
    RunnerV3Action,
    RunnerV3HostCapacity,
    RunnerV3JobManifest,
    RunnerV3Outcome,
    RunnerV3Receipt,
    RunnerV3StepReceipt,
    RunnerV3WorkspaceMode,
)

_MAX_GIT_OUTPUT: Final = 1_000_000
_READ_CHUNK: Final = 65_536
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class RunnerV3ExecutionError(RuntimeError):
    """Fail closed when a Runner V3 execution invariant is not proven."""


@dataclass(frozen=True)
class _CommandResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    output_truncated: bool = False


def _milliseconds() -> int:
    return time.time_ns() // 1_000_000


def _safe_path(path: str) -> None:
    if (
        not path
        or len(path) > 512
        or path.startswith(("/", "\\"))
        or "\\" in path
        or "//" in path
        or "\x00" in path
    ):
        raise RunnerV3ExecutionError("Runner V3 patch contains an unsafe path")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise RunnerV3ExecutionError("Runner V3 patch contains an unsafe path")
    if parts[0].casefold() == ".git":
        raise RunnerV3ExecutionError("Runner V3 patch cannot target Git metadata")


def _git(
    workspace: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> bytes:
    try:
        result = subprocess.run(
            (
                "git",
                "-c",
                f"safe.directory={workspace}",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                str(workspace),
                *arguments,
            ),
            input=input_bytes,
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunnerV3ExecutionError("Runner V3 Git inspection failed") from exc
    if check and (
        result.returncode != 0 or len(result.stdout) + len(result.stderr) > _MAX_GIT_OUTPUT
    ):
        raise RunnerV3ExecutionError("Runner V3 Git inspection failed")
    return result.stdout


def _git_text(workspace: Path, *arguments: str) -> str:
    try:
        return _git(workspace, *arguments).decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise RunnerV3ExecutionError("Runner V3 Git identity was not ASCII") from exc


def _source_identity(workspace: Path) -> tuple[str, str]:
    commit = _git_text(workspace, "rev-parse", "HEAD")
    tree = _git_text(workspace, "rev-parse", "HEAD^{tree}")
    if not _GIT_SHA.fullmatch(commit) or not _GIT_SHA.fullmatch(tree):
        raise RunnerV3ExecutionError("Runner V3 source identity is invalid")
    return commit, tree


def _status_entries(workspace: Path) -> tuple[tuple[str, str], ...]:
    raw = _git(
        workspace,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    )
    records = [record for record in raw.split(b"\0") if record]
    entries: list[tuple[str, str]] = []
    index = 0
    while index < len(records):
        try:
            record = records[index].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise RunnerV3ExecutionError("Runner V3 workspace contains a non-UTF-8 path") from exc
        if len(record) < 4 or record[2] != " ":
            raise RunnerV3ExecutionError("Runner V3 Git status is malformed")
        code = record[:2]
        path = record[3:]
        if "R" in code or "C" in code:
            raise RunnerV3ExecutionError("Runner V3 does not accept runtime renames or copies")
        _safe_path(path)
        entries.append((code, path))
        index += 1
    return tuple(entries)


def _changed_paths(workspace: Path) -> tuple[str, ...]:
    return tuple(sorted({path for _, path in _status_entries(workspace)}))


def _assert_regular_target(workspace: Path, relative: str) -> None:
    _safe_path(relative)
    cursor = workspace
    parts = relative.split("/")
    for part in parts[:-1]:
        cursor = cursor / part
        if not cursor.exists():
            continue
        metadata = cursor.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise RunnerV3ExecutionError("Runner V3 patch target has an unsafe parent")
    target = workspace / relative
    if target.is_symlink():
        raise RunnerV3ExecutionError("Runner V3 patch cannot target a symlink or gitlink")
    if target.exists() and not stat.S_ISREG(target.lstat().st_mode):
        raise RunnerV3ExecutionError("Runner V3 patch target must be a regular file")
    tracked = _git_text(workspace, "ls-files", "-s", "--", relative)
    if tracked:
        mode = tracked.split(maxsplit=1)[0]
        if mode in {"120000", "160000"}:
            raise RunnerV3ExecutionError("Runner V3 patch cannot target a symlink or gitlink")


def _parse_patch_paths(text: str) -> tuple[str, ...]:
    disallowed_prefixes = (
        "rename from ",
        "rename to ",
        "copy from ",
        "copy to ",
        "similarity index ",
        "dissimilarity index ",
        "old mode ",
        "new mode ",
        "GIT binary patch",
        "Binary files ",
    )
    paths: list[str] = []
    file_markers: list[str] = []
    in_hunk = False
    for line in text.splitlines():
        if line.startswith(disallowed_prefixes):
            raise RunnerV3ExecutionError(
                "Runner V3 patch cannot rename, copy, change mode, or contain binary data"
            )
        if line.startswith(("new file mode 120000", "deleted file mode 120000")):
            raise RunnerV3ExecutionError("Runner V3 patch cannot create a symlink or gitlink")
        if line.startswith(("new file mode 160000", "deleted file mode 160000")):
            raise RunnerV3ExecutionError("Runner V3 patch cannot create a symlink or gitlink")
        if line.startswith("index ") and line.endswith((" 120000", " 160000")):
            raise RunnerV3ExecutionError("Runner V3 patch cannot create a symlink or gitlink")
        if line.startswith("diff --git "):
            in_hunk = False
            fields = line.split(" ")
            if (
                len(fields) != 4
                or not fields[2].startswith("a/")
                or not fields[3].startswith("b/")
                or fields[2][2:] != fields[3][2:]
                or '"' in line
                or "\t" in line
            ):
                raise RunnerV3ExecutionError("Runner V3 patch has an unsafe diff header")
            path = fields[2][2:]
            _safe_path(path)
            paths.append(path)
            continue
        if line.startswith(("@@ ", "@@-")):
            in_hunk = True
        if not in_hunk and line.startswith(("--- ", "+++ ")):
            marker = line[4:]
            if marker == "/dev/null":
                continue
            expected_prefix = "a/" if line.startswith("--- ") else "b/"
            if (
                not marker.startswith(expected_prefix)
                or '"' in marker
                or "\t" in marker
                or " " in marker
            ):
                raise RunnerV3ExecutionError("Runner V3 patch has an unsafe file marker")
            path = marker[2:]
            _safe_path(path)
            file_markers.append(path)
    if not paths or len(set(paths)) != len(paths):
        raise RunnerV3ExecutionError("Runner V3 patch must contain unique normal file diffs")
    if any(path not in paths for path in file_markers):
        raise RunnerV3ExecutionError("Runner V3 patch file markers do not match its diff headers")
    return tuple(paths)


def _check_patch(
    workspace: Path,
    manifest: RunnerV3JobManifest,
) -> tuple[str, ...]:
    patch = manifest.patch
    if patch is None:
        return ()
    paths = _parse_patch_paths(patch.text)
    if set(paths) != set(patch.authorized_paths):
        raise RunnerV3ExecutionError("Runner V3 patch touched paths do not match authorized paths")
    for path in paths:
        _assert_regular_target(workspace, path)
    _git(
        workspace,
        "apply",
        "--check",
        "--whitespace=error-all",
        "-",
        input_bytes=patch.text.encode("utf-8"),
    )
    return tuple(sorted(paths))


def _apply_patch(workspace: Path, manifest: RunnerV3JobManifest) -> None:
    patch = manifest.patch
    if patch is None:
        return
    _git(
        workspace,
        "apply",
        "--whitespace=error-all",
        "-",
        input_bytes=patch.text.encode("utf-8"),
    )
    for path in patch.authorized_paths:
        _assert_regular_target(workspace, path)
    if set(_changed_paths(workspace)) != set(patch.authorized_paths):
        raise RunnerV3ExecutionError("Runner V3 applied patch does not match authorized paths")


def _path_fingerprint(workspace: Path, relative: str) -> str:
    target = workspace / relative
    if target.is_symlink():
        raise RunnerV3ExecutionError("Runner V3 patch produced a symlink or gitlink")
    if not target.exists():
        return hashlib.sha256(b"deleted").hexdigest()
    metadata = target.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise RunnerV3ExecutionError("Runner V3 patch produced a non-regular target")
    digest = hashlib.sha256()
    digest.update(f"{stat.S_IMODE(metadata.st_mode):o}\0{metadata.st_size}\0".encode())
    with target.open("rb") as stream:
        for chunk in iter(lambda: stream.read(_READ_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _patch_fingerprints(
    workspace: Path,
    paths: tuple[str, ...],
) -> dict[str, str]:
    return {path: _path_fingerprint(workspace, path) for path in paths}


def _actual_patch(workspace: Path, entries: tuple[tuple[str, str], ...]) -> bytes:
    if not entries:
        return b""
    paths = tuple(sorted({path for _, path in entries}))
    untracked = tuple(sorted(path for code, path in entries if code == "??"))
    for path in paths:
        _assert_regular_target(workspace, path)
    for path in untracked:
        metadata = (workspace / path).lstat()
        if metadata.st_size > MAX_RUNNER_V3_PATCH_BYTES:
            raise RunnerV3ExecutionError("Runner V3 changed file exceeds the evidence patch limit")
    if untracked:
        _git(workspace, "add", "-N", "--", *untracked)
    try:
        patch = _git(
            workspace,
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--",
            *paths,
        )
    finally:
        if untracked:
            _git(workspace, "reset", "-q", "--", *untracked)
    if not patch:
        raise RunnerV3ExecutionError("Runner V3 could not preserve changed-workspace evidence")
    if len(patch) + 1 > MAX_RUNNER_V3_PATCH_BYTES:
        raise RunnerV3ExecutionError("Runner V3 candidate patch exceeds the evidence limit")
    return patch.rstrip(b"\n") + b"\n"


def _host_capacity(workspace: Path) -> RunnerV3HostCapacity:
    memory_mb = 0
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            if line.startswith("MemTotal:"):
                memory_mb = int(line.split()[1]) // 1_024
                break
    except (OSError, ValueError, IndexError):
        memory_mb = 0
    if memory_mb < 128:
        try:
            memory_mb = (
                int(os.sysconf("SC_PHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE")) // 1_048_576
            )
        except (OSError, ValueError):
            memory_mb = 128
    disk = shutil.disk_usage(workspace)
    runner_os = os.environ.get("RUNNER_OS") or platform.system() or "unknown"
    runner_arch = os.environ.get("RUNNER_ARCH") or platform.machine() or "unknown"
    runner_name = os.environ.get("RUNNER_NAME") or "local-runner-v3"
    runner_label = os.environ.get("RUNNER_V3_LABEL") or os.environ.get("IMAGEOS") or "local"
    return RunnerV3HostCapacity(
        cpu_count=max(1, os.cpu_count() or 1),
        memory_mb=max(128, memory_mb),
        free_disk_mb=max(1, disk.free // 1_048_576),
        runner_os=runner_os[:64],
        runner_arch=runner_arch[:64],
        runner_name=runner_name[:256],
        runner_label=runner_label[:128],
    )


def _child_environment(output_directory: Path) -> dict[str, str]:
    home = output_directory / "home"
    temporary = output_directory / "tmp"
    pycache = output_directory / "pycache"
    ruff_cache = output_directory / "ruff-cache"
    mypy_cache = output_directory / "mypy-cache"
    for directory in (home, temporary, pycache, ruff_cache, mypy_cache):
        directory.mkdir(mode=0o700)
    path = os.environ.get("PATH") or "/usr/local/bin:/usr/bin:/bin"
    return {
        "PATH": path,
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "NO_COLOR": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPYCACHEPREFIX": str(pycache),
        "RUFF_CACHE_DIR": str(ruff_cache),
        "MYPY_CACHE_DIR": str(mypy_cache),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "OPENAI_API_KEY": "",
        "LILTWEAK_LIVE_MODEL_ENABLED": "false",
        "LILTWEAK_REPOSITORY_EXECUTION_ENABLED": "false",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "",
    }


def _limit_process(manifest: RunnerV3JobManifest) -> Callable[[], None]:
    memory_bytes = manifest.memory_mb_ceiling * 1_048_576
    file_bytes = min(manifest.disk_mb_ceiling * 1_048_576, 4_294_967_296)
    cpu_seconds = min(1_800, max(1, manifest.timeout_seconds + 5))

    def apply_limits() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return apply_limits


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        with suppress(ProcessLookupError):
            process.kill()


def _fixed_command(
    action: RunnerV3Action,
    output_directory: Path,
) -> tuple[str, ...]:
    commands: Mapping[RunnerV3Action, tuple[str, ...]] = {
        RunnerV3Action.COMPILE_PYTHON: (
            sys.executable,
            "-m",
            "compileall",
            "-q",
            "liltweak",
            "scripts",
        ),
        RunnerV3Action.PYTEST: (
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
        ),
        RunnerV3Action.RUFF_CHECK: (
            sys.executable,
            "-m",
            "ruff",
            "check",
            ".",
        ),
        RunnerV3Action.RUFF_FORMAT_CHECK: (
            sys.executable,
            "-m",
            "ruff",
            "format",
            "--check",
            ".",
        ),
        RunnerV3Action.MYPY: (sys.executable, "-m", "mypy"),
        RunnerV3Action.BUILD_PACKAGE: (
            "uv",
            "build",
            "--offline",
            "--out-dir",
            str(output_directory / "build"),
        ),
    }
    try:
        return commands[action]
    except KeyError as exc:
        raise RunnerV3ExecutionError("Runner V3 action has no fixed executable mapping") from exc


def _run_process(
    command: tuple[str, ...],
    *,
    workspace: Path,
    environment: dict[str, str],
    manifest: RunnerV3JobManifest,
    deadline: float,
    poll_interval_seconds: float,
    cancellation_requested: Callable[[], bool],
) -> _CommandResult:
    try:
        process = subprocess.Popen(
            command,
            cwd=workspace,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            preexec_fn=_limit_process(manifest),
        )
    except OSError:
        return _CommandResult(
            exit_code=127,
            stdout=b"",
            stderr=b"Runner V3 fixed action could not start\n",
        )
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        raise RunnerV3ExecutionError("Runner V3 action pipes are unavailable")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    output = {"stdout": bytearray(), "stderr": bytearray()}
    forced_exit: int | None = None
    truncated = False
    try:
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            try:
                cancelled = cancellation_requested()
            except Exception as exc:
                _kill_process_group(process)
                raise RunnerV3ExecutionError("Runner V3 cancellation check failed") from exc
            if cancelled:
                forced_exit = 130
                _kill_process_group(process)
            elif now >= deadline:
                forced_exit = 124
                _kill_process_group(process)
            if forced_exit is not None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    _kill_process_group(process)
                break
            wait = min(poll_interval_seconds, max(0.0, deadline - now))
            for key, _ in selector.select(timeout=wait):
                chunk = os.read(key.fd, _READ_CHUNK)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                current_size = len(output["stdout"]) + len(output["stderr"])
                remaining = max(0, manifest.output_byte_limit - current_size)
                target = output[str(key.data)]
                target.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    forced_exit = 70
                    _kill_process_group(process)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        _kill_process_group(process)
                    break
            if forced_exit is not None:
                break
        if process.poll() is None:
            _kill_process_group(process)
        try:
            return_code = int(process.wait(timeout=5))
        except subprocess.TimeoutExpired:
            _kill_process_group(process)
            return_code = -signal.SIGKILL
        exit_code = forced_exit
        if exit_code is None:
            exit_code = (
                min(255, 128 + abs(return_code)) if return_code < 0 else min(255, return_code)
            )
        return _CommandResult(
            exit_code=exit_code,
            stdout=bytes(output["stdout"]),
            stderr=bytes(output["stderr"]),
            output_truncated=truncated,
        )
    finally:
        selector.close()


def _write_new(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise RunnerV3ExecutionError("Runner V3 evidence path is not safely writable") from exc
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RunnerV3ExecutionError("Runner V3 evidence write was incomplete")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_json(path: Path, value: Mapping[str, object]) -> None:
    _write_new(path, f"{canonical_json(value)}\n".encode())


def _step_receipt(
    *,
    action: RunnerV3Action,
    result: _CommandResult,
    started_at_ms: int,
    finished_at_ms: int,
) -> RunnerV3StepReceipt:
    if result.exit_code == 0:
        outcome = RunnerV3Outcome.SUCCEEDED
    elif result.exit_code == 130:
        outcome = RunnerV3Outcome.CANCELLED
    else:
        outcome = RunnerV3Outcome.FAILED
    return RunnerV3StepReceipt(
        action=action,
        outcome=outcome,
        exit_code=result.exit_code,
        stdout_digest=hashlib.sha256(result.stdout).hexdigest(),
        stderr_digest=hashlib.sha256(result.stderr).hexdigest(),
        started_at_ms=started_at_ms,
        finished_at_ms=finished_at_ms,
        output_truncated=result.output_truncated,
    )


def _persist_step(
    output_directory: Path,
    index: int,
    receipt: RunnerV3StepReceipt,
    result: _CommandResult,
) -> None:
    prefix = output_directory / "steps" / f"{index:02d}-{receipt.action.value}"
    _write_json(prefix.with_suffix(".json"), receipt.model_dump(mode="json"))
    _write_new(prefix.with_suffix(".stdout"), result.stdout)
    _write_new(prefix.with_suffix(".stderr"), result.stderr)


class RunnerV3Executor:
    """Execute a strict Runner V3 manifest in one ephemeral GitHub workspace."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] | None = None,
        poll_interval_seconds: float = 0.05,
    ) -> None:
        if poll_interval_seconds <= 0 or poll_interval_seconds > 1:
            raise ValueError("Runner V3 poll interval must be between zero and one")
        self._clock: Callable[[], datetime] = clock or (lambda: datetime.now(UTC))
        self._poll_interval_seconds: float = poll_interval_seconds

    def execute(
        self,
        manifest: RunnerV3JobManifest,
        *,
        workspace: Path,
        output_directory: Path,
        cancellation_requested: Callable[[], bool],
    ) -> RunnerV3Receipt:
        validated = self._validate_manifest(manifest)
        workspace = self._validate_workspace(workspace)
        output_directory = self._validate_output_directory(
            workspace,
            output_directory,
        )
        source_commit, source_tree = _source_identity(workspace)
        if source_commit != validated.source_commit or source_tree != validated.source_tree:
            raise RunnerV3ExecutionError("Runner V3 source does not match the exact manifest")
        if _changed_paths(workspace):
            raise RunnerV3ExecutionError("Runner V3 source workspace is not initially clean")
        patch_paths = _check_patch(workspace, validated)
        capacity = _host_capacity(workspace)

        output_directory.mkdir(parents=True, mode=0o700, exist_ok=False)
        output_directory.chmod(0o700)
        steps_directory = output_directory / "steps"
        steps_directory.mkdir(mode=0o700)
        environment = _child_environment(output_directory)

        started_at_ms = _milliseconds()
        deadline = time.monotonic() + validated.timeout_seconds
        receipts: list[RunnerV3StepReceipt] = []
        patch_fingerprints: dict[str, str] | None = None
        for index, action in enumerate(validated.actions):
            step_started = _milliseconds()
            if action is RunnerV3Action.INSPECT_SOURCE:
                result = self._inspect_source(
                    workspace,
                    validated,
                    deadline=deadline,
                    cancellation_requested=cancellation_requested,
                )
            elif action is RunnerV3Action.GIT_DIFF:
                result = self._git_diff(
                    workspace,
                    validated,
                    patch_fingerprints=patch_fingerprints,
                )
            else:
                result = _run_process(
                    _fixed_command(action, output_directory),
                    workspace=workspace,
                    environment=environment,
                    manifest=validated,
                    deadline=deadline,
                    poll_interval_seconds=self._poll_interval_seconds,
                    cancellation_requested=cancellation_requested,
                )
                result = self._enforce_workspace_state(
                    workspace,
                    validated,
                    result,
                    patch_fingerprints=patch_fingerprints,
                )
            step_finished = _milliseconds()
            step = _step_receipt(
                action=action,
                result=result,
                started_at_ms=step_started,
                finished_at_ms=step_finished,
            )
            receipts.append(step)
            _persist_step(output_directory, index, step, result)
            if (
                action is RunnerV3Action.INSPECT_SOURCE
                and result.exit_code == 0
                and validated.patch is not None
            ):
                _apply_patch(workspace, validated)
                patch_fingerprints = _patch_fingerprints(
                    workspace,
                    patch_paths,
                )
            if result.exit_code != 0:
                break

        final_commit, final_tree = _source_identity(workspace)
        entries = _status_entries(workspace)
        changed_paths = tuple(sorted({path for _, path in entries}))
        candidate = self._candidate_patch(
            workspace,
            validated,
            entries,
            patch_fingerprints=patch_fingerprints,
        )
        state_valid = self._final_state_is_valid(
            validated,
            final_commit=final_commit,
            final_tree=final_tree,
            changed_paths=changed_paths,
            patch_fingerprints=patch_fingerprints,
            workspace=workspace,
        )
        outcome = self._outcome(receipts)
        if outcome is RunnerV3Outcome.SUCCEEDED and not state_valid:
            outcome = RunnerV3Outcome.FAILED
        candidate_digest: str | None = None
        if candidate is not None:
            candidate_digest = hashlib.sha256(candidate).hexdigest()
            _write_new(output_directory / "candidate.patch", candidate)

        receipt = RunnerV3Receipt.issue(
            manifest=validated,
            host_capacity=capacity,
            steps=tuple(receipts),
            outcome=outcome,
            source_commit_after=final_commit,
            source_tree_after=final_tree,
            workspace_changed=bool(changed_paths),
            changed_paths=changed_paths,
            candidate_patch_digest=candidate_digest,
            started_at_ms=started_at_ms,
            finished_at_ms=_milliseconds(),
        )
        _write_json(
            output_directory / "runner-v3-receipt.json",
            receipt.model_dump(mode="json"),
        )
        return receipt

    def _validate_manifest(
        self,
        manifest: RunnerV3JobManifest,
    ) -> RunnerV3JobManifest:
        if not isinstance(manifest, RunnerV3JobManifest):
            raise RunnerV3ExecutionError("Runner V3 manifest has an invalid schema")
        try:
            validated = RunnerV3JobManifest.model_validate(manifest.model_dump(mode="python"))
        except ValidationError as exc:
            raise RunnerV3ExecutionError("Runner V3 manifest digest or schema is invalid") from exc
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise RunnerV3ExecutionError("Runner V3 executor clock must be timezone-aware")
        if now < validated.issued_at or now >= validated.expires_at:
            raise RunnerV3ExecutionError("Runner V3 manifest is not within its validity window")
        if validated.actions[0] is not RunnerV3Action.INSPECT_SOURCE:
            raise RunnerV3ExecutionError("Runner V3 must execute inspect_source first")
        return validated

    @staticmethod
    def _validate_workspace(workspace: Path) -> Path:
        if workspace.is_symlink():
            raise RunnerV3ExecutionError("Runner V3 workspace cannot be a symlink")
        try:
            resolved = workspace.resolve(strict=True)
        except OSError as exc:
            raise RunnerV3ExecutionError("Runner V3 workspace does not exist") from exc
        if not resolved.is_dir():
            raise RunnerV3ExecutionError("Runner V3 workspace must be a directory")
        inside = _git_text(resolved, "rev-parse", "--is-inside-work-tree")
        if inside != "true":
            raise RunnerV3ExecutionError("Runner V3 workspace is not a Git checkout")
        return resolved

    @staticmethod
    def _validate_output_directory(
        workspace: Path,
        output_directory: Path,
    ) -> Path:
        if output_directory.exists() or output_directory.is_symlink():
            raise RunnerV3ExecutionError("Runner V3 output directory must not already exist")
        resolved = output_directory.resolve(strict=False)
        if resolved == workspace or workspace in resolved.parents:
            raise RunnerV3ExecutionError(
                "Runner V3 output directory must remain outside the workspace"
            )
        return resolved

    @staticmethod
    def _inspect_source(
        workspace: Path,
        manifest: RunnerV3JobManifest,
        *,
        deadline: float,
        cancellation_requested: Callable[[], bool],
    ) -> _CommandResult:
        if cancellation_requested():
            return _CommandResult(130, b"", b"Runner V3 execution cancelled\n")
        if time.monotonic() >= deadline:
            return _CommandResult(124, b"", b"Runner V3 execution timed out\n")
        commit, tree = _source_identity(workspace)
        changed = _changed_paths(workspace)
        matched = commit == manifest.source_commit and tree == manifest.source_tree and not changed
        payload = {
            "source_commit": commit,
            "source_tree": tree,
            "workspace_clean": not changed,
            "source_matched": matched,
        }
        return _CommandResult(
            0 if matched else 70,
            f"{canonical_json(payload)}\n".encode(),
            b"" if matched else b"Runner V3 exact source check failed\n",
        )

    @staticmethod
    def _state_matches_patch(
        workspace: Path,
        manifest: RunnerV3JobManifest,
        *,
        patch_fingerprints: dict[str, str] | None,
    ) -> bool:
        patch = manifest.patch
        if patch is None or patch_fingerprints is None:
            return False
        if set(_changed_paths(workspace)) != set(patch.authorized_paths):
            return False
        return (
            _patch_fingerprints(
                workspace,
                tuple(sorted(patch.authorized_paths)),
            )
            == patch_fingerprints
        )

    def _git_diff(
        self,
        workspace: Path,
        manifest: RunnerV3JobManifest,
        *,
        patch_fingerprints: dict[str, str] | None,
    ) -> _CommandResult:
        entries = _status_entries(workspace)
        if not entries:
            payload = b'{"changed_paths":[]}\n'
            return _CommandResult(0, payload, b"")
        if (
            manifest.workspace_mode is RunnerV3WorkspaceMode.EPHEMERAL_PATCH
            and self._state_matches_patch(
                workspace,
                manifest,
                patch_fingerprints=patch_fingerprints,
            )
        ):
            patch_contract = manifest.patch
            if patch_contract is None:
                raise RunnerV3ExecutionError("Runner V3 patch evidence contract is missing")
            patch = patch_contract.text.encode("utf-8")
            return self._bounded_internal_output(
                manifest,
                exit_code=0,
                stdout=patch,
                stderr=b"",
            )
        patch = _actual_patch(workspace, entries)
        return self._bounded_internal_output(
            manifest,
            exit_code=70,
            stdout=patch,
            stderr=b"Runner V3 workspace mutation exceeded its authorization\n",
        )

    @staticmethod
    def _bounded_internal_output(
        manifest: RunnerV3JobManifest,
        *,
        exit_code: int,
        stdout: bytes,
        stderr: bytes,
    ) -> _CommandResult:
        combined = stdout + stderr
        if len(combined) <= manifest.output_byte_limit:
            return _CommandResult(exit_code, stdout, stderr)
        bounded = combined[: manifest.output_byte_limit]
        stdout_size = min(len(stdout), len(bounded))
        return _CommandResult(
            70,
            bounded[:stdout_size],
            bounded[stdout_size:],
            output_truncated=True,
        )

    def _enforce_workspace_state(
        self,
        workspace: Path,
        manifest: RunnerV3JobManifest,
        result: _CommandResult,
        *,
        patch_fingerprints: dict[str, str] | None,
    ) -> _CommandResult:
        if result.exit_code != 0:
            return result
        commit, tree = _source_identity(workspace)
        if commit != manifest.source_commit or tree != manifest.source_tree:
            return _CommandResult(
                70,
                result.stdout,
                result.stderr + b"Runner V3 source identity changed\n",
                result.output_truncated,
            )
        changed = _changed_paths(workspace)
        if manifest.workspace_mode is RunnerV3WorkspaceMode.READ_ONLY:
            if changed:
                return _CommandResult(
                    70,
                    result.stdout,
                    result.stderr + b"Runner V3 read-only workspace changed\n",
                    result.output_truncated,
                )
            return result
        if not self._state_matches_patch(
            workspace,
            manifest,
            patch_fingerprints=patch_fingerprints,
        ):
            return _CommandResult(
                70,
                result.stdout,
                result.stderr + b"Runner V3 authorized patch state changed\n",
                result.output_truncated,
            )
        return result

    def _candidate_patch(
        self,
        workspace: Path,
        manifest: RunnerV3JobManifest,
        entries: tuple[tuple[str, str], ...],
        *,
        patch_fingerprints: dict[str, str] | None,
    ) -> bytes | None:
        if not entries:
            return None
        if (
            manifest.workspace_mode is RunnerV3WorkspaceMode.EPHEMERAL_PATCH
            and self._state_matches_patch(
                workspace,
                manifest,
                patch_fingerprints=patch_fingerprints,
            )
        ):
            patch_contract = manifest.patch
            if patch_contract is None:
                raise RunnerV3ExecutionError("Runner V3 patch evidence contract is missing")
            return patch_contract.text.encode("utf-8")
        return _actual_patch(workspace, entries)

    @staticmethod
    def _final_state_is_valid(
        manifest: RunnerV3JobManifest,
        *,
        final_commit: str,
        final_tree: str,
        changed_paths: tuple[str, ...],
        patch_fingerprints: dict[str, str] | None,
        workspace: Path,
    ) -> bool:
        if final_commit != manifest.source_commit or final_tree != manifest.source_tree:
            return False
        if manifest.workspace_mode is RunnerV3WorkspaceMode.READ_ONLY:
            return not changed_paths
        patch = manifest.patch
        if patch is None or patch_fingerprints is None:
            return False
        if set(changed_paths) != set(patch.authorized_paths):
            return False
        return (
            _patch_fingerprints(
                workspace,
                tuple(sorted(patch.authorized_paths)),
            )
            == patch_fingerprints
        )

    @staticmethod
    def _outcome(
        receipts: list[RunnerV3StepReceipt],
    ) -> RunnerV3Outcome:
        if any(step.outcome is RunnerV3Outcome.CANCELLED for step in receipts):
            return RunnerV3Outcome.CANCELLED
        if any(step.outcome is RunnerV3Outcome.FAILED for step in receipts):
            return RunnerV3Outcome.FAILED
        return RunnerV3Outcome.SUCCEEDED
