"""Credential-free qualification of the installed production sandbox path."""

from __future__ import annotations

import argparse
import json
import os
import re
import selectors
import secrets
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from .limits import (
    RUNNER_WORKSPACE_BYTES,
    RUNNER_WORKSPACE_INODES,
    TRUSTED_WORK_ROOT_BYTES,
    TRUSTED_WORK_ROOT_INODES,
)
from .openai_agent import WorkspaceTools, cleanup_patch_remnants
from .runtime_lock import (
    RUNTIME_PROBE_LATCH_NAME,
    RuntimeExecutionBusy,
    runtime_execution_lock,
)
from .sandbox import RUNNER_CLEANUP_GRACE_SECONDS, PodmanSandbox, SandboxLimits


RUNNER_OBSERVATION_SENTINEL = "LIL_TWEAK_RUNNER_OBSERVATION_V1:"
RUNTIME_PROBE_SENTINEL = "LIL_TWEAK_RUNTIME_PROBE_V1:"
_PROBE_LATCH_CONTENT = b"lil-tweak-runtime-probe-v1\n"
_PROBE_OUTPUT_BYTES = 64 * 1024
_TOKEN = re.compile(r"^[0-9a-f]{16}$")
_PINNED_IMAGE = re.compile(r"^[A-Za-z0-9._/:-]+@sha256:[0-9a-f]{64}$")
_OBSERVATION_FIELDS = frozenset(
    {
        "schema",
        "seed",
        "uid",
        "gid",
        "workspace",
        "uid_map",
        "gid_map",
        "workspace_executed",
        "cpu_max",
        "memory_max",
        "memory_swap_max",
        "interfaces",
        "network_denied",
        "git",
        "patch",
    }
)
_WORKSPACE_FIELDS = frozenset(
    {"mountinfo", "mode", "uid", "gid", "bytes", "inodes"}
)
_PATCH = """--- /dev/null
+++ b/result.txt
@@ -0,0 +1 @@
+runtime-probe-ok
"""
_RUNNER_PROGRAM = r"""
import json
import os
import shutil
import socket
import subprocess
from pathlib import Path

root = Path("/workspace")
(root / "scratch-only.py").write_text("print('scratch only')\n", encoding="utf-8")
(root / "scratch-only.bin").write_bytes(b"\x00\x01\x02\xff")
executable = root / "scratch-exec"
executable.write_text(
    "#!/usr/bin/python3\nprint('workspace-exec-ok')\n", encoding="utf-8"
)
executable.chmod(0o700)
execution = subprocess.run(
    [str(executable)],
    shell=False,
    capture_output=True,
    text=True,
    timeout=2,
    check=False,
)
stats = os.statvfs(root)
metadata = root.stat()
connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection.settimeout(0.5)
try:
    network_denied = connection.connect_ex(("192.0.2.1", 443)) != 0
except OSError:
    network_denied = True
finally:
    connection.close()
value = {
    "schema": "lil-tweak-runner-observation-v1",
    "seed": (root / "seed.txt").read_text(encoding="utf-8"),
    "uid": os.geteuid(),
    "gid": os.getegid(),
    "workspace": {
        "mountinfo": Path("/proc/self/mountinfo").read_text(encoding="utf-8"),
        "mode": metadata.st_mode & 0o7777,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "bytes": stats.f_frsize * stats.f_blocks,
        "inodes": stats.f_files,
    },
    "uid_map": Path("/proc/self/uid_map").read_text(encoding="utf-8"),
    "gid_map": Path("/proc/self/gid_map").read_text(encoding="utf-8"),
    "workspace_executed": (
        execution.returncode == 0
        and execution.stdout == "workspace-exec-ok\n"
        and execution.stderr == ""
    ),
    "cpu_max": Path("/sys/fs/cgroup/cpu.max").read_text(encoding="utf-8"),
    "memory_max": Path("/sys/fs/cgroup/memory.max").read_text(encoding="utf-8"),
    "memory_swap_max": Path("/sys/fs/cgroup/memory.swap.max").read_text(encoding="utf-8"),
    "interfaces": sorted(item.name for item in Path("/sys/class/net").iterdir()),
    "network_denied": network_denied,
    "git": shutil.which("git"),
    "patch": shutil.which("patch"),
}
print(
    "LIL_TWEAK_RUNNER_OBSERVATION_V1:"
    + json.dumps(value, sort_keys=True, separators=(",", ":")),
    flush=True,
)
""".strip()


class ProbeFailure(RuntimeError):
    def __init__(self) -> None:
        super().__init__("runtime probe failed")


def _fail() -> None:
    raise ProbeFailure()


def _mount_field(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def _workspace_mount(mountinfo: str) -> tuple[str, frozenset[str]]:
    matches: list[tuple[str, frozenset[str]]] = []
    for line in mountinfo.splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
            mount_point = _mount_field(fields[4])
            filesystem = fields[separator + 1]
            options = frozenset(fields[5].split(",")) | frozenset(
                fields[separator + 3].split(",")
            )
        except (IndexError, ValueError):
            _fail()
        if mount_point == "/workspace":
            matches.append((filesystem, options))
    if len(matches) != 1:
        _fail()
    return matches[0]


def _map_covers(value: str, identifier: int) -> bool:
    covered = False
    if (
        not value
        or not value.endswith("\n")
        or len(value.encode("utf-8")) > 4096
    ):
        return False
    for line in value[:-1].split("\n"):
        match = re.fullmatch(
            r"[ \t]*((?:0|[1-9][0-9]{0,19}))[ \t]+"
            r"((?:0|[1-9][0-9]{0,19}))[ \t]+"
            r"((?:0|[1-9][0-9]{0,19}))[ \t]*",
            line,
        )
        if match is None:
            return False
        container_start, _host_start, length = map(int, match.groups())
        if min(container_start, _host_start) < 0 or length <= 0:
            return False
        if container_start <= identifier < container_start + length:
            covered = True
    return covered


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail()
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    _fail()


def parse_runner_observation(stdout: str) -> dict[str, Any]:
    """Parse exactly one bounded, sentinel-prefixed runner observation."""

    if not isinstance(stdout, str) or len(stdout.encode("utf-8")) > _PROBE_OUTPUT_BYTES:
        _fail()
    if not stdout.endswith("\n") or stdout.count("\n") != 1:
        _fail()
    line = stdout[:-1]
    if not line.startswith(RUNNER_OBSERVATION_SENTINEL):
        _fail()
    payload = line[len(RUNNER_OBSERVATION_SENTINEL) :]
    if RUNNER_OBSERVATION_SENTINEL in payload:
        _fail()
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeError, ValueError):
        _fail()
    if not isinstance(value, dict) or set(value) != _OBSERVATION_FIELDS:
        _fail()
    return value


def validate_runner_observation(value: dict[str, Any]) -> None:
    """Fail closed unless every effective runner boundary is provable."""

    if not isinstance(value, dict) or set(value) != _OBSERVATION_FIELDS:
        _fail()

    workspace = value.get("workspace")
    if not isinstance(workspace, dict) or set(workspace) != _WORKSPACE_FIELDS:
        _fail()
    if not isinstance(workspace["mountinfo"], str):
        _fail()
    filesystem, options = _workspace_mount(workspace["mountinfo"])
    if (
        value["schema"] != "lil-tweak-runner-observation-v1"
        or value["seed"] != "seeded-input\n"
        or type(value["uid"]) is not int
        or type(value["gid"]) is not int
        or value["uid"] != 65532
        or value["gid"] != 65532
        or value["workspace_executed"] is not True
        or filesystem != "tmpfs"
        or not {"rw", "nosuid", "nodev"}.issubset(options)
        or "ro" in options
        or "noexec" in options
        or type(workspace["mode"]) is not int
        or workspace["mode"] != 0o700
        or type(workspace["uid"]) is not int
        or type(workspace["gid"]) is not int
        or workspace["uid"] != 65532
        or workspace["gid"] != 65532
        or type(workspace["bytes"]) is not int
        or not 0 < workspace["bytes"] <= RUNNER_WORKSPACE_BYTES
        or type(workspace["inodes"]) is not int
        or not 0 < workspace["inodes"] <= RUNNER_WORKSPACE_INODES
        or not isinstance(value["uid_map"], str)
        or not _map_covers(value["uid_map"], 65532)
        or not isinstance(value["gid_map"], str)
        or not _map_covers(value["gid_map"], 65532)
    ):
        _fail()
    if not isinstance(value["cpu_max"], str) or re.fullmatch(
        r"(?:0|[1-9][0-9]{0,19}) (?:0|[1-9][0-9]{0,19})\n",
        value["cpu_max"],
    ) is None:
        _fail()
    cpu = value["cpu_max"][:-1].split(" ")
    if len(cpu) != 2:
        _fail()
    quota, period = map(int, cpu)
    if quota <= 0 or period <= 0 or quota > period:
        _fail()
    if (
        not isinstance(value["memory_max"], str)
        or not isinstance(value["memory_swap_max"], str)
        or re.fullmatch(
            r"(?:0|[1-9][0-9]{0,19})\n", value["memory_max"]
        )
        is None
        or re.fullmatch(
            r"(?:0|[1-9][0-9]{0,19})\n", value["memory_swap_max"]
        )
        is None
    ):
        _fail()
    memory = int(value["memory_max"][:-1])
    swap = int(value["memory_swap_max"][:-1])
    if memory != 1024 * 1024 * 1024 or swap != 0:
        _fail()
    if (
        value["interfaces"] != ["lo"]
        or value["network_denied"] is not True
        or value["git"] is not None
        or not isinstance(value["patch"], str)
        or not value["patch"].startswith("/")
    ):
        _fail()


def validate_core_runtime(
    root: Path,
    *,
    mountinfo_text: str | None = None,
    statvfs: Callable[[Path], Any] = os.statvfs,
    swap_text: str | None = None,
) -> None:
    """Bind qualification to this core process's own tmpfs and cgroup."""

    try:
        metadata = root.lstat()
        text = (
            Path("/proc/self/mountinfo").read_text(encoding="utf-8")
            if mountinfo_text is None
            else mountinfo_text
        )
        matches: list[tuple[str, frozenset[str]]] = []
        for line in text.splitlines():
            fields = line.split()
            separator = fields.index("-")
            if _mount_field(fields[4]) != str(root):
                continue
            matches.append(
                (
                    fields[separator + 1],
                    frozenset(fields[5].split(","))
                    | frozenset(fields[separator + 3].split(",")),
                )
            )
        if len(matches) != 1:
            _fail()
        filesystem, options = matches[0]
        capacity = statvfs(root)
        swap = (
            Path("/sys/fs/cgroup/memory.swap.max").read_text(encoding="utf-8")
            if swap_text is None
            else swap_text
        )
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.getuid()
            or metadata.st_gid != os.getgid()
            or filesystem != "tmpfs"
            or not {"rw", "nosuid", "nodev"}.issubset(options)
            or "ro" in options
            or "noexec" in options
            or capacity.f_frsize * capacity.f_blocks != TRUSTED_WORK_ROOT_BYTES
            or capacity.f_files != TRUSTED_WORK_ROOT_INODES
            or swap != "0\n"
        ):
            _fail()
    except ProbeFailure:
        raise
    except Exception:
        _fail()


def _fsync_parent(root: Path) -> None:
    descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_latch(root: Path) -> tuple[int, int]:
    path = root / RUNTIME_PROBE_LATCH_NAME
    descriptor: int | None = None
    try:
        root_metadata = root.lstat()
        descriptor = os.open(
            path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        offset = 0
        while offset < len(_PROBE_LATCH_CONTENT):
            written = os.write(descriptor, _PROBE_LATCH_CONTENT[offset:])
            if written <= 0:
                _fail()
            offset += written
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_uid != root_metadata.st_uid
            or opened.st_gid != root_metadata.st_gid
            or opened.st_dev != root_metadata.st_dev
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            or current.st_size != len(_PROBE_LATCH_CONTENT)
        ):
            _fail()
        _fsync_parent(root)
        return opened.st_dev, opened.st_ino
    except ProbeFailure:
        raise
    except Exception:
        _fail()
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _remove_latch(root: Path, identity: tuple[int, int]) -> None:
    path = root / RUNTIME_PROBE_LATCH_NAME
    descriptor: int | None = None
    try:
        root_metadata = root.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        opened = os.fstat(descriptor)
        content = os.read(descriptor, len(_PROBE_LATCH_CONTENT) + 1)
        current = path.lstat()
        if (
            content != _PROBE_LATCH_CONTENT
            or not stat.S_ISREG(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_uid != root_metadata.st_uid
            or opened.st_gid != root_metadata.st_gid
            or opened.st_dev != root_metadata.st_dev
            or (opened.st_dev, opened.st_ino) != identity
            or (current.st_dev, current.st_ino)
            != (opened.st_dev, opened.st_ino)
            or current.st_size != len(_PROBE_LATCH_CONTENT)
        ):
            _fail()
        os.close(descriptor)
        descriptor = None
        # A pre-unlink parent fsync failure preserves the admission latch.
        _fsync_parent(root)
        path.unlink()
        try:
            path.lstat()
        except FileNotFoundError:
            _fsync_parent(root)
            return
        _fail()
    except ProbeFailure:
        raise
    except Exception:
        _fail()
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _create_workspace(root: Path, name: str) -> Path:
    workspace = root / name
    try:
        root_metadata = root.lstat()
        workspace.mkdir(mode=0o700)
        metadata = workspace.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != root_metadata.st_uid
            or metadata.st_gid != root_metadata.st_gid
            or metadata.st_dev != root_metadata.st_dev
        ):
            _fail()
        (workspace / "seed.txt").write_text("seeded-input\n", encoding="utf-8")
        return workspace
    except ProbeFailure:
        raise
    except Exception:
        _fail()


def _bounded_command(
    argv: list[str],
    *,
    executor: Callable[..., subprocess.CompletedProcess[str]],
    timeout: int,
    max_output_bytes: int,
) -> subprocess.CompletedProcess[str]:
    if executor is not subprocess.run:
        try:
            completed = executor(
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            stdout = completed.stdout
            stderr = completed.stderr
            if not isinstance(stdout, str) or not isinstance(stderr, str):
                _fail()
            if len(stdout.encode("utf-8")) + len(stderr.encode("utf-8")) > max_output_bytes:
                _fail()
            return completed
        except ProbeFailure:
            raise
        except Exception:
            _fail()

    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    streams: tuple[Any, Any] = (None, None)
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            argv,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        streams = (process.stdout, process.stderr)
        if any(stream is None for stream in streams):
            _fail()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        total = 0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail()
            for key, _ in selector.select(min(0.1, remaining)):
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if total + len(chunk) > max_output_bytes:
                    _fail()
                captured[key.data].extend(chunk)
                total += len(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail()
        process.wait(timeout=remaining)
        try:
            stdout = bytes(captured["stdout"]).decode("utf-8")
            stderr = bytes(captured["stderr"]).decode("utf-8")
        except UnicodeDecodeError:
            _fail()
        return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
    except ProbeFailure:
        raise
    except Exception:
        _fail()
    finally:
        selector.close()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        for stream in streams:
            if stream is not None:
                stream.close()


def _prove_container_absent(
    name: str,
    executor: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    try:
        completed = _bounded_command(
            [
                "podman",
                "ps",
                "--all",
                "--quiet",
                "--no-trunc",
                f"--filter=name=^{name}$",
            ],
            executor=executor,
            timeout=RUNNER_CLEANUP_GRACE_SECONDS,
            max_output_bytes=4096,
        )
        if (
            completed.returncode != 0
            or completed.stdout != ""
            or completed.stderr != ""
        ):
            _fail()
    except ProbeFailure:
        raise
    except Exception:
        _fail()


def _strict_cleanup(
    *,
    root: Path,
    workspace: Path,
    sandbox: PodmanSandbox,
    executor: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    """Remove the proposal last; any earlier uncertainty preserves its latch."""

    try:
        sandbox.teardown()
        _prove_container_absent(sandbox.name, executor)
        cleanup_patch_remnants(root, workspace_name=workspace.name)
        forbidden = (
            f".{workspace.name}-candidate-",
            f".{workspace.name}-patch-",
            f".{workspace.name}-promotion-tmp-",
        )
        if any(
            item.name == f".{workspace.name}-promotion-v1.json"
            or item.name.startswith(forbidden)
            for item in root.iterdir()
        ):
            _fail()
        try:
            metadata = workspace.lstat()
        except FileNotFoundError:
            metadata = None
        if metadata is not None:
            root_metadata = root.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_dev != root_metadata.st_dev
                or metadata.st_uid != root_metadata.st_uid
                or metadata.st_gid != root_metadata.st_gid
            ):
                _fail()
            shutil.rmtree(workspace)
        if workspace.exists() or workspace.is_symlink():
            _fail()
    except ProbeFailure:
        raise
    except Exception:
        _fail()


def _execute_probe(
    *,
    workspace: Path,
    sandbox: PodmanSandbox,
) -> dict[str, str]:
    result = sandbox.run_ephemeral(["python3", "-I", "-c", _RUNNER_PROGRAM], timeout=30)
    if (
        result.exit_code != 0
        or result.timed_out
        or result.truncated
        or result.stderr
    ):
        _fail()
    observation = parse_runner_observation(result.stdout)
    validate_runner_observation(observation)
    tools = WorkspaceTools(workspace, sandbox)
    patch_result = tools.execute("apply_patch", {"patch": _PATCH})
    if (
        patch_result.get("exit_code") != 0
        or patch_result.get("timed_out") is not False
        or patch_result.get("truncated") is not False
        or patch_result.get("promoted") is not True
        or patch_result.get("rejection_code") is not None
        or patch_result.get("cleanup_code") is not None
    ):
        _fail()
    try:
        entries = {item.name for item in workspace.iterdir()}
        if entries != {"result.txt", "seed.txt"}:
            _fail()
        if (workspace / "seed.txt").read_text(encoding="utf-8") != "seeded-input\n":
            _fail()
        if (workspace / "result.txt").read_text(encoding="utf-8") != "runtime-probe-ok\n":
            _fail()
    except ProbeFailure:
        raise
    except Exception:
        _fail()
    return {"schema": "lil-tweak-runtime-probe-v1", "status": "ok"}


def run_runtime_probe(
    *,
    image: str,
    work_root: str | os.PathLike[str] = "/var/lib/lil-tweak/work",
    executor: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    token_factory: Callable[[], str] = lambda: secrets.token_hex(8),
    environ: Mapping[str, str] | None = None,
    runtime_validator: Callable[[Path], None] = validate_core_runtime,
) -> dict[str, str]:
    """Run the real ephemeral-command and atomic apply-patch production paths."""

    root = Path(work_root).absolute()
    if not isinstance(image, str) or _PINNED_IMAGE.fullmatch(image) is None:
        raise ProbeFailure()
    environment = os.environ if environ is None else environ
    if (
        environment.get("LIL_TWEAK_RUNNER_IMAGE") != image
        or environment.get("LIL_TWEAK_WORK_ROOT") != str(root)
        or environment.get("LIL_TWEAK_WORK_ROOT_INODES")
        != str(TRUSTED_WORK_ROOT_INODES)
    ):
        raise ProbeFailure()
    try:
        runtime_validator(root)
    except ProbeFailure:
        raise
    except Exception:
        raise ProbeFailure() from None
    try:
        with runtime_execution_lock(root):
            token = token_factory()
            if not isinstance(token, str) or not _TOKEN.fullmatch(token):
                _fail()
            workspace = root / f"runtime-probe-{token}"
            container_name = f"lt-runtime-probe-{token}"
            latch_identity = _publish_latch(root)
            sandbox: PodmanSandbox | None = None
            result: dict[str, str] | None = None
            body_error: BaseException | None = None
            body_traceback: Any = None
            try:
                workspace = _create_workspace(root, workspace.name)
                sandbox = PodmanSandbox(
                    image=image,
                    workspace=workspace,
                    name=container_name,
                    limits=SandboxLimits(
                        wall_timeout_seconds=120,
                        command_timeout_seconds=30,
                        max_output_bytes=_PROBE_OUTPUT_BYTES,
                    ),
                    executor=executor,
                )
                result = _execute_probe(
                    workspace=workspace,
                    sandbox=sandbox,
                )
            except BaseException as error:
                body_error = error
                body_traceback = error.__traceback__

            cleanup_error: BaseException | None = None
            cleanup_traceback: Any = None
            if sandbox is not None:
                try:
                    _strict_cleanup(
                        root=root,
                        workspace=workspace,
                        sandbox=sandbox,
                        executor=executor,
                    )
                except BaseException as error:
                    cleanup_error = error
                    cleanup_traceback = error.__traceback__
            else:
                cleanup_error = ProbeFailure()
            if cleanup_error is None:
                try:
                    _remove_latch(root, latch_identity)
                except BaseException as error:
                    cleanup_error = error
                    cleanup_traceback = error.__traceback__

            if body_error is not None:
                raise body_error.with_traceback(body_traceback)
            if cleanup_error is not None:
                raise cleanup_error.with_traceback(cleanup_traceback)
            if result is None:
                _fail()
            return result
    except ProbeFailure:
        raise
    except RuntimeExecutionBusy:
        raise ProbeFailure() from None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise ProbeFailure() from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    arguments = parser.parse_args(argv)
    try:
        result = run_runtime_probe(image=arguments.image)
    except Exception:
        print("runtime probe failed", file=sys.stderr)
        return 1
    print(
        RUNTIME_PROBE_SENTINEL
        + json.dumps(result, sort_keys=True, separators=(",", ":")),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
