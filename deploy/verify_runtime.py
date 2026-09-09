"""Verify the live rootless Podman boundary without external network use."""

from __future__ import annotations

import json
import os
import re
import selectors
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable


PINNED_IMAGE = re.compile(r"^[A-Za-z0-9._/:-]+@sha256:[0-9a-f]{64}$")
ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
ALLOWED_CORE_ENVIRONMENT_NAMES = frozenset(
    {
        "LIL_TWEAK_DATABASE_URL",
        "LIL_TWEAK_SIGNING_KEYS_JSON",
        "LIL_TWEAK_CANONICAL_OWNER_ID",
        "OPENAI_API_KEY",
        "LIL_TWEAK_OPENAI_MODEL",
        "LIL_TWEAK_RUNNER_IMAGE",
        "LIL_TWEAK_WORK_ROOT",
        "LIL_TWEAK_WORK_ROOT_INODES",
        "LIL_TWEAK_MAX_ADMITTED_JOBS",
        "LIL_TWEAK_JOB_TIMEOUT_SECONDS",
        "LIL_TWEAK_EVIDENCE_BUCKET",
        "LIL_TWEAK_EVIDENCE_ENDPOINT",
        "LIL_TWEAK_R2_ACCESS_KEY_ID",
        "LIL_TWEAK_R2_SECRET_ACCESS_KEY",
        "LIL_TWEAK_GIT_ALLOWED_HOSTS",
    }
)
EXPECTED_WORK_ROOT = Path("/var/lib/lil-tweak/work")
PODMAN_SOCKET_SUFFIX = "/podman/podman.sock"
CORE_WORK_ROOT_BYTES = 1024 * 1024 * 1024
CORE_WORK_ROOT_INODES = 204_800
MAX_PROBE_OUTPUT_BYTES = 64 * 1024
RUNTIME_PROBE_SENTINEL = "LIL_TWEAK_RUNTIME_PROBE_V1:"
_RUNTIME_PROBE_VALUE = {
    "schema": "lil-tweak-runtime-probe-v1",
    "status": "ok",
}


class ProbeError(RuntimeError):
    pass


def load_environment(path: Path) -> dict[str, str]:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or before.st_gid != os.getgid()
            or before.st_size > 64 * 1024
        ):
            raise ProbeError("invalid core environment file")
        chunks = bytearray()
        while len(chunks) <= 64 * 1024:
            chunk = os.read(descriptor, min(8192, 64 * 1024 + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            len(chunks) > 64 * 1024
            or len(chunks) != before.st_size
            or (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            != (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
            or not stat.S_ISREG(after.st_mode)
            or stat.S_IMODE(after.st_mode) != 0o600
            or after.st_nlink != 1
            or after.st_uid != os.getuid()
            or after.st_gid != os.getgid()
            or not stat.S_ISREG(current.st_mode)
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_nlink != 1
            or current.st_uid != os.getuid()
            or current.st_gid != os.getgid()
        ):
            raise ProbeError("invalid core environment file")
        content = bytes(chunks).decode("utf-8")
    except ProbeError:
        raise
    except Exception:
        raise ProbeError("invalid core environment file") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if "\x00" in content:
        raise ProbeError("invalid core environment file")
    values: dict[str, str] = {}
    for line in content.splitlines():
        logical = line.lstrip()
        if not logical or logical.startswith("#"):
            continue
        if "=" not in logical:
            raise ProbeError("invalid core environment file")
        name, value = logical.split("=", 1)
        name = name.rstrip()
        if (
            not ENVIRONMENT_NAME.fullmatch(name)
            or name not in ALLOWED_CORE_ENVIRONMENT_NAMES
            or name in values
        ):
            raise ProbeError("invalid core environment file")
        values[name] = value
    return values


def _run_bounded(
    argv: list[str],
    *,
    timeout: int,
    max_output_bytes: int,
    executor: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run shell-free and kill as soon as aggregate capture exceeds its cap."""

    if executor is not None:
        try:
            completed = executor(
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if not isinstance(completed.stdout, str) or not isinstance(
                completed.stderr, str
            ):
                raise ProbeError("bounded command failed")
            if (
                len(completed.stdout.encode("utf-8"))
                + len(completed.stderr.encode("utf-8"))
                > max_output_bytes
            ):
                raise ProbeError("bounded command failed")
            return completed
        except ProbeError:
            raise
        except Exception:
            raise ProbeError("bounded command failed") from None

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
            raise ProbeError("bounded command failed")
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        total = 0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeError("bounded command failed")
            for key, _ in selector.select(min(0.1, remaining)):
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if total + len(chunk) > max_output_bytes:
                    raise ProbeError("bounded command failed")
                captured[key.data].extend(chunk)
                total += len(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProbeError("bounded command failed")
        process.wait(timeout=remaining)
        try:
            stdout = bytes(captured["stdout"]).decode("utf-8")
            stderr = bytes(captured["stderr"]).decode("utf-8")
        except UnicodeDecodeError:
            raise ProbeError("bounded command failed") from None
        return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
    except ProbeError:
        raise
    except Exception:
        raise ProbeError("bounded command failed") from None
    finally:
        selector.close()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        for stream in streams:
            if stream is not None:
                stream.close()


def probe_socket(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise ProbeError("Podman socket is missing") from None
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_gid != os.getgid()
    ):
        raise ProbeError("Podman socket identity is invalid")
    if stat.S_IMODE(metadata.st_mode) & 0o007:
        raise ProbeError("Podman socket is accessible to other users")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2)
    try:
        client.connect(str(path))
        client.sendall(b"GET /_ping HTTP/1.0\r\nHost: podman\r\n\r\n")
        response = client.recv(4096)
    except OSError:
        raise ProbeError("Podman socket did not answer") from None
    finally:
        client.close()
    try:
        current = path.lstat()
    except OSError:
        raise ProbeError("Podman socket identity is invalid") from None
    if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
        raise ProbeError("Podman socket identity is invalid")
    if not response.startswith((b"HTTP/1.0 200", b"HTTP/1.1 200")) or b"OK" not in response:
        raise ProbeError("Podman socket health response is invalid")


def probe_image(
    image: str,
    *,
    executor: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> None:
    if not PINNED_IMAGE.fullmatch(image):
        raise ProbeError("runner image is not digest-pinned")
    result = _run_bounded(
        ["podman", "image", "inspect", image, "--format=json"],
        timeout=10,
        max_output_bytes=256 * 1024,
        executor=executor,
    )
    if result.returncode != 0 or result.stderr != "":
        raise ProbeError("configured runner image is unavailable")
    try:
        inspected = json.loads(
            result.stdout,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        if (
            not isinstance(inspected, list)
            or len(inspected) != 1
            or not isinstance(inspected[0], dict)
        ):
            raise ProbeError("runner image metadata is invalid")
        descriptor = inspected[0]
        digest = descriptor.get("Digest")
        repo_digests = descriptor.get("RepoDigests", [])
        if (
            not isinstance(digest, str)
            or not isinstance(repo_digests, list)
            or not all(isinstance(item, str) for item in repo_digests)
        ):
            raise ProbeError("runner image metadata is invalid")
    except ProbeError:
        raise
    except (IndexError, KeyError, TypeError, json.JSONDecodeError, ValueError):
        raise ProbeError("runner image metadata is invalid") from None
    expected_digest = image.rsplit("@", 1)[1]
    if digest != expected_digest or image not in repo_digests:
        raise ProbeError("local runner does not match the configured image digest")


def probe_core_work_root(
    *,
    executor: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> None:
    program = (
        "from pathlib import Path; import os, stat, sys; "
        "root=Path('/var/lib/lil-tweak/work'); metadata=root.stat(); "
        "filesystem=os.statvfs(root); mounted=False; safe=False; "
        "\nfor line in Path('/proc/self/mountinfo').read_text().splitlines():\n"
        " fields=line.split(); separator=fields.index('-');\n"
        " if fields[4] == str(root):\n"
        "  options=set(fields[5].split(',')) | set(fields[separator+3].split(','));\n"
        "  mounted=fields[separator+1] == 'tmpfs';\n"
        "  safe={'rw','nodev','nosuid'}.issubset(options) and 'noexec' not in options\n"
        "swap=Path('/sys/fs/cgroup/memory.swap.max').read_text(encoding='utf-8'); "
        "valid=(mounted and safe and stat.S_ISDIR(metadata.st_mode) "
        "and stat.S_IMODE(metadata.st_mode) == 0o700 "
        "and metadata.st_uid == os.getuid() and metadata.st_gid == os.getgid() "
        f"and filesystem.f_blocks * filesystem.f_frsize == {CORE_WORK_ROOT_BYTES} "
        f"and filesystem.f_files == {CORE_WORK_ROOT_INODES} and swap == '0\\n'); "
        "sys.exit(0 if valid else 24)"
    )
    result = _run_bounded(
        ["podman", "exec", "lil-tweak-core", "python", "-I", "-c", program],
        timeout=15,
        max_output_bytes=4096,
        executor=executor,
    )
    if result.returncode != 0 or result.stdout != "" or result.stderr != "":
        raise ProbeError("trusted core work-root tmpfs is invalid")


def probe_service_swap(
    *,
    executor: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> None:
    result = _run_bounded(
        [
            "systemctl",
            "--user",
            "show",
            "lil-tweak-core.service",
            "-p",
            "MemorySwapMax",
            "--value",
        ],
        timeout=10,
        max_output_bytes=4096,
        executor=executor,
    )
    if result.returncode != 0 or result.stdout != "0\n" or result.stderr != "":
        raise ProbeError("trusted core service swap limit is invalid")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ProbeError("installed runtime probe output is invalid")
        value[key] = item
    return value


def _reject_constant(_value: str) -> None:
    raise ProbeError("installed runtime probe output is invalid")


def _parse_runtime_probe(stdout: str) -> None:
    if (
        not isinstance(stdout, str)
        or len(stdout.encode("utf-8")) > MAX_PROBE_OUTPUT_BYTES
        or not stdout.endswith("\n")
        or stdout.count("\n") != 1
    ):
        raise ProbeError("installed runtime probe output is invalid")
    line = stdout[:-1]
    if not line.startswith(RUNTIME_PROBE_SENTINEL):
        raise ProbeError("installed runtime probe output is invalid")
    payload = line[len(RUNTIME_PROBE_SENTINEL) :]
    if RUNTIME_PROBE_SENTINEL in payload:
        raise ProbeError("installed runtime probe output is invalid")
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError, ValueError):
        raise ProbeError("installed runtime probe output is invalid") from None
    if value != _RUNTIME_PROBE_VALUE:
        raise ProbeError("installed runtime probe output is invalid")


def probe_installed_runtime(
    image: str,
    *,
    executor: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> None:
    if not PINNED_IMAGE.fullmatch(image):
        raise ProbeError("runner image is not digest-pinned")
    result = _run_bounded(
        [
            "podman",
            "exec",
            "lil-tweak-core",
            "python",
            "-I",
            "-m",
            "lil_tweak.runtime_probe",
            "--image",
            image,
        ],
        timeout=180,
        max_output_bytes=MAX_PROBE_OUTPUT_BYTES,
        executor=executor,
    )
    if result.returncode != 0 or result.stderr != "":
        raise ProbeError("installed runtime probe failed")
    _parse_runtime_probe(result.stdout)


def main(argv: list[str]) -> int:
    if argv == ["--check"]:
        print("runtime probe check: ok")
        return 0
    if len(argv) != 1:
        print("usage: verify_runtime.py CORE_ENV", file=sys.stderr)
        return 2
    try:
        environment = load_environment(Path(argv[0]))
        runner_image = environment["LIL_TWEAK_RUNNER_IMAGE"]
        configured_root = Path(environment["LIL_TWEAK_WORK_ROOT"])
        if configured_root != EXPECTED_WORK_ROOT:
            raise ProbeError("work root is not the isolated in-container tmpfs path")
        if environment["LIL_TWEAK_WORK_ROOT_INODES"] != str(CORE_WORK_ROOT_INODES):
            raise ProbeError("work root inode configuration is invalid")
        if "LIL_TWEAK_GALOR_READONLY_URL" in environment:
            raise ProbeError("retired LIL_TWEAK_GALOR_READONLY_URL is rejected")
        runtime_root = Path(os.environ.get("XDG_RUNTIME_DIR", ""))
        expected_runtime = Path(f"/run/user/{os.getuid()}")
        if runtime_root != expected_runtime:
            raise ProbeError("unexpected service runtime directory")
        socket_path = Path(f"{runtime_root}{PODMAN_SOCKET_SUFFIX}")
        probe_socket(socket_path)
        probe_image(runner_image)
        probe_core_work_root()
        probe_service_swap()
        probe_installed_runtime(runner_image)
    except Exception:
        print("runtime probe failed", file=sys.stderr)
        return 1
    print("runtime probe: installed sandbox lifecycle and swap isolation ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
