"""Host-controlled immutable Git source intake."""

from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .archive import ArchiveError, ArchiveLimits, validate_portable_path
from .limits import MAX_EXPANDED_SOURCE_BYTES
from .store import GitSourceSpec


class GitIntakeError(RuntimeError):
    code = "git_source_intake_failed"


def ingest_git_source(
    source: GitSourceSpec,
    destination: str | os.PathLike[str],
    *,
    allowed_hosts: Sequence[str],
    execute: Callable[..., Any] = subprocess.run,
    resolve: Callable[..., Any] = socket.getaddrinfo,
    deadline_seconds: float = 60,
    max_files: int = 20_000,
    max_file_bytes: int = 25 * 1024 * 1024,
    max_total_bytes: int = MAX_EXPANDED_SOURCE_BYTES,
) -> list[str]:
    parsed = urlsplit(source.repository_url)
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise GitIntakeError("git_url_invalid")
    if host not in {item.lower() for item in allowed_hosts}:
        raise GitIntakeError("git_host_not_allowed")
    try:
        port = parsed.port or 443
        addresses = resolve(host, port)
        resolved_ips = [ipaddress.ip_address(item[4][0]) for item in addresses]
        if not resolved_ips or any(not address.is_global for address in resolved_ips):
            raise GitIntakeError("git_host_unsafe")
    except GitIntakeError:
        raise
    except (OSError, ValueError, IndexError):
        raise GitIntakeError("git_host_unresolved") from None

    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    deadline = time.monotonic() + deadline_seconds
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    pinned_address = str(resolved_ips[0])
    if ":" in pinned_address:
        pinned_address = f"[{pinned_address}]"
    curl_resolve = f"{host}:{port}:{pinned_address}"

    def run(arguments: list[str]) -> str:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GitIntakeError("git_timeout")
        try:
            result = execute(
                [
                    "prlimit",
                    f"--fsize={max_total_bytes}",
                    "--",
                    "git",
                    "-c",
                    "http.followRedirects=false",
                    "-c",
                    f"http.curloptResolve={curl_resolve}",
                    "-c",
                    "credential.helper=",
                    *arguments,
                ],
                cwd=root,
                env=environment,
                timeout=remaining,
                capture_output=True,
                text=True,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            raise GitIntakeError("git_timeout") from None
        stdout = str(result.stdout or "")
        stderr = str(result.stderr or "")
        if result.returncode != 0 or len(stdout.encode()) + len(stderr.encode()) > 64 * 1024:
            raise GitIntakeError("git_command_failed")
        return stdout

    try:
        run(["init", "."])
        run(["remote", "add", "origin", source.repository_url])
        run(
            [
                "fetch",
                "--depth=1",
                "--filter=blob:limit=26214400",
                "origin",
                source.commit,
            ]
        )
        _bounded_disk_usage(root, max_total_bytes=max_total_bytes)
        run(["checkout", "--detach", "FETCH_HEAD"])
        resolved = run(["rev-parse", "HEAD"]).strip().lower()
        if resolved != source.commit:
            raise GitIntakeError("git_commit_mismatch")
        shutil.rmtree(root / ".git", ignore_errors=True)
        return _bounded_inventory(
            root,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
        )
    except GitIntakeError:
        shutil.rmtree(root, ignore_errors=True)
        raise
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise GitIntakeError("git_source_intake_failed") from None


def _bounded_disk_usage(root: Path, *, max_total_bytes: int) -> None:
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            raise GitIntakeError("git_symlink_rejected")
        if path.is_file():
            total += path.stat().st_size
            if total > max_total_bytes:
                raise GitIntakeError("git_size_limit")


def _bounded_inventory(
    root: Path, *, max_files: int, max_file_bytes: int, max_total_bytes: int
) -> list[str]:
    inventory: list[str] = []
    seen: set[str] = set()
    total = 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise GitIntakeError("git_symlink_rejected")
        try:
            portable = validate_portable_path(
                relative,
                limits=ArchiveLimits(
                    max_entries=max_files,
                    max_file_bytes=max_file_bytes,
                    max_total_bytes=max_total_bytes,
                ),
            )
        except ArchiveError:
            raise GitIntakeError("git_unsafe_path") from None
        folded = portable.casefold()
        if folded in seen:
            raise GitIntakeError("git_duplicate_path")
        seen.add(folded)
        if not path.is_file():
            continue
        inventory.append(portable)
        if len(inventory) > max_files:
            raise GitIntakeError("git_file_limit")
        size = path.stat().st_size
        if size > max_file_bytes:
            raise GitIntakeError("git_file_too_large")
        total += size
        if total > max_total_bytes:
            raise GitIntakeError("git_size_limit")
    return inventory
