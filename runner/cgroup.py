from __future__ import annotations

import os
import re
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

_EXECUTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class CgroupError(RuntimeError):
    """Reject absent cgroup-v2 isolation or incomplete emergency cleanup."""


def _write(path: Path, value: str) -> None:
    try:
        path.write_text(value, encoding="ascii")
    except OSError as exc:
        raise CgroupError(f"cannot configure {path.name}") from exc


@dataclass(frozen=True)
class CgroupJob:
    path: Path

    def attach(self, pid: int) -> None:
        if pid <= 1:
            raise CgroupError("job pid is invalid")
        _write(self.path / "cgroup.procs", f"{pid}\n")

    def kill(self) -> None:
        _write(self.path / "cgroup.kill", "1\n")

    def cleanup(self, *, timeout_seconds: float = 10.0) -> None:
        self.kill()
        deadline = time.monotonic() + timeout_seconds
        events = self.path / "cgroup.events"
        while time.monotonic() < deadline:
            try:
                populated = "populated 1" in events.read_text(encoding="ascii")
            except OSError as exc:
                raise CgroupError("cannot read cgroup cleanup state") from exc
            if not populated:
                self.path.rmdir()
                return
            time.sleep(0.05)
        raise CgroupError("cgroup remained populated after emergency kill")


def _current_service_cgroup() -> Path:
    try:
        lines = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise CgroupError("cgroup v2 state is unavailable") from exc
    unified = [line[3:] for line in lines if line.startswith("0::/")]
    if len(unified) != 1:
        raise CgroupError("unified cgroup v2 is required")
    return Path("/sys/fs/cgroup") / unified[0].lstrip("/")


class CgroupManager:
    def __init__(self, *, service_cgroup: Path | None = None) -> None:
        self._service = service_cgroup or _current_service_cgroup()
        if not self._service.is_dir() or self._service.is_symlink():
            raise CgroupError("service cgroup is invalid")
        daemon = self._service / "liltweak-daemon"
        daemon.mkdir(mode=0o700, exist_ok=True)
        _write(daemon / "cgroup.procs", f"{os.getpid()}\n")
        _write(self._service / "cgroup.subtree_control", "+cpu +memory +pids\n")
        self._jobs = self._service / "liltweak-jobs"
        self._jobs.mkdir(mode=0o700, exist_ok=True)
        _write(self._jobs / "cgroup.subtree_control", "+cpu +memory +pids\n")

    def create(self, execution_id: str) -> CgroupJob:
        if not _EXECUTION_ID.fullmatch(execution_id):
            raise CgroupError("execution id is invalid")
        path = self._jobs / execution_id
        try:
            path.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise CgroupError("execution cgroup already exists") from exc
        limits = {
            "cpu.max": "200000 100000\n",
            "memory.max": "4294967296\n",
            "memory.swap.max": "0\n",
            "pids.max": "256\n",
        }
        try:
            for name, value in limits.items():
                _write(path / name, value)
        except Exception:
            with suppress(OSError):
                path.rmdir()
            raise
        return CgroupJob(path)
