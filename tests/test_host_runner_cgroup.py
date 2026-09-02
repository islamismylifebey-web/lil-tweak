from __future__ import annotations

import os
from pathlib import Path

import runner.cgroup as cgroup_module
from runner.cgroup import CgroupManager, _current_service_cgroup


def test_current_service_cgroup_stays_under_unified_root(monkeypatch) -> None:
    def fake_read_text(path: Path, *, encoding: str) -> str:
        assert path == Path("/proc/self/cgroup")
        assert encoding == "ascii"
        return "0::/system.slice/liltweak-runner.service\n"

    monkeypatch.setattr(Path, "read_text", fake_read_text)

    assert _current_service_cgroup() == Path("/sys/fs/cgroup/system.slice/liltweak-runner.service")


def test_cgroup_manager_moves_daemon_to_leaf_before_enabling_controllers(
    monkeypatch, tmp_path: Path
) -> None:
    service = tmp_path / "service"
    service.mkdir()
    real_write = cgroup_module._write

    def checked_write(path: Path, value: str) -> None:
        if path == service / "cgroup.subtree_control":
            assert (service / "liltweak-daemon" / "cgroup.procs").read_text() == (
                f"{os.getpid()}\n"
            )
        real_write(path, value)

    monkeypatch.setattr(cgroup_module, "_write", checked_write)

    CgroupManager(service_cgroup=service)

    assert (service / "cgroup.subtree_control").read_text() == "+cpu +memory +pids\n"
    assert (service / "liltweak-jobs" / "cgroup.subtree_control").read_text() == (
        "+cpu +memory +pids\n"
    )


def test_cgroup_applies_cpu_memory_swap_and_pid_limits_and_emergency_kill(
    tmp_path: Path,
) -> None:
    service = tmp_path / "service"
    service.mkdir()
    manager = CgroupManager(service_cgroup=service)

    job = manager.create("exec-001")
    job.attach(4321)
    job.kill()

    root = service / "liltweak-jobs" / "exec-001"
    assert (root / "cpu.max").read_text() == "200000 100000\n"
    assert (root / "memory.max").read_text() == "4294967296\n"
    assert (root / "memory.swap.max").read_text() == "0\n"
    assert (root / "pids.max").read_text() == "256\n"
    assert (root / "cgroup.procs").read_text() == "4321\n"
    assert (root / "cgroup.kill").read_text() == "1\n"
