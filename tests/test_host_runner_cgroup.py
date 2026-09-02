from __future__ import annotations

from pathlib import Path

from runner.cgroup import CgroupManager


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
