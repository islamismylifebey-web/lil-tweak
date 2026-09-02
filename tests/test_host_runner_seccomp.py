from __future__ import annotations

import struct

from runner.seccomp import (
    AUDIT_ARCH_X86_64,
    SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO,
    SECCOMP_RET_KILL_PROCESS,
    build_seccomp_filter,
)


def _run_filter(program: bytes, *, arch: int, syscall: int) -> int:
    instructions = [
        struct.unpack("<HBBI", program[offset : offset + 8]) for offset in range(0, len(program), 8)
    ]
    accumulator = 0
    pc = 0
    while True:
        code, jump_true, jump_false, value = instructions[pc]
        if code == 0x20:
            accumulator = syscall if value == 0 else arch
            pc += 1
        elif code == 0x15:
            pc += (jump_true if accumulator == value else jump_false) + 1
        elif code == 0x35:
            pc += (jump_true if accumulator >= value else jump_false) + 1
        elif code == 0x06:
            return value
        else:  # pragma: no cover - test deliberately supports only the pinned program
            raise AssertionError(f"unexpected BPF opcode {code:#x}")


def test_seccomp_filter_denies_network_and_privilege_syscalls_but_allows_build_io() -> None:
    program = build_seccomp_filter()

    for syscall in (41, 42, 43, 44, 45, 46, 47, 49, 50, 101, 165, 272, 321):
        assert _run_filter(program, arch=AUDIT_ARCH_X86_64, syscall=syscall) == (
            SECCOMP_RET_ERRNO | 1
        )
    for syscall in (0, 1, 59, 257):
        assert _run_filter(program, arch=AUDIT_ARCH_X86_64, syscall=syscall) == (SECCOMP_RET_ALLOW)
    assert _run_filter(program, arch=0x40000003, syscall=0) == SECCOMP_RET_KILL_PROCESS
    assert (
        _run_filter(program, arch=AUDIT_ARCH_X86_64, syscall=0x40000001) == SECCOMP_RET_KILL_PROCESS
    )
