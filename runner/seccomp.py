from __future__ import annotations

import struct

AUDIT_ARCH_X86_64 = 0xC000003E
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000

_BPF_LOAD_WORD_ABSOLUTE = 0x20
_BPF_JUMP_EQUAL = 0x15
_BPF_JUMP_GREATER_OR_EQUAL = 0x35
_BPF_RETURN = 0x06
_X32_SYSCALL_BIT = 0x40000000

_DENIED_SYSCALLS = (
    # No socket surface exists inside a qualification job.
    41,  # socket
    42,  # connect
    43,  # accept
    44,  # sendto
    45,  # recvfrom
    46,  # sendmsg
    47,  # recvmsg
    48,  # shutdown
    49,  # bind
    50,  # listen
    51,  # getsockname
    52,  # getpeername
    53,  # socketpair
    54,  # setsockopt
    55,  # getsockopt
    101,  # ptrace
    155,  # pivot_root
    161,  # chroot
    165,  # mount
    166,  # umount2
    167,  # swapon
    168,  # swapoff
    169,  # reboot
    175,  # init_module
    176,  # delete_module
    246,  # kexec_load
    248,  # add_key
    249,  # request_key
    250,  # keyctl
    272,  # unshare
    298,  # perf_event_open
    304,  # open_by_handle_at
    308,  # setns
    311,  # process_vm_writev
    313,  # finit_module
    321,  # bpf
    323,  # userfaultfd
    425,  # io_uring_setup
    426,  # io_uring_enter
    427,  # io_uring_register
    428,  # open_tree
    429,  # move_mount
    430,  # fsopen
    431,  # fsconfig
    432,  # fsmount
    433,  # fspick
    435,  # clone3
    438,  # pidfd_getfd
    442,  # mount_setattr
)


def _instruction(code: int, jump_true: int, jump_false: int, value: int) -> bytes:
    return struct.pack("<HBBI", code, jump_true, jump_false, value)


def build_seccomp_filter() -> bytes:
    instructions = [
        _instruction(_BPF_LOAD_WORD_ABSOLUTE, 0, 0, 4),
        _instruction(_BPF_JUMP_EQUAL, 1, 0, AUDIT_ARCH_X86_64),
        _instruction(_BPF_RETURN, 0, 0, SECCOMP_RET_KILL_PROCESS),
        _instruction(_BPF_LOAD_WORD_ABSOLUTE, 0, 0, 0),
        _instruction(_BPF_JUMP_GREATER_OR_EQUAL, 0, 1, _X32_SYSCALL_BIT),
        _instruction(_BPF_RETURN, 0, 0, SECCOMP_RET_KILL_PROCESS),
    ]
    for syscall in _DENIED_SYSCALLS:
        instructions.extend(
            (
                _instruction(_BPF_JUMP_EQUAL, 0, 1, syscall),
                _instruction(_BPF_RETURN, 0, 0, SECCOMP_RET_ERRNO | 1),
            )
        )
    instructions.append(_instruction(_BPF_RETURN, 0, 0, SECCOMP_RET_ALLOW))
    return b"".join(instructions)
