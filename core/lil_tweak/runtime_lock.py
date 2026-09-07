"""Cross-process singleton for production jobs and live runtime qualification."""

from __future__ import annotations

import fcntl
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


RUNTIME_EXECUTION_LOCK_NAME = ".execution.lock"
RUNTIME_PROBE_LATCH_NAME = ".runtime-probe-active"


class RuntimeExecutionBusy(RuntimeError):
    code = "runtime_execution_busy"

    def __init__(self) -> None:
        super().__init__("runtime execution busy")


@contextmanager
def runtime_execution_lock(work_root: str | os.PathLike[str]) -> Iterator[None]:
    """Acquire the validated work-root singleton without waiting."""

    root = Path(work_root).absolute()
    descriptor: int | None = None
    acquired = False
    try:
        root_before = root.lstat()
        if not stat.S_ISDIR(root_before.st_mode) or stat.S_ISLNK(root_before.st_mode):
            raise RuntimeExecutionBusy()
        lock_path = root / RUNTIME_EXECUTION_LOCK_NAME
        descriptor = os.open(
            lock_path,
            os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeExecutionBusy() from None
        acquired = True
        opened = os.fstat(descriptor)
        root_after = root.lstat()
        current = lock_path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_uid != root_before.st_uid
            or opened.st_gid != root_before.st_gid
            or opened.st_dev != root_before.st_dev
            or (root_after.st_dev, root_after.st_ino)
            != (root_before.st_dev, root_before.st_ino)
            or (current.st_dev, current.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            raise RuntimeExecutionBusy()
        try:
            (root / RUNTIME_PROBE_LATCH_NAME).lstat()
        except FileNotFoundError:
            pass
        else:
            # A probe publishes this fixed latch before creating any runner or
            # work tree and removes it only after strict cleanup/absence proof.
            # Process death releases flock, so the latch is the durable
            # admission barrier for every post-crash boundary.
            raise RuntimeExecutionBusy()
    except RuntimeExecutionBusy:
        if descriptor is not None:
            try:
                if acquired:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        raise
    except Exception:
        if descriptor is not None:
            try:
                if acquired:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        raise RuntimeExecutionBusy() from None
    try:
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
