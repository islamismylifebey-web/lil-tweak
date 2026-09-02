from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path, PurePosixPath

from liltweak.providers.self_hosted.qualification_manifest import (
    JOB_B_ARTIFACT_CONTENT,
    JOB_B_ARTIFACT_CONTENT_SHA256,
    JOB_B_ARTIFACT_EXPECTED_BEFORE_SHA256,
    JOB_B_ARTIFACT_PATH,
    QualificationBoundedWriteManifest,
    QualificationReadOnlyManifest,
)

RUNTIME_ROOTFS = "/opt/liltweak-runtime/rootfs"
RUNTIME_VENV = "/opt/liltweak-runtime/venv"
WORKSPACE_ROOT = PurePosixPath("/var/lib/liltweak-runner/workspaces")
APPARMOR_PROFILE = "liltweak-runner-job"
_BRANCH = re.compile(r"^qualification/galor-tweak-runner-01/[a-z0-9][a-z0-9-]{0,31}$")


class SandboxError(RuntimeError):
    """Reject unsafe workspace or sandbox execution state."""


class SandboxStep(StrEnum):
    PROBE = "probe"
    SOURCE_STATUS = "source_status"
    COMPILE = "compile"
    TEST = "test"
    RUFF_CHECK = "ruff_check"
    RUFF_FORMAT = "ruff_format"
    CREATE_BRANCH = "create_branch"
    WRITE_ARTIFACT = "write_artifact"
    VERIFY_BOUNDED_DIFF = "verify_bounded_diff"
    COMMIT = "commit"


def workspace_tmpfs_mount_command(workspace: Path) -> tuple[str, ...]:
    workspace_posix = _validated_workspace(workspace)
    return (
        "/usr/bin/mount",
        "-t",
        "tmpfs",
        "-o",
        "size=4294967296,nr_inodes=200000,nodev,nosuid,noexec,mode=0700",
        f"liltweak-{workspace_posix.name}",
        workspace_posix.as_posix(),
    )


def _validated_workspace(workspace: Path) -> PurePosixPath:
    workspace_posix = PurePosixPath(workspace.as_posix())
    if workspace_posix.parent != WORKSPACE_ROOT or workspace_posix.name in {"", ".", ".."}:
        raise SandboxError("workspace is outside the fixed runner root")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", workspace_posix.name):
        raise SandboxError("workspace execution id is invalid")
    return workspace_posix


_PROBE = """import json, os
status = open('/proc/self/status', encoding='ascii').read().splitlines()
seccomp = [line for line in status if line.startswith('Seccomp:')]
label = open('/proc/self/attr/current', encoding='ascii').read().strip()
if os.geteuid() == 0 or seccomp != ['Seccomp:\t2'] or not label or label.startswith('unconfined'):
    raise SystemExit(74)
print(json.dumps({'apparmor': label, 'nonroot': True, 'seccomp': 2}, sort_keys=True))
"""

_WRITE_ARTIFACT = f"""import hashlib, os, pathlib
path = pathlib.Path({JOB_B_ARTIFACT_PATH!r})
path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
before = path.read_bytes() if path.exists() else b''
if hashlib.sha256(before).hexdigest() != {JOB_B_ARTIFACT_EXPECTED_BEFORE_SHA256!r}:
    raise SystemExit(75)
flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
fd = os.open(path, flags, 0o644)
try:
    data = {JOB_B_ARTIFACT_CONTENT.encode("utf-8")!r}
    if os.write(fd, data) != len(data):
        raise SystemExit(76)
    os.fsync(fd)
finally:
    os.close(fd)
if hashlib.sha256(path.read_bytes()).hexdigest() != {JOB_B_ARTIFACT_CONTENT_SHA256!r}:
    raise SystemExit(77)
"""

_VERIFY_BOUNDED_DIFF = f"""import hashlib, pathlib, subprocess
path = pathlib.Path({JOB_B_ARTIFACT_PATH!r})
status = subprocess.run(
    ['/usr/bin/git', 'status', '--porcelain=v1', '--untracked-files=all'],
    check=True, capture_output=True, text=True,
).stdout
if status != {"?? " + JOB_B_ARTIFACT_PATH + chr(10)!r}:
    raise SystemExit(78)
if hashlib.sha256(path.read_bytes()).hexdigest() != {JOB_B_ARTIFACT_CONTENT_SHA256!r}:
    raise SystemExit(79)
"""

_COMMIT = f"""import subprocess
subprocess.run(['/usr/bin/git', 'add', '--', {JOB_B_ARTIFACT_PATH!r}], check=True)
subprocess.run([
    '/usr/bin/git', '-c', 'user.name=Lil Tweak Qualification',
    '-c', 'user.email=runner-qualification@invalid', 'commit',
    '--no-gpg-sign', '-m', 'chore: qualify private runner bounded write',
], check=True)
"""

_FIXED_ACTIONS: dict[SandboxStep, tuple[str, ...]] = {
    SandboxStep.PROBE: ("/opt/liltweak-venv/bin/python", "-I", "-c", _PROBE),
    SandboxStep.SOURCE_STATUS: (
        "/usr/bin/git",
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    ),
    SandboxStep.COMPILE: (
        "/opt/liltweak-venv/bin/python",
        "-m",
        "compileall",
        "-q",
        "liltweak",
        "runner",
        "scripts",
    ),
    SandboxStep.TEST: (
        "/opt/liltweak-venv/bin/python",
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "tests/test_private_runner_control_plane.py",
        "tests/test_runner_qualification_manifest.py",
        "tests/test_self_hosted_provider.py",
        "tests/test_runner_gate3_connection.py",
        "tests/test_host_runner_protocol.py",
        "tests/test_host_runner_offer.py",
        "tests/test_host_runner_client.py",
        "tests/test_host_runner_sandbox.py",
    ),
    SandboxStep.RUFF_CHECK: (
        "/opt/liltweak-venv/bin/ruff",
        "check",
        "liltweak/private_runner_control_plane.py",
        "liltweak/providers/self_hosted/qualification_manifest.py",
        "runner",
    ),
    SandboxStep.RUFF_FORMAT: (
        "/opt/liltweak-venv/bin/ruff",
        "format",
        "--check",
        "liltweak/private_runner_control_plane.py",
        "liltweak/providers/self_hosted/qualification_manifest.py",
        "runner",
    ),
    SandboxStep.WRITE_ARTIFACT: (
        "/opt/liltweak-venv/bin/python",
        "-I",
        "-c",
        _WRITE_ARTIFACT,
    ),
    SandboxStep.VERIFY_BOUNDED_DIFF: (
        "/opt/liltweak-venv/bin/python",
        "-I",
        "-c",
        _VERIFY_BOUNDED_DIFF,
    ),
    SandboxStep.COMMIT: (
        "/opt/liltweak-venv/bin/python",
        "-I",
        "-c",
        _COMMIT,
    ),
}


def build_sandbox_command(
    *,
    step: SandboxStep,
    workspace: Path,
    sandbox_uid: int,
    sandbox_gid: int,
    seccomp_fd: int,
    qualification_branch: str | None = None,
) -> tuple[str, ...]:
    workspace_posix = _validated_workspace(workspace)
    if not 1_000 <= sandbox_uid <= 60_000 or not 1_000 <= sandbox_gid <= 60_000:
        raise SandboxError("sandbox uid or gid is invalid")
    if seccomp_fd < 3:
        raise SandboxError("seccomp descriptor is invalid")
    if step is SandboxStep.CREATE_BRANCH:
        if qualification_branch is None or not _BRANCH.fullmatch(qualification_branch):
            raise SandboxError("qualification branch is invalid")
        action: tuple[str, ...] = (
            "/usr/bin/git",
            "switch",
            "-c",
            qualification_branch,
        )
    else:
        try:
            action = _FIXED_ACTIONS[step]
        except KeyError as exc:
            raise SandboxError("sandbox step is not authorized") from exc
    return (
        "/usr/bin/aa-exec",
        "-p",
        APPARMOR_PROFILE,
        "--",
        "/usr/bin/prlimit",
        "--cpu=1800",
        "--as=4294967296",
        "--nproc=256",
        "--nofile=256",
        "--fsize=67108864",
        "--",
        "/usr/bin/bwrap",
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        RUNTIME_ROOTFS,
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/tmp/home",
        "--ro-bind",
        RUNTIME_VENV,
        "/opt/liltweak-venv",
        "--bind",
        workspace_posix.as_posix(),
        "/workspace",
        "--chdir",
        "/workspace",
        "--clearenv",
        "--setenv",
        "HOME",
        "/tmp/home",
        "--setenv",
        "PATH",
        "/opt/liltweak-venv/bin:/usr/local/bin:/usr/bin:/bin",
        "--setenv",
        "PYTHONPATH",
        "/workspace",
        "--setenv",
        "PYTHONPYCACHEPREFIX",
        "/tmp/pycache",
        "--setenv",
        "GIT_CONFIG_NOSYSTEM",
        "1",
        "--setenv",
        "GIT_CONFIG_GLOBAL",
        "/dev/null",
        "--setenv",
        "GIT_TERMINAL_PROMPT",
        "0",
        "--setenv",
        "OPENAI_API_KEY",
        "",
        "--setenv",
        "LILTWEAK_LIVE_MODEL_ENABLED",
        "false",
        "--setenv",
        "LILTWEAK_REPOSITORY_EXECUTION_ENABLED",
        "false",
        "--uid",
        str(sandbox_uid),
        "--gid",
        str(sandbox_gid),
        "--seccomp",
        str(seccomp_fd),
        "--",
        *action,
    )


def fixed_job_steps(
    manifest: QualificationReadOnlyManifest | QualificationBoundedWriteManifest,
) -> tuple[SandboxStep, ...]:
    if isinstance(manifest, QualificationReadOnlyManifest):
        return (
            SandboxStep.PROBE,
            SandboxStep.SOURCE_STATUS,
            SandboxStep.COMPILE,
            SandboxStep.TEST,
            SandboxStep.RUFF_CHECK,
            SandboxStep.RUFF_FORMAT,
            SandboxStep.SOURCE_STATUS,
        )
    if isinstance(manifest, QualificationBoundedWriteManifest):
        return (
            SandboxStep.PROBE,
            SandboxStep.CREATE_BRANCH,
            SandboxStep.WRITE_ARTIFACT,
            SandboxStep.COMPILE,
            SandboxStep.TEST,
            SandboxStep.RUFF_CHECK,
            SandboxStep.RUFF_FORMAT,
            SandboxStep.VERIFY_BOUNDED_DIFF,
            SandboxStep.COMMIT,
        )
    raise SandboxError("job manifest type is not authorized")
