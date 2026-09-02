from __future__ import annotations

from pathlib import Path

import pytest

from liltweak.providers.self_hosted.qualification_manifest import (
    JOB_B_ARTIFACT_CONTENT,
    QualificationBoundedWriteManifest,
    QualificationReadOnlyManifest,
    QualificationSource,
)
from runner.sandbox import (
    SandboxError,
    SandboxStep,
    build_sandbox_command,
    fixed_job_steps,
    workspace_tmpfs_mount_command,
)


def _source() -> QualificationSource:
    return QualificationSource(commit_sha="a" * 40, tree_sha="b" * 40)


def test_sandbox_command_uses_pinned_rootfs_mac_seccomp_nonroot_and_no_network() -> None:
    command = build_sandbox_command(
        step=SandboxStep.PROBE,
        workspace=Path("/var/lib/liltweak-runner/workspaces/exec-001"),
        sandbox_uid=17001,
        sandbox_gid=17001,
        seccomp_fd=9,
    )

    assert command[:6] == (
        "/usr/bin/aa-exec",
        "-p",
        "liltweak-runner-job",
        "--",
        "/usr/bin/prlimit",
        "--cpu=1800",
    )
    for namespace in ("ipc", "pid", "net", "uts", "cgroup"):
        assert f"--unshare-{namespace}" in command
    assert "--unshare-all" not in command
    assert "--unshare-user" not in command
    assert command[command.index("--ro-bind") : command.index("--ro-bind") + 3] == (
        "--ro-bind",
        "/opt/liltweak-runtime/rootfs",
        "/",
    )
    assert command[command.index("--seccomp") + 1] == "9"
    assert "/usr/bin/setpriv" in command
    assert "--reuid=17001" in command
    assert "--regid=17001" in command
    assert "--bounding-set=-all" in command
    assert "--no-new-privs" in command
    assert "--share-net" not in command
    assert "Seccomp" in "\n".join(command)
    assert "/proc/self/attr/current" in "\n".join(command)


def test_job_a_plan_has_only_probe_and_fixed_read_only_verification() -> None:
    manifest = QualificationReadOnlyManifest(source=_source(), timeout_seconds=900)

    assert fixed_job_steps(manifest) == (
        SandboxStep.PROBE,
        SandboxStep.SOURCE_STATUS,
        SandboxStep.COMPILE,
        SandboxStep.TEST,
        SandboxStep.RUFF_CHECK,
        SandboxStep.RUFF_FORMAT,
        SandboxStep.SOURCE_STATUS,
    )


def test_job_b_plan_has_one_fixed_artifact_and_local_commit_but_never_push() -> None:
    manifest = QualificationBoundedWriteManifest(
        source=_source(),
        timeout_seconds=1_200,
        qualification_branch="qualification/galor-tweak-runner-01/probe-001",
    )

    steps = fixed_job_steps(manifest)

    assert steps == (
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
    all_arguments = "\n".join(
        argument
        for step in steps
        for argument in build_sandbox_command(
            step=step,
            workspace=Path("/var/lib/liltweak-runner/workspaces/exec-001"),
            sandbox_uid=17001,
            sandbox_gid=17001,
            seccomp_fd=9,
            qualification_branch=manifest.qualification_branch,
        )
    )
    assert repr(JOB_B_ARTIFACT_CONTENT.encode("utf-8")) in all_arguments
    assert "/usr/bin/git\npush\n" not in all_arguments
    assert "/usr/bin/git\nmerge\n" not in all_arguments
    assert "/usr/bin/git\ndeploy\n" not in all_arguments
    assert "pip install" not in all_arguments


def test_sandbox_rejects_workspace_outside_fixed_root() -> None:
    with pytest.raises(SandboxError, match="workspace"):
        build_sandbox_command(
            step=SandboxStep.PROBE,
            workspace=Path("/tmp/escape"),
            sandbox_uid=17001,
            sandbox_gid=17001,
            seccomp_fd=9,
        )


def test_workspace_tmpfs_has_fixed_disk_and_inode_limits() -> None:
    assert workspace_tmpfs_mount_command(Path("/var/lib/liltweak-runner/workspaces/exec-001")) == (
        "/usr/bin/mount",
        "-t",
        "tmpfs",
        "-o",
        "size=4294967296,nr_inodes=200000,nodev,nosuid,noexec,mode=0700",
        "liltweak-exec-001",
        "/var/lib/liltweak-runner/workspaces/exec-001",
    )
