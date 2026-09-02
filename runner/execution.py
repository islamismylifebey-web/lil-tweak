from __future__ import annotations

import hashlib
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from liltweak.providers.self_hosted.qualification_manifest import (
    JOB_B_ARTIFACT_CONTENT_SHA256,
    JOB_B_ARTIFACT_PATH,
    QualificationBoundedWriteManifest,
)

from .candidates import CandidateStore
from .cgroup import CgroupJob, CgroupManager
from .offer import VerifiedOffer
from .sandbox import (
    SandboxStep,
    build_sandbox_command,
    fixed_job_steps,
    workspace_tmpfs_mount_command,
)

_GIT_SHA = re.compile(r"^[a-f0-9]{40}$")
_EXECUTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_GIT_OUTPUT = 128_000
_MAX_JOB_OUTPUT = 128_000

WORKSPACE_ROOT = Path("/var/lib/liltweak-runner/workspaces")
DEPLOY_KEY_PATH = Path("/etc/liltweak-runner/repository_deploy_key")
KNOWN_HOSTS_PATH = Path("/etc/liltweak-runner/github_known_hosts")
SECCOMP_PATH = Path("/opt/liltweak-runner/seccomp.bpf")
SECCOMP_SHA256 = "50eeb8b4cb2c33284f09453c8dd64c5895f5e1a2fa6b7a7440dfbac175fe1c23"
REPOSITORY_URL = "git@github.com:islamismylifebey-web/lil-tweak.git"
ROOTFS_IMAGE_REF = (
    "python@sha256:"
    "229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
)


class ExecutionSecurityError(RuntimeError):
    """Fail closed when source, workspace, or candidate invariants diverge."""


def _validate_root_file(path: Path, *, allowed_modes: set[int]) -> os.stat_result:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) not in allowed_modes
    ):
        raise ExecutionSecurityError(f"protected host file {path.name} is invalid")
    return metadata


def _git(workspace: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={workspace}",
            "-C",
            str(workspace),
            *arguments,
        ],
        check=False,
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0 or len(result.stdout) > _MAX_GIT_OUTPUT:
        raise ExecutionSecurityError("Git checkout inspection failed")
    return result.stdout


def _git_text(workspace: Path, *arguments: str) -> str:
    try:
        return _git(workspace, *arguments).decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise ExecutionSecurityError("Git checkout inspection was not ASCII") from exc


def _validate_sha(value: str, label: str) -> None:
    if not _GIT_SHA.fullmatch(value):
        raise ExecutionSecurityError(f"{label} is invalid")


def inspect_job_a_checkout(
    workspace: Path,
    *,
    expected_commit: str,
    expected_tree: str,
) -> dict[str, object]:
    _validate_sha(expected_commit, "expected source commit")
    _validate_sha(expected_tree, "expected source tree")
    commit = _git_text(workspace, "rev-parse", "HEAD")
    tree = _git_text(workspace, "rev-parse", "HEAD^{tree}")
    status = _git(workspace, "status", "--porcelain=v1", "--untracked-files=all")
    if commit != expected_commit or tree != expected_tree:
        raise ExecutionSecurityError("checkout source does not match the exact manifest")
    if status:
        raise ExecutionSecurityError("checkout source mutated during read-only execution")
    return {
        "candidate_sha": None,
        "source_commit": commit,
        "source_tree": tree,
        "source_mutated": False,
    }


def inspect_job_b_candidate(
    workspace: Path,
    *,
    expected_source_commit: str,
    expected_source_tree: str,
) -> dict[str, object]:
    _validate_sha(expected_source_commit, "expected source commit")
    _validate_sha(expected_source_tree, "expected source tree")
    source_tree = _git_text(workspace, "rev-parse", f"{expected_source_commit}^{{tree}}")
    if source_tree != expected_source_tree:
        raise ExecutionSecurityError("bounded candidate source tree is not exact")
    candidate = _git_text(workspace, "rev-parse", "HEAD")
    _validate_sha(candidate, "candidate commit")
    parents = _git_text(workspace, "rev-list", "--parents", "-n", "1", "HEAD").split()
    if parents != [candidate, expected_source_commit]:
        raise ExecutionSecurityError("bounded candidate is not one commit above exact source")
    if _git(workspace, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ExecutionSecurityError("bounded candidate workspace is not clean")
    expected_diff = b"A\0" + JOB_B_ARTIFACT_PATH.encode("ascii") + b"\0"
    actual_diff = _git(
        workspace,
        "diff",
        "--name-status",
        "-z",
        expected_source_commit,
        candidate,
    )
    if actual_diff != expected_diff:
        raise ExecutionSecurityError("bounded diff contains an unauthorized path or change type")
    artifact = workspace / JOB_B_ARTIFACT_PATH
    metadata = artifact.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 4096:
        raise ExecutionSecurityError("bounded artifact metadata is invalid")
    artifact_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if artifact_digest != JOB_B_ARTIFACT_CONTENT_SHA256:
        raise ExecutionSecurityError("bounded artifact content is invalid")
    candidate_tree = _git_text(workspace, "rev-parse", "HEAD^{tree}")
    _validate_sha(candidate_tree, "candidate tree")
    return {
        "artifact_path": JOB_B_ARTIFACT_PATH,
        "artifact_sha256": artifact_digest,
        "candidate_sha": candidate,
        "candidate_tree": candidate_tree,
        "source_commit": expected_source_commit,
        "source_tree": source_tree,
        "source_mutated": True,
    }


@dataclass(frozen=True)
class ExecutionResult:
    outcome: Literal["succeeded", "failed", "cancelled"]
    exit_code: int
    stdout: bytes
    stderr: bytes
    receipt: Mapping[str, object]
    started_at_ms: int
    finished_at_ms: int


@dataclass(frozen=True)
class WorkspaceLease:
    path: Path


class WorkspaceManager:
    def __init__(self, *, sandbox_uid: int, sandbox_gid: int) -> None:
        self._uid = sandbox_uid
        self._gid = sandbox_gid

    @staticmethod
    def _minimal_git_environment() -> dict[str, str]:
        ssh = (
            f"/usr/bin/ssh -i {DEPLOY_KEY_PATH} -o IdentitiesOnly=yes "
            "-o BatchMode=yes -o StrictHostKeyChecking=yes "
            f"-o UserKnownHostsFile={KNOWN_HOSTS_PATH}"
        )
        return {
            "HOME": "/nonexistent",
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_SSH_COMMAND": ssh,
        }

    @staticmethod
    def _run(command: tuple[str, ...], *, environment: dict[str, str] | None = None) -> None:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            env=environment,
            timeout=180,
        )
        if result.returncode != 0 or len(result.stdout) + len(result.stderr) > _MAX_GIT_OUTPUT:
            raise ExecutionSecurityError("workspace materialization command failed")

    def materialize(self, offer: VerifiedOffer) -> WorkspaceLease:
        execution_id = offer.execution_id
        if not _EXECUTION_ID.fullmatch(execution_id):
            raise ExecutionSecurityError("workspace execution id is invalid")
        get_effective_uid = getattr(os, "geteuid", lambda: -1)
        if get_effective_uid() != 0:
            raise ExecutionSecurityError("workspace supervisor must run as root")
        _validate_root_file(DEPLOY_KEY_PATH, allowed_modes={0o400, 0o600})
        _validate_root_file(KNOWN_HOSTS_PATH, allowed_modes={0o400, 0o444, 0o600, 0o644})
        root = WORKSPACE_ROOT
        root_metadata = root.lstat()
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or root.is_symlink()
            or root_metadata.st_uid != 0
            or stat.S_IMODE(root_metadata.st_mode) & 0o022
        ):
            raise ExecutionSecurityError("workspace root is invalid")
        workspace = root / execution_id
        if workspace.exists() or workspace.is_symlink():
            raise ExecutionSecurityError("workspace already exists")
        workspace.mkdir(mode=0o700)
        mounted = False
        try:
            self._run(workspace_tmpfs_mount_command(workspace))
            mounted = True
            git = "/usr/bin/git"
            environment = self._minimal_git_environment()
            self._run((git, "-C", str(workspace), "init"), environment=environment)
            self._run(
                (git, "-C", str(workspace), "remote", "add", "origin", REPOSITORY_URL),
                environment=environment,
            )
            self._run(
                (
                    git,
                    "-C",
                    str(workspace),
                    "fetch",
                    "--no-tags",
                    "--depth=1",
                    "origin",
                    offer.manifest.source.commit_sha,
                ),
                environment=environment,
            )
            self._run(
                (
                    git,
                    "-C",
                    str(workspace),
                    "checkout",
                    "--detach",
                    offer.manifest.source.commit_sha,
                ),
                environment=environment,
            )
            self._run(
                (git, "-C", str(workspace), "config", "core.hooksPath", "/dev/null"),
                environment=environment,
            )
            inspect_job_a_checkout(
                workspace,
                expected_commit=offer.manifest.source.commit_sha,
                expected_tree=offer.manifest.source.tree_sha,
            )
            self._run(
                (
                    "/usr/bin/chown",
                    "-R",
                    "--no-dereference",
                    f"{self._uid}:{self._gid}",
                    str(workspace),
                )
            )
            return WorkspaceLease(path=workspace)
        except Exception:
            if mounted:
                subprocess.run(
                    ("/usr/bin/umount", str(workspace)),
                    check=False,
                    capture_output=True,
                )
            if workspace.exists() and not workspace.is_symlink():
                shutil.rmtree(workspace)
            raise

    def cleanup(self, lease: WorkspaceLease) -> None:
        if lease.path.parent != WORKSPACE_ROOT or not _EXECUTION_ID.fullmatch(lease.path.name):
            raise ExecutionSecurityError("workspace cleanup target is invalid")
        result = subprocess.run(
            ("/usr/bin/umount", str(lease.path)),
            check=False,
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise ExecutionSecurityError("workspace tmpfs could not be unmounted")
        if lease.path.exists() and not lease.path.is_symlink():
            shutil.rmtree(lease.path)


@dataclass(frozen=True)
class CommandOutput:
    exit_code: int
    stdout: bytes
    stderr: bytes


class SandboxProcess:
    def __init__(self, *, sandbox_uid: int, sandbox_gid: int) -> None:
        self._uid = sandbox_uid
        self._gid = sandbox_gid

    @staticmethod
    def _kill_process(process: subprocess.Popen[bytes], cgroup: CgroupJob) -> None:
        try:
            cgroup.kill()
        except Exception:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)  # type: ignore[attr-defined]

    def run(
        self,
        *,
        execution_id: str,
        cgroup: CgroupJob,
        step: SandboxStep,
        workspace: Path,
        timeout_seconds: float,
        cancellation_requested: Callable[[], bool],
        qualification_branch: str | None,
    ) -> CommandOutput:
        filter_metadata = _validate_root_file(SECCOMP_PATH, allowed_modes={0o400, 0o444})
        if filter_metadata.st_size > 4096:
            raise ExecutionSecurityError("seccomp filter size is invalid")
        filter_bytes = SECCOMP_PATH.read_bytes()
        if hashlib.sha256(filter_bytes).hexdigest() != SECCOMP_SHA256:
            raise ExecutionSecurityError("seccomp filter digest is invalid")
        descriptor = os.open(
            SECCOMP_PATH,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        command = build_sandbox_command(
            step=step,
            workspace=workspace,
            sandbox_uid=self._uid,
            sandbox_gid=self._gid,
            seccomp_fd=descriptor,
            qualification_branch=qualification_branch,
        )
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(descriptor,),
            start_new_session=True,
        )
        os.close(descriptor)
        cgroup.attach(process.pid)
        if process.stdout is None or process.stderr is None:
            self._kill_process(process, cgroup)
            raise ExecutionSecurityError("sandbox output pipes are unavailable")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        output = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + timeout_seconds
        next_cancellation_check = 0.0
        try:
            while selector.get_map() or process.poll() is None:
                now = time.monotonic()
                if now >= deadline:
                    self._kill_process(process, cgroup)
                    return CommandOutput(124, bytes(output["stdout"]), bytes(output["stderr"]))
                if now >= next_cancellation_check:
                    next_cancellation_check = now + 1.0
                    if cancellation_requested():
                        self._kill_process(process, cgroup)
                        process.wait(timeout=10)
                        return CommandOutput(
                            130,
                            bytes(output["stdout"]),
                            bytes(output["stderr"]),
                        )
                for key, _ in selector.select(timeout=min(0.25, deadline - now)):
                    chunk = os.read(key.fd, 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    target = output[str(key.data)]
                    target.extend(chunk)
                    if len(output["stdout"]) + len(output["stderr"]) > _MAX_JOB_OUTPUT:
                        self._kill_process(process, cgroup)
                        process.wait(timeout=10)
                        return CommandOutput(
                            70,
                            bytes(output["stdout"][:_MAX_JOB_OUTPUT]),
                            bytes(output["stderr"][:_MAX_JOB_OUTPUT]),
                        )
            return_code = int(process.wait())
            return CommandOutput(
                min(255, 128 + abs(return_code)) if return_code < 0 else min(255, return_code),
                bytes(output["stdout"]),
                bytes(output["stderr"]),
            )
        finally:
            selector.close()


class HostJobExecutor:
    def __init__(self, *, sandbox_uid: int = 17_001, sandbox_gid: int = 17_001) -> None:
        self._workspace = WorkspaceManager(sandbox_uid=sandbox_uid, sandbox_gid=sandbox_gid)
        self._sandbox = SandboxProcess(sandbox_uid=sandbox_uid, sandbox_gid=sandbox_gid)
        self._cgroups = CgroupManager()
        self._candidates = CandidateStore()

    def execute(
        self,
        offer: VerifiedOffer,
        *,
        cancellation_requested: Callable[[], bool],
    ) -> ExecutionResult:
        started_at = time.time_ns() // 1_000_000
        stdout = bytearray()
        stderr = bytearray()
        receipt: dict[str, object] = {
            "runner_id": "galor-tweak-runner-01",
            "runtime_image": ROOTFS_IMAGE_REF,
            "seccomp_sha256": SECCOMP_SHA256,
            "apparmor_profile": "liltweak-runner-job",
            "network_denied": True,
            "package_install_allowed": False,
            "production_access_allowed": False,
            "deploy_allowed": False,
            "workspace_cleaned": False,
            "cgroup_cleaned": False,
        }
        outcome: Literal["succeeded", "failed", "cancelled"] = "failed"
        exit_code = 70
        lease: WorkspaceLease | None = None
        cgroup: CgroupJob | None = None
        candidate_persisted = False
        try:
            if cancellation_requested():
                outcome = "cancelled"
                exit_code = 0
            else:
                lease = self._workspace.materialize(offer)
                cgroup = self._cgroups.create(offer.execution_id)
                deadline = min(
                    started_at + offer.manifest.timeout_seconds * 1000,
                    offer.expires_at_ms,
                )
                for step in fixed_job_steps(offer.manifest):
                    remaining = (deadline - (time.time_ns() // 1_000_000)) / 1000
                    if remaining <= 0:
                        exit_code = 124
                        break
                    output = self._sandbox.run(
                        execution_id=offer.execution_id,
                        cgroup=cgroup,
                        step=step,
                        workspace=lease.path,
                        timeout_seconds=remaining,
                        cancellation_requested=cancellation_requested,
                        qualification_branch=(
                            offer.manifest.qualification_branch
                            if isinstance(offer.manifest, QualificationBoundedWriteManifest)
                            else None
                        ),
                    )
                    stdout.extend(output.stdout)
                    stderr.extend(output.stderr)
                    if output.exit_code != 0:
                        exit_code = output.exit_code
                        outcome = "cancelled" if output.exit_code == 130 else "failed"
                        break
                else:
                    if isinstance(offer.manifest, QualificationBoundedWriteManifest):
                        bounded = inspect_job_b_candidate(
                            lease.path,
                            expected_source_commit=offer.manifest.source.commit_sha,
                            expected_source_tree=offer.manifest.source.tree_sha,
                        )
                        receipt.update(bounded)
                        receipt = self._candidates.persist(
                            execution_id=offer.execution_id,
                            workspace=lease.path,
                            source_commit=offer.manifest.source.commit_sha,
                            candidate_commit=str(bounded["candidate_sha"]),
                            qualification_branch=offer.manifest.qualification_branch,
                            base_receipt=receipt,
                            now_ms=time.time_ns() // 1_000_000,
                        )
                        candidate_persisted = True
                    else:
                        receipt.update(
                            inspect_job_a_checkout(
                                lease.path,
                                expected_commit=offer.manifest.source.commit_sha,
                                expected_tree=offer.manifest.source.tree_sha,
                            )
                        )
                    outcome = "succeeded"
                    exit_code = 0
        except Exception as exc:
            stderr.extend(type(exc).__name__.encode("ascii", errors="replace"))
            outcome = "failed"
            exit_code = 70
        finally:
            if cgroup is not None:
                try:
                    cgroup.cleanup()
                    receipt["cgroup_cleaned"] = True
                except Exception:
                    outcome = "failed"
                    exit_code = 70
            if lease is not None:
                try:
                    self._workspace.cleanup(lease)
                    receipt["workspace_cleaned"] = True
                except Exception:
                    outcome = "failed"
                    exit_code = 70
            if candidate_persisted:
                try:
                    receipt = self._candidates.finalize(
                        execution_id=offer.execution_id,
                        receipt=receipt,
                    )
                except Exception:
                    outcome = "failed"
                    exit_code = 70
        finished_at = time.time_ns() // 1_000_000
        return ExecutionResult(
            outcome=outcome,
            exit_code=exit_code,
            stdout=bytes(stdout[:_MAX_JOB_OUTPUT]),
            stderr=bytes(stderr[:_MAX_JOB_OUTPUT]),
            receipt=receipt,
            started_at_ms=started_at,
            finished_at_ms=finished_at,
        )
