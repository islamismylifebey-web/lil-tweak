from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from liltweak.creator_contract import canonical_json
from liltweak.providers.github.runner_v3_contracts import (
    RunnerV3Action,
    RunnerV3JobManifest,
    RunnerV3WorkspaceMode,
)

_REPOSITORY_ID = "github:islamismylifebey-web/lil-tweak"


class RunnerV3SmokeManifestError(RuntimeError):
    """Reject a smoke manifest when the exact checkout is not provable."""


def _digest(label: str, commit: str, tree: str) -> str:
    return hashlib.sha256(f"{label}\0{commit}\0{tree}".encode()).hexdigest()


def _git(workspace: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            (
                "git",
                "-c",
                f"safe.directory={workspace}",
                "-C",
                str(workspace),
                *arguments,
            ),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunnerV3SmokeManifestError(
            "Runner V3 smoke source inspection failed"
        ) from exc
    if result.returncode != 0 or len(result.stdout) + len(result.stderr) > 128_000:
        raise RunnerV3SmokeManifestError(
            "Runner V3 smoke source inspection failed"
        )
    return result.stdout.strip()


def build_smoke_manifest(
    workspace: Path,
    *,
    now: datetime | None = None,
) -> RunnerV3JobManifest:
    """Bind a no-write smoke job to one exact clean Git checkout."""

    if workspace.is_symlink():
        raise RunnerV3SmokeManifestError(
            "Runner V3 smoke workspace cannot be a symlink"
        )
    try:
        resolved = workspace.resolve(strict=True)
    except OSError as exc:
        raise RunnerV3SmokeManifestError(
            "Runner V3 smoke workspace does not exist"
        ) from exc
    if not resolved.is_dir():
        raise RunnerV3SmokeManifestError(
            "Runner V3 smoke workspace must be a directory"
        )
    if _git(resolved, "rev-parse", "--is-inside-work-tree") != "true":
        raise RunnerV3SmokeManifestError(
            "Runner V3 smoke workspace is not a Git checkout"
        )
    commit = _git(resolved, "rev-parse", "HEAD")
    tree = _git(resolved, "rev-parse", "HEAD^{tree}")
    if len(commit) != 40 or len(tree) != 40:
        raise RunnerV3SmokeManifestError(
            "Runner V3 smoke source identity is invalid"
        )
    if _git(resolved, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RunnerV3SmokeManifestError(
            "Runner V3 smoke workspace must be clean"
        )

    issued_at = now or datetime.now(UTC)
    if issued_at.tzinfo is None or issued_at.utcoffset() is None:
        raise RunnerV3SmokeManifestError(
            "Runner V3 smoke issuance time must be timezone-aware"
        )
    expires_at = issued_at + timedelta(minutes=15)
    return RunnerV3JobManifest.issue(
        execution_id=f"runner_v3_smoke_{commit[:16]}",
        attempt_nonce=_digest("attempt", commit, tree),
        repository_id=_REPOSITORY_ID,
        source_commit=commit,
        source_tree=tree,
        contract_digest=_digest("contract", commit, tree),
        lease_digest=_digest("lease", commit, tree),
        commands_digest=_digest("commands", commit, tree),
        approval_digest=_digest("approval", commit, tree),
        policy_digest=_digest("policy", commit, tree),
        issued_at=issued_at,
        expires_at=expires_at,
        cpu_ceiling=2,
        memory_mb_ceiling=2_048,
        disk_mb_ceiling=4_096,
        timeout_seconds=600,
        output_byte_limit=128_000,
        workspace_mode=RunnerV3WorkspaceMode.READ_ONLY,
        source_write_authorized=False,
        actions=(
            RunnerV3Action.INSPECT_SOURCE,
            RunnerV3Action.COMPILE_PYTHON,
            RunnerV3Action.GIT_DIFF,
        ),
        patch=None,
    )


def _write_manifest(path: Path, manifest: RunnerV3JobManifest) -> None:
    if path.exists() or path.is_symlink():
        raise RunnerV3SmokeManifestError(
            "Runner V3 smoke manifest output already exists"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise RunnerV3SmokeManifestError(
            "Runner V3 smoke manifest output is not safely writable"
        ) from exc
    try:
        payload = (
            f"{canonical_json(manifest.model_dump(mode='json'))}\n".encode()
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RunnerV3SmokeManifestError(
                    "Runner V3 smoke manifest write was incomplete"
                )
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create one exact-source Runner V3 smoke manifest",
    )
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    manifest = build_smoke_manifest(arguments.workspace)
    _write_manifest(arguments.output, manifest)
    print(
        canonical_json(
            {
                "execution_id": manifest.execution_id,
                "manifest_digest": manifest.manifest_digest,
                "source_commit": manifest.source_commit,
                "source_tree": manifest.source_tree,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
