from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import uuid
from collections.abc import Mapping
from pathlib import Path

from .protocol import canonical_json

CANDIDATE_ROOT = Path("/var/lib/liltweak-runner/candidates")
DEFAULT_MAX_BUNDLE_BYTES = 1_000_000
MAX_RECEIPT_BYTES = 64_000
_EXECUTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_GIT_SHA = re.compile(r"^[a-f0-9]{40}$")
_BRANCH = re.compile(r"^qualification/galor-tweak-runner-01/[a-z0-9][a-z0-9-]{0,31}$")


class CandidateStoreError(RuntimeError):
    """Reject unsafe or oversized candidate persistence."""


def _run_git(workspace: Path, *arguments: str) -> None:
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
        timeout=60,
    )
    if result.returncode != 0 or len(result.stdout) + len(result.stderr) > 128_000:
        raise CandidateStoreError("candidate bundle operation failed")


class CandidateStore:
    def __init__(
        self,
        *,
        root: Path = CANDIDATE_ROOT,
        max_bundle_bytes: int = DEFAULT_MAX_BUNDLE_BYTES,
    ) -> None:
        if not 4_096 <= max_bundle_bytes <= 16_000_000:
            raise CandidateStoreError("candidate bundle limit is invalid")
        self._root = root
        self._max_bundle_bytes = max_bundle_bytes

    def persist(
        self,
        *,
        execution_id: str,
        workspace: Path,
        source_commit: str,
        candidate_commit: str,
        qualification_branch: str,
        base_receipt: Mapping[str, object],
        now_ms: int,
    ) -> dict[str, object]:
        if not _EXECUTION_ID.fullmatch(execution_id):
            raise CandidateStoreError("execution id is invalid")
        if not _GIT_SHA.fullmatch(source_commit) or not _GIT_SHA.fullmatch(candidate_commit):
            raise CandidateStoreError("candidate source binding is invalid")
        if not _BRANCH.fullmatch(qualification_branch):
            raise CandidateStoreError("qualification branch is invalid")
        if not isinstance(now_ms, int) or isinstance(now_ms, bool) or now_ms < 0:
            raise CandidateStoreError("candidate timestamp is invalid")
        root_metadata = self._root.stat()
        if not stat.S_ISDIR(root_metadata.st_mode) or self._root.is_symlink():
            raise CandidateStoreError("candidate root is invalid")
        target = self._root / execution_id
        if target.exists() or target.is_symlink():
            raise CandidateStoreError("candidate record already exists")
        temporary = self._root / f".{execution_id}.{uuid.uuid4().hex}.tmp"
        temporary.mkdir(mode=0o700)
        bundle = temporary / "candidate.bundle"
        receipt_path = temporary / "receipt.json"
        try:
            _run_git(
                workspace,
                "bundle",
                "create",
                str(bundle),
                qualification_branch,
                f"^{source_commit}",
            )
            os.chmod(bundle, 0o600)
            metadata = bundle.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size < 1
                or metadata.st_size > self._max_bundle_bytes
            ):
                raise CandidateStoreError("candidate bundle exceeded its bound")
            _run_git(workspace, "bundle", "verify", str(bundle))
            bundle_bytes = bundle.read_bytes()
            receipt: dict[str, object] = {
                **dict(base_receipt),
                "bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
                "bundle_size": len(bundle_bytes),
                "candidate_store_id": execution_id,
                "created_at_ms": now_ms,
                "qualification_branch": qualification_branch,
            }
            encoded = (canonical_json(receipt) + "\n").encode("utf-8")
            if len(encoded) > MAX_RECEIPT_BYTES:
                raise CandidateStoreError("candidate receipt exceeded its bound")
            descriptor = os.open(
                receipt_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                if os.write(descriptor, encoded) != len(encoded):
                    raise CandidateStoreError("candidate receipt write was incomplete")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.chmod(receipt_path, 0o600)
            os.chmod(temporary, 0o700)
            os.rename(temporary, target)
            return receipt
        except Exception:
            if temporary.exists() and not temporary.is_symlink():
                shutil.rmtree(temporary)
            raise

    def finalize(
        self,
        *,
        execution_id: str,
        receipt: Mapping[str, object],
    ) -> dict[str, object]:
        if not _EXECUTION_ID.fullmatch(execution_id):
            raise CandidateStoreError("execution id is invalid")
        target = self._root / execution_id
        bundle = target / "candidate.bundle"
        receipt_path = target / "receipt.json"
        if target.is_symlink() or not target.is_dir():
            raise CandidateStoreError("candidate record is invalid")
        bundle_bytes = bundle.read_bytes()
        finalized = dict(receipt)
        if (
            finalized.get("candidate_store_id") != execution_id
            or finalized.get("bundle_size") != len(bundle_bytes)
            or finalized.get("bundle_sha256") != hashlib.sha256(bundle_bytes).hexdigest()
        ):
            raise CandidateStoreError("candidate receipt is not bound to the bundle")
        encoded = (canonical_json(finalized) + "\n").encode("utf-8")
        if len(encoded) > MAX_RECEIPT_BYTES:
            raise CandidateStoreError("candidate receipt exceeded its bound")
        temporary = target / ".receipt.json.tmp"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            if os.write(descriptor, encoded) != len(encoded):
                raise CandidateStoreError("candidate receipt write was incomplete")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(temporary, 0o600)
        os.replace(temporary, receipt_path)
        return finalized

    def cleanup_expired(self, *, now_seconds: int, retention_seconds: int) -> int:
        if retention_seconds < 3_600 or retention_seconds > 604_800:
            raise CandidateStoreError("candidate retention is invalid")
        removed = 0
        for child in self._root.iterdir():
            if not _EXECUTION_ID.fullmatch(child.name) or child.is_symlink() or not child.is_dir():
                continue
            if now_seconds - int(child.stat().st_mtime) < retention_seconds:
                continue
            entries = {entry.name: entry for entry in child.iterdir()}
            if set(entries) != {"candidate.bundle", "receipt.json"}:
                continue
            if any(entry.is_symlink() or not entry.is_file() for entry in entries.values()):
                continue
            shutil.rmtree(child)
            removed += 1
        return removed
