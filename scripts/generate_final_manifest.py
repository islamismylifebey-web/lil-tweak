#!/usr/bin/env python3
"""Generate the self-excluding final Lil Tweak source-tree manifest."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "FINAL_FILE_MANIFEST.json"
BASELINE_COMMIT = "373400cb2b459dbf8a37dacceb0d3d1186eef949"


def _git_blob_sha1(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


def generate() -> dict[str, object]:
    result = subprocess.run(
        ("git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"),
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=10,
        shell=False,
        env={
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        },
    )
    paths = sorted(
        value.decode("utf-8")
        for value in result.stdout.split(b"\0")
        if value and value.decode("utf-8") != OUTPUT.name
    )
    files: list[dict[str, object]] = []
    for relative in paths:
        path = ROOT / relative
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            # A tracked deletion is absent from the candidate tree by definition.
            continue
        if stat.S_ISREG(metadata.st_mode):
            content = path.read_bytes()
            entry_type = "regular_file"
            git_mode = "100755" if metadata.st_mode & 0o111 else "100644"
        elif stat.S_ISLNK(metadata.st_mode):
            content = os.readlink(path).encode("utf-8")
            entry_type = "symbolic_link"
            git_mode = "120000"
        else:
            raise RuntimeError(f"manifest path has an unsupported file type: {relative}")
        files.append(
            {
                "relative_path": relative,
                "entry_type": entry_type,
                "git_mode": git_mode,
                "sha256": hashlib.sha256(content).hexdigest(),
                "git_blob_sha1": _git_blob_sha1(content),
                "bytes": len(content),
            }
        )
    return {
        "schema_version": "liltweak-final-file-manifest-v2",
        "package": "lil-tweak-master-builder-architecture",
        "built_at_utc": datetime.now(UTC).isoformat(),
        "repository": "islamismylifebey-web/lil-tweak",
        "branch": "codex/lil-tweak-live-workbench-build",
        "audited_baseline_commit": BASELINE_COMMIT,
        "candidate_commit": "recorded externally after immutable commit creation",
        "candidate_tree": "verified externally after manifest generation",
        "scope": (
            "Every tracked or candidate-untracked path in the final Git tree, excluding only "
            "this self-referential manifest from its own entry list."
        ),
        "self_excluded_from_hash_list": True,
        "file_count_excluding_manifest": len(files),
        "files": files,
    }


if __name__ == "__main__":
    OUTPUT.write_text(
        json.dumps(generate(), indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
