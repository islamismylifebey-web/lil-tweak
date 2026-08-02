#!/usr/bin/env python3
"""Generate or verify the self-excluding manifest from Git objects, never worktree bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "FINAL_FILE_MANIFEST.json"
BASELINE_COMMIT = "373400cb2b459dbf8a37dacceb0d3d1186eef949"
GIT_ENV = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/local/bin:/usr/bin:/bin",
}


def _git(*arguments: str) -> bytes:
    return subprocess.run(
        ("git", *arguments),
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=30,
        shell=False,
        env=GIT_ENV,
    ).stdout


def _git_blob_sha1(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


def _index_entries() -> tuple[str, list[tuple[str, str, str]]]:
    records: list[tuple[str, str, str]] = []
    for raw in _git("ls-files", "--stage", "-z").split(b"\0"):
        if not raw:
            continue
        metadata, path_bytes = raw.split(b"\t", 1)
        mode, object_id, stage = metadata.decode("ascii").split()
        if stage != "0":
            raise RuntimeError("manifest generation refuses an unmerged Git index")
        relative = path_bytes.decode("utf-8")
        if relative != OUTPUT.name:
            records.append((relative, mode, object_id))
    return "git-index:staged-blobs-self-excluded", sorted(records)


def _commit_entries(commit: str) -> tuple[str, list[tuple[str, str, str]]]:
    resolved = _git("rev-parse", "--verify", f"{commit}^{{commit}}").decode("ascii").strip()
    records: list[tuple[str, str, str]] = []
    for raw in _git("ls-tree", "-rz", resolved).split(b"\0"):
        if not raw:
            continue
        metadata, path_bytes = raw.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split()
        if object_type != "blob":
            raise RuntimeError("manifest scope contains a non-blob Git entry")
        relative = path_bytes.decode("utf-8")
        if relative != OUTPUT.name:
            records.append((relative, mode, object_id))
    return f"git-commit:{resolved}", sorted(records)


def generate(*, commit: str | None = None) -> dict[str, object]:
    source_view, entries = _commit_entries(commit) if commit else _index_entries()
    files: list[dict[str, object]] = []
    for relative, git_mode, object_id in entries:
        if git_mode not in {"100644", "100755", "120000"}:
            raise RuntimeError(f"manifest path has an unsupported Git mode: {relative}")
        content = _git("cat-file", "blob", object_id)
        calculated_object_id = _git_blob_sha1(content)
        if calculated_object_id != object_id:
            raise RuntimeError(f"Git blob identity mismatch while reading: {relative}")
        files.append(
            {
                "relative_path": relative,
                "entry_type": "symbolic_link" if git_mode == "120000" else "regular_file",
                "git_mode": git_mode,
                "sha256": hashlib.sha256(content).hexdigest(),
                "git_blob_sha1": object_id,
                "bytes": len(content),
            }
        )
    scope_digest = hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "liltweak-final-file-manifest-v3",
        "package": "lil-tweak-master-builder-architecture",
        "source_view": source_view,
        "repository": "islamismylifebey-web/lil-tweak",
        "branch": "codex/lil-tweak-live-workbench-build",
        "audited_baseline_commit": BASELINE_COMMIT,
        "candidate_commit": "recorded externally after immutable commit creation",
        "manifest_scope_digest": scope_digest,
        "scope": (
            "Every Git blob in the candidate tree, excluding only this self-referential "
            "manifest from its own entry list. Content is read from Git objects, not paths."
        ),
        "self_excluded_from_hash_list": True,
        "file_count_excluding_manifest": len(files),
        "files": files,
    }


def _validate(existing: dict[str, object], expected: dict[str, object]) -> None:
    compared = (
        "schema_version",
        "package",
        "repository",
        "branch",
        "audited_baseline_commit",
        "manifest_scope_digest",
        "scope",
        "self_excluded_from_hash_list",
        "file_count_excluding_manifest",
        "files",
    )
    mismatches = [name for name in compared if existing.get(name) != expected.get(name)]
    if mismatches:
        raise RuntimeError("final manifest does not match Git objects: " + ", ".join(mismatches))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--commit")
    arguments = parser.parse_args()
    expected = generate(commit=arguments.commit)
    if arguments.check:
        existing = json.loads(OUTPUT.read_text(encoding="utf-8"))
        _validate(existing, expected)
        print(json.dumps({"status": "PASSED", "source_view": expected["source_view"]}))
        return 0
    if arguments.commit:
        parser.error("--commit is verification-only; generate from a fully staged index")
    OUTPUT.write_text(json.dumps(expected, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
