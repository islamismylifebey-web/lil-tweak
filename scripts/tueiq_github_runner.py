#!/usr/bin/env python3
"""Execute one exact Tueiq manifest using a fixed, non-shell action vocabulary."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.lil_tweak.github_runner import GitHubRunnerError, RunnerManifest


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def git(workspace: Path, *args: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(workspace), *args),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if result.returncode != 0 or len(result.stdout.encode()) + len(result.stderr.encode()) > 128_000:
        raise GitHubRunnerError("runner git operation failed")
    return result.stdout.rstrip("\r\n")


def source_identity(workspace: Path) -> tuple[str, str]:
    return git(workspace, "rev-parse", "HEAD"), git(workspace, "rev-parse", "HEAD^{tree}")


def changed_paths(workspace: Path) -> tuple[str, ...]:
    output = git(workspace, "status", "--porcelain=v1", "--untracked-files=all")
    paths = []
    for line in output.splitlines():
        path = line[3:]
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        paths.append(path)
    return tuple(sorted(paths))


def run_action(action: str, workspace: Path, manifest: RunnerManifest) -> int:
    try:
        return _run_action(action, workspace, manifest)
    except subprocess.SubprocessError:
        return 70


def _run_action(action: str, workspace: Path, manifest: RunnerManifest) -> int:
    if action == "inspect_source":
        commit, tree = source_identity(workspace)
        return 0 if (commit, tree) == (manifest.source_commit, manifest.source_tree) else 70
    if action == "apply_patch":
        completed = subprocess.run(
            ("git", "-C", str(workspace), "apply", "--whitespace=nowarn", "-"),
            input=manifest.patch,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return completed.returncode
    if action == "compile_python":
        try:
            for path in workspace.rglob("*.py"):
                if ".git" not in path.parts:
                    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            return 0
        except (OSError, UnicodeError, SyntaxError):
            return 1
    if action == "npm_verify":
        environment = {
            **os.environ,
            "OPENAI_API_KEY": "",
            "LIL_TWEAK_LIVE_MODEL_ENABLED": "false",
            "GIT_TERMINAL_PROMPT": "0",
        }
        for command in (("npm", "ci"), ("npm", "run", "verify")):
            completed = subprocess.run(
                command,
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=1200,
                env=environment,
            )
            if completed.returncode != 0:
                return completed.returncode
        return 0
    if action == "git_diff":
        changed = set(changed_paths(workspace))
        return 0 if changed == set(manifest.authorized_paths) else 70
    return 70


def execute(manifest: RunnerManifest, workspace: Path) -> dict:
    if os.environ.get("GITHUB_REPOSITORY") != manifest.repository:
        raise GitHubRunnerError("runner repository binding failed")
    if datetime.now(UTC) >= datetime.fromisoformat(manifest.expires_at.replace("Z", "+00:00")):
        raise GitHubRunnerError("runner manifest expired")
    if source_identity(workspace) != (manifest.source_commit, manifest.source_tree):
        raise GitHubRunnerError("runner source binding failed")

    steps = []
    outcome = "succeeded"
    for action in manifest.actions:
        exit_code = run_action(action, workspace, manifest)
        steps.append({"action": action, "exitCode": exit_code})
        if exit_code != 0:
            outcome = "failed"
            break
    changed = changed_paths(workspace)
    receipt = {
        "schemaVersion": "lil-tweak-github-runner-receipt-v1",
        "executionId": manifest.execution_id,
        "repository": manifest.repository,
        "sourceCommit": manifest.source_commit,
        "sourceTree": manifest.source_tree,
        "manifestDigest": manifest.manifest_digest,
        "authorityDigest": manifest.authority_digest,
        "outcome": outcome,
        "workspaceChanged": bool(changed),
        "changedPaths": list(changed),
        "steps": steps,
    }
    receipt["receiptDigest"] = hashlib.sha256(canonical(receipt)).hexdigest()
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        raw = args.manifest.read_bytes()
        if len(raw) > 45_000:
            raise GitHubRunnerError("runner manifest too large")
        value = json.loads(raw.decode("utf-8", "strict"))
        if not isinstance(value, dict):
            raise GitHubRunnerError("invalid runner manifest")
        manifest = RunnerManifest.parse(value)
        receipt = execute(manifest, args.workspace.resolve(strict=True))
        args.output.mkdir(mode=0o700)
        (args.output / "runner-receipt.json").write_bytes(canonical(receipt) + b"\n")
        print(json.dumps({
            "executionId": manifest.execution_id,
            "outcome": receipt["outcome"],
            "receiptDigest": receipt["receiptDigest"],
        }, separators=(",", ":")))
        return 0 if receipt["outcome"] == "succeeded" else 1
    except (
        GitHubRunnerError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ):
        print("Tueiq GitHub runner failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
