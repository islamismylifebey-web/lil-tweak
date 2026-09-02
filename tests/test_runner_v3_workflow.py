from __future__ import annotations

import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from liltweak.providers.github.runner_v3_contracts import (
    RUNNER_V3_PROFILE_ID,
    RunnerV3Action,
    RunnerV3WorkspaceMode,
)
from scripts.runner_v3_smoke_manifest import build_smoke_manifest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "runner-v3.yml"
WORKFLOW_TEXT = WORKFLOW_PATH.read_text(encoding="utf-8")


def _workflow() -> dict[str | bool, Any]:
    value = yaml.safe_load(WORKFLOW_TEXT)
    assert isinstance(value, dict)
    return value


def _events(workflow: dict[str | bool, Any]) -> dict[str, Any]:
    value = workflow.get("on", workflow.get(True))
    assert isinstance(value, dict)
    return value


def _steps(workflow: dict[str | bool, Any]) -> list[dict[str, Any]]:
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    job = jobs["runner-v3"]
    assert isinstance(job, dict)
    value = job["steps"]
    assert isinstance(value, list)
    return value


def _step_by_name(steps: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next(step for step in steps if step.get("name") == name)


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(repository), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def test_runner_v3_workflow_is_read_only_and_headless() -> None:
    workflow = _workflow()
    events = _events(workflow)
    jobs = workflow["jobs"]
    job = jobs["runner-v3"]

    assert workflow["name"] == "Runner V3 GitHub-first worker"
    assert workflow["permissions"] == {"contents": "read"}
    assert set(events) == {"pull_request", "workflow_dispatch"}
    assert events["pull_request"]["branches"] == ["main"]
    inputs = events["workflow_dispatch"]["inputs"]
    assert set(inputs) == {
        "expected_commit",
        "manifest_base64",
        "manifest_digest",
        "acknowledge_builder_only",
    }
    assert inputs["acknowledge_builder_only"]["type"] == "boolean"
    assert inputs["acknowledge_builder_only"]["required"] is True
    assert inputs["acknowledge_builder_only"]["default"] is False
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] == 30
    assert "permissions" not in job
    assert job["env"]["RUNNER_V3_PROFILE_ID"] == RUNNER_V3_PROFILE_ID
    assert job["env"]["RUNNER_V3_OUTPUT_DIR"] == (
        "${{ runner.temp }}/runner-v3-output"
    )
    assert job["env"]["RUNNER_V3_MANIFEST_PATH"] == (
        "${{ runner.temp }}/runner-v3-manifest.json"
    )
    assert job["env"]["OPENAI_API_KEY"] == ""
    assert job["env"]["LILTWEAK_LIVE_MODEL_ENABLED"] == "false"
    assert job["env"]["LILTWEAK_REPOSITORY_EXECUTION_ENABLED"] == "false"


def test_runner_v3_workflow_pins_checkout_toolchain_and_artifacts() -> None:
    workflow = _workflow()
    steps = _steps(workflow)
    checkout = _step_by_name(steps, "Checkout exact Runner V3 source")
    setup_python = _step_by_name(steps, "Set up Python")
    setup_uv = _step_by_name(steps, "Set up uv")
    upload = _step_by_name(steps, "Upload bounded Runner V3 evidence")
    cleanup = _step_by_name(steps, "Remove ephemeral Runner V3 material")

    assert checkout["uses"] == (
        "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
    )
    assert checkout["with"]["persist-credentials"] is False
    assert checkout["with"]["fetch-depth"] == 1
    assert checkout["with"]["clean"] is True
    assert checkout["with"]["lfs"] is False
    assert checkout["with"]["submodules"] is False
    assert "expected_commit" in checkout["with"]["ref"]
    assert "pull_request.head.sha" in checkout["with"]["ref"]
    assert setup_python["uses"] == (
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
    )
    assert setup_python["with"]["python-version"] == "3.12.13"
    assert setup_uv["uses"] == (
        "astral-sh/setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9"
    )
    assert setup_uv["with"]["version"] == "0.11.33"
    assert setup_uv["with"]["enable-cache"] is False
    assert upload["uses"] == (
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    )
    assert upload["with"]["if-no-files-found"] == "error"
    assert upload["with"]["retention-days"] == 1
    assert upload["with"]["include-hidden-files"] is False
    assert upload["with"]["path"] == "${{ env.RUNNER_V3_OUTPUT_DIR }}"
    assert cleanup["if"] == "always()"
    for step in steps:
        action = step.get("uses")
        if action is not None:
            assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action)


def test_runner_v3_workflow_has_no_external_or_write_control_plane() -> None:
    lowered = WORKFLOW_TEXT.casefold()

    for forbidden in (
        "contents: write",
        "cloudflare",
        "vercel",
        "digitalocean",
        "wrangler",
        "docker",
        "sudo ",
        "ssh ",
        "git push",
        "gh pr",
        "merge_pull_request",
        "deployment",
        "deploy ",
        "curl ",
        "wget ",
        "${{ secrets.",
    ):
        assert forbidden not in lowered
    assert "python scripts/runner_v3_smoke_manifest.py" in WORKFLOW_TEXT
    assert "python scripts/runner_v3.py" in WORKFLOW_TEXT
    assert "uv lock --check --offline" in WORKFLOW_TEXT
    assert "uv sync --locked --group dev --python 3.12.13" in WORKFLOW_TEXT
    assert "base64.b64decode" in WORKFLOW_TEXT
    assert "validate=True" in WORKFLOW_TEXT
    assert "60_000" in WORKFLOW_TEXT
    assert "manifest_digest" in WORKFLOW_TEXT
    assert "acknowledge_builder_only" in WORKFLOW_TEXT
    run_blocks = "\n".join(
        str(step.get("run", "")) for step in _steps(_workflow())
    )
    assert "${{ inputs.manifest_base64 }}" not in run_blocks
    assert "${{ inputs.manifest_digest }}" not in run_blocks


def test_smoke_manifest_binds_exact_checkout_without_patch(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "liltweak").mkdir()
    (repository / "liltweak" / "__init__.py").write_text("", encoding="utf-8")
    (repository / "scripts").mkdir()
    (repository / "scripts" / "tool.py").write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(("git", "-C", str(repository), "init", "-b", "main"), check=True)
    subprocess.run(
        ("git", "-C", str(repository), "config", "user.name", "Runner V3 Test"),
        check=True,
    )
    subprocess.run(
        (
            "git",
            "-C",
            str(repository),
            "config",
            "user.email",
            "runner-v3-test@invalid",
        ),
        check=True,
    )
    subprocess.run(("git", "-C", str(repository), "add", "."), check=True)
    subprocess.run(
        ("git", "-C", str(repository), "commit", "-m", "fixture"),
        check=True,
    )
    now = datetime(2026, 9, 2, 18, 30, tzinfo=UTC)

    manifest = build_smoke_manifest(repository, now=now)

    assert manifest.runner_profile_id == RUNNER_V3_PROFILE_ID
    assert manifest.source_commit == _git(repository, "rev-parse", "HEAD")
    assert manifest.source_tree == _git(repository, "rev-parse", "HEAD^{tree}")
    assert manifest.workspace_mode is RunnerV3WorkspaceMode.READ_ONLY
    assert manifest.source_write_authorized is False
    assert manifest.patch is None
    assert manifest.actions == (
        RunnerV3Action.INSPECT_SOURCE,
        RunnerV3Action.COMPILE_PYTHON,
        RunnerV3Action.GIT_DIFF,
    )
    assert manifest.issued_at == now
    assert manifest.expires_at > now
    assert (manifest.expires_at - manifest.issued_at).total_seconds() <= 1_800
    assert len(manifest.manifest_digest) == 64
