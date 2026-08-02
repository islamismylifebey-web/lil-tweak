from __future__ import annotations

import re
import tomllib
from pathlib import Path

from fastapi.testclient import TestClient

from liltweak.api import create_app
from liltweak.config import Settings
from liltweak.store import SQLiteStore

ROOT = Path(__file__).parents[1]
FULL_SHA = re.compile(r"^[a-z0-9-]+/[a-z0-9-]+@[0-9a-f]{40}(?:\s+#.*)?$")


def workflow_job(workflow: str, job_id: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_id)}:\n.*?(?=^  [a-z0-9][a-z0-9-]*:\n|\Z)",
        workflow,
    )
    assert match is not None, f"workflow job {job_id!r} is missing"
    return match.group(0)


def workflow_run_blocks(workflow: str) -> tuple[str, ...]:
    lines = workflow.splitlines()
    blocks: list[str] = []
    for index, line in enumerate(lines):
        if line.lstrip() not in {"run: |", "run: |-", "run: |+"}:
            continue
        indentation = len(line) - len(line.lstrip())
        body: list[str] = []
        for candidate in lines[index + 1 :]:
            candidate_indentation = len(candidate) - len(candidate.lstrip())
            if candidate.strip() and candidate_indentation <= indentation:
                break
            body.append(candidate)
        blocks.append("\n".join(body))
    return tuple(blocks)


def test_phase71_release_versions_are_consistent() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    lock = (ROOT / "uv.lock").read_text(encoding="utf-8")
    creator_contract = (ROOT / "liltweak" / "creator_contract.py").read_text(encoding="utf-8")
    creator = (ROOT / "liltweak" / "creator.py").read_text(encoding="utf-8")
    api = (ROOT / "liltweak" / "api.py").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    execution_manifest = (ROOT / "EXECUTION-MANIFEST.md").read_text(encoding="utf-8")

    assert 'version = "0.7.1"' in pyproject
    assert 'name = "lil-tweak-engine"\nversion = "0.7.1"' in lock
    assert 'version: Literal["0.7.1"] = "0.7.1"' in creator_contract
    assert '"version": "0.7.1"' in creator
    assert 'version="0.7.1"' in api
    assert readme.startswith(
        "# Lil Tweak Automatic Verification and Dormant Runner Qualification — 0.7.1\n"
    )
    assert changelog.startswith(
        "# Changelog\n\n## 0.8.0 — Live Workbench and Bounded Execution Bridge\n"
    )
    assert "## 0.7.1 — Automatic Verification and Dormant Runner Qualification\n" in changelog
    assert execution_manifest.startswith(
        "# Lil Tweak Automatic Verification and Dormant Runner Qualification 0.7.1\n"
    )
    assert "`ARCHITECTURE IMPLEMENTED AND TESTED — NOT OPERATIONAL`." in readme


def test_distribution_declares_complete_runtime_payload_and_locked_build_tools() -> None:
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    setuptools = configuration["tool"]["setuptools"]
    discovery = setuptools["packages"]["find"]
    package_data = setuptools["package-data"]
    dev_dependencies = set(configuration["dependency-groups"]["dev"])

    assert set(discovery["include"]) == {"docs*", "liltweak*", "migrations*", "web*"}
    assert set(discovery["exclude"]) == {"evals*", "scripts*", "tests*"}
    assert set(package_data["docs"]) == {
        "creator-live-prompt.md",
        "engineering-prompt.md",
        "prompt.md",
        "workbench-agent-prompt.md",
    }
    assert package_data["migrations"] == ["*.sql"]
    assert set(package_data["web.workbench"]) == {"*.css", "*.html", "*.js"}
    assert {"setuptools==82.0.1", "wheel==0.47.0"} <= dev_dependencies


def test_phase71_preserves_schema_v2() -> None:
    assert SQLiteStore.SCHEMA_VERSION == 2


def test_phase71_preserves_all_phase7_http_operations(tmp_path: Path) -> None:
    settings = Settings(
        environment="test",
        database_path=Path(":memory:"),
        dev_api_key=None,
        auth_disabled=True,
        model="test-model",
        monthly_budget_usd=250,
        job_hard_limit_usd=5,
        workspace_root=tmp_path / "workspace",
        artifact_root=tmp_path / "artifacts",
    )
    app = create_app(settings=settings)
    operations = {
        (path, method)
        for path, item in app.openapi()["paths"].items()
        for method in item
        if method in {"get", "post", "put", "patch", "delete"}
    }
    expected_phase7 = {
        ("/v1/creator/executions", "post"),
        ("/v1/creator/executions/{execution_id}", "get"),
        ("/v1/creator/executions/{execution_id}/decision", "post"),
        ("/v1/creator/executions/{execution_id}/run", "post"),
        ("/v1/creator/executions/{execution_id}/result", "get"),
    }
    assert expected_phase7 <= operations
    assert len(operations) == 31

    with TestClient(app) as client:
        health = client.get("/v1/creator/health")
    assert health.status_code == 200
    assert health.json()["version"] == "0.7.1"
    assert health.json()["execution_connected"] is False
    assert health.json()["source_execution_connected"] is False


def test_standard_ci_is_read_only_secretless_and_offline() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "pull_request_target" not in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "secrets." not in workflow
    assert 'OPENAI_API_KEY: ""' in workflow
    assert 'LILTWEAK_LIVE_MODEL_ENABLED: "false"' in workflow
    assert 'LILTWEAK_REPOSITORY_EXECUTION_ENABLED: "false"' in workflow
    assert 'SOURCE_DATE_EPOCH: "1735689600"' in workflow
    assert 'version: "0.11.33"' in workflow
    assert 'test "$(uv --version)" = "uv 0.11.33"' in workflow
    assert "--live" not in workflow
    assert "run_phase6_live.py" not in workflow
    assert "run_phase7_snapshot_benchmark.py" not in workflow
    assert "persist-credentials: false" in workflow
    assert "uv lock --check --offline" in workflow
    assert "uv run --no-sync --offline pytest" in workflow
    for required_path in (
        "docs/creator-live-prompt.md",
        "docs/engineering-prompt.md",
        "docs/prompt.md",
        "docs/workbench-agent-prompt.md",
        "migrations/0008_workbench.sql",
        "migrations/0009_canonical_control_plane.sql",
        "migrations/0010_workbench_canonical_authority.sql",
        "web/workbench/app.js",
        "web/workbench/index.html",
        "web/workbench/styles.css",
    ):
        assert f'"{required_path}"' in workflow
    assert 'name.startswith(("evals/", "scripts/", "tests/"))' in workflow
    assert '"migrations/", "scripts/"' not in workflow
    assert 'PYTHONPATH="$RUNNER_TEMP/wheel-target"' in workflow
    assert 'WorkbenchStore(database, signing_key=b"w" * 32)' in workflow
    assert '--wheel-artifact "$wheel_artifact"' in workflow
    assert '--sdist-artifact "$sdist_artifact"' in workflow
    assert "git diff --exit-code" in workflow
    uses = [
        line.strip().removeprefix("uses: ")
        for line in workflow.splitlines()
        if line.strip().startswith("uses:")
    ]
    assert uses
    assert all(FULL_SHA.fullmatch(item) for item in uses)


def test_qualification_workflow_is_manual_main_only_bounded_and_dormant() -> None:
    workflow = (ROOT / ".github" / "workflows" / "runner-qualification.yml").read_text(
        encoding="utf-8"
    )
    issue_job = workflow_job(workflow, "validate-and-issue")
    collect_job = workflow_job(workflow, "collect-candidate-evidence")
    verify_job = workflow_job(workflow, "verify-candidate-evidence")

    assert "pull_request:" not in workflow
    assert "push:" not in workflow
    assert "workflow_dispatch:" in workflow
    assert "refs/heads/main" in issue_job
    assert "runs-on: ubuntu-24.04" in issue_job
    assert "runs-on: ubuntu-24.04" in verify_job
    assert "environment: liltweak-runner-qualification" in issue_job
    assert "environment: liltweak-runner-qualification" in verify_job
    assert "actions/checkout@" in issue_job
    assert "actions/checkout@" in verify_job
    assert "ref: ${{ github.sha }}" in issue_job
    assert "ref: ${{ github.sha }}" in verify_job

    assert "needs: validate-and-issue" in collect_job
    assert "environment: liltweak-runner-qualification" in collect_job
    assert "permissions: {}" in collect_job
    assert "contents: read" not in collect_job
    assert "runs-on: [self-hosted, linux, x64, liltweak-qualification, ephemeral]" in collect_job
    assert "actions/checkout@" not in collect_job
    assert "scripts/" not in collect_job
    assert "python" not in collect_job.lower()
    assert "uv run" not in collect_job
    assert "needs: [validate-and-issue, collect-candidate-evidence]" in verify_job
    assert "python -m scripts.verify_runner_qualification verify" in verify_job
    assert "scripts.verify_runner_qualification verify" not in collect_job

    assert "timeout-minutes: 30" in workflow
    assert "permissions:\n  contents: read" in workflow
    assert 'LILTWEAK_REPOSITORY_EXECUTION_ENABLED: "false"' in workflow
    assert '"connection_authorized": (false|False)' in workflow
    assert "persist-credentials: false" in workflow
    assert "${{ vars." not in "\n".join(workflow_run_blocks(workflow))

    assert "/opt/liltweak-qualification/bin/collect" in collect_job
    assert "/opt/liltweak-qualification/bin/destroy" in collect_job
    assert "--issuer-public-key" in collect_job
    assert "liltweak-qualification-issuer.json" in collect_job
    assert "QUALIFIER_SHA256" in collect_job
    assert "DESTROYER_SHA256" in collect_job
    assert "root:root:555" in collect_job
    assert 'test "$(id -u)" -ne 0' in collect_job
    assert "sha256sum" in collect_job

    assert "if: ${{ always() }}" in collect_job
    cleanup = collect_job.rsplit("if: ${{ always() }}", maxsplit=1)[1]
    assert "DESTROYER_SHA256" in cleanup
    assert "root:root:555" in cleanup
    assert "sha256sum" in cleanup
    destroy_invocation = cleanup.rindex('"$destroyer"')
    assert cleanup.index("sha256sum") < destroy_invocation
    assert destroy_invocation < cleanup.index("Upload signed evidence after cleanup")

    assert "actions/upload-artifact@" in workflow
    assert "actions/download-artifact@" in workflow
    assert "actions/upload-artifact@" in issue_job
    assert "actions/upload-artifact@" in collect_job
    assert "actions/download-artifact@" in collect_job
    assert "actions/download-artifact@" in verify_job
    assert "--issuer-public-key-file" in verify_job
    assert "--runner-public-key-b64" in verify_job
    uses = [
        line.strip().removeprefix("uses: ")
        for line in workflow.splitlines()
        if line.strip().startswith("uses:")
    ]
    assert uses
    assert all(FULL_SHA.fullmatch(item) for item in uses)

    assert workflow.index("  collect-candidate-evidence:") < workflow.index(
        "  verify-candidate-evidence:"
    )
    assert "execution_connected=true" not in workflow
    assert "secrets." not in workflow
