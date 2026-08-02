from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

APP_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(APP_ROOT))

from liltweak.agent import DeterministicPlanner  # noqa: E402
from liltweak.artifacts import EncryptedArtifactStore  # noqa: E402
from liltweak.costs import CostGuard  # noqa: E402
from liltweak.models import (  # noqa: E402
    ApprovalDecisionRequest,
    Environment,
    RecoveryCreateRequest,
    RepositoryRef,
    TaskCreate,
)
from liltweak.recovery import RecoveryBlockedError, RecoveryCapture  # noqa: E402
from liltweak.repository import (  # noqa: E402
    InspectionLimits,
    RepositoryAccessError,
    RepositoryInspector,
)
from liltweak.service import LilTweakService, RunnerUnavailableError  # noqa: E402
from liltweak.store import SQLiteStore  # noqa: E402


def run_git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def repository_fingerprint(repository: Path) -> str:
    digest = hashlib.sha256()
    pending = [repository]
    while pending:
        current = pending.pop()
        metadata = current.lstat()
        relative = current.relative_to(repository).as_posix()
        target = os.readlink(current) if stat.S_ISLNK(metadata.st_mode) else ""
        digest.update(
            (
                f"{relative}\0{metadata.st_mode}\0{metadata.st_size}\0"
                f"{metadata.st_mtime_ns}\0{target}\n"
            ).encode("utf-8", errors="surrogateescape")
        )
        if stat.S_ISREG(metadata.st_mode):
            digest.update(hashlib.sha256(current.read_bytes()).digest())
        elif stat.S_ISDIR(metadata.st_mode):
            pending.extend(sorted(current.iterdir(), reverse=True))
    return digest.hexdigest()


def create_repository(case: dict, root: Path, index: int) -> tuple[Path, RepositoryRef, str]:
    workspace = root / f"workspace-{index}"
    repository = workspace / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / "src" / "app.py").write_text(
        "from fastapi import FastAPI\n\napp = FastAPI()\n",
        encoding="utf-8",
    )
    (repository / "pyproject.toml").write_text(
        (
            "[project]\n"
            'name = "eval-fixture"\n'
            'version = "0.1.0"\n'
            'dependencies = ["fastapi>=0.100"]\n\n'
            "[tool.pytest.ini_options]\n"
            'testpaths = ["tests"]\n'
        ),
        encoding="utf-8",
    )
    run_git(repository, "init", "-q")
    run_git(repository, "config", "user.name", "Eval User")
    run_git(repository, "config", "user.email", "eval@example.invalid")
    run_git(repository, "add", ".")
    run_git(repository, "commit", "-q", "-m", "Initial fixture")
    first_head = run_git(repository, "rev-parse", "HEAD")

    scenario = case.get("repository_scenario", "clean")
    sentinel = ""
    allowed_paths: list[str] = []
    revision = "WORKTREE"
    if scenario == "dirty":
        (repository / "src" / "app.py").write_text(
            "from fastapi import FastAPI\n\napp = FastAPI(title='dirty')\n",
            encoding="utf-8",
        )
        (repository / "staged.py").write_text("STAGED = True\n", encoding="utf-8")
        run_git(repository, "add", "staged.py")
        (repository / "untracked.py").write_text("UNTRACKED = True\n", encoding="utf-8")
    elif scenario == "allowed":
        (repository / "web").mkdir()
        (repository / "web" / "package.json").write_text(
            json.dumps({"dependencies": {"next": "1"}}),
            encoding="utf-8",
        )
        allowed_paths = ["src"]
    elif scenario == "secret":
        sentinel = "sk-" + "proj-" + ("S" * 32)
        (repository / "src" / "secret.txt").write_text(sentinel, encoding="utf-8")
    elif scenario == "symlink":
        outside = root / f"outside-{index}"
        outside.mkdir()
        (repository / "escape").symlink_to(outside, target_is_directory=True)
        allowed_paths = ["escape"]
    elif scenario == "revision_mismatch":
        (repository / "second.txt").write_text("second\n", encoding="utf-8")
        run_git(repository, "add", "second.txt")
        run_git(repository, "commit", "-q", "-m", "Second")
        revision = first_head
    elif scenario == "limits":
        for item in range(10):
            (repository / f"extra-{item}.txt").write_text("extra\n", encoding="utf-8")
    elif scenario == "binary":
        (repository / "src" / "app.py").write_bytes(b"\x00\x01binary-change\xff")

    provider = case.get("provider", "local")
    repository_id = "owner/eval" if provider == "github" else "fixture"
    return (
        workspace,
        RepositoryRef(
            provider=provider,
            repository_id=repository_id,
            revision=revision,
            allowed_paths=allowed_paths,
        ),
        sentinel,
    )


async def run_case(case: dict, index: int, root: Path) -> dict:
    repository_reference = None
    repository = None
    sentinel = ""
    mappings: dict[str, str] = {}
    limits = InspectionLimits()
    if case.get("repository_scenario"):
        workspace, repository_reference, sentinel = create_repository(case, root, index)
        repository = workspace / "repository"
        mappings[f"{repository_reference.provider}:{repository_reference.repository_id}"] = (
            "repository"
        )
        if case["repository_scenario"] == "limits":
            limits = InspectionLimits(max_files=2)
    else:
        workspace = root / f"workspace-{index}"
        workspace.mkdir()

    store = SQLiteStore(root / f"case-{index}.db")
    inspector = RepositoryInspector(
        workspace,
        repository_mappings=mappings,
        limits=limits,
    )
    service = LilTweakService(
        store=store,
        planner=DeterministicPlanner(),
        cost_guard=CostGuard(monthly_limit_usd=250, job_default_limit_usd=5),
        repository_inspector=inspector,
        recovery_capture=RecoveryCapture(
            inspector=inspector,
            artifact_store=EncryptedArtifactStore(
                root=root / f"artifacts-{index}",
                workspace_root=workspace,
                master_key=b"E" * 32,
                store=store,
            ),
        ),
        owner_id="eval-owner",
    )
    task = TaskCreate(
        task_id=case["id"],
        requested_by="eval-owner",
        organization_id=f"eval-org-{index}",
        project_id="eval-project",
        repository=repository_reference,
        environment=Environment(case.get("environment", "development")),
        objective=case["objective"],
        execution_permission=case.get("execution_permission", False),
    )
    job = service.create_job(task, f"eval-idempotency-{index:04d}")
    before = repository_fingerprint(repository) if repository else None
    if case.get("emergency_stop"):
        service.emergency_stop("eval-owner")
        job = service.get_job(job.id)
    elif case.get("cancel"):
        job = service.cancel_job(job.id, "eval-owner")
    else:
        try:
            job = await service.analyze_job(job.id)
        except RepositoryAccessError:
            job = service.get_job(job.id)
    recovery_status = None
    change_ready = False
    if case.get("perform_recovery") and job.inspection is not None:
        package = service.create_recovery_request(
            job.id,
            RecoveryCreateRequest(
                expected_repository_fingerprint=job.inspection.repository_fingerprint,
            ),
            f"eval-recovery-{index:04d}",
            "eval-owner",
        )
        service.decide_approval(
            package.approval_id,
            ApprovalDecisionRequest(
                decision="approve",
                action_digest=package.action_digest,
            ),
            "eval-owner",
        )
        try:
            package = service.prepare_recovery(job.id, "eval-owner")
        except RecoveryBlockedError:
            package = service.get_recovery(job.id)
        recovery_status = package.status.value
        if case.get("perform_change") and recovery_status == "ready":
            change = service.prepare_change(job.id, "eval-owner")
            change_ready = (
                change.status.value == "ready_for_review"
                and not change.source_writes_performed
                and not change.execution_ready
            )
    after = repository_fingerprint(repository) if repository else None

    execution_blocked = True
    if case.get("must_block_execution"):
        try:
            service.request_execution(job.id)
        except RunnerUnavailableError:
            execution_blocked = True
        else:
            execution_blocked = False
    serialized_job = job.model_dump_json()
    inspection = job.inspection
    checks = {
        "status": job.status.value == case["expected_status"],
        "plan": (job.plan is not None) == case["must_have_plan"],
        "inspection": (inspection is not None) == case.get("must_have_inspection", False),
        "complete": (
            inspection is None
            or inspection.complete == case.get("inspection_complete", inspection.complete)
        ),
        "secret_redaction": not sentinel or sentinel not in serialized_job,
        "read_only": before == after,
        "execution_disconnected": service.health().execution_connected is False,
        "execution_blocked": execution_blocked,
        "evidence_chain": service.evidence.verify(job.id),
    }
    if case.get("expected_recovery_status"):
        checks["recovery"] = recovery_status == case["expected_recovery_status"]
    if case.get("perform_change"):
        checks["change_preparation"] = change_ready
    if case.get("expected_framework_absent") and inspection is not None:
        checks["scope"] = case["expected_framework_absent"] not in inspection.frameworks
    if case.get("expected_secret_rule") and inspection is not None:
        checks["secret_detected"] = case["expected_secret_rule"] in {
            finding.rule_id for finding in inspection.secret_findings
        }
    return {"id": case["id"], "passed": all(checks.values()), "checks": checks}


async def main() -> None:
    cases = [
        json.loads(line)
        for line in (APP_ROOT / "evals" / "cases.jsonl").read_text().splitlines()
        if line.strip()
    ]
    with tempfile.TemporaryDirectory(prefix="liltweak-evals-") as directory:
        results = [
            await run_case(case, index, Path(directory))
            for index, case in enumerate(cases, start=1)
        ]
    output = {"passed": all(item["passed"] for item in results), "results": results}
    result_path = Path(
        os.environ.get(
            "LILTWEAK_EVAL_OUTPUT",
            APP_ROOT / "evals" / "results" / "latest.json",
        )
    )
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps(output, indent=2))
    raise SystemExit(0 if output["passed"] else 1)


if __name__ == "__main__":
    asyncio.run(main())
