from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

APP_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(APP_ROOT))

from liltweak.creator_contract import (  # noqa: E402
    CommandKind,
    SandboxCommand,
    content_digest,
)
from liltweak.execution_contract import (  # noqa: E402
    ExecutionRecipe,
    ProcessObservation,
    RepositoryExecutionPlan,
    RunnerAttestation,
    SandboxExecutionEvidence,
    SandboxProfile,
    SourceSnapshotManifest,
)
from liltweak.execution_plane import RepositoryVerificationGate  # noqa: E402

IMAGE = "registry.invalid/liltweak-python@sha256:" + ("d" * 64)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def fixture() -> tuple[RepositoryExecutionPlan, SandboxProfile]:
    recipe = ExecutionRecipe(
        recipe_id="python-verify",
        image_ref=IMAGE,
        commands=(
            SandboxCommand(
                command_id="lint",
                kind=CommandKind.LINT,
                argv=("ruff", "check", "."),
                timeout_seconds=60,
            ),
            SandboxCommand(
                command_id="tests",
                kind=CommandKind.TEST,
                argv=("pytest", "-q"),
                timeout_seconds=60,
            ),
        ),
    )
    source = SourceSnapshotManifest(
        provider="local",
        repository_id="fixture",
        resolved_revision="a" * 40,
        repository_fingerprint=digest("repository"),
        tree_digest=digest("tree"),
        archive_digest=digest("archive"),
        file_count=4,
        total_bytes=512,
    )
    profile = SandboxProfile(
        runtime_sha256=digest("bubblewrap"),
        limiter_sha256=digest("prlimit"),
        image_ref=IMAGE,
        container_user=recipe.container_user,
    )
    created_at = datetime(2026, 7, 29, tzinfo=UTC)
    values = {
        "id": "repo_exec_offline",
        "job_id": "job_offline",
        "organization_id": "org_offline",
        "project_id": "project_offline",
        "brief_digest": digest("brief"),
        "route_digest": digest("route"),
        "recipe_id": recipe.recipe_id,
        "recipe_digest": recipe.recipe_digest,
        "source": source,
        "sandbox_profile_digest": profile.profile_digest,
        "workspace_mount_digest": content_digest(
            {
                "source_manifest_digest": source.manifest_digest,
                "sandbox_profile_digest": profile.profile_digest,
                "recipe_digest": recipe.recipe_digest,
            }
        ),
        "image_ref": recipe.image_ref,
        "commands": recipe.commands,
        "wall_clock_seconds": recipe.wall_clock_seconds,
        "memory_megabytes": recipe.memory_megabytes,
        "cpu_count": recipe.cpu_count,
        "pid_limit": recipe.pid_limit,
        "file_size_limit_bytes": recipe.file_size_limit_bytes,
        "output_byte_limit": recipe.output_byte_limit,
        "created_at": created_at,
        "expires_at": created_at + timedelta(minutes=15),
        "attempt_nonce": digest("attempt"),
    }
    unsigned = RepositoryExecutionPlan.model_construct(
        **values,
        plan_digest="0" * 64,
    )
    plan = RepositoryExecutionPlan(
        **values,
        plan_digest=content_digest(unsigned.model_dump(mode="json", exclude={"plan_digest"})),
    )
    return plan, profile


def evidence_for(
    plan: RepositoryExecutionPlan,
    profile: SandboxProfile,
    *,
    source_tampered: bool = False,
    order_tampered: bool = False,
) -> SandboxExecutionEvidence:
    observations = [
        ProcessObservation(
            command_id=command.command_id,
            exit_code=0,
            stdout_digest=digest(f"stdout:{command.command_id}"),
            stderr_digest=digest(""),
            stdout_bytes=32,
            stderr_bytes=0,
            duration_ms=10,
        )
        for command in plan.commands
    ]
    if order_tampered:
        observations.reverse()
    return SandboxExecutionEvidence(
        plan_digest=plan.plan_digest,
        session_id="offline-sandbox",
        source_before_digest=plan.source.tree_digest,
        source_after_digest=(
            digest("tampered-tree") if source_tampered else plan.source.tree_digest
        ),
        observations=tuple(observations),
        attestation=RunnerAttestation(
            attempt_nonce=plan.attempt_nonce,
            runtime_sha256=profile.runtime_sha256,
            limiter_sha256=profile.limiter_sha256,
            sandbox_profile_digest=profile.profile_digest,
            image_ref=profile.image_ref,
            cleanup_verified=True,
        ),
    )


def main() -> int:
    plan, profile = fixture()
    gate = RepositoryVerificationGate()
    accepted = 0
    rejected = 0
    cases = []
    for index in range(120):
        source_tampered = 80 <= index < 100
        order_tampered = index >= 100
        result = gate.verify(
            plan=plan,
            evidence=evidence_for(
                plan,
                profile,
                source_tampered=source_tampered,
                order_tampered=order_tampered,
            ),
            profile=profile,
            canceled=False,
            emergency_stopped=False,
        )
        expected = index < 80
        matched = result.verified is expected
        accepted += int(result.verified)
        rejected += int(not result.verified)
        cases.append(
            {
                "case": index + 1,
                "expected_verified": expected,
                "observed_verified": result.verified,
                "matched": matched,
            }
        )
    summary = {
        "phase": 7,
        "cases": len(cases),
        "accepted": accepted,
        "rejected": rejected,
        "all_matched": all(item["matched"] for item in cases),
        "provider_calls": 0,
        "paid_calls": 0,
        "executions": 0,
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["all_matched"] and accepted == 80 and rejected == 40 else 1


if __name__ == "__main__":
    raise SystemExit(main())
