from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import re
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPOSITORY_ID = "github:islamismylifebey-web/lil-tweak"
RUNNER_ID = "galor-tweak-runner-01"
RUNNER_ROLE = "role-tweak-runner"
REMOTE_CANDIDATE_ROOT = "/var/lib/liltweak-runner/candidates"
JOB_B_ARTIFACT_PATH = "docs/runner-qualification/galor-tweak-runner-01.md"
JOB_B_ARTIFACT_SHA256 = "62253a2945ea498f3b206a0449e5a97a0cf5783dd7858d7a11fbb365f4c04a91"
GITHUB_REPOSITORY = "islamismylifebey-web/lil-tweak"
GITHUB_PR_NUMBER = 12
GITHUB_PR_BRANCH = "feature/tweak-private-runner-control-plane-20260901"
GITHUB_CI_WORKFLOW = ".github/workflows/ci.yml"
GITHUB_CI_WORKFLOW_NAME = "Lil Tweak Master Builder deterministic verification"
GITHUB_CI_JOB_NAME = "Deterministic gates after locked dependency bootstrap"
GITHUB_CI_REQUIRED_CHECKS = frozenset(
    {
        "Checkout exact revision",
        "Verify toolchain, lock, and frozen environment",
        "Lint and format",
        "Static type check",
        "Tests",
        "Deterministic offline evaluations and smoke paths",
        "Preserve generated supply-chain evidence",
        "Validate deterministic evidence",
        "Source tree remained unchanged",
    }
)
_EXECUTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_QUALIFICATION_BRANCH = re.compile(r"^qualification/galor-tweak-runner-01/[a-z0-9][a-z0-9-]{0,31}$")


REMOTE_POLL_SCRIPT = r"""
import base64
import hashlib
import json
import secrets
import time
from datetime import UTC, datetime

import httpx
from cryptography.hazmat.primitives import serialization

from liltweak.cloudflare_runner_qualification import (
    CloudflareRunnerPollObservation,
    CloudflareRunnerPollRequest,
)
from liltweak.creator_contract import content_digest
from runner.config import load_credentials
from runner.protocol import canonical_json, sign_runner_request

credentials = load_credentials()
issued_at_ms = time.time_ns() // 1_000_000
envelope = sign_runner_request(
    operation="poll",
    payload={},
    private_key=credentials.runner_private_key,
    issued_at_ms=issued_at_ms,
    request_nonce=secrets.token_bytes(32),
)
headers = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Authorization": f"Bearer {credentials.runner_bearer_token}",
    "CF-Access-Client-Id": credentials.cf_access_client_id,
    "CF-Access-Client-Secret": credentials.cf_access_client_secret,
}
with httpx.Client(
    base_url=credentials.control_plane_url,
    headers=headers,
    follow_redirects=False,
    timeout=httpx.Timeout(15.0),
    trust_env=False,
) as client:
    response = client.post(
        "/v1/runners/galor-tweak-runner-01/next",
        content=canonical_json(envelope).encode("utf-8"),
    )
observed_at = datetime.now(UTC)
if response.status_code not in {200, 404} or len(response.content) > 128_000:
    raise SystemExit("bounded signed poll was rejected")
values = {
    "endpoint": credentials.control_plane_url,
    "request": CloudflareRunnerPollRequest.model_validate(envelope["request"]),
    "signature": envelope["signature"],
    "worker_response_status": response.status_code,
    "worker_response_digest": hashlib.sha256(response.content).hexdigest(),
    "observed_at": observed_at,
    "nonce_consumed": True,
}
draft = CloudflareRunnerPollObservation.model_construct(
    **values,
    observation_digest="0" * 64,
)
observation = CloudflareRunnerPollObservation(
    **values,
    observation_digest=content_digest(
        draft.model_dump(mode="json", exclude={"observation_digest"})
    ),
)
runner_public_key = credentials.runner_private_key.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)
print(json.dumps({
    "runner_public_key_b64": (
        base64.urlsafe_b64encode(runner_public_key)
        .decode("ascii")
        .rstrip("=")
    ),
    "poll_observation": observation.model_dump(mode="json"),
}, sort_keys=True, separators=(",", ":")))
"""


def _run(command: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode != 0:
        raise RuntimeError(f"operator command failed: {command[0]}")
    return result.stdout.strip()


def _run_bytes(
    command: list[str],
    *,
    cwd: Path | None = None,
    maximum_bytes: int,
) -> bytes:
    result = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        timeout=180,
    )
    if result.returncode != 0 or len(result.stdout) > maximum_bytes or len(result.stderr) > 128_000:
        raise RuntimeError(f"operator command failed: {command[0]}")
    return result.stdout


def _git(repo: Path, *arguments: str) -> str:
    return _run(["git", "-c", f"safe.directory={repo}", "-C", str(repo), *arguments])


def _decode_b64url(value: str, expected_length: int) -> bytes:
    decoded = base64.b64decode(
        value + "=" * (-len(value) % 4),
        altchars=b"-_",
        validate=True,
    )
    if len(decoded) != expected_length:
        raise ValueError("public artifact has an invalid encoded length")
    return decoded


def _single(root: Path, name: str) -> Path:
    matches = list(root.rglob(name))
    if len(matches) != 1 or not matches[0].is_file() or matches[0].is_symlink():
        raise RuntimeError(f"Gate 3 artifact {name} is unavailable or ambiguous")
    return matches[0]


def _read_json(path: Path, maximum_bytes: int = 128_000) -> Any:
    if path.stat().st_size < 2 or path.stat().st_size > maximum_bytes:
        raise RuntimeError(f"bounded JSON artifact {path.name} has an invalid size")
    return json.loads(path.read_text(encoding="utf-8"))


def _github_ci_evidence(*, run_id: int, head: str) -> tuple[dict[str, Any], str]:
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id < 1:
        raise RuntimeError("GitHub Job A run identity is invalid")
    if _GIT_SHA.fullmatch(head) is None:
        raise RuntimeError("GitHub Job A source identity is invalid")
    run = json.loads(
        _run(
            [
                "gh",
                "api",
                f"repos/{GITHUB_REPOSITORY}/actions/runs/{run_id}",
            ]
        )
    )
    jobs_payload = json.loads(
        _run(
            [
                "gh",
                "api",
                f"repos/{GITHUB_REPOSITORY}/actions/runs/{run_id}/jobs?per_page=100",
            ]
        )
    )
    if not isinstance(run, dict) or not isinstance(jobs_payload, dict):
        raise RuntimeError("GitHub Job A evidence has an invalid shape")
    expected_url = f"https://github.com/{GITHUB_REPOSITORY}/actions/runs/{run_id}"
    run_bindings = (
        (run.get("id"), run_id),
        (run.get("name"), GITHUB_CI_WORKFLOW_NAME),
        (run.get("path"), GITHUB_CI_WORKFLOW),
        (run.get("event"), "pull_request"),
        (run.get("status"), "completed"),
        (run.get("conclusion"), "success"),
        (run.get("head_sha"), head),
        (run.get("head_branch"), GITHUB_PR_BRANCH),
        ((run.get("repository") or {}).get("full_name"), GITHUB_REPOSITORY),
        ((run.get("head_repository") or {}).get("full_name"), GITHUB_REPOSITORY),
        (run.get("html_url"), expected_url),
    )
    if any(observed != expected for observed, expected in run_bindings):
        raise RuntimeError("GitHub Job A run is not the exact successful source candidate")
    run_attempt = run.get("run_attempt")
    if not isinstance(run_attempt, int) or isinstance(run_attempt, bool) or run_attempt < 1:
        raise RuntimeError("GitHub Job A run attempt is invalid")
    pull_requests = run.get("pull_requests")
    if not isinstance(pull_requests, list) or not any(
        isinstance(pull_request, dict)
        and pull_request.get("number") == GITHUB_PR_NUMBER
        and (pull_request.get("base") or {}).get("ref") == "main"
        and (pull_request.get("head") or {}).get("ref") == GITHUB_PR_BRANCH
        for pull_request in pull_requests
    ):
        raise RuntimeError("GitHub Job A run is not bound to PR #12")

    jobs = jobs_payload.get("jobs")
    if jobs_payload.get("total_count") != 1 or not isinstance(jobs, list) or len(jobs) != 1:
        raise RuntimeError("GitHub Job A run has an unexpected job set")
    job = jobs[0]
    if not isinstance(job, dict):
        raise RuntimeError("GitHub Job A run has an invalid job")
    job_bindings = (
        (job.get("name"), GITHUB_CI_JOB_NAME),
        (job.get("head_sha"), head),
        (job.get("status"), "completed"),
        (job.get("conclusion"), "success"),
        (job.get("run_attempt"), run_attempt),
    )
    job_id = job.get("id")
    if (
        any(observed != expected for observed, expected in job_bindings)
        or not isinstance(job_id, int)
        or isinstance(job_id, bool)
        or job_id < 1
    ):
        raise RuntimeError("GitHub Job A run did not complete its exact successful job")
    steps = job.get("steps")
    if not isinstance(steps, list):
        raise RuntimeError("GitHub Job A run lacks completed checks")
    completed_checks = {
        step.get("name")
        for step in steps
        if isinstance(step, dict)
        and step.get("status") == "completed"
        and step.get("conclusion") == "success"
        and isinstance(step.get("name"), str)
    }
    if not completed_checks >= GITHUB_CI_REQUIRED_CHECKS:
        raise RuntimeError("GitHub Job A run lacks required successful checks")

    evidence: dict[str, Any] = {
        "schema_version": "lil-tweak.github-independent-verification/v1",
        "repository_id": REPOSITORY_ID,
        "pull_request_number": GITHUB_PR_NUMBER,
        "workflow_path": GITHUB_CI_WORKFLOW,
        "workflow_name": GITHUB_CI_WORKFLOW_NAME,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "job_id": job_id,
        "job_name": GITHUB_CI_JOB_NAME,
        "head_sha": head,
        "head_branch": GITHUB_PR_BRANCH,
        "status": "completed",
        "conclusion": "success",
        "html_url": expected_url,
        "completed_checks": sorted(GITHUB_CI_REQUIRED_CHECKS),
    }
    digest = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return evidence, digest


def _source_archive_digest(repo: Path, commit: str) -> str:
    with tempfile.TemporaryDirectory(prefix="liltweak-operator-") as temporary:
        archive = Path(temporary) / "source.tar"
        _run(
            [
                "git",
                "-c",
                f"safe.directory={repo}",
                "-C",
                str(repo),
                "archive",
                "--format=tar",
                f"--output={archive}",
                commit,
            ]
        )
        return hashlib.sha256(archive.read_bytes()).hexdigest()


def _verify_candidate_artifacts(
    *,
    repo: Path,
    receipt_path: Path,
    bundle_path: Path,
    execution_id: str,
    signed_receipt: dict[str, Any],
) -> dict[str, Any]:
    if _EXECUTION_ID.fullmatch(execution_id) is None:
        raise RuntimeError("candidate execution identity is invalid")
    expected_keys = {
        "runner_id",
        "runtime_image",
        "seccomp_sha256",
        "apparmor_profile",
        "network_denied",
        "package_install_allowed",
        "production_access_allowed",
        "deploy_allowed",
        "workspace_cleaned",
        "cgroup_cleaned",
        "artifact_path",
        "artifact_sha256",
        "candidate_sha",
        "candidate_tree",
        "source_commit",
        "source_tree",
        "source_mutated",
        "bundle_sha256",
        "bundle_size",
        "candidate_store_id",
        "created_at_ms",
        "qualification_branch",
    }
    if not isinstance(signed_receipt, dict) or set(signed_receipt) != expected_keys:
        raise RuntimeError("signed runner evidence has an invalid bounded receipt")
    if (
        receipt_path.is_symlink()
        or bundle_path.is_symlink()
        or not receipt_path.is_file()
        or not bundle_path.is_file()
    ):
        raise RuntimeError("retrieved candidate artifacts are unavailable")
    observed_receipt = _read_json(receipt_path, maximum_bytes=64_000)
    if observed_receipt != signed_receipt:
        raise RuntimeError("retrieved candidate receipt does not match signed runner evidence")

    source_commit = signed_receipt["source_commit"]
    source_tree = signed_receipt["source_tree"]
    candidate_sha = signed_receipt["candidate_sha"]
    candidate_tree = signed_receipt["candidate_tree"]
    branch = signed_receipt["qualification_branch"]
    bundle_digest = signed_receipt["bundle_sha256"]
    scalar_bindings = (
        (signed_receipt["runner_id"], RUNNER_ID),
        (signed_receipt["artifact_path"], JOB_B_ARTIFACT_PATH),
        (signed_receipt["artifact_sha256"], JOB_B_ARTIFACT_SHA256),
        (signed_receipt["candidate_store_id"], execution_id),
        (signed_receipt["source_mutated"], True),
        (signed_receipt["workspace_cleaned"], True),
        (signed_receipt["cgroup_cleaned"], True),
    )
    if any(observed != expected for observed, expected in scalar_bindings):
        raise RuntimeError("signed runner evidence bounded receipt binding mismatch")
    if not all(
        isinstance(value, str) and _GIT_SHA.fullmatch(value)
        for value in (source_commit, source_tree, candidate_sha, candidate_tree)
    ):
        raise RuntimeError("signed runner evidence contains an invalid Git object")
    if not isinstance(branch, str) or _QUALIFICATION_BRANCH.fullmatch(branch) is None:
        raise RuntimeError("signed runner evidence qualification branch is invalid")
    if not isinstance(bundle_digest, str) or _SHA256.fullmatch(bundle_digest) is None:
        raise RuntimeError("signed runner evidence bundle digest is invalid")

    repo = repo.resolve(strict=True)
    if (
        _git(repo, "rev-parse", "HEAD") != source_commit
        or _git(repo, "rev-parse", "HEAD^{tree}") != source_tree
    ):
        raise RuntimeError("candidate source does not match the operator checkout")
    if _git(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError("candidate verification refuses a dirty source checkout")

    bundle_size = bundle_path.stat().st_size
    expected_size = signed_receipt["bundle_size"]
    if (
        not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
        or bundle_size != expected_size
        or not 1 <= bundle_size <= 1_000_000
    ):
        raise RuntimeError("retrieved candidate bundle size does not match signed evidence")
    bundle_bytes = bundle_path.read_bytes()
    if hashlib.sha256(bundle_bytes).hexdigest() != bundle_digest:
        raise RuntimeError("retrieved candidate bundle digest does not match signed evidence")

    _git(repo, "bundle", "verify", str(bundle_path.resolve(strict=True)))
    heads = _git(repo, "bundle", "list-heads", str(bundle_path.resolve(strict=True)))
    expected_head = f"{candidate_sha} refs/heads/{branch}"
    if heads.splitlines() != [expected_head]:
        raise RuntimeError("candidate bundle head does not match signed runner evidence")

    with tempfile.TemporaryDirectory(prefix="liltweak-candidate-verify-") as temporary:
        verification_repo = Path(temporary) / "verification.git"
        _run(
            [
                "git",
                "clone",
                "--bare",
                "--no-hardlinks",
                str(repo),
                str(verification_repo),
            ]
        )
        _git(
            verification_repo,
            "fetch",
            "--no-tags",
            str(bundle_path.resolve(strict=True)),
            f"refs/heads/{branch}:refs/verify/candidate",
        )
        fetched_candidate = _git(
            verification_repo,
            "rev-parse",
            "refs/verify/candidate",
        )
        fetched_tree = _git(
            verification_repo,
            "rev-parse",
            "refs/verify/candidate^{tree}",
        )
        parents = _git(
            verification_repo,
            "rev-list",
            "--parents",
            "-n",
            "1",
            "refs/verify/candidate",
        ).split()
        if (
            fetched_candidate != candidate_sha
            or fetched_tree != candidate_tree
            or parents != [candidate_sha, source_commit]
        ):
            raise RuntimeError("candidate bundle Git bindings do not match signed evidence")
        changed = _git(
            verification_repo,
            "diff",
            "--name-status",
            "-z",
            source_commit,
            candidate_sha,
        )
        if changed != f"A\0{JOB_B_ARTIFACT_PATH}\0":
            raise RuntimeError("candidate bundle contains an unauthorized Git diff")
        artifact_bytes = _run_bytes(
            [
                "git",
                "-c",
                f"safe.directory={verification_repo}",
                "-C",
                str(verification_repo),
                "show",
                f"{candidate_sha}:{JOB_B_ARTIFACT_PATH}",
            ],
            maximum_bytes=4_096,
        )
        if hashlib.sha256(artifact_bytes).hexdigest() != JOB_B_ARTIFACT_SHA256:
            raise RuntimeError("candidate bundle artifact content is not authorized")

    if _git(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError("candidate verification mutated the source checkout")
    return {
        "execution_id": execution_id,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "candidate_sha": candidate_sha,
        "candidate_tree": candidate_tree,
        "qualification_branch": branch,
        "artifact_path": JOB_B_ARTIFACT_PATH,
        "artifact_sha256": JOB_B_ARTIFACT_SHA256,
        "bundle_sha256": bundle_digest,
        "bundle_size": bundle_size,
        "retrieved_receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
    }


def _retrieve_candidate_artifacts(
    *,
    ssh_key: Path,
    runner_host: str,
    execution_id: str,
    destination: Path,
) -> tuple[Path, Path]:
    if _EXECUTION_ID.fullmatch(execution_id) is None:
        raise RuntimeError("candidate execution identity is invalid")
    if (
        not isinstance(runner_host, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", runner_host) is None
    ):
        raise RuntimeError("runner host is invalid")
    ssh_key = ssh_key.resolve(strict=True)
    if ssh_key.is_symlink() or not ssh_key.is_file():
        raise RuntimeError("runner SSH identity is unavailable")
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("candidate artifact destination must not already exist")
    destination.mkdir(parents=True)
    remote = f"root@{runner_host}:{REMOTE_CANDIDATE_ROOT}/{execution_id}"
    result = subprocess.run(
        [
            "scp",
            "-q",
            "-i",
            str(ssh_key),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            f"{remote}/receipt.json",
            f"{remote}/candidate.bundle",
            str(destination),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError("runner candidate artifacts could not be retrieved")
    receipt_path = destination / "receipt.json"
    bundle_path = destination / "candidate.bundle"
    if {path.name for path in destination.iterdir()} != {
        receipt_path.name,
        bundle_path.name,
    }:
        raise RuntimeError("runner candidate artifact response has an invalid shape")
    if (
        receipt_path.is_symlink()
        or bundle_path.is_symlink()
        or not receipt_path.is_file()
        or not bundle_path.is_file()
    ):
        raise RuntimeError("runner candidate artifacts are unavailable")
    return receipt_path, bundle_path


def _fresh_host_poll(*, ssh_key: Path, runner_host: str) -> dict[str, Any]:
    encoded = base64.b64encode(REMOTE_POLL_SCRIPT.encode("utf-8")).decode("ascii")
    remote_command = (
        "cd /opt/liltweak-runner/app && "
        "exec /opt/liltweak-runner/venv/bin/python -c "
        f"\"import base64;exec(base64.b64decode('{encoded}'))\""
    )
    result = subprocess.run(
        [
            "ssh",
            "-i",
            str(ssh_key),
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            f"root@{runner_host}",
            remote_command,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0 or len(result.stdout) > 256_000:
        raise RuntimeError("runner could not produce a fresh bounded signed poll observation")
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or set(value) != {
        "runner_public_key_b64",
        "poll_observation",
    }:
        raise RuntimeError("runner signed-poll response has an invalid shape")
    return value


async def _collect(orchestrator: Any, receipt: Any, timeout_seconds: int) -> Any:
    deadline = time.monotonic() + timeout_seconds
    current = receipt
    while time.monotonic() < deadline:
        await asyncio.sleep(2)
        current = await orchestrator.collect(current)
        if current.runner_evidence_digest is not None:
            return current
    await orchestrator.cancel(current)
    raise TimeoutError("private runner evidence did not arrive before the operator deadline")


async def _execute(arguments: argparse.Namespace) -> dict[str, Any]:
    repo = arguments.repo.resolve(strict=True)
    sys.path.insert(0, str(repo))

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    from liltweak.cloudflare_runner_qualification import (
        CloudflareRunnerPollObservation,
        CloudflareRunnerQualificationVerifier,
    )
    from liltweak.creator_contract import content_digest
    from liltweak.private_runner_activation import (
        GALOR_TWEAK_PROFILE_SPEC_DIGEST,
        IndependentVerificationReceipt,
        PrivateRunnerApproval,
        PrivateRunnerQualificationEvidence,
        PrivateRunnerQualificationOrchestrator,
        QualifiedRunnerScope,
        SourceEvidence,
        build_live_private_runner_orchestrator,
        load_protected_controller_config,
    )
    from liltweak.providers.contracts import VerificationOutcome
    from liltweak.providers.self_hosted.galor_tweak_runner import (
        RunnerBoundedWriteReceipt,
        RunnerReadOnlyReceipt,
    )
    from liltweak.providers.self_hosted.qualification_manifest import (
        QualificationBoundedWriteManifest,
        QualificationJobManifest,
        QualificationReadOnlyManifest,
        QualificationSource,
    )
    from liltweak.runner_qualification import (
        LocalRunnerConnectionAuthorization,
        LocalRunnerConnectionDecision,
        LocalRunnerExecutionBindings,
        RunnerQualificationChallenge,
        RunnerQualificationDecision,
        RunnerQualificationExpectations,
        RunnerQualificationVerifier,
        SignedRunnerQualificationAttestation,
        encode_runner_signature,
        local_runner_authorization_signature_message,
        runner_key_id,
    )

    head = _git(repo, "rev-parse", "HEAD")
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    if _git(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError("operator refuses a dirty source checkout")
    github_a_evidence, github_a_evidence_digest = _github_ci_evidence(
        run_id=arguments.github_a_run_id,
        head=head,
    )

    challenge = RunnerQualificationChallenge.model_validate(
        _read_json(_single(arguments.gate3_dir, "liltweak-qualification-challenge.json"))
    )
    attestation = SignedRunnerQualificationAttestation.model_validate(
        _read_json(
            _single(
                arguments.gate3_dir,
                "liltweak-qualification-attestation*.json",
            )
        )
    )
    issuer_payload = _read_json(_single(arguments.gate3_dir, "liltweak-qualification-issuer.json"))
    if not isinstance(issuer_payload, dict) or set(issuer_payload) != {"public_key_b64"}:
        raise RuntimeError("Gate 3 issuer artifact has an invalid shape")
    issuer_public_key = _decode_b64url(issuer_payload["public_key_b64"], 32)

    if (
        challenge.repository_id != REPOSITORY_ID
        or challenge.runner_id != RUNNER_ID
        or challenge.repository_commit != head
        or challenge.repository_tree != tree
        or attestation.repository_commit != head
        or attestation.repository_tree != tree
    ):
        raise RuntimeError("Gate 3 artifacts are not bound to the exact operator source")

    source_archive_digest = _source_archive_digest(repo, head)
    source = SourceEvidence(
        commit_sha=head,
        tree_sha=tree,
        source_archive_digest=source_archive_digest,
    )
    controller = load_protected_controller_config(arguments.controller_bundle)
    owner_private_key = Ed25519PrivateKey.from_private_bytes(
        controller.dispatch_private_key.get_secret_value()
    )
    owner_public_key = owner_private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    class Gate3Source:
        def __init__(self, runner_public_key: bytes) -> None:
            expectations = RunnerQualificationExpectations(
                runner_id=RUNNER_ID,
                repository_id=REPOSITORY_ID,
                repository_commit=head,
                repository_tree=tree,
                image_ref=challenge.image_ref,
                sandbox_profile_digest=challenge.sandbox_profile_digest,
                runtime_sha256=challenge.runtime_sha256,
                limiter_sha256=challenge.limiter_sha256,
                qualifier_sha256=challenge.qualifier_sha256,
                destroyer_sha256=challenge.destroyer_sha256,
            )
            self._verifier = RunnerQualificationVerifier(
                expectations=expectations,
                trusted_issuer_public_keys={runner_key_id(issuer_public_key): issuer_public_key},
                trusted_runner_public_keys={RUNNER_ID: runner_public_key},
            )

        def verify(
            self,
            *,
            now: datetime,
        ) -> tuple[RunnerQualificationDecision, SignedRunnerQualificationAttestation]:
            return self._verifier.verify(
                challenge=challenge,
                attestation=attestation,
                now=now,
            ), attestation

    def issue_local_authorization(
        *, manifest: Any, qualification: Any, now: datetime
    ) -> LocalRunnerConnectionAuthorization:
        bindings = LocalRunnerExecutionBindings(
            repository_id=REPOSITORY_ID,
            repository_commit=head,
            repository_tree=tree,
            source_snapshot_digest=source_archive_digest,
            task_id=f"task:pr12-{manifest.job_type}",
            plan_digest=manifest.commands_digest,
            execution_attempt=1,
            sandbox_profile_digest=challenge.sandbox_profile_digest,
            resource_profile_digest=GALOR_TWEAK_PROFILE_SPEC_DIGEST,
        )
        values = {
            "authorization_id": f"lra_{secrets.token_hex(16)}",
            "owner_key_id": runner_key_id(owner_public_key),
            "provider_id": RUNNER_ID,
            # The signed 47-check Gate 3 attestation is the actual host report.
            "report_digest": attestation.evidence_digest,
            "qualification_id": qualification.qualification_id,
            "qualification_evidence_digest": qualification.evidence_digest,
            "bindings": bindings,
            "bindings_digest": bindings.bindings_digest,
            "nonce": secrets.token_hex(32),
            "generation": int(now.timestamp() * 1_000_000),
            "issued_at": now,
            "expires_at": now + timedelta(minutes=5),
        }
        draft = LocalRunnerConnectionAuthorization.model_construct(
            **values,
            authorization_digest="0" * 64,
            signature="A" * 86,
        )
        digest = content_digest(
            draft.model_dump(
                mode="json",
                exclude={"authorization_digest", "signature"},
            )
        )
        unsigned = LocalRunnerConnectionAuthorization.model_construct(
            **values,
            authorization_digest=digest,
            signature="A" * 86,
        )
        return LocalRunnerConnectionAuthorization(
            **values,
            authorization_digest=digest,
            signature=encode_runner_signature(
                owner_private_key.sign(local_runner_authorization_signature_message(unsigned))
            ),
        )

    class OwnerAuthorizedGate3Source:
        def __init__(
            self,
            authorization: LocalRunnerConnectionAuthorization,
            manifest: Any,
        ) -> None:
            self.authorization = authorization
            self.manifest = manifest

        def verify(
            self,
            *,
            qualification: Any,
            now: datetime,
        ) -> tuple[LocalRunnerConnectionDecision, LocalRunnerConnectionAuthorization]:
            authorization = LocalRunnerConnectionAuthorization.model_validate(
                self.authorization.model_dump(mode="json")
            )
            if (
                now < authorization.issued_at
                or now >= authorization.expires_at
                or authorization.provider_id != RUNNER_ID
                or authorization.report_digest != attestation.evidence_digest
                or authorization.qualification_id != qualification.qualification_id
                or authorization.qualification_evidence_digest != qualification.evidence_digest
                or authorization.bindings.repository_id != REPOSITORY_ID
                or authorization.bindings.repository_commit != head
                or authorization.bindings.repository_tree != tree
                or authorization.bindings.source_snapshot_digest != source_archive_digest
                or authorization.bindings.task_id != f"task:pr12-{self.manifest.job_type}"
                or authorization.bindings.plan_digest != self.manifest.commands_digest
                or authorization.bindings.execution_attempt != 1
                or authorization.bindings.sandbox_profile_digest != challenge.sandbox_profile_digest
                or authorization.bindings.resource_profile_digest != GALOR_TWEAK_PROFILE_SPEC_DIGEST
                or authorization.bindings.network_mode != "denied"
                or authorization.owner_key_id != runner_key_id(owner_public_key)
            ):
                raise RuntimeError("owner-authorized Gate 3 binding is invalid")
            signature = _decode_b64url(authorization.signature, 64)
            try:
                Ed25519PublicKey.from_public_bytes(owner_public_key).verify(
                    signature,
                    local_runner_authorization_signature_message(authorization),
                )
            except InvalidSignature as exc:
                raise RuntimeError("owner-authorized Gate 3 signature is invalid") from exc
            values: dict[str, Any] = {
                "provider_id": RUNNER_ID,
                "report_digest": authorization.report_digest,
                "host_qualified": True,
                "qualification_verified": True,
                "authorization_verified": True,
                "connection_authorized": True,
                "authorization_id": authorization.authorization_id,
                "authorization_digest": authorization.authorization_digest,
                "failure_codes": (),
                "verified_at": now,
            }
            draft = LocalRunnerConnectionDecision.model_construct(
                **values,
                decision_digest="0" * 64,
            )
            return LocalRunnerConnectionDecision(
                **values,
                decision_digest=content_digest(
                    draft.model_dump(mode="json", exclude={"decision_digest"})
                ),
            ), authorization

    async def build_for_manifest(
        manifest: QualificationJobManifest,
    ) -> tuple[
        PrivateRunnerQualificationOrchestrator,
        PrivateRunnerQualificationEvidence,
    ]:
        host_poll = _fresh_host_poll(
            ssh_key=arguments.ssh_key,
            runner_host=arguments.runner_host,
        )
        runner_public_key = _decode_b64url(host_poll["runner_public_key_b64"], 32)
        if runner_key_id(runner_public_key) != challenge.key_id:
            raise RuntimeError("live runner signing identity does not match Gate 3")
        gate3_source = Gate3Source(runner_public_key)
        qualification_decision, _ = gate3_source.verify(now=datetime.now(UTC))
        authorization = issue_local_authorization(
            manifest=manifest,
            qualification=qualification_decision,
            now=datetime.now(UTC),
        )
        verifier = CloudflareRunnerQualificationVerifier(
            qualification_source=gate3_source,
            local_source=OwnerAuthorizedGate3Source(authorization, manifest),
            poll_observation=CloudflareRunnerPollObservation.model_validate(
                host_poll["poll_observation"]
            ),
            runner_public_key=runner_public_key,
            clock=lambda: datetime.now(UTC),
        )
        proof = await verifier.refresh()
        qualification = PrivateRunnerQualificationEvidence(
            profile_spec_digest=GALOR_TWEAK_PROFILE_SPEC_DIGEST,
            qualified=True,
            healthy=True,
            qualified_scopes=(QualifiedRunnerScope.JOB_A, QualifiedRunnerScope.JOB_B),
            gate3_contract_digest=verifier.contract_digest,
            qualification_evidence_digest=proof.qualification_evidence_digest,
            authorization_evidence_digest=proof.authorization_evidence_digest,
            proof=proof,
        )
        orchestrator = build_live_private_runner_orchestrator(
            controller=controller,
            qualification=qualification,
            qualification_verifier=verifier,
            runner_public_key=runner_public_key,
            monthly_resource_limit_microusd=arguments.monthly_resource_limit_microusd,
            clock=lambda: datetime.now(UTC),
        )
        return orchestrator, qualification

    manifest_a = QualificationReadOnlyManifest(
        source=QualificationSource(commit_sha=head, tree_sha=tree),
        timeout_seconds=arguments.job_timeout_seconds,
    )
    orchestrator_a, qualification_a = await build_for_manifest(manifest_a)
    approval_a = PrivateRunnerApproval(
        approval_id=f"founder-approval-pr12-job-a-{head[:12]}",
        approved=True,
        approval_digest=arguments.approval_digest_a,
        policy_digest=arguments.policy_digest,
        maximum_execution_cost_microusd=arguments.maximum_execution_cost_microusd,
    )
    receipt_a = await orchestrator_a.offer(
        manifest=manifest_a,
        source=source,
        approval=approval_a,
        qualification=qualification_a,
    )
    receipt_a = await _collect(
        orchestrator_a,
        receipt_a,
        arguments.collect_timeout_seconds,
    )
    envelope_a = receipt_a.runner_evidence_envelope
    if envelope_a is None or not isinstance(
        envelope_a.request.payload.evidence.receipt,
        RunnerReadOnlyReceipt,
    ):
        raise RuntimeError("Job A detailed signed runner receipt is unavailable")
    signed_receipt_a = envelope_a.request.payload.evidence.receipt.model_dump(mode="json")
    verification_a = IndependentVerificationReceipt(
        job_type="read_only",
        runner_execution_id=receipt_a.execution_id,
        source_commit=head,
        runner_evidence_digest=receipt_a.runner_evidence_digest,
        github_evidence_digest=github_a_evidence_digest,
        verification_outcome=VerificationOutcome.VERIFIED,
    )
    verified_a = orchestrator_a.accept_independent_verification(receipt_a, verification_a)

    branch = arguments.qualification_branch or (
        f"qualification/galor-tweak-runner-01/pr12-{head[:12]}"
    )
    manifest_b = QualificationBoundedWriteManifest(
        source=QualificationSource(commit_sha=head, tree_sha=tree),
        timeout_seconds=arguments.job_timeout_seconds,
        qualification_branch=branch,
    )
    orchestrator_b, qualification_b = await build_for_manifest(manifest_b)
    approval_b = PrivateRunnerApproval(
        approval_id=f"founder-approval-pr12-job-b-{head[:12]}",
        approved=True,
        approval_digest=arguments.approval_digest_b,
        policy_digest=arguments.policy_digest,
        maximum_execution_cost_microusd=arguments.maximum_execution_cost_microusd,
    )
    receipt_b = await orchestrator_b.offer(
        manifest=manifest_b,
        source=source,
        approval=approval_b,
        qualification=qualification_b,
        prior_job_a_verification=verified_a,
    )
    receipt_b = await _collect(
        orchestrator_b,
        receipt_b,
        arguments.collect_timeout_seconds,
    )
    envelope_b = receipt_b.runner_evidence_envelope
    if envelope_b is None or not isinstance(
        envelope_b.request.payload.evidence.receipt,
        RunnerBoundedWriteReceipt,
    ):
        raise RuntimeError("Job B detailed signed runner receipt is unavailable")
    signed_receipt_b = envelope_b.request.payload.evidence.receipt.model_dump(mode="json")
    artifact_root = (
        arguments.artifact_dir
        if arguments.artifact_dir is not None
        else arguments.output.parent / f"{arguments.output.stem}-candidate-artifacts"
    ).resolve()
    try:
        artifact_root.relative_to(repo)
    except ValueError:
        pass
    else:
        raise RuntimeError("candidate artifacts must be stored outside the source checkout")
    artifact_directory = artifact_root / receipt_b.execution_id
    retrieved_receipt, retrieved_bundle = _retrieve_candidate_artifacts(
        ssh_key=arguments.ssh_key,
        runner_host=arguments.runner_host,
        execution_id=receipt_b.execution_id,
        destination=artifact_directory,
    )
    candidate_verification = _verify_candidate_artifacts(
        repo=repo,
        receipt_path=retrieved_receipt,
        bundle_path=retrieved_bundle,
        execution_id=receipt_b.execution_id,
        signed_receipt=signed_receipt_b,
    )

    return {
        "schema_version": "lil-tweak.private-runner-operator-result/v2",
        "source_commit": head,
        "source_tree": tree,
        "source_archive_digest": source_archive_digest,
        "gate3_qualification_id": challenge.qualification_id,
        "gate3_evidence_digest": attestation.evidence_digest,
        "job_a": {
            "github_verification": github_a_evidence,
            "github_evidence_digest": github_a_evidence_digest,
            "dispatch": receipt_a.model_dump(mode="json"),
            "runner_receipt": signed_receipt_a,
            "verified": verified_a.model_dump(mode="json"),
        },
        "job_b": {
            "dispatch": receipt_b.model_dump(mode="json"),
            "runner_receipt": signed_receipt_b,
            "qualification_branch": branch,
            "remote_candidate_directory": (f"{REMOTE_CANDIDATE_ROOT}/{receipt_b.execution_id}"),
            "candidate_artifacts": {
                **candidate_verification,
                "artifact_directory": str(artifact_directory),
                "receipt_path": str(retrieved_receipt),
                "bundle_path": str(retrieved_bundle),
            },
        },
    }


def _digest(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise argparse.ArgumentTypeError("value must be a lowercase SHA-256 digest")
    return value


def parser() -> argparse.ArgumentParser:
    default_repo = Path(__file__).resolve().parent.parent
    target = argparse.ArgumentParser(
        description="Dispatch bounded Lil Tweak qualification Jobs A and B through the live Worker."
    )
    target.add_argument("--repo", type=Path, default=default_repo)
    target.add_argument("--gate3-dir", type=Path, required=True)
    target.add_argument("--controller-bundle", type=Path, required=True)
    target.add_argument("--ssh-key", type=Path, required=True)
    target.add_argument("--runner-host", default="165.232.134.154")
    target.add_argument("--approval-digest-a", type=_digest, required=True)
    target.add_argument("--approval-digest-b", type=_digest, required=True)
    target.add_argument("--policy-digest", type=_digest, required=True)
    target.add_argument("--github-a-run-id", type=int, required=True)
    target.add_argument("--qualification-branch")
    target.add_argument("--maximum-execution-cost-microusd", type=int, default=50_000)
    target.add_argument("--monthly-resource-limit-microusd", type=int, default=100_000)
    target.add_argument("--job-timeout-seconds", type=int, default=300)
    target.add_argument("--collect-timeout-seconds", type=int, default=300)
    target.add_argument("--artifact-dir", type=Path)
    target.add_argument("--output", type=Path, required=True)
    return target


def main() -> int:
    arguments = parser().parse_args()
    result = asyncio.run(_execute(arguments))
    encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(encoded, encoding="utf-8")
    print(arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
