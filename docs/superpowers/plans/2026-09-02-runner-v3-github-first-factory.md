# Runner V3 GitHub-First Factory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `galor-tweak-runner-v3-github-01`, the first headless, disposable GitHub Actions worker in Lil' Tweak's Runner Factory.

**Architecture:** Add a strict typed manifest, a lease-consuming GitHub builder provider, a local executor with a fixed action vocabulary, and a read-only GitHub Actions workflow. The runner may apply an authorized patch only inside its ephemeral checkout and may emit a candidate patch artifact, but it cannot push, merge, deploy, use production, or claim independent verification.

**Tech Stack:** Python 3.12.13, Pydantic 2, `uv` 0.11.33, pytest, Ruff, mypy, GitHub Actions on Ubuntu 24.04.

**Spec:** `docs/superpowers/specs/2026-09-02-runner-v3-github-first-factory-design.md`

## Global Constraints

- Preserve all existing Resource Director, contract, lease, approval, policy, evidence, and independent-verification behavior.
- Keep PR #12 open and unchanged as reference.
- Runner profile ID is exactly `galor-tweak-runner-v3-github-01`.
- No Cloudflare, Vercel, DigitalOcean, custom hostname, permanent host, model call, browser, GPU, secret, production, deployment, push, or merge dependency.
- GitHub workflow repository permission is `contents: read`.
- No arbitrary shell or model-generated executable/argument channel.
- Builder evidence never becomes independent verification.
- Every real execution binds exact repository, commit, tree, contract digest, lease digest, command digest, approval digest, policy digest, nonce, expiry, and resource ceilings.
- Full deterministic CI and the dedicated Runner V3 smoke job must pass on the exact candidate commit.

---

### Task 1: Define the Runner V3 manifest and evidence contracts

**Files:**
- Create: `liltweak/providers/github/runner_v3_contracts.py`
- Test: `tests/test_runner_v3_contracts.py`

**Interfaces:**
- Produces: `RunnerV3Action`, `RunnerV3WorkspaceMode`, `RunnerV3Patch`, `RunnerV3JobManifest`, `RunnerV3StepReceipt`, `RunnerV3HostCapacity`, `RunnerV3Receipt`, `RunnerV3ProviderConfig`, `RunnerV3WorkflowSnapshot`, and `RunnerV3Client`.
- Produces: `RunnerV3JobManifest.issue(...) -> RunnerV3JobManifest` and `RunnerV3Receipt.issue(...) -> RunnerV3Receipt`.

- [ ] **Step 1: Write failing contract tests**

Add tests that construct an exact source-bound manifest and prove:

```python
assert manifest.runner_profile_id == "galor-tweak-runner-v3-github-01"
assert manifest.manifest_digest == content_digest(
    manifest.model_dump(mode="json", exclude={"manifest_digest"})
)
```

Add rejection tests for unknown fields, duplicate actions, expired timestamps, read-only mode with a patch, patch mode without source-write authority, malformed patch digest, unsafe paths, excessive patch bytes, and a forged `manifest_digest`.

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
uv run --no-sync --offline pytest -q tests/test_runner_v3_contracts.py
```

Expected: import failure because `runner_v3_contracts.py` does not exist.

- [ ] **Step 3: Implement strict immutable Pydantic contracts**

Use `CreatorSchema`, strict fields, timezone-aware timestamps, path normalization through `PurePosixPath`, canonical `content_digest`, and model validators. Limit the manifest to eight unique actions, patch text to 262,144 UTF-8 bytes, authorized paths to 64, timeout to 1–1,800 seconds, and output to 1–1,000,000 bytes.

- [ ] **Step 4: Run focused tests and static checks**

```bash
uv run --no-sync --offline pytest -q tests/test_runner_v3_contracts.py
uv run --no-sync --offline ruff check liltweak/providers/github/runner_v3_contracts.py tests/test_runner_v3_contracts.py
uv run --no-sync --offline ruff format --check liltweak/providers/github/runner_v3_contracts.py tests/test_runner_v3_contracts.py
uv run --no-sync --offline mypy liltweak/providers/github/runner_v3_contracts.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add liltweak/providers/github/runner_v3_contracts.py tests/test_runner_v3_contracts.py
git commit -m "feat: add strict Runner V3 contracts"
```

### Task 2: Add the lease-bound GitHub builder provider

**Files:**
- Create: `liltweak/providers/github/runner_v3.py`
- Test: `tests/test_runner_v3_provider.py`

**Interfaces:**
- Consumes: Task 1 contracts and existing `ExecutionLeaseRegistry`, `ResourceExecutionContractV2`, `ProviderRuntimeState`, and provider result types.
- Produces: `GitHubRunnerV3Provider` implementing `ExecutionProvider`.
- Constructor accepts `manifest_factory: Callable[[ResourceExecutionContractV2, ExecutionLease], RunnerV3JobManifest]`.

- [ ] **Step 1: Write failing provider tests**

Cover inactive, stale, unqualified, disconnected, wrong provider, wrong resource type, wrong profile, wrong repository, production, deployment, secrets, persistent workspace, browser, Docker, GPU, duplicate execution, replayed lease, forged manifest binding, successful dispatch, failed snapshot, cancellation, collection, and destruction.

A successful collection must assert:

```python
assert result.status is ProviderExecutionStatus.SUCCEEDED
assert result.verification_outcome is VerificationOutcome.NOT_APPLICABLE
assert result.evidence_digest == snapshot.receipt_digest
assert "independent verification" in result.reason
```

- [ ] **Step 2: Run provider tests and verify RED**

```bash
uv run --no-sync --offline pytest -q tests/test_runner_v3_provider.py
```

Expected: import failure because `runner_v3.py` does not exist.

- [ ] **Step 3: Implement the provider**

Mirror the established GitHub verifier adapter's qualification and health behavior, but report `builder=True` and `independent_verifier=False`. Consume the execution lease exactly once before dispatch. Validate every manifest field against the contract and lease before calling `RunnerV3Client.dispatch_job(...)`. Keep operation state local and reject duplicate execution IDs.

- [ ] **Step 4: Run focused tests and static checks**

```bash
uv run --no-sync --offline pytest -q tests/test_runner_v3_provider.py tests/test_execution_lease.py
uv run --no-sync --offline ruff check liltweak/providers/github/runner_v3.py tests/test_runner_v3_provider.py
uv run --no-sync --offline ruff format --check liltweak/providers/github/runner_v3.py tests/test_runner_v3_provider.py
uv run --no-sync --offline mypy liltweak/providers/github/runner_v3.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add liltweak/providers/github/runner_v3.py tests/test_runner_v3_provider.py
git commit -m "feat: add GitHub Runner V3 provider"
```

### Task 3: Build the fixed-action ephemeral executor

**Files:**
- Create: `liltweak/providers/github/runner_v3_executor.py`
- Create: `scripts/runner_v3.py`
- Test: `tests/test_runner_v3_executor.py`

**Interfaces:**
- Consumes: `RunnerV3JobManifest` and receipt types from Task 1.
- Produces: `RunnerV3Executor.execute(manifest, *, workspace, output_directory, cancellation_requested) -> RunnerV3Receipt`.
- Produces CLI: `python scripts/runner_v3.py --manifest PATH --workspace PATH --output-directory PATH`.

- [ ] **Step 1: Write failing executor tests**

Use temporary Git repositories. Cover exact source inspection, source-tree mismatch, clean read-only execution, optional patch application, unauthorized changed path, symlink rejection, patch digest mismatch, fixed command mapping, no arbitrary executable input, failing step short-circuit, timeout, cancellation, output truncation, candidate patch generation, source mutation evidence, and deterministic receipt digest.

- [ ] **Step 2: Run executor tests and verify RED**

```bash
uv run --no-sync --offline pytest -q tests/test_runner_v3_executor.py
```

Expected: import failure because the executor does not exist.

- [ ] **Step 3: Implement source and patch guards**

Validate `git rev-parse HEAD`, `HEAD^{tree}`, and clean status before work. Parse only `diff --git a/<path> b/<path>` headers, reject renames and unsafe paths, require the touched path set to equal the manifest's authorized path set, run `git apply --check`, apply the patch, and reject symlinks before and after mutation.

- [ ] **Step 4: Implement fixed actions and bounded process control**

Map enum values to internal functions or exact tuples only:

```python
RunnerV3Action.COMPILE_PYTHON: (sys.executable, "-m", "compileall", "-q", "liltweak", "scripts")
RunnerV3Action.PYTEST: (sys.executable, "-m", "pytest", "-q")
RunnerV3Action.RUFF_CHECK: ("ruff", "check", ".")
RunnerV3Action.RUFF_FORMAT_CHECK: ("ruff", "format", "--check", ".")
RunnerV3Action.MYPY: ("mypy",)
RunnerV3Action.BUILD_PACKAGE: ("uv", "build", "--offline", "--out-dir", build_directory)
```

Use a new process group, poll cancellation, kill the group on timeout/cancellation/output overflow, bound stdout and stderr separately, and clear model/provider credentials from the child environment.

- [ ] **Step 5: Emit exact evidence artifacts**

Write canonical JSON receipts, one JSON step record per action, and `candidate.patch` only when the workspace changed. Recheck changed paths and source state before issuing the final receipt.

- [ ] **Step 6: Run focused tests and static checks**

```bash
uv run --no-sync --offline pytest -q tests/test_runner_v3_executor.py
uv run --no-sync --offline ruff check liltweak/providers/github/runner_v3_executor.py scripts/runner_v3.py tests/test_runner_v3_executor.py
uv run --no-sync --offline ruff format --check liltweak/providers/github/runner_v3_executor.py scripts/runner_v3.py tests/test_runner_v3_executor.py
uv run --no-sync --offline mypy liltweak/providers/github/runner_v3_executor.py scripts/runner_v3.py
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add liltweak/providers/github/runner_v3_executor.py scripts/runner_v3.py tests/test_runner_v3_executor.py
git commit -m "feat: add bounded Runner V3 executor"
```

### Task 4: Add the first factory profile and GitHub workflow

**Files:**
- Create: `liltweak/providers/github/runner_v3_profile.py`
- Create: `scripts/runner_v3_smoke_manifest.py`
- Create: `.github/workflows/runner-v3.yml`
- Test: `tests/test_runner_v3_profile.py`
- Test: `tests/test_runner_v3_workflow.py`

**Interfaces:**
- Produces: `github_runner_v3_profile(...) -> ResourceProfile` with conservative unqualified capacity and no GPU/browser/Docker/secrets/production/deployment capabilities.
- Produces: a workflow-dispatch runner and pull-request smoke path.

- [ ] **Step 1: Write failing profile and workflow tests**

Assert the exact profile ID, GitHub Actions resource type, ephemeral writable workspace, source-write capability limited to the ephemeral checkout, conservative capacity, disabled/unqualified defaults, and no production capabilities.

Parse the workflow as YAML and assert `permissions.contents == "read"`, `persist-credentials == false`, pinned actions, exact toolchain, bounded timeout, artifact upload, cleanup, and absence of `cloudflare`, `vercel`, `digitalocean`, `wrangler`, `ssh`, `OPENAI_API_KEY` use, `contents: write`, deployment, push, and merge commands.

- [ ] **Step 2: Run tests and verify RED**

```bash
uv run --no-sync --offline pytest -q tests/test_runner_v3_profile.py tests/test_runner_v3_workflow.py
```

Expected: missing files.

- [ ] **Step 3: Implement the conservative factory profile**

Declare 2 CPU, 7,000 MB memory, 14,000 MB disk, parallel limit 1, 30-minute maximum duration, zero GPU/browser/Docker/network/dynamic-package/secrets/production/deployment capabilities, and `EPHEMERAL_WRITABLE` workspace. Leave qualification and health unproven by default.

- [ ] **Step 4: Implement smoke-manifest generation and workflow**

The smoke manifest binds the current checkout's commit and tree, uses `inspect_source`, `compile_python`, and `git_diff`, makes no patch, and expires within 30 minutes. The workflow chooses the dispatched manifest for real jobs and generates the smoke manifest for pull requests. It uploads evidence with one-day retention and fails when evidence is absent.

- [ ] **Step 5: Run focused tests and static checks**

```bash
uv run --no-sync --offline pytest -q tests/test_runner_v3_profile.py tests/test_runner_v3_workflow.py
uv run --no-sync --offline ruff check liltweak/providers/github/runner_v3_profile.py scripts/runner_v3_smoke_manifest.py tests/test_runner_v3_profile.py tests/test_runner_v3_workflow.py
uv run --no-sync --offline ruff format --check liltweak/providers/github/runner_v3_profile.py scripts/runner_v3_smoke_manifest.py tests/test_runner_v3_profile.py tests/test_runner_v3_workflow.py
uv run --no-sync --offline mypy liltweak/providers/github/runner_v3_profile.py scripts/runner_v3_smoke_manifest.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add liltweak/providers/github/runner_v3_profile.py scripts/runner_v3_smoke_manifest.py .github/workflows/runner-v3.yml tests/test_runner_v3_profile.py tests/test_runner_v3_workflow.py
git commit -m "feat: add first GitHub runner factory profile"
```

### Task 5: Prove integration and preserve release evidence

**Files:**
- Modify only if required: `README.md`
- Create temporarily, then delete in its own finalizing commit: `.github/workflows/runner-v3-finalize.yml`
- Regenerate: `BUILD_PROVENANCE.json`
- Regenerate: `DEPENDENCY_SECURITY_SCAN_REPORT.json`
- Regenerate: `SUPPLY_CHAIN_SBOM.json`
- Regenerate: `LICENSE_INVENTORY.json`
- Regenerate: `FINAL_FILE_MANIFEST.json`

**Interfaces:**
- Produces: exact-candidate deterministic evidence and an open draft PR.

- [ ] **Step 1: Run the complete local-equivalent suite in GitHub Actions**

```bash
uv lock --check --offline
uv sync --locked --group dev --python 3.12.13
uv run --no-sync --offline ruff check .
uv run --no-sync --offline ruff format --check .
uv run --no-sync --offline mypy
uv run --no-sync --offline pytest
uv build --offline
```

Expected: all code and tests pass before evidence comparison.

- [ ] **Step 2: Regenerate deterministic evidence on the exact branch**

Use the repository's existing generators with the exact pinned environment, remove the temporary finalizer before final manifest generation, and commit only the generated evidence plus finalizer deletion.

- [ ] **Step 3: Open a draft pull request**

The PR body must state exact scope, head SHA, test counts, Runner V3 smoke evidence, read-only permission boundary, PR #12 preservation, and remaining live-qualification boundary.

- [ ] **Step 4: Verify the exact PR head**

Require the master deterministic workflow and Runner V3 workflow to pass. Review changed files for unrelated edits, inspect workflow permissions, and confirm no secret-like material.

- [ ] **Step 5: Leave merge decision separate**

Do not merge automatically. Report `SOURCE TESTED` only when exact-head CI passes. Report `LIVE UNQUALIFIED` until an actual authorized `workflow_dispatch` run has been collected and reviewed.