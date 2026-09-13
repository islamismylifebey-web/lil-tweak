# GitHub-Hosted Runner Activation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Repair and harden Lil' Tweak's GitHub Actions backend so it can be activated on GitHub-hosted Ubuntu without enrolling the personal control workstation as a self-hosted runner.

**Architecture:** Capture immutable Git commit/tree identity before sanitizing the source, carry it through orchestration, and bind it into an exact-run GitHub dispatch and receipt. Run trusted control code from a separate workflow checkout, make npm verification self-contained, and align production secret validation, documentation, and the canonical Linux verification gate.

**Tech Stack:** Python 3.12 standard library and unittest, GitHub Actions on ubuntu-24.04, Node.js 24, npm, Node test runner.

**Spec:** docs/superpowers/specs/2026-09-12-github-runner-activation-design.md

## Global Constraints

- Do not install or register a self-hosted GitHub Actions runner on the personal control workstation.
- .github/workflows/tueiq-runner.yml must retain runs-on: ubuntu-24.04 and permissions: contents: read.
- All third-party GitHub Actions references remain pinned to full commit SHAs.
- The production dispatch targets ref main, requests return_run_details: true, accepts HTTP 200, and tracks only the returned positive non-boolean workflow_run_id.
- The status window is 360 polls at 5 seconds, matching the workflow's 30-minute timeout; exhaustion attempts cancellation of the exact run.
- Manifest schema names remain lil-tweak-github-runner-manifest-v1 and lil-tweak-github-runner-receipt-v1.
- Git object IDs accepted at intake are lowercase 40- or 64-hex values of equal width; the GitHub manifest remains restricted to GitHub's 40-hex commit/tree identifiers.
- GitHub repository slugs have exactly two non-dot components matching [A-Za-z0-9_.-]+. GitHub source URLs allow only HTTPS github.com, no credentials/query/fragment, port omitted or 443, optional trailing slash, and optional .git suffix.
- No new production dependency is allowed.
- Secrets, subprocess output, manifest contents, patches, and token values must not appear in stable public errors or logs.
- local_podman remains the shipped default. github_actions is an explicit opt-in requiring repository and token; dormant GitHub credentials in local mode are rejected.
- Follow TDD: observe the focused test fail before changing production code, then record the focused green run and one broader regression run in the task report.
- Do not push, merge, deploy, or create credentials during implementation.

---

### Task 1: Preserve immutable Git identity through orchestration

**Files:**

- Modify: core/lil_tweak/git_source.py
- Modify: core/main.py
- Modify: core/lil_tweak/orchestrator.py
- Modify: core/lil_tweak/github_runner.py
- Modify: core/lil_tweak/test_world_runtime.py
- Test: core/tests/test_git_source.py
- Test: core/tests/test_main.py
- Test: core/tests/test_orchestrator.py
- Test: core/tests/test_github_runner.py
- Test: core/tests/test_test_world_runtime.py

**Interfaces:**

- Produces: GitIntakeResult(inventory: tuple[str, ...], source_commit: str, source_tree: str).
- Produces: EngineeringOrchestrator.run_job(..., source_commit: str | None = None, source_tree: str | None = None).
- Produces: GitHubPatchVerifier.verify(..., source_commit: str, source_tree: str) with no workspace Git fallback.
- Consumes: GitSourceSpec.commit and the existing sanitized workspace/inventory flow.

- [ ] **Step 1: Write failing Git intake identity tests**

Add a deterministic executor that returns the requested commit for rev-parse HEAD and a distinct tree for rev-parse HEAD^{tree}. Assert the returned object, immutable tuple inventory, and post-intake .git removal:

~~~python
result = ingest_git_source(source, destination, allowed_hosts=("git.example",), execute=execute, resolve=resolve)
self.assertEqual(result.source_commit, "a" * 40)
self.assertEqual(result.source_tree, "b" * 40)
self.assertEqual(result.inventory, ("README.md",))
self.assertFalse((destination / ".git").exists())
~~~

Add subtests for uppercase, nonhex, wrong-length, and unequal-width rev-parse results. Each must raise GitIntakeError and remove the destination.

- [ ] **Step 2: Run the intake test and capture RED**

Run:

~~~text
python3 -B -m unittest core.tests.test_git_source -v
~~~

Expected: the success case fails because ingest_git_source still returns list[str] and never resolves HEAD^{tree}; malformed tree cases do not fail closed.

- [ ] **Step 3: Implement the typed intake result before .git removal**

Add the frozen result and exact object-ID validation:

~~~python
@dataclass(frozen=True, slots=True)
class GitIntakeResult:
    inventory: tuple[str, ...]
    source_commit: str
    source_tree: str

def _object_id(value: str) -> str:
    normalized = value.strip()
    if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", normalized) is None:
        raise GitIntakeError("git_identity_invalid")
    return normalized
~~~

Resolve HEAD and HEAD^{tree}, require commit equality and matching widths, remove .git, then return GitIntakeResult(tuple(_bounded_inventory(...)), resolved_commit, resolved_tree). Keep existing cleanup behavior for every failure.

- [ ] **Step 4: Write failing propagation and fail-closed tests**

In main/orchestrator tests, use GitIntakeResult(("README.md",), commit, tree). Assert execute_job forwards inventory, source_commit, and source_tree. Extend the fake verifier to record exact kwargs and add missing/partial identity subtests:

~~~python
self.assertEqual(verifier.calls[0]["source_commit"], commit)
self.assertEqual(verifier.calls[0]["source_tree"], tree)
for source_commit, source_tree in ((None, None), (commit, None), (None, tree)):
    with self.subTest(source_commit=source_commit, source_tree=source_tree):
        with self.assertRaisesRegex(ValueError, "verified Git source identity"):
            orchestrator.run_job(..., source_commit=source_commit, source_tree=source_tree)
~~~

Update Test World expectations so prepare_workspace consumes GitIntakeResult.inventory without gaining remote-verifier authority.

- [ ] **Step 5: Run propagation tests and capture RED**

Run:

~~~text
python3 -B -m unittest core.tests.test_main core.tests.test_orchestrator core.tests.test_test_world_runtime core.tests.test_github_runner -v
~~~

Expected: unexpected result/keyword failures and the verifier's existing workspace rev-parse fallback are observed.

- [ ] **Step 6: Carry identity through main and orchestrator**

Change prepare_sources and execute_job to accept GitIntakeResult | list[str], normalize it once, and pass the exact pair into run_job. Add optional identity parameters to EngineeringOrchestrator.run_job. When runner_verifier is active for a non-chat job, require job.git_source, workspace, source_commit, and source_tree before calling:

~~~python
runner_receipt = self.runner_verifier.verify(
    job=job,
    patch=patch,
    baseline_digest=baseline.source_digest,
    final_digest=final.source_digest,
    source_commit=source_commit,
    source_tree=source_tree,
)
~~~

The verifier must not receive or inspect workspace for identity.

- [ ] **Step 7: Bind the trusted identity into GitHub verification**

Make source_commit and source_tree required verifier keyword arguments. Require source_commit == job.git_source.commit. Remove subprocess_run_git and its import path. Add sourceTree to the canonical authority payload and pass both trusted values into RunnerManifest.issue. Add a regression assertion that changing only source_tree changes authority_digest.

- [ ] **Step 8: Run focused and broader tests**

Run:

~~~text
python3 -B -m unittest core.tests.test_git_source core.tests.test_main core.tests.test_orchestrator core.tests.test_github_runner core.tests.test_test_world_runtime -v
python3 -B -m unittest discover -s core/tests -p "test_*.py"
~~~

Expected: focused tests pass with pristine output. Record any host-only failures from the broader suite separately; do not describe them as product passes.

- [ ] **Step 9: Commit**

~~~text
git add core/lil_tweak/git_source.py core/main.py core/lil_tweak/orchestrator.py core/lil_tweak/github_runner.py core/lil_tweak/test_world_runtime.py core/tests/test_git_source.py core/tests/test_main.py core/tests/test_orchestrator.py core/tests/test_github_runner.py core/tests/test_test_world_runtime.py
git commit -m "fix: preserve Git source identity for remote verification"
~~~

### Task 2: Bind GitHub dispatch to one exact run and harden boundary parsing

**Files:**

- Modify: core/lil_tweak/github_runner.py
- Modify: core/lil_tweak/config.py
- Test: core/tests/test_github_runner.py
- Test: core/tests/test_config.py

**Interfaces:**

- Consumes: Task 1's required source_commit and source_tree verifier inputs.
- Produces: GitHubActionsRunner.execute dispatches with return_run_details and polls _wait_for_run(run_id, manifest).
- Produces: a shared behavioral repository-slug contract across runtime configuration and verifier URL parsing.

- [ ] **Step 1: Write failing exact-run dispatch tests**

Replace list-based fake responses with a 200 dispatch body containing workflow_run_id: 44 followed by exact run status. Assert the request body and paths:

~~~python
self.assertTrue(dispatch_body["return_run_details"])
self.assertEqual(request_paths, [
    "/actions/workflows/tueiq-runner.yml/dispatches",
    "/actions/runs/44",
    "/actions/runs/44/artifacts",
    "/actions/artifacts/91/zip",
])
~~~

Add subtests for missing, string, boolean, zero, and negative workflow_run_id. Add run metadata rejection for wrong id, event, or display_title. Add a timeout test with 360 queued responses that asserts 360 five-second sleeps and one POST /actions/runs/44/cancel.

- [ ] **Step 2: Run exact-run tests and capture RED**

Run:

~~~text
python3 -B -m unittest core.tests.test_github_runner.GitHubRunnerTests -v
~~~

Expected: current code expects 204, lists runs by title, accepts ambiguous IDs, and never cancels the timed-out exact run.

- [ ] **Step 3: Implement exact dispatch correlation**

Send this top-level body shape:

~~~python
{
    "ref": "main",
    "return_run_details": True,
    "inputs": {
        "execution_id": manifest.execution_id,
        "expected_commit": manifest.source_commit,
        "manifest_base64": encoded,
        "manifest_digest": manifest.manifest_digest,
        "acknowledge_builder_only": "true",
    },
}
~~~

Require status 200, parse a mapping, and accept workflow_run_id only when type(value) is int and value > 0. Poll GET /actions/runs/{run_id} for exactly 360 attempts with five-second sleeps between incomplete attempts. Validate id, event == "workflow_dispatch", and display_title == "Tueiq Runner {execution_id}" before using status/conclusion. On exhaustion, attempt POST /actions/runs/{run_id}/cancel and raise GitHubRunnerError("GitHub runner timed out") regardless of cancel response or error.

- [ ] **Step 4: Write failing manifest and receipt type tests**

Table-test each scalar replaced by a list, authorizedPaths/actions replaced by non-lists or containing non-strings, and parse called with a non-mapping. Table-test receipt steps containing None, missing/extra fields, boolean exit codes, and non-string digests. Every case must raise GitHubRunnerError rather than TypeError, AttributeError, or a successful coercion.

- [ ] **Step 5: Implement defensive shape validation**

Before datetime parsing or tuple conversion, require the exact key set, a string for every manifest scalar, and list[str] for both arrays. In verify_receipt, require receiptDigest to be a string, steps to be list[Mapping[str, object]], every step to have exactly action and exitCode, action to be a string, and type(exitCode) is int. Preserve digest comparison only after those checks.

- [ ] **Step 6: Write failing repository URL and slug tests**

Accept the configured repository when the job URL is any safe case variant of:

~~~text
https://github.com/OWNER/REPOSITORY
https://github.com/OWNER/REPOSITORY/
https://github.com/OWNER/REPOSITORY.git
https://github.com:443/OWNER/REPOSITORY.git/
~~~

Reject credentials, query, fragment, non-443 explicit ports, encoded separators, double/extra path components, and owner/repository components equal to "." or "..". Add Config tests rejecting dot aliases and dormant GitHub credentials under local_podman.

- [ ] **Step 7: Implement structural GitHub URL parsing and aligned runtime validation**

Use urlsplit, catch invalid port access, validate host and path without unquoting, remove only one optional trailing slash and one case-insensitive .git suffix, then compare casefolded owner/repository with the configured slug. Emit self._runner.repository into the manifest. Replace the permissive slug regex with a helper that requires exactly two safe non-dot components. Apply the same rule in Config and reject token/repository presence unless execution_backend == "github_actions".

- [ ] **Step 8: Run focused and broader tests**

Run:

~~~text
python3 -B -m unittest core.tests.test_github_runner core.tests.test_config -v
python3 -B -m unittest discover -s core/tests -p "test_*.py"
~~~

Expected: focused tests pass with pristine output; broader results are recorded exactly.

- [ ] **Step 9: Commit**

~~~text
git add core/lil_tweak/github_runner.py core/lil_tweak/config.py core/tests/test_github_runner.py core/tests/test_config.py
git commit -m "fix: bind GitHub verification to exact workflow runs"
~~~

### Task 3: Isolate trusted workflow control code and make npm verification self-contained

**Files:**

- Modify: .github/workflows/tueiq-runner.yml
- Modify: scripts/tueiq_github_runner.py
- Test: core/tests/test_github_runner_job.py
- Create: core/tests/test_github_runner_workflow.py

**Interfaces:**

- Consumes: RunnerManifest.parse and the exact source commit/tree contract from Tasks 1 and 2.
- Produces: workflow directories named control and source; the runner receives source as --workspace and imports only from control.
- Produces: npm_verify runs npm ci and then npm run verify, returning one bounded integer result.

- [ ] **Step 1: Write failing runner subprocess tests**

Mock subprocess.run and assert npm_verify calls exactly npm ci before npm run verify in the same workspace and scrubbed environment. Assert an npm ci nonzero result skips verify. Assert TimeoutExpired from either npm command returns a fixed nonzero integer and the CLI guard prints only Tueiq GitHub runner failed.

- [ ] **Step 2: Run runner tests and capture RED**

Run:

~~~text
python3 -B -m unittest core.tests.test_github_runner_job -v
~~~

Expected: only npm run verify is called and TimeoutExpired escapes the current CLI guard.

- [ ] **Step 3: Implement bounded npm installation and subprocess failures**

For npm_verify, invoke ("npm", "ci") first with timeout=1200 and the existing scrubbed environment. Return its nonzero code without invoking verify; otherwise invoke ("npm", "run", "verify") with the same workspace, timeout, and environment. Catch subprocess.SubprocessError inside action execution and convert it to a fixed nonzero action result. Include subprocess.SubprocessError in main's stable failure guard for failures that occur outside an action result.

- [ ] **Step 4: Write the failing workflow trust contract test**

Parse the workflow as text and assert:

- runs-on remains exactly ubuntu-24.04 and permissions remain contents: read.
- checkout appears twice with distinct paths control and source.
- the control ref contains github.workflow_sha.
- the source ref contains inputs.expected_commit for dispatch and pull_request.head.sha for the canary.
- PYTHONPATH and the executed script resolve from the control directory.
- every Git identity command and --workspace resolve against the source directory.
- actions/setup-node uses the repository's existing full pinned SHA and node-version "24".
- no self-hosted label appears.

- [ ] **Step 5: Run the workflow contract and capture RED**

Run:

~~~text
python3 -B -m unittest core.tests.test_github_runner_workflow -v
~~~

Expected: the workflow has one checkout, executes candidate scripts from GITHUB_WORKSPACE, and has no Node setup.

- [ ] **Step 6: Split trusted control and candidate source checkouts**

Use the existing pinned checkout action twice. The first checkout uses ref: ${{ github.workflow_sha }} and path: control. The second uses the existing event-dependent immutable source ref and path: source. Set PYTHONPATH to the absolute control directory for manifest preparation. Run all rev-parse commands with git -C against source. Execute the absolute control/scripts/tueiq_github_runner.py with --workspace pointing to source. Preserve the existing empty OpenAI key, disabled live model, read-only permissions, 30-minute timeout, manifest cleanup, and receipt artifact behavior.

- [ ] **Step 7: Add pinned Node 24 setup**

Insert actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 with node-version: "24" before executing the bounded job. Keep all third-party action references as full SHAs.

- [ ] **Step 8: Run focused and broader tests**

Run:

~~~text
python3 -B -m unittest core.tests.test_github_runner_job core.tests.test_github_runner_workflow -v
python3 -B -m unittest discover -s core/tests -p "test_github_runner*.py"
~~~

Expected: focused tests and the runner group pass with pristine output.

- [ ] **Step 9: Commit**

~~~text
git add .github/workflows/tueiq-runner.yml scripts/tueiq_github_runner.py core/tests/test_github_runner_job.py core/tests/test_github_runner_workflow.py
git commit -m "fix: isolate trusted GitHub runner control code"
~~~

### Task 4: Align production activation, documentation, and the canonical gate

**Files:**

- Modify: scripts/lil-tweak-secret-snapshot.py
- Modify: deploy/core.env.example
- Modify: deploy/tests/test_secret_snapshot.py
- Modify: tests/deployment-contract.test.mjs
- Modify: package.json
- Modify: README.md
- Modify: docs/operations/digitalocean.md

**Interfaces:**

- Consumes: Task 2's repository-slug rules and the existing Config backend values local_podman and github_actions.
- Produces: required staged LIL_TWEAK_EXECUTION_BACKEND plus conditional GitHub repository/token validation.
- Produces: npm scripts test:deploy and verify with deployment tests included.

- [ ] **Step 1: Write failing secret-snapshot mode tests**

Add LIL_TWEAK_EXECUTION_BACKEND=local_podman to valid_core_environment. Add a successful github_actions case with islamismylifebey-web/lil-tweak and a 40-byte test token; assert the output core.env is byte-for-byte identical and stdout contains only the runner image. Add rejection subtests for missing/unknown/case-mismatched backend, partial credentials, token under 32 UTF-8 bytes, invalid repository shapes including dot aliases, and any GitHub credential under local_podman. Reuse assert_rejected so every rejection proves zero partial output and no token disclosure.

- [ ] **Step 2: Run snapshot tests and capture RED**

On Ubuntu/POSIX, run:

~~~text
python3 -B -m unittest discover -s deploy/tests -p "test_secret_snapshot.py" -v
~~~

Expected: the current parser rejects the new names as unknown, fails the valid remote case, and does not enforce the backend matrix.

- [ ] **Step 3: Implement the fail-closed staged environment matrix**

Make LIL_TWEAK_EXECUTION_BACKEND required and add LIL_TWEAK_GITHUB_REPOSITORY and LIL_TWEAK_GITHUB_TOKEN to the optional allowlist. Keep ASSIGNMENT_PATTERN nonempty. Validate:

~~~python
backend = values["LIL_TWEAK_EXECUTION_BACKEND"]
repository = values.get("LIL_TWEAK_GITHUB_REPOSITORY")
token = values.get("LIL_TWEAK_GITHUB_TOKEN")
if backend == "github_actions":
    if repository is None or not _valid_github_repository(repository) or token is None or len(token.encode("utf-8")) < 32:
        raise SnapshotError
elif backend != "local_podman" or repository is not None or token is not None:
    raise SnapshotError
~~~

The helper must use the same exact two safe non-dot component rule as Task 2. Do not print the rejected value.

- [ ] **Step 4: Fix the shipped example and write static contract tests**

Keep the active line LIL_TWEAK_EXECUTION_BACKEND=local_podman. Replace active empty credentials with comments:

~~~dotenv
# github_actions only: change the backend above and uncomment both reviewed values.
# LIL_TWEAK_GITHUB_REPOSITORY=OWNER/REPOSITORY
# LIL_TWEAK_GITHUB_TOKEN=REPLACE
~~~

In tests/deployment-contract.test.mjs assert those settings, the documented conditional contract, package.json's test:deploy command, and verify invoking npm run test:deploy.

- [ ] **Step 5: Run the Node contract and capture RED**

Run:

~~~text
node --test --test-name-pattern="GitHub Actions|package verification" tests/deployment-contract.test.mjs
~~~

Expected: active empty credential lines remain and package verification omits deploy tests.

- [ ] **Step 6: Add deployment tests to the canonical Linux gate**

Add:

~~~json
"test:deploy": "PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s deploy/tests -p 'test_*.py'",
"verify": "npm run typecheck && npm run lint && npm test && npm run test:core && npm run test:deploy"
~~~

Changing package scripts does not require a package-lock update.

- [ ] **Step 7: Document explicit activation and credential handling**

Update README.md and docs/operations/digitalocean.md to state:

- local_podman is the default; GitHub Actions requires all three reviewed settings.
- invalid/partial settings and dormant GitHub credentials in local mode fail before mutation.
- GitHub-source jobs require LIL_TWEAK_GIT_ALLOWED_HOSTS=github.com.
- the token is repository-scoped, expiring, least-privilege Actions read/write, server-only, and included in the rotation runbook.
- readiness does not contact GitHub; activation requires one controlled dispatch/receipt after Linux verification.
- npm run verify includes POSIX deployment security tests and is authoritative on Ubuntu.
- the personal control workstation is not part of the runner execution boundary.

- [ ] **Step 8: Run focused and canonical verification**

Run locally where supported:

~~~text
python3 -B -m unittest discover -s deploy/tests -p "test_secret_snapshot.py" -v
node --test tests/deployment-contract.test.mjs
git diff --check
~~~

Run on Ubuntu 24.04 before activation:

~~~text
npm ci
npm run verify
scripts/install-lil-tweak-release.sh --check
bash scripts/verify-deployment.sh --check
~~~

Expected: all canonical commands pass with pristine output. A native-Windows POSIX failure is an environment limitation and cannot substitute for the Ubuntu gate.

- [ ] **Step 9: Commit**

~~~text
git add scripts/lil-tweak-secret-snapshot.py deploy/core.env.example deploy/tests/test_secret_snapshot.py tests/deployment-contract.test.mjs package.json README.md docs/operations/digitalocean.md
git commit -m "fix: validate GitHub runner production activation"
~~~

### Task 5: Final integration verification

**Files:**

- Modify only if a test exposes a regression in files already named by Tasks 1 through 4.
- Test: all repository verification surfaces.

**Interfaces:**

- Consumes: the complete source identity, exact dispatch, trusted workflow, runner execution, and deployment contracts.
- Produces: one reviewed branch that is ready for a user-authorized push and Linux CI, but is not yet deployed.

- [ ] **Step 1: Run cross-component focused tests**

~~~text
python3 -B -m unittest core.tests.test_git_source core.tests.test_main core.tests.test_orchestrator core.tests.test_github_runner core.tests.test_github_runner_job core.tests.test_github_runner_workflow core.tests.test_config -v
node --test tests/deployment-contract.test.mjs
~~~

Expected: all supported focused tests pass with pristine output.

- [ ] **Step 2: Run static and language checks**

~~~text
npm run typecheck
npm run lint
git diff --check
python3 -B -m compileall -q core scripts
~~~

Expected: every command exits zero.

- [ ] **Step 3: Record the platform-limited canonical check**

On Ubuntu 24.04, run npm ci followed by npm run verify and both deployment --check commands from Task 4. If this checkout remains on native Windows, do not fake the POSIX result: record it as pending GitHub-hosted CI and retain the branch for user-authorized push.

- [ ] **Step 4: Commit only test-driven integration fixes**

If Step 1 or Step 2 required a production change, first add a focused failing regression test, observe RED, implement the minimal fix, rerun GREEN, and commit:

~~~text
git add -u
git commit -m "fix: close GitHub runner integration regression"
~~~

If no files changed, record that no Task 5 commit was necessary.
