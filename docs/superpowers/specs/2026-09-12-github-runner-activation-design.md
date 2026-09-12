# GitHub-Hosted Runner Activation Design

## Context

Lil' Tweak already has a GitHub Actions execution backend, but the merged implementation cannot yet be activated safely. The source checkout removes its .git directory before orchestration, while remote verification later attempts to recover the source tree from that sanitized workspace. The workflow also runs its manifest parser and runner script from the candidate source commit, which lets candidate code redefine the verifier. Dispatch correlation is based only on a display title, npm dependencies are not installed, malformed external data is not uniformly rejected, and the production secret snapshot does not accept the settings required to select the backend.

The personal control workstation must not be registered as a self-hosted GitHub Actions runner. The repository is public, so running public pull-request code on a persistent personal machine would create an unnecessary host-compromise path.

## Goal

Make the existing GitHub Actions backend a fail-closed, testable production option that runs only on GitHub-hosted Ubuntu infrastructure and preserves an exact, trusted binding from immutable Git intake through the final receipt.

## Non-goals

- Do not install, register, or configure a self-hosted runner on the personal control workstation.
- Do not change the normal local_podman execution path.
- Do not merge, deploy, create production credentials, or push this branch as part of local implementation.
- Do not claim production activation until a user-authorized push is followed by the repository's Linux checks and one controlled workflow-dispatch receipt.
- Do not turn the GitHub receipt into independent verification. It remains builder evidence bound to owner authorization.

## Security invariants

1. The workflow job continues to use runs-on: ubuntu-24.04. No self-hosted label may be introduced.
2. Immutable Git intake resolves and validates both the source commit and its tree before deleting .git. Those identities travel as typed host data; no later component may rediscover them from the editable workspace or a parent repository.
3. Remote verification requires both identities. The verified commit must equal the job's requested immutable commit, and sourceTree is included in the authority digest.
4. A production dispatch targets the reviewed main workflow and requests return_run_details. The client accepts only a positive, non-boolean workflow_run_id, then polls and, on timeout, cancels that exact run ID. It never correlates by a list result or display title alone.
5. External JSON is validated before conversion or dereference. Manifest scalars are strings, authorizedPaths and actions are arrays of strings, receipt steps are exact mappings, and exitCode values are integers but never booleans.
6. GitHub repository URLs are parsed structurally. Only HTTPS github.com URLs with no credentials, query, or fragment, default port or 443, exactly two safe non-dot path components, and optional trailing slash or .git suffix are accepted. Matching is case-insensitive, while the configured owner/repository spelling is emitted canonically.
7. The workflow checks out its control implementation at github.workflow_sha into a dedicated directory and checks out expected_commit into a separate source directory. Manifest parsing, PYTHONPATH, and the executed script come only from the control checkout.
8. All third-party actions remain pinned to full commit SHAs. Node is explicitly configured at version 24. npm_verify runs npm ci before npm run verify inside the candidate source checkout with the existing scrubbed environment and bounded timeouts.
9. Subprocess timeouts and other subprocess failures produce a controlled nonzero result or the stable public runner failure message; no traceback or command output is exposed.
10. Production secret staging requires an explicit LIL_TWEAK_EXECUTION_BACKEND. local_podman forbids dormant GitHub credentials. github_actions requires both a valid owner/repository slug and a token of at least 32 UTF-8 bytes. The token is never printed.
11. npm run verify includes the deployment security test suite. That canonical full gate is Linux/POSIX-only and must run on Ubuntu before activation.

## Design

### Trusted source identity

core.lil_tweak.git_source defines a frozen GitIntakeResult with tuple inventory, source_commit, and source_tree. ingest_git_source obtains HEAD and HEAD^{tree} before removing .git, validates lowercase 40- or 64-hex object IDs of the same width, and requires the resolved commit to equal GitSourceSpec.commit. Cleanup remains fail closed.

prepare_sources returns either GitIntakeResult for Git intake or the existing R2 inventory. execute_job normalizes that result and forwards the inventory plus optional source_commit and source_tree. EngineeringOrchestrator requires the pair when a non-chat job uses the GitHub verifier and passes them to GitHubPatchVerifier. Test World intake consumes result.inventory because Test Worlds do not dispatch the production GitHub verifier.

GitHubPatchVerifier no longer accepts a missing identity and removes the git subprocess fallback. It rejects a verified commit that differs from the job source, includes sourceTree in the authority payload, and uses the configured canonical repository slug.

### Exact dispatch and defensive boundary

GitHubActionsRunner sends return_run_details: true at the top level of the workflow-dispatch body. A 200 response must contain one valid workflow_run_id. Status polling uses GET /actions/runs/{id}, validates that ID, workflow_dispatch event, and expected display title, waits up to the workflow's 30-minute ceiling, and collects artifacts only after successful completion. Exhaustion attempts POST /actions/runs/{id}/cancel and then reports a timeout without trusting the cancellation response.

The existing 10-minute manifest expiry remains the admission window. It does not cap the execution after the workflow has admitted the manifest.

### Trusted control checkout

The hosted job uses two checkout directories:

- control: the repository revision identified by github.workflow_sha; it supplies core.lil_tweak.github_runner and scripts/tueiq_github_runner.py.
- source: the immutable candidate commit; it is the only workspace that receives the patch and runs validation.

The PR canary still tests changes to the runner implementation because github.workflow_sha for that event identifies the workflow revision being exercised. Production workflow_dispatch targets main, so candidate source cannot replace the control parser or runner.

### Production activation contract

deploy/core.env.example keeps local_podman as the active default and comments the two GitHub-only settings. The snapshot parser keeps its nonempty assignment grammar, accepts the three reviewed names, and validates the selected mode before any output is created. Runtime Config rejects dormant GitHub credentials under local mode and uses the same safe repository-slug grammar.

Documentation describes GitHub Actions as an explicit three-setting opt-in, the required github.com intake allowlist, least-privilege repository-scoped credentials, rotation, and the controlled activation check.

## Verification

Focused Python and Node tests cover every new failure mode. Native Windows can run the mocked core/runner tests and Node contract tests, but the authoritative deploy suite and full npm run verify require Ubuntu/POSIX semantics. After local review, pushing or opening a pull request requires separate user authorization. Production activation requires green Linux checks and a single controlled dispatch whose exact run ID and receipt are inspected.
