# Runner V3 — GitHub-first runner-factory design

## Status

Approved for implementation on `feature/runner-v3-github-first-factory-01`.

This design creates the first worker template in Lil' Tweak's Runner Factory. It preserves the existing Resource Director, resource execution contract, execution lease, approval, policy, source-binding, evidence, and independent-verification boundaries. PR #12 remains frozen as reference.

## Objective

Build one dependable, headless engineering runner that Lil' Tweak can use without Cloudflare, Vercel, DigitalOcean, a custom control-plane hostname, or a permanently running host.

The first profile is `galor-tweak-runner-v3-github-01`.

GitHub Actions supplies one fresh Ubuntu worker for each accepted job. Runner V3 performs one bounded engineering workload inside that ephemeral workspace, emits structured evidence, and terminates. The same template can later be cloned into additional runner profiles without changing Tweak's intelligence or contracts.

## Chosen approach

Use a dedicated GitHub Actions workflow as the execution surface and add a separate Runner V3 builder adapter beside the existing GitHub independent-verification adapter.

The roles remain distinct:

- Runner V3 executes a bounded engineering manifest and returns builder evidence.
- GitHub independent verification remains the authority that can establish verified completion.

Builder success is evidence, not truth.

## Alternatives rejected

Continuing PR #12 in place was rejected because it couples host provisioning, Linux sandboxing, Cloudflare Access, a Worker, a Durable Object, qualification, cryptographic dispatch, and release repair into one activation path.

A permanent self-hosted super-runner was rejected for V3 because it creates host maintenance, credential rotation, ingress, recovery, capacity contention, and a single-host failure surface before the first dependable execution loop exists.

Unrestricted shell was rejected because model-generated command text must never become execution authority.

## Trust boundaries

1. Tweak describes a workload.
2. Existing policy and approval logic authorize it.
3. The Resource Director selects the Runner V3 profile.
4. The existing execution lease binds the exact source, profile, resource ceilings, authority digests, command digest, nonce, sequence, revocation epoch, and expiry.
5. The Runner V3 adapter consumes the lease once and dispatches only an exact typed manifest.
6. GitHub checks out the exact source commit with persisted credentials disabled.
7. The executor validates the manifest again before any action runs.
8. It performs only allowlisted actions and emits bounded evidence.
9. Optional patch content may modify only explicitly authorized repository-relative paths inside the ephemeral workspace.
10. Runner V3 never pushes, merges, deploys, writes secrets, accesses production, or claims independent verification.

## Job contract

The canonical JSON manifest contains:

- schema version;
- execution ID, attempt nonce, and expiry;
- exact runner profile, repository, source commit, and source tree;
- CPU, memory, disk, timeout, and output ceilings;
- approval, policy, resource-contract, execution-lease, and command digests;
- workspace mode: `read_only` or `ephemeral_patch`;
- ordered allowlisted actions;
- optional UTF-8 unified patch, digest, and authorized changed paths.

Initial actions:

- `inspect_source`;
- `compile_python`;
- `pytest`;
- `ruff_check`;
- `ruff_format_check`;
- `mypy`;
- `build_package`;
- `git_diff`.

Unknown fields, duplicate actions, unsafe paths, symlink targets, out-of-scope patch paths, malformed digests, source mismatch, profile mismatch, expired input, oversized input/output, and timeout fail closed.

## Workflow

The headless workflow supports authorized `workflow_dispatch` jobs plus a deterministic pull-request smoke fixture that makes zero model/provider calls.

It checks out the exact requested commit, pins the repository toolchain, installs the locked environment, writes the manifest to a protected temporary file, runs `scripts/runner_v3.py`, uploads receipts and an optional candidate patch, and removes temporary inputs.

Repository permission remains read-only. V3 does not receive source-write permission.

## Capacity and factory behavior

V3 does not hard-code an unverified machine-size claim. Every run records observed CPU, memory, free disk, operating system, and runner label. The Resource Catalog uses a conservative profile until live evidence proves more included capacity.

Each workflow run is disposable. Different execution IDs may run in parallel subject to GitHub account limits. Duplicate attempts for one execution ID are serialized and replay-protected. New factory workers are created by cloning the versioned profile and changing only approved capability and capacity declarations.

## Evidence

Receipts bind the manifest and lease digests, exact source before and after execution, runner profile, observed capacity, ordered action outcomes, exit codes, durations, output digests, workspace mutation state, candidate patch digest and changed paths, final outcome, timestamps, and receipt digest.

A successful receipt means only that the authorized builder actions completed. It does not mean the change is correct, merged, deployed, connected to production, or independently verified.

## Testing

Tests must prove strict manifest validation, canonical digesting, lease replay rejection, exact provider/profile/source binding, fail-closed provider state, fixed action mapping, patch path/size/digest enforcement, source checks, bounded output, timeout/cancellation cleanup, receipt integrity, read-only workflow permissions, and absence of Cloudflare, Vercel, DigitalOcean, custom-hostname, model-call, and production dependencies.

The exact branch head must pass full deterministic repository CI and the dedicated Runner V3 pull-request smoke path.

## Completion boundary

Source completion does not establish live qualification. No `CONNECTED`, `QUALIFIED`, or production-capable claim may be made until an actual GitHub-hosted run executes an authorized manifest and its evidence is collected and reviewed.