# Lil Tweak Master Builder Remaining Blockers

## Evidence scope

| Item | Value |
|---|---|
| Repository | `islamismylifebey-web/lil-tweak` |
| Working branch | `codex/lil-tweak-live-workbench-build` |
| Draft pull request | [PR #6](https://github.com/islamismylifebey-web/lil-tweak/pull/6) |
| Audited remote baseline | `373400cb2b459dbf8a37dacceb0d3d1186eef949` |
| Working candidate commit | **PENDING** — no candidate commit is claimed by this report |
| Exact final tested tree | **PENDING** — the current evidence is a mutable working-tree checkpoint only |
| Environment | Private Codex Linux workspace, Python 3.12, Chromium 149; disconnected runner; no GCP/public authorization |
| Integrated checkpoint | `.venv/bin/pytest -q`: 597 passed, 0 failed, 0 skipped, with one known warning on the mutable working tree |
| Browser checkpoint | Chromium 149: 30 PASS / 3 BLOCKED / 0 FAIL; result SHA-256 `d0e150189eff95b10fb5e4fa68768020428bb4a1175c9c72aefc49295a87cb18`; screenshot SHA-256 `387e7ddce232bddbbb0f861dbcaa95b7f0797f5d16531d9d0a80243e3dd58542` |
| Package checkpoint | Wheel and sdist builds passed after explicitly configuring setuptools 82.0.1 and wheel 0.47.0 |
| Final artifacts and digests | **PENDING** — the candidate commit remains external/null, so these mutable checkpoints are not immutable clean-commit evidence |

Passing contract tests is necessary but does not waive a live, independent, or operational gate.
The following blockers are ordered by dependency and blast radius.

## 1. Freeze and verify an exact candidate

**Current state:** The working candidate SHA, exact tested tree, and immutable final evidence digest
do not yet exist. The complete mutable-tree suite passed 597 tests with zero failures and zero skips
and one known warning. Chromium 149 acceptance produced 30 PASS / 3 BLOCKED / 0 FAIL, and the wheel
and sdist builds passed with the explicit build-tool configuration above. These are checkpoints,
not final clean-commit evidence, and must be repeated after the candidate commit is frozen.

**Required to unblock:**

- freeze one candidate commit on `codex/lil-tweak-live-workbench-build`;
- prove a clean worktree and capture the exact commit/tree IDs;
- run the entire prescribed test, lint, format, type, migration, API schema, frontend, and live
  launch matrix from a clean checkout of that commit;
- save command lines, exit codes, test counts, timestamps, environment facts, and artifact SHA-256
  digests in a signed manifest;
- repeat any gate after any code, test, dependency, workflow, or report change.

Until this is done, merge and release evidence is incomplete.

## 2. Finish canonical reconciliation outside the private Workbench

**Current state:** The active private Workbench now uses the canonical lifecycle authoritatively on
one SQLite connection through migration `0010_workbench_canonical_authority.sql`. Its task,
approval, dispatch, failure/cancellation, rollback, emergency, and completion guards are atomic
with the compatibility projection. Its descriptor-pinned context integration is also complete and
tested. Legacy API/service paths and a live delivery publisher are not yet reconciled, and crash
recovery still intentionally engages emergency stop for unsafe states instead of automatically
resuming work.

**Required to unblock:**

- reconcile the remaining legacy API/service and future publisher paths onto the same lifecycle;
- prove atomic state, event, outbox, approval-consumption, and evidence operations under restart,
  concurrency, stale-state, replay, and migration scenarios;
- add a new-task revision workflow instead of attempting to rewind an approved canonical task;
- add clean-database and real-upgrade migration tests tied to the final schema digest.

## 3. Complete live provider qualification

**Current state:** Authorized Sol evidence includes all six combinations of `standard`/`pro` and
`high`/`xhigh`/`max`, plus continuation and concurrency exercises. The label-blind v2 holdout
passed 15/15 in exactly one provider call with zero retries. That is valid partial qualification
evidence, but no final-candidate signed bundle or full production-provider qualification is
claimed.

**Required to unblock:**

- bind the v2 artifact to the immutable source suite, opaque request, hidden evaluation contract,
  exact provider prompt/input, parsed output, profile, usage, and final candidate tree digests;
- inject and qualify the production Workbench provider path rather than relying only on the
  qualification harness;
- qualify live compaction behavior and context lineage;
- qualify prompt-cache semantics and telemetry, including cache-miss and ambiguous telemetry cases;
- qualify timeout, active cancellation, refusal, incomplete/truncated response, malformed
  structured output, retry, idempotency, and provider-unavailable paths;
- bind every request and result to model snapshot, profile, prompt/schema/policy/context digests,
  reservation/cost, task, attempt, and exact candidate commit;
- persist redacted signed artifacts without exposing credentials or private chain-of-thought;
- independently reproduce and approve the Sol suite before changing its gate to operational;
- preserve cancellation propagation as a live qualification blocker until active cancellation is
  proven not to be converted into ordinary model failure or completion;
- separately qualify Terra before enabling any degraded profile.

Until then, keep `LILTWEAK_WORKBENCH_MODEL_ENABLED=false` and
`LILTWEAK_LIVE_MODEL_ENABLED=false` for the documented private launch.

## 4. Finish the tool authority schema and orchestration boundary

**Current state:** `TOOL_AUTHORITY_REGISTRY.json` truthfully exports two non-mutating definitions:
repository read and named verification. The registry digest is
`b6eab6b90ea8d90f21ede11de3bf751c6bd5535d933e1cd06de6f6d9d1a2b53f`. No mutation,
publisher, network, or GCP tool is registered, and model-directed dispatch is disabled.

**Required to unblock:**

- add and enforce output schemas, role allowlists, working-directory and filesystem roots,
  environment allowlists, resource ceilings, retry/timeout/output bounds, redaction, approval
  bindings, artifact rules, and dispatch-receipt fields;
- bind requests to exact registry and implementation digests and reject drift;
- prove the orchestrator, rather than the model, validates arguments and dispatches only registered
  tools;
- record immutable request/result/evidence receipts and cancellation outcomes;
- keep mutation absent until runner, approval, evidence, publisher, and rollback gates separately
  qualify.

## 5. Qualify and connect the isolated runner

**Current state:** The 47-check qualification contract exists with suite digest
`45197dc51a04a0a8f1a7a56183d326ee2fb758c2f013ef4a9ba314e0ff53f531`, but the host
is not qualified. Production uses `DisconnectedProcessTransport`.

**Observed blockers:** qualifier and destroyer executables are missing/unpinned; the runtime root
and pinned manifest are missing; cgroup v2 is not delegated; the bubblewrap namespace probe timed
out; independent qualification and signed connection authorization are absent; no process
transport is connected.

**Required to unblock:** provision the exact pinned runtime and qualified image/executables on a dedicated host,
pass all 47 hostile checks including kill/cleanup/resource/network/filesystem scenarios, obtain an
independent signed qualification receipt and a separate signed connection authorization, then
exercise the actual process transport. Test-only connected overrides do not count.

## 6. Connect a genuinely independent external anti-rollback checkpoint

**Current state:** `liltweak/external_checkpoint.py` defines append, expectation, and receipt
interfaces. The default client is disabled. Local HMAC/hash-chain evidence is not an external
checkpoint.

**Required to unblock:**

- select an append-only backend controlled outside the Lil Tweak mutation domain;
- independently verify provider identity, monotonic sequence, prior-head expectation, durability,
  replay handling, unavailable/ambiguous outcomes, and signed receipts;
- extend the checkpoint contract to bind repository pre/post state, control-plane audit head,
  generation/attempt, policy, registry, runner, candidate, and delivery result;
- integrate and adversarially test the real backend under outage, stale head, duplicate submit,
  rollback attempt, and verifier compromise assumptions.

## 7. Implement and qualify production repository delivery

**Current state:** Strict delivery contracts and an `EphemeralTestRepositoryPublisher` prove
protocol behavior in pytest. `DisabledRepositoryPublisherClient` remains the production default.
There is no production owner security principal, approval verifier, durable journal, real Git
executor, or Workbench apply/commit/rollback API.

**Required to unblock:**

- implement a least-privilege, locally isolated publisher that cannot push, merge, release, or
  deploy;
- verify one-use, expiring, purpose-bound owner approvals against exact repository, plan, policy,
  registry, runner, network, attempt, nonce, evidence, patch, and expected-result digests;
- lock and re-check exact owner-tree pre-state immediately before mutation;
- durably journal pre-image/restoration data before apply;
- prove byte-exact patch boundaries, symlink/binary/submodule/repository-boundary denial, post-apply
  verification, mandatory restoration on failure, purpose-bound local commit, crash recovery, and
  discretionary rollback with a new approval;
- obtain distinct Founder approvals for apply, commit, and rollback, each purpose-bound to the
  exact operation and immutable facts it authorizes;
- run those tests on disposable real Git repositories under the production security principal and
  retain signed receipts.

Owner-tree apply, local commit, and rollback remain blocked. Remote push, PR mutation, merge,
release, and deployment remain absent by design.

## 8. Add independent verification and completion evidence

**Current state:** The Workbench correctly stops at `VERIFIED` with independent examiner false and
completion false. It does not seal or checkpoint evidence and cannot reach the delivery gates.

**Required to unblock:** run a separately identified examiner against the exact candidate in the
qualified runner; bind examiner inputs/outputs and deterministic checks to immutable evidence;
seal the evidence, obtain an external checkpoint receipt where policy requires it, and prove the
canonical completion predicate rejects every missing or stale gate. No control-plane or model
self-attestation may substitute for the independent examiner.

## 9. Complete real-browser and private-session qualification

**Current state:** Chromium 149 acceptance produced 30 PASS / 3 BLOCKED / 0 FAIL. Invalid Host was
rejected with HTTP 400, cross-origin Origin with HTTP 403, the IPv6 listener was refused, and all
test listeners were cleared. The result artifact SHA-256 is
`d0e150189eff95b10fb5e4fa68768020428bb4a1175c9c72aefc49295a87cb18`; the screenshot SHA-256 is
`387e7ddce232bddbbb0f861dbcaa95b7f0797f5d16531d9d0a80243e3dd58542`. The three blocked cases are
live planning/approval without a complete provider-qualification receipt, delivery/rollback
without the qualified runner and publisher, and real-time session expiry under the current
minimum 300-second TTL. Revocation is process-local, and this mutable-browser checkpoint is not
bound to a final candidate commit.

**Required to unblock:**

- repeat the browser suite against the exact frozen candidate and bind its artifacts to that commit;
- resolve and exercise the three blocked cases, including a safe way to qualify real-time expiry;
- complete any browser cases not already covered for refresh/restart, rotation, concurrent
  sessions, lockout, rate-limit recovery, accessibility, focus, and responsive layout;
- implement and qualify durable session revocation or rotate signing credentials on restart;
- prove private metadata does not leak through errors, logs, exports, caches, browser storage, or
  history;
- define and enforce model egress policy before enabling live repository context;
- repeat literal IPv4 and IPv6 loopback listener checks on the final candidate.

## 10. Run the complete evaluation and adversarial matrix

**Current state:** The full mutable-tree suite passed 597 tests with 0 failures, 0 skips, and one
known warning, but no exact-candidate end-to-end run spans the production provider, independent
orchestration, qualified runner, verifier, checkpoint, and production delivery.

**Required to unblock:** complete adversarial cases for injection, malicious repository content,
secret exfiltration, symlink/TOCTOU, stale approval, replay, duplicate dispatch, crash/restart,
concurrency, cancellation, budget exhaustion, partial provider response, evidence rollback,
publisher recovery, and capability downgrade. Record live-versus-mocked provenance for every gate
and require zero silent fallbacks.

## 11. Complete supply-chain and reproducibility evidence

**Current state:** Wheel and sdist builds pass after explicitly configuring setuptools 82.0.1 and
wheel 0.47.0, and the mutable-tree supply checks have advanced. Final-candidate immutable supply
evidence is still absent. The vulnerability database is unavailable, three license findings still
require review, and there is no independently qualified runner/image.

**Required to unblock:** generate these artifacts from the exact candidate using pinned tooling;
record tool versions, inputs, outputs, exclusions, and SHA-256 digests; resolve or explicitly block
on findings; verify workflow permissions and dependency pins; and reproduce the build/test result
from a clean checkout. Do not backfill an artifact after the tested commit changes.

## 12. Keep GCP and public deployment disabled

**Current state:** Both are disabled by policy, unconfigured, unauthenticated, and unqualified.

This is not a blocker for the narrow loopback-only inspection launch, but it is an absolute blocker
for any cloud or public claim. Enabling either would require a new threat model, owner authorization,
identity and secret architecture, network policy, infrastructure review, deployment qualification,
monitoring, incident response, rollback, cost controls, and independent release evidence.

## 13. Publication and repository handoff

**Current state:** The working branch and draft PR are identified, but this report claims no final
candidate commit, push, PR update, merge, tag, release, or deployment.

**Required to unblock the requested branch/PR handoff:** finish blockers applicable to the intended
private scope, freeze and verify the exact candidate, inspect the final diff and evidence bundle,
commit only intended files, push the branch, and confirm PR #6 points to that exact candidate. Merge,
release, and deployment require separate explicit authorization and gates.

## Non-waiver rule

No test double, capability flag, UI label, owner approval, model assertion, local HMAC, earlier
baseline run, or prose report may waive a missing operational proof. A blocker changes state only
when its required evidence is tied to the exact candidate and independently verifiable.

## Current determination

**ARCHITECTURE IMPLEMENTED AND TESTED — NOT OPERATIONAL**

The external checkpoint, qualified runner/image, production Workbench provider injection, live
compaction/failure/cache scenarios, Founder-approved apply/commit/rollback, vulnerability database,
and three license reviews remain blocked. Remote publication, merge, release, GCP, and public
deployment also remain blocked.
