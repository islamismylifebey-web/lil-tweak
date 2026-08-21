# Lil Tweak Automatic Verification and Dormant Runner Qualification 0.7.1

Date: 2026-07-29 (America/Chicago)
Owner: Maurice Pennington-Bey
Verified private-repository baseline:
`43580205930718d45d3571b99033ff00e8952d41`
Production deployed: No
Repository execution enabled: No
Execution runner connected: No

## Implemented

- A separately versioned Phase 7 execution contract.
- Exact clean-commit, complete-tree, deterministic `.git`-free source manifests.
- UTF-8, NFC, case-fold, ancestor, control-character, path-depth, file-count, file-size, aggregate
  size, sensitive-path, and credential-shaped-content rejection.
- Server-owned recipe registration with configured immutable image-reference labels, exact
  argument vectors, a pytest/Ruff-only verification allowlist, and bounded declared resources.
- Digest-bound plans covering owner scope, job, organization, project, signed brief, route,
  recipe, source, image, sandbox profile, commands, limits, expiry, and prohibited authority.
- Exact expiring Founder approval and an atomic one-attempt claim tied to job cancellation and
  emergency-stop state.
- Schema version 2 with atomic, idempotent migration of the complete prior schema and durable
  execution, approval, idempotency, and result tables.
- A permanently disconnected candidate Bubblewrap adapter that generates an invocation using a
  dedicated read-only runtime root, non-root identity,
  isolated namespaces, disabled nested user namespaces, dropped capabilities, cleared
  environment, read-only source, bounded output, process-group termination, and cleanup checks.
- Verification that fails closed on source drift, plan/profile/runtime/image mismatch, command
  omission/reordering/duplication, timeout, output overflow, required-check failure, cancellation,
  emergency stop, artifacts, or unverified cleanup.
- HMAC-signed immutable success or failure outcomes for completed fixture attempts.
- Additive authenticated execution API routes; the 0.6.0 route set remains present.
- Automatic GitHub-hosted deterministic verification on pull requests and `main`, with read-only
  permissions, no repository secrets, no live evaluations, and full-SHA action pins.
- Separately signed Ed25519 runner challenge and attestation contracts bound to one exact
  repository identity, source commit and tree, runner key, image, sandbox profile, runtime,
  limiter, collector, destroyer, nonce, expiry, and exact ordered adversarial suite.
- A manual three-job evidence workflow that issues and verifies on separate GitHub-hosted jobs
  while the uniquely labeled, non-root, repository-token-free ephemeral candidate runs only
  hash-pinned host-owned collection and cleanup tools.
- A qualification decision whose `connection_authorized` value is structurally fixed to `false`.

## Verification

- 326 unit, integration, API, repository, migration, concurrency, isolation-contract, and
  adversarial tests pass.
- Ruff lint and formatting checks pass.
- All pre-Phase 7 deterministic tests and offline evaluation suites remain green.
- 160 Creator routing simulations pass with zero real provider calls or executions.
- 120 Phase 6 offline cases pass with zero real provider calls.
- 120 Phase 7 cases pass: 80 accepted fixtures, 20 source-tamper rejections, and 20
  command-order-tamper rejections.
- Phase 7 model calls: 0.
- Phase 7 provider calls: 0.
- Phase 7 paid calls: 0.
- Phase 7 real repository executions: 0.
- Legacy HTTP path compatibility: passed.
- Registered source writes, commits, pushes, deployments, and artifact releases during runtime
  verification: 0.
- Optional-only recipes and plans are rejected, and the verification gate independently refuses
  vacuous success when no required check exists.
- Concurrent cancellation, emergency stop, and decision-time expiry retain their true terminal
  state and failure code.
- Existing execution schemas, digest domains, database schema version 2, HTTP operations, and
  stored Phase 7 records remain unchanged.
- The runner qualification verifier is not called by the API, execution controller, health
  response, or database.

## Isolation evidence

- Bubblewrap binary SHA-256:
  `52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712`
- `prlimit` binary SHA-256:
  `f27cfd8c1512a4cc6541b59b80cb4cdfd6ef28c34aa21db4299b48264cd0d128`
- Required namespace probe result: failed closed with `Operation not permitted`.
- `execution_connected`: `false`.
- No registered source was passed to the failed probe.
- The adapter is hard-disconnected in 0.7 even on a host where this smoke probe succeeds.
- Automatic GitHub CI is regression evidence and is not runner-isolation evidence.
- The dedicated-runner workflow remains dormant until its exact ephemeral host labels, protected
  environment, independently managed runner key, host-owned collector and destroyer, and pinned
  digests are configured.

## Honest boundary

The deterministic fixture suite proves the plan, approval, persistence, replay, source-integrity,
and outcome-verification contracts. It does not prove that this managed host can safely execute an
untrusted repository.

The candidate local adapter is not a production sandbox. It does not yet prove cgroup-level CPU,
memory, PID, disk, or inode enforcement; active cancellation/emergency termination after
dispatch; remotely signed runner attestation; host mandatory-access-control policy; or
crash-recovered orphan cleanup. Those are connection gates, not deferred documentation.

Committed-tree ingestion remains bounded by file, byte, output, and aggregate time ceilings. Each
independent verification pass now inventories the tree, admits every declared object size through
one fresh `git cat-file --batch-check` process, and only then streams exact blob bodies through one
fresh `git cat-file --batch` process. The reader validates every response header, size, delimiter,
object type, object ID, and recomputed Git object hash under one fixed deadline. It never caches
content or trust decisions across the two passes. Local paired evidence is recorded in
`docs/phase7-batch-ingestion-evidence.md`.

No production behavior was enabled. A future dedicated runner must pass the adversarial
qualification in `docs/phase7-security-boundaries.md` before the server may report
`execution_connected=true`.
Phase 7.1 can validate a signed offline report, but its decision type always returns
`connection_authorized=false`. Activation additionally requires durable one-use replay state,
a fresh signed connection lease, per-attempt runner signatures, and control-plane integration
that are intentionally absent from this release.

## Release exclusions

- `.env` and `.env.*` other than the empty `.env.example`;
- API keys, signing/encryption keys, credentials, and secret-bearing logs;
- execution roots, runtime roots, sandbox/probe directories, repositories, and artifact storage;
- SQLite databases, journals, state, caches, virtual environments, bytecode, core dumps, and
  temporary files;
- build/distribution output and package metadata;
- archives, Git bundles, and prior release packages.

