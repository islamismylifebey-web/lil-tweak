# Lil Tweak Isolated Repository Verification 0.7.0

Date: 2026-07-29 (America/Chicago)
Owner: Maurice Pennington-Bey
Verified private-repository baseline:
`0051503b1327177573359347fe8ff7f0a2ed8d5c`
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

## Verification

- 247 unit, integration, API, repository, migration, concurrency, isolation-contract, and
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

## Isolation evidence

- Bubblewrap binary SHA-256:
  `52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712`
- `prlimit` binary SHA-256:
  `f27cfd8c1512a4cc6541b59b80cb4cdfd6ef28c34aa21db4299b48264cd0d128`
- Required namespace probe result: failed closed with `Operation not permitted`.
- `execution_connected`: `false`.
- No registered source was passed to the failed probe.
- The adapter is hard-disconnected in 0.7 even on a host where this smoke probe succeeds.

## Honest boundary

The deterministic fixture suite proves the plan, approval, persistence, replay, source-integrity,
and outcome-verification contracts. It does not prove that this managed host can safely execute an
untrusted repository.

The candidate local adapter is not a production sandbox. It does not yet prove cgroup-level CPU,
memory, PID, disk, or inode enforcement; active cancellation/emergency termination after
dispatch; remotely signed runner attestation; host mandatory-access-control policy; or
crash-recovered orphan cleanup. Those are connection gates, not deferred documentation.

Committed-tree ingestion is bounded by file, byte, output, and aggregate time ceilings, but the
current reader starts per-object Git subprocesses. Large repositories therefore fail closed at
the deadline rather than offering optimized batch ingestion; a persistent `git cat-file` batch
reader is the next performance optimization.

No production behavior was enabled. A future dedicated runner must pass the adversarial
qualification in `docs/phase7-security-boundaries.md` before the server may report
`execution_connected=true`.

## Release exclusions

- `.env` and `.env.*` other than the empty `.env.example`;
- API keys, signing/encryption keys, credentials, and secret-bearing logs;
- execution roots, runtime roots, sandbox/probe directories, repositories, and artifact storage;
- SQLite databases, journals, state, caches, virtual environments, bytecode, core dumps, and
  temporary files;
- build/distribution output and package metadata;
- archives, Git bundles, and prior release packages.
