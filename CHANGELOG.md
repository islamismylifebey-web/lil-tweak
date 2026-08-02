# Changelog

## 0.8.0 — Live Workbench and Bounded Execution Bridge

- Added the private owner Workbench UI and session/CSRF API.
- Added immutable tasks, live typed planning, exact one-time approvals, bounded file and command
  tools, isolated task workspaces, recovery snapshots, evidence, and locked submissions.
- Added GCP Qualification bindings and fail-closed project, identity, region, zone, IAM, billing,
  credential, deletion, audit, and administrative-exposure guards.
- Kept live planning and the qualified command runner disabled by default.

## 0.7.1 — Automatic Verification and Dormant Runner Qualification

- Added automatic GitHub-hosted deterministic verification for pull requests and `main`.
- Pinned every GitHub Action by full commit SHA and limited the token to read-only contents.
- Required the frozen lock, Ruff, the complete test suite, every offline evaluation, both smoke
  paths, zero paid/provider calls, and disconnected execution.
- Added separately signed Ed25519 challenge and attestation domains bound to the exact repository
  identity, source, runner key, image, profile, runtime, collector, destroyer, nonce, and suite.
- Required one exact ordered adversarial suite covering network denial, hard resource limits,
  cancellation, emergency termination, hostile workloads, source integrity, and cleanup.
- Added a manual three-job workflow that issues and verifies on separate GitHub-hosted jobs while
  the uniquely labeled ephemeral candidate only invokes hash-pinned host-owned collection and
  cleanup tools.
- Kept qualification evidence outside the production API, SQLite schema, execution plans,
  execution outcomes, and connectivity decision.
- Preserved `execution_connected=false`; a valid Phase 7.1 report is review evidence only.

## 0.7.0 — Isolated Repository Verification

- Added deterministic `.git`-free snapshots for exact clean Git commits.
- Added server-owned verification recipes and digest-bound execution plans.
- Added exact Founder approval, atomic one-attempt claims, and signed outcomes.
- Added schema-versioned repository execution persistence and fail-closed migration checks.
- Added an explicitly disconnected candidate Bubblewrap adapter.
- Added additive authenticated repository verification API routes.
- Added migration, concurrency, replay, tamper, source-integrity, runner-contract, API, and
  compatibility tests.
- Replaced per-object snapshot subprocesses with bounded two-stage `git cat-file --batch-check`
  admission and `git cat-file --batch` content streaming while retaining two independent
  verification passes.
- Added a reproducible offline snapshot benchmark with source identity, raw samples, and direct
  snapshot process counts.
- Required at least one mandatory verification check at the recipe, plan, and outcome-gate
  boundaries.
- Preserved cancellation, emergency-stop, and expiry truth across concurrent failure paths.
- Added a 120-case deterministic Phase 7 evaluation with no provider calls or executions.
- Preserved the 0.6.0 API paths and disabled production execution by default.
