# Changelog

## 0.7.0 — Isolated Repository Verification

- Added deterministic `.git`-free snapshots for exact clean Git commits.
- Added server-owned verification recipes and digest-bound execution plans.
- Added exact Founder approval, atomic one-attempt claims, and signed outcomes.
- Added schema-versioned repository execution persistence and fail-closed migration checks.
- Added an explicitly disconnected candidate Bubblewrap adapter.
- Added additive authenticated repository verification API routes.
- Added migration, concurrency, replay, tamper, source-integrity, runner-contract, API, and
  compatibility tests.
- Required at least one mandatory verification check at the recipe, plan, and outcome-gate
  boundaries.
- Preserved cancellation, emergency-stop, and expiry truth across concurrent failure paths.
- Added a 120-case deterministic Phase 7 evaluation with no provider calls or executions.
- Preserved the 0.6.0 API paths and disabled production execution by default.
