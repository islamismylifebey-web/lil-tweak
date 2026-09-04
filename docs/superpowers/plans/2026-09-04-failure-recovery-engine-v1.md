# Failure Recovery Engine V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a deterministic, bounded, fail-closed recovery decision engine and connect it to the current engineering orchestrator through an opt-in evidence-only adapter.

**Architecture:** Add a cohesive `core/lil_tweak/failure_recovery/` package. Keep classification, canonical fingerprints, policy, append-only history, objective progress evaluation, and coordination separate. The current orchestrator remains unchanged; the adapter observes its final result and records recovery authority after source binding. Actual retry transitions remain the future Engineering DAG’s responsibility.

**Tech Stack:** Python 3.12 standard library, frozen dataclasses, enums, protocols, SQLite, `unittest`, and current Lil Tweak core contracts.

**Spec:** `docs/superpowers/specs/2026-09-04-failure-recovery-engine-v1-design.md`

## Global Constraints

- Baseline: `274d76b65175807c268249241c845928095e484f`.
- No new runtime dependency.
- No shell, source-write, Git, credential, provider, deployment, push, or merge authority.
- Unknown, ambiguous, stale, replayed, or integrity-invalid failures block.
- Existing runner, sandbox, approval, lease, evidence, JobStore event schema, and job-state behavior remain unchanged.
- Canonical outputs exclude timestamps and random values.

### Task 1: Lock public contracts with failing tests

- [x] Create strict contract/controller tests.
- [x] Cover bindings, enums, deterministic fingerprints, unknown-failure blocking, safe budgets, retry, repair, replan, rollback, reroute, escalation, no progress, owner isolation, and monotonic history.
- [x] Open draft PR #30 and prove RED because the package did not exist.

### Task 2: Implement contracts and canonical fingerprints

**Files:** `core/lil_tweak/failure_recovery/contracts.py`, `fingerprints.py`, `__init__.py`

- [x] Implement frozen typed signals, contexts, budgets, classifications, decisions, outcomes, history entries, and resource decisions.
- [x] Implement stable SHA-256 failure and decision digests.
- [x] Bind exact current and alternate resource identities.
- [x] Reject malformed IDs, digests, booleans, reason codes, unverified success, and invalid action/authority combinations.

### Task 3: Implement classification, policy, and durable history

**Files:** `classifier.py`, `policy.py`, `history.py`

- [x] Implement conservative known-code classification and fail-closed unknowns.
- [x] Implement authority-preserving rollback precedence.
- [x] Implement per-node, per-fingerprint, and per-mission budgets.
- [x] Implement distinct qualified/healthy/authorized/cost-approved/source-bound rerouting with a fresh lease.
- [x] Implement owner-isolated append-only in-memory and SQLite history with monotonic sequencing.
- [x] Preserve original failed-check evidence and exact reroute targets.

### Task 4: Implement controller and typed DAG handoff

**File:** `controller.py`

- [x] Compose classifier, fingerprint, policy, and history.
- [x] Reject stale, wrong-context, forged, duplicate, or unissued decision/outcome bindings.
- [x] Derive failed-outcome progress from reduced checks or new plan/candidate/resource evidence; reject self-declared progress.
- [x] Require independent verification for successful recovery.
- [x] Emit deterministic DAG handoff with no execution, authorization, or provider-selection authority.

### Task 5: Integrate current orchestration without changing its state machine

**Files:** `orchestrator_bridge.py`, `core/tests/test_failure_recovery_orchestrator.py`, `core/tests/test_failure_recovery_review_remediation.py`

- [x] Add `RecoveryAwareEngineeringOrchestrator` as an opt-in composition adapter; do not modify `EngineeringOrchestrator` or `JobStore`.
- [x] Observe model-call failures, failures elsewhere in orchestration, and terminal command timeouts.
- [x] Issue decisions only after the authoritative final source digest is present.
- [x] Preserve existing terminal `FAILED`/`TIMED_OUT` behavior and perform no retry.
- [x] Keep recovery decisions in the append-only recovery history; do not invent a new JobStore audit-event kind.

### Task 6: Adversarial verification and review

- [x] Add security, durable history, reroute binding, and independent-review remediation tests.
- [x] Reject model-forced retries, authority loss, stale leases, replay, missing approvals, unqualified resources, same-runner reroutes, changed-fingerprint budget bypass, mutable nested evidence, unissued decisions, false progress, and self-verification.
- [ ] Obtain fresh exact-head focused and full canonical verification after the final remediation.
- [ ] Obtain independent review with no remaining P1/P2 findings.
- [ ] Confirm current `main` is still the verified base or reconcile safely.
- [ ] Merge only the exact reviewed green candidate.
- [ ] Verify post-merge `main` through the recovery-specific and repository-standard workflows.