# Failure Recovery Engine V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic, bounded, fail-closed recovery decision engine and connect it to the current engineering orchestrator as an evidence-only bridge.

**Architecture:** Add a cohesive `core/lil_tweak/failure_recovery/` package. Keep classification, canonical fingerprints, policy, append-only history, and coordination separate. The current orchestrator records decisions but preserves existing terminal-state behavior until the Engineering DAG exists.

**Tech Stack:** Python 3.12 standard library, frozen dataclasses, enums, protocols, `unittest`, current Lil Tweak core contracts.

**Spec:** `docs/superpowers/specs/2026-09-04-failure-recovery-engine-v1-design.md`

## Global Constraints

- Baseline is `274d76b65175807c268249241c845928095e484f`.
- No new runtime dependency.
- No shell, source-write, Git, credential, provider, deployment, push, or merge authority.
- Unknown, ambiguous, stale, replayed, or integrity-invalid failures block.
- Existing runner, sandbox, approval, lease, evidence, and job-state behavior remains unchanged.
- Canonical outputs exclude timestamps and random values.

---

### Task 1: Lock the public contracts with failing tests

**Files:**
- Create: `core/tests/test_failure_recovery_contracts.py`
- Create: `core/tests/test_failure_recovery_controller.py`

**Interfaces:**
- Produces expected imports and behavior for `FailureSignal`, `RecoveryContext`, `RecoveryBudgets`, `FailureRecoveryController`, and `InMemoryRecoveryHistoryStore`.

- [ ] Write tests for strict binding validation, enumerated failure/action values, deterministic fingerprints, unknown-failure blocking, and safe default budgets.
- [ ] Write tests for transient retry, candidate repair, replan, rollback precedence, reroute qualification, authority escalation, same-fingerprint budget, no-progress blocking, owner isolation, and monotonic history.
- [ ] Open a draft PR and verify the tests fail because the package does not exist.

### Task 2: Implement contracts and canonical fingerprints

**Files:**
- Create: `core/lil_tweak/failure_recovery/__init__.py`
- Create: `core/lil_tweak/failure_recovery/contracts.py`
- Create: `core/lil_tweak/failure_recovery/fingerprints.py`

**Interfaces:**
- `failure_fingerprint(signal: FailureSignal, context: RecoveryContext) -> str`
- Frozen records for signals, contexts, budgets, decisions, history entries, outcomes, and resource decisions.

- [ ] Implement strict frozen models and canonical serialization.
- [ ] Implement stable SHA-256 fingerprinting from failure-relevant material.
- [ ] Run contract tests and keep unrelated tests green.

### Task 3: Implement classification, policy, and history

**Files:**
- Create: `core/lil_tweak/failure_recovery/classifier.py`
- Create: `core/lil_tweak/failure_recovery/policy.py`
- Create: `core/lil_tweak/failure_recovery/history.py`

**Interfaces:**
- `FailureClassifier.classify(signal, context) -> ClassifiedFailure`
- `RecoveryPolicy.decide(classified, context, history, budgets, resource_decision=None) -> RecoveryDecision`
- Append-only owner-scoped history with monotonic sequence.

- [ ] Implement conservative known-code classification and unknown blocking.
- [ ] Implement precedence, authority checks, budgets, and no-progress detection.
- [ ] Implement thread-safe append-only owner isolation.
- [ ] Run focused tests.

### Task 4: Implement the controller and typed handoff

**Files:**
- Create: `core/lil_tweak/failure_recovery/controller.py`

**Interfaces:**
- `FailureRecoveryController.decide(...) -> RecoveryDecision`
- `FailureRecoveryController.record_outcome(...) -> RecoveryHistoryEntry`
- `FailureRecoveryController.dag_handoff(decision) -> dict[str, object]`

- [ ] Compose classifier, fingerprint, policy, and history.
- [ ] Reject stale decision/outcome bindings.
- [ ] Emit deterministic machine-readable DAG handoff without execution authority.
- [ ] Run focused tests.

### Task 5: Integrate the current orchestrator without changing its state machine

**Files:**
- Modify: `core/lil_tweak/orchestrator.py`
- Modify: `core/lil_tweak/store.py`
- Create: `core/tests/test_failure_recovery_orchestrator.py`

**Interfaces:**
- Optional `recovery_controller` constructor dependency.
- Validated `failure_recovery_decision` audit event.

- [ ] Write failing tests proving errors are classified and recorded while the job still terminates as `FAILED` or `TIMED_OUT`.
- [ ] Add the optional bridge and bounded event schema.
- [ ] Prove no retry, source mutation, or authority is introduced.

### Task 6: Adversarial verification and final review

**Files:**
- Create: `core/tests/test_failure_recovery_security.py`

- [ ] Test model-forced retry/reroute, wrong source/candidate/contract digest, stale lease, replay, missing approval, unqualified resource, budget overflow, repeated no-progress failure, cross-owner history, and self-declared recovery.
- [ ] Run `python3 -m unittest` for all focused recovery tests.
- [ ] Run `npm run verify`.
- [ ] Review the exact diff for state-machine, runner, deployment, and authority changes.
- [ ] Merge only the exact green candidate and verify post-merge `main`.