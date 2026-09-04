# Lil Tweak Failure Recovery Engine V1 Design

## Goal

Create one deterministic, fail-closed recovery authority that turns a bounded engineering failure into exactly one permitted outcome: retry, replan, repair, rollback, resource reroute, requalification, escalation, or block.

## Source authority

- Repository: `islamismylifebey-web/lil-tweak`
- Baseline: `274d76b65175807c268249241c845928095e484f`
- Canonical package: `core/lil_tweak/`
- Existing job state, leases, evidence, source revision, cancellation, sandbox, and store contracts remain authoritative.

## Architecture

The engine is an additive package at `core/lil_tweak/failure_recovery/`.

1. **Contracts** define stable failure classes, reason codes, dispositions, actions, authority requirements, budgets, evidence bindings, decisions, and outcomes.
2. **Fingerprints** create deterministic SHA-256 identities from failure-relevant canonical material only. Timestamps, prose messages, and random identifiers do not alter equivalence.
3. **Classifier** maps typed signals and known exception codes into a conservative taxonomy. Unknown failures fail closed.
4. **Policy** selects the narrowest permitted action, enforces per-node/per-fingerprint/mission budgets, blocks no-progress loops, and requires new authority when scope or resource changes.
5. **History store** preserves append-only decisions and outcomes with owner isolation and monotonic sequence numbers. Initial failed-check evidence and exact alternate-resource bindings remain durable.
6. **Controller** combines classification, fingerprinting, history, objective progress evaluation, and policy; it does not execute commands or mutate source.
7. **Orchestrator adapter** wraps the existing `EngineeringOrchestrator`, observes the complete terminal result, and records a bounded recovery decision only after the final source digest is available. Until Tweak’s DAG exists, the current job remains failed or timed out; the adapter never invents a retry transition.

## Recovery flow

`failure signal → validate bindings → classify → fingerprint → load history → enforce budgets/objective progress → select action → persist decision → expose typed DAG handoff`

Every decision binds the exact task/job, owner, node, source revision, plan/candidate/contract digests when present, execution/lease/current-resource identifiers when present, exact alternate resource when rerouting, attempt number, and failure evidence.

## Precedence

1. Cancellation, integrity failure, wrong/stale binding, missing required authority, lease replay/expiry, security failure, and rollback failure block automatic retry.
2. A partial mutation requires rollback only when existing authority remains valid. Missing/stale approval, stale source, or another reauthorization requirement cannot be discarded by rollback selection.
3. Plan/contract/context defects require replan or escalation.
4. Candidate/test defects may permit bounded repair.
5. Proven transient execution/provider failures may permit one bounded retry.
6. Resource reroute is allowed only through an injected, distinct, qualified, healthy, authorized, cost-approved, source-bound resource decision with a fresh lease.
7. Unknown or ambiguous failures block.

## Budgets

Safe defaults:

- same-node retries: 2
- same-fingerprint retries: 1
- full replans: 2
- candidate repairs: 2
- resource reroutes: 1
- rollback attempts: 1

Server-side policy may lower these values but cannot exceed hard maximums defined in code.

## Progress

A caller cannot self-declare progress. For a non-successful recovery outcome, the controller derives progress only when canonical evidence changes: failed checks strictly decrease, a new plan or candidate digest is produced, or the resource changes to the exact approved reroute target. A successful outcome additionally requires independent verification. The same failure after the same strategy without objective progress becomes `recovery_strategy_no_progress` and blocks.

## Current integration boundary

- `RecoveryAwareEngineeringOrchestrator` is an opt-in adapter around the existing orchestrator; the base orchestrator and state machine remain unchanged.
- The adapter records issued decisions and outcomes in the recovery history store and exposes the most recent decision to its caller.
- It does **not** append a new event kind to `JobStore`; the existing store’s event allowlist remains unchanged.
- It observes model-call failures, failures occurring elsewhere in orchestration, and terminal command-observation timeouts after the authoritative job record has its final source binding.
- Existing state transitions remain unchanged; the adapter cannot reopen a terminal job or execute its recovery recommendation.
- Future DAG integration consumes `RecoveryDecision` and owns the separately authorized transition.
- A future, explicitly designed JobStore audit projection may mirror recovery history only after its event schema and compatibility rules are approved.
- Future Contract Registry, Repository Mapper, Reviewer/Critic, Resource Director, and verifier integrations are typed optional inputs. Missing evidence blocks only when the governing request marks it required.

## Security

The engine has no shell, filesystem-write, Git, runner, provider, credential, deployment, merge, or production authority. It cannot grant approval, issue execution leases, choose an unqualified resource, suppress failed checks, self-verify recovery, or delete recovery history. Outcomes and DAG handoffs accept only controller-issued, digest-valid decisions.

## Verification

Tests must prove deterministic classification/fingerprinting, fail-closed unknowns, binding validation, budget exhaustion, objective no-progress detection, rollback authority preservation, authorization escalation, exact resource reroute binding, owner isolation, monotonic history, stale evidence rejection, model-claim rejection, complete-orchestrator observation, and existing orchestrator compatibility.

## Non-claims

V1 does not claim an active Engineering DAG, automatic rollback execution, live Resource Director integration, Contract Registry enforcement, Reviewer/Critic integration, or production recovery. It provides the deterministic recovery authority and evidence-only current-orchestrator adapter those systems can consume.