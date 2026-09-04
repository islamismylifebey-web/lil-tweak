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
5. **History store** preserves append-only attempts and outcomes with owner isolation and monotonic sequence numbers.
6. **Controller** combines classification, fingerprinting, history, and policy; it does not execute commands or mutate source.
7. **Orchestrator bridge** records a bounded recovery decision when the existing engineering orchestrator fails. Until Tweak’s DAG exists, the current job remains failed/timed out; the bridge never invents a retry transition.

## Recovery flow

`failure signal → validate bindings → classify → fingerprint → load history → enforce budgets/progress → select action → persist decision → expose typed DAG handoff`

Every decision binds the exact task/job, owner, node, source revision, plan/candidate/contract digests when present, execution/lease/resource identifiers when present, attempt number, and evidence references.

## Precedence

1. Cancellation, integrity failure, wrong/stale binding, missing required authority, lease replay/expiry, security failure, and rollback failure block automatic retry.
2. Explicit rollback requirements outrank retry or replan.
3. Plan/contract/context defects require replan or escalation.
4. Candidate/test defects may permit bounded repair.
5. Proven transient execution/provider failures may permit one bounded retry.
6. Resource reroute is allowed only through an injected qualified/healthy/authorized/cost-approved resource decision.
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

A repeated attempt is progress only when at least one canonical signal changes: failed checks decrease, a critic finding clears, a new plan/candidate digest is produced, resource qualification/health changes, or the failure fingerprint changes. The same fingerprint after the same strategy without progress becomes `recovery_strategy_no_progress` and blocks.

## Integration boundaries

- Current `EngineeringOrchestrator` may inject the controller and append a `failure_recovery_decision` audit event.
- Existing state transitions remain unchanged; the bridge cannot reopen a terminal job.
- Future DAG integration consumes `RecoveryDecision` and owns the approved transition.
- Future Contract Registry, Repository Mapper, Reviewer/Critic, Resource Director, and verifier integrations are typed optional inputs. Missing evidence blocks only when the governing request marks it required.

## Security

The engine has no shell, filesystem-write, Git, runner, provider, credential, deployment, merge, or production authority. It cannot grant approval, issue execution leases, choose an unqualified resource, suppress failed checks, self-verify recovery, or delete recovery history.

## Verification

Tests must prove deterministic classification/fingerprinting, fail-closed unknowns, binding validation, budget exhaustion, no-progress detection, rollback precedence, authorization escalation, safe resource reroute, owner isolation, monotonic history, stale evidence rejection, model-claim rejection, and existing orchestrator compatibility.

## Non-claims

V1 does not claim an active Engineering DAG, automatic rollback execution, live Resource Director integration, Contract Registry enforcement, Reviewer/Critic integration, or production recovery. It provides the complete deterministic recovery authority and current-orchestrator evidence bridge those systems will call.