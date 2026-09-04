# Lil' Tweak Engineering Contract Registry V1 Design

**Date:** 2026-09-04  
**Repository:** `islamismylifebey-web/lil-tweak`  
**Status:** Approved design  
**Final human approver:** Mauce Pennington Bey

## Purpose

Build a machine-checkable control layer that decides what engineering work Lil' Tweak may perform for a specific requester, action, and asset. The registry protects authority, system boundaries, engineering integrity, evidence requirements, and the human–AI working relationship.

V1 answers one question reliably:

> Given a requester, target asset, and engineering action, what may Lil' Tweak do now, and what approval and evidence are required?

The registry is not a task list, policy wiki, runner, deployment system, or general business-contract database.

## Approved safety boundaries

1. V1 starts in **shadow mode**. It records the decision it would enforce but does not interrupt the active runner workflow.
2. This branch must not change either runner branch, runner configuration, deployment configuration, or live runner state.
3. The following work remains independent and untouched:
   - PR #21: `infra/digitalocean-runner-v3-activation`
   - PR #24: `infra/runner-v3-core-activation`
4. If no valid contract matches, the effective mode is **explain only**.
5. Explain only prohibits code execution, patch creation, patch application, export, push, merge, publish, and deployment.
6. Ambiguous authority, conflicting contracts, expired contracts, missing approvals, stale approvals, or missing evidence fail closed.
7. Lil' Tweak may never describe speculative, drafted, or unverified work as completed.
8. Contract activation and high-risk exceptions require final approval from **Mauce Pennington Bey**.
9. Secrets, raw credentials, and unredacted regulated data must never enter registry records or audit payloads.

## Existing system alignment

V1 is implemented natively under `core/lil_tweak/` and follows the current trusted Core's Python protocols, PostgreSQL-backed production store pattern, canonical hashing, HMAC authentication, replay protection, immutable evidence, and owner scoping.

Old PR #13, `copilot/implement-lil-tweak-registry`, is superseded rather than merged. It targets the obsolete `liltweak/` package, uses SQLite as authoritative storage, is behind `main`, and does not implement the approved request/asset/action authority model. V1 may intentionally recover these sound concepts from PR #13:

- stable contract IDs and immutable versions;
- canonical fingerprints and digests;
- explicit sources and provenance;
- approval and verification records;
- append-only audit events;
- conflict detection;
- exact-revision evidence linkage.

No qualification, approval, completion, or provenance claim from PR #13 carries forward automatically.

## V1 architecture

### 1. Contract domain

A focused module defines validated immutable records:

- `Principal`: requester, agent, team, service, or approver identity and status.
- `Asset`: repository, service, environment, pipeline, database, or document boundary.
- `ContractVersion`: scope, permitted actions, prohibited actions, required approvals, required evidence, effective time, expiry, and supersession.
- `DecisionRequest`: requester, acting agent, action class, target asset, environment, and exact source revision when applicable.
- `Decision`: matched contract versions, effective mode, reasons, requirements, decision digest, and shadow/enforced disposition.
- `ApprovalRecord`: approver, exact decision or contract digest, scope, issue time, expiry, and revocation state.
- `EvidenceReference`: content digest and trusted location metadata, never raw secret-bearing evidence.
- `ExceptionVersion`: narrow, time-limited, approved deviation with compensating controls.
- `AuditEvent`: append-only record chained to its predecessor hash.

Records use narrow enumerations and reject unknown values. Meaningful changes create new versions; active records are not edited in place.

### 2. Deterministic decision engine

The decision engine performs these steps in order:

1. Validate the complete request and reject unknown or ambiguous fields.
2. Verify the requester and acting-agent principal are active.
3. Resolve the exact asset and action class.
4. Select contracts that are active at the decision time and explicitly cover the principal, asset, action, and environment.
5. Detect conflicts and apply the most restrictive compatible result.
6. Check required approval and evidence references against the exact canonical digest.
7. Return the permitted mode and requirements.
8. Append the decision audit event.

Contract selection precedence is mechanical:

- any explicit prohibition wins;
- among compatible permissions, the lowest-authority mode wins;
- required approvals and evidence are the union of all compatible matching contracts;
- logically incompatible scopes or requirements produce `BLOCKED` with `conflicting_active_contracts`;
- a broader contract cannot weaken a narrower contract that covers the same request.

The initial execution modes, from least to most authority, are:

- `BLOCKED`
- `EXPLAIN_ONLY`
- `DRAFT_CODE`
- `PREPARE_PATCH`
- `APPLY_SANDBOX`
- `APPLY_NON_PRODUCTION`

V1 never grants production mutation, push, merge, publish, or deployment authority. Those actions remain prohibited even if a malformed or overly broad contract requests them.

When no contract matches, the result is `EXPLAIN_ONLY` with reason `no_matching_contract`.

#### Governed vocabulary

Environment is a closed V1 enumeration:

- `DOCUMENT_ONLY`
- `REPOSITORY`
- `SANDBOX`
- `NON_PRODUCTION`
- `PRODUCTION`

Action class and operation intent are separate dimensions.

Action classes:

- `ANALYSIS`
- `CODE_GENERATION`
- `PATCH_PREPARATION`
- `PATCH_APPLICATION`
- `APPROVAL_BINDING`
- `EVIDENCE_BINDING`

Operation intents:

- `READ`
- `PROPOSE`
- `MODIFY`
- `APPLY`
- `PUBLISH`
- `DEPLOY`

`PUBLISH` and `DEPLOY` are always prohibited in V1. `APPLY` is permitted only in `SANDBOX` or `NON_PRODUCTION` when a matching contract and every required approval and evidence reference allow it.

Reason codes are a closed, tested V1 registry:

- `no_matching_contract`
- `invalid_request`
- `ambiguous_request`
- `inactive_principal`
- `unknown_asset`
- `contract_not_effective`
- `contract_expired`
- `conflicting_active_contracts`
- `missing_required_approval`
- `stale_approval`
- `revoked_approval`
- `wrong_digest_binding`
- `missing_required_evidence`
- `prohibited_target`
- `prohibited_action`
- `audit_persist_failed`
- `integrity_check_failed`

Unknown internal failures are mapped to `integrity_check_failed` at the public decision boundary and remain blocked. New public reason codes require a versioned contract change and tests.

### 3. Persistence

Production persistence uses the repository's existing PostgreSQL/Drizzle infrastructure. Python accesses it through a narrow `ContractRegistryStore` protocol and a production adapter consistent with current trusted Core storage boundaries. An in-memory adapter supports deterministic unit tests.

Required tables:

- principals and principal versions;
- assets and asset versions;
- contract versions;
- approval records;
- evidence references;
- exception versions;
- contract decisions;
- append-only audit events.

Database constraints enforce owner scoping, immutable version identity, uniqueness, effective/expiry ordering, and digest format. Updates that would rewrite governed history are rejected.

### 4. Integrity and audit chain

All governed records use canonical JSON and SHA-256 fingerprints. Each audit event stores:

- a globally unique event ID;
- an owner-scoped monotonic sequence;
- owner scope;
- subject type and ID;
- event type;
- canonical payload digest;
- previous event hash;
- current event hash;
- authenticated actor;
- recorded time.

The hash chain is maintained per owner scope. Each event binds its owner-scoped sequence and prior owner event hash, making rewriting, deletion, cross-owner insertion, or reordering detectable. HMAC request signing and nonce replay protection reuse the trusted Core's existing authentication model. Cryptographic signing-key rotation and external transparency anchoring are future work; V1 must not pretend a hash chain alone proves external identity.

### 5. Approval and evidence validity

An approval is valid only when all of these conditions hold at decision time:

- it is authenticated through the trusted owner mechanism;
- it has not been revoked;
- its issue time is not later than the decision time;
- its expiry is later than the decision time;
- its digest exactly matches the governed contract version or decision;
- its scope exactly covers the principal, asset, action class, operation intent, and environment tuple;
- no governed contract version it approves was superseded after the approval was issued.

Any failure returns a specific approval reason code and blocks the request.

An evidence reference is valid only when it contains:

- a supported digest algorithm and valid content digest;
- a closed trusted-locator class and bounded locator value;
- a closed evidence type;
- a recognized source system;
- creation time;
- exact source revision when the evidence concerns source code;
- an explicit redaction/asserted-safe flag;
- scope binding to the governed decision or contract digest.

A reference proves that a trusted record was supplied; it does not independently prove an external artifact still exists. Missing, wrong-revision, unsafe, or wrong-digest evidence blocks the request.

### 6. Service boundary

A small authenticated trusted-Core endpoint accepts decision requests and returns deterministic decisions. It follows current API limits, exact JSON validation, owner isolation, idempotency, and generic authentication failures.

The endpoint is decision-only in V1. Contract administration is performed through tested internal service methods; a general admin UI and public CRUD API are outside V1.

Shadow-mode responses expose both:

- `observedMode`: the mode the existing workflow currently follows;
- `recommendedMode`: the registry decision;
- `enforced: false`.

No call from the orchestrator or runner is blocked in V1. Integration points are recorded and tested without changing live execution behavior.

### 7. Initial authority policy

The seed policy identifies:

- Lil' Tweak as the governed engineering agent;
- the verified repository-owner scope as the owning principal boundary;
- Mauce Pennington Bey as the final human approver;
- `github:islamismylifebey-web/lil-tweak` as the first protected asset;
- runner and deployment surfaces as prohibited V1 targets;
- `EXPLAIN_ONLY` as the unmatched-contract default.

Seed records are versioned and loaded idempotently. A name alone does not authenticate an approver; activation requires the approver identity to be bound through the trusted authenticated owner mechanism before enforcement can ever be enabled.

## Failure behavior

The registry returns safe, stable reason codes and does not expose internal policy details through authentication failures.

It returns `BLOCKED` for:

- invalid or ambiguous requests;
- inactive, suspended, revoked, or unknown required principals;
- unresolved assets;
- conflicting active contracts;
- expired or not-yet-effective contracts;
- stale, revoked, wrong-scope, or wrong-digest approvals;
- missing required evidence;
- prohibited runner, production, deployment, secret, or regulated-data actions;
- audit persistence failure.

It returns `EXPLAIN_ONLY` only for a valid request with no matching contract. A database outage or integrity failure is not treated as "no match"; it blocks the decision path.

## Testing and proof

V1 requires:

- schema and strict-input validation tests;
- decision-table tests for every action/mode combination;
- unmatched-contract explain-only tests;
- conflict and most-restrictive-result tests;
- expired, revoked, wrong-scope, superseded-version, future-issued, and wrong-digest approval tests;
- evidence completeness, trusted-locator, redaction flag, source-revision, and digest-binding tests;
- owner-isolation tests;
- idempotency and replay tests;
- audit-chain tamper, deletion, and reordering detection tests;
- shadow-mode non-interference tests;
- explicit regression proof that runner and deployment files are unchanged;
- PostgreSQL adapter integration tests;
- full `npm run verify` on the exact branch head.

Completion evidence must identify the exact commit tested. A passing test from a different revision does not qualify the candidate.

## Out of scope for V1

- runner activation or qualification;
- runner configuration changes;
- deployment or production enforcement;
- public customer access;
- admin dashboard;
- general-purpose policy language such as OPA or Cedar;
- object-storage management of raw evidence;
- contract authoring by Lil' Tweak without human review;
- unlimited or silent exceptions;
- automatic merge, push, publish, or deploy;
- legal or business contract management.

## Non-claims

V1 does not claim:

- authenticated human identity solely from a display name;
- execution control over external systems;
- independent proof that an external artifact exists beyond its referenced trusted record;
- production enforcement;
- runner connection or qualification;
- legal authorization outside the authenticated trusted owner scope;
- external identity proof from an internal hash chain alone.

## Acceptance criteria

V1 is complete when the exact branch head proves that:

1. the trusted Core produces deterministic decisions for valid requests;
2. no matching contract produces explain-only and nothing stronger;
3. prohibited, ambiguous, conflicting, expired, or under-evidenced requests fail closed;
4. approvals bind to the exact contract/decision digest and expire or revoke correctly;
5. governed history is append-only and tampering is detectable;
6. owner scopes cannot read or affect one another;
7. shadow mode records recommendations without changing runner behavior;
8. PR #21, PR #24, their branches, runner configuration, and deployment configuration remain untouched;
9. the full repository verification suite passes;
10. no claim of production enforcement, runner qualification, or completed execution is made without its required proof.
