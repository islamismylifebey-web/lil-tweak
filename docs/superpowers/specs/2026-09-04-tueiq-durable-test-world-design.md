# Tueiq Durable Test World Design

Date: 2026-09-04
Status: approved for implementation
Scope: Tueiq (`islamismylifebey-web/lil-tweak`) only

## Goal

Give Tueiq a bounded, durable practice environment where it can inspect an immutable codebase, attempt a repair, receive deterministic judge feedback, retry from the same authoritative baseline plus its prior accepted work, and be scored repeatedly. The complete user-visible state must come from the authoritative trusted core; the browser must never invent running/pass/fail state.

## Non-goals

This change does not generalize the system to other agents, deploy infrastructure, merge to `main`, change production credentials, grant external-action authority, or give the sandbox network access. It does not replace Tueiq's existing engineering-job path.

## Architecture

Tueiq remains one product and one API boundary:

`Practice UI -> same-origin Cloudflare route -> signed core transport -> trusted core -> Postgres world/attempt journal -> existing rootless Podman sandbox -> deterministic judge -> Postgres -> signed response -> UI`

The Test World reuses the existing `PodmanSandbox`, `WorkspaceTools`, OpenAI Responses client, immutable Git intake, runtime execution lock, output redaction, resource limits, and evidence primitives. There is no second frontend/backend pair.

## World contract

A world is owner-scoped and immutable with respect to its challenge definition:

- generated `world:<32 hex>` id
- human-readable name
- explicit objective
- immutable Git repository URL and exact 40- or 64-hex commit
- 1-8 deterministic judge checks
- each check has a display name, argv command, and bounded timeout
- maximum attempts from 1 through 10
- authoritative status: `ready`, `running`, `failed`, `passed`, `exhausted`, or `blocked`

V1 accepts Git source only. This keeps every retry reproducible and avoids introducing a second source-storage protocol.

## Attempt contract

Each attempt is immutable after completion and receives a monotonically increasing attempt number. It records:

- generated `attempt:<32 hex>` id
- state: `queued`, `running`, `passed`, `failed`, or `error`
- deterministic judge outcome
- per-check bounded/redacted result
- cumulative patch from the world's immutable baseline
- agent plan, summary, and self-reported tests
- model call and token counts
- start/finish timestamps
- durable lease generation/expiry for crash recovery

Only one attempt per world may execute at a time.

## Retry model

Every attempt starts from the exact world Git commit. For attempt N > 1, the trusted core reapplies the cumulative patch from attempt N-1 using the existing safe patch-promotion machinery before asking Tueiq to continue. The agent receives the objective plus bounded feedback from prior failed checks, but not hidden judge implementation details beyond the owner-visible check names/results. A failed attempt is evidence, not automatic termination; retry remains available until `maxAttempts` is reached.

## Execution and judge boundary

The trusted core, not the model, owns the judge. The model may inspect/edit/run allowed sandbox tools exactly as in the existing engineering lane. After the model finishes, the core captures the final workspace and runs every configured judge command inside the same network-disabled Podman policy. Passing requires every command to exit zero without timeout. Judge stdout/stderr is bounded and redacted by the existing sandbox implementation.

The OpenAI API key remains host/runtime configuration. It is never persisted in a world, included in a model-visible file, copied into a container, returned by an API, logged by the feature, or stored in Git.

## Durability

PostgreSQL is authoritative for worlds and attempts. A forward-only schema migration creates world and attempt tables and advances the schema version to 3. Queued/running attempts use generation-fenced leases. On restart, expired running attempts are made schedulable again or safely failed according to their durable record; no browser memory is required to resume truth.

A dedicated world scheduler polls durable queued work and uses the same trusted work-root execution lock as ordinary engineering work. This prevents practice execution and engineering execution from mutating the bounded work root concurrently.

## Trusted core API

All Test World routes use the existing signed owner-only core protocol:

- `POST /v1/test-worlds` create a world idempotently
- `GET /v1/test-worlds?limit=N` list authoritative summaries
- `GET /v1/test-worlds/{id}` return one world and its attempts
- `POST /v1/test-worlds/{id}/attempts` enqueue the next attempt idempotently

Mutation requests require the existing signed idempotency key. Responses contain no secrets and use strict bounded parsing.

## Cloudflare/API surface

The browser never talks to the trusted core directly. Same-origin owner-authenticated routes proxy through the existing signed core client:

- `/api/practice/worlds`
- `/api/practice/worlds/[id]`
- `/api/practice/worlds/[id]/attempts`

Unlike engineering-job mirror state, Test World v1 does not add a D1 mirror. The Practice UI reads the trusted core's authoritative state directly so frontend/backend drift cannot create false status.

## UI

Add a `Practice` view to the existing Tueiq workbench, not a separate application. It supports:

- create world from immutable Git source
- define objective, judge checks, and attempt budget
- list worlds and authoritative status
- inspect attempt history and judge feedback
- start/retry an attempt
- poll while the backend reports queued/running
- show pass/fail/exhausted only from server responses

No optimistic `passed`, `failed`, or `running` state is synthesized in the browser.

## Failure handling

- invalid source/check definitions: reject before persistence
- unavailable signed core: return unavailable; UI shows connection failure
- failed Git intake/sandbox lifecycle/model protocol: attempt becomes `error` with bounded public feedback and world remains retryable unless exhausted/blocked by unrecoverable state
- judge failure: attempt becomes `failed`; retry allowed within budget
- expired lease: scheduler can reclaim with generation fencing
- replay/idempotency conflict: fail closed using existing request protections
- secret-like output: existing sandbox redaction applies before persistence

## Verification

Implementation follows test-first development. Required proof:

1. core unit tests for world validation, idempotency, leases, fail/retry/pass/exhaustion
2. core API tests for signed create/list/get/attempt routes
3. runner tests proving baseline reconstruction, prior-patch replay, judge pass/fail, and credential-free sandbox invocation
4. migration/deployment contract tests for schema version 3 and file inventories
5. TypeScript protocol tests rejecting malformed authoritative responses
6. route tests proving the browser API calls the signed core rather than local fake state
7. rendered/UI contract test for the Practice surface
8. full `npm run verify` on the feature branch

Live OpenAI, PostgreSQL, R2/Git egress, and production Podman qualification remain explicitly unverified until the user injects the existing API key and runtime infrastructure later. No deployment is part of this branch.