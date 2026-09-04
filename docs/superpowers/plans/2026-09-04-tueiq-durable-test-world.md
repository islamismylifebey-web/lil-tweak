# Tueiq Durable Test World Implementation Plan

Date: 2026-09-04
Branch: `feature/tueiq-durable-test-world`
Base: `72810ca4e06bbef7eceabad7b9edf406cba6b66e`

## Scope guard

Implement only the Tueiq durable Test World described in `docs/superpowers/specs/2026-09-04-tueiq-durable-test-world-design.md`. Do not merge, deploy, mutate production infrastructure, add credentials, weaken existing approval/sandbox boundaries, or generalize to other agents.

## Slice 1 — RED: durable world domain and store contract

- [ ] Add `core/tests/test_test_world.py` before production code.
- [ ] Specify strict world/check validation, generated ids, immutable challenge definition, attempt numbering, one-active-attempt rule, retry budget, pass/fail/exhausted transitions, idempotent create/enqueue, and generation-fenced leases.
- [ ] Run only the new core test and confirm RED because `core.lil_tweak.test_world` does not exist.
- [ ] Commit RED evidence.

## Slice 2 — GREEN: in-memory domain implementation

- [ ] Add `core/lil_tweak/test_world.py` with enums/dataclasses, validation, protocol, `MemoryTestWorldStore`, serializers/helpers, and lease operations needed by the tests.
- [ ] Keep public feedback bounded and free of secrets.
- [ ] Run the focused core test until GREEN.
- [ ] Run the existing core suite to catch regressions.
- [ ] Commit.

## Slice 3 — RED/GREEN: Postgres schema and adapter

- [ ] Add failing migration/store-contract assertions for schema version 3, world/attempt constraints, unique attempt numbering, and lease columns.
- [ ] Confirm RED against missing migration/adapter.
- [ ] Add `core/migrations/003_test_world.sql`.
- [ ] Add `PostgresTestWorldStore` using parameterized SQL and atomic transactions.
- [ ] Update core readiness to require schema version 3.
- [ ] Update deployment integrity/version checks and the exact migration-file inventories required by install/rollback verification.
- [ ] Teach the installer to accept versions 0-3 and apply migration 003 only from version 2.
- [ ] Update the DigitalOcean migration runbook text to version 3 without changing runtime infrastructure.
- [ ] Run focused migration/store/deployment contract tests GREEN.
- [ ] Commit.

## Slice 4 — RED/GREEN: signed trusted-core API

- [ ] Add failing API tests for signed `POST /v1/test-worlds`, `GET /v1/test-worlds`, `GET /v1/test-worlds/{id}`, and `POST /v1/test-worlds/{id}/attempts`.
- [ ] Test owner binding, strict fields, body limits, idempotency, invalid ids, retry budget, and authoritative attempt responses.
- [ ] Confirm RED because routes/dependency are absent.
- [ ] Extend `LilTweakApi` with an optional Test World store and attempt-queued callback while preserving existing job API behavior.
- [ ] Add strict serializers that never expose prompts containing secrets, credentials, internal lease values, or hidden runtime data.
- [ ] Run API tests GREEN plus existing API suite.
- [ ] Commit.

## Slice 5 — RED/GREEN: durable attempt runner and judge

- [ ] Add failing runner/scheduler tests before implementation.
- [ ] Specify immutable Git intake, baseline capture, previous cumulative-patch replay, prior-feedback prompt construction, CodeEngineer invocation, deterministic judge pass/fail, bounded result persistence, teardown, lease renewal/recovery, and attempt exhaustion.
- [ ] Confirm RED.
- [ ] Implement a Test World executor that reuses `ingest_git_source`, `PodmanSandbox`, `WorkspaceTools`, `CodeEngineer`, `capture_workspace`, `build_workspace_patch`, and `runtime_execution_lock`.
- [ ] Never pass `OPENAI_API_KEY`, signing material, R2/database credentials, host environment, or network access into the sandbox.
- [ ] Implement a durable scheduler that polls/claims queued world attempts and generation-fences completion.
- [ ] Wire scheduler/store into `core/main.py` beside the existing engineering scheduler, sharing the runtime execution lock.
- [ ] Run focused tests GREEN and full Python core tests.
- [ ] Commit.

## Slice 6 — RED/GREEN: TypeScript authoritative protocol and signed core client

- [ ] Add `tests/test-world-protocol.test.mjs` first.
- [ ] Specify accepted world/attempt states, ids, immutable source, checks, attempt feedback, timestamps, counts, and response size assumptions; reject extra/malformed fields.
- [ ] Confirm RED because `lib/test-world.ts` is missing.
- [ ] Add strict TypeScript types/parsers in `lib/test-world.ts`.
- [ ] Add `listCoreTestWorlds`, `createCoreTestWorld`, `getCoreTestWorld`, and `startCoreTestWorldAttempt` to `lib/core-client.ts`, all through the existing signed request path.
- [ ] Run focused Node tests GREEN.
- [ ] Commit.

## Slice 7 — RED/GREEN: same-origin Practice API

- [ ] Add route-contract tests proving Practice routes authenticate the owner, require same-origin mutation, derive the canonical owner scope, and call only signed core-client Test World functions.
- [ ] Confirm RED because routes are absent.
- [ ] Add `/api/practice/worlds`, `/api/practice/worlds/[id]`, and `/api/practice/worlds/[id]/attempts` routes.
- [ ] Do not add D1 status storage or optimistic backend mirrors.
- [ ] Map unavailable/rejected core failures to bounded owner-facing errors.
- [ ] Run focused tests GREEN.
- [ ] Commit.

## Slice 8 — RED/GREEN: Practice UI end-to-end contract

- [ ] Add rendered/source contract tests for a Practice tab/panel and authoritative polling behavior before UI code.
- [ ] Confirm RED.
- [ ] Add `app/test-world-client.ts` for same-origin browser calls and strict response parsing.
- [ ] Add `app/practice-panel.tsx` with world creation, immutable Git fields, explicit check argv input, attempt budget, world list/detail, attempt history, judge feedback, Run/Retry, and polling only while backend state is queued/running.
- [ ] Add `practice` to `app/workbench.tsx` navigation and render the panel inside the existing workbench.
- [ ] Add focused styles to `app/globals.css`; do not redesign unrelated views.
- [ ] Ensure browser never synthesizes `running`, `passed`, `failed`, or `exhausted` status.
- [ ] Run focused UI/Node tests GREEN.
- [ ] Commit.

## Slice 9 — integration acceptance gate

- [ ] Add a deterministic acceptance test using fake model/Git/sandbox dependencies that drives the full logical flow: create world -> enqueue attempt -> runner executes -> judge fails -> UI/API-compatible detail exposes feedback -> enqueue retry -> previous patch/feedback are supplied -> judge passes -> world becomes passed.
- [ ] Ensure production code—not mocks of the state machine—is under test; fake only external boundaries that cannot run in repository CI.
- [ ] Run RED first if any missing connection is exposed, then fix minimally and rerun GREEN.
- [ ] Commit.

## Slice 10 — branch CI and verification

- [ ] Add a branch/PR GitHub Actions workflow that installs Node 22 and Python 3.12, runs `npm ci`, then `npm run verify`.
- [ ] Do not add or read an OpenAI key in CI; tests use deterministic fake Responses clients.
- [ ] Push the RED commit before implementation where practical and confirm the failure reason is the missing Test World implementation, not CI setup.
- [ ] Push GREEN implementation commits and confirm Actions succeeds.
- [ ] Run/check: TypeScript, ESLint, production build, all Node tests, all Python core tests.
- [ ] Review changed files against scope; confirm no production secret, deployment action, merge, external-action permission, or network-enabled sandbox change.

## Slice 11 — completion and handoff

- [ ] Read and apply `verification-before-completion`.
- [ ] Inspect final feature-branch head and CI status.
- [ ] Create a draft PR to `main` with exact base/head SHAs, architecture summary, tests, security boundaries, and an explicit `LIVE INTEGRATION PENDING` section for OpenAI key/runtime injection.
- [ ] Do not merge or deploy.
- [ ] Read and apply `finishing-a-development-branch` and leave the branch/PR in the safest reviewable state.

## Acceptance criteria

The branch is complete only when repository tests prove that Tueiq can create a durable immutable world, run a bounded attempt, be judged by deterministic backend checks, receive persisted feedback, retry using prior work/feedback, and reach authoritative pass/fail/exhausted state through the same signed backend the Practice UI reads. Live OpenAI/runtime verification may remain pending solely because the user has not injected the existing key/infrastructure; every deterministic integration path must be GREEN before handoff.