# Phase 3.2 Build Brief

## Confirmed facts

- Lil Tweak is an independent, API-first software-engineering engine personally owned by
  Maurice Pennington-Bey.
- GALORE currently appears on an IRS document because of a reported typo and is not recorded
  here as Lil Tweak’s owner.
- Terhuti connects only after Lil Tweak is independently complete and cannot bypass policy.
- Full Voice Access activates after the core and execution runner are verified.
- The first pilots are Coverall Sports CIE, GLITCH, and GALOR Production OS.
- The normal operating budget is $125–$200 monthly with a $250 ceiling.
- Lil Tweak remains one configured model with no router, handoffs, specialist models, or
  engineering-commander layer.

## Phase 3.2 reasoning gate

Before connecting execution, Lil Tweak must pass a bounded engineering-reasoning trial using one
model call per case and no tools. The required method is:

- Trace exact evidence.
- Weigh competing causal hypotheses.
- Explain the selected causal chain.
- Act with the smallest supported change.
- Kill regressions with falsifying tests.

The trial uses three synthetic packets covering atomicity, tenant isolation, and sports-data
temporal leakage. Hidden grading expectations are never submitted to the model. Packet and output
schemas, citations, paths, symbols, hashes, credentials, resource bounds, and unsupported
execution claims are checked deterministically.

This is an evaluation boundary only. It does not widen the production repository reader, write
source, run code, or grant approval authority.

## Phase 3 goal

Turn the verified read-only inspection into a safe recovery and review-preparation boundary:

- require an exact, expiring, server-authenticated owner approval before source is copied;
- consume that approval atomically at the start of one recovery attempt;
- build staged and unstaged patches from full Git object IDs and securely opened raw files,
  without invoking repository-controlled filters or text conversion;
- include Git-ignored files in the non-index archive scope instead of silently omitting them;
- reject credentials, sensitive paths, binary changes, conflicts, incomplete inspection, stale
  fingerprints, unsafe Git layouts, symlinks, hardlinks, special files, path collisions, and
  size or time limit violations;
- generate every source-derived artifact twice and require matching digests;
- encrypt every published artifact with AES-256-GCM under a tenant-derived key;
- place ciphertext only in a private artifact root disjoint from the repository workspace;
- bind approval to a byte-accurate tracked/non-index snapshot, then re-inspect before and after
  capture and prove that bytes in the approved capture scope and relevant Git control state were
  unchanged;
- authenticate the evidence-chain head and count with an external HMAC key;
- reject detected credentials in task input before storage or model submission;
- reserve a conservative paid-planning amount transactionally before the provider call;
- prepare a deterministic, review-only change specification with no source writes;
- keep execution, project tests, builds, package managers, restores, commits, and deployments
  disconnected.

## Recovery contract

Input:

- authenticated owner-only API request;
- a completed, verified Phase 3 repository inspection and plan;
- exact repository fingerprint returned by that inspection;
- exact recovery snapshot digest committed by that fingerprint;
- server-owned repository registration and optional allowed-path scope;
- requested retention of 1–168 hours;
- explicit acceptance if local commits ahead of upstream are not captured.

Output:

- `RecoveryPackage` with an opaque ID and independent status;
- exact approval and source-fingerprint binding;
- encrypted `staged_patch`, `unstaged_patch`, and/or `untracked_archive`;
- encrypted canonical recovery manifest;
- plaintext and ciphertext SHA-256 metadata without storage paths;
- completeness, exclusions, warnings, and blocker codes;
- evidence records that contain digests and counts but no source or secret values.

Phase 3 deliberately refuses binary patches, unresolved conflicts, external Git directories,
Git object alternates, `core.worktree` overrides, and local-commit bundle capture. If commits are
ahead of upstream, the owner must either stop or explicitly accept an incomplete working-tree
package. A later phase must add encrypted, verified Git-history recovery before claiming that
case complete.

## Trust boundaries

The OpenAI planning agent has no filesystem, shell, artifact, Git, or execution tool. It receives
only sanitized inspection facts and cannot authorize recovery or change state.

Deterministic code owns repository resolution, filter-free Git plumbing, direct file reads, path
validation, credential scanning, archive construction, encryption, approval state, idempotency,
limits, evidence anchors, budget admission, and source snapshot checks. Repository content,
filenames, configuration, branches, and model output are untrusted data.

The development bearer token authenticates the one configured owner. Request fields such as
`requested_by`, organization, and project are metadata—not proof of authority. Production
tenant identities, tenant-scoped repository bindings, and distributed authorization remain a
launch gate.

## HTTP surface

- `GET /health`
- `POST /v1/jobs`
- `GET /v1/jobs/{job_id}`
- `POST /v1/jobs/{job_id}/inspect`
- `GET /v1/jobs/{job_id}/inspection`
- `POST /v1/jobs/{job_id}/analyze`
- `POST /v1/jobs/{job_id}/recovery`
- `GET /v1/jobs/{job_id}/recovery`
- `POST /v1/jobs/{job_id}/recovery/prepare`
- `POST /v1/jobs/{job_id}/changes/prepare`
- `POST /v1/jobs/{job_id}/cancel`
- `POST /v1/jobs/{job_id}/execute` (truthfully blocked)
- `GET /v1/jobs/{job_id}/evidence`
- `GET /v1/approvals/{approval_id}`
- `POST /v1/approvals/{approval_id}/decision`
- `POST /v1/emergency-stop`

No artifact download or restore endpoint exists in Phase 3.

## Required environment names

- `OPENAI_API_KEY`
- `LILTWEAK_MODEL`
- `LILTWEAK_ENVIRONMENT`
- `LILTWEAK_DB_PATH`
- `LILTWEAK_DEV_API_KEY`
- `LILTWEAK_OWNER_ID`
- `LILTWEAK_MONTHLY_BUDGET_USD`
- `LILTWEAK_JOB_HARD_LIMIT_USD`
- `LILTWEAK_PLANNING_RESERVATION_USD`
- `LILTWEAK_WORKSPACE_ROOT`
- `LILTWEAK_REPOSITORIES_JSON`
- `LILTWEAK_ARTIFACT_ROOT`
- `LILTWEAK_ARTIFACT_ENCRYPTION_KEY` (URL-safe base64 encoding of exactly 32 random bytes)
- `LILTWEAK_EVIDENCE_SIGNING_KEY` (same encoding; required in production)

Without an artifact encryption key, inspection and planning remain available but recovery
preparation reports disabled. No secret value belongs in source, documentation, tests, evidence,
logs, model context, or archives.

The Phase 3 budget guard reserves a conservative ceiling before a paid planning call and
transactionally enforces Lil Tweak's configured monthly admission limit. This is not a
provider-enforced billing cap. Provider usage-to-invoice reconciliation is not yet implemented,
so `actual_cost_usd` remains zero and production billing accounting is a later launch gate.

## Verification

```bash
uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run pytest
uv run python evals/run_local.py
uv run python evals/run_gauntlet.py
uv run python evals/run_engineering_trial.py
uv run python main.py smoke
uv run --env-file ../.env.local python evals/run_gauntlet.py --live
uv run --env-file ../.env.local python evals/run_engineering_trial.py --live
uv run --env-file ../.env.local python main.py phase3-live-smoke
```

## Deliberately deferred

- encrypted and verified Git-history bundles;
- artifact download, restore, automatic retention purge, and key rotation;
- candidate source blobs or code patches authored from raw source;
- isolated execution runner and disposable test/build sandbox;
- Git writes, commits, pushes, previews, and deployments;
- live GitHub connector;
- production identity, tenant authorization, database, and deployment;
- provider token-usage pricing reconciliation and provider-enforced spending controls;
- planning-claim lease/reconciliation after crashes;
- atomic state/evidence commits and aggregate per-tenant request and artifact-storage quotas;
- external monotonic or append-only evidence checkpoints for anti-rollback;
- directory-descriptor-pinned artifact publication and durable encryption metadata backup;
- enforced artifact expiry at every downstream use;
- aggregate wall-clock and process-count limits for inspection and capture;
- defense-in-depth secret scanning beyond deterministic credential patterns;
- Terhuti integration;
- Full Voice Access.

