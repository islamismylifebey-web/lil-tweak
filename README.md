# Lil Tweak Creator Model Foundation — 0.5.0

Lil Tweak the Super Geek is an independent, API-first software-engineering engine personally
owned by Maurice Pennington-Bey. It does not depend on Terhuti, and a future Terhuti client will
use the same bounded API without policy-bypass authority.

The verified Phase 3.2 baseline adds owner-approved, encrypted recovery and non-executing change preparation to the
verified inspection, planning, policy, cost, and evidence core. Phase 3.2 adds an evaluation-only
engineering-reasoning gate for the single Lil Tweak model.

Version 0.5.0 adds the first real Creator Model control plane:

- a signed prompt compiler that preserves Founder direction;
- deterministic deliverables, negative constraints, acceptance criteria, and material questions;
- visual-language compilation for qualities such as shine, electric, clean, fast, secure, and
  fluid;
- least-cost capable adaptive routing with measurable escalation and de-escalation triggers;
- caller-proof server authority and digest-bound immutable briefs;
- high-stakes gates that accept prerequisites only from the trusted harness;
- a bounded sandbox execution contract with exact one-attempt approvals;
- proof-based completion gates tied to observed command results;
- append-only causal learning from signed verified outcomes;
- 160 offline Creator Model routing simulations with no provider, tool, or execution calls.

The Creator Model contract is documented in
[`docs/creator-model-foundation.md`](docs/creator-model-foundation.md).

The reasoning gate uses Tweak's versioned TWEAK method: trace evidence, weigh competing
hypotheses, explain causality, act minimally, and kill regressions with falsifying tests. It does
not add model routing, specialist models, tools, source writes, or execution authority.

## What is real

- opaque, server-owned registration for local or pre-materialized GitHub repositories;
- filter-free, read-only Git inspection built from bounded object/index inventories and direct
  no-symlink file reads;
- redacted credential-risk findings with no secret values;
- byte-accurate recovery snapshots that include tracked and every non-index file, including
  Git-ignored files, within the approved allowed-path scope;
- before/after repository fingerprints and HMAC-anchored evidence-chain verification;
- rejection of detected credential material in task input before storage or model submission;
- a transactional, conservative paid-planning admission reservation before the provider call;
- atomic job creation and request-key binding under concurrent duplicate requests;
- atomic approval publication, decision, cancellation, and emergency invalidation across workers;
- atomic recovery-package, approval, and operation-key publication;
- a separate recovery state machine that does not misuse job execution states;
- server-authenticated, exact-digest recovery approvals with expiry;
- atomic, one-attempt approval consumption;
- double-generated staged and unstaged full-OID, Git-compatible text patches rendered without
  invoking repository filters, text conversion, hooks, or filesystem monitors;
- double-generated, validated, regular-file-only untracked TAR archives;
- rejection of detected credentials, sensitive paths, binary changes, conflicts, unsafe paths,
  symlinks, hardlinks, special files, non-text changes, incomplete metadata, stale byte
  snapshots, unsafe Git layouts, partial/promisor object stores, and configured size/time limits;
- AES-256-GCM artifact encryption with tenant-derived keys and authenticated metadata;
- private `0700` artifact storage outside the repository workspace and `0600` ciphertext files;
- private `0700` local state storage with a `0600` SQLite database;
- canonical encrypted manifest with artifact hashes, coverage, exclusions, and restore order;
- a review-only `ChangePreparation` record bound to the approved source snapshot and verified
  recovery;
- authenticated HTTP routes for inspection, planning, recovery, change preparation, approvals,
  cancellation, emergency stop, and evidence;
- offline tests, adversarial fixtures, local workflow evaluations, and live OpenAI smoke support.
- a bounded single-model engineering-reasoning contract with deterministic citation, scope,
  secret, and unsupported-execution validation;
- three progressively harder synthetic reasoning trials for atomicity, tenant isolation, and
  sport-agnostic temporal leakage, with hidden grading expectations and a three-call live cap.

Only ciphertext is written to the artifact root. API models expose opaque IDs, hashes, sizes,
media types, and statuses—never storage paths, encryption nonces, keys, source content, or raw
artifact bytes.

## Deliberate boundaries

Phase 3 does not:

- write to a registered source repository;
- apply or restore a patch;
- run project code, tests, builds, package managers, or lifecycle scripts;
- checkout, add, commit, reset, clean, push, deploy, or contact a Git host;
- expose filesystem, Git, shell, or artifact tools to the OpenAI planning agent;
- create Git-history bundles for commits ahead of upstream;
- expose artifact download or restoration routes;
- automatically purge expired artifacts yet;
- report provider invoice cost from token usage yet; Phase 3 reserves a conservative ceiling
  before each paid planning call and exposes actual cost as zero until reconciliation exists;
- deploy to production;
- integrate with Terhuti;
- activate Full Voice Access.

The Phase 3.2 reasoning trial receives only synthetic, bounded evidence packets. It is not wired
to registered repository contents or production API authority. Passing it proves evidence-backed
engineering reasoning; it does not prove custom-trained foundation weights or executed code.

Binary working-tree changes are blocked rather than packaged because encoded binary patches
cannot yet receive the same credential-safety proof. Local commits ahead of upstream require
explicit acceptance of an incomplete working-tree package; they are never silently omitted.
Ignored files are never silently omitted: they are included as non-index files and receive the
same path, type, size, and credential checks.

## Configuration

The API never accepts a filesystem path or clone URL. Map an opaque identity to a relative path
under a server-owned workspace:

```env
LILTWEAK_WORKSPACE_ROOT=./repositories
LILTWEAK_REPOSITORIES_JSON={"local:coverall-cie":"coverall","github:owner/project":"snapshots/project"}
```

Configure recovery separately:

```env
LILTWEAK_ARTIFACT_ROOT=./artifacts
LILTWEAK_ARTIFACT_ENCRYPTION_KEY=<URL-safe base64 for exactly 32 random bytes>
LILTWEAK_OWNER_ID=maurice-pennington-bey
LILTWEAK_EVIDENCE_SIGNING_KEY=<URL-safe base64 for exactly 32 random bytes>
LILTWEAK_PLANNING_RESERVATION_USD=1
```

The artifact root and repository workspace must be disjoint. Without the encryption key,
inspection and planning work, while `recovery_preparation_enabled` remains false.
Production requires the evidence signing key. Development without one uses a process-ephemeral
key and reports `durable_evidence_integrity=false`; it cannot verify persisted evidence after a
restart.

`provider="github"` still means that a server-authorized snapshot already exists locally.
Phase 3 does not clone, fetch, pull, or call GitHub.

## Recovery flow

1. Create and analyze a job.
2. Use its exact `repository_fingerprint`, which commits to the byte snapshot, to create a
   recovery request.
3. Read the generated approval and approve its exact `action_digest`.
4. Call recovery preparation once. The approval becomes `consumed` before source copying.
5. Read the package metadata and evidence.
6. Prepare a review-only change specification only after complete recovery is `ready`.

If bytes in the approved capture scope or relevant Git control state change after approval,
credential material is detected, or a safety check fails, the package becomes `blocked`, no
plaintext is published, and any partially published ciphertext is quarantined.

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
- `POST /v1/jobs/{job_id}/execute` (returns runner unavailable)
- `GET /v1/jobs/{job_id}/evidence`
- `GET /v1/approvals/{approval_id}`
- `POST /v1/approvals/{approval_id}/decision`
- `POST /v1/emergency-stop`

Every `/v1/*` route requires the development bearer token. The token identifies the one
configured owner; request fields do not grant authority.

## Verification

```bash
UV_CACHE_DIR=/tmp/liltweak-uv-cache uv sync --frozen
UV_CACHE_DIR=/tmp/liltweak-uv-cache uv run ruff check .
UV_CACHE_DIR=/tmp/liltweak-uv-cache uv run ruff format --check .
UV_CACHE_DIR=/tmp/liltweak-uv-cache uv run pytest
UV_CACHE_DIR=/tmp/liltweak-uv-cache uv run python evals/run_local.py
UV_CACHE_DIR=/tmp/liltweak-uv-cache uv run python evals/run_gauntlet.py
UV_CACHE_DIR=/tmp/liltweak-uv-cache uv run python evals/run_engineering_trial.py
UV_CACHE_DIR=/tmp/liltweak-uv-cache uv run python evals/run_creator_benchmark.py
UV_CACHE_DIR=/tmp/liltweak-uv-cache uv run python main.py smoke
UV_CACHE_DIR=/tmp/liltweak-uv-cache uv run python main.py creator-smoke
UV_CACHE_DIR=/tmp/liltweak-uv-cache uv run --env-file ../.env.local python evals/run_gauntlet.py --live
UV_CACHE_DIR=/tmp/liltweak-uv-cache uv run --env-file ../.env.local python evals/run_engineering_trial.py --live
UV_CACHE_DIR=/tmp/liltweak-uv-cache uv run --env-file ../.env.local python main.py phase3-live-smoke
```

## Launch status

This remains an owner-only development API. Organization and project fields prepare the model
for later tenancy, but production identity, tenant-scoped repository bindings, distributed
authorization, durable key management, automatic retention, production storage, rate limits,
provider-usage billing reconciliation, provider-enforced spending controls, planning-claim
reconciliation, state/evidence transaction unification, aggregate per-tenant request and storage
quotas, an external anti-rollback evidence checkpoint, artifact-path publication hardening,
enforced artifact expiry, aggregate inspection resource limits, defense-in-depth secret scanning,
and deployment are still launch gates.

The latest high-volume and live adversarial results are documented in
[`docs/gauntlet-report.md`](docs/gauntlet-report.md). The single-model engineering result is in
[`docs/engineering-trial-report.md`](docs/engineering-trial-report.md).
