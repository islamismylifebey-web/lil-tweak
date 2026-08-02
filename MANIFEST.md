# Phase 3.2 Engineering Reasoning Verification Manifest

Date: 2026-07-28 (America/Chicago)  
Version: 0.3.2  
Owner: Maurice Pennington-Bey  
Project: Lil Tweak the Super Geek  
Production deployed: No  
Terhuti integrated: No  
Execution runner connected: No  
Full Voice Access activated: No

## Release result

- Dependency lock synchronized successfully.
- Ruff lint passed.
- Ruff formatting check passed.
- 146 unit, integration, API, policy, approval, evidence, cost, concurrency,
  repository, recovery, and adversarial tests passed.
- 15 local workflow evaluations passed.
- 9 high-volume file/recovery flood cases and 11 state/concurrency/fault-injection cases passed.
- 2 offline hostile-agent cases passed.
- 1 live OpenAI hostile-agent case passed with exactly one paid planner call.
- 3 offline engineering baselines were correctly rejected without provider calls.
- The final 3-case live Tweak engineering-reasoning gate passed atomicity, tenant-isolation, and
  synthetic sports-CIE temporal-leakage cases with exactly one call per case.
- Every final reasoning case used one `lil-tweak-engineering-v1` identity on the configured
  `gpt-5.6-luna` foundation model, with zero tools, handoffs, source reads, or execution.
- Two earlier three-call calibration gates exposed rubric and schema ambiguity; those failures
  were promoted into deterministic contract checks before the clean final gate.
- Offline Phase 3 smoke passed.
- The live hostile-agent case inspected 64+ files read-only, found a late credential as redacted
  metadata, rejected fabricated execution claims, and preserved a valid evidence chain.
- No path entered execution, testing, restore, commit, push, or deployment.

## Verified security and state boundaries

- Repository identities are resolved only through a server-owned opaque registry.
- Inspection and capture avoid working-tree `git status` and `git diff`, repository filters,
  text conversion, hooks, filesystem monitors, replacement objects, and lazy network fetching.
- The fingerprint binds the HEAD tree, index, tracked worktree bytes, every non-index file
  including ignored files, approved path scope, and relevant Git control state.
- Full-repository safety inventories reject sensitive cross-scope moves, case/Unicode and
  ancestor collisions, sparse checkout, skip-worktree, assume-unchanged, conflicts, submodules,
  unsafe Git layouts, partial/promisor stores, alternates, symlinks, hardlinks, and special files.
- Credential-like task input is rejected before storage or model submission; repository findings
  disclose rule, path, severity, and line metadata without returning detected values.
- Recovery requires a complete read-only inspection, an exact expiring owner approval, a matching
  source snapshot, and a fresh before/after inspection.
- Recovery approvals are server-authenticated and consumed once before capture.
- Technical approvals bind the canonical reviewed plan digest and approved source snapshot;
  stale, canceled, emergency-stopped, or changed proposals fail closed.
- Explicitly prohibited named Phase 3 operations cannot be prepared.
- Staged and unstaged strict-text patches and scoped non-index TAR archives are generated twice,
  compared, and encrypted with AES-256-GCM and tenant-derived keys.
- Artifact storage is private and disjoint from the repository; only ciphertext is published.
- Local state storage requires a private `0700` directory and `0600` regular, singly linked
  SQLite database and journal files.
- Evidence rows are hash-chained; the head and count are HMAC-authenticated.
- Paid planning uses a transactional conservative admission reservation, durable one-shot claim,
  and optimistic state publication so concurrent cancellation or emergency stop cannot be
  overwritten.
- A concurrent paid-planning probe produced exactly one provider call and one reservation.
- Concurrent duplicate creation returns one durable job with no orphan rows.
- Approval publication, linked decisions, cancel/emergency invalidation, and recovery-request
  publication commit atomically across database connections.
- Sixty-four identical recovery requests return one package and one approval.
- API validation errors do not echo rejected request values, and caller-supplied actor labels do
  not override the authenticated owner.

## Deliberate Phase 3 boundary

Phase 3 may inspect, plan, prepare encrypted recovery, and prepare a non-executing review record.
Phase 3.2 may also evaluate Tweak against bounded synthetic evidence packets. The evaluation
contract does not widen production repository access or execution authority.
It does not:

- write to a registered source repository;
- apply or restore a patch;
- run project code, tests, builds, package managers, or lifecycle scripts;
- checkout, add, commit, reset, clean, fetch, pull, push, deploy, or contact a Git host;
- expose filesystem, Git, shell, approval, or artifact tools to the planning model;
- create a Git-history bundle for commits ahead of upstream;
- expose artifact download or restore routes;
- deploy to production;
- integrate with Terhuti;
- activate Full Voice Access.

`provider="github"` means a server-authorized snapshot has already been materialized locally.
There is no live GitHub connector in this phase.

## Production launch gates

- A hostile concurrent local writer cannot be eliminated without an immutable filesystem
  snapshot or OS sandbox.
- State changes and their evidence events are not yet one crash-atomic transaction and need
  reconciliation.
- A crash after the one-shot planning claim leaves the job fail-closed until a lease or recovery
  workflow exists.
- The evidence anchor lives in the same SQLite database and cannot detect rollback to an older
  valid database and matching anchor without an external monotonic or append-only checkpoint.
- The budget reservation governs Lil Tweak's admission ledger, not a provider-enforced billing
  cap. Provider token usage is not reconciled to invoice cost, so `actual_cost_usd` remains zero.
- Artifact publication is not yet directory-descriptor-pinned, and encryption metadata needed
  for future recovery is stored only in SQLite.
- Artifact expiry is not enforced at every downstream use, and automatic retention cleanup and
  key rotation are not implemented.
- Inspection and capture lack one aggregate wall-clock and process-count ceiling.
- Aggregate per-tenant request, job, artifact-byte, and storage quotas are not implemented.
- Credential detection is pattern-based and needs defense-in-depth production scanning.
- Task policy lists other than enforced named prohibited operations remain planning context, not
  a general-purpose authorization language.
- Production identity, tenant authorization, managed storage and keys, rate limiting, isolated
  execution, deployment hardening, and provider billing controls are not implemented.

## Excluded from the release archive

- `.env` and `.env.*` files other than the empty `.env.example`;
- API keys and credentials;
- `.venv`;
- local databases, journals, state directories, and artifact storage;
- caches, bytecode, and generated evaluation result state;
- build output, VCS metadata, temporary repositories, and smoke-test data;
- previous release archives.

