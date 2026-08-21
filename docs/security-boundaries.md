# Phase 3.2 Security Boundaries

## Trust model

Repository content, filenames, Git configuration, object data, task text, model output, and API
request metadata are untrusted. The registered workspace mapping, authenticated owner identity,
environment configuration, encryption key, and evidence signing key are server-controlled.

The OpenAI planning agent receives only a bounded task after credential-pattern screening and a
sanitized repository fact object. It has no filesystem, Git, shell, artifact, approval, or
execution tool.

The separate Phase 3.2 evaluation harness receives only bounded synthetic evidence packets. It
uses the same single-model boundary with no tools or handoffs. Packet contents are untrusted data,
credential-screened before submission, and hash-bound. Deterministic validation rejects unknown
evidence, path, symbol, or invariant citations and rejects model claims of execution. The harness
does not read registered source or change API authority.

## Repository reads

Phase 3 does not call working-tree `git status` or `git diff`. Those commands can invoke a
repository-configured clean filter.

The inspector and recovery capture instead use a fixed allowlist of read-only Git plumbing:

- resolve and validate a full HEAD object ID;
- inventory the HEAD tree with `ls-tree`;
- inventory index entries with `ls-files --stage`;
- enumerate every non-index file with `ls-files --others`, without ignore exclusions;
- read a validated full blob ID with `cat-file blob`;
- read worktree files through directory descriptors with no symlink following.

Object IDs are recomputed, source files are checked before and after reading, configured object
alternates and partial/promisor stores are blocked, lazy fetching and replacement objects are
disabled, and critical Git metadata cannot be symlinked or hard-linked.

The approval digest commits to a byte snapshot of the HEAD tree, index, tracked worktree, and all
non-index files in the allowed scope. Ignored files are included. Changes to bytes, modes,
inventory, or Git control state invalidate capture.

## Recovery artifacts

Only bounded, strict UTF-8 tracked changes are patchable in Phase 3. Binary data, unsafe control
characters, credentials, sensitive paths, conflicts, submodule entries, special files,
symlinks, hardlinks, path collisions, and incomplete inventories fail closed.

Artifacts are generated twice, compared, encrypted with AES-256-GCM under a tenant-derived key,
and stored as private ciphertext outside the repository workspace. There is no artifact download
or restore endpoint, and restoration is never performed against the registered source.

Artifact-root validation and private permissions are enforced, but final path publication is not
yet pinned through directory descriptors and encryption metadata needed for future decryption is
stored only in SQLite. Retention begins when the package is created, and expiry is not yet
enforced when preparing a change review. Directory-descriptor-pinned publication, durable
metadata backup, and enforced expiry remain production gates.

Credential detection is deterministic and pattern-based, so it is one boundary rather than proof
that arbitrary data is secret-free. Production requires defense-in-depth scanning and review.
Inspection and capture apply bounded files, bytes, and subprocess timeouts, but do not yet impose
one aggregate wall-clock or process-count budget over the complete operation.

Named Phase 3 operations are denied when explicitly listed in `prohibited_actions`, and every
endpoint also has its own deterministic safety guard. Other task policy lists remain planning
context; they are not a general-purpose authorization language.

## Evidence and cost

Each evidence record remains hash-chained. The chain count and head are also HMAC-authenticated,
which detects altered rows, deleted tails, and empty-chain replacement when the external signing
key remains secret. The authenticated anchor is stored in the same SQLite database, so restoring
an older valid database together with its matching anchor is not detectable without an external
monotonic or append-only checkpoint. State changes and evidence appends are not yet one database
transaction, so cross-record crash reconciliation remains a production launch gate.

Paid planning reserves a conservative amount in a transaction before contacting the provider.
That reservation enforces Lil Tweak's monthly admission ledger without trusting model-supplied
cost; it is not a provider-enforced billing cap. Provider token usage is not yet reconciled to an
invoice price, so the API does not claim a real `actual_cost_usd`.

The one-shot planning claim prevents duplicate paid provider calls. A hard crash after that claim
leaves the job fail-closed until a future lease/reconciliation mechanism exists. Job creation and
its idempotency key now commit together. Approval publication and decisions, cancel/emergency
invalidation, and recovery request publication also use short immediate transactions across
database connections.

Local development state is kept under a private `0700` directory with a `0600` SQLite database.
Production still requires managed storage, backup, access control, and key management.

## Deferred controls

Before production launch, Lil Tweak still needs production identity and tenant authorization,
managed key storage and rotation, automatic retention cleanup, provider billing reconciliation,
provider-enforced spending controls, planning-claim reconciliation, atomic state/evidence commits,
aggregate tenant quotas, an external anti-rollback evidence checkpoint, rate limiting, a
sandboxed execution runner, directory-descriptor-pinned artifact publication, durable artifact
metadata, enforced expiry, aggregate resource ceilings, defense-in-depth secret scanning, and
deployment hardening. Terhuti integration and Full Voice Access remain disconnected.

