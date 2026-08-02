# Lil Tweak Context Retrieval and Memory Architecture

This architecture makes repository context deterministic, provenance-bound, token-bounded, and non-authoritative. Memory is opt-in, explicitly promoted, continuously reassessed, and invalidated when its evidence or environment changes.

## Binding and current status

| Field | Value |
|---|---|
| Audited remote baseline | `373400cb2b459dbf8a37dacceb0d3d1186eef949` |
| Branch / PR | `codex/lil-tweak-live-workbench-build` / `#6` |
| Working candidate commit | Pending |
| Retrieval artifact schema | `context-manifest-v1` |
| Memory schemas | `memory-record-v1`, `memory-promotion-grant-v1`, `memory-assessment-v1`, `memory-tombstone-v1` |
| Implementation status | Deterministic context-manifest retrieval is active in private Workbench planning; memory and full multi-role lifecycle integration remain pending |

## 1. Deterministic retrieval pipeline

`build_context_manifest` accepts a real repository directory plus repository ID, exact source revision, objective, optional diagnostics, and a controller-owned `ContextPolicy`.

### Scan policy

The scanner pins the repository root with a directory descriptor and traverses in deterministic order using descriptor-relative operations. It never follows symlinks, reads and hashes each accepted file through one pinned descriptor, and verifies entry and descriptor identity before and after the read. It fails closed if the root or a traversed entry changes identity. Every observed path is recorded as allowed or excluded. It rejects or excludes:

- vendor and generated dependency directories, including `.git`, virtual environments, caches, build outputs, `node_modules`, `target`, and `vendor`;
- directory and file symlinks;
- files and directories that cross the pinned repository filesystem boundary;
- regular files with more than one hard link, preventing an external alias from changing repository context;
- non-regular files;
- sensitive paths identified by repository policy;
- files over the per-file or total-byte ceiling;
- unreadable, binary, or non-UTF-8 content;
- credential-shaped content;
- content or ancestry that changes during descriptor-pinned validation.

Exclusion is evidence: the file record retains path, category, byte count, policy reasons, digest when safely available, and secret-rule IDs without exposing the sensitive content.

### Selection order and budget

Allowed text is selected in this exact order, then by path:

1. governing instruction files;
2. manifests;
3. lock files;
4. CI/deployment configuration;
5. tests;
6. Python source;
7. documentation;
8. other files.

Each excerpt is truncated to the configured character ceiling. UTF-8 byte length is used as `utf8-bytes-as-token-upper-bound-v1`, a deliberately conservative upper bound rather than a provider token claim. Reserved output tokens are subtracted first. A file that would exceed the remaining bound is recorded with `selection_blocker="context_token_budget"`.

Default policy:

| Limit | Default |
|---|---:|
| Files scanned | 10,000 |
| Bytes per file | 2,000,000 |
| Total readable bytes | 25,000,000 |
| Excerpt characters | 4,000 |
| Python symbols per file | 256 |
| Python imports per file | 256 |
| Input token ceiling | 12,000 |
| Reserved output tokens | 4,096 |

### Manifest contents

The final manifest binds:

- repository ID and exact source revision;
- objective and diagnostics SHA-256 values;
- complete file provenance and exclusions;
- selected excerpts with file/text digests, line range, byte count, token bound, and truncation flag;
- instruction scope, depth, precedence, digest, and whether selected;
- Python symbols, imports, and parse errors;
- manifest, lock, CI, and test project signals;
- normalized diagnostic records with repository-relative or hashed external paths and redacted messages;
- scan truncation/blockers;
- source-tree digest;
- exact token-budget arithmetic;
- digest of the entire unsigned manifest.

The manifest validator requires path ordering, one-to-one agreement between selected files and excerpts, exact arithmetic, and an exact digest.

## 2. From retrieval artifact to reasoning context

The deterministic `context-manifest-v1` artifact and the reasoning-role `ContextManifest` version `1.0.0` serve different layers:

- the deterministic artifact proves what the controller actually scanned and selected;
- the reasoning contract binds a task, source, policy, retrieval-plan digest, evidence references, missing evidence, token accounting, and compaction status for model consumption.

The controller must perform an explicit transformation that preserves the deterministic artifact digest and only emits referenced excerpts. A model must never create or upgrade local provenance. The active private Workbench now does this for its bounded planner: `WorkbenchController` builds the deterministic manifest from the task workspace, verifies the source snapshot before and after the scan, rejects truncation or prohibited content, records the manifest and source-tree digests as evidence, and passes a relative-path-only `workbench-planning-context-v2` projection to the planner. This projection does not replace the separate reasoning-role `ContextManifest`; that full multi-role adapter remains unreconciled.

## 3. Memory lifecycle

Memory is not an automatic transcript or model-side state. It is a controller-owned record of a verified outcome, causal claim, or procedure guardrail.

### Candidate creation

A `MemoryRecord` begins in `candidate` state and binds:

- repository, source revision, and source-tree digest;
- task, context-manifest, prompt, model-policy, and tool-registry digests;
- effective model and verifier principal;
- a unique sorted set of evidence digests;
- verification time, retention end, statement, outcome, confidence, and explicit reuse conditions;
- its own canonical record digest.

Candidates cannot claim promotion, quarantine, or invalidation.

### Promotion

Promotion requires a separate `PromotionGrant` with authority scope `memory:promote`. The grant is bound to one principal, repository, exact candidate-record digest, authority-evidence digest, issuance, expiry, and grant digest.

Promotion fails unless:

- the record is still a clean candidate;
- the principal is in the controller's authorized set;
- repository and candidate digest match;
- the grant is currently active;
- retention has not expired.

Only a promoted record can ever be reused.

### Reuse assessment

Every use requires a fresh `MemoryReuseContext`. The assessment compares repository, revision, tree, model policy, tool registry, verifier revocation, evidence trust/quarantine sets, and retention.

| Condition | Disposition |
|---|---|
| Retention expired; repository/revision/tree/policy/tool registry changed | `invalidate` |
| Verifier revoked; evidence untrusted or quarantined | `quarantine` |
| Record not promoted | `hold` |
| All provenance and authority gates satisfied | `reuse` |

Only `reuse` sets `reusable=true`. Applying an adverse assessment removes any promotion grant and writes exact reasons into a newly digested immutable record.

### Deletion

Deletion produces a non-content `MemoryTombstone` containing record ID, deleted-record digest, deletion-authority digest, deletion time, and tombstone digest. Deleted memory digests propagate into the training contamination index so erased source material is excluded from future training exports.

## 4. Threat and failure model

| Threat | Control |
|---|---|
| Prompt injection in repository text | Retrieved text is evidence only; stable prompts mark it untrusted |
| Secret exfiltration | Sensitive paths/content excluded; diagnostic messages redacted; provider input/output scanned |
| Repository race during scan | Metadata/size/hash/read consistency checks fail closed |
| Token overflow | Output reserve plus conservative UTF-8-byte upper bound |
| Instruction shadowing | Instruction scope, depth, precedence, and digest are explicit |
| Stale memory | Revision/tree/policy/tool changes invalidate reuse |
| Poisoned evidence | Trust and quarantine sets gate reuse |
| Unauthorized learning | Separate expiring promotion authority; candidates are not reusable |
| Deletion resurrection | Tombstone digest feeds training exclusion |

## 5. Compaction and provider caching

Local deterministic context selection is implemented. Provider explicit compaction is a different capability and remains `BLOCKED`; this architecture must not label excerpting as provider compaction.

Stable prompt prefixes allow potential provider caching, but the live evidence observed zero cached tokens. No cache-hit telemetry is qualified, and cost or latency claims must not assume a cache hit.

## 6. Current integration and remaining requirements

The active private Workbench surrounds this planning path with the authoritative canonical bridge: `WorkbenchStore` and `CanonicalStateStore` share one SQLite connection and lock, with migration `0010_workbench_canonical_authority.sql` binding the compatibility projection to canonical task and approval authority. That integration does not make model, runner, memory, verifier, delivery, or publisher capabilities operational.

Remaining end-to-end requirements are:

1. transform the deterministic artifact into the separate reasoning-role `ContextManifest` for the multi-role pipeline;
2. revalidate source binding before candidate generation, checks, verification, and finalization;
3. expose memory only after a current reuse assessment returns `reuse`;
4. quarantine or invalidate memory on any binding change;
5. propagate tombstones into every training contamination index;
6. reconcile legacy non-Workbench, full multi-role, and future publisher paths with canonical authority;
7. add integration tests proving that those paths cannot bypass these gates.

The current accurate verdict is: **deterministic retrieval is active and offline-tested for private Workbench planning; memory governance and the legacy, full multi-role, and future publisher paths are not end-to-end active or operational**.
