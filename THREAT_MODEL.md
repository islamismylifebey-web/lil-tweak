# Threat Model

## Scope and claim boundary

This threat model describes the Lil Tweak repository on branch
`codex/lil-tweak-live-workbench-build`, derived from audited baseline
`373400cb2b459dbf8a37dacceb0d3d1186eef949`. The final candidate commit is intentionally recorded
outside committed artifacts after the tree is frozen.

The repository contains implemented contracts and offline-testable security mechanisms. That is
not evidence that every production path is integrated, connected, independently qualified, or
operational. In particular:

- `liltweak/canonical_lifecycle.py`, `liltweak/canonical_store.py`, and migrations
  `0009_canonical_control_plane.sql` and `0010_workbench_canonical_authority.sql` define the
  canonical control plane used authoritatively by the active private Workbench on the same SQLite
  connection. Descriptor-pinned context is integrated and tested there. Legacy/future publisher
  paths remain unreconciled.
- The cognitive pipeline is a non-authoritative model substate machine. Its fresh critic and
  verifier contexts are separate model calls, not independent security principals.
- The label-blind v2 holdout passed 15/15 in one live call with zero retries, and Chromium 149
  acceptance produced 30 PASS / 3 BLOCKED / 0 FAIL. Full production-provider qualification,
  runner, external checkpoint, repository publisher, owner-tree apply, local commit, and rollback
  remain disabled, disconnected, blocked, or unqualified as applicable.
- Mocks, fakes, in-memory adapters, configured model names, schema validation, and passing offline
  tests do not establish a live capability.

An earlier mutable tree reported 597 passed, 0 failed, 0 skipped, and one known warning. Wheel
and sdist builds pass with setuptools 82.0.1 and wheel 0.47.0. These results and the browser
artifacts are mutable working-tree checkpoints, not immutable final-candidate evidence.

The controlling verdict is **FAILED — RELEASE GATES NOT MET**. Every report
must preserve the distinction between implemented, offline tested, installed, configured,
connected, healthy, qualified, authorized, and operational.

## Protected assets and trust domains

Protected assets include owner sessions and approval authority; provider, signing, publisher, and
runner credentials; repository bytes, modes, Git identity, and pre-existing owner work; task,
policy, model, context, and source bindings; approval nonces and leases; evidence and control-audit
chains; recovery material; external checkpoint receipts; private prompts and minimized source
context; training-data authority and lineage; and capability/qualification truthfulness.

Lil Tweak treats these as separate trust domains:

1. **Control plane:** authentication, policy, state, context assembly, and authorization.
2. **Model plane:** structured reasoning and proposals only.
3. **Runner plane:** isolated execution of untrusted repository code.
4. **Verifier/evidence plane:** deterministic checks, independent qualification, and authoritative
   evidence.
5. **Publisher plane:** separately approved owner-tree apply, local commit, and rollback.

Repository content, instructions, comments, issues, model output, memory, retrieved documents,
webpages, tool output, logs, test output, and task artifacts are untrusted evidence. None grants
authority. "Independent" requires a different security principal and trust boundary with separate
key custody; another function, process-local object, or fresh call to the same model is not enough.

## Implemented controls and residual risk

| Threat | Implemented or specified control | Residual or unqualified boundary |
|---|---|---|
| Prompt injection or model self-authorization | Strict role contracts, schema rejection, tool-free cognitive calls, server-owned policy, non-authoritative candidate/verification/finalization flags, and the active Workbench's canonical lifecycle and descriptor-pinned context path. | The v2 holdout passed, but the provider is not fully qualified or injected into the production Workbench. The cognitive verifier is not an independent security principal. |
| False approved, tested, verified, connected, or completed claims | Typed status enums and capability gates keep individual prerequisites separate. Cognitive contracts set mutation, execution, completion authorization, and task-completion claims to false. The current Workbench uses the canonical status path and stops after local `VERIFIED` when independent examiner verification is false. Chromium acceptance reported 30 PASS / 3 BLOCKED / 0 FAIL. | No independent verifier principal is connected. The three browser-blocked operational cases and exact-candidate evidence remain unresolved. |
| Illegal, stale, duplicate, or concurrent lifecycle mutation | Canonical state models are frozen; legal transitions are checked in code and a SQLite trigger; task and capability updates use optimistic versions; runtime generation fencing, active dispatch leases, transactions, and specialized atomic APIs exist. The active Workbench uses this store authoritatively on the same SQLite connection. | Legacy/future publisher paths and multi-process/database deployment behavior remain unreconciled or unqualified; restart recovery has not been live-qualified. |
| Approval replay, expiry bypass, purpose confusion, or approval surviving changed facts | Canonical approvals bind task/version, purpose, operation, policy, capability snapshot, nonce, and expiry; approval consumption and evidence append occur transactionally; emergency stop revokes pending/approved approvals and cancels active leases. | Founder authentication and an approval signer outside model/runner authority are not connected to the canonical store. Exact bindings for model/profile, source, runner/image, network, final diff, and independent checkpoint still require end-to-end integration and live proof. |
| Restart, crash, or database restoration revives unsafe work | Runtime IDs, generations, restart-unsafe states, reconciliation, emergency stop, leases, hash-chained control events, and transactional SQLite updates are implemented in the canonical store. | Same-database checks cannot detect restoration of an older internally valid database and anchor. Crash/restart behavior on a production multi-process deployment is unqualified. |
| Host-header injection, DNS rebinding, cross-origin mutation, CSRF, session replay, or rate abuse | Private Workbench requests validate a configured loopback Host; mutation requests with `Origin` require exact scheme, host, and effective port; test-only `testserver` is environment-gated. Owner sessions are HMAC-signed, expiring, HttpOnly, SameSite Strict, Secure under HTTPS, and CSRF-bound. Logout revokes the current session in memory. Rate exhaustion returns HTTP 429 with `Retry-After`. Chromium 149 confirmed invalid Host returns 400, cross-origin Origin returns 403, IPv6 is refused, and listeners are cleared. | Missing `Origin` remains allowed for non-browser clients, which must still provide CSRF. Revocation and rate state are process-local and do not survive restart or coordinate across processes. Three browser cases remain blocked, including real-time expiry under the minimum 300-second TTL; proxy/TLS and broader deployment behavior remain unqualified. |
| Session/signing-key or provider-key theft | Secrets remain server-side; secret-shaped content is rejected or redacted at multiple boundaries; cookies and CSRF tokens do not expose the signing key. | Application memory and its host remain a trust domain. Key storage, rotation, recovery, process isolation, and external secret-manager integration are not qualified. An OpenAI call would transmit authorized minimized context to OpenAI and must not be described as local-only. |
| Path traversal, symlink/hardlink escape, special-file access, or owner-source mutation | Existing repository/workspace controls canonicalize paths, block unsafe file types and Git/control-plane paths, use immutable source captures and disposable workspaces, and scan for secrets. Structured publisher contracts bind exact source/final state and manifests. | No independently qualified production runner or publisher currently enforces these controls across the full lifecycle. Owner-tree preservation, hardlink/device/socket cases, binary policy, and exact rollback need live hostile trials. |
| Shell, command, Git-hook, filter, pager, editor, credential-helper, submodule, or external-diff injection | Tool and publisher contracts use structured executable/argument vectors and hardened Git environment rules; shell strings and caller-chosen executable authority are prohibited. | The repository publisher is an interface with a disabled default. The pytest-only publisher cannot touch or qualify an owner repository. Production apply, commit, and rollback remain blocked. |
| Runner escape, privilege escalation, network bypass, resource exhaustion, orphaned processes, or cleanup failure | Runner architecture and qualification contracts require an immutable digest-pinned image, non-root identity, namespaces, cgroup limits, seccomp/MAC policy, network denial, bounded output/storage, process-tree cancellation, and destruction evidence. | No production runner provider or independently capable/qualified host is connected. A sandbox prefix, subprocess, dormant transport, or mock cannot satisfy this boundary. Execution and browser execution remain default-off. GCP remains disabled and was not authorized by the directive. |
| Context poisoning, secret egress, missing governing instructions, or misleading token accounting | Deterministic context contracts cover provenance, governing files, secret/vendor/binary/oversize handling, bounded excerpts, and explicit token measurement/accounting modes. The active Workbench uses descriptor-pinned context; model calls are tool-free and source context is treated as evidence, not authority. | Production Workbench provider injection and live compaction, failure, cache, tokenizer/retrieval, and provider data-control qualification remain prerequisites. Legacy paths are not all reconciled. |
| Memory poisoning, stale knowledge, or learned authority | Memory records carry provenance, repository/source validity, evidence digests, confidence, retention, promotion grants, quarantine/invalidation rules, assessments, and tombstones. Model proposals cannot self-promote. | These contracts are not an operational durable-memory service in the current controller. Promotion principal separation, persistence, reconciliation, deletion propagation, and retrieval behavior need integration and adversarial qualification. |
| Unauthorized training, private-data inclusion, benchmark leakage, or silent self-modification | Training-readiness contracts require authority, redaction, lineage, deduplication, contamination indexes, repository/task/temporal holdouts, exclusions, and deletion propagation. Reports are export-only and `TRAINING_EXECUTION_AVAILABLE` is false. | No training or fine-tuning is enabled. Human label governance, storage, licensing/privacy review, dataset lifecycle, and training execution remain outside this implementation and require separate authorization. |
| Evidence tampering, deletion, truncation, or internally valid rollback | Local evidence and control events use canonical digests, previous-hash chaining, HMAC/authenticated anchors where already present, strict sequencing, and atomic append with sensitive transitions. External checkpoint request/expectation/receipt contracts bind ledger, task, sequence, chain head, prior receipt, and provider proof. | The external checkpoint client is disabled and has no independent retained backend, trusted clock/sequence source, key custody, startup reconciliation, outbox, or recovery procedure. Local HMAC/hash chains cannot alone detect deletion of all state or restoration of an older valid database. Anti-rollback is unqualified. |
| Publisher substitutes a different patch/tree, stages owner work, or performs an unauthorized Git action | Repository delivery contracts bind exact repository/source state, content-addressed final-tree and patch manifests, purpose-specific apply/commit/rollback approvals, structured Git commands, post-apply verification, and fail-closed capability truth. Binary mutation is blocked by policy. | The default publisher is disabled; the ephemeral publisher is test-only and non-operational. There is no isolated publisher principal, owner-tree integration, atomic apply/compensating restore, live local commit, or live rollback qualification. Push, PR, merge, release, and deployment are not Lil Tweak capabilities. |
| Supply-chain substitution, malicious dependency behavior, or unverifiable build | Lock and CI checks plus generated SBOM/license/provenance/scan artifact workflows can make dependency and build inputs reviewable. Wheel and sdist builds pass with explicitly configured setuptools 82.0.1 and wheel 0.47.0. | The vulnerability database is unavailable, three license findings require review, no qualified runner/image exists, and mutable-tree artifacts are not final-candidate provenance or reproducibility evidence. |

## Canonical lifecycle security properties

The source-derived state and transition inventory is frozen in
`COGNITIVE_AND_EXECUTION_STATE_MACHINES.json`. The canonical store additionally implements these
fail-closed properties:

- all execution-affecting capability gates (`model`, `runner`, `owner_tree_apply`, `local_commit`,
  `external_checkpoint`, and `browser_execution`) initialize to `DISABLED_BY_POLICY` with every
  operational prerequisite false;
- only legal forward transitions are accepted, with rollback and emergency paths explicit;
- operations that need approvals, dispatch, evidence sealing, patch readiness, apply, local commit,
  rollback, or completion use purpose-specific transactional APIs;
- stale task/capability versions and stale runtime generations fail closed;
- evidence records and control events are sequenced and hash chained;
- completion requires the configured required capabilities, verification/evidence bindings, and an
  external-checkpoint receipt digest at the canonical contract boundary; and
- emergency stop blocks new mutation, cancels active leases, revokes live approvals, and moves
  nonterminal tasks to `EMERGENCY_STOPPED`.

These properties now govern the active private Workbench through the authoritative canonical store
and same-connection compatibility projection. Legacy/future publisher paths remain unreconciled,
and independent providers remain unqualified, so this integration is not a claim of production
execution.

## Model and cognitive authority boundary

`gpt-5.6-sol` is the only configured primary engineering model. `gpt-5.6-terra` is limited to an
explicit degraded, read-only fallback after bounded Sol failure, and `gpt-5.6-luna` is limited to
separately justified low-risk classification or diagnostics. A configured identifier or catalog
entry does not prove entitlement, returned effective model, behavior, or qualification.

Every cognitive provider call has `tool_authority=none`, an empty tool list, and no previous
response ID. Critic and verifier calls require fresh context. Repair loops are bounded to at most
two full repairs. Candidate contracts cannot claim mutation or execution; verification cannot
authorize completion; finalization cannot claim task completion. `COGNITIVE_READY` means only that
the non-authoritative cognitive checks reached their terminal ready state. It never means
`COMPLETED`, applied, committed, pushed, released, or deployed.

## Production qualification blockers

The following must remain visibly blocked until evidence from the actual private environment is
recorded:

1. The v2 label-blind holdout passed 15/15 in one live call with zero retries. Full qualification
   still requires production Workbench provider injection, live compaction/failure/cache scenarios,
   truthful failure handling and usage reconciliation, and binding the result to the immutable
   final tree, suite, request, hidden evaluation contract, provider input, and parsed-output digests.
2. An independently qualified runner bound to the exact host, kernel, runtime image, isolation
   policy, transport, resource/network policy, attestation, and fresh dispatch authorization.
3. A genuinely independent append-only/monotonic checkpoint with separate principal/key custody,
   trusted sequence/time, startup and pre-gate verification, rotation, recovery, and rollback
   detection.
4. A separately authenticated publisher with exact owner-tree binding, distinct Founder-reviewed
   purpose-bound apply/commit/rollback approvals, atomic patch apply, post-apply verification,
   compensating restoration, local commit, and discretionary rollback trials.
5. Chromium 149 acceptance is partially complete at 30 PASS / 3 BLOCKED / 0 FAIL, with invalid
   Host 400, cross-origin Origin 403, IPv6 refusal, and listener cleanup observed. The three blocked
   cases and immutable final-candidate artifact binding still require qualification.
6. Cross-controller integration into one canonical policy/state/evidence path, plus concurrency,
   multi-process, crash, restart, migration, and disaster-restoration tests.
7. Final supply-chain evidence from an available vulnerability database, disposition of three
   license reviews, a qualified runner/image, and a clean immutable candidate build.

Until those gates pass, the exact verdict is **FAILED — RELEASE GATES NOT MET**. No component may
infer authority or operational status from another component's
configuration or test double.
