# Lil' Tueeq: Super Geek Respectability Exercise

## Scope and source

Owner request, September 18, 2026: give the Super Geek a serious exercise in GitHub while model usage is unavailable. This is an application of the owner-supplied **Agent Respectability Engineering** skill, not model fine-tuning or a new agent subsystem.

Source attachment: `Agent_Respectability_Engineering_SKILL.md`.
Source SHA-256: `c7e32fe7d15849459b3a8e1951c793d8619e8422d82273f37c7aab68c189ba29`.
Audited base: `f3023620f4d13f51001e7934f433ab56cc3dd712`.
Immutable failing-test commit: `d956966c94ecc46d8488bf9b1fba2f637ae8b491`.

No paid model calls, model replacement, self-hosted runner use, infrastructure mutation, secret access, automatic merge, or deployment is part of this exercise. The production changes proposed here are restricted to two existing Python control-layer modules. A passing report is evidence of the named checks, not a production-readiness certificate.

## 1. Agent Architecture Audit

The examined path is the private request verifier (`core/lil_tweak/signing.py`) and the job authority policy (`core/lil_tweak/state.py`), using the existing protocol enums in `contracts.py`. These are below the model. The repository also contains state-store, evidence, ingestion, sandbox, runner, Test World, Skill Forge, and failure-recovery suites. The new CI runs the complete existing Python test discovery as a separate check; its actual result and skips are recorded rather than assumed.

This audit is deliberately bounded. It does not establish that malformed values can reach these functions through a live HTTP endpoint. It does not test a running deployment, the model's reasoning, or every caller and database transaction.

## 2. Critical Invariants

- Applying a proposal requires `approval_recorded is True`, `approval_consumed is False`, and matching string digests. Truthy strings, integers, arrays, and mappings are not authority.
- Changed proposals cannot borrow an old approval. Invalid digest representations reject with the existing approval error instead of escaping as a type error.
- Only the awaiting-approval state may enter applying. Every terminal state rejects every outgoing transition.
- Every signed request field and the body are bound to the signature. Forged, malformed, stale, and future requests must not consume a legitimate nonce.
- A nonce-store callback authorizes success only by returning literal `True`; replay and malformed callback results fail closed.
- The scorekeeper must reject an empty suite, expose skips and expected failures, preserve failing test IDs, and never certify deployment.

## 3. Authority Map

Existing `SideEffect` rules are preserved: local read/write/test do not require the external-action approval gate; commit, push, deploy, publish, external delete, send-message, and spend do. Unknown effects reject. This PR does not grant the agent permission to perform any of those external actions.

The test strings such as "not approved" are deliberately passed as malformed serialized approval flags. They are **not** a certification of natural-language approval recognition, voice transcription, or HTTP-level authorization.

## 4. Evidence / Truth Model

`PASS` means the requested tests actually ran without failures, errors, skips, or expected failures. `PASS_WITH_GAPS` exposes skips/expected failures; it is not a full pass. `FAIL` includes zero executed tests. The report includes the checked-out commit, source-file SHA-256 hashes, timestamps, repetitions, counts, and bounded failing-test identifiers. `deployment_certified` is always false for this limited exercise.

CI additionally replays the immutable pre-fix commit in a separate directory and requires the known red result. This proves the regressions actually break the prior implementation; no test is weakened to produce green.

## 5. Tool Safety Matrix

| Operation | Allowed here | Enforcement / evidence |
| --- | --- | --- |
| Read and test repository code | Yes | Exact-head checkout; contents-read token only |
| Use a real AI provider | No | No provider secrets; tests execute in a network namespace without external networking |
| Run local HTTP test fixtures | Yes | Loopback enabled inside the isolated namespace |
| Write test evidence | Yes | Runner-owned temporary directories; complete JSON atomically replaced |
| Modify production host, deploy, spend, send outreach | No | No such workflow steps or credentials |
| Merge this PR | Not automatic | Owner review remains separate |

Network isolation applies to the CI test commands and child processes, not to checkout/setup/artifact-upload steps. Invoking the Python script alone is not a network sandbox. The existing Python tests may create temporary local repositories and files; that is not a remote push or production write.

## 6. Persistence / Recovery Model

The state-machine tests exhaust terminal-state transitions but do not prove durable database restart or race safety. The nonce tests verify the production verifier's callback contract; their controlled callback is **not** proof of a real nonce store's concurrency behavior. Existing persistence and recovery suites are included in full Python discovery, with actual skips/errors retained.

The scorecard uses a temporary file, flush/fsync, and atomic replacement, so readers do not receive partially written JSON. This is not a claim of complete machine power-loss durability, immutable evidence storage, or tamper-proof signing. GitHub's job outcome remains authoritative if a process dies before report publication.

## 7. Threat Matrix

| Threat | Exercise | Limitation |
| --- | --- | --- |
| Approval type confusion | Truthy and falsy serialized impostors | Function boundary, not live API exploit |
| Approval reuse on changed work | 300 seeded proposal-digest mutations | No database race claim |
| Signed request substitution | 300 seeded field mutations | Known canonical protocol only |
| Replay / nonce poisoning | Forged body followed by valid request; repeated request; malformed callback results | Callback contract, not distributed exactly-once proof |
| Malformed auth input | Wrong-type signatures/targets and unsafe target forms | Not exhaustive parser fuzzing |
| State resurrection | Every terminal state against every target state | Pure policy, not storage corruption recovery |
| False green evidence | Scorekeeper tests for zero tests, skips, expected failures, and actual failures | Report hashes are not signatures |

## 8. Stress Gauntlet

Command: `python3 -B scripts/run-respectability-gauntlet.py --suite focused --repeat 3`.
Broader command: `python3 -B scripts/run-respectability-gauntlet.py --suite core --repeat 1 --output respectability-results/core.json`.

The focused exercise has **25 test methods and 764 subtest cases per repetition**, including 600 seeded tampering cases using seeds `7`, `101`, and `20260918`. Repetitions intentionally reuse those seeds for reproducibility. This is not 764 independent model conversations.

The skill's wave numbering is preserved below. Existing test modules are starting points for further work, not automatic proof of a whole wave.

| Skill wave | This exercise / next proof obligation |
| --- | --- |
| 0 Static correctness | Compile changed Python; run focused and complete Python suites. Frontend lint/typecheck/build and installed-package smoke are not supplied by this workflow. |
| 1 Authority attacks | New typed-flag/digest/state cases. Natural-language, voice, and endpoint ambiguity remain separate obligations. |
| 2 Tool abuse | New signed-request, replay, nonce-contract cases; existing runner/sandbox/API suites run in core discovery. Real side-effect concurrency remains unproved here. |
| 3 Prompt / ingestion poisoning | Existing archive/source-intake suites run. New hostile PDF/image/decompression campaigns are not claimed. |
| 4 Evidence poisoning | Existing evidence tests run. Full scoped contradiction/supersession campaign is not claimed. |
| 5 Persistence / restart | Existing store/recovery tests run. Production restart certification is not claimed. |
| 6 Concurrency | Existing concurrency tests run. Distributed worker exactly-once proof is not claimed. |
| 7 Resource exhaustion | Existing configured-limit tests run. Broad memory/storage/load torture is not claimed. |
| 8 Deep state torture | TEST_REQUIRED: 50+ revisions, long histories, authoritative lineage under restart. |
| 9 Crash injection | TEST_REQUIRED: real process death around writes, claims, result persistence, and artifact publication. |
| 10 Randomized / fuzz | New seeded boundary mutations and three repeat runs; broader provider/state/order fuzzing remains TEST_REQUIRED. |

## 9. Failure Register

Local reproduction used source files verified against their GitHub blob hashes, on Python 3.13.5. The original 19 tests produced **22 failing subtests and 14 erroring subtests**. The GitHub workflow must independently reproduce that red result on Python 3.12.

| ID | Reproduced defect | Minimal correction |
| --- | --- | --- |
| RSP-001 | Truthy non-booleans satisfied recorded approval | Require literal `True` |
| RSP-002 | Falsy non-booleans satisfied unconsumed approval | Require literal `False` |
| RSP-003 | Truthy non-booleans from nonce callback reported success | Require literal `True` |
| RSP-004 | Malformed/non-text approval digests escaped rejection or could compare as bytes | String-only comparison; malformed comparison returns false |
| RSP-005 | Wrong-type signatures escaped uniform authentication failure | Validate signature type before comparison |
| RSP-006 | Wrong-type request targets escaped uniform authentication failure | Validate target type before parsing |

These are reproduced control-function defects. External exploitability, deployed impact, and incident history are UNKNOWN, not inferred.

## 10. Regression Test Register

RSP-001: `test_recorded_approval_requires_literal_true`.
RSP-002: `test_consumed_approval_requires_literal_false`.
RSP-003: `test_nonce_claim_requires_literal_true`.
RSP-004: `test_malformed_approval_digests_fail_closed`.
RSP-005: `test_malformed_signatures_have_uniform_authentication_failure`.
RSP-006: `test_malformed_targets_have_uniform_authentication_failure`.

Additional tests preserve valid approvals, equivalent query ordering, uppercase signatures, clock-skew boundaries, tamper rejection, terminal-state invariants, and storage-error visibility. Six scorekeeper tests prevent invented green results or partial report publication.

## 11. Current Maturity Level

**NOT CERTIFIED by this bounded exercise.** The inspected deterministic controls are evidence consistent with some Level 2 (Governed Agent) requirements, but the whole-agent criteria have not been audited sufficiently to award a level. Neither a feature list nor this focused pass establishes Level 3, 4, or 5.

## 12. Deployment Gate Status

**BLOCKED FOR RESPECTABILITY CERTIFICATION pending the complete applicable gauntlet and owner review.** This document/report is not wired into existing deployment workflows and does not claim to impose a repository-wide release lock. No merge, deployment, production configuration, model selection, or existing release workflow is changed here.

GitHub CI artifacts on the exact final head are the execution record. A local pass is not substituted for a GitHub pass, a skipped test is not certified, and a model's claim of completion is not execution evidence.
