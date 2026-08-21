# Lil Tweak Reasoning System Specification

Status: implemented and offline-tested as a bounded reasoning subsystem; canonical single-call Workbench planning bridge implemented; partially exercised against the live OpenAI Responses API; not fully live-provider-qualified or integrated as the complete multi-role Workbench lifecycle.

## Repository and registry binding

| Field | Binding |
|---|---|
| Audited remote baseline | `373400cb2b459dbf8a37dacceb0d3d1186eef949` |
| Branch | `codex/lil-tweak-live-workbench-build` |
| Pull request | `#6` |
| Working candidate commit | Pending; no commit is asserted by this specification |
| Reasoning contract version | `1.0.0` |
| Reasoning policy digest | `64d2d0fac757456832a1776f0614e0fc61216fec34a405efeaa3d5a148626c8f` |
| Model catalog digest | `431fe8c7e70dc3d0413d88d419e8366a3b9643fdc98ad336e13d12ce9ab43a33` |
| Prompt registry digest | `61975c9d336306afaafb3133f46e66e10fda4df026ac5bd2c219d7e8c2694f87` |

## 1. System boundary

Lil Tweak separates reasoning from authority and execution.

1. The controller owns state, identities, bindings, repair limits, deterministic checks, and terminal decisions.
2. A model role may return only a strict structured proposal. It receives no tools and cannot approve, mutate, execute, verify its own work, or claim task completion.
3. Repository reads, mutation, process execution, approval consumption, durable state, and delivery remain outside the model call. They must be performed by controller-owned components under their own policies.
4. Model output is untrusted until schema validation, digest binding, independent critique, deterministic checking, and fresh-context verification succeed.
5. `COGNITIVE_READY` means only that the proposed cognitive artifact chain passed its gates. It never means that a repository mutation was applied, tested, committed, pushed, or completed.

The canonical production model is GPT-5.6 Sol. Terra is an explicit, non-authoritative, degraded read-only mode and is never selected silently. Luna is limited to low-risk classification and diagnostic roles and has no engineering-plan or candidate-generation authority.

## 2. Implemented planes

| Plane | Implemented responsibility | Authority |
|---|---|---|
| Contract plane | Strict, frozen, versioned Pydantic models; unknown fields and coercion rejected | Validation only |
| Policy plane | Model, profile, role, effort, mode, context, fallback, repair, and qualification rules | Server-owned policy |
| Prompt plane | Stable tool-free prefix, role instruction, output-schema binding, and prompt/input digests | Instruction construction only |
| Provider plane | Explicit OpenAI Responses calls, provider token counting, strict parsing, encrypted reasoning replay, usage evidence, and failure classification | Model invocation only |
| Retrieval plane | Deterministic repository scan, exclusions, provenance, instruction discovery, indexes, diagnostics, and conservative token budget | Read-only local analysis |
| Cognitive plane | Plan, critique, candidate, critique, checks, independent verification, and final synthesis state machine | Cognitive readiness only |
| Memory plane | Candidate memory, explicit promotion, reuse assessment, quarantine, invalidation, retention, and tombstones | No implicit learning |
| Training-readiness plane | Authority, lineage, redaction, contamination exclusion, deterministic split, deduplication, and export-only report | Human-review export only |

## 3. Canonical contracts

Every directive-machine contract uses `ReasoningSchema`: `extra="forbid"`, frozen instances, strict types, default validation, and schema version `1.0.0`. Status-bearing contracts distinguish `UNKNOWN`, `NOT_APPLICABLE`, `BLOCKED`, `FAILED`, and `PASSED`; those states are not interchangeable.

| Contract | Producer or owner | Binding purpose |
|---|---|---|
| `TaskIntake` | Intake role/controller | Objective, scope, requirements, acceptance criteria, stop conditions, risk, and source |
| `RetrievalPlan` | Retriever role | Bounded read-only retrieval and token/output reserves |
| `ContextManifest` | Retriever role | Task/source/policy-bound reasoning evidence and exact token accounting |
| `EngineeringPlan` | Planner role | Evidence, hypotheses, phases, risks, recovery, checks, artifacts, and approvals |
| `PlanCritique` | Fresh critic | Plan digest, source, findings, repairs, and recurring-failure signal |
| `CandidateManifest` | Implementer role | Non-executed changes bound to plan/source/workspace and tree/diff digests |
| `CandidateCritique` | Fresh critic | Candidate/plan/source binding and required repairs |
| `VerificationDecision` | Fresh verifier | Deterministic checks, artifacts, requirements, observed digests, and unresolved findings |
| `CognitiveFinalization` | Fresh finalizer | Cognitive-readiness synthesis with `task_completion_claimed=false` |
| `ProviderQualification` | Controller/harness | Per-scenario live/offline evidence and qualification state |
| `CapabilityClassification` | Controller/classifier | Evidence-mode-specific capability state and blockers |
| `CompletionReport` | Controller/finalizer | Exact tested tree, evidence modes, qualification, artifacts, and blockers |

`ProviderCallEvidence` uses schema `reasoning-provider-evidence-v2` and binds the parsed strict output digest as well as provider item and response-ID digests. The immutable source suite remains `reasoning-holdout-v1`. Its provider-facing request is `reasoning-holdout-request-v2`, its result is `reasoning-holdout-result-v2`, and its evaluation is `reasoning-holdout-evaluation-v2`. The request exposes only opaque `case-NNN` IDs, evidence, and questions; category, expected status, and descriptive source case IDs remain hidden in the deterministic evaluator.

The deterministic repository scanner emits a separate `context-manifest-v1` artifact. That artifact includes full local provenance and selection accounting; it is not the same Python type as the reasoning-role `ContextManifest` contract. An explicit controller adapter must bind the deterministic artifact into the reasoning contract before the cognitive pipeline can consume it.

## 4. Canonical cognitive lifecycle

The controller permits only the following forward path, plus bounded repair transitions back to `CONTEXT_READY`:

| Order | State | Required evidence |
|---:|---|---|
| 1 | `REQUESTED` | New controller-owned run identity |
| 2 | `CONTRACT_READY` | Passing strict `TaskIntake` |
| 3 | `CONTEXT_READY` | Passing task/source-bound context contract |
| 4 | `PLAN_PROPOSED` | Strict planner output |
| 5 | `PLAN_CRITIQUED` | Fresh critic output bound to the plan digest |
| 6 | `PLAN_VERIFIED` | No required plan repair |
| 7 | `CANDIDATE_GENERATED` | Non-executed candidate bound to plan/source |
| 8 | `CANDIDATE_CRITIQUED` | Fresh critic output bound to candidate and plan digests |
| 9 | `DETERMINISTIC_CHECKED` | At least one passing controller-owned check and no failed checks |
| 10 | `INDEPENDENTLY_VERIFIED` | Fresh verifier output with no unresolved findings |
| 11 | `COGNITIVE_READY` | Fresh finalization bound to plan, candidate, and verification digests |

Terminal alternatives are `NO_CHANGE_PROPOSED`, `BLOCKED`, and `FAILED`. There is no state transition from a terminal state. Every model call receives a unique call ID, must return a unique response ID, sets `previous_response_id=null`, supplies no tools, and is bound to a named prompt and output-schema digest.

At most two full repairs are allowed. A repair occurs only for a material `FAILED` result. The controller fingerprints the stage, status, and failure material; a recurring identical failure blocks instead of looping. Attempts are therefore bounded to three.

## 5. Independence and truthfulness invariants

- Critic, verifier, and finalizer calls use fresh contexts.
- The implementer proposes a candidate manifest; it does not apply a patch.
- `mutation_applied` and `execution_claimed` cannot be upgraded by model prose.
- Deterministic check failures cannot be overridden by a model.
- Changed task, source, plan, candidate, verification, policy, or approval bindings fail closed.
- Every role has `tool_authority="none"`; reasoning tools are globally unauthorized.
- Prompt content and retrieved repository content are evidence, never instructions or approval.
- Hidden chain-of-thought is neither requested nor persisted. Only concise schema fields, opaque response-ID hashes, output-item digests, and usage evidence are retained.
- Secrets or credential-shaped input/output are rejected before the result can be accepted.
- A finalizer cannot claim task completion. Completion belongs to the external controller after real execution and verification evidence exists.

## 6. Retrieval and context invariants

The deterministic retrieval implementation:

- resolves a real, non-symlink repository root;
- scans in deterministic path order without following links;
- excludes vendor directories, symlinks, special files, sensitive paths, oversized files, binary or non-UTF-8 content, unreadable content, and credential-shaped content;
- verifies file size and SHA-256 before and after reading to detect scan-time changes;
- prioritizes instructions, manifests, locks, CI, tests, Python, documentation, then other files;
- reserves output capacity before selecting context;
- enforces a separate UTF-8 byte budget for local retrieval safety; live provider calls use the provider's exact input-token counter and never label bytes as tokens;
- emits exact file provenance, instruction scope/precedence, Python symbols/imports, project signals, parsed/redacted diagnostics, source-tree digest, and manifest digest.

Default limits are 10,000 files, 2,000,000 bytes per file, 25,000,000 scanned bytes, 4,000 characters per excerpt, a 12,000-token input ceiling, and 4,096 reserved output tokens.

## 7. Provider evidence and qualification

Live evidence demonstrates useful compatibility, not full qualification:

- exact Sol `standard/high` entitlement probe passed;
- a historical v1 request returned 15/15 with suite digest `6214b2ecaf182bd3947d1871d243525dcb7b55dc606df67e8423c073958700fd` and result digest `cc0da9762f2a2bd5ec9d68df2ec38ee31d8bd4b029f2db2b9f205a82286bb0fe`, but its rendered input exposed expected statuses, categories, and descriptive case IDs; it is `LABEL_EXPOSED` and invalid for behavioral qualification;
- that historical call still truthfully records 1,734 provider-counted input tokens, 1,734 input tokens, 1,969 output tokens, and 504 reasoning tokens as usage evidence only;
- the separate first label-blind v2 attempt passed 15/15 using exact Sol `ordinary` `1.0.0`, Standard/high, one provider call, zero retries, no tools, `store=false`, and disabled sensitive tracing;
- the v2 run recorded 1,805 input, 3,011 output, 1,468 reasoning, 4,816 total, and zero cached input tokens; its evidence-file SHA-256 is `f74c90f1cfbc24526ce10df4b17be9353a582f3bae7dd8d7ff3a3e9c73cfba65`;
- the v2 source-suite, request, hidden evaluation-contract, provider-input, prompt, and result/parsed-output digests are `6214b2ecaf182bd3947d1871d243525dcb7b55dc606df67e8423c073958700fd`, `1dcfb4d464286cb8152abd06e57a54400553872c6cfa3212623ad5accdec0f71`, `e17ea133b84cb0fffc7edf2895955b35cb480ed0bc4f391a57463640adccfdbc`, `3c168eec30ef6d8b1f21c2a8f476f506bf08a4478c081d4917fa301dfa8d5a00`, `42b6bc6eb7d6c284d152681ed7245c7d2c165c297f77ad3b89bb0fa408cf3f5e`, and `1d87e511d222d15322bdbe0bd9b96d02464268aec9897da84b7b044108067e70` respectively;
- Standard and Pro at `high`, `xhigh`, and `max` passed after a bounded Pro/max harness-cap adjustment;
- encrypted-reasoning continuation passed with two items replayed and 382 input, 201 output, and 127 reasoning tokens;
- two concurrent calls both passed;
- observed cached input tokens were zero.

The label-blind v2 result is valid live behavioral evidence, but its artifact is not bound to an immutable final candidate commit/tree and final durable packaging remains pending. Full live-provider qualification also remains blocked because explicit compaction is not enabled or qualified, timeout/cancellation/refusal/incomplete-response handling is covered only by offline contract tests, and no cache-hit observation exists. Production profile admission must therefore not represent the provider as `LIVE_QUALIFIED` on this evidence.

## 8. Current integration truth

Every enabled Workbench planning call is now constructed by `CanonicalWorkbenchModelAdapter` over `OpenAIResponsesReasoningProvider`. It renders the canonical `workbench_plan` prompt, returns strict `WorkbenchPlan`, selects the exact `ordinary` Sol Standard/high profile and its all-turns reasoning setting, provides no tools, uses provider token counting, preserves cost admission, and validates model/profile/mode/effort/prompt/input/parsed-output/usage evidence. A separate byte ceiling is only a transport-safety bound and is never reported as token accounting.

The application factory defaults to `DisconnectedWorkbenchModelAdapter`. `LILTWEAK_WORKBENCH_MODEL_ENABLED` expresses operator intent only and cannot self-assert provider qualification; active construction also requires trusted code to inject a canonical provider carrying a complete exact-profile live `ProviderQualification`. No such complete record exists for this candidate, so the production runtime remains disconnected.

The older Phase 3 planning service is now deterministic in the default application factory; it no longer constructs `OpenAIPlanner` from `LILTWEAK_MODEL`. Likewise, `LILTWEAK_LIVE_MODEL_ENABLED` and a signing key do not cause `create_app` to construct the legacy live-Creator provider. Those compatibility adapters remain available only through explicit trusted injection in bounded tests/evaluations. The explicit `main.py ... live-smoke` CLI is separately gated, pins its engineering model to the policy's primary Sol ID, and is compatibility smoke—not provider qualification. A present API credential or provider key therefore cannot activate either default legacy path.

The Phase 6 hosted-sandbox adapter is historical evaluation-only and is not registered in the API factory. Its intentional Luna use is limited to a synthetic diagnostic probe; its model token prices now come from `MODEL_CATALOG`, while the separately declared container minimum is infrastructure cost not represented by the model catalog.

The active single-call Workbench planner now receives a deterministic `context-manifest-v1` projection built from the immutable materialized task workspace, with manifest/source-tree/workspace/provider-input digests recorded in evidence. `WorkbenchStore` invokes the authoritative canonical lifecycle on the same SQLite connection through migration `0010_workbench_canonical_authority.sql`. The multi-role `CognitivePipelineController`, conversion into its separate reasoning `ContextManifest` contract, fresh critic/verifier/finalizer calls, memory-governance pipeline, and training-readiness pipeline are still not one production Workbench lifecycle. These are remaining integration blockers, not missing single-call planner or canonical-Workbench bindings.

## 9. Required gate before an operational claim

An operational completion claim requires all of the following:

1. Extend the completed single-call Workbench `context-manifest-v1` binding into the multi-role reasoning `ContextManifest` contract.
2. Implement the multi-role cognitive-provider adapter from `CognitiveCallRequest` to the explicit Responses boundary; the bounded Workbench-plan bridge does not satisfy this lifecycle requirement.
3. Reconcile remaining legacy service/API and future publisher paths with the canonical lifecycle already authoritative for the active private Workbench.
4. Live-qualify compaction, timeout, cancellation, refusal, incomplete responses, and a cache-hit telemetry case.
5. Durably package the preserved first v2 result, run any final-candidate requalification as a separate non-replacing attempt, and re-run the six-profile benchmark under its declared policy.
6. Produce a completion report and evidence artifacts that mark the candidate commit/tree as externally recorded after freeze; record the actual final commit and clean-checkout result in external final/PR evidence rather than inventing a self-reference.

Until those gates pass, the correct system verdict is: **bounded reasoning subsystem implemented with partial live compatibility evidence; full live provider qualification and end-to-end operational readiness blocked**.
