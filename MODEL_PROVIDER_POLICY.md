# Lil Tweak Model and Provider Policy

This policy binds the reasoning subsystem to explicit models, profiles, OpenAI Responses semantics, data controls, and fail-closed qualification. It does not grant any model tool, mutation, approval, or completion authority.

## Binding

| Field | Value |
|---|---|
| Audited remote baseline | `373400cb2b459dbf8a37dacceb0d3d1186eef949` |
| Branch / PR | `codex/lil-tweak-live-workbench-build` / `#6` |
| Working candidate commit | Pending |
| Policy ID / version | `lil-tweak.reasoning-policy` / `1.0.0` |
| Policy digest | `64d2d0fac757456832a1776f0614e0fc61216fec34a405efeaa3d5a148626c8f` |
| Catalog ID / version | `openai.gpt-5.6.model-catalog` / `2026-08-02.1` |
| Catalog digest | `431fe8c7e70dc3d0413d88d419e8366a3b9643fdc98ad336e13d12ce9ab43a33` |
| Standard price registry | `openai-standard-2026-08-02.1` |

## 1. Model-selection policy

| Model | Permitted use | Prohibited use |
|---|---|---|
| `gpt-5.6-sol` | Sole primary engineering model for intake through finalization | No tools, direct execution, approval, or completion authority |
| `gpt-5.6-terra` | Explicit degraded read-only fallback for analysis-oriented roles after separate live qualification | Never silent/default; never authoritative; no implementer role, candidate generation, or mutation-capable task |
| `gpt-5.6-luna` | Low-risk classification and diagnostics only | No engineering plan, candidate generation, critic/verifier authority, or fallback for primary engineering work |

All authoritative profiles require live qualification. A production caller must pass `LIVE_QUALIFIED` to `require_production_profile`; every other state fails closed. A model/profile change invalidates prior approval and must be re-bound and re-qualified.

The model capability catalog and the reasoning policy are deliberately separate. Capability or price metadata cannot silently change role authority, and role policy cannot invent provider features or prices.

## 2. Named profile policy

| Profile | Model | Mode / effort | Context | Roles | Repair cap |
|---|---|---|---|---|---:|
| `intake` | Sol | Standard / high | Current turn | Intake, retriever | 0 |
| `ordinary` | Sol | Standard / high | Stable all turns | Analyst, planner, implementer | 2 |
| `deep_architecture` | Sol | Standard / xhigh | Stable all turns | Architect, planner, implementer | 2 |
| `apex` | Sol | Pro / max | Stable all turns | Architect, planner, implementer | 2 |
| `critic` | Sol | Pro / max | Fresh | Critic | 2 |
| `verifier` | Sol | Pro / max | Fresh | Verifier | 2 |
| `finalizer` | Sol | Standard / high | Fresh | Finalizer | 0 |
| `terra_degraded_read_only` | Terra | Standard / high | Fresh | Read-only roles and diagnostic | 0 |

Configuration must name a registered profile and exactly match its model, request mode, and effort. Scattered overrides are rejected. Qualification harnesses may temporarily select one of the six benchmark variants; production calls may not override the selected profile.

Legacy environment flags are not qualification evidence. The default API uses deterministic planning and does not auto-construct either the Phase 3 `OpenAIPlanner` or the 0.6 live-Creator provider. `LILTWEAK_MODEL` is constrained to the canonical primary model for explicit compatibility CLIs, and `LILTWEAK_LIVE_MODEL_ENABLED` cannot connect a provider without trusted controller injection. That injection remains test/evaluation compatibility, not canonical production qualification.

## 3. Explicit Responses API boundary

The canonical provider is `openai-responses`, implemented with `AsyncOpenAI.responses`.

Every call must:

- use the profile's exact model ID;
- call the provider input-token counter with the same instructions, input, reasoning settings, strict text format, empty tools, and `parallel_tool_calls=false`;
- reject the request if provider-counted input exceeds the controller ceiling;
- call `responses.parse` with the required Pydantic output type;
- set explicit reasoning `mode`, `effort`, `context`, and `summary="auto"`;
- set `tools=[]`, `parallel_tool_calls=false`, `store=false`, and a bounded output ceiling and timeout;
- request `reasoning.encrypted_content` so provider-generated reasoning items can be replayed without storing or exposing hidden reasoning text;
- preserve every provider output item for continuation, removing only SDK-only parsed helpers and the output-only reasoning `status` field rejected on replay;
- validate effective model, completion status, refusal absence, strict output schema, secret policy, response ID, and usage arithmetic;
- emit only digested response/item identifiers, a digest of the accepted parsed output, and numeric usage evidence; when a billable response later fails semantic validation, preserve only its sanitized usage and response-ID digest for cost reconciliation.

The provider call has no handoffs and no tools. Sensitive tracing is disabled. Credentials are read through normal environment configuration and are never included in prompts, evidence, reports, or logs.

## 4. Context and continuation policy

Stable instructions precede volatile input so prefix caching is possible without blending evidence into authority. Critic, verifier, and finalizer roles use fresh controller calls with no previous response ID. The cognitive controller itself always sets `previous_response_id=null`.

Continuation qualification is a separate provider behavior: all prior provider-created output items, including encrypted reasoning content, are replayed as input items. The passed live continuation probe replayed two items. This proves that bounded continuation path, not general memory, conversation state, or explicit compaction.

Explicit compaction remains disabled or unavailable in the qualification harness and must be reported `BLOCKED`.

## 5. Data-control policy

- Treat task text, repository content, diagnostics, memory, and retrieved documents as untrusted evidence.
- Reject credential-shaped material before a provider call and in parsed output.
- Do not request, display, persist, or grade hidden chain-of-thought.
- Persist only strict role output, opaque/digested provider identifiers, output-item digests, explicit usage, and approved evidence artifacts.
- Disable provider storage and sensitive tracing for reasoning calls.
- Supply no tools or parallel tool calls.
- Do not send memory unless it is promoted, currently reusable, and bound to the active repository, revision, tree, policy, tool registry, verifier, retention, and evidence trust set.
- Never use live holdout cases or results as training examples.

## 6. Usage and pricing policy

The controller reserves bounded cost from declared token ceilings before the model call. The provider's exact input-token count is the authoritative request measurement and must remain within that reservation; UTF-8 bytes are a separate transport-safety limit and are never labeled as tokens. Returned usage must be non-negative, remain within controller ceilings, reconcile total tokens, and report cached and reasoning-token details. Missing or invalid usage fails closed, while sanitized billable usage from a rejected response is still charged to its admission.

Standard-tier prices are server-owned, versioned metadata. For inputs up to and including 272,000 tokens, short-context prices apply; long-context prices apply only above 272,000. All values are USD per one million tokens.

| Model | Short input / cached / cache-write / output | Long input / cached / cache-write / output |
|---|---|---|
| Sol | 5.00 / 0.50 / 6.25 / 30.00 | 10.00 / 1.00 / 12.50 / 45.00 |
| Terra | 2.00 / 0.20 / 2.50 / 12.00 | 4.00 / 0.40 / 5.00 / 18.00 |
| Luna | 0.20 / 0.02 / 0.25 / 1.20 | 0.40 / 0.04 / 0.50 / 1.80 |

These are Standard processing prices only. This registry does not assert a Pro-mode price. Regional-processing uplift is not included.

## 7. Failure taxonomy and behavior

| Failure kind | Required behavior |
|---|---|
| `not_configured` | Block before creating a live client |
| `authentication` / `entitlement` / `quota` | Fail closed; do not substitute a model |
| `rate_limit` / `service` | Fail closed; caller may retry only under an external bounded policy |
| `timeout` / `canceled` | Preserve distinct status; do not report a model verdict |
| `refusal` / `incomplete` | Reject output even if another field appears parseable |
| `malformed_output` / `model_mismatch` | Reject and record no accepted role result |
| `usage_invalid` | Reject because admission/accounting evidence is unsound |
| `sensitive_input` | Reject before acceptance and do not echo the sensitive content |
| `blocked_profile` | Deny unqualified, role-incompatible, or override-only profile use |

There is no automatic Sol-to-Terra or Sol-to-Luna fallback. Terra degraded mode must be selected explicitly, separately qualified, visibly reported, and denied for mutation-capable work.

## 8. Qualification standard

Full live qualification requires all required scenarios to pass against the exact model/profile/provider boundary and final tested tree:

1. entitlement and effective-model match;
2. strict structured schema;
3. refusal and incomplete handling;
4. continuation with encrypted reasoning items;
5. explicit compaction, if the production path depends on it;
6. timeout and cancellation;
7. bounded concurrency;
8. provider-count and returned-usage reconciliation;
9. an observed cache-hit telemetry case if caching is claimed;
10. storage and sensitive-tracing controls.
11. a one-call, no-retry, label-blind frozen holdout whose provider input omits category, expected status, and descriptive source case IDs and whose evidence binds the exact suite, request, hidden evaluation contract, prompt, input, and parsed output digests.

Offline mocks validate code behavior but cannot satisfy a live scenario. A scenario is live-qualified only with unmocked provider evidence.

## 9. Current qualification decision

The exact Sol Standard/high entitlement probe, all six Standard/Pro high–max variants, encrypted-reasoning continuation, and 2/2 concurrency probes passed. A historical v1 holdout call returned 15/15 and recorded 1,734 provider-counted/input tokens, 1,969 output tokens, 504 reasoning tokens, and zero cached tokens, but its rendered provider input exposed expected statuses, categories, and descriptive case IDs. That result is `LABEL_EXPOSED`, is invalid for behavioral qualification, and is retained only as historical live-call and usage provenance. The continuation recorded 382 input, 201 output, 127 reasoning tokens, and two replayed items.

The separate first-attempt label-blind v2 holdout passed 15/15 against `gpt-5.6-sol` using the `ordinary` `1.0.0` profile, Standard/high, one provider call, and zero retries. It recorded 1,805 input tokens, 3,011 output tokens, 1,468 reasoning tokens, 4,816 total tokens, and zero cached input tokens. The evidence-file SHA-256 is `f74c90f1cfbc24526ce10df4b17be9353a582f3bae7dd8d7ff3a3e9c73cfba65`; its source-suite, request, hidden evaluation-contract, provider-input, prompt, and result/parsed-output digests are respectively `6214b2ecaf182bd3947d1871d243525dcb7b55dc606df67e8423c073958700fd`, `1dcfb4d464286cb8152abd06e57a54400553872c6cfa3212623ad5accdec0f71`, `e17ea133b84cb0fffc7edf2895955b35cb480ed0bc4f391a57463640adccfdbc`, `3c168eec30ef6d8b1f21c2a8f476f506bf08a4478c081d4917fa301dfa8d5a00`, `42b6bc6eb7d6c284d152681ed7245c7d2c165c297f77ad3b89bb0fa408cf3f5e`, and `1d87e511d222d15322bdbe0bd9b96d02464268aec9897da84b7b044108067e70`. This is valid live behavioral evidence, distinct from the invalid v1 result.

The Pro/max benchmark required a bounded harness-cap adjustment. This is recorded as test-harness evidence and does not authorize unbounded production output.

The v2 artifact is not bound to an immutable final candidate commit/tree, and its final durable evidence bundle is pending. Explicit compaction is blocked. Timeout, cancellation, refusal, and incomplete handling have offline contract coverage only. No cache hit was observed. Therefore the current provider qualification state is **BLOCKED with partial live evidence**, not `LIVE_QUALIFIED`.

No production component may represent this tree as fully live-provider-qualified until the missing live scenarios and final-tree requalification pass, the evidence is durably packaged, and a complete typed qualification record is explicitly injected. Any final-candidate holdout requalification is a separate attempt and cannot replace the preserved first v2 result.

The Workbench production factory now exposes only the canonical bridge for enabled planning. The controller deterministically builds and evidence-binds `context-manifest-v1` from the immutable materialized task workspace before that call, while `WorkbenchStore` invokes the authoritative canonical lifecycle through migration `0010_workbench_canonical_authority.sql`. The model bridge enforces `require_production_profile`, exact `ordinary` profile semantics, the canonical prompt and `WorkbenchPlan`, no tools, provider token counting, cost accounting, and provider-evidence binding. The environment flag alone still constructs a disconnected adapter; no complete live qualification is present or auto-derived from configuration. This is offline-tested single-call wiring, not an operational provider claim or the complete multi-role cognitive lifecycle.
