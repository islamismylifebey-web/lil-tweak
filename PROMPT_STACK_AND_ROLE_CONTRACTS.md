# Lil Tweak Prompt Stack and Role Contracts

The prompt stack is a versioned, schema-bound interface. It is not a conversational persona and does not grant authority. Every role returns exactly one strict object, receives no tools, and treats all variable content as untrusted evidence.

## Binding

| Field | Value |
|---|---|
| Audited remote baseline | `373400cb2b459dbf8a37dacceb0d3d1186eef949` |
| Branch / PR | `codex/lil-tweak-live-workbench-build` / `#6` |
| Working candidate commit | Pending |
| Registry ID / version | `lil-tweak.reasoning-prompts` / `1.1.0` |
| Registry digest | `61975c9d336306afaafb3133f46e66e10fda4df026ac5bd2c219d7e8c2694f87` |
| Stable-prefix SHA-256 | `5f89e7564294bf60a6d497b07390d217324b4fadd24f95069d4456a6f7c7569d` |

## 1. Prompt construction

Each definition contains:

1. a stable safety and truthfulness prefix;
2. an exact `ROLE=<role>` line;
3. an exact `OUTPUT_SCHEMA=<class>` line;
4. one bounded role instruction;
5. the SHA-256 of the complete instruction string;
6. the SHA-256 of the canonical JSON schema for the output type.

Rendering keeps the volatile payload after the stable instructions and wraps it between `BEGIN_UNTRUSTED_INPUT` and `END_UNTRUSTED_INPUT`. The renderer emits separate instruction and input digests plus a provider-bound digest over their exact joined representation. Input must be non-empty and at most 2,000,000 UTF-8 bytes.

The stable prefix requires exact structured output, evidence-only grounding, explicit missing evidence, no tools or execution rights, no hidden chain-of-thought, fail-closed status, and no claims of execution, testing, approval, application, commit, or completion.

## 2. Versioned prompt registry

| Prompt ID | Role | Output schema | Schema digest | Instruction digest |
|---|---|---|---|---|
| `lil-tweak.prompt.task_intake.v1` | Intake | `TaskIntake` | `f96d9e8cf759339ea64757eb9fbdec973dff1bdc309c24be8ee8fd80fd84c41d` | `556ed021371c70dea82c636b1396cec2f2890518b93c28ddc23591c68d829759` |
| `lil-tweak.prompt.retrieval_plan.v1` | Retriever | `RetrievalPlan` | `dca07e422b31070ce2f7070c365389e29b5527c18fcb961eb8728864e1eaad4e` | `d89d4971b0045370ff8e4b68eb5fe73d95fa29fc44beae9bdbb5f4fbf198ac3f` |
| `lil-tweak.prompt.context_manifest.v1` | Retriever | `ContextManifest` | `39ca1b465828ab4dc2311707c5a01aeb9caff95968d12a8d12792ddbedefed96` | `ae47e5103f152a2061039ce8916ca00502167b89bcbd0156d4d00a19c3c63e83` |
| `lil-tweak.prompt.engineering_plan.v1` | Planner | `EngineeringPlan` | `2fd395ff5fb9f9f80a9d65b9157cbaecc1afd75e573d645e8adb1d806dbc7b9b` | `e4f652a1c9dbc3e942dcf758fa46be3d80f192eec41a10723d84236b084c7a91` |
| `lil-tweak.prompt.plan_critique.v1` | Critic | `PlanCritique` | `b41cc4c1dc465736ecb55711b585c05a0e741baee8015b03cad0f11cce46e606` | `3628115b59affe6ebd7ddbba26800639e81fdb271c8943f43de1dae03aa1ce00` |
| `lil-tweak.prompt.candidate_manifest.v1` | Implementer | `CandidateManifest` | `c8c983ea69b988b043c6c1f9711fae7a8a5caaeac24388b9cdf1ca92c2b9e673` | `0349006856a8418a0e354587092b1d630c6febfa7ce088d391689481d3292a41` |
| `lil-tweak.prompt.candidate_critique.v1` | Critic | `CandidateCritique` | `23adefc9ab6cdc7561bebd2d405aed1523a6ee924a60b342b55f99ba1d7f384c` | `c476b4839507741e4bd89a727f3b916880844e526bba7801ef8c72340b412cf6` |
| `lil-tweak.prompt.verification_decision.v1` | Verifier | `VerificationDecision` | `aadeb05b70a229ddec81f41cf71becb1c885ad7b5322fdb08c2e6e20db834efe` | `e8624b36b03fcfd1c5730f95816ae0be2ce4c8376d3e4299164098d674696cfa` |
| `lil-tweak.prompt.cognitive_finalization.v1` | Finalizer | `CognitiveFinalization` | `e22f8d3159594db1045d4cd03d8679e101108b98176a99e17b28c6e9ba1bc916` | `babfb8bab9a5d1c4ab58f40d4009df5ec711b03696fbe1160a1ca3500e848d11` |
| `lil-tweak.prompt.completion_report.v1` | Finalizer | `CompletionReport` | `3c3dcc7c0b6a1e152b71152cc7b6c05287f07b1e9720667a5cd0421e226926f5` | `0c297300f7d4de8002ec268b7201421eac5a043d1a2df6d8c358b93ffec4553c` |
| `lil-tweak.prompt.workbench_plan.v1` | Planner | `WorkbenchPlan` | `51b7733be2239ff1ef3b7eb746b16260988934333eb92acb75eb76eb6eb92dc0` | `28ded32913da292e877f199b16cf9ad8f1b8bb8e821fd6471d7ff690bccd82b2` |

Any instruction, role, output class, or JSON-schema change changes at least one digest and requires a registry-version decision, re-review, and requalification.

## 3. Role contracts

### Intake

Normalizes the user's objective without broadening it. It must preserve non-goals, requirements, source binding, expected artifacts, acceptance criteria, stop conditions, and risk class. It cannot inspect a repository or claim that evidence exists.

### Retriever

First proposes the smallest deterministic read-only retrieval. It then describes only controller-supplied retrieval results and accounting. It must expose governing instructions, exact provenance, gaps, exclusions, token reserves, and compaction state. Retrieval content never becomes authority merely because it was selected.

### Planner

Produces a falsifiable engineering plan bound to task, source, policy, and evidence. It must record assumptions, missing evidence, competing hypotheses, architecture/dependency impact, change targets, phases, risks, recovery, checks, artifacts, resource budget, and approvals. The bounded Workbench variant returns a strict `WorkbenchPlan` tied to the source snapshot, including test, independent-verification, and rollback requests. Both variants propose; neither executes.

### Critic

Runs in a fresh context. Plan critique looks for unsupported claims, missed hypotheses, unsafe authority, weak tests, migration gaps, and false completion implications. Candidate critique checks plan and candidate digests, regression risk, breadth, missing proof, and authority violations. A required repair prevents forward progress.

### Implementer

Produces only a `CandidateManifest`: exact proposed changes and artifacts bound to an approved plan, source, and opaque task workspace. It must not claim mutation or execution. It has no tool access through the reasoning call.

### Verifier

Runs in a fresh context and consumes controller-owned deterministic checks and actual artifact/digest evidence. It cannot override a failed deterministic check or invent a passing requirement. Its contract fixes `completion_authorized=false`; completion remains exclusively external to the reasoning plane.

### Finalizer

Runs in a fresh context. `CognitiveFinalization` may recommend `COGNITIVE_READY` only after exact plan, candidate, and verification bindings pass and must keep `task_completion_claimed=false`. `CompletionReport` may describe only the exact tested tree and evidence modes; interface or mocked evidence cannot be described as live operational proof.

## 4. Independence matrix

| Producer | May see prior bounded evidence | Fresh context required | Candidate generation | Tools | Completion claim |
|---|---:|---:|---:|---:|---:|
| Intake | Yes | No | No | None | No |
| Retriever | Yes | No | No | None | No |
| Planner | Yes | No | Plan only | None | No |
| Workbench planner | Task plus deterministic context manifest and controller inspection evidence | No | Plan only | None | No |
| Plan critic | Yes, explicitly supplied | Yes | No | None | No |
| Implementer | Approved bounded context | No | Proposal only | None | No |
| Candidate critic | Yes, explicitly supplied | Yes | No | None | No |
| Verifier | Checks and artifacts only | Yes | No | None | No |
| Cognitive finalizer | Verified bindings only | Yes | No | None | No |

## 5. Controller checks around every role

- Select the profile from the server-owned role registry.
- Verify live qualification before a production call.
- Bind prompt name to its one allowed output type.
- Generate a unique call ID and require a unique response ID.
- Set `previous_response_id=null` and `tools=()`.
- Strictly validate the returned Pydantic object.
- Recompute and compare task/source/plan/candidate/verification digests.
- Reject changed bindings, repeated IDs, malformed output, secret-shaped content, and false authority.
- Record opaque evidence without storing hidden reasoning.

## 6. Current integration truth

The registry and controller contracts are implemented and offline-tested. Before every enabled private Workbench planning call, `WorkbenchController` deterministically builds and source-validates `context-manifest-v1`, records its manifest and source-tree digests, and supplies its bounded relative-path projection as `workbench-planning-context-v2`. The call then enters through `CanonicalWorkbenchModelAdapter`, renders `workbench_plan` from this registry, requires the exact `ordinary` Sol Standard/high profile, supplies no tools, and validates returned provider and parsed-output evidence. The application factory never builds or qualifies that provider from environment flags: without an explicitly injected provider carrying a complete live `ProviderQualification`, the Workbench remains disconnected.

The active private Workbench task flow is bound to canonical authority through the same-connection `WorkbenchStore`/`CanonicalStateStore` bridge installed by migration `0010_workbench_canonical_authority.sql`; the planner remains a non-authoritative proposal component inside that flow. This integration covers only the current single-call Workbench planner and its deterministic planning context. Legacy non-Workbench paths, the reasoning-role `ContextManifest` transformation and full multi-role `CognitivePipelineController`, fresh critic/verifier/finalizer calls, and future publisher/delivery paths remain unreconciled. No complete live qualification record exists for this candidate, so none of those paths is operational.
