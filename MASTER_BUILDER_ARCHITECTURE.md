# Lil Tweak Master Builder Architecture

## Evidence scope

| Item | Value |
|---|---|
| Repository | `islamismylifebey-web/lil-tweak` |
| Working branch | `codex/lil-tweak-live-workbench-build` |
| Draft pull request | [PR #6](https://github.com/islamismylifebey-web/lil-tweak/pull/6) |
| Audited remote baseline | `373400cb2b459dbf8a37dacceb0d3d1186eef949` |
| Working candidate commit | **PENDING** — no candidate SHA is claimed inside this pre-commit file |
| Exact final tested tree | **PENDING** — the prior 523-test checkpoint ran on an uncommitted working tree and was invalidated for release purposes by later lifecycle and documentation changes |
| Environment | Private Codex Linux workspace, Python 3.12, loopback-only Workbench; real Chromium `149.0.7827.0` acceptance executed; no qualified runner; GCP and public deployment disabled |
| Integrated checkpoint | Historical mutable-tree result only; exact-commit result must be reported externally |
| Current focused checkpoint | Historical mutable-tree result only; exact-commit result must be reported externally |
| Immutable evidence digest | **PENDING** — final manifest and exact-commit verification have not run |

The 597-test result is an engineering checkpoint, not final publication evidence. A clean checkout
of the eventual candidate commit must repeat every gate.

## System boundary

Lil Tweak is a private, owner-controlled engineering system divided into five trust domains:

| Domain | Responsibilities | Authority it must not possess |
|---|---|---|
| Control plane | Authentication, policy, lifecycle, context assembly, capability gates, approvals | Independent verifier, external checkpoint, publisher, or runner authority |
| Model plane | Structured, tool-free reasoning proposals and bounded context consumption | Owner session, signing material, operating-system, Git, approval, or completion authority |
| Runner plane | Isolated execution of an exact authorized invocation | Approval issuance, model credentials, owner repository, evidence-signing keys |
| Verifier/evidence plane | Deterministic checks, independent qualification, append-only evidence and external receipts | Mutation or publisher authority |
| Publisher plane | Separately approved owner-tree apply, local commit, and rollback | Model/runner identity, remote push, merge, release, or deployment authority |

No credential or connection in one plane activates another plane.

## Authoritative architecture

| Concern | Working-candidate implementation | Current truth |
|---|---|---|
| Canonical lifecycle | `liltweak/canonical_lifecycle.py`, `liltweak/canonical_store.py`, migrations `0009`, `0010`, and `0011` | Authoritative for the active private Workbench; pre-canonical task databases require an explicit export/migration workflow and legacy paths remain unreconciled |
| Reasoning policy | `liltweak/reasoning_policy.py`, `liltweak/model_catalog.py`, `liltweak/reasoning_prompts.py` | Sol-primary, versioned roles/profiles; full live provider qualification remains blocked |
| Provider boundary | `liltweak/reasoning_provider.py` | Responses/Agents boundary with strict output and failure classification; only a partial live gate has passed |
| Cognitive pipeline | `liltweak/cognitive_contract.py`, `liltweak/cognitive_pipeline.py` | Tool-free/offline-tested but not integrated into production Workbench analysis; this is a directive blocker |
| Context and memory | `liltweak/context_manifest.py`, `liltweak/memory_governance.py`, `liltweak/training_readiness.py` | Deterministic inventory context is active; relevance/call-graph retrieval and durable memory/training authority are absent |
| Tool authority | `liltweak/tool_registry.py`, `TOOL_AUTHORITY_REGISTRY.json` | Two non-mutating definitions exist offline, but production Workbench dispatch does not use the registry |
| Runner | `liltweak/workbench_executor.py`, `liltweak/runner_qualification.py` | Contracts and hostile qualification logic exist; production transport remains disconnected/unqualified |
| Evidence checkpoint | `liltweak/external_checkpoint.py` | Submit/assert interface exists; default client is disabled and no independent backend is configured |
| Repository delivery | `liltweak/repository_delivery.py` | Strict contracts and pytest-only protocol exerciser exist; production publisher is disabled |
| Workbench | `liltweak/workbench_api.py`, `web/workbench/` | Private HTTP/API surface has real Chromium acceptance evidence; three required cases remain blocked, so end-to-end operation is not established |

## Lifecycle and completion

The canonical monotonic lifecycle is:

`RECEIVED → INSPECTED → PLANNING → PLAN_PROPOSED → APPROVAL_PENDING → APPROVED → RUNNER_PREFLIGHT → EXECUTING → TESTING → VERIFYING → EVIDENCE_SEALED → PATCH_READY → APPLY_APPROVAL_PENDING → APPLIED → COMMIT_APPROVAL_PENDING → LOCALLY_COMMITTED → COMPLETED`

Cancellation, failure, rollback, and emergency-stop paths are explicit. Exact transition rules live
in `liltweak/canonical_lifecycle.py`; durable atomic operations live in
`liltweak/canonical_store.py`.

The private Workbench is a compatibility projection over that lifecycle. `WorkbenchStore` and
`CanonicalStateStore` share one SQLite connection and reentrant lock; nested canonical operations
use savepoints inside the Workbench `BEGIN IMMEDIATE` transaction. Task creation, plan admission,
approval publication/decision, approval consumption plus dispatch claim, testing entry,
verification entry, cancellation/failure, rollback, emergency control, and completion checks
therefore cannot commit one side without the other. Migration `0010` binds task and approval IDs
and makes canonical evidence, control events, dispatch bindings, and bridge bindings immutable.
An exact-plan revision cannot rewind the monotonic task; it fails closed and requires a new task.

Planning in this active private path also builds a deterministic `context-manifest-v1`, revalidates
the workspace snapshot, records the manifest and source-tree digests, and supplies a bounded
`workbench-planning-context-v2` projection to the planner. The same-connection bridge and context
path do not yet reconcile legacy non-Workbench services, the full multi-role cognitive pipeline,
or future publisher/delivery paths.

The Workbench controller is not allowed to bridge missing gates. Its public state remains an API/UI
projection and it stops at
`VERIFIED` after local deterministic verification because independent examiner verification is
false. `COMPLETED` remains unreachable until independent verification, evidence sealing, external
checkpoint policy, and every required delivery state are satisfied.

## Cognitive pipeline

The model-side substate machine is separate from task authority:

`REQUESTED → CONTRACT_READY → CONTEXT_READY → PLAN_PROPOSED → PLAN_CRITIQUED → PLAN_VERIFIED → CANDIDATE_GENERATED → CANDIDATE_CRITIQUED → DETERMINISTIC_CHECKED → INDEPENDENTLY_VERIFIED → COGNITIVE_READY | NO_CHANGE_PROPOSED | BLOCKED | FAILED`

Planner, implementer, critic, verifier, and finalizer use strict role contracts. The pipeline may
propose work but cannot approve, dispatch, publish, roll back, or mark a task complete.

## Capability gates

Model, runner, external checkpoint, publisher, browser, owner-tree apply, local commit, GCP, and
public deployment are independent capabilities. Every capability must separately prove installed,
configured, connected, healthy, qualified, authorized, and operational status. Missing proof is a
blocker, not a degraded synonym for operational.

Current default state:

- model: partial live reasoning evidence, but overall provider qualification **BLOCKED**;
- runner: **BLOCKED**, disconnected and unqualified;
- external checkpoint: **BLOCKED**, interface-only;
- publisher/apply/commit/rollback: **BLOCKED** in production, test-only exerciser available;
- browser acceptance: Chromium `149.0.7827.0` produced **30 PASS / 3 BLOCKED / 0 FAIL**; the blocked cases are live planning and approval-digest proof (no complete injected qualification receipt), patch review and rollback delivery (no qualified runner, publisher, apply, or rollback authority), and real-time session expiry (minimum private TTL is 300 seconds; clock control is unit-tested only);
- GCP and public deployment: **DISABLED BY POLICY**.

The browser result artifact has SHA-256
`d0e150189eff95b10fb5e4fa68768020428bb4a1175c9c72aefc49295a87cb18`; the captured screenshot has
SHA-256 `387e7ddce232bddbbb0f861dbcaa95b7f0797f5d16531d9d0a80243e3dd58542`. Boundary probes returned
HTTP 400 for an invalid Host, HTTP 403 for a disallowed Origin, refused IPv6 loopback, and found
all listeners cleared after shutdown. This is real-browser acceptance evidence, not an operational
claim for model planning, runner execution, external verification, delivery, publication, or
session-expiry behavior.

## Approval and mutation invariant

Every independently initiated mutation requires a fresh, one-use, expiring, purpose-bound owner
approval bound to the exact task, repository state, source, plan, policy, tool registry, runner,
network, attempt, nonce, evidence, and requested result. Mandatory restoration after a failed
approved apply is part of that exact apply transaction. Discretionary rollback requires its own
approval.

## Current classification

**FAILED — RELEASE GATES NOT MET**

This classification is provisional until the exact final candidate commit passes clean-checkout
verification. It does not authorize merge, release, deployment, GCP, owner-tree publication, or
autonomous execution.
