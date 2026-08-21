# Lil Tweak Creator Model Foundation 0.6.0

Date: 2026-07-29 (America/Chicago)  
Owner: Maurice Pennington-Bey  
Recovered baseline: Phase 3.2 Engineering API  
Baseline archive SHA-256:
`1089820d491ee70356003447817e85e15e3b7dff86a8f3cde9e801047f890be5`

## Implemented

- Creator invariant cycle encoded into every brief.
- Natural-direction prompt compiler with exact intent preservation.
- Work classification, deliverables, constraints, negative constraints, acceptance criteria, and
  material-question detection.
- Visual quality compilation for shine, electric, clean, fast, secure, and fluid.
- HMAC-signed, digest-bound briefs with server-owned authority.
- Least-cost capable routing across economy, standard, and frontier tiers.
- Reasoning effort, context, turn, escalation, de-escalation, and synthetic-cost controls.
- High-stakes blocking unless prerequisites arrive from the trusted harness.
- Rejection of caller-asserted authority and route evidence.
- Raw creator request limits, duplicate-JSON-key rejection, and credential-shaped input rejection.
- Bounded sandbox execution-plan contract.
- Exact, expiring, atomic, one-attempt execution approvals.
- Verification gate for required command observations, sandbox isolation, network use, artifact
  limits, source identity, and credential findings.
- Completion claims allowed only after verified checks.
- Append-only causal learning for signed observed success and failure outcomes.
- Stored-learning integrity verification and duplicate-outcome immutability.
- Authenticated Creator Model API routes for health, compile, route, prepare, and read-only
  learning retrieval.
- Immutable live-run proposals bound to a signed brief, recomputed route, exact model, reasoning
  effort, token limits, price schedule, and conservative dollar ceiling.
- Separate exact-digest Founder approval with expiry and atomic one-attempt consumption.
- Transactional monthly and per-call live-spend admission across database connections.
- One-turn typed Agents SDK work-order generation with tools, handoffs, source access, and
  execution disabled.
- Provider usage recording, estimated token-cost calculation, provider request-ID hashing, and
  immutable success or failed-attempt state.
- A hard prohibition on automatic paid retry.
- A provider-hosted, network-disabled synthetic sandbox probe adapter that remains unverified and
  disconnected from source.
- A minimum 1,024-token output gate plus bounded schema and prompt rules derived from observed
  truncation failures.

## Creator API

- `GET /v1/creator/health`
- `POST /v1/creator/compile`
- `POST /v1/creator/route`
- `POST /v1/creator/prepare`
- `GET /v1/creator/learning?problem_signature=...`
- `POST /v1/creator/live/proposals`
- `GET /v1/creator/live/proposals/{proposal_id}`
- `POST /v1/creator/live/proposals/{proposal_id}/decision`
- `POST /v1/creator/live/runs`
- `GET /v1/creator/live/results/{proposal_id}`

Compilation, routing, preparation, and learning routes cannot call a model or spend. The live
routes can make exactly one approved model call only when the server explicitly enables them.
No Creator route can use a tool, execute, write source, deploy, or treat a work order as evidence.

## Verification

- 190 unit, integration, API, security, recovery, concurrency, Creator, runtime, and
  adversarial tests pass.
- Ruff lint and formatting checks pass.
- Original Phase 3.2 workflows, hostile cases, engineering gates, recovery checks, and smoke flow
  remain green.
- 160 Creator routing simulations pass.
- 140 routable simulations match always-heavy coverage.
- 20 high-stakes simulations block before routing.
- 16 signed-brief tampering attempts are rejected.
- Adaptive synthetic cost: 456 units.
- Always-heavy synthetic cost: 1,120 units.
- Synthetic reduction: 59.2857%.
- 120 Phase 6 offline cases pass: 80 approved fixture runs, 20 high-stakes blocks, and 20
  tampered-route rejections.
- Offline provider fixture calls: 80.
- Real billable model attempts: 2, each separately approved and limited to one request.
- Completed live work orders: 0; both attempts failed closed when bounded structured output was
  truncated.
- Aggregate approved model-spend ceilings: $0.07; provider invoice reconciliation is unavailable.
- Tool calls: 0.
- Executions: 0.
- Hosted sandbox calls: 0.

## Honest boundary

This release contains a live-model control plane, but it is not a deployed or fully proven live
Creator Model.

- The adaptive cost score is synthetic, not provider billing.
- The compiler is deterministic and must still be tested against live model-assisted assignment
  understanding.
- The Agents SDK model path exists and is disabled by default. Two bounded probes reached the
  provider but did not complete the typed schema, so successful live assignment understanding is
  still unproven.
- The hosted sandbox adapter is implemented but was not called. Its current container minimum did
  not fit the remaining approved ceiling.
- Offline fixture execution proves the approval and verification contracts, not operating-system
  isolation.
- The development API key is stored only in the ignored local `.env.local` and is excluded from
  Git and release artifacts.
- No production deployment or Terhuti integration occurred.
- No source, shell, network tool, repository execution, or deployment was exposed to either paid
  probe.

The next paid model or sandbox probe requires a new digest-bound proposal and exact Founder spend
approval. Real repository execution requires a later, separately proven isolation and execution
phase.

