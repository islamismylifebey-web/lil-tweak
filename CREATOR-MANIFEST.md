# Lil Tweak Creator Model Foundation 0.5.0

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

## Creator API

- `GET /v1/creator/health`
- `POST /v1/creator/compile`
- `POST /v1/creator/route`
- `POST /v1/creator/prepare`
- `GET /v1/creator/learning?problem_signature=...`

No Creator route can call a model, use a tool, spend, execute, write source, or deploy.

## Verification

- 174 unit, integration, API, security, recovery, concurrency, Creator, runtime, and
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
- Provider calls: 0.
- Tool calls: 0.
- Executions: 0.
- Paid calls: 0.

## Honest boundary

This release is the Creator Model control plane, not a deployed live Creator Model.

- The adaptive cost score is synthetic, not provider billing.
- The compiler is deterministic and must still be tested against live model-assisted assignment
  understanding.
- The Agents SDK model path is not enabled for Creator runs.
- No real sandbox provider is connected.
- Offline fixture execution proves the approval and verification contracts, not operating-system
  isolation.
- No API key was created or stored.
- No production deployment or Terhuti integration occurred.

The next phase may connect a disposable sandbox and live model only after a separate credential,
spend, provider, and execution approval.
