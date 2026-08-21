# Phase 6 Build Brief: Bounded Live Creator Loop

## Confirmed facts

- Version 0.5.0 is the verified starting point at commit
  `bab8800417d50f955d90ad1cd082bde8685fe16e`.
- The starting point independently passes 174 tests, Ruff lint, and Ruff format checks.
- A usable `OPENAI_API_KEY` exists only in the ignored, untracked `.env.local` file.
- The Creator compiler, route preview, exact execution approval, verification gate, causal
  learning, and offline execution fixtures already exist.
- Model calls, tool execution, repository writes, and deployment are disabled in 0.5.0.
- The installed Agents SDK supports structured outputs, usage accounting, hosted container shell,
  and sandbox agents.
- Docker is not available in the current build environment. Unix-local sandboxing is suitable for
  local iteration but does not prove container isolation.

## Current interpretation

Phase 6 should connect the smallest live capability that can be proven without weakening the
0.5.0 boundary:

1. Convert a signed Creator brief and signed route into an immutable live-run proposal.
2. Bind the proposal to one exact model, effort level, input ceiling, output ceiling, turn limit,
   price schedule, and conservative dollar ceiling.
3. Require a separate, expiring, server-signed Founder approval for that exact proposal.
4. Atomically consume the approval and reserve the dollar ceiling before one provider attempt.
5. Run one structured-output model turn with no tools, handoffs, source access, or execution
   authority.
6. Record provider usage, estimate actual token cost from the versioned price schedule, and reject
   results that exceed any bound.
7. Keep completion claims, causal learning, repository writes, and execution blocked until
   deterministic verification exists.
8. Prove the provider-hosted, network-disabled container boundary only with a synthetic challenge.
   Do not upload or mutate a real repository in this phase.

The hosted container itself has a current 1 GB minimum charge of $0.03 before model tokens, so its
approval ceiling is separate from the live work-order ceiling.

Two bounded live work-order probes demonstrated that 512- and 768-token output limits can
truncate the typed response. Both failed closed without retry, tool use, or execution. The
controller now refuses limits below 1,024 tokens, and the work-order schema and trusted prompt
enforce concise bounded output. See
[`phase6-live-evidence.md`](phase6-live-evidence.md).

## App contract

### Goal

Give Lil Tweak real assignment understanding while keeping approval, billing, state, evidence,
and recovery in the trusted harness.

### Input

- signed `CreatorBriefEnvelope`;
- deterministic `RouteDecision` recomputed by the trusted harness;
- authenticated Founder identity;
- no caller-supplied model, price, authority, approval, or evidence fields.

### Model output

A strict `CreatorWorkOrder` containing:

- functional gap;
- confirmed facts;
- unknowns;
- testable hypotheses;
- smallest supported intervention;
- verification checks;
- stop conditions;
- whether execution is required.

The work order is analysis, not evidence and not permission.

### Model routing

| Router tier | OpenAI model | Purpose |
| --- | --- | --- |
| Economy | `gpt-5.6-luna` | Cost-sensitive structured work |
| Standard | `gpt-5.6-terra` | Balanced engineering and long-context work |
| Frontier | `gpt-5.6-sol` | Highest-complexity or validated high-stakes review |

The route selects the least costly capable tier. One failed validated attempt may justify a new,
separately approved proposal at the next tier. It must never trigger an automatic paid retry.

### Approvals and spending

- Proposal digest includes the brief, route, model, effort, token limits, turn limit, price
  schedule, and conservative cost ceiling.
- Founder approval must match the exact proposal digest and expires quickly.
- Approval is one-attempt and is consumed before the provider call.
- Monthly and per-call limits are enforced transactionally from conservative reservations.
- Provider usage is recorded after the call. A failed call still consumes the one attempt.
- No public request field can grant approval or alter the model price schedule.

### Sandbox

- The trusted harness remains outside model-directed compute.
- The first hosted-container check uses an automatically provisioned disposable container with
  network disabled and a synthetic nonce challenge.
- Real source material, credentials, mounts, and repository writes remain prohibited.
- A future Docker or hosted sandbox adapter must prove isolation, input materialization,
  artifact review, command observation, cleanup, and destruction before source execution can be
  reported as connected.

### API surface

- prepare one live proposal from a signed brief;
- inspect one proposal;
- approve or reject the exact proposal digest;
- execute one approved proposal;
- inspect the immutable result and usage record;
- run no hosted sandbox from the public API during the initial phase.

### Deployment assumptions

- Owner-only development service.
- Live models are disabled unless explicitly enabled by server configuration.
- Hosted sandbox probing is CLI/evaluation-only.
- Production identity, external secret management, provider-enforced organization spend caps,
  durable deployment, and real repository execution remain launch gates.

## Standalone implementation prompt

Extend Lil Tweak 0.5.0 into a bounded 0.6.0 live Creator foundation. Preserve all existing safety
contracts. Add immutable live-run proposals, exact expiring Founder approvals, atomic one-attempt
consumption, conservative monthly/per-run dollar reservations, versioned OpenAI model pricing,
structured one-turn Creator work orders, provider usage reconciliation, safe API endpoints, and
offline concurrency/adversarial tests. Add a provider-hosted network-disabled synthetic sandbox
probe, but do not upload or mutate real source and do not mark repository execution connected.
Every success claim must be backed by deterministic checks or provider observations. Never expose,
log, return, or commit credentials.

