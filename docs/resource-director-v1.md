# Resource Director v1

## Current increment

The Resource Director is an additive, fail-closed control-plane subsystem beneath Lil Tweak's
existing policy, approval, source-integrity, evidence, and v1 execution contracts. It does not
replace or broaden `execution_contract.py`.

`ResourceExecutionContractV2` binds a typed workload, immutable source, exact resource profile,
provider and resource type, workspace and network policies, resource and time ceilings, cost
ceiling, approval and policy digests, verification policy, commands digest, retry/failover
authority, and expiry. A separately signed, one-use execution lease binds the future provider
attempt to that contract and fails closed on expiry, revocation, replay, or substitution.
Models may suggest that network access or package installation is technically required, but only
authenticated server authority supplies destinations or grants package/workspace capability.

The catalog and scheduler are server-owned. Routing applies ordered qualification, health,
capability, authorization, and cost gates. It then prefers included capacity, lower net estimated
cost, lower risk, configured priority, and stable identifiers. Single-machine capacity is kept
separate from aggregate parallel capacity.

## Modes

| Mode | State | Behavior |
|---|---|---|
| `disabled` | CURRENT / default | Does not calculate a route or dispatch. |
| `shadow` | SHADOW | Records a digest-bound comparison; never provisions or sends a command. |
| `active` | BLOCKED | Calculates a route but cannot dispatch without a later, separately verified activation increment. |

## Providers

| Provider surface | State | Boundary |
|---|---|---|
| GitHub Actions | TESTED | Independent verification adapter only; exact-source dispatch through an injected client; no source write or deployment authority. |
| GitHub Codespaces | SCAFFOLDED | Disconnected builder-shaped interface; unqualified and inactive. |
| Vercel Sandbox / Builds | SCAFFOLDED | Disconnected, preview-only declarations; no client, credentials, calls, resources, or deployments. |
| Cloudflare Workers / Workflows / Queues / Containers | SCAFFOLDED | Disconnected orchestration declarations; no client, credentials, calls, resources, storage migration, or production mutation. |

No provider is qualified, connected, or active in this increment. No production deployment is
automatically authorized. A provider adapter's own success cannot establish completion; only
independent, source-bound verification evidence can return `VERIFIED`.

## Planned, not current

Qualification evidence, server-side credential wiring, provider health probes, durable ledger
persistence, Cloudflare D1/R2 storage adapters, Vercel execution, and authoritative active routing
remain separate future increments. Each requires independent qualification and explicit owner
activation without weakening existing contracts.
