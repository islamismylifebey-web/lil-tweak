# Runner V3 Core-Owned Activation Design

## Context

Lil’ Tweak `main` was reconciled to the exact Sites v22 source at commit `63522fa027836b47808eeff201b84ce49a9ae1b6`. The active architecture is now Sites/Cloudflare → signed private Core → bounded engineering execution. The old Python Runner V2 integration path is no longer the current application boundary.

GALOR Hub `main` now canonically publishes Runner V3 with:

- contract: `galor-runner`
- version: `3.0.0`
- execution host: `galor-tweak-runner-01`
- current contract SHA-256: `5c649d1c2c338bc4a01f8c20778867036a703b049f25476cfe5e246c84eadd4c`
- dedicated DigitalOcean identity: Droplet `597343619`
- policy: `ENGINEERING_EXECUTION_ONLY`
- production authority: none
- deployment authority: none

Current Lil’ Tweak Sites metadata still advertises the historical GALOR contract `1.0.0` on `galor-private-cloud-01`. The trusted Core currently executes engineering jobs through its local digest-pinned Podman sandbox. Those facts must be corrected without weakening the existing Sites → Core trust boundary.

## Goal

Connect Lil’ Tweak’s trusted private Core to GALOR Runner V3 so engineering execution can be routed to the dedicated `galor-tweak-runner-01` only after fresh authenticated connection proof and qualification, while remaining fail-closed and preserving all owner, approval, evidence, source, and production-safety boundaries.

## Non-goals

This activation does not:

- grant arbitrary shell access;
- permit push, merge, deployment, DNS, production mutation, browser authority, or production credentials;
- expose runner secrets or service credentials to the Sites/browser layer;
- treat configuration, TCP reachability, HTTP health, or a stale historical proof as `CONNECTED`;
- treat `CONNECTED` as `QUALIFIED`;
- silently fall back to local Podman when GALOR V3 is selected and unavailable;
- rewrite or reuse historical Runner V1/V2 qualification evidence as V3 evidence;
- merge the activation PR before exact-head verification and live qualification evidence exist.

## Source authority

The implementation starts from Lil’ Tweak `main` commit `63522fa027836b47808eeff201b84ce49a9ae1b6` on branch `infra/runner-v3-core-activation`.

The authoritative Runner V3 identity and contract come from the corrected GALOR Hub `main`, not from old Lil’ Tweak V1/V2 fixtures or PR #12 artifacts.

The existing draft PR #21 was based on pre-reconciliation Lil’ Tweak source and is superseded by the fresh activation branch. No PR #12 or PR #21 generated evidence is carried forward as proof of connection or qualification.

## Architecture

### Sites/Cloudflare boundary

The Sites application remains responsible for owner authentication, owner-scoped engineering job creation, D1/R2 control-plane state, source intake metadata, and signed calls to the private Core. It does not receive GALOR Runner credentials and does not talk directly to the runner.

`lib/core-client.ts` remains the only Sites-side path into the trusted Core. Existing request signing, owner binding, bounded response handling, redirect rejection, and idempotency behavior remain intact.

### Trusted Core boundary

The private Core owns Runner V3 integration. A new focused Runner V3 client module will:

- require HTTPS for the configured GALOR gateway origin;
- reject embedded credentials, query strings, fragments, redirects, and malformed origins;
- use bounded request and response sizes and explicit timeouts;
- authenticate using server-only credentials;
- pin contract name, version, execution host, and SHA-256;
- verify returned proof identity before changing connection state;
- expose typed operations rather than an arbitrary command channel;
- map transport, authentication, contract, proof, and availability failures to fail-closed Core errors.

The browser and Sites worker never receive the GALOR service token, HMAC material, runner callback secret, or connection-proof material that could authorize execution.

### Execution backend selection

Execution backend selection is explicit and server-owned.

Supported modes:

- `local_podman`: preserve the current bounded local Podman execution path for environments explicitly configured for it.
- `galor_v3`: dispatch only through the qualified GALOR V3 path.

There is no automatic runtime fallback between the two modes. When `galor_v3` is selected and GALOR is unavailable, unconnected, contract-mismatched, or unqualified, job execution is blocked. This prevents an outage from bypassing the intended remote execution boundary.

## Canonical Runner V3 constants

Lil’ Tweak will pin the following public, non-secret identifiers in one focused Core module:

```text
GALOR_RUNNER_CONTRACT_NAME=galor-runner
GALOR_RUNNER_CONTRACT_VERSION=3.0.0
GALOR_RUNNER_EXECUTION_HOST=galor-tweak-runner-01
GALOR_RUNNER_CONTRACT_SHA256=5c649d1c2c338bc4a01f8c20778867036a703b049f25476cfe5e246c84eadd4c
GALOR_RUNNER_DROPLET_ID=597343619
```

The current Lil’ Tweak commit used for any live proof must be supplied from the exact activation candidate rather than hard-coded to an older commit.

## Configuration contract

Core configuration for `galor_v3` will require server-only values for:

- exact backend mode;
- GALOR gateway HTTPS origin;
- dedicated service authentication material;
- exact Lil’ Tweak repository identity;
- exact Lil’ Tweak candidate commit;
- canonical Runner V3 contract SHA-256.

Validation fails during startup when `galor_v3` is selected and any required value is missing or does not match the canonical public contract identifiers.

Secret values must never be returned by `/healthz`, `/readyz`, engineering status APIs, evidence manifests, logs, exceptions sent to callers, or serialized job state.

## Connection state model

Runner state is represented independently from Core bridge health.

States:

1. `DISCONNECTED`
   - default;
   - configuration or health reachability alone does not change it.

2. `CONNECTED_UNQUALIFIED`
   - requires fresh authenticated connection proof;
   - proof must bind the exact runner identity, current contract, exact Lil’ Tweak candidate commit, owner/tenant scope, and fresh job/nonce data;
   - execution remains blocked.

3. `CONNECTED_QUALIFIED`
   - requires successful Qualification Job A, Qualification Job B, and adversarial fail-closed checks on the same accepted identity/contract lineage;
   - only this state permits normal `galor_v3` engineering dispatch.

Any identity mismatch, stale/replayed proof, contract mismatch, revoked authorization, failed adversarial gate, or freshness expiry returns the effective state to a non-executable condition.

## Fresh connection proof

Connection proof uses GALOR Hub’s approved typed `runner.reportIdentity` path.

Lil’ Tweak accepts proof only when all required fields agree with server-owned expectations, including:

- runner name `galor-tweak-runner-01`;
- Runner V3 contract name/version/digest;
- expected repository `islamismylifebey-web/lil-tweak`;
- exact candidate commit;
- expected scope/tenant/owner binding;
- unique proof job identifier;
- freshness window;
- authenticated Hub-persisted result.

The Core must never infer connection from a successful generic health endpoint.

## Qualification

### Qualification Job A — no-write

A harmless read-only qualification job proves:

- exact runner identity;
- exact contract identity;
- repository checkout is bound to the requested commit;
- only approved read/repository-inspection actions are available;
- no repository mutation, push, merge, deployment, or production authority occurs;
- evidence is returned through the authenticated Hub path.

### Qualification Job B — bounded disposable write

A disposable isolated checkout receives one bounded patch/write operation. The job must prove:

- writes remain inside the temporary workspace;
- the authorized path/action limits are enforced;
- resulting patch/evidence digests are stable and verifiable;
- the canonical repository is not pushed or mutated;
- teardown removes the disposable mutation context.

### Adversarial fail-closed checks

Qualification is incomplete until tests prove rejection of:

- wrong runner name or Droplet identity;
- wrong contract version or SHA-256;
- stale or replayed proof;
- wrong Lil’ Tweak commit;
- wrong owner/tenant/scope;
- arbitrary command/shell requests;
- secret escalation;
- network escalation outside the contract;
- production/deployment operations;
- malformed or oversized responses;
- redirects;
- runner unavailability;
- dispatch before qualification.

## Engineering job routing

The current Core orchestration lifecycle remains authoritative for Lil’ Tweak job state and evidence mirroring.

For `local_podman`, the existing `PodmanSandbox` path remains unchanged.

For `galor_v3`, the Core will use a dedicated executor adapter behind the same orchestration boundary. The adapter receives only the typed, bounded job input required by GALOR V3 and returns normalized evidence/result data to the existing Core state machine.

The adapter must not expose a general-purpose shell method.

## Status and provenance

`lib/engineering-connection.ts` and its tests will be updated so public/owner-visible status reflects current provenance without leaking secrets:

- Lil’ Tweak current activation candidate;
- corrected GALOR Hub Runner V3 contract identity;
- execution host `galor-tweak-runner-01`;
- distinct bridge health, runner connection, and qualification states.

Historical `galor-private-cloud-01` references may remain only where they describe immutable V1/V2 history. Current V3 status and execution code must not use that host as a default or fallback.

## Failure handling

Runner integration fails closed.

- configuration failure: Core startup/readiness does not authorize runner execution;
- authentication failure: disconnected/non-executable;
- contract mismatch: disconnected/non-executable;
- proof mismatch or replay: disconnected/non-executable;
- runner unavailable: no execution and no local fallback in `galor_v3` mode;
- malformed evidence: job fails without trusting the result;
- qualification failure: remains unqualified;
- teardown/evidence persistence failure: no success claim.

Public errors remain generic. Detailed internal diagnostics must not contain secrets.

## Testing strategy

Development is test-first.

1. Add regression tests proving current reconciled source is stale: V1/old host expectations fail against the approved V3 identity.
2. Add configuration tests for exact V3 pinning and fail-closed missing/mismatched configuration.
3. Add Runner V3 client tests covering URL validation, bounded I/O, redirects, authentication headers without secret leakage, exact proof verification, replay/freshness, and typed actions.
4. Add backend-selection tests proving no local fallback from `galor_v3`.
5. Add status tests separating Core bridge health from runner connection and qualification.
6. Add qualification-state tests for Job A, Job B, and adversarial gates.
7. Run focused tests after each implementation slice.
8. Run repository verification: `npm run verify`.
9. Require exact-head GitHub CI evidence before any merge or qualification claim.

Live host evidence is a separate gate from repository tests.

## Operational activation sequence

1. Repository implementation and exact-head verification.
2. Host baseline and secure access proof for Droplet `597343619`.
3. Host hardening and unprivileged runner service account.
4. Install the approved Runner V3 runtime and bind exact identity/contract.
5. Fresh authenticated connection proof.
6. Qualification Job A.
7. Qualification Job B.
8. Adversarial fail-closed checks.
9. Mark `CONNECTED_QUALIFIED` only after all evidence is present.
10. Enable normal GALOR V3 engineering dispatch only after qualification.

## Merge rule

The activation PR remains draft until:

- implementation is present on a fresh branch from reconciled `main`;
- exact-head repository verification passes;
- live DigitalOcean host evidence is available;
- connection proof is fresh and authenticated;
- Qualification Jobs A and B pass;
- adversarial gates pass;
- no production/deployment authority has been introduced.

No merge, deploy, publish, or production mutation is part of repository implementation alone.
