# Lil' Tweak private engineering runner design

## Goal

Add the smallest additive control path that can carry an already-authorized Lil' Tweak engineering execution from the existing Resource Director and lease model to the existing GALOR Work Gateway runner boundary, then require an independent GitHub candidate verification before any completion claim.

## Non-goals

- This change does not deploy a Worker, create a Cloudflare account resource, enroll a runner, issue credentials, migrate production data, merge a PR, or construct an Engineering DAG.
- It does not relax the existing `galor-private-cloud-01` Gate 3 contract or expose raw shell commands, secrets, or browser credentials.

## Trust boundaries

1. Lil' Tweak issues the existing resource execution contract and execution lease after policy and approval checks.
2. A new, separately versioned Ed25519 dispatch attestation binds immutable contract, lease, and action-manifest digests to exactly `galor-tweak-runner-01` / `role-tweak-runner` with a short expiry and one-time nonce.
3. A Cloudflare Worker and one deterministic Durable Object per runner profile accept only typed offer, claim, evidence, and read-only reconciliation messages. The Durable Object atomically consumes a nonce and retains only digests and state.
4. The runner remains outbound-only and can receive only its exact profile's bounded, declared actions. It cannot supply arbitrary command text, credentials, or completion status.
5. The Python self-hosted provider treats runner evidence as dispatch evidence only. GitHub's independently verified exact candidate remains the sole completion signal.

## Safety properties

- Identity mismatch, expiration, altered digests, replay, undeclared action, raw command text, secret-like fields, and direct completion/qualification claims fail closed.
- The Worker verifies with a public key only; it cannot mint Lil' Tweak attestations.
- Existing Gate 3 authorization and legacy runner validation stay unchanged.
- Qualification stays `UNQUALIFIED` until live harmless no-write and bounded-write runner evidence plus independent GitHub verification exist.

## Deliverables

- Canonical signed dispatch-attestation Python contract and tests.
- Fail-closed self-hosted provider adapter and tests.
- Cloudflare Worker/Durable Object source, local tests, and no deployment configuration values or secrets.
- Configuration/factory wiring that preserves existing Gate 3 defaults and disables the new path unless all required protected settings exist.
- A reviewable feature branch and PR; no merge or deployment.
