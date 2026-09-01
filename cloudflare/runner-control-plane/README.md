# Lil Tweak private-runner control plane

This package is a bounded Cloudflare Worker/Durable Object control plane for the
single pinned runner `galor-tweak-runner-01` with role `role-tweak-runner`.
It coordinates signed leases and digest-only evidence; it never receives a shell
command, command output, credential, or completion/qualification assertion.

## HTTP contract

Every route requires `Authorization: Bearer <server-to-server token>` and
returns `Cache-Control: no-store`.

| Route | Caller | Request | Result |
| --- | --- | --- | --- |
| `POST /v1/control/offer` | Lil Tweak control plane | `{ "attestation": { "key_id", "attestation", "signature" } }` | `OFFERED` |
| `POST /v1/runners/galor-tweak-runner-01/claim` | pinned runner | `{ "execution_id", "attempt_nonce" }` | `CLAIMED` or a conflict |
| `POST /v1/runners/galor-tweak-runner-01/evidence` | pinned runner | `{ "execution_id", "attempt_nonce", "evidence" }` | `EVIDENCE_RECORDED` |
| `GET /v1/control/executions/:execution_id` | Lil Tweak control plane | none | digest-only structured status |
| `POST /v1/control/executions/:execution_id/cancel` | Lil Tweak control plane | `{ "reason_digest" }` | `CANCEL_REQUESTED` |

The attestation is Ed25519 over UTF-8 recursively key-sorted compact JSON of
the exact payload, with no signing-domain prefix. It binds the runner identity,
execution ID, lease/contract/commands/approval/policy SHA-256 digests, a
32-byte unpadded-base64url nonce, and a maximum five-minute validity window.
The Durable Object is resolved with `getByName("galor-tweak-runner-01")` and
atomically records nonce consumption with the claim transition.

## Required external bindings

Nothing in this repository supplies a live credential or key. Before any
deployment, configure these Worker bindings through the approved deployment
secret/configuration path:

- `CONTROL_PLANE_BEARER_TOKEN` — control-plane server bearer secret.
- `RUNNER_BEARER_TOKEN` — runner bearer secret, distinct from the control token.
- `LIL_TWEAK_ATTESTATION_KEY_ID` — 64 lowercase hexadecimal signer key ID.
- `LIL_TWEAK_ATTESTATION_PUBLIC_KEY` — base64url raw 32-byte Ed25519 public key.

Cloudflare Access must also protect the service route. Missing or malformed
bindings fail closed; `wrangler.jsonc` deliberately contains no values for
them. The Worker cannot dispatch or execute work itself, and its evidence state
is deliberately not a completion or qualification decision.

## Local verification

`npm test` runs the Worker in the Cloudflare Vitest runtime. It generates an
ephemeral test key in memory, validates the strict routes, race-safe nonce
claim, digest-only evidence, and the public cross-language fixture at
`test/fixtures/dispatch-attestation-v1.json`. `npm run types` validates the
Wrangler configuration and regenerates ignored local runtime types.
