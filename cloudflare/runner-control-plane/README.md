# Lil Tweak private-runner control plane

This package is a bounded Cloudflare Worker/Durable Object control plane for the
single pinned runner `galor-tweak-runner-01` with role `role-tweak-runner`.
It coordinates signed leases and bounded structured evidence; it never receives
a shell command, command output, credential, or completion/qualification
assertion.

## HTTP contract

Every route requires `Authorization: Bearer <server-to-server token>` and
returns `Cache-Control: no-store`. Cloudflare Access is a separate outer gate:
callers must also send `CF-Access-Client-Id` and `CF-Access-Client-Secret` for
an approved service token. Access does not replace the route-specific Worker
bearer.

| Route | Caller | Request | Result |
| --- | --- | --- | --- |
| `POST /v1/control/offer` | Lil Tweak control plane | `{ "attestation": { "key_id", "attestation", "signature" }, "manifest": { ... } }` | `OFFERED` |
| `POST /v1/runners/galor-tweak-runner-01/next` | pinned runner | signed `poll` envelope | exact signed attestation and typed manifest for one valid `OFFERED` execution |
| `POST /v1/runners/galor-tweak-runner-01/claim` | pinned runner | signed `claim` envelope | `CLAIMED` or a conflict |
| `POST /v1/runners/galor-tweak-runner-01/status` | pinned runner | signed `status` envelope | bounded status, including a cancellation request |
| `POST /v1/runners/galor-tweak-runner-01/evidence` | pinned runner | signed `evidence` envelope | `EVIDENCE_RECORDED` |
| `GET /v1/control/executions/:execution_id` | Lil Tweak control plane | none | structured status and, after evidence, the verified signed runner envelope |
| `POST /v1/control/executions/:execution_id/cancel` | Lil Tweak control plane | `{ "reason_digest" }` | `CANCEL_REQUESTED` |

The attestation is Ed25519 over UTF-8 recursively key-sorted compact JSON of
the exact payload, with no signing-domain prefix. It binds the runner identity,
execution ID, lease/contract/commands/approval/policy SHA-256 digests, a
32-byte unpadded-base64url nonce, and a maximum five-minute validity window.
The Durable Object is resolved with `getByName("galor-tweak-runner-01")` and
atomically records nonce consumption with the claim transition.

The offer manifest is a strict discriminated union. Both job types bind the
exact repository, source commit and tree, fixed verification profile, bounded
timeout, GitHub-only network scope, and false package-install, production, and
deployment flags. `read_only` selects only the fixed read-only qualification
action. `bounded_write` additionally selects only the fixed documentation
qualification action, a branch under `qualification/galor-tweak-runner-01/`,
and the pinned documentation artifact preimage and content digests. The
SHA-256 of canonical manifest JSON must equal the attestation
`commands_digest`; shell text, argv, content, secrets, and extra fields are not
accepted.

Runner calls require more than the runner bearer. Their exact envelope is
`{ "request": { "schema_version", "runner_id", "operation",
"request_nonce", "issued_at_ms", "payload" }, "signature" }`. The signature
is raw Ed25519 over UTF-8
`lil-tweak.runner-request/<operation>/v1\n<canonical-request-json>`. Requests
outside the 30-second clock window, with the wrong operation or key, or with a
replayed 32-byte nonce fail closed. The Durable Object consumes that nonce in
the same transaction as poll, claim, status, or evidence handling.

Evidence uses schema v2 and contains only the fixed receipt type for the offered
job or a bounded failure/cancellation receipt. The Worker recomputes the receipt
digest, verifies the runner signature, and stores the normalized envelope. Only
the controller-authenticated status route exposes that envelope; runner status
does not. Receipts contain no stdout, stderr, shell text, or secrets.

## Required external bindings

Nothing in this repository supplies a live credential or key. Before any
deployment, configure these Worker bindings through the approved deployment
secret/configuration path:

- `CONTROL_PLANE_BEARER_TOKEN` — control-plane server bearer secret.
- `RUNNER_BEARER_TOKEN` — runner bearer secret, distinct from the control token.
- `LIL_TWEAK_RUNNER_SIGNING_PUBLIC_KEY` — protected base64url raw 32-byte
  Ed25519 public key for proof that runner calls came from the pinned host.
- `LIL_TWEAK_ATTESTATION_KEY_ID` — 64 lowercase hexadecimal signer key ID.
- `LIL_TWEAK_ATTESTATION_PUBLIC_KEY` — base64url raw 32-byte Ed25519 public key.

Cloudflare Access must also protect the service route. Missing or malformed
bindings fail closed; `wrangler.jsonc` deliberately contains no values for
them. Public `workers.dev` and preview URLs are disabled, so deployment does
not expose an alternate public endpoint; an explicit Access-protected route is
required. The Lil Tweak server receives its Access service-token credentials
through `LILTWEAK_PRIVATE_RUNNER_ACCESS_CLIENT_ID` and
`LILTWEAK_PRIVATE_RUNNER_ACCESS_CLIENT_SECRET`. The Worker cannot dispatch or
execute work itself, and its evidence state is deliberately not a completion
or qualification decision.

## Local verification

`npm test` runs the Worker in the Cloudflare Vitest runtime. It generates an
ephemeral controller and runner test keys in memory, validates the strict
manifest, domain-separated runner proof-of-possession, race-safe nonces,
bounded v2 evidence, and the public cross-language fixture at
`test/fixtures/dispatch-attestation-v1.json`. `npm run types` validates the
Wrangler configuration and regenerates ignored local runtime types.
