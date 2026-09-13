# Cloudflare-only ingress contract

Lil Tweak has two distinct ingress boundaries. The owner-facing Sites Worker accepts requests only from the managed Sites hostname. The DigitalOcean core accepts requests only through a named Cloudflare Tunnel protected by an Access service token and the independent Lil Tweak HMAC protocol.

Do not publish either route until every negative test in this runbook passes.

## Production bindings

Configure these Worker bindings. Values marked secret belong in the platform secret store, not a checked-in environment file, D1, R2, a client bundle, or Terraform output.

| Binding | Kind | Contract |
|---|---|---|
| `LIL_TWEAK_ENVIRONMENT` | variable | Exact value `production`; a missing value fails closed, and only an explicit `development` or `test` value is permitted in a local preview |
| `PUBLIC_ORIGIN` | variable | Exact `https://host` owner-facing Sites origin; no trailing slash, path, query, fragment, or `workers.dev` alias |
| `MANAGED_INGRESS_SECRET` | secret | At least 32 UTF-8 bytes; stripped from client requests and injected by managed Sites ingress as `X-Lil-Tweak-Managed-Ingress` |
| `CORE_ORIGIN` | variable | Exact `https://host` Access-protected Tunnel origin |
| `CORE_ACCESS_CLIENT_ID` | secret | Service-token client ID |
| `CORE_ACCESS_CLIENT_SECRET` | secret | Service-token client secret |
| `CORE_SIGNING_KEY_ID` | variable | Active Lil Tweak HMAC key ID matching `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` |
| `CORE_SIGNING_SECRET` | secret | Active Lil Tweak HMAC secret containing at least 32 UTF-8 bytes |

`deploy/cloudflare/worker.production.env.example` is the complete name contract and explicitly sets `LIL_TWEAK_ENVIRONMENT=production`. Missing LIL_TWEAK_ENVIRONMENT fails closed as a production misconfiguration; it never silently selects development behavior. An explicit `development` or `test` value is for local preview only. Production must also fail closed if `PUBLIC_ORIGIN` or `MANAGED_INGRESS_SECRET` is absent, if exactly one Access credential is configured, or if any request origin differs from `PUBLIC_ORIGIN`.

The managed host must remove every client-supplied `X-Lil-Tweak-Managed-Ingress`, `oai-authenticated-user-id`, and `oai-authenticated-user-email` header, then inject its authenticated identity headers and the secret ingress header. The Worker compares the ingress secret in constant time. If the Sites hosting layer cannot provide this overwrite guarantee, the production deployment is blocked; accepting raw identity headers is not a fallback.

## Named Tunnel and Access

Create a named Tunnel dedicated to Lil Tweak. Never reuse a GALOR Hub Tunnel or credential. Route exactly one private core hostname to it. The locally managed configuration is rendered from `deploy/cloudflared/config.yml.example`; its only origin is `http://127.0.0.1:8017` and its final ingress rule returns `404`.

Before adding DNS or starting `cloudflared`, create a Cloudflare Access self-hosted application for the exact core hostname. `deploy/cloudflare/access-application.json` is the application payload. Create a dedicated service token, substitute its opaque ID into `deploy/cloudflare/access-policy.json`, and attach that policy to the application with the Service Auth action (`decision: non_identity`). Do not add an Everyone, Bypass, email, IP, or reusable GALOR policy.

The Worker sends both official Access headers on every HMAC-signed core request:

```text
CF-Access-Client-Id: <CORE_ACCESS_CLIENT_ID>
CF-Access-Client-Secret: <CORE_ACCESS_CLIENT_SECRET>
```

Access is the edge gate; HMAC is still the application gate. A leaked service token alone cannot create a job, and a leaked HMAC key alone cannot pass Access. Neither credential is stored on the droplet. The Tunnel credential stored on the droplet cannot authenticate Worker requests.

The Access application and service token can be created in Zero Trust > Access controls. For API-driven review, use the checked-in JSON bodies with the documented account Access application/policy endpoints, but keep the API token and returned service-token secret outside the repository. Review the plan before applying it.

## Install the outbound connector

Install a distribution-packaged or otherwise audited `cloudflared` binary at `/usr/bin/cloudflared`, record its SHA-256, and stage the named Tunnel JSON credential as a root-readable file. The setup script validates configuration offline without touching systemd or the network:

```bash
scripts/install-lil-tweak-release.sh --check
```

On `galor-tweak-runner-01`, supply the reviewed values below alongside the core inputs in the DigitalOcean runbook. The production release must use `scripts/install-lil-tweak-release.sh` so one host-global rollback lease covers the core and Tunnel stages; do not split the initial release into two independent transactions.

```bash
export LIL_TWEAK_TUNNEL_ID='LOWERCASE_TUNNEL_UUID'
export LIL_TWEAK_CORE_HOSTNAME='CORE_HOSTNAME'
export LIL_TWEAK_TUNNEL_CREDENTIALS='/ABSOLUTE/ROOT_ONLY/TUNNEL_JSON'
export LIL_TWEAK_CLOUDFLARED_SHA256='64_HEX_DIGEST'
export LIL_TWEAK_ROLLBACK_RECEIPT='/var/lib/lil-tweak-release-rollback/YYYYMMDDTHHMMSSZ-12_HEX_PREFIX'
export ROLLBACK_MANIFEST_SHA256='64_HEX_DIGEST'
# Then run the combined transaction command in docs/operations/digitalocean.md.
```

The connector runs as the separate `lil-tweak-tunnel` Unix user. It does not join a container network, read `/var/lib/lil-tweak`, or access GALOR Hub storage, credentials, networks, or databases. It needs outbound Cloudflare connectivity and loopback access only. Metrics bind to `127.0.0.1:20241`.

At the DigitalOcean Cloud Firewall and host firewall, never open port 8017. There is no public origin IP or load balancer for the core. `127.0.0.1:8017` is the sole listener, and the Tunnel is outbound-only. A DNS-only record pointing at the droplet, a second Tunnel hostname, or a GALOR reverse-proxy route is prohibited.

## Required negative tests

Run these from an external trusted workstation without printing secrets:

1. Request the core hostname with no Access headers. Access must deny it; an origin JSON response is a release blocker.
2. Request it with the service-token headers but without Lil Tweak HMAC headers. The core must return the generic authentication failure.
3. Send a correctly signed readiness request through the Worker path. It must pass Access and HMAC and return ready.
4. Request the owner application through its `workers.dev` or any alternate hostname. The Worker must reject it because it differs from `PUBLIC_ORIGIN`.
5. Send a public request with a forged `X-Lil-Tweak-Managed-Ingress` and forged `oai-*` identity headers. Managed ingress must overwrite/remove them, and the Worker must reject a value that does not match `MANAGED_INGRESS_SECRET`.
6. Scan the droplet externally. TCP 8017 must be unreachable. Locally, `ss -lnt` must show only `127.0.0.1:8017`.
7. Stop `lil-tweak-cloudflared.service`. The core hostname must become unavailable while GALOR Hub remains unaffected. Restart it and confirm the inverse isolation as well.

Record Access application ID, policy ID, service-token ID and expiry, Tunnel ID, connector binary digest, Worker deployment ID, image digests, and test results. Never record token bytes, signing keys, the managed-ingress secret, owner emails, or Tunnel credential contents.

## Rotation and incident response

Rotate the Access service token with overlap: create a new token, permit it in Access, update both Worker secrets, verify, then remove and revoke the old token. Access service-token headers are never accepted as HMAC headers. Rotate HMAC keys separately using the dual-key procedure in the DigitalOcean runbook.

Rotate a Tunnel credential only during an audited maintenance window. Install the replacement under the same dedicated identity, validate ingress, start a second connector if the Cloudflare plan supports replicas, verify it, then retire the old credential. Revoking a Tunnel credential must not touch GALOR Hub.

If any direct-origin path is found, immediately remove the DNS/route or firewall rule, revoke the Access token and Tunnel credential if exposure is suspected, rotate HMAC, pause job admission, and audit Access plus Lil Tweak request IDs.
