# Lil'Tweak.AI

Lil Tweak is an owner-only, approval-gated code engineer. Its public control plane runs on Cloudflare; its trusted execution core runs in an isolated rootless Podman service on `galor-private-cloud-01`.

`galor-private-cloud-01` is being qualified as a dedicated Lil Tweak host. GALOR Hub is not installed by this release and `LIL_TWEAK_GALOR_READONLY_URL` remains unset.

This repository contains the application, execution core, migrations, tests, and deployment assets. It has not been deployed from this workspace. Production still requires a live Podman/Quadlet qualification on the target droplet and real integration checks against PostgreSQL, R2, Cloudflare Tunnel, and the OpenAI API. Four-GiB co-residency remains blocked; a four-GiB dedicated host still requires live headroom qualification. Four-GiB GALOR co-residency is blocked: production requires at least the eight-GiB plan class with monitored headroom, or a dedicated host/move for Lil Tweak or GALOR before qualification.

## Architecture

- `app/`, `worker/`, and `lib/`: owner UI and Cloudflare control plane.
- D1: owner-facing job, source, evidence, and audit mirror.
- R2: private request, source, and verified evidence objects.
- `core/`: signed trusted-core API, PostgreSQL state, OpenAI Responses loop, source intake, evidence production, and approval enforcement.
- Rootless Podman: one fresh, network-disabled, resource-capped sandbox per job.
- `local_podman` is the shipped default execution backend. Optional GitHub Actions
  verification requires all three reviewed settings:
  `LIL_TWEAK_EXECUTION_BACKEND=github_actions`,
  `LIL_TWEAK_GITHUB_REPOSITORY=OWNER/REPOSITORY`, and a server-only
  `LIL_TWEAK_GITHUB_TOKEN`. Invalid or partial settings, including dormant GitHub
  credentials in local mode, fail before mutation. GitHub-source jobs also require
  `LIL_TWEAK_GIT_ALLOWED_HOSTS=github.com`.
- The GitHub token must be repository-scoped, expiring, and limited to
  least-privilege Actions read/write access. Keep it server-only and include it in
  the credential rotation runbook. Readiness does not contact GitHub; activation
  requires one controlled dispatch/receipt after Linux verification. The workflow
  uses a GitHub-hosted `ubuntu-24.04` runner; no self-hosted personal workstation is
  part of the runner execution boundary. The returned receipt is bound to the job,
  source commit/tree, authority digest, ordered actions, and manifest digest.
- `deploy/` and `scripts/`: digest-pinned Quadlets and checked DigitalOcean install/verification tooling.
- `deploy/Containerfile.runner`: credential-free Node/Python/Go/Rust/Java sandbox toolchain built from an operator-supplied base digest.

Cloudflare Sites must be the only browser ingress. The managed ingress must strip and replace all `oai-authenticated-*` identity headers, and the service must not have a separate public origin. The DigitalOcean core listens only on `127.0.0.1:8017` behind a constrained Cloudflare Tunnel and still requires signed, nonce-protected requests.

## Safety boundary

Lil Tweak may inspect, edit, and test source code inside a disposable sandbox. It cannot commit, push, deploy, publish, send, delete external data, or spend without a fresh owner decision bound to the exact proposal digest and authoritative core revision. The only implemented approval action is a one-time patch export for owner download.

GALOR Hub is optional and read-only. It must remain on a different Unix user, network, volume, PostgreSQL role, credential set, and port. Lil Tweak continues to operate if GALOR retrieval is unavailable.

### Safety amendment — 2026-08-14: v1 byte-limit profile

The earlier 500 MiB expanded-source and 50 MiB evidence targets are superseded for v1. The enforceable profile is 128 MiB (134,217,728 bytes) maximum expanded source for ZIP and Git intake and 2 MiB (2,097,152 bytes) maximum per evidence artifact, including `changes.patch`. Raising either ceiling requires coordinated schema, runtime, storage, staging-capacity, and live-qualification changes; it is not a one-line configuration change.

## Requirements

- Node.js 22.13 or newer.
- Python 3.12.x for the trusted core and its tests.
- Rootless Podman with Quadlet support on the production host.
- Cloudflare Sites with D1 and R2 bindings.
- PostgreSQL for authoritative core state.

## Local verification

```bash
npm ci
npm run verify
scripts/install-lil-tweak-release.sh --check
bash scripts/verify-deployment.sh --check
```

`npm run verify` performs TypeScript checking, linting, a production build, all JavaScript contract tests, all Python core tests, and the POSIX deployment security tests. This canonical gate is authoritative on Ubuntu; a Windows adaptation is not a substitute. Local tests use fakes; they do not make a paid OpenAI request or deploy infrastructure.

The deployment tests exercise real root ownership and process-lease permissions. The hosted runner and activation-check workflows explicitly set `LIL_TWEAK_DEPLOY_TEST_AS_ROOT=1`; the test wrapper verifies the hosted Linux context and uses noninteractive sudo only for that suite, with a fresh root-owned private temporary directory. Other checks run as the ordinary runner user. The default local test command does not elevate; complete deployment verification requires a disposable Linux environment with root and process-inspection permissions. Hosted execution must pass before runner activation.

## Configuration

- Cloudflare binds D1 as `DB` and R2 as `FILES` through `.openai/hosting.json`.
- Configure core origin, signing key ID, and signing secret as Worker secrets/bindings; never expose them to the browser or store them in D1.
- Configure the core using `deploy/core.env.example`. Keep the OpenAI key, R2 credentials, database URL, signing keys, and optional GALOR credential outside source control and outside every sandbox.
- Keep `LIL_TWEAK_EXECUTION_BACKEND=local_podman` unless explicitly activating GitHub Actions with both reviewed GitHub settings described above.
- The model is operator-configurable; the example uses `gpt-5.6-terra`.

## Deployment

Read [the DigitalOcean operations runbook](docs/operations/digitalocean.md), [the private Cloudflare ingress runbook](docs/operations/cloudflare-private-ingress.md), and [the Cloudflare D1 migration gate](docs/operations/cloudflare-d1.md) before installation. They cover host validation, isolated resources, secret staging, both database migrations, Cloudflare-only ingress, readiness verification, backup/restore, key rotation, upgrades, rollback, and GALOR coexistence.
