# Lil Tweak on `galor-tweak-runner-01`

galor-tweak-runner-01 is being qualified as a dedicated Tueiq host. Tueiq directly owns the signed Core-to-local-Podman runner path with no intermediary. This runbook does not claim that the runner has passed live connection or qualification gates. This is an operations guide, not an automatic remote deployment: run every mutating command from an audited console on the intended droplet.

## Invariants

- Cloudflare is the sole public ingress. A Cloudflare Tunnel makes an outbound connection to the managed edge and forwards only to `http://127.0.0.1:8017`; never open port 8017 in the DigitalOcean Cloud Firewall, `ufw`, or an external load balancer.
- The core and PostgreSQL run as the dedicated `lil-tweak` Unix user with rootless Podman.
- The `lil-tweak-private` network, `lil-tweak-data` volume, `lil-tweak-postgres-data` volume, PostgreSQL database, and `lil_tweak_app`/`lil_tweak_migrator` roles belong only to Lil Tweak.
- Production images are referenced by registry digest. Tags are allowed during a build, never in an installed Quadlet.
- The trusted core admits one job. Each code job still receives a fresh, network-disabled sandbox with its own resource limits.
- Trusted Git/R2 intake and snapshot staging live only on an exact 1 GiB, 204,800-inode tmpfs mounted inside the core; there is no writable host-workspace bind. The inode budget is three 65,536-inode tree slots (current proposal, immutable baseline, and mutually exclusive patch-candidate/final staging) plus an 8,192-inode bookkeeping reserve. Each runner receives a separate executable 256 MiB, 65,536-inode tmpfs and no host path.
- The OpenAI, R2, database, request-signing, and Tunnel credentials remain outside every sandbox.
- The trusted Core invokes each fresh, network-disabled Podman sandbox directly. Tueiq has no intermediary runner control plane.

## Host and image preparation

The immutable guest is DigitalOcean Droplet `597343619` with short hostname `galor-tweak-runner-01`. Confirm both identity components before doing anything:

```bash
python3 scripts/lil-tweak-digitalocean-target.py --check
sudo python3 scripts/lil-tweak-digitalocean-target.py
```

The live command reads only the Linux short hostname and `http://169.254.169.254/metadata/v1/id`. It accepts only exact decimal ID `597343619`, rejects redirects, uses a two-second timeout, and reads at most 33 bytes to enforce a 32-byte ceiling. No environment variable or command-line option can replace the expected provider, Droplet ID, hostname, metadata URL, role, timeout, or response limit. A mismatch or metadata failure emits only a generic error. The `--check` command validates the helper and fixed parser fixtures without contacting guest metadata, so it is safe on a development host.

Every mutating core installer, Tunnel installer, combined wrapper path (including its internal lease-held invocation), and rollback API runs this verifier after root/offline validation and before credentials, receipt parents or locks, temporary files, users, directories, systemd, or Podman changes. The legacy word embedded in the immutable provider hostname grants no relationship, credential, transport, process, network, repository, or authority.

Install supported host packages from the operating-system repository: rootless Podman with Quadlet support, `uidmap`, `slirp4netns` or `pasta`, `curl`, `iproute2`, and a current `cloudflared`. Do not use a download piped into a shell. Keep the host and container runtime patched.

Build the core in CI or on a dedicated build host. Pass a Python base image by digest because `Containerfile.core` intentionally has no mutable default:

```bash
podman build \
  --build-arg PYTHON_BASE_IMAGE='REGISTRY/PYTHON@sha256:64_HEX_DIGEST' \
  --file deploy/Containerfile.core \
  --tag TEMPORARY_BUILD_TAG .
```

Build the disposable runner separately from a digest-pinned Node 22 Debian base. The shipped runner adds Python/pytest, a dedicated patch utility, Make/CMake, Go, Rust, and a headless JDK. It deliberately contains no Git binary, contains no Lil Tweak service credentials, and receives no network at runtime. Git source intake occurs only in the trusted core before files enter the sandbox:

```bash
podman build \
  --build-arg RUNNER_BASE_IMAGE='REGISTRY/NODE22-DEBIAN@sha256:64_HEX_DIGEST' \
  --file deploy/Containerfile.runner \
  --tag TEMPORARY_RUNNER_BUILD_TAG .
```

Publish the image to the private registry, record the returned digest, and scan/SBOM the final digest. Obtain digest-pinned references for the core, PostgreSQL, Python base, and sandbox runner. An example that still contains `64_HEX_DIGEST`, `CHANGE_ME`, or `REPLACE_WITH_64_HEX_CHARACTERS` is deliberately invalid and must not be installed.

## Secret staging

Create a temporary, root-owned directory on the droplet with mode `0700`. It must contain:

- `core.env`, based on `deploy/core.env.example`;
- `postgres-admin-password`;
- `postgres-app-password`;
- `postgres-migrator-password`; and
- `registry-auth.json`, containing only the private registries used by the three pinned runtime images.

Every file in that list must be root-owned mode `0600`. Each PostgreSQL password file must contain exactly one independently generated 32–128 character base64url value followed by one final newline. The application password in `LIL_TWEAK_DATABASE_URL` must equal `postgres-app-password`.

Write `core.env` as strict UTF-8 with one final newline. Every physical line must be blank, a column-zero `#` comment, or a column-zero `UPPERCASE_NAME=value` assignment. Names must be unique; values must be nonempty and must not start or end with whitespace. Do not use CRLF, leading indentation, semicolon comments, a quote as the first value character, control characters, backslashes, escapes, or continuations. Use only the required names in `deploy/core.env.example` plus `LIL_TWEAK_GIT_ALLOWED_HOSTS` when needed; arbitrary assignments are rejected. Compact signing JSON such as `{"primary":"BASE64URL_SECRET"}` is accepted because its quotes occur inside an unquoted value. Each signing-key ID must match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, and each signing secret must contain at least 32 UTF-8 bytes; generate it as base64url so the JSON needs no backslash escapes. The evidence endpoint must be one exact credential-free HTTPS origin with no path, query, or fragment. `core.env` must not contain shell substitutions or either owner email. For this release, set `LIL_TWEAK_CANONICAL_OWNER_ID=a0885bc0b2c079e996629061a723c74d`; both the installer and core reject every other 32-character value. That exact control-plane owner scope is carried in the signature-bound `X-Lil-Tweak-Owner` header.

The request-signing JSON should initially contain one key ID. Store the same key under a Cloudflare Worker secret, never in D1, R2, source code, a browser response, or a log. Set `LIL_TWEAK_RUNNER_IMAGE` to a digest-pinned sandbox image. Container loopback (`127.0.0.1`) is reserved for the Lil Tweak Core.

After a successful install, securely remove the staging copy according to the host's secret-handling policy. Podman's admin-password secret and the installed `core.env` remain under the dedicated account. Do not copy them into backup logs or support bundles.

## Install and migration

The following first performs an offline contract check. `--check` validates the exact-target helper without contacting guest metadata or any other droplet network endpoint, starting services, or consuming credentials.

```bash
scripts/install-lil-tweak-release.sh --check
bash scripts/verify-deployment.sh --check
```

Capture and verify one release-bound rollback receipt before either installer mutates the host. Use the frozen 40-lowerhex source commit and one UTC timestamp; the helper prints the canonical manifest digest without printing captured secret bytes:

```bash
export LIL_TWEAK_SOURCE_COMMIT='REPLACE_WITH_40_LOWERHEX_SOURCE_COMMIT'
[[ "${LIL_TWEAK_SOURCE_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || {
  printf 'replace LIL_TWEAK_SOURCE_COMMIT with the frozen release commit\n' >&2
  return 1 2>/dev/null || exit 1
}
export LIL_TWEAK_ROLLBACK_RECEIPT="/var/lib/lil-tweak-release-rollback/$(date -u +%Y%m%dT%H%M%SZ)-${LIL_TWEAK_SOURCE_COMMIT:0:12}"
sudo python3 scripts/lil-tweak-rollback.py capture \
  --output "${LIL_TWEAK_ROLLBACK_RECEIPT}" \
  --source-commit "${LIL_TWEAK_SOURCE_COMMIT}"
export ROLLBACK_MANIFEST_SHA256="$(sudo python3 scripts/lil-tweak-rollback.py verify \
  --receipt "${LIL_TWEAK_ROLLBACK_RECEIPT}")"
test "${#ROLLBACK_MANIFEST_SHA256}" -eq 64
```

Keep that exact receipt path and digest for both the core and Tunnel installers. If owner-flow verification fails after an installer has returned, disable the new route and restore manually from the audited root session:

```bash
sudo python3 scripts/lil-tweak-rollback.py restore \
  --receipt "${LIL_TWEAK_ROLLBACK_RECEIPT}" \
  --expected-manifest-sha256 "${ROLLBACK_MANIFEST_SHA256}"
```

Do not delete a receipt whose restore reports quarantined drift; inspect the root-only `quarantine/` directory and preserve it for reconciliation.

This first production installation is deliberately fresh-host only. Both the captured receipt and a live preflight under the transaction lease must prove that every Lil Tweak managed path, service identity, unit, Podman object, listener, and linger setting is absent. Any prior or drifting Lil Tweak state stops the installer before host mutation. A completed receipt cannot be reused for another installation. It remains available for an explicit manual restore of that exact release if later owner-flow verification fails.

Set the exact core and Tunnel installer inputs in the audited root session, then run the single transaction wrapper. It holds one host-global, receipt-bound lease across both installers and invokes the receipt-bound restore if either stage fails. Exact new named volumes are never deleted automatically: if a failed attempt created one, rollback cleans independently authorized non-volume state, preserves the volume as `retained-data`, returns an incomplete outcome, and requires operator reconciliation before retry. Do not describe that retained-data outcome as a fully restored baseline.

```bash
export LIL_TWEAK_CORE_IMAGE='REGISTRY/CORE@sha256:64_HEX_DIGEST'
export LIL_TWEAK_POSTGRES_IMAGE='REGISTRY/POSTGRES@sha256:64_HEX_DIGEST'
export LIL_TWEAK_SECRETS_SOURCE='/ABSOLUTE/ROOT_ONLY/STAGING_DIRECTORY'
export LIL_TWEAK_REGISTRY_AUTH_SOURCE='/ABSOLUTE/ROOT_ONLY/STAGING_DIRECTORY/registry-auth.json'
export LIL_TWEAK_SOURCE_MANIFEST='/ABSOLUTE/ROOT_ONLY/STAGING_DIRECTORY/source-manifest.json'
export LIL_TWEAK_RUNTIME_MANIFEST='/ABSOLUTE/ROOT_ONLY/STAGING_DIRECTORY/runtime-manifest.json'
export LIL_TWEAK_RUNTIME_MANIFEST_SHA256='64_HEX_DIGEST'
export LIL_TWEAK_TUNNEL_ID='LOWERCASE_TUNNEL_UUID'
export LIL_TWEAK_CORE_HOSTNAME='CORE_HOSTNAME'
export LIL_TWEAK_TUNNEL_CREDENTIALS='/ABSOLUTE/ROOT_ONLY/TUNNEL_JSON'
export LIL_TWEAK_CLOUDFLARED_SHA256='64_HEX_DIGEST'
export LIL_TWEAK_ROLLBACK_RECEIPT='/var/lib/lil-tweak-release-rollback/YYYYMMDDTHHMMSSZ-12_HEX_PREFIX'
export ROLLBACK_MANIFEST_SHA256='64_HEX_DIGEST'
sudo --preserve-env=LIL_TWEAK_CORE_IMAGE,LIL_TWEAK_POSTGRES_IMAGE,LIL_TWEAK_SECRETS_SOURCE,LIL_TWEAK_REGISTRY_AUTH_SOURCE,LIL_TWEAK_SOURCE_MANIFEST,LIL_TWEAK_RUNTIME_MANIFEST,LIL_TWEAK_RUNTIME_MANIFEST_SHA256,LIL_TWEAK_TUNNEL_ID,LIL_TWEAK_CORE_HOSTNAME,LIL_TWEAK_TUNNEL_CREDENTIALS,LIL_TWEAK_CLOUDFLARED_SHA256,LIL_TWEAK_ROLLBACK_RECEIPT,ROLLBACK_MANIFEST_SHA256 \
  scripts/install-lil-tweak-release.sh --install
```

The source and runtime manifests must be the root-owned, single-link, mode-`0444` canonical manifests produced for this release. Before `mutation_started`, the gate requires the runtime-manifest SHA-256, frozen source commit and tree, every descriptor-relative source path, mode, size, and SHA-256, and the exact core, PostgreSQL, and runner image references to match the rollback receipt, extracted source directory, and staged secret snapshot. Missing, extra, linked, changed, or mismatched source fails silently and stops the release.

The fresh-host installer:

1. refuses any hostname or metadata Droplet-ID mismatch, mutable images, missing configuration, symlinks, weak database passwords, and placeholder values;
2. after verifying the rollback receipt and before mutating the host, validates and freezes the four fixed secret inputs in a new root-owned mode-`0700` directory containing mode-`0600` snapshots; all later reads use only those snapshots;
3. creates or validates the dedicated account and enables lingering;
4. stages private-registry authentication only in the service runtime, pulls and verifies all three immutable images, and removes the temporary authentication before any application unit can start;
5. installs only Lil Tweak Quadlets, the core environment, and forward-only migration files;
6. creates the rootless PostgreSQL admin secret once;
7. starts isolated PostgreSQL;
8. creates separate migrator and application roles;
9. applies `001_initial.sql` from schema version zero, then advances version one through the separately reviewed `002_fencing.sql`, always as `lil_tweak_migrator`;
10. grants the application role data access without schema-creation rights; and
11. starts one trusted-core worker only after the migration succeeds.

The installer accepts only schema versions zero, one, two, or three and advances one known migration at a time. A failed `002_fencing.sql` transaction leaves version one available for a safe installer retry; a failed `003_test_world.sql` transaction leaves version two available for the same safe retry. The deployment verifier requires schema version three, the generation-fencing column, the one-proposal approval constraint, and both durable Test World tables before cutover. Never edit an applied migration and never let application startup apply schema changes.

## Cloudflare-only ingress

Keep `lil-tweak-core` bound to `127.0.0.1:8017`. Configure a named Cloudflare Tunnel under its own constrained service identity to forward one private hostname to that loopback origin. Protect the hostname with a Cloudflare Access service policy limited to the Worker, and keep the Lil Tweak HMAC protocol enabled behind Access. The Worker must validate the owner and same-origin browser mutation before signing a core request.

The Tunnel needs outbound HTTPS only. Deny inbound TCP 8017 in both the DigitalOcean Cloud Firewall and the host firewall. Do not add a public `PublishPort`, an intermediary proxy route, or a direct DNS record for the origin. A direct-origin test from a separate host must time out; a valid Worker request through Cloudflare should succeed.

## Verification and health

Run locally as root or `lil-tweak`:

```bash
bash scripts/verify-deployment.sh
```

The verifier checks active rootless units, digest-pinned running images, exact network membership, loopback-only binding, `/healthz`, signed `/readyz`, normalized PostgreSQL rows, and the one-job concurrency setting. It also checks the service-owned Podman socket, exact runner digest, the exact 1 GiB/204,800-inode core work tmpfs at `/var/lib/lil-tweak/work`, both effective `MemorySwapMax=0` and the core's own `memory.swap.max=0`, and the actual installed sandbox lifecycle. The host invokes only `podman exec lil-tweak-core python -I -m lil_tweak.runtime_probe --image <digest>`; that module takes the same cross-process execution lock as production, traverses the real ephemeral-command and `WorkspaceTools.apply_patch` paths, validates the executable 256 MiB/65,536-inode runner tmpfs, UID maps, cgroups, network denial, tools, copy-out/promotion, and strict cleanup, then proves the exact runner name is absent. It has no direct `podman run` fallback.

This is a live qualification gate, not an offline configuration check. Run it on the target with working rootless Podman, cgroup v2, and the built images. `deploy/verify_runtime.py --check` proves only that the script loads; it is not production evidence. Drain any active engineering job first. The runtime probe acquires the singleton without waiting, so an active job makes qualification fail closed; while the probe holds the lock, the scheduler reports no admission and cannot start another job. Any missing cgroup controller, nonzero swap value, malformed observation, cleanup uncertainty, leftover probe latch, or inability to prove the exact container absent blocks cutover and requires diagnosis followed by a fresh complete run. Do not substitute mocked output or record the live gate as passed on a host where Podman/cgroup qualification is unavailable.

`/healthz` is an unauthenticated liveness response but is reachable only on loopback. `/readyz` is signed and checks the database schema, request-signing configuration, evidence configuration, bounded staging filesystem, Podman runner availability, and current singleton admission. Never expose readiness details without a valid signature.

The normal verifier does not contact R2. To opt into a safe credential/bucket check, run the same verification with the explicit flag. The probe issues only the S3-compatible `HeadBucket` request; it does not create, list, upload, overwrite, or remove an object:

```bash
LIL_TWEAK_VERIFY_R2=1 bash scripts/verify-deployment.sh
```

For diagnosis, use the dedicated journal and redact before sharing:

```bash
sudo -u lil-tweak systemctl --user status lil-tweak-core.service
sudo -u lil-tweak journalctl --user-unit lil-tweak-core.service --since today
```

Logs must not contain cookies, authorization values, signatures, nonces, emails, prompts, source contents, SQL parameters, presigned URLs, or any environment value. Job/request/event IDs and stable error codes are sufficient for correlation.

## Backup

Back up each plane independently. Encrypt backups with a key not present on the droplet and record a manifest hash.

1. PostgreSQL: pause job admission, wait for the active job to finish, and keep the database quiescent through both the fingerprint and dump. Record a content fingerprint for the normalized job/source/evidence rows with `bash scripts/verify-data-integrity.sh --snapshot /ABSOLUTE/ENCRYPTED/MANIFEST`. Then run `pg_dump --format=custom` from the isolated container and copy the stream directly to the encrypted backup target before resuming admission. The snapshot command refuses to overwrite an existing manifest. Include roles as a separately protected metadata export, but exclude password values from manifests and logs.
2. R2: copy immutable evidence/source object keys to a separate backup account or bucket without `--delete`. Retain multiple dated snapshots and verify stored SHA-256 values against evidence manifests.
3. D1: before every Cloudflare migration, export D1 from an authenticated administration workstation and retain the schema plus redacted owner-facing mirror.
4. Configuration: back up the Quadlet templates and non-secret configuration. Back up secrets only through the organization's secret manager, never in the same archive as application data. The core and runner work tmpfs filesystems are deliberately ephemeral and must never be backed up.

At least monthly, verify a random evidence object's digest and run the restore drill below. A successful command is not proof of a usable backup.

## Restore drill

Never overwrite the only production copy during a drill.

1. Create an isolated restore account, network, volume, and database name with no Tunnel route or external service access.
2. Restore the PostgreSQL custom dump into the alternate database; apply no new migration yet. Point the isolated restore verification console at that restored `lil-tweak-postgres` container, then run `bash scripts/verify-data-integrity.sh --compare /ABSOLUTE/ENCRYPTED/MANIFEST`. This checks ownership links, required digests/object keys, and a SHA-256 fingerprint of every normalized job/source/evidence field without writing database rows or exposing row contents.
3. Restore a dated R2 snapshot into an alternate prefix or bucket and compare object digests with the database evidence manifest.
4. Restore the matching D1 export into a non-production D1 database.
5. start the exact digest-pinned release against the restored resources and run `/healthz`, signed `/readyz`, owner-isolation tests, a read-only job lookup, and evidence download verification.
6. destroy the drill resources only after the result, release digest, backup IDs, hashes, and reviewer are recorded.

For disaster recovery, restore into new resources first, verify them, pause admission, update only the secret references, and then move the Cloudflare route. Keep the previous resources read-only until the rollback window closes.

## Rotation

### Request-signing-key rotation

1. Generate a new random key with a new key ID in the secret manager.
2. Add both old and new keys to the core signing-key JSON and restart the core.
3. Verify readiness, then configure the Worker to sign new requests with the new key ID.
4. Wait longer than the 300-second signature window and for all in-flight requests to finish.
5. remove the old key from the Worker and core, restart, and run verification again.

Never reuse a key ID for different bytes. Replay nonces remain keyed by key ID and must not be cleared during rotation.

### Other credentials

Rotate the application database password using the admin console, update `core.env`, restart, and verify before retiring the old credential. Rotate PostgreSQL admin/migrator, R2, OpenAI, and Tunnel credentials independently. A rootless Podman secret is immutable; stop PostgreSQL, remove and recreate only the named Lil Tweak admin secret, then start and verify. Never touch another product's secret during a Lil Tweak rotation.

## Upgrade, rollback, and capacity

Before an upgrade, record running image digests, take PostgreSQL/D1 backups, confirm R2 evidence replication, run offline checks, and run the migration. Replace Quadlet image references only with reviewed digests. Start PostgreSQL, migrate, then restart the core and verify before changing a Cloudflare route.

For code-only rollback, restore the previous core digest and restart. Database migrations are forward-only: if the previous binary is incompatible with the new schema, keep the new schema-compatible binary or restore all planes into alternate resources from the pre-upgrade backup. Do not run ad-hoc reverse SQL against production.

Four-GiB deployment remains blocked until live headroom qualification. Keep one Lil Tweak execution at a time. The installed hard limits permit roughly 1.5 GiB for the core (including its 1 GiB staging tmpfs), 1 GiB for the transient runner, and 512 MiB for PostgreSQL. Use at least the eight-GiB plan class until live evidence supports otherwise. Reject or queue new work when admission is occupied. Add capacity by moving Lil Tweak to a larger dedicated host before raising concurrency.
