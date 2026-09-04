# Offline dependency workflow

Lil Tweak never enables network access inside a code sandbox. The current release does not mount a shared host package cache because it cannot yet bind a cache's content digest to an immutable job source/proposal digest. A generic writable cache would create cross-job mutation and supply-chain paths, so the supported contract is deliberately narrower:

- language runtimes and build tools already present in the digest-pinned runner image;
- standard-library projects; or
- dependencies vendored into the uploaded source and frozen by a reviewed lock plus artifact hashes.

Missing dependencies are a bounded test failure, not permission to fetch from the Internet. The model cannot change this policy.

## Trusted preparation

Prepare dependencies on a separate, trusted workstation or CI fetch job. That fetch environment may use the network; the resulting source must be scanned and reviewed before upload. It receives no Lil Tweak signing, OpenAI, R2, Tunnel, database, or other-product credentials.

Run the preflight before creating the source ZIP:

```bash
python3 scripts/verify-offline-dependencies.py /ABSOLUTE/SOURCE_DIRECTORY
```

The verifier reads metadata and vendored files only. It does not execute a package manager, install software, or access the network. It accepts these bounded layouts:

| Ecosystem | Required offline layout | Sandbox install/test form |
|---|---|---|
| npm | `package-lock.json` v2/v3; every resolved dependency is an integrity-bound `file:vendor/npm/*.tgz` | `npm ci --offline --ignore-scripts`, then explicitly reviewed scripts/tests |
| Python | exact `requirements.txt` with `--no-index`, `--find-links vendor/wheels`, and SHA-256 hashes; reviewed wheels under `vendor/wheels` | create a workspace venv, then `pip install --no-index --require-hashes ...` |
| Go | `go.mod`, `go.sum`, and `vendor/modules.txt` | `go test -mod=vendor ./...` |
| Rust | `Cargo.lock`, `.cargo/config.toml` replacing crates.io with a repository-local directory, and vendored crates | `cargo test --locked --offline` |

Yarn, pnpm, Composer, Ruby Bundler, NuGet, and other lock formats are not hydrated in this release. A job using them may still inspect/refactor source but must report tests blocked by unavailable dependencies. Do not disguise a host path or remote package server as a local dependency.

## Source safety still applies

Vendored content must fit the normal source limits: 25 MiB per file, 100 MiB browser upload total, and 128 MiB validated decompressed total. ZIP traversal, symlinks, devices, duplicate/case-colliding paths, excessive compression, and unsafe names remain rejected. Do not upload a prebuilt virtual environment or `node_modules`; those trees commonly contain platform-specific binaries and symlinks and are not a portable trust boundary.

Record the source archive SHA-256, lockfile hashes, vendor directory manifest, fetch job identity, scanner result, and runner image digest. Dependency license and vulnerability review happens before upload. A lockfile alone is not proof that its vendored bytes are safe.

## Future cache contract

A read-only host cache may be added only after the trusted control plane can:

1. normalize a supported lock format;
2. fetch with strict size, host, redirect, checksum, and signature policy outside the sandbox;
3. produce an immutable cache manifest and digest;
4. bind that digest to the job and evidence proposal;
5. give each job a read-only, digest-addressed mount with no cross-job writable state; and
6. reproduce and garbage-collect it without exposing service credentials.

Until all six exist and are tested, the sandbox retains `--network=none` and no dependency-cache mount.
