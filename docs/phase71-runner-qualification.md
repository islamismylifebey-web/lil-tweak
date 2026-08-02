# Phase 7.1 Dormant Runner Qualification

Date: 2026-07-29 (America/Chicago)  
Version: 0.7.1  
Baseline private `main`: `43580205930718d45d3571b99033ff00e8952d41`  
Execution connected: No

## Purpose

Phase 7.1 adds automatic source regression checks and a review-only contract for evidence from a
future dedicated Linux runner. It does not create, register, deploy, lease, or connect that
runner. GitHub-hosted CI proves source regressions only and is deliberately separate from
runner-isolation evidence.

## Signed contract

A GitHub-hosted coordinator generates an ephemeral Ed25519 issuer key and signs a short-lived
challenge. The challenge binds:

- the exact `github:islamismylifebey-web/lil-tweak` repository identity, commit, and tree;
- one runner identifier and the SHA-256 key identifier of its protected Ed25519 public key;
- the exact qualification-suite digest;
- immutable image, sandbox-profile, runtime, limiter, external collector, and destroyer digests;
- a 256-bit nonce, issue time, expiry of at most ten minutes, and challenge digest.

The external host supervisor returns an Ed25519-signed `runner-qualification-v1` attestation.
The GitHub-hosted verifier independently pins every expected binding; it does not learn trust
values from the attestation. It authenticates the ephemeral challenge issuer, maps the expected
runner identity to its protected public key, revalidates both schemas at the verification
boundary, and rejects any mismatch.

Canonical signing messages are exact bytes:

```text
b"liltweak:runner-qualification-challenge:v1\0"
  + UTF8(canonical_json(challenge_without_issuer_signature))

b"liltweak:runner-qualification:v1\0"
  + UTF8(canonical_json(attestation_without_signature))
```

The terminating NUL byte is part of each domain. Canonical JSON uses the repository’s
`canonical_json` function. The challenge digest excludes `challenge_digest` and
`issuer_signature`; the evidence digest excludes `evidence_digest` and `signature`. The
signatures include their respective digest field. Fixed message-digest test vectors protect
external collector interoperability.

All 47 observations are mandatory, unique, and ordered. They cover IPv4, IPv6, DNS, loopback,
metadata, proxy, and Unix-socket denial; non-root identity; capabilities, no-new-privileges, MAC
and seccomp; host PID and process-environment denial; CPU, memory, PID, disk, inode, wall-clock,
and output limits; read-only source and root filesystems; absence of Git metadata, credentials,
other repositories, host devices, container sockets, SSH agents, and control-plane state;
timeout, OOM, fork, output, disk, inode, and sleeping-child attacks; live cancellation,
emergency termination, crash recovery; unchanged source; and complete cgroup, mount, namespace,
workspace, and process cleanup.

Missing, extra, reordered, duplicate, failed, stale, future, mismatched, malformed, oversized,
badly encoded, or badly signed evidence fails closed.

## Three-job manual workflow

`.github/workflows/runner-qualification.yml` is manual and `main`-only:

1. `validate-and-issue` runs on GitHub-hosted Ubuntu. It rejects a bad ref, commit,
   acknowledgement, repository identity, or protected configuration; checks out only
   `github.sha`; installs the locked environment; creates the ephemeral signed challenge; and
   uploads only the bounded public challenge and issuer public key for one day.
2. `collect-candidate-evidence` runs on the uniquely labeled ephemeral self-hosted candidate. It
   has an empty GitHub token permission set, checks out no repository, runs as a non-root host
   account, and runs no repository Python. It passes the original challenge and ephemeral issuer
   public key to the host-owned collector, verifies root ownership, link count, non-writable path
   ancestry, and pinned SHA-256 for the collector and destroyer, invokes only the collector,
   revalidates the destroyer before mandatory cleanup, and uploads the bounded signed attestation
   only after cleanup succeeds.
3. `verify-candidate-evidence` runs on a fresh GitHub-hosted Ubuntu job after collection and
   cleanup. It independently downloads the original challenge and attestation, validates every
   protected expectation again, verifies both signatures, and writes the only passing summary.

All referenced actions are full-commit pinned. The workflow has read-only repository permission,
persists no checkout credential, exposes no API key, makes no paid model call, writes no
repository state, and never sets execution enabled. Artifact names are unique to the workflow
run and attempt; only bounded public signed JSON is retained for one day. Collector stdout and
stderr are not uploaded.

The protected `liltweak-runner-qualification` environment must supply:

- `LILTWEAK_QUALIFICATION_RUNNER_ID`;
- `LILTWEAK_QUALIFICATION_KEY_ID`;
- `LILTWEAK_QUALIFICATION_RUNNER_PUBLIC_KEY` as unpadded URL-safe base64;
- `LILTWEAK_QUALIFICATION_IMAGE_REF`;
- `LILTWEAK_QUALIFICATION_PROFILE_DIGEST`;
- `LILTWEAK_QUALIFICATION_RUNTIME_SHA256`;
- `LILTWEAK_QUALIFICATION_LIMITER_SHA256`;
- `LILTWEAK_QUALIFIER_SHA256`;
- `LILTWEAK_DESTROYER_SHA256`.

The candidate must have the exact labels `self-hosted`, `linux`, `x64`,
`liltweak-qualification`, and `ephemeral`. Its external lifecycle controller must provision a
fresh machine for one job and destroy it even if GitHub Actions or the in-guest cleanup command
fails. The workflow verifies in-guest cleanup but cannot substitute for that independent
machine-lifecycle guarantee.

## Activation blockers

A valid offline report is not live authorization. The decision type fixes
`connection_authorized=false`. A future activation phase still needs:

- durable, atomic one-use challenge and attestation replay prevention;
- a fresh runner-signed connection nonce and short lease on every control-plane start;
- a per-attempt signature binding the plan digest, attempt nonce, runner session, and current
  qualification;
- remote authenticated transport whose private signing key is unavailable to job and sandbox
  code, preferably backed by TPM, KMS, or a host attestor;
- control-plane checks immediately before snapshot, claim, and dispatch;
- independent runner destruction and orphan recovery.

Until all of those exist, `execution_connected=false` is mandatory.

