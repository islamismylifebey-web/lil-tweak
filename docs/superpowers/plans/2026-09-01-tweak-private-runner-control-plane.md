# Lil' Tweak private runner control-plane implementation plan

> **For implementation:** Use test-first changes, keep the existing Resource Director and Gate 3 contracts authoritative, and do not deploy or qualify from source-only evidence.

## Task 1: Define and test the dispatch attestation

**Files:** `liltweak/resource/dispatch.py`, `tests/test_resource_dispatch.py`

1. Add failing tests for canonical signing, exact runner/role binding, expiry, digest tampering, and prohibited raw payload fields.
2. Implement the narrow Ed25519 attestation model and verification helpers.
3. Run `pytest -q tests/test_resource_dispatch.py`.

## Task 2: Add the typed self-hosted provider

**Files:** `liltweak/providers/self_hosted/*`, `tests/test_self_hosted_provider.py`

1. Add failing tests for profile identity, typed dispatch, action-manifest limits, and non-completion receipts.
2. Implement an injected-client adapter compatible with the existing provider contract.
3. Run `pytest -q tests/test_self_hosted_provider.py`.

## Task 3: Build the Cloudflare runner control plane

**Files:** `cloudflare/runner-control-plane/*`

1. Add failing Worker/DO tests for identity, signature, expiry, nonce replay, and forbidden fields.
2. Implement deterministic runner Durable Object storage and typed Worker routes.
3. Run the package tests and a non-deploy config/type check.

## Task 4: Integrate configuration and activation guards

**Files:** `liltweak/config.py`, `liltweak/api.py`, `liltweak/resource/*`, tests as needed, `.env.example`

1. Add failing tests proving missing new settings keep the path disabled and existing Gate 3 behavior unchanged.
2. Add a protected factory that builds the self-hosted provider only from a fully pinned configuration and keeps runtime status unqualified.
3. Run focused Python tests, static checks, and the Worker test/check commands.

## Task 5: Review and prepare the PR

**Files:** all changed files, documentation

1. Inspect diff for arbitrary execution, secret exposure, weakened legacy validation, deployment configuration, or false completion claims.
2. Run the relevant CI-equivalent checks available locally.
3. Commit, push the isolated feature branch, and prepare a PR without merging or deployment.
