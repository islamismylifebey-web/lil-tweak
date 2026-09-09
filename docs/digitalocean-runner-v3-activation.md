# DigitalOcean Runner V3 Activation

## Purpose

This is the canonical activation track for the dedicated Lil' Tweak DigitalOcean runner.

It supersedes PR #12 as the active runner-activation path. PR #12 is closed and must not be reopened, merged, or used as a live activation dependency.

## Immutable runner identity

- Provider: DigitalOcean
- Droplet ID: `597343619`
- Name: `galor-tweak-runner-01`
- Region: `nyc1`
- OS: Ubuntu 24.04 LTS x64
- Size: `s-4vcpu-8gb`
- CPU: 4 vCPU
- Memory: 8192 MB
- Disk: 160 GB
- Required role label: `role-tweak-runner`
- Policy: `ENGINEERING_EXECUTION_ONLY`
- Public IPv4: `147.182.140.5`
- Private IPv4: `10.116.0.3`
- VPC: `084ac399-e504-4513-8a51-b2716d8378ea`

The immutable identity is provider + droplet ID + expected name. A matching name with a different ID, or matching ID with a different name, fails closed.

## Current observed state

DigitalOcean reports the droplet as active. Monitoring, the DigitalOcean agent, and private networking are enabled. This does not prove that Lil' Tweak execution is connected or qualified.

Current truth:

- DROPLET_ACTIVE = YES
- RUNNER_INSTALLED = UNVERIFIED
- RUNNER_CONNECTED = NO EVIDENCE
- RUNNER_QUALIFIED = NO
- PRODUCTION_AUTHORITY = NO
- DEPLOYMENT_AUTHORITY = NO

## Activation gates

The runner may not be called CONNECTED or QUALIFIED until all gates below have fresh evidence for this exact droplet identity.

### Gate 1 — Host baseline

Verify the exact host identity and operating system. Establish secure administrative access through an approved runtime/console path. Do not place private keys, passwords, registration tokens, or secret values in GitHub, chat logs, screenshots, or committed files.

### Gate 2 — Host hardening

Create an unprivileged runner service account. Apply least-privilege filesystem ownership, bounded workspace directories, patching, firewall policy, service isolation, logging, and resource ceilings appropriate for engineering execution only.

### Gate 3 — Runner identity and control contract

Install the approved Lil' Tweak runner runtime and bind it to the exact server-owned contract, identity, role, repository scope, and revocation state. No arbitrary shell, unrestricted repository target, production credential, deployment credential, or browser authority is allowed.

### Gate 4 — Connection proof

Produce fresh authenticated evidence that Lil' Tweak can see and address only `galor-tweak-runner-01` under the required `role-tweak-runner` identity. Provider-active state alone does not satisfy this gate.

### Gate 5 — Qualification Job A

Run a harmless no-write engineering job against an immutable repository revision. Required evidence includes exact input revision, lease/authorization binding, runner identity, bounded execution record, output digest, and independent verification.

### Gate 6 — Qualification Job B

Run a bounded disposable write/patch verification job that cannot push, merge, deploy, mutate production, or escape the authorized workspace. The result must be independently verified against the exact Job A/contract lineage required by the active qualification policy.

### Gate 7 — Adversarial fail-closed checks

Prove rejection of at least: stale lease, wrong droplet/runner identity, wrong repository revision, expired authorization, unauthorized action type, path escape, production/deployment request, replay, and mismatched evidence digest.

## Completion rule

Only after Gates 1-7 pass on the exact live DigitalOcean runner may Lil' Tweak report:

- `CONNECTED = YES`
- `QUALIFIED = YES`

Until then, the runner remains provisioned infrastructure under preparation.

## Change control

This activation track must remain independent of the closed PR #12 branch. Any useful contract or test concept recovered from PR #12 must be intentionally ported and reverified; no generated provenance, qualification state, or live-connected claim from PR #12 carries forward automatically.

Do not merge this activation branch merely because the droplet is active. Merge only when the repository changes associated with the new DigitalOcean runner are reviewed and the required exact-head verification passes.