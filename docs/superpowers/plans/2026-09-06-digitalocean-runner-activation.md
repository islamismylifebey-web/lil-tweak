# DigitalOcean Runner Activation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Activate and qualify DigitalOcean Droplet `597343619` as Lil' Tweak's direct, private, engineering-only Podman execution host with fresh authenticated evidence.

**Architecture:** Preserve the current `Sites -> signed private Core -> digest-pinned ephemeral Podman sandbox` path. The Core, PostgreSQL, Cloudflare Tunnel, and disposable runner live under dedicated least-privilege identities on `galor-tweak-runner-01`; GALOR Hub is absent from configuration, transport, authentication, and status. Connection and qualification are derived from signed live Core readiness plus exact-host qualification evidence, never from provider-active state.

**Tech Stack:** Next.js/TypeScript Sites layer, Python 3.12 trusted Core, PostgreSQL 16, rootless Podman/Quadlet, Cloudflare Tunnel/Access, DigitalOcean Ubuntu 24.04, unittest and Node test runner.

**Spec:** `docs/digitalocean-runner-v3-activation.md`

## Global Constraints

- Exact host identity is provider `DigitalOcean`, Droplet `597343619`, name `galor-tweak-runner-01`.
- Required role is `role-tweak-runner`; policy is `ENGINEERING_EXECUTION_ONLY`.
- GALOR Hub is not a dependency, intermediary, dispatcher, supervisor, contract authority, or authentication hop.
- No arbitrary shell, unrestricted repository target, production mutation, deployment, browser, push, or merge authority is granted to the runner.
- Secrets stay server-side and must not appear in Git, terminal output, evidence payloads, screenshots, or PR comments.
- Completion requires fresh Gates 1-7 evidence from the exact live host and exact-head verification.
- Live model calls remain disabled while credits are exhausted; deterministic qualification must not consume model credits.

---

### Task 1: Retain current source authority and remove Hub coupling

**Files:**
- Modify: `README.md`
- Modify: `app/engineering-client.ts`
- Modify: `app/workbench.tsx`
- Modify: `core/lil_tweak/config.py`
- Delete: `core/lil_tweak/galor.py`
- Modify: `core/lil_tweak/orchestrator.py`
- Modify: `core/main.py`
- Test: `core/tests/test_hub_detachment.py`
- Test: `tests/hub-detachment.test.mjs`

**Interfaces:**
- Consumes: current `main` at `e7d48f9143c44966a1d0f1320994378933b09fd6` and PR #28 commits.
- Produces: a direct Core-to-Podman path with the retired `LIL_TWEAK_GALOR_READONLY_URL` value rejected.

- [x] **Step 1: Rebase PR #21 onto current `main`**

  Run `git rebase main` on `infra/digitalocean-runner-v3-activation` and verify the activation document is retained.

- [x] **Step 2: Port the reviewed Hub-detachment commits**

  Cherry-pick `eee5f50f729ec3a7da83a2db5ef122b25ba2c426^..43157bbe53b1ab2fa46c2e49a012bd0a3fefa5aa` and retain the original TDD sequence.

- [ ] **Step 3: Run detachment tests**

  Run `python -m unittest core.tests.test_hub_detachment` and `node --test tests/hub-detachment.test.mjs tests/engineering-connection.test.mjs tests/deployment-contract.test.mjs`.

- [ ] **Step 4: Verify no live Hub path remains**

  Run `rg -n "GALOR|galor" core app lib deploy docs README.md` and review every remaining match as either a retired-setting rejection, historical statement, or unrelated artwork reference.

### Task 2: Make connection and qualification evidence explicit

**Files:**
- Create: `core/lil_tweak/runner_qualification.py`
- Modify: `core/lil_tweak/api.py`
- Modify: `core/main.py`
- Modify: `lib/engineering-connection.ts`
- Test: `core/tests/test_runner_qualification.py`
- Test: `tests/engineering-connection.test.mjs`
- Modify: `docs/digitalocean-runner-v3-activation.md`

**Interfaces:**
- Consumes: signed Core request verification, existing `readiness()` dependency checks, and the Podman runtime probe.
- Produces: `RunnerQualificationEvidence` with exact droplet identity, source revision, image digest, connection nonce, job lineage, adversarial results, generated-at timestamp, and canonical SHA-256 digest; authenticated readiness reports `connection` and `qualification` separately.

- [ ] **Step 1: Write failing Python evidence tests**

  Define tests that reject wrong droplet ID/name, mutable image references, stale timestamps, Job B without matching Job A lineage, replayed nonces, missing adversarial cases, mismatched digests, and `qualified=true` when any gate failed.

- [ ] **Step 2: Verify the Python tests fail for the missing module**

  Run `python -m unittest core.tests.test_runner_qualification -v` and require failure before implementation.

- [ ] **Step 3: Implement canonical evidence validation**

  Add frozen dataclasses and strict canonical-JSON hashing. Accept only droplet `597343619`, host `galor-tweak-runner-01`, role `role-tweak-runner`, policy `ENGINEERING_EXECUTION_ONLY`, a lowercase 40/64-character immutable source revision, and `@sha256:` runner references. Require the nine adversarial checks named by the activation spec.

- [ ] **Step 4: Expose evidence only through the authenticated Core status path**

  Load the root-owned read-only evidence file configured by `LIL_TWEAK_RUNNER_QUALIFICATION_EVIDENCE`; readiness must fail closed to `not_reported` or `failed`, never infer success from `/healthz`.

- [ ] **Step 5: Run Python and Node evidence tests**

  Run `python -m unittest core.tests.test_runner_qualification core.tests.test_api core.tests.test_main -v` and `node --test tests/engineering-connection.test.mjs`.

### Task 3: Harden the exact host without destroying retained artifacts

**Files:**
- Create: `scripts/activate-digitalocean-runner.sh`
- Create: `deploy/lil-tweak-runner-host.service.d/hardening.conf`
- Test: `deploy/tests/test_digitalocean_runner_activation.py`
- Modify: `docs/operations/digitalocean.md`

**Interfaces:**
- Consumes: DigitalOcean metadata endpoint, Ubuntu host state, existing `lil-tweak-host-identity.py`, and the dedicated SSH administration path.
- Produces: an idempotent host activation command and a machine-readable baseline receipt.

- [ ] **Step 1: Write failing activation-script contract tests**

  Assert exact metadata/name/role/policy checks, locked `lil-tweak` and `lil-tweak-tunnel` users, rootless subordinate IDs, AppArmor enforcement, automatic security updates, UFW default-deny, SSH key-only authentication, journald persistence, resource ceilings, and preservation of `/var/lib/lil-tweak-build`.

- [ ] **Step 2: Run the activation tests and require RED**

  Run `python -m unittest deploy.tests.test_digitalocean_runner_activation -v`.

- [ ] **Step 3: Implement the idempotent host activation command**

  The command must stop before mutation on an identity mismatch, make a timestamped configuration backup, install only approved Ubuntu packages, create dedicated identities/directories with exact modes, apply firewall and SSH hardening while preserving the verified key session, and emit a SHA-256-bound receipt without secret values.

- [ ] **Step 4: Apply activation to the live host**

  Copy the exact PR-head source/archive to `/var/lib/lil-tweak-release/<head>`, verify its SHA-256 and Git tree, run the activation command as root, reconnect over SSH, and confirm no unexpected public listeners.

- [ ] **Step 5: Verify host Gate 1 and Gate 2 evidence**

  Verify metadata ID, hostname, Ubuntu version, role tag from DigitalOcean, firewall policy, SSH configuration, dedicated account identity, AppArmor mode, cgroup v2, disk/memory headroom, and zero failed units.

### Task 4: Install the approved Core and runner runtime

**Files:**
- Modify: `deploy/core.env.example`
- Modify: `scripts/install-lil-tweak-release.sh`
- Modify: `scripts/verify-deployment.sh`
- Test: `deploy/tests/test_install_transaction.py`
- Test: `deploy/tests/test_release_tooling.py`
- Test: `deploy/tests/test_runtime_qualification.py`

**Interfaces:**
- Consumes: exact source head, retained local registry/images only if their source and digest provenance validates, rootless Podman, Quadlet units, and server-side secrets.
- Produces: loopback-only private Core, PostgreSQL, outbound-only dedicated Tunnel, and digest-pinned credential-free disposable runner.

- [ ] **Step 1: Validate retained build artifacts**

  Match each retained image digest to its build log, source bundle commit/tree, SBOM, and vulnerability scan. Rebuild from the exact PR head when any link is missing or stale.

- [ ] **Step 2: Run release-tooling tests**

  Run `python -m unittest discover deploy/tests -v` and fix only runner-mission regressions.

- [ ] **Step 3: Stage server-side configuration**

  Generate fresh signing, database, and qualification nonce material on-host; restore approved external OpenAI/R2/Tunnel values from existing protected host inputs without printing them. Keep model execution disabled.

- [ ] **Step 4: Perform the transactional install**

  Run `scripts/install-lil-tweak-release.sh` with exact source/runtime manifests, digest-pinned images, a verified rollback receipt, and one host-global rollback lease.

- [ ] **Step 5: Verify the installed runtime**

  Run `scripts/verify-deployment.sh`, signed `/readyz`, normalized PostgreSQL checks, exact image inspection, loopback binding checks, rootless socket checks, transient sandbox lifecycle, and strict cleanup.

### Task 5: Run live qualification and adversarial checks

**Files:**
- Create: `scripts/qualify-digitalocean-runner.py`
- Create: `docs/verification/digitalocean-runner-597343619.json`
- Test: `core/tests/test_live_qualification_driver.py`

**Interfaces:**
- Consumes: authenticated Core status, immutable repository head, digest-pinned runner image, runtime execution lock, and canonical evidence validator.
- Produces: fresh, digest-bound Job A, Job B, adversarial, and exact-head evidence for PR #21.

- [ ] **Step 1: Write failing qualification-driver tests**

  Use deterministic fake transports to prove nonce freshness, immutable revision binding, no-write Job A, disposable-write Job B, no push/merge/deploy authority, independent output verification, replay rejection, and cleanup after each case.

- [ ] **Step 2: Run tests and require RED**

  Run `python -m unittest core.tests.test_live_qualification_driver -v`.

- [ ] **Step 3: Implement the bounded driver**

  Job A computes and independently verifies a repository inventory digest without writes. Job B writes one marker inside a disposable workspace, produces a patch/digest, verifies the source remains unchanged, and proves the workspace/container are destroyed. The driver then executes all nine required rejection cases.

- [ ] **Step 4: Run live Jobs A and B**

  Bind both jobs to the exact PR head, droplet metadata ID, runner image digest, connection nonce, authorization expiry, and one qualification lineage. Store no secrets or source payloads in the evidence document.

- [ ] **Step 5: Run live fail-closed cases**

  Prove rejection of stale lease, wrong droplet identity, wrong runner name, wrong repository revision, expired authorization, unauthorized action, path escape, production/deployment request, replay, and mismatched evidence digest.

### Task 6: Exact-head verification and PR evidence

**Files:**
- Modify: `docs/digitalocean-runner-v3-activation.md`
- Modify: `docs/verification/digitalocean-runner-597343619.json`

**Interfaces:**
- Consumes: exact Git head after all fixes and the live qualification receipt.
- Produces: reviewed PR #21 with passing checks and truthful `CONNECTED`/`QUALIFIED` state.

- [ ] **Step 1: Run focused and full local verification**

  Run Python Core tests, deploy tests, Node tests, typecheck, lint, production build, secret scan, and manifest verification against the exact head. Record commands, timestamps, exit codes, and head SHA.

- [ ] **Step 2: Push the rebuilt PR branch safely**

  Use `git push --force-with-lease origin infra/digitalocean-runner-v3-activation` because the retained one-commit branch was rebased. Confirm the remote head equals the locally verified head.

- [ ] **Step 3: Verify GitHub checks on the exact head**

  Wait for required checks, inspect every failure, fix runner-mission blockers, and repeat live/exact-head evidence whenever a code change invalidates it.

- [ ] **Step 4: Publish sanitized evidence and update PR #21**

  Include exact head, droplet ID/name, runner digest, signed connection proof digest, Job A/B evidence digests, adversarial outcomes, timestamps, and verification run URLs. Do not include credentials, raw environment, private source, or reusable nonces.

- [ ] **Step 5: Merge only after all gates pass**

  Mark ready and merge PR #21 only when the remote exact head, live installed exact head, evidence head, and verified checks are identical and all Gates 1-7 are green. Otherwise keep the PR draft and report the precise unmet gate.
