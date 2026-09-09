# Tueiq Direct Runner Activation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver and live-prove one Hub-independent Tueiq engineering runner on DigitalOcean Droplet `597343619`.

**Architecture:** Preserve the current Sites source, import the merged durable Test World, remove every GALOR Hub integration, and deploy the trusted Core/PostgreSQL/rootless-Podman stack together on the existing Droplet. The owner-authenticated Site sends HMAC-signed requests through Cloudflare ingress directly to the loopback-only Core; Core schedules disposable local Podman sandboxes without a broker or GitHub runner.

**Tech Stack:** TypeScript/React/Vinext, Cloudflare Workers/Sites/D1/R2/Access/Tunnel, Python 3.12 ASGI Core, PostgreSQL schema v3, rootless Podman/Quadlet, DigitalOcean Ubuntu 24.04, Node 22.

**Spec:** `docs/superpowers/specs/2026-09-04-tueiq-direct-runner-activation-design.md`

## Global Constraints

- Immutable target: provider `DigitalOcean`, Droplet ID `597343619`, hostname `galor-tweak-runner-01`, region `nyc1`, Ubuntu 24.04 LTS x64, size `s-4vcpu-8gb`, role `role-tweak-runner`, owner `tueiq`, canonical Core owner scope `a0885bc0b2c079e996629061a723c74d`, policy `ENGINEERING_EXECUTION_ONLY`.
- Direct path only: owner-authenticated Site -> HMAC-signed Core -> Core-local scheduler -> local rootless Podman -> fresh sandbox.
- Cloudflare Tunnel/Access is ingress transport only; intermediary is `none`.
- No GALOR Hub adapter, configuration, environment value, fetched context, status object, provenance, UI panel, workflow, container label, runtime, credential, process, network, or operational dependency.
- Presence of `LIL_TWEAK_GALOR_READONLY_URL`, including a blank value, fails closed.
- Preserve Sites source commit `e76996970e816c4cce7b8334e0495e1e0de48e7d` and import Test World merge `97acede665df94ea7002b6eb7eceb8dc28ea94f7` without the self-mutating workflow `.github/workflows/tueiq-main-wiring-patch.yml`.
- Schema version is `3`; Core, PostgreSQL, and runner images are strict digest-pinned references.
- Core listens only on `127.0.0.1:8017`; sandboxes are rootless, network-disabled, capability-dropped, resource-limited, and disposable; concurrency remains one shared runtime lock.
- No arbitrary host shell, unrestricted repository target, push, merge, deploy, production credential, browser authority, OpenAI key, database/R2 credential, signing key, or host environment reaches a sandbox.
- Unsigned `/healthz` never establishes connection; only an owner-bound HMAC v2 `/readyz` response with every check true may establish `ready`.
- Signed readiness establishes connection only. Qualification is `not_reported` until fresh live Gates 1-7 pass on the immutable target.
- Task 5 emits only `tueiq-direct-runner-local-qualification-v1`, with no `CONNECTED`, `QUALIFIED`, or `READY_TO_WORK` fields. Activation is a two-phase candidate -> independent witness -> final model: candidate construction and review contain and print no final uppercase truth; only post-review `finalize-reviewed` may create those booleans in `tueiq-direct-runner-activation-v1`, and only `verify-final` may print them after independently reopening every original live artifact.
- Every behavior change follows RED -> GREEN -> refactor; every test names an observable break and exercises real production behavior.
- Do not reset, rebuild, replace, resize, power-cycle, snapshot, or delete the existing Droplet as part of this plan.
- Never print or commit credentials, private IPs, public IPs, keys, tokens, signatures, environment values, or raw secret-bearing responses.

---

### Task 1: Import and harden the durable Test World

**Files:**
- Create: `core/lil_tweak/test_world.py`
- Create: `core/lil_tweak/test_world_api.py`
- Create: `core/lil_tweak/test_world_postgres.py`
- Create: `core/lil_tweak/test_world_runner.py`
- Create: `core/lil_tweak/test_world_runtime.py`
- Create: `core/lil_tweak/test_world_scheduler.py`
- Create: `core/migrations/003_test_world.sql`
- Create: `core/tests/test_test_world.py`
- Create: `core/tests/test_test_world_api.py`
- Create: `core/tests/test_test_world_invariants.py`
- Create: `core/tests/test_test_world_main.py`
- Create: `core/tests/test_test_world_modes.py`
- Create: `core/tests/test_test_world_runner.py`
- Create: `core/tests/test_test_world_runtime.py`
- Create: `core/tests/test_test_world_scheduler.py`
- Create: `core/tests/test_test_world_schema.py`
- Create: `.github/workflows/tueiq-test-world-ci.yml`
- Modify: `core/main.py`
- Modify: `scripts/install-digitalocean.sh`
- Modify: `scripts/lil-tweak-rollback.py`
- Modify: `scripts/lil-tweak-service-files.py`
- Modify: `deploy/postgres-integrity.sql`
- Modify: `deploy/tests/test_operations_contract.py`
- Modify: `deploy/tests/test_service_files.py`
- Modify: `tests/deployment-contract.test.mjs`
- Delete after import: `.github/workflows/tueiq-main-wiring-patch.yml`

**Interfaces:**
- Consumes: existing `PodmanSandbox`, `WorkspaceTools`, immutable Git intake, `runtime_execution_lock`, CodeEngineer, signed Core ASGI request verification, and PostgreSQL migration v2.
- Produces: schema v3 durable worlds/attempts, `TestWorldStore.count_attempts(owner_id: str, world_id: str) -> int`, generation-fenced attempt execution, and an owner-only signed Test World API suitable for live Job A/B practice.

- [ ] **Step 1: Install dependencies and record the clean Sites baseline**

Run:

```bash
node /root/.codex/plugins/cache/openai-curated-remote/sites/0.1.49/scripts/install-dependencies.mjs
git status --short --branch
git rev-parse HEAD
npm run typecheck
python3 -m unittest core.tests.test_main deploy.tests.test_operations_contract deploy.tests.test_service_files
```

Expected: clean activation worktree at `e76996970e816c4cce7b8334e0495e1e0de48e7d`; any baseline failure is recorded verbatim in the task report and distinguished from new failures.

- [ ] **Step 2: Mechanically import the authenticated PR #29 diff**

Use the authenticated GitHub connector to fetch PR `29` from `islamismylifebey-web/lil-tweak`. Require `merged=true`, base SHA `72810ca4e06bbef7eceabad7b9edf406cba6b66e`, head SHA `ee246394f5603e72ef3017289e7acef81bc4034a`, and merge SHA `97acede665df94ea7002b6eb7eceb8dc28ea94f7` before using its unified diff. Record the fetched diff's SHA-256 in the task report, verify `git apply --check`, then apply that exact byte stream. Remove `.github/workflows/tueiq-main-wiring-patch.yml` immediately; it grants `contents: write` and pushes rewritten code and is forbidden by the spec. Do not replace the Sites UI commits or merge unrelated GitHub history.

Run:

```bash
git diff --check
test ! -e .github/workflows/tueiq-main-wiring-patch.yml
```

Expected: imported Test World files are present, schema v3 is wired, the self-mutating workflow is absent, and the worktree has no whitespace errors.

- [ ] **Step 3: Write failing lease and summary-bound tests**

Add literal behavior cases to `core/tests/test_test_world.py` and `core/tests/test_test_world_modes.py` that construct two owners/worlds and prove all of these calls fail without changing the attempt:

```python
with self.assertRaisesRegex(ValueError, "attempt lease is stale"):
    store.fail_attempt(other_owner, world.id, attempt.id, lease, "failed")
with self.assertRaisesRegex(ValueError, "attempt lease is stale"):
    store.fail_attempt(owner, other_world.id, attempt.id, lease, "failed")
with self.assertRaisesRegex(ValueError, "attempt lease is stale"):
    store.fail_attempt(owner, world.id, completed_attempt.id, lease, "failed")
with self.assertRaisesRegex(ValueError, "attempt lease is stale"):
    store.fail_attempt(owner, world.id, attempt.id, lease.with_generation(lease.generation + 1), "failed")
with self.assertRaisesRegex(ValueError, "attempt lease is stale"):
    store.fail_attempt(owner, world.id, attempt.id, lease.with_worker_id("worker:wrong"), "failed")
with self.assertRaisesRegex(ValueError, "summary is too large"):
    store.fail_attempt(owner, world.id, attempt.id, lease, "é" * 32769)
```

If the imported lease type has no `with_generation`/`with_worker_id` helper, construct literal replacement lease values with the same public type and all other fields unchanged; do not add production helpers only for tests. Mirror wrong generation, wrong worker, and the 65,537-byte rejection at the PostgreSQL adapter boundary with the real adapter and a recording DB connection, asserting no mutation query is issued for rejected input. Add acceptance of an ASCII summary exactly 65,536 bytes long in both stores.

- [ ] **Step 4: Run the new tests to prove RED**

Run:

```bash
python3 -m unittest core.tests.test_test_world core.tests.test_test_world_modes core.tests.test_test_world_schema -v
```

Expected: imported happy-path tests may pass, while at least the new cross-owner/cross-world/non-running/UTF-8-byte-bound cases fail against the imported implementation for the stated reason.

- [ ] **Step 5: Bind failure transitions and bounds in both stores**

Make `fail_attempt` accept and validate the canonical owner and world identity, require the attempt to be `running`, require exact lease generation and worker ID, and call the existing bounded-text validator with a `65_536` UTF-8 byte ceiling before either in-memory mutation or SQL. The PostgreSQL `UPDATE` predicate must include owner ID, world ID, attempt ID, state, lease generation, and worker ID and must require exactly one updated row.

The observable rule is:

```python
if attempt.owner_id != owner_id or attempt.world_id != world_id or attempt.state != AttemptState.RUNNING:
    raise ValueError("attempt lease is stale")
summary = bounded_text(summary, field="summary", maximum_bytes=65_536)
```

- [ ] **Step 6: Write a failing count-path test**

In `core/tests/test_test_world_api.py`, use a store double whose `list_attempts` raises and whose `count_attempts` returns a literal count. Call `GET /v1/test-worlds` through the real signed ASGI app and assert the response uses the literal count without calling `list_attempts`.

```python
def list_attempts(self, owner_id: str, world_id: str):
    raise AssertionError("listing worlds must not load attempt payloads")

def count_attempts(self, owner_id: str, world_id: str) -> int:
    return 7
```

- [ ] **Step 7: Run the count-path test to prove RED**

Run:

```bash
python3 -m unittest core.tests.test_test_world_api -v
```

Expected: FAIL because the imported list route calls `list_attempts` or the store interface lacks `count_attempts`.

- [ ] **Step 8: Implement bounded attempt counts**

Add `count_attempts(owner_id, world_id)` to the store protocol and implementations. The in-memory implementation counts only attempts belonging to the exact owner/world. The PostgreSQL implementation issues `SELECT count(*)` scoped by both owner and world and returns a non-negative integer. Change list serialization to call `count_attempts` once per world and never load attempt feedback/patch payloads.

- [ ] **Step 9: Run Test World and deployment tests GREEN**

Run:

```bash
python3 -m unittest \
  core.tests.test_test_world \
  core.tests.test_test_world_api \
  core.tests.test_test_world_invariants \
  core.tests.test_test_world_main \
  core.tests.test_test_world_modes \
  core.tests.test_test_world_runner \
  core.tests.test_test_world_runtime \
  core.tests.test_test_world_scheduler \
  core.tests.test_test_world_schema \
  deploy.tests.test_operations_contract \
  deploy.tests.test_service_files -v
node --test tests/deployment-contract.test.mjs
```

Expected: all named suites pass and schema version 3 is required throughout install, readiness, integrity, service inventory, and rollback inventory.

- [ ] **Step 10: Commit**

```bash
git add .github core deploy docs scripts tests
git commit -m "feat: import and harden Tueiq test world"
```

### Task 2: Remove GALOR Hub from Tueiq end to end

**Files:**
- Delete: `core/lil_tweak/galor.py`
- Delete: `core/tests/test_galor.py`
- Create: `core/tests/test_direct_runner_detachment.py`
- Create: `tests/direct-runner-detachment.test.mjs`
- Modify: `core/lil_tweak/config.py`
- Modify: `core/lil_tweak/openai_agent.py`
- Modify: `core/lil_tweak/orchestrator.py`
- Modify: `core/lil_tweak/store.py`
- Modify: `core/main.py`
- Modify: `core/tests/test_config.py`
- Modify: `core/tests/test_main.py`
- Modify: `core/tests/test_orchestrator.py`
- Modify: `core/.env.example`
- Modify: `deploy/core.env.example`
- Modify: `deploy/verify_runtime.py`
- Modify: `deploy/quadlet/lil-tweak-core.container`
- Modify: `scripts/install-cloudflare-tunnel.sh`
- Modify: `scripts/install-digitalocean.sh`
- Modify: `scripts/lil-tweak-rollback.py`
- Modify: `scripts/lil-tweak-secret-snapshot.py`
- Modify: `scripts/verify-deployment.sh`
- Modify: `lib/engineering-connection.ts`
- Modify: `tests/engineering-connection.test.mjs`
- Modify: `app/engineering-client.ts`
- Modify: `app/workbench.tsx`
- Modify: `app/public-shell.tsx`
- Rename: `public/icons/lil-tueeq-galor-icon.jpg` -> `public/icons/lil-tueeq-icon.jpg`
- Modify: `tests/rendered-html.test.mjs`
- Modify: `README.md`
- Modify: `docs/operations/cloudflare-private-ingress.md`
- Modify: `docs/operations/digitalocean.md`
- Modify: `docs/operations/offline-dependencies.md`
- Modify: `deploy/tests/test_operations_contract.py`
- Modify: `deploy/tests/test_release_rollback.py`
- Modify: `deploy/tests/test_release_tooling.py`
- Modify: `deploy/tests/test_secret_snapshot.py`
- Modify: `tests/deployment-contract.test.mjs`

**Interfaces:**
- Consumes: Task 1's Test World/core-main/schema-v3 integration.
- Produces: a Core constructor and orchestration path with no Hub parameter; a direct runner status contract `{ owner, provider, dropletId, host, role, route, intermediary, imagePolicy, connection, qualification }`; and the container label `com.tueiq.lil-tweak.max-concurrent-jobs=1`.

- [ ] **Step 1: Recreate PR #28's detachment tests on the combined tree**

Use the authenticated GitHub connector to verify PR #28 head `43157bbe53b1ab2fa46c2e49a012bd0a3fefa5aa` and record its unified-diff SHA-256 as reference evidence. Write the required tests directly against the combined Task 1 tree rather than partially applying ambiguous hunks. Preserve schema-v3 and Test World expectations. Configuration rejects key presence rather than a truthy value:

```python
for value in ("", " ", "https://retired.invalid/v1"):
    environment = valid_environment()
    environment["LIL_TWEAK_GALOR_READONLY_URL"] = value
    with self.assertRaisesRegex(ValueError, "retired"):
        Config.from_env(environment)
```

The TypeScript status test must assert literal direct identity fields, absence of `galor`/`hub` keys in the serialized response, `connection: "not_reported"`, and `qualification: "not_reported"` before probing.

- [ ] **Step 2: Run detachment tests to prove RED**

Run:

```bash
python3 -m unittest core.tests.test_config core.tests.test_direct_runner_detachment core.tests.test_main core.tests.test_orchestrator -v
node --test tests/direct-runner-detachment.test.mjs tests/engineering-connection.test.mjs
```

Expected: FAIL because Hub configuration, adapter construction, orchestration, response fields, and UI/status provenance still exist.

- [ ] **Step 3: Remove Hub production plumbing**

Port the production hunks from PR #28 onto the combined branch. Delete the adapter and its test, remove the config field and every constructor/call argument, remove fetched context from agent prompts/store snapshots, and reject the retired environment variable by key presence before parsing ordinary Core values. Preserve Task 1's Test World construction and schema-v3 readiness query.

No compatibility shim, nullable `galor` field, no-op adapter, future-enable comment, or hidden fallback remains.

- [ ] **Step 4: Replace status and UI provenance with direct ownership**

Return only the exact runner metadata below before Task 4 adds live probing:

```typescript
runner: {
  owner: "tueiq",
  provider: "digitalocean",
  dropletId: "597343619",
  host: "galor-tweak-runner-01",
  role: "role-tweak-runner",
  route: "direct_core_to_local_podman",
  intermediary: "none",
  imagePolicy: "digest_pinned",
  connection: "not_reported",
  qualification: "not_reported",
}
```

Remove Hub/GALOR repository provenance from the API contract, browser parser, and workbench. Replace “GitHub + runner connection”/“secure gateway” copy with direct Tueiq Core/runner language. Do not display `ready`, `connected`, or `qualified` yet.

- [ ] **Step 5: Remove residual Hub attachment and legacy namespace**

Rename the concurrency label in both producer and verifier:

```text
com.tueiq.lil-tweak.max-concurrent-jobs=1
```

Remove every GALOR namespace and standalone Hub reference from release docs, code, tests, filenames, labels, and examples except (a) the immutable physical hostname `galor-tweak-runner-01` and (b) the exact retired-key denylist sentinel `LIL_TWEAK_GALOR_READONLY_URL` in `core/lil_tweak/config.py`, `core/tests/test_config.py`, and `core/tests/test_direct_runner_detachment.py` only. That sentinel must only reject key presence, including an empty/blank value; it is not configuration or a compatibility path. Rename the public avatar asset to `public/icons/lil-tueeq-icon.jpg`. Replace every old default hostname with the exact immutable hostname, including installer/rollback tests. Remove co-residency/future-enable guidance. The ordinary word `GitHub` and the required `.github` directory are not Hub references.

- [ ] **Step 6: Run detachment tests GREEN**

Run:

```bash
python3 -m unittest core.tests.test_config core.tests.test_direct_runner_detachment core.tests.test_main core.tests.test_orchestrator deploy.tests.test_operations_contract -v
node --test tests/direct-runner-detachment.test.mjs tests/engineering-connection.test.mjs tests/deployment-contract.test.mjs
git ls-files --cached --others --exclude-standard -z | python3 -c '
import os, pathlib, re, sys
paths = [pathlib.Path(os.fsdecode(p)) for p in sys.stdin.buffer.read().split(b"\0") if p]
paths = [p for p in paths if not p.as_posix().startswith("docs/superpowers/")]
name_bad = re.compile(r"(?i)galor|(?:^|[/_.-])hub(?:$|[/_.-])")
body_bad = re.compile(rb"(?i)galor|\bhub\b")
host = b"galor-tweak-runner-01"
retired = b"LIL_TWEAK_GALOR_READONLY_URL"
retired_paths = {
    "core/lil_tweak/config.py",
    "core/tests/test_config.py",
    "core/tests/test_direct_runner_detachment.py",
}
failures = []
for path in paths:
    path_text = path.as_posix().replace(host.decode(), "")
    if name_bad.search(path_text): failures.append(f"name:{path}")
    try: body = path.read_bytes().replace(host, b"")
    except (OSError, ValueError): failures.append(f"read:{path}"); continue
    if path.as_posix() in retired_paths: body = body.replace(retired, b"")
    if body_bad.search(body): failures.append(f"content:{path}")
print("\n".join(failures))
raise SystemExit(bool(failures))'
```

Expected: all tests pass. The scanner includes tracked and non-ignored untracked files, checks both path components and bytes, catches concatenated/camel-case/underscore GALOR identifiers while not mistaking `GitHub`/`.github` for standalone Hub, exits `0`, and prints nothing. It excludes only the planning workspace, removes the exact immutable hostname globally, and removes the denylist sentinel only in its three allowlisted enforcement/test files, so another prohibited token on the same line still fails.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor: detach Tueiq from GALOR Hub"
```

### Task 3: Bind every mutation to the exact DigitalOcean target

**Files:**
- Create: `scripts/lil-tweak-digitalocean-target.py`
- Create: `deploy/tests/test_digitalocean_target.py`
- Modify: `scripts/install-digitalocean.sh`
- Modify: `scripts/install-cloudflare-tunnel.sh`
- Modify: `scripts/install-lil-tweak-release.sh`
- Modify: `scripts/lil-tweak-rollback.py`
- Modify: `deploy/tests/test_install_transaction.py`
- Modify: `deploy/tests/test_release_rollback.py`
- Modify: `deploy/tests/test_release_tooling.py`
- Modify: `deploy/tests/test_operations_contract.py`
- Modify: `tests/deployment-contract.test.mjs`
- Modify: `README.md`
- Modify: `docs/operations/digitalocean.md`
- Modify: `docs/operations/cloudflare-private-ingress.md`

**Interfaces:**
- Consumes: Linux short hostname and DigitalOcean guest metadata `http://169.254.169.254/metadata/v1/id`; provider-side verification separately supplies active state, region, image, and size in Task 6.
- Produces: `read_metadata(opener, url) -> bytes`, `verify_target(hostname_getter, metadata_reader) -> TargetIdentity`, CLI `--check`, and live CLI success only for the exact immutable guest identity.

- [ ] **Step 1: Write exact-identity tests**

Create table-driven literal tests for the real verification function:

```python
GOOD_IDENTITY = {
    "provider": "DigitalOcean",
    "droplet_id": "597343619",
    "hostname": "galor-tweak-runner-01",
    "role": "role-tweak-runner",
}

def test_accepts_only_exact_hostname_and_metadata_id(self):
    identity = module.verify_target(
        hostname_getter=lambda: "galor-tweak-runner-01",
        metadata_reader=lambda: b"597343619\n",
    )
    self.assertEqual(identity.as_dict(), GOOD_IDENTITY)
```

Add rejection cases for a different hostname, different ID, blank ID, signed/negative/non-decimal/overlong ID, trailing extra data, invalid UTF-8, metadata exception, and hostname exception. Test `read_metadata` against a local `http.server` fixture: `/id` returns the exact ID, `/redirect` returns 302 to `/id`, and `/oversize` returns 33 bytes. Require the exact `/id` URL passed by the production call, a `2` second timeout, redirect rejection, and a single bounded `read(33)` that rejects more than 32 bytes. Add CLI tests proving `--check` performs no metadata call and returns `0`, while live failure returns one generic message without echoing received metadata.

- [ ] **Step 2: Run target tests to prove RED**

Run:

```bash
python3 -m unittest deploy.tests.test_digitalocean_target -v
```

Expected: FAIL because `scripts/lil-tweak-digitalocean-target.py` does not exist.

- [ ] **Step 3: Implement the target verifier**

Use only the Python standard library. Define immutable constants for provider `DigitalOcean`, Droplet `597343619`, hostname `galor-tweak-runner-01`, region `nyc1`, OS `Ubuntu 24.04 LTS x64`, size `s-4vcpu-8gb`, and role `role-tweak-runner`; a frozen `TargetIdentity`; strict byte parsing; a 2-second metadata timeout; a redirect-rejecting `HTTPRedirectHandler`; a maximum response of 32 bytes implemented by reading at most 33 bytes; and generic failure text. `--check` validates constants and parser fixtures without contacting metadata. Default invocation performs the live guest check and prints only:

```text
DigitalOcean target verified: droplet 597343619 / galor-tweak-runner-01
```

The metadata request target is exactly `http://169.254.169.254/metadata/v1/id`; no environment override may change expected ID, expected hostname, provider, role, URL, timeout, or response ceiling in production mode.

- [ ] **Step 4: Prove each installer checks identity before mutation**

Add execution tests that substitute a verifier returning failure and assert the Core installer, Tunnel installer, combined wrapper, and rollback mutation exit before creating users, directories, receipts, service files, or systemd/Podman calls. The tests must execute the scripts/helpers with controlled dependencies; do not assert source text alone.

- [ ] **Step 5: Wire the verifier into live mutation paths**

Add the verifier to each offline file inventory and call:

```bash
"${PYTHON}" -I -B "${TARGET_HELPER}" >/dev/null \
  || die 'DigitalOcean target verification failed'
```

after root/offline validation but before rollback lease creation or any mutation in both installers and their wrapper. In Python rollback entry points call the imported verifier before capture, restore, acknowledgement, mark-completed, or lease execution can mutate host state. Use the exact hostname as the non-overridable default; remove `LIL_TWEAK_EXPECTED_HOST` as a production bypass.

- [ ] **Step 6: Update operations contracts**

Update the runbooks and tests to name the exact target and require both hostname and metadata ID verification. Keep the legacy hostname explanation from the spec and do not reproduce IP addresses, VPC IDs, credentials, or mutable provider metadata.

- [ ] **Step 7: Run target and release tests GREEN**

Run:

```bash
python3 -m unittest \
  deploy.tests.test_digitalocean_target \
  deploy.tests.test_install_transaction \
  deploy.tests.test_release_rollback \
  deploy.tests.test_release_tooling \
  deploy.tests.test_operations_contract -v
node --test tests/deployment-contract.test.mjs
bash scripts/install-digitalocean.sh --check
bash scripts/install-cloudflare-tunnel.sh --check
bash scripts/install-lil-tweak-release.sh --check
```

Expected: all named tests/checks pass without contacting metadata during `--check`.

- [ ] **Step 8: Commit**

```bash
git add scripts deploy tests README.md docs/operations
git commit -m "feat: bind release to Tueiq DigitalOcean runner"
```

### Task 4: Make connection status an authenticated readiness proof

**Files:**
- Modify: `lib/engineering-connection.ts`
- Modify: `tests/engineering-connection.test.mjs`
- Modify: `app/api/engineering/status/route.ts`
- Modify: `app/engineering-client.ts`
- Modify: `app/workbench.tsx`
- Modify: `app/globals.css`
- Modify: `lib/engineering-api.ts`
- Modify: `core/lil_tweak/config.py`
- Modify: `core/tests/test_api.py`
- Modify: `core/tests/test_config.py`
- Modify: `core/.env.example`
- Modify: `deploy/core.env.example`
- Modify: `scripts/lil-tweak-secret-snapshot.py`
- Modify: `deploy/tests/test_secret_snapshot.py`
- Modify: `tests/direct-runner-detachment.test.mjs`
- Create: `tests/engineering-status-route.integration.test.mjs`
- Modify: `docs/operations/digitalocean.md`

**Interfaces:**
- Consumes: `ownerFor(request)` for login authorization; `ownerScope(owner)` for the existing 32-lower-hex D1/Core partition; `signCoreRequest`, `sha256Hex`, `validateCoreSigningConfig`, `validateCoreTransportConfig`, and `coreAccessHeaders` for transport.
- Produces: canonical Core owner scope `a0885bc0b2c079e996629061a723c74d`; `engineeringConnectionStatus(bindings, ownerScope, options)` whose options include injectable `now`, `nonceFactory`, `requestIdFactory`, `probe`, and `fetcher`; a bounded HMAC v2 `GET /readyz`; `runner.connection` as the only connection state; and a strict browser parser that accepts only the literal direct identity and a consistent status object. `runner.qualification` remains `not_reported`.

- [ ] **Step 1: Replace unsigned-health expectations with signed-ready expectations**

First add an executable Node regression test that imports and calls `ownerScope("beythetruth4ever@paradigmshiftingthepodcast.net")` and proves the result is exactly `a0885bc0b2c079e996629061a723c74d`; a source-text match is not evidence. Add a Python config and secret-snapshot test proving both runtime parsers accept that exact value and reject the login-email hash `ab43c7488fb38a90c7bb9c4bcc0e23e5`. Then write status tests with a fixed clock, nonce, request ID, the exact canonical scope, and literal signing secret. The successful fetcher must receive exactly `/readyz`, no redirects, Access headers as applicable, and all required HMAC v2 headers. Independently compute the expected canonical string and signature in the test using Node `createHmac`, not the production signer.

The bodyless readiness request binds an empty idempotency field in the canonical
HMAC v2 string and deliberately omits the HTTP `Idempotency-Key` header. Test
that the Core convention maps a missing header to the same empty field, and
that the real Core `/readyz` handler accepts that exact signed request while the
probe neither sends a blank header nor substitutes a generated value.

The accepted response is exactly:

```json
{
  "status": "ready",
  "checks": {
    "database": true,
    "runner": true,
    "git": true,
    "workspace": true,
    "evidence": true,
    "signing": true,
    "admission": true
  }
}
```

Add one subtest per failure: redirect, non-200, missing/wrong content type, oversized declared body, oversized streamed body, malformed UTF-8/JSON, extra top-level key, missing/extra check, non-boolean check, any false check, timeout/fetch exception, and malformed or noncanonical owner scope. The streamed-body test must prove the reader stops at 16 KiB plus one byte and cancels rather than buffering an unbounded response. An invalid owner performs zero fetches. Each post-configuration probe failure returns `runner.connection: "unreachable"` without leaking request headers or raw bodies.

Add browser-parser cases that feed the real `getEngineeringConnectionStatus`
path missing/extra keys, each wrong literal identity field, unsupported
connection/qualification strings, and inconsistent transport/connection
combinations. All must reject before rendering. The parser must not use a blind
TypeScript cast.

Finally, import and execute the actual `GET` route under a controlled
`cloudflare:workers` environment. Prove an authorized request calls
`ownerFor(request)`, derives the canonical scope through `ownerScope(owner)`,
and signs the probe for that scope; prove a missing/wrong authenticated identity
returns `401` and makes no Core fetch. Do not substitute regex inspection of the
route source.

- [ ] **Step 2: Run status tests to prove RED**

Run:

```bash
node --test \
  tests/engineering-connection.test.mjs \
  tests/direct-runner-detachment.test.mjs \
  tests/engineering-status-route.integration.test.mjs
python3 -m unittest core.tests.test_api core.tests.test_config deploy.tests.test_secret_snapshot -v
```

Expected: FAIL because Core is pinned to the wrong owner scope, the status
implementation probes unsigned `/healthz`, the actual route does not derive the
scope, the browser blindly casts ambiguous status, and the runtime parsers
disagree with the required owner partition.

- [ ] **Step 3: Implement the bounded signed readiness probe**

Build the empty-body v2 signature for `GET /readyz` with an empty canonical idempotency field and the authenticated owner, while omitting `Idempotency-Key` from the HTTP headers. Enforce a 5-second timeout, a streamed 16-KiB maximum response, fatal UTF-8 decoding, JSON content type, exact top-level keys, and exact seven readiness checks. Follow no redirects. Return only normalized state; never return the origin, request headers, signature, raw body, or caught error.

Map states as follows:

```typescript
const connection = !transport || !signing
  ? "pending_configuration"
  : options.probe !== true
    ? "configured_pending_probe"
    : ready
      ? "ready"
      : "unreachable";
```

Keep `qualification: "not_reported"` regardless of readiness. Remove
`bridge.state` entirely and update the UI/CSS to key only from
`runner.connection`; it must not preserve a second readiness value that can
contradict the runner. Keep bridge/transport diagnostics descriptive and make
their literal configuration fields consistent with the selected connection.

- [ ] **Step 4: Bind the route to its authenticated owner**

Change the route to authorize the login identity, then derive the established Core/D1 scope exactly as ordinary job routes do:

```typescript
const owner = ownerFor(request);
const scope = await ownerScope(owner);
return json({ status: await engineeringConnectionStatus(env, scope, { probe: true }) });
```

Change `CANONICAL_OWNER_SCOPE`, Core/deployment examples, and secret-snapshot fixtures to `a0885bc0b2c079e996629061a723c74d`. Update the browser parser and workbench labels so `ready` means “Tueiq Core ready” and no state says `qualified`.

Implement a runtime `parseEngineeringConnectionStatus(value)` boundary in the
browser client. Require exact object keys; the literal owner/provider/Droplet/
host/role/route/intermediary/image-policy identity; one of the four connection
states; qualification exactly `not_reported`; and a consistent diagnostic
tuple. `ready`, `unreachable`, and `configured_pending_probe` require configured
transport/signing with no missing required names, while
`pending_configuration` requires a missing transport or signing input. Reject
unknown identity or state values, contradictory diagnostics, and malformed
timestamps before the UI receives the object.

Pin the complete successful status shape (with no unlisted keys) to:

```json
{
  "generatedAt": "2026-09-04T16:30:00.000Z",
  "controlPlane": {
    "storage": "configured",
    "d1": "configured",
    "r2": "configured"
  },
  "bridge": {
    "origin": "core_origin",
    "transport": "configured",
    "signing": "configured",
    "access": "configured",
    "missing": []
  },
  "runner": {
    "owner": "tueiq",
    "provider": "digitalocean",
    "dropletId": "597343619",
    "host": "galor-tweak-runner-01",
    "role": "role-tweak-runner",
    "route": "direct_core_to_local_podman",
    "intermediary": "none",
    "imagePolicy": "digest_pinned",
    "connection": "ready",
    "qualification": "not_reported"
  }
}
```

The parser enforces this state/diagnostic matrix; `missing` is a unique ordered
subset of the documented binding names and is empty outside
`pending_configuration`:

| `runner.connection` | transport/signing | probe | parser invariant |
| --- | --- | --- | --- |
| `pending_configuration` | either missing | not sent | at least one matching required name is in `missing` |
| `configured_pending_probe` | both configured | not sent | `missing` is empty |
| `ready` | both configured | exact response accepted | `missing` is empty |
| `unreachable` | both configured | attempted and failed | `missing` is empty |

`bridge.origin` is `none` only when no origin is configured; otherwise it is
the literal selected transport kind. Its `access` value must agree with
environment/origin selection. `generatedAt` is canonical UTC ISO-8601 with
milliseconds, and `controlPlane.storage` is `configured` if and only if both
D1 and R2 are configured.

Update the DigitalOcean operations guide and both production Core parsers to
the same owner-scope literal. Add a regression proving the checked-in Core
example, `Config.from_env`, and `lil-tweak-secret-snapshot.py` agree; any parser
disagreement fails closed before installation or probing.

- [ ] **Step 5: Run focused status and route tests GREEN**

Run:

```bash
node --test tests/engineering-connection.test.mjs tests/direct-runner-detachment.test.mjs
node --test tests/engineering-status-route.integration.test.mjs
python3 -m unittest core.tests.test_api core.tests.test_config deploy.tests.test_secret_snapshot -v
npm run typecheck
```

Expected: all named tests and type checking pass; the executable route derives
the exact owner scope, the browser rejects ambiguous status, and serialized
status contains one connection truth, direct runner identity, and no secret or
retired-intermediary provenance.

- [ ] **Step 6: Commit**

```bash
git add lib app tests core/lil_tweak/config.py core/tests/test_api.py core/tests/test_config.py core/.env.example deploy/core.env.example scripts/lil-tweak-secret-snapshot.py deploy/tests/test_secret_snapshot.py docs/operations/digitalocean.md
git commit -m "feat: prove direct runner readiness with signed status"
```

### Task 5: Build an executable direct qualification harness

**Files:**
- Create: `scripts/lil-tweak-qualification.py`
- Create: `deploy/tests/test_qualification.py`
- Modify: `scripts/verify-deployment.sh`
- Modify: `deploy/tests/test_operations_contract.py`

**Interfaces:**
- Consumes: exact guest-target verifier, signed loopback Core API, existing deployment/runtime probes, ordinary engineering Git-source jobs, evidence download endpoints, `InMemoryTestWorldStore` lease fencing, workspace path validation, and side-effect approval policy.
- Produces: CLI `python3 scripts/lil-tweak-qualification.py --check`, live CLI `python3 scripts/lil-tweak-qualification.py run --core-env PATH --source-root PATH --provider-evidence PATH --evidence-dir PATH`, and offline CLI `python3 scripts/lil-tweak-qualification.py verify-local PATH`; canonical JSON receipt schema `tueiq-direct-runner-local-qualification-v1` written atomically with mode `0600` only after every local check passes. This receipt is an input to Task 6's activation finalizer, not final activation evidence.

- [ ] **Step 1: Write failing signer, protocol, and receipt tests**

Use a real local HTTP server and temporary directories. The server independently verifies literal HMAC v2 canonical requests and emulates only the documented Core responses. Tests must prove the harness:

```python
SOURCE_URL = "https://github.com/octocat/Hello-World.git"
SOURCE_COMMIT = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"
SOURCE_FILE = "README"
SOURCE_SHA256 = "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340"
PATCHED_SHA256 = "30a62e82bef5e3bad05d4444ad9cd850cf35407d58f53e06e415de83f50cec28"
BASELINE_TREE_SHA256 = "d23d6b2878e2ce3351e8e155c282d20290e4d6dfe49795669023aac75b574922"
PATCHED_TREE_SHA256 = "aeb26da02bb4201906f381e59e390dd42545e05651957743a2fa3d9db83e8429"
PATCH_SHA256 = "f1620f84800d8ca024720f16c01e68248a18d29801c036a62da54f7e8d522766"
PATCH_BYTES = 66
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
OWNER_SCOPE = "a0885bc0b2c079e996629061a723c74d"
```

- sends Job A as mode `architect` with the immutable Git source and exact instruction to inspect `README`, compute its SHA-256, report only findings, and make no edit;
- requires Job A terminal state `completed`, source digest/revision binding, bounded evidence, and independent `README` digest verification. The production orchestrator always emits a non-null evidence-bundle `proposalDigest` and a `changes.patch` descriptor, so the exact no-write semantics are: `approvalProposal` is null, `approvalConsumed` is false, `changes.patch` has zero bytes and `EMPTY_SHA256`, the proposal digest recomputes correctly, and baseline/final tree digests are both `BASELINE_TREE_SHA256`;
- sends Job B as mode `refactor` with the same source and exact instruction to change only `README` from `Hello World!\n` to `Hello Tueiq!\n` and run the literal content check;
- requires Job B state `awaiting_approval`, an unconsumed `export_patch -> owner_download` proposal, the exact 66-byte `changes.patch` with `PATCH_SHA256`, baseline/patched tree digests above, a clean second immutable-intake replay whose only changed path is `README`, exact patched bytes, and patched file digest above;
- rejects Job B through the normal decision endpoint and requires terminal state `rejected`; it never approves or exports;
- omits all secret values and raw response bodies from its receipt;
- writes no receipt on any failed/partial check and rejects an existing evidence path or output symlink. The parent directory must already be root-owned mode `0700`; the harness creates the final `--evidence-dir` itself with mode `0700` and refuses symlink, hard-link, pre-existing-path, ownership, or permission ambiguity.

For both jobs download and verify exactly `plan.md`, `changes.patch`,
`tests.log`, `manifest.json`, and `summary.md`. Cross-check response media type,
declared length, `X-Content-Sha256`, descriptor size, body digest, derived evidence
ID, canonical manifest bytes, exact artifact set/hashes, recomputed proposal
digest, source/proposal source bindings, approval state, command metadata, edit
journal, network policy, timeout, and truncation results. Do not copy R2 object
keys, raw bodies, prompts, stdout/stderr, internal paths, origins, signatures, or
credentials into the receipt.

Tests also provide canonical `tueiq-digitalocean-provider-evidence-v1` input captured from the authenticated read-only operation `mcp__codex_apps__digitalocean_droplet_get({"ID":597343619})`. Require exact allowlisted fields for observation time, ID, name, status, region slug, image distribution/slug/name, size slug/memory/vCPU/disk, and the required role tag, plus the SHA-256 of the exact raw connector response bytes. Reject evidence older than 30 minutes or more than 60 seconds in the future, unknown/extra fields, network fields, malformed digests, wrong provider values, insecure mode/ownership, symlinks, hard links, and input over 16 KiB.

Pin the normalized provider document to this exact shape and canonical JSON with
no trailing newline:

```json
{
  "schema": "tueiq-digitalocean-provider-evidence-v1",
  "observedAt": "YYYY-MM-DDTHH:MM:SSZ",
  "operation": "mcp__codex_apps__digitalocean_droplet_get",
  "rawResponseSha256": "64-lower-hex",
  "provider": "DigitalOcean",
  "droplet": {
    "id": "597343619",
    "name": "galor-tweak-runner-01",
    "status": "active",
    "region": "nyc1",
    "image": {
      "distribution": "Ubuntu",
      "slug": "ubuntu-24-04-x64",
      "name": "24.04 (LTS) x64"
    },
    "size": {
      "slug": "s-4vcpu-8gb",
      "memoryMiB": 8192,
      "vcpus": 4,
      "diskGiB": 160
    },
    "roleTag": "role-tweak-runner"
  }
}
```

The local receipt embeds the complete normalized provider-evidence object plus
the SHA-256 of its canonical no-newline JSON bytes. Add tampering tests proving
`verify-local` recomputes that embedded digest rather than trusting a copied
string. Also test missing/extra fields (including rejection of `CONNECTED`,
`QUALIFIED`, or `READY_TO_WORK`), malformed identity, wrong Job A empty-patch
semantics, Job A/Job B source mismatch, missing lineage, duplicate/omitted
negative checks, wrong digest, non-canonical JSON, mode other than `0600`, hard
links, symlinks, files over 64 KiB, receipt duration over 20 minutes, and a
receipt older than 15 minutes at verification.

The exact raw connector response may contain forbidden network fields and is
not persisted in the evidence package. Consequently, `verify-local` and the
candidate builder recompute the normalized provider-document binding, not the
raw response itself. Before the raw bytes are discarded, the independent
reviewer must execute Task 6's `witness-provider` command against those exact
bytes and the sealed normalized document. The later independent review and
post-review verifier require that witness and recompute its retained bindings;
no verifier may overstate the raw-response hash as cryptographically derivable
from the normalized fields.

- [ ] **Step 2: Write failing adversarial-boundary tests**

Drive the real production boundary functions, not string searches, and require these exact receipt keys:

```python
NEGATIVE_KEYS = (
    "stale_lease",
    "wrong_runner_identity",
    "wrong_source_revision",
    "expired_authorization",
    "forbidden_action",
    "path_escape",
    "production_deployment_request",
    "replay",
    "mismatched_evidence_digest",
)
```

The test server must host the actual `LilTweakApi` production handler (with injected in-memory stores/runtime and a real socket), not emulate response codes. Require `401 authentication_failed` for an HMAC request older than 300 seconds and `409 request_replayed` for a reused nonce. Run the real guest target verifier with a mismatched metadata ID for `wrong_runner_identity`; real Test World lease functions with a stale generation for `stale_lease`; immutable Git intake against the qualification repository with a one-nibble-wrong commit for `wrong_source_revision`; and real portable-path/workspace validation with `../escape` for `path_escape`.

For `expired_authorization`, create a separate sacrificial awaiting-approval job
through the production orchestrator, advance the injected Core clock past its
exact `expiresAt`, submit its otherwise exact signed approval to
`/v1/jobs/{id}/decisions`, and require `409 invalid_approval` with unchanged
state, revision, evidence, and sandbox/container count. In the live run, wait
past that sacrificial proposal's real five-minute expiry, prove the same
rejection, then cancel the sacrificial job through the normal signed cancel
endpoint and require terminal cleanup. Job B remains unexpired and is rejected
normally after its independent replay. For `forbidden_action`, submit a signed
decision whose `decision` is outside `approve|reject` and require `400
invalid_request` with the same absence proof. For
`production_deployment_request`, submit a signed approval using the real Job B
identity but a proposal mutated to action `deploy` and target `production`;
require production Core rejection (`400 invalid_request` or the narrower `400
unsupported_action`) and prove state, revision, evidence, export availability,
runtime invocation count, and container inventory are unchanged. For
`mismatched_evidence_digest`, drive the real evidence verifier with a
deliberately wrong expected SHA-256. Nonce consumption is the only permitted
mutation for an authenticated rejected request.

The installed-Core HTTP cases are expired authorization, forbidden action,
production/deployment request, replay, the auxiliary stale timestamp, the live
wrong-revision job, and final cleanup/cancellation. Stale lease, exact guest
identity, portable path escape, immutable intake, and evidence-digest mismatch
also invoke their real local production functions on the exact installed source;
do not mutate live host identity or weaken those boundaries merely to force
every negative through HTTP.

- [ ] **Step 3: Run the qualification tests to prove RED**

Run:

```bash
python3 -m unittest deploy.tests.test_qualification -v
```

Expected: FAIL because the executable harness does not exist.

- [ ] **Step 4: Implement the bounded qualification client**

Use only the Python standard library plus existing repository modules. Layer secure-file validation around the exact environment syntax and HMAC v2 field order used by `deploy/verify_ready.py`; never log the loaded environment or headers. The Core environment must be a stable regular file owned by the verified `lil-tweak` UID/GID, mode `0600`, link count one, within its byte limit, and parsed from a pinned descriptor. Send requests only to fixed loopback origin `http://127.0.0.1:8017`; expose no origin, target, repository, owner, or timeout override. Reject redirects, require JSON media type, cap ordinary responses at 256 KiB and evidence at the repository evidence ceiling, and poll with a monotonic 20-minute deadline.

The live command must run in this order:

1. validate fresh canonical provider evidence and its raw-response digest;
2. exact DigitalOcean guest verification;
3. `LIL_TWEAK_VERIFY_R2=1 bash scripts/verify-deployment.sh` from `--source-root`;
4. immutable qualification source fetch/verification at the exact URL/commit/file/digest above;
5. signed `/readyz`;
6. Job A submit/poll/evidence/independent verification;
7. create the separate sacrificial approval job, wait past its exact expiry,
   prove expired-authorization rejection, cancel it normally, and prove cleanup;
8. only after the expiry wait is over, submit Job B, poll/evidence-check it, and
   perform the clean replay while its own proposal remains unexpired;
9. run the remaining eight named adversarial checks against the installed Core
   and exact production functions specified in Step 2, then reject Job B
   normally without approval or export;
10. container-absence and signed-readiness recheck;
11. atomic canonical local-receipt publication.

IDs, nonces, request IDs, timestamps, image/source/evidence digests, normalized states, and exit statuses may enter the receipt. Prompts, raw stdout/stderr, response bodies, environment paths, origins, IP addresses, usernames, and all secrets may not.

Use `finally` cleanup to reject any harness-created job that unexpectedly
reaches `awaiting_approval`, including on partial failure, and query the service
user's rootless Podman store for pre/post container absence. A failed run
publishes no `local-qualification.json` and prints no final activation truth.

- [ ] **Step 5: Make receipt truth fail closed**

The exact top-level local receipt fields are:

```text
schema, startedAt, completedAt, sourceHead, providerEvidence, identity, topology, images,
deployment, readiness, jobA, jobB, negativeChecks, cleanup
```

Require schema `tueiq-direct-runner-local-qualification-v1`.
`providerEvidence` has exactly `{ document, sha256 }`, where `document` is the
complete normalized provider object above and `sha256` is recomputed from its
canonical bytes; derive receipt identity/provider/region/OS/size/role fields
from that validated document rather than hard-coded receipt literals. Require
exact owner/scope values from the spec; topology route
`direct_core_to_local_podman`, intermediary `none`, and policy
`ENGINEERING_EXECUTION_ONLY`; strict image digests; one source head; Job A's
exact empty-patch semantics; Job B lineage equal to Job A source/revision plus
its own job ID; final Job B rejection and no export; all nine negative booleans
true; cleanup true; and every gate timestamp within the same invocation.

The local schema contains no final uppercase activation booleans.
`verify-local PATH` revalidates secure file mode/owner/link count, canonical
bytes, exact fields, freshness, the recomputed canonical digest of the embedded
provider document, identity derivation, image/source/evidence digests, lineage,
Job A/B semantics, every negative check, and cleanup without running jobs or
contacting provider, metadata, Core, Podman, Git, R2, or the Site. Success may
print a local-receipt digest, but never `CONNECTED`, `QUALIFIED`, or
`READY_TO_WORK`.

- [ ] **Step 6: Wire the harness into deployment verification inventory**

`scripts/verify-deployment.sh --check` must require and run `lil-tweak-qualification.py --check` without starting a live qualification. The operations-contract test executes this offline path and proves it does not contact Core, GitHub, metadata, Podman, or R2.

- [ ] **Step 7: Run qualification and operations tests GREEN**

Run:

```bash
python3 -m unittest deploy.tests.test_qualification deploy.tests.test_operations_contract -v
bash scripts/verify-deployment.sh --check
```

Expected: all tests/checks pass with pristine output; the HTTP-server test independently verifies signatures, bodies, states, replay behavior, evidence bounds, rejection, and receipt content.

- [ ] **Step 8: Commit**

```bash
git add scripts/lil-tweak-qualification.py scripts/verify-deployment.sh deploy/tests
git commit -m "feat: add direct runner qualification harness"
```

### Task 6: Verify and package the exact activation release

**Files:**
- Create: `scripts/lil-tweak-activation-finalizer.py`
- Create: `scripts/lil-tweak-independent-review.py`
- Create: `scripts/lil-tweak-live-evidence.py`
- Create: `lib/engineering-activation-collector.ts`
- Create: `app/api/engineering/jobs/[id]/activation-evidence/route.ts`
- Create: `deploy/tests/test_activation_finalizer.py`
- Create: `deploy/tests/test_activation_review.py`
- Create: `deploy/tests/test_live_evidence.py`
- Create: `tests/engineering-activation-collector.test.mjs`
- Create: `tests/engineering-activation-evidence-route.integration.test.mjs`
- Modify: `scripts/lil-tweak-release.py`
- Modify: `scripts/verify-deployment.sh`
- Modify: `deploy/tests/test_release_tooling.py`
- Modify: `deploy/tests/test_operations_contract.py`
- Modify: `tests/deployment-contract.test.mjs`
- Modify only when a failing test requires it: other files already named in Tasks 1-5
- Create: `docs/operations/tueiq-runner-activation.md`

**Interfaces:**
- Consumes: Tasks 1-5; the exact source checkout; executable owner-only Site response collection; and explicit local-qualification, provider, provider-witness, release-primary, runtime, rollback, production, Site-primary, D1 cross-check, Core cross-check, guest cross-check, owner-flow decision/job, and session change-record artifacts.
- Produces: an in-page `collectTueiqActivationEvidence(...)` that never reads cookies; an owner-only D1 activation-evidence route; secure primary-evidence sealing; CLI `python3 scripts/lil-tweak-activation-finalizer.py --check`; a no-truth `build-candidate` command; separate independent provider-witness/review commands; a post-review `finalize-reviewed` command that alone may create canonical root-owned mode-`0600` `tueiq-direct-runner-activation-v1`; `verify-final`, which alone may print final truth after reopening the candidate, review, and original evidence; one exact reviewed source head; and a secret-free live runbook.

- [ ] **Step 1: Write failing activation-finalizer and release-order tests**

Build a complete valid fixture from canonical artifacts and call the real
finalizer. The CLI must require explicit paths, not caller-supplied identity or
digest literals:

```bash
python3 scripts/lil-tweak-activation-finalizer.py build-candidate \
  --source-root PATH \
  --local-qualification PATH \
  --preflight-provider-evidence PATH \
  --provider-evidence PATH \
  --release-evidence-root DIR \
  --runtime-manifest PATH \
  --rollback-receipt DIR \
  --production-manifest PATH \
  --owner-flow-receipt PATH \
  --owner-flow-job PATH \
  --site-status-evidence PATH \
  --guest-evidence PATH \
  --site-primary-evidence DIR \
  --d1-cross-check PATH \
  --core-cross-check PATH \
  --guest-cross-check PATH \
  --change-record PATH \
  --candidate PATH
```

Require schema `tueiq-direct-runner-activation-candidate-v1`. Test one failure at a time
for every missing/extra field; noncanonical JSON; oversized file; wrong owner,
mode, or link count; symlink; unstable file; stale/out-of-order time; changed
source head/tree; copied rather than recomputed digest; provider/local/guest
identity mismatch; runtime/local/production image mismatch; incomplete or dirty
rollback; Site source/version/deployment/access/status mismatch; unsigned or
non-ready Site status; missing owner flow; owner-job edit/nonzero patch;
D1/Core ID, revision, source, state, or evidence disagreement; decision/export
use; leftover runner container; preflight collision; unknown/pre-existing
resource recorded as session-created; rollback scope wider than session changes;
and any secret-bearing/forbidden field. Every failure must leave the candidate
path nonexistent and print no final truth.

The candidate receipt has exactly these top-level fields and no uppercase truth:

```text
schema, startedAt, completedAt, sourceHead, artifactDigests, identity, topology,
images, provider, guest, runtime, rollback, production, site, ownerFlow,
localQualification, changeRecord
```

Add executable tests for the full evidence chain:

- `collectTueiqActivationEvidence` runs in the authenticated Site page, uses
  same-origin `fetch(..., {credentials: "same-origin"})`, never reads
  `document.cookie`, and retains only exact allowlisted status/create/dispatch/
  poll/evidence response bodies plus status code, media type, declared length,
  and content SHA-256 where applicable. It serializes no request header and no
  cookie, authorization, Access, signing, `Set-Cookie`, origin, or other
  secret-bearing response metadata;
- the owner-only activation-evidence route exports the matching D1 job row,
  public/remote IDs, job revision, Core revision, source/evidence digests, and
  ordered event `{id,type,createdAt}` triples, but no prompt, object key, owner
  email, binding, environment, cookie, request header, origin, or secret;
- `lil-tweak-live-evidence.py` seals the collector output and independently
  collected D1/Core/guest observations into stable canonical root-owned files,
  mode `0600`, under a new root-owned mode-`0700` directory; and
- a fake browser/session, real route, independent Core socket, and independent
  D1/guest fixtures prove mismatched provenance is rejected. Tests fail if the
  collector accesses cookies, serializes any request header, or serializes any
  response metadata outside the exact non-secret allowlist.

The primary Site evidence directory has an exact manifest plus the original
allowlisted response bodies; a separately executed owner-only D1 export, signed
loopback Core read, and guest target/runtime check produce the three cross-check
inputs. They may share only correlation IDs/digests, never collector summaries.
The candidate builder must require all four sources and reject agreement among
self-authored summaries without matching primary bodies.

Pin the executable interfaces in the tests. The browser calls
`collectTueiqActivationEvidence({ requestId })`, where `requestId` must be a
fresh UUIDv4 and the immutable repository, commit, instruction, and expected
README digest are module constants rather than caller overrides. It returns one
bounded `tueiq-site-primary-capture-v1` value containing the status/create/
dispatch/final-poll JSON response bytes and the five evidence-preview body
bytes, with only the allowed response metadata above. Stream that value once to:

```bash
python3 scripts/lil-tweak-live-evidence.py seal-site \
  --collector-stdin --site-deployment-record PATH --output-dir DIR
```

`seal-site` writes `manifest.json`, `status.body`, `create.body`,
`dispatch.body`, `poll-final.body`, and five descriptor-ID-addressed evidence
bodies without rewriting their bytes; it also derives
`site-status-evidence.json` and `owner-flow-job.json` from those primary files.
A separate `seal-guest --provider-evidence PATH --runtime-manifest PATH
--verification-receipt PATH --output PATH` command derives the canonical guest
evidence from those primary receipts; `collect-guest` below is a fresh,
independent live observation and never consumes that derived guest file.
A separate owner-authenticated page evaluation, not the collector return value,
fetches `GET /api/engineering/jobs/{id}/activation-evidence` once and streams
that response to `seal-d1 --response-stdin --job-id ID --output PATH`. The guest
then runs `collect-core --core-env PATH --d1-cross-check PATH --output PATH` and
`collect-guest --source-root PATH --provider-evidence PATH --runtime-manifest
PATH --job-id ID --output PATH`. These commands have no origin, arbitrary host,
or secret-value option; `collect-core` is fixed to the signed loopback Core and
the secret file itself never enters an artifact. Each command uses exclusive,
descriptor-relative, root-owned mode-`0600` output under a root-owned mode-`0700`
parent and refuses existing paths, links, unstable inputs, extra fields, or
secret-bearing data.

The D1 route derives `ownerFor(request)` and then `ownerScope(owner)`, rejects
an invalid owner before any D1/R2/Core fetch, and returns only the public job ID,
remote Core job ID, owner scope, job-row revision, Core revision, immutable Git
source/digest, evidence IDs/descriptors, decision/export counts, and ordered
event `{id,type,createdAt}` triples. Tests call the real route with an owner
fixture and a forbidden-owner fixture and prove the latter performs zero
binding fetches.

Test the independent phase separately. Before either raw provider response is
discarded, an independent reviewer runs:

```bash
python3 scripts/lil-tweak-independent-review.py witness-provider \
  --normalized PATH --raw-response-stdin --witness PATH
```

The command reads the authenticated raw response only from a non-logging stdin,
recomputes its raw SHA-256 and allowlisted projection, compares the normalized
file, emits a sanitized canonical `tueiq-provider-response-witness-v1` with
exact fields `schema`, `witnessedAt`, `operation`, `rawResponseSha256`,
`normalizedSha256`, `projectionSha256`, and `reviewerNonce`, and never persists
or prints raw fields. Then `review-candidate` reopens the candidate, both
provider witnesses, all primary artifacts, and all independent cross-checks and
may publish only `tueiq-direct-runner-independent-review-v1` with exact fields
`schema`, `reviewedAt`, `reviewerNonce`, `candidateSha256`,
`providerWitnessDigests`, `primaryArtifactDigests`, `crossCheckDigests`, and
`decision: "pass"`. Neither artifact contains or prints a final uppercase
truth.

Make the phase boundary executable rather than implicit. `verify-candidate`
accepts the same original arguments as `build-candidate` plus `--candidate` and
prints only its canonical SHA-256. `review-candidate` accepts the candidate,
local qualification, exact source root, both normalized provider records and witnesses, release
evidence root, runtime manifest, rollback receipt, production manifest,
owner-flow decision/job, Site primary directory and derived status record, the
separately collected D1/Core/guest inputs, derived guest record, change record,
and a nonexistent `--review` output. It reopens each path itself; an input list
or hashes copied from the candidate is insufficient. It writes the review only
after every check passes and prints only the review SHA-256.

Finally test that `finalize-reviewed` rejects a missing/stale/mismatched review
and that only a valid candidate plus review can create
`tueiq-direct-runner-activation-v1`. Its exact top-level fields are:

```text
schema, completedAt, candidateSha256, independentReviewSha256,
CONNECTED, QUALIFIED, READY_TO_WORK
```

`finalize-reviewed` and `verify-final` both require `--candidate`,
`--independent-review`, both provider witness paths, and the complete explicit
original argument set accepted by `review-candidate`; `finalize-reviewed` adds
a nonexistent `--activation` path, while `verify-final` adds the existing final
receipt. No digest literal or caller-authored summary may replace a path.

Pin independent literal key sets for every candidate/review/final nested object and for the canonical
`tueiq-site-status-evidence-v1`, `tueiq-guest-evidence-v1`,
`tueiq-owner-flow-job-v1`, and session-change-record schemas in
`deploy/tests/test_activation_finalizer.py`. Production validation must use
independent allowlists and semantic checks, not accept arbitrary objects merely
because test and implementation share one schema constant.

Add a release-tooling regression for a new owner-flow decision receipt that is
created only after Site version/deployment IDs and the canonical
`tueiq-owner-flow-job-v1` digest exist. It must bind runtime/source/tree, Site
version/deployment/archive, and `owner_flow_job_sha256`; the production manifest
must bind that upgraded receipt and the same job digest. Prove the old receipt,
a receipt created before Site deployment, or a changed job digest is rejected.

Add operations/runbook contract tests for the exact live order and exact six
Site additions. Source-text presence alone is insufficient: tests execute the
collector, D1 route, sealer, `build-candidate`, provider witness,
`review-candidate`, `finalize-reviewed`, `verify-final`, and every `--check`.

- [ ] **Step 2: Run the finalizer tests to prove RED**

Run:

```bash
python3 -m unittest \
  deploy.tests.test_activation_finalizer \
  deploy.tests.test_activation_review \
  deploy.tests.test_live_evidence \
  deploy.tests.test_release_tooling \
  deploy.tests.test_operations_contract -v
node --test \
  tests/engineering-activation-collector.test.mjs \
  tests/engineering-activation-evidence-route.integration.test.mjs
```

Expected: FAIL because the collector, D1 evidence route, primary-evidence
sealer, candidate/review/final split, and owner-flow job binding do not exist.

- [ ] **Step 3: Implement the fail-closed activation finalizer**

Use the same descriptor-relative, no-follow, stable-file, canonical-JSON, size,
ownership, permission, and link-count rules as the existing release/evidence
tools. `--check` validates constants, schemas, parser fixtures, and file
inventory, then returns without reading live artifacts or contacting GitHub,
provider APIs, metadata, the Site, Core, Podman, R2, or the network.
Add the finalizer, independent-review helper, and live-evidence sealer to
`scripts/verify-deployment.sh`'s required-file inventory and have its offline
path run each helper's `--check` only; the operations test must execute that
wrapper path with contact traps armed.

For `build-candidate`, reopen every explicit original artifact and recompute all
canonical SHA-256 values. Validate at least:

1. the source root is clean, its exact 40-hex HEAD/tree matches every manifest,
   and the preserved Sites base is an ancestor;
2. both supplied provider documents are exact and root-owned mode `0600`; the
   preflight record predates mutation and matches the change record, while the
   fresh live record is byte/digest-equal to the normalized provider document
   embedded in the local receipt, and both identify the same immutable target;
3. guest evidence binds the exact metadata ID, hostname, Ubuntu release,
   architecture, source head, and direct local runtime to that provider record;
4. the secure `--release-evidence-root` has an exact descriptor-relative
   inventory containing the source manifest/archive, verification receipt,
   host-GO and base-image receipts, scan-hash receipt, and exactly four SBOM/
   scan artifacts; reopen and hash those primary files, reconcile them with the
   runtime manifest's exact source/archive inventory and five image roles, parse
   the scan JSON, and require recorded audited tool versions plus explicit
   vulnerability-policy `PASS` rather than accepting filename hashes alone;
5. the rollback directory was opened before mutation, is securely owned, binds
   the same source/runtime/images, and ends with
   `transaction_state=completed` plus `rollback_outcome=clean`;
6. the production manifest binds the same runtime, D1/R2/ingress resources,
   exact owner-only Site source/version/deployment/archive/access revisions, and
   the post-deployment owner-flow receipt/job digest;
7. exact allowlisted primary Site response bodies and their collector manifest
   prove the deployed owner-authenticated status route and owner job; the status
   records exact direct identity, `runner.connection = ready`,
   `runner.qualification = not_reported`, the same Site head/version/deployment,
   and no second connection state;
8. the independently collected D1 export, signed loopback Core read, and guest
   check match those primary responses and prove Site -> D1 -> signed Core ->
   local runner, exact owner scope, public/remote job linkage, job-row revision,
   Core revision, immutable source, identical D1/R2/Core evidence hashes,
   zero-byte empty patch, no approval, decision, or export, a recomputed
   non-null evidence-bundle proposal digest, equal baseline/final tree digests,
   successful network-disabled execution, and cleanup. The current event schema
   has no per-event revision; require unique event IDs and nondecreasing
   timestamps in the expected type order, correlated to the exported job row's
   job/Core revisions, rather than inventing event revision fields;
9. the session change record proves all six managed binding names and all new
   external resource names were absent before mutation, records the prior Site
   version/access state, lists only session-created IDs and exactly five added
   Site keys using `CORE_ORIGIN`, and limits rollback to those additions in
   reverse order; and
10. all timestamps, nonces, and artifact production order belong to one fresh
    activation session and every local negative/cleanup check remains true.

The candidate embeds only normalized non-secret facts and recomputed artifact
digests. It excludes prompts, stdout/stderr, cookies, request/response headers,
signatures, environment paths/secret values, private origins, IPs, usernames, and credentials;
the exact public Site origin is retained only in the deployment binding;
only the separately stored, explicitly allowlisted non-secret response bodies
may remain as primary evidence. After all validators return, publish the
candidate atomically with `O_CREAT|O_EXCL|O_NOFOLLOW`, fsync/rename/fsync, and
recheck root ownership, mode `0600`, regular-file identity, and link count one.
No `build-candidate` or `verify-candidate` path contains or prints uppercase
truth.

Implement `witness-provider` and `review-candidate` in the separate independent
review script. The reviewer must independently collect the D1/Core/guest
cross-check inputs rather than receive copies emitted by the Site collector,
reopen every primary input, recompute every retained hash, and validate the two
provider capture witnesses. A PASS review is atomic, canonical, root-owned mode
`0600`, fresh, and bound to the exact candidate digest; it contains and prints
no uppercase truth.

Only `finalize-reviewed` may construct the final canonical object with exact
booleans `CONNECTED = true`, `QUALIFIED = true`, and `READY_TO_WORK = true`, and
only after both candidate and independent-review validators return. It publishes
with the same atomic file rules. `verify-final` must accept the final receipt,
candidate, independent review, both provider witnesses, and the same explicit
original inputs; perform no live network/job action; reopen every retained
artifact; recompute every digest/cross-binding; and only then print the three
truth lines plus receipt SHA-256. It must not trust a self-contained assertion
or print truth before independent review.

- [ ] **Step 4: Write the secret-free live activation runbook**

Document exact ordered actions without embedding values: authenticated provider
identity capture plus independent in-memory raw-response witness; approved
console/SSH entry; source archive/tree verification; image build and semantic
scan receipts; pre-mutation Cloudflare/Sites inventory and rollback/change
record; new Tunnel/Access/service-token and HMAC-pair creation; secret directory
creation outside the repository and matching Core/cloudflared staging; combined
release installer; DNS route plus private Site binding/deployment; capture of
Site version/deployment identifiers; a second provider capture/witness; the
executable in-page signed-status/owner-job collector and exact primary response
artifacts; separately collected D1/Core/guest cross-checks; post-deployment
owner-flow receipt and production manifest; the Task 5 local qualification;
candidate construction/verification; independent candidate review; post-review
finalization; independent final verification; evidence redaction; rollback
decision; and final status wording. A production or owner-flow receipt that
needs Site IDs or owner-job evidence cannot be created before both exist.

Name every required Site key exactly: `LIL_TWEAK_ENVIRONMENT`, `PUBLIC_ORIGIN`,
`CORE_ORIGIN`, `CORE_ACCESS_CLIENT_ID`, `CORE_ACCESS_CLIENT_SECRET`,
`CORE_SIGNING_KEY_ID`, and `CORE_SIGNING_SECRET`;
preserve the existing owner-only direct-chat `OPENAI_API_KEY` without reading or
rewriting it. Require all six activation-managed names—including the unused
alternative `CUSTOMER_HTTP_LIL_TWEAK_CORE`—to be absent before resource
creation. This release adds exactly five values, selects `CORE_ORIGIN`, and keeps
`CUSTOMER_HTTP_LIL_TWEAK_CORE` absent. Existing `LIL_TWEAK_ENVIRONMENT`,
`PUBLIC_ORIGIN`, and `OPENAI_API_KEY` remain untouched. A collision stops
activation.

The browser trust boundary is private Sites custom access with exactly one
owner, zero groups, zero visitors, zero custom domains, dispatch-owned SIWC
identity headers, exact canonical `PUBLIC_ORIGIN`, the server owner allowlist,
and existing mutation same-origin checks. Live evidence must prove anonymous
denial, forged-identity denial, alternate-host rejection, and an owner
same-origin success without retaining an identity/header value, cookie, secret,
or raw response. Any failed boundary probe stops activation. Core ingress stays
separately protected by the Access service token and HMAC contract.

Resource observations use exactly
`tunnel,access_application,service_token,access_policy,secret_directory,dns` in
that creation order. Validate the two checked-in Access display names exactly,
DNS as a strict lowercase FQDN, the fixed secret-directory path exactly, and
Tunnel/service-token display names as bounded printable ASCII without control
characters or surrounding whitespace. Preflight and creation names are
byte-equal; returned IDs retain the opaque identifier grammar.

Installation uses only `scripts/install-lil-tweak-release.sh --install`; there
is no direct child-installer fallback. Bind source head/tree/archive, pinned
base/runtime images, SBOM/scan policy, host-GO, runtime, provider, guest,
rollback, Site version/deployment, owner job, production, and change-record
evidence. Secret values enter only approved secret stores/console, never command
history, output, examples, receipts, or source. Site rollback redeploys the
recorded prior Site version and removes only the five previously absent Site
binding keys plus external resources/files created in this session, in reverse
order; it never reads, copies, or restores a prior Site binding secret. This
restriction does not apply to protected host rollback: the existing
transactional rollback must still capture and, when invoked, restore the exact
pre-existing sensitive `core.env` and Tunnel bytes inside its root-only receipt,
without printing, exporting, or weakening their existing protection.

The runbook must state that a local receipt is insufficient and that
`CONNECTED = YES`, `QUALIFIED = YES`, and `READY_TO_WORK = YES` are forbidden
until the activation finalizer and independent replay accept every original
artifact from the same session and an independent-review `decision: "pass"`
artifact exists.
Candidate construction/verification and review must never print those lines.
In the operational document describe the old system only as the “retired
intermediary” so the Task 2 namespace scanner stays clean.

- [ ] **Step 5: Run focused finalizer and runbook tests GREEN**

Run:

```bash
python3 -m unittest \
  deploy.tests.test_activation_finalizer \
  deploy.tests.test_activation_review \
  deploy.tests.test_live_evidence \
  deploy.tests.test_release_tooling \
  deploy.tests.test_operations_contract -v
node --test \
  tests/engineering-activation-collector.test.mjs \
  tests/engineering-activation-evidence-route.integration.test.mjs
python3 scripts/lil-tweak-activation-finalizer.py --check
python3 scripts/lil-tweak-independent-review.py --check
python3 scripts/lil-tweak-live-evidence.py --check
bash scripts/verify-deployment.sh --check
git diff --check
```

Expected: all focused tests pass, offline checks make no external contact, and
the runbook order and final-truth boundary are executable contracts.

- [ ] **Step 6: Commit the finalizer and runbook before the full gate**

Start with an empty index diff. Mark each planned new file intent-to-add so it
appears in `git diff --name-only`, then print and save that exact inventory.
Also show `git status --short`, which must contain no unlisted untracked path.
A fresh reviewer must compare the saved inventory to the fixed Task 6 file list
and approve that exact newline-delimited content before staging. Stop on any
unreviewed path. After approval, stage every path literally—never a directory,
glob, generated path list, or `-A`—and require the cached inventory to match the
reviewed inventory byte-for-byte:

```bash
test -z "$(git diff --cached --name-only)"
git add -N -- \
  'app/api/engineering/jobs/[id]/activation-evidence/route.ts' \
  docs/operations/tueiq-runner-activation.md \
  lib/engineering-activation-collector.ts \
  scripts/lil-tweak-activation-finalizer.py \
  scripts/lil-tweak-independent-review.py \
  scripts/lil-tweak-live-evidence.py \
  deploy/tests/test_activation_finalizer.py \
  deploy/tests/test_activation_review.py \
  deploy/tests/test_live_evidence.py \
  tests/engineering-activation-collector.test.mjs \
  tests/engineering-activation-evidence-route.integration.test.mjs
reviewed_task6_inventory="$(mktemp)"
staged_task6_inventory="$(mktemp)"
git diff --name-only | tee "$reviewed_task6_inventory"
git status --short
# STOP here until a fresh reviewer approves exactly reviewed_task6_inventory.
git add -- \
  'app/api/engineering/jobs/[id]/activation-evidence/route.ts' \
  docs/operations/tueiq-runner-activation.md \
  lib/engineering-activation-collector.ts \
  scripts/lil-tweak-activation-finalizer.py \
  scripts/lil-tweak-independent-review.py \
  scripts/lil-tweak-live-evidence.py \
  scripts/lil-tweak-release.py \
  scripts/verify-deployment.sh \
  deploy/tests/test_activation_finalizer.py \
  deploy/tests/test_activation_review.py \
  deploy/tests/test_live_evidence.py \
  deploy/tests/test_operations_contract.py \
  deploy/tests/test_release_tooling.py \
  tests/deployment-contract.test.mjs \
  tests/engineering-activation-collector.test.mjs \
  tests/engineering-activation-evidence-route.integration.test.mjs
git diff --cached --name-only | tee "$staged_task6_inventory"
cmp -- "$reviewed_task6_inventory" "$staged_task6_inventory"
git diff --cached --check
git commit -m "feat: finalize Tueiq runner activation evidence"
```

If a regression legitimately changes another Task 1-5 path, stop, add that
exact literal to both explicit `git add` commands, regenerate the inventory, and
obtain a new review of the entire exact list before staging content. Never append
an unreviewed path after approval.
Expected: finalizer, tests, release binding, and runbook are all part of the
candidate activation head. Do not use an uncommitted runbook or code change as
release evidence.

- [ ] **Step 7: Record the exact head, then run the complete gate**

First require a clean worktree and record the candidate:

```bash
test -z "$(git status --porcelain)"
activation_head="$(git rev-parse --verify HEAD)"
test "${#activation_head}" -eq 40
git merge-base --is-ancestor e76996970e816c4cce7b8334e0495e1e0de48e7d "$activation_head"
git show --stat --oneline --decorate "$activation_head"
```

Then run, in this exact order, on that committed head:

```bash
npm run verify
python3 -m unittest discover -s deploy/tests -p 'test_*.py' -v
bash scripts/install-lil-tweak-release.sh --check
bash scripts/verify-deployment.sh --check
git diff --check
```

Expected: every command exits `0` without changing the worktree. Diagnose any
failure at its root, add a failing regression test, implement the smallest fix,
commit that fix, record the new head, and rerun this entire five-command gate.

- [ ] **Step 8: Run the retirement scanner and exact-head checks**

Run the Task 2 scanner verbatim against the same head:

```bash
test -n "${activation_head:?run Step 7 and keep its recorded head}"
git ls-files --cached --others --exclude-standard -z | python3 -c '
import os, pathlib, re, sys
paths = [pathlib.Path(os.fsdecode(p)) for p in sys.stdin.buffer.read().split(b"\0") if p]
paths = [p for p in paths if not p.as_posix().startswith("docs/superpowers/")]
name_bad = re.compile(r"(?i)galor|(?:^|[/_.-])hub(?:$|[/_.-])")
body_bad = re.compile(rb"(?i)galor|\bhub\b")
host = b"galor-tweak-runner-01"
retired = b"LIL_TWEAK_GALOR_READONLY_URL"
retired_paths = {
    "core/lil_tweak/config.py",
    "core/tests/test_config.py",
    "core/tests/test_direct_runner_detachment.py",
}
failures = []
for path in paths:
    path_text = path.as_posix().replace(host.decode(), "")
    if name_bad.search(path_text): failures.append(f"name:{path}")
    try: body = path.read_bytes().replace(host, b"")
    except (OSError, ValueError): failures.append(f"read:{path}"); continue
    if path.as_posix() in retired_paths: body = body.replace(retired, b"")
    if body_bad.search(body): failures.append(f"content:{path}")
print("\n".join(failures))
raise SystemExit(bool(failures))'
test -z "$(git status --porcelain)"
test "$(git rev-parse --verify HEAD)" = "$activation_head"
git merge-base --is-ancestor e76996970e816c4cce7b8334e0495e1e0de48e7d "$activation_head"
```

Expected: scanner exits `0` with no output and the exact committed head remains
clean and unchanged.

- [ ] **Step 9: Independently review that exact head**

Review the exact Task 1-6 diff and gate evidence. Any review fix or any other
new commit invalidates Steps 7-9: record the new head, rerun the complete
five-command gate and scanner, and repeat independent review. Only the final
accepted head may enter Task 7.

### Task 7: Deploy and prove the live runner

**Files:**
- External state: existing DigitalOcean Droplet `597343619`
- External state: Cloudflare Tunnel/Access/DNS and Sites environment bindings
- Evidence output: a new timestamped, secret-free local evidence directory outside Git

**Interfaces:**
- Consumes: exact independently accepted Task 6 head, digest-pinned images, approved secret inputs, DigitalOcean guest console/SSH, Cloudflare/Sites owner access, Task 5's local-qualification CLI, and Task 6's activation finalizer.
- Produces: fresh Gate 1-7 primary and cross-check evidence, a harmless canonical owner-flow job receipt, a no-truth activation candidate, an independent-review artifact, one independently replayed post-review activation receipt, and the only authorized final claims `CONNECTED = YES`, `QUALIFIED = YES`, `READY_TO_WORK = YES`.

- [ ] **Step 1: Capture authenticated provider evidence and verify authority**

The primary agent must invoke the authenticated read-only operation `mcp__codex_apps__digitalocean_droplet_get({"ID":597343619})`. Keep the exact UTF-8 JSON response bytes only in controlled process memory while writing `/run/lil-tweak-activation/provider-evidence-preflight.json` as a mode-`0600`, root-owned canonical `tueiq-digitalocean-provider-evidence-v1` file containing only: observation time; operation name; raw-response SHA-256; ID; name; status; region slug; image distribution, slug, and name; size slug, memory, vCPUs, and disk; and presence of tag `role-tweak-runner`. Reject unknown fields and omit all networks, addresses, gateways, VPC IDs, prices, and unrelated tags. Require status `active`, name `galor-tweak-runner-01`, region `nyc1`, image `Ubuntu` / `ubuntu-24-04-x64` / `24.04 (LTS) x64`, size `s-4vcpu-8gb` / 8192 MiB / 4 vCPU / 160 GiB, and the role tag.

Before those raw bytes are discarded, the independent reviewer must stream the
same in-memory bytes over non-logging stdin to `witness-provider` with the
normalized path and a new mode-`0600` witness path. Require the witness's raw
hash, allowlisted projection, and normalized-document hash to match, then
discard the raw bytes without writing, printing, or copying them. If the
reviewer is not present or the witness fails, stop; a later recollection cannot
witness this response retroactively. This first normalized record and witness
prove the pre-mutation target and are bound into the change record. Step 5
performs a distinct live capture/witness after installation; never overwrite
any record or witness.

```bash
python3 scripts/lil-tweak-independent-review.py witness-provider \
  --normalized /run/lil-tweak-activation/provider-evidence-preflight.json \
  --raw-response-stdin \
  --witness /run/lil-tweak-activation/provider-evidence-preflight.witness.json
```

Use the approved console/SSH path, run `scripts/lil-tweak-digitalocean-target.py`, verify `/etc/os-release` identifies Ubuntu 24.04 and `uname -m` is `x86_64`, compare the checked-out source to the Task 6 head, and verify no retired-intermediary process, unit, container, environment key, file, or network dependency is present. Stop on any mismatch. Retain only sanitized identity measurements in the secure session workspace; Step 5 combines them with post-install runtime proof before atomically publishing the canonical guest evidence. Do not record addresses, usernames, paths, raw output, or credentials.

- [ ] **Step 2: Preflight and create direct-control resources before host installation**

Inventory Cloudflare Tunnel/DNS/Access and Sites state before mutation. Create a canonical, root-owned, mode-`0600`, session-specific change record containing prior Site version/access policy, existing environment-key names, and every resource ID created in this session; never record secret values. Require the chosen Tueiq Core hostname, Tunnel name, Access application name, and service-token name to be absent. Also require all six activation-managed Site binding keys named in Task 6 to be absent. Any collision stops activation rather than adopting, replacing, or mutating existing state. Pin the record identity and append only canonical session-created entries through the controlled recorder; the finalizer rejects an incomplete, replaced, widened, or ambiguous record.

The complete resource order is Tunnel, Access application, service token, policy, fixed secret directory, then DNS. Create only the first five resources now; defer DNS routing until Step 4 after combined host installation. The policy consumes the already-created service-token ID. The two Access names must byte-equal their checked-in JSON names, DNS must be a strict lowercase FQDN, the secret directory must equal `/var/lib/lil-tweak-activation/secrets`, and Tunnel/service-token names must satisfy the bounded printable display-name grammar. Preflight and creation names remain byte-equal; returned IDs retain the opaque identifier validator. Create one new HMAC key ID/secret pair and stage the matching cloudflared credential/config and Core environment in their installer-required root-owned secret paths outside Git. Do not deploy the Site yet. On failure, remove only resources and files created in this session, in reverse order; never delete or overwrite pre-existing state.

- [ ] **Step 3: Build and install the exact release transaction**

Create fresh digest-pinned Core/PostgreSQL/runner images and the repository-required semantic scan, source, runtime, host-GO, and rollback receipts. Require the exact four SBOM/scan documents, audited tool versions, and explicit vulnerability-policy `PASS`. Do not create a production manifest or owner-flow receipt yet: their Site version/deployment and live owner-job inputs do not exist. With the Tunnel and matching secret inputs already staged, run only `scripts/install-lil-tweak-release.sh --install` for the combined Core+Tunnel transaction. Capture exit status and non-secret digests; do not split the transaction or run direct Podman fallbacks.

- [ ] **Step 4: Route direct ingress and deploy the exact private Site**

Point the new Tunnel only to `http://127.0.0.1:8017`, create its new DNS route, and set only five previously absent Site keys: `CORE_ORIGIN`, both Access keys, and both signing keys. Keep `CUSTOMER_HTTP_LIL_TWEAK_CORE` absent. Preserve `LIL_TWEAK_ENVIRONMENT`, `PUBLIC_ORIGIN`, and `OPENAI_API_KEY` unchanged. Save and deploy the exact activation head with private Sites custom access set to exactly one owner, zero groups, and zero visitors, and require zero custom domains. Prove exact production-origin equality plus anonymous denial, forged-identity denial, alternate-host rejection, and a successful owner same-origin flow; retain only sanitized booleans and stop on any failure. Then record the new Site version ID/number, deployment ID, archive digest, environment/access revisions, origin, access counts, custom-domain count, probe booleans, and prior version in the deployment record and its production-manifest binding; the change record retains its strict prior-state/resource/additions schema. These IDs and boundary observations must exist before any owner-flow decision receipt or production manifest is created. On failure, redeploy the recorded prior Site version; remove only the five previously absent Site bindings added in this session without reading or restoring any prior Site binding secret; and remove only the DNS route, secret directory, policy, token, application, and Tunnel created in this session, in reverse order. This Site rule does not change protected host rollback: the transactional installer must retain and restore any pre-existing sensitive `core.env` and Tunnel bytes through its root-only receipt. Do not create a custom-domain proxy, front Worker, Transform Rule, identity-header fallback, runner broker, Durable Object control plane, GitHub self-hosted runner, or retired-intermediary route.

- [ ] **Step 5: Prove signed connection and runtime lifecycle**

First repeat Step 1's authenticated provider capture into a new
`/run/lil-tweak-activation/provider-evidence-live.json` and, before discarding
the raw bytes, have the independent reviewer create
`provider-evidence-live.witness.json` with `witness-provider`. Require the two
new files to match the pre-mutation target and be no older than 30 minutes. Use
this exact live pair for every remaining provider binding; if either becomes
stale before post-review finalization, abandon without overwriting all dependent
guest/Site/local/owner-flow/production/candidate/review artifacts and repeat
Steps 5 onward in a new evidence session. Freshness must still hold when
`verify-final` completes.

```bash
python3 scripts/lil-tweak-independent-review.py witness-provider \
  --normalized /run/lil-tweak-activation/provider-evidence-live.json \
  --raw-response-stdin \
  --witness /run/lil-tweak-activation/provider-evidence-live.witness.json
```

From the guest run:

```bash
LIL_TWEAK_VERIFY_R2=1 bash scripts/verify-deployment.sh
python3 scripts/lil-tweak-live-evidence.py seal-guest \
  --provider-evidence /run/lil-tweak-activation/provider-evidence-live.json \
  --runtime-manifest /run/lil-tweak-activation/runtime-manifest.json \
  --verification-receipt /run/lil-tweak-activation/release-evidence/verification-receipt.json \
  --output /run/lil-tweak-activation/guest-evidence.json
```

Independently confirm loopback-only port 8017, local digest-pinned runner image,
one-job label, network-disabled runtime probe, cleanup, schema v3, and no
retired-intermediary reference in service environments. Retain only the
allowlisted provider pair and guest/runtime measurements under a newly created
root-owned mode-`0700` evidence session. Do not hand-author Site status, guest,
or owner-flow summaries: Step 6's executable producers derive them from primary
responses and separately collected observations. No file may contain an origin,
address, cookie, secret header, signature, environment value, username, or raw
command output.

- [ ] **Step 6: Prove the owner-authenticated Site-to-runner flow**

Run the tested `collectTueiqActivationEvidence({ requestId })` in an
owner-authenticated same-origin Site page. Generate `requestId` with
`crypto.randomUUID()` and reject it unless it is UUIDv4. The collector may let
the browser attach its existing session with `credentials: "same-origin"`, but
it must never read or return `document.cookie`, owner identity, origin, request
headers, Access/signing metadata, or any secret. Its fixed create body is:

```json
{
  "requestId": "<same UUIDv4 as Idempotency-Key>",
  "mode": "architect",
  "prompt": "Inspect README, run literal sha256sum README, report the known fixture digest, and make no edit or external action.",
  "projectId": null,
  "sources": [],
  "gitSource": {
    "repositoryUrl": "https://github.com/octocat/Hello-World.git",
    "commit": "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"
  }
}
```

Fetch and retain the exact allowlisted response artifacts in this order:
`GET /api/engineering/status`; `POST /api/engineering/jobs` with the UUID in
both fields; `POST /api/engineering/jobs/{id}` with exact body
`{"action":"dispatch","revision":<create job.revision>}`; repeated
`GET /api/engineering/jobs/{id}?fresh=1` until `completed`; and
`GET /api/engineering/evidence/{evidenceId}?preview=1` for exactly `plan.md`,
`changes.patch`, `tests.log`, `manifest.json`, and `summary.md`. Require create
`201 queued`, recompute the public job ID from owner scope and UUID, and stream
the bounded capture once to `lil-tweak-live-evidence.py seal-site`. The sealer
must preserve the primary body bytes and derive, rather than accept from the
operator, canonical `tueiq-site-status-evidence-v1` and
`tueiq-owner-flow-job-v1` records. Status must prove the exact target identity,
`runner.connection: "ready"`, `runner.qualification: "not_reported"`, and no
`bridge.state`.

```bash
python3 scripts/lil-tweak-live-evidence.py seal-site \
  --collector-stdin \
  --site-deployment-record /run/lil-tweak-activation/site-deployment.json \
  --output-dir /run/lil-tweak-activation/site-primary
```

Next perform three independent collections that do not consume the collector's
summaries: a separate authenticated page evaluation fetches only
`GET /api/engineering/jobs/{id}/activation-evidence` and streams it to
`seal-d1`; the guest runs `collect-core` against the signed loopback Core; and
the guest runs `collect-guest` against the target/runtime. The D1 export and
Core read must agree on public job, remote Core job, owner scope, immutable
source digest, completed state, job-row revision, and Core revision, and must
bind Core idempotency `job:<publicJobId>:dispatch`. Because the event schema has
no event revision, require unique event IDs and nondecreasing timestamps for
`job_created`, `dispatch_reserved`, `core_dispatched`, and
`core_status_mirrored` in that order, correlated to the exported job/Core
revisions; never synthesize a per-event revision.

```bash
python3 scripts/lil-tweak-live-evidence.py seal-d1 \
  --response-stdin --job-id "$owner_job_id" \
  --output /run/lil-tweak-activation/d1-cross-check.json
python3 scripts/lil-tweak-live-evidence.py collect-core \
  --core-env /var/lib/lil-tweak/.config/lil-tweak/core.env \
  --d1-cross-check /run/lil-tweak-activation/d1-cross-check.json \
  --output /run/lil-tweak-activation/core-cross-check.json
python3 scripts/lil-tweak-live-evidence.py collect-guest \
  --source-root "$PWD" \
  --provider-evidence /run/lil-tweak-activation/provider-evidence-live.json \
  --runtime-manifest /run/lil-tweak-activation/runtime-manifest.json \
  --job-id "$owner_job_id" \
  --output /run/lil-tweak-activation/guest-cross-check.json
```

Across primary files and independent cross-checks, require identical D1/R2/Core
evidence descriptors and hashes, a recomputed non-null evidence-bundle
`proposalDigest`, equal baseline/final tree digests, and a zero-byte
`changes.patch` with SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Require `approvalProposal: null`, `approvalConsumed: false`, no decision/export
call or audit record, command exit zero, the known README digest, network
disabled, admission restored, and no ephemeral runner container. All derived
records contain only allowlisted IDs, revisions, digests, states, and timestamps;
primary Site bodies are isolated in their exact manifest. A signed readiness
response or hand-authored normalized summary cannot substitute for this chain.

- [ ] **Step 7: Complete post-deployment release evidence and local qualification**

Now that the Site version/deployment identifiers and the primary-derived owner
job plus independent D1/Core/guest cross-checks exist, create the upgraded
owner-flow decision receipt binding the owner-job SHA-256; then create the
production manifest that binds the same owner job, owner-flow receipt,
runtime/source, and Site version/deployment. This order is mandatory. Finalize
the rollback receipt as `transaction_state=completed` and
`rollback_outcome=clean`, and seal the session change record. Do not edit any
sealed artifact afterward.

Use the Step 5 root-owned mode-`0700` evidence session. Create a separate
root-owned mode-`0700` qualification parent within the allowed qualification
root, pass a nonexistent child path so the Task 5 harness creates the local
evidence directory itself, then run the exact local CLI from the checked-out
Task 6 head:

```bash
qualification_root=/var/lib/lil-tweak-qualification
if [[ -e "$qualification_root" ]]; then
  [[ -d "$qualification_root" && ! -L "$qualification_root" ]]
  [[ "$(stat -c '%u:%g:%a' "$qualification_root")" == '0:0:700' ]]
else
  install -d -o root -g root -m 0700 "$qualification_root"
fi
evidence_parent="$(mktemp -d -p "$qualification_root" session.XXXXXXXX)"
chmod 0700 "$evidence_parent"
local_evidence_dir="$evidence_parent/local"
python3 scripts/lil-tweak-qualification.py run \
  --core-env /var/lib/lil-tweak/.config/lil-tweak/core.env \
  --source-root "$PWD" \
  --provider-evidence /run/lil-tweak-activation/provider-evidence-live.json \
  --evidence-dir "$local_evidence_dir"
env -i PATH=/usr/bin:/bin LC_ALL=C \
  python3 scripts/lil-tweak-qualification.py verify-local \
  "$local_evidence_dir/local-qualification.json"
```

Expected: Job A has the exact empty-patch semantics, Job B has the exact
disposable one-file patch and is rejected without export, all nine negative
checks pass, cleanup/readiness pass again, and `local-qualification.json` is
written. Its verifier recomputes the embedded provider binding but prints no
final activation truth. A nonzero exit, stale provider record, or missing local
receipt leaves every final claim false. The separate sacrificial job must reach
expiry rejection, normal cancellation, and cleanup before Job B is created;
Job B's replay and normal rejection must both finish while its own proposal is
unexpired.

- [ ] **Step 8: Build and verify the no-truth activation candidate**

Only after Step 7 seals every required artifact, define the complete explicit
input set and build phase one's candidate:

```bash
original_inputs=(
  --source-root "$PWD"
  --local-qualification "$local_evidence_dir/local-qualification.json"
  --preflight-provider-evidence /run/lil-tweak-activation/provider-evidence-preflight.json
  --provider-evidence /run/lil-tweak-activation/provider-evidence-live.json
  --release-evidence-root /run/lil-tweak-activation/release-evidence
  --runtime-manifest /run/lil-tweak-activation/runtime-manifest.json
  --rollback-receipt /run/lil-tweak-activation/rollback
  --production-manifest /run/lil-tweak-activation/production-manifest.json
  --owner-flow-receipt /run/lil-tweak-activation/owner-flow-receipt.txt
  --owner-flow-job /run/lil-tweak-activation/site-primary/owner-flow-job.json
  --site-status-evidence /run/lil-tweak-activation/site-primary/site-status-evidence.json
  --guest-evidence /run/lil-tweak-activation/guest-evidence.json
  --site-primary-evidence /run/lil-tweak-activation/site-primary
  --d1-cross-check /run/lil-tweak-activation/d1-cross-check.json
  --core-cross-check /run/lil-tweak-activation/core-cross-check.json
  --guest-cross-check /run/lil-tweak-activation/guest-cross-check.json
  --change-record /run/lil-tweak-activation/change-record.json
)
activation_candidate="$evidence_parent/activation-candidate.json"
python3 scripts/lil-tweak-activation-finalizer.py build-candidate \
  "${original_inputs[@]}" --candidate "$activation_candidate"
env -i PATH=/usr/bin:/bin LC_ALL=C \
  python3 scripts/lil-tweak-activation-finalizer.py verify-candidate \
  "${original_inputs[@]}" --candidate "$activation_candidate"
```

Both commands reopen and hash the original primary/cross-check inputs. They may
print only the candidate SHA-256; they must not create, contain, or print any
final uppercase truth. Failure leaves the candidate path absent.

- [ ] **Step 9: Create the independent-review artifact before final activation**

The independent reviewer who witnessed both raw provider captures must operate
the separate review helper with no signing/OpenAI/R2/database environment. It
reopens the candidate and every original retained input, verifies both provider
witnesses and the independently collected D1/Core/guest provenance, and does
not trust candidate-embedded hashes:

```bash
independent_review="$evidence_parent/independent-review.json"
env -i PATH=/usr/bin:/bin LC_ALL=C \
  python3 scripts/lil-tweak-independent-review.py review-candidate \
  "${original_inputs[@]}" \
  --candidate "$activation_candidate" \
  --preflight-provider-witness /run/lil-tweak-activation/provider-evidence-preflight.witness.json \
  --provider-witness /run/lil-tweak-activation/provider-evidence-live.witness.json \
  --review "$independent_review"
```

Expected: a canonical root-owned mode-`0600`
`tueiq-direct-runner-independent-review-v1` with lowercase `decision: "pass"`
and recomputed hashes. It contains and prints no final uppercase truth. The
reviewer also checks provider/guest identity, exact Task 6 head, image/scan
digests, clean rollback, Site IDs/access/status, owner-flow lineage and empty
patch, local Job A/B, all nine rejections, change scope, ordering, freshness,
and cleanup. Make any redaction only as a separate derivative; never rewrite a
bound canonical input. Missing, stale, or changed evidence invalidates the
candidate and requires a new evidence session.

- [ ] **Step 10: Finalize only the independently reviewed candidate**

Phase two may begin only after Step 9. Set a nonexistent output path and invoke
the post-review finalizer with the candidate, review, both provider witnesses,
and every original input:

```bash
activation_receipt="$evidence_parent/activation.json"
python3 scripts/lil-tweak-activation-finalizer.py finalize-reviewed \
  "${original_inputs[@]}" \
  --candidate "$activation_candidate" \
  --independent-review "$independent_review" \
  --preflight-provider-witness /run/lil-tweak-activation/provider-evidence-preflight.witness.json \
  --provider-witness /run/lil-tweak-activation/provider-evidence-live.witness.json \
  --activation "$activation_receipt"
```

Only this command may atomically create the root-owned mode-`0600`
`tueiq-direct-runner-activation-v1` and set its three uppercase booleans true,
after recomputing all digests and review bindings. It emits no truth lines.

- [ ] **Step 11: Independently verify and report final truth**

In a separate clean process, `verify-final` must reopen the final receipt,
candidate, independent review, provider witnesses, and every original input:

```bash
env -i PATH=/usr/bin:/bin LC_ALL=C \
  python3 scripts/lil-tweak-activation-finalizer.py verify-final \
  "${original_inputs[@]}" \
  --candidate "$activation_candidate" \
  --independent-review "$independent_review" \
  --preflight-provider-witness /run/lil-tweak-activation/provider-evidence-preflight.witness.json \
  --provider-witness /run/lil-tweak-activation/provider-evidence-live.witness.json \
  --activation "$activation_receipt"
sha256sum "$activation_receipt"
```

Only after that command exits `0`, prints the receipt SHA-256 and the three
truth lines, and the independent `sha256sum` matches may Step 11 report:

```text
CONNECTED = YES
QUALIFIED = YES
READY_TO_WORK = YES
```

If console/network access, Cloudflare resource authority, or a required secret
binding is unavailable, report that exact blocker and leave all three claims
false; do not substitute provider-active state, offline tests, signed readiness,
the candidate/review, or the local-qualification receipt.
