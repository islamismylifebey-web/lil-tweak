# Runner V3 Core Handshake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a real, fail-closed Lil’ Tweak private-Core client for GALOR Runner V3’s authenticated handshake on the corrected dedicated runner identity, while leaving execution blocked until GALOR Hub’s independent runtime-supervisor gate is qualified.

**Architecture:** The private Core, never the Sites/browser layer, owns the GALOR service token and calls `POST /api/executor/handshake` with `Authorization: Bearer <token>` and `x-galor-service-id: lil-tweak`. The client validates the exact V3 contract/runner expectations and treats the Hub’s current `VERIFIED_SANDBOX_RUNTIME_NOT_CONNECTED` response as disconnected rather than falling back to local execution.

**Tech Stack:** Python 3.12 standard library, existing Lil’ Tweak Core configuration and unittest suite, existing TypeScript Sites status metadata.

**Spec:** `docs/superpowers/specs/2026-09-03-runner-v3-core-activation-design.md`

## Global Constraints

- Runner contract name: `galor-runner`.
- Runner contract version: `3.0.0`.
- Runner execution host: `galor-tweak-runner-01`.
- Runner contract SHA-256: `5c649d1c2c338bc4a01f8c20778867036a703b049f25476cfe5e246c84eadd4c`.
- Dedicated DigitalOcean Droplet ID: `597343619`.
- Service authentication stays server-only and must never be serialized into status, evidence, or errors returned to callers.
- `galor_v3` failures never silently fall back to `local_podman`.
- A successful generic health check is not a runner connection proof.
- The current GALOR Hub blocker `VERIFIED_SANDBOX_RUNTIME_NOT_CONNECTED` remains authoritative until the independent runtime-supervisor track is implemented and qualified.
- No merge, deploy, publish, production mutation, push, or custom-domain change is part of this plan.

---

### Task 1: Pin the Core Runner V3 configuration contract

**Files:**
- Modify: `core/lil_tweak/config.py`
- Modify: `core/tests/test_config.py`
- Modify: `core/.env.example`

**Interfaces:**
- Produces `Config.execution_backend: str` with values `local_podman` or `galor_v3`.
- Produces `Config.galor_runner_gateway_url: str | None`.
- Produces `Config.galor_lil_tweak_service_token: str | None`.
- Produces `Config.repository_commit: str | None` for exact activation-candidate binding.
- When `execution_backend == "galor_v3"`, configuration requires the gateway URL, service token, and exact 40-character Git commit.

- [ ] **Step 1: Write failing configuration tests**

Add tests that assert:

```python
environment = valid_environment()
environment.update({
    "LIL_TWEAK_EXECUTION_BACKEND": "galor_v3",
    "LIL_TWEAK_GALOR_RUNNER_GATEWAY_URL": "https://galor.example",
    "LIL_TWEAK_GALOR_SERVICE_TOKEN": "s" * 32,
    "LIL_TWEAK_REPOSITORY_COMMIT": "a" * 40,
})
config = Config.from_env(environment)
self.assertEqual(config.execution_backend, "galor_v3")
self.assertEqual(config.galor_runner_gateway_url, "https://galor.example")
self.assertEqual(config.repository_commit, "a" * 40)
self.assertNotIn(config.galor_lil_tweak_service_token, repr(config))
```

Also assert `galor_v3` rejects missing values, non-HTTPS/credentialed/query/fragment gateway URLs, service tokens shorter than 32 UTF-8 bytes, non-40-hex commits, and unknown backend names. Assert the default remains `local_podman` with no GALOR V3 secrets required.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `python3 -m unittest core.tests.test_config -v`

Expected: FAIL because the new fields/validation do not exist.

- [ ] **Step 3: Implement the minimal configuration contract**

Add the four fields to `Config`, validate the backend enum and V3-only requirements, and preserve existing read-only GALOR context configuration independently.

- [ ] **Step 4: Update the environment example**

Document disabled-by-default values without any real secret:

```text
LIL_TWEAK_EXECUTION_BACKEND=local_podman
LIL_TWEAK_GALOR_RUNNER_GATEWAY_URL=
LIL_TWEAK_GALOR_SERVICE_TOKEN=
LIL_TWEAK_REPOSITORY_COMMIT=
```

- [ ] **Step 5: Run the focused test and verify GREEN**

Run: `python3 -m unittest core.tests.test_config -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add core/lil_tweak/config.py core/tests/test_config.py core/.env.example
git commit -m "feat: pin Runner V3 Core configuration"
```

### Task 2: Add the authenticated GALOR Runner V3 handshake client

**Files:**
- Create: `core/lil_tweak/galor_runner_v3.py`
- Create: `core/tests/test_galor_runner_v3.py`

**Interfaces:**
- Produces public constants `GALOR_RUNNER_CONTRACT_NAME`, `GALOR_RUNNER_CONTRACT_VERSION`, `GALOR_RUNNER_EXECUTION_HOST`, `GALOR_RUNNER_CONTRACT_SHA256`, and `GALOR_RUNNER_DROPLET_ID`.
- Produces immutable `RunnerV3HandshakeResult` with `connected: bool`, `reason: str`, `runner_id: str | None`, `tenant_id: str | None`, `checked_at: str | None`, and `expires_at: str | None`.
- Produces `GalorRunnerV3Client.handshake() -> RunnerV3HandshakeResult`.

- [ ] **Step 1: Write failing client tests**

Cover:

```python
client = GalorRunnerV3Client(
    "https://galor.example",
    service_token="x" * 32,
    repository_commit="a" * 40,
    opener=fake_opener,
    nonce=lambda: "n" * 32,
)
result = client.handshake()
self.assertTrue(result.connected)
self.assertEqual(result.runner_id, "galor-tweak-runner-01")
```

The fake success response must be `galor-executor-health-handshake-v2`, echo the nonce, set `authenticated: true`, `serviceId: "lil-tweak"`, `hub: "islamismylifebey-web/galor-hub"`, `runnerId: "galor-tweak-runner-01"`, include a non-empty tenant, unexpired timestamps, healthy/configured/signing gateway flags, and heartbeat action `runner.reportIdentity`.

Also test rejection of redirects, oversized responses, malformed JSON, nonce mismatch, wrong service id, wrong runner, wrong heartbeat action, expired proof, missing gateway flags, and generic 503. A 503 body carrying `VERIFIED_SANDBOX_RUNTIME_NOT_CONNECTED` must return `connected=False` without exposing the service token.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `python3 -m unittest core.tests.test_galor_runner_v3 -v`

Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement the bounded client**

Use only standard-library HTTP primitives. Disable ambient proxies, reject redirects, cap timeout at two seconds, cap response bytes at 64 KiB, send:

```text
Authorization: Bearer <server-only-token>
x-galor-service-id: lil-tweak
Accept: application/json
Content-Type: application/json
```

POST exactly `{"nonce":"<nonce>"}` to `/api/executor/handshake`. Convert every transport/protocol failure into a non-secret disconnected result; do not raise raw HTTP bodies to callers.

- [ ] **Step 4: Run the focused test and verify GREEN**

Run: `python3 -m unittest core.tests.test_galor_runner_v3 -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/lil_tweak/galor_runner_v3.py core/tests/test_galor_runner_v3.py
git commit -m "feat: add authenticated Runner V3 handshake"
```

### Task 3: Wire handshake truth into Core readiness without enabling execution

**Files:**
- Modify: `core/main.py`
- Modify: `core/tests/test_main.py`

**Interfaces:**
- `build_app()` constructs `GalorRunnerV3Client` only when `execution_backend == "galor_v3"`.
- Core readiness adds `galor_runner_connected: bool` when V3 is selected.
- The existing local `PodmanSandbox` execution path is preserved only for `local_podman`.
- For this handshake slice, queued execution under `galor_v3` must fail closed before local `PodmanSandbox` construction with a stable internal code/message indicating V3 execution is not yet qualified.

- [ ] **Step 1: Write failing integration tests**

Add tests that prove `galor_v3` never constructs or executes the local Podman backend and that readiness remains false when handshake reports disconnected. Add a positive readiness test using an injected/faked connected handshake while still asserting execution is blocked as unqualified.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `python3 -m unittest core.tests.test_main -v`

Expected: FAIL on the new V3 backend/readiness assertions.

- [ ] **Step 3: Implement minimal wiring**

Construct the client from validated Config. In `readiness()`, call the bounded handshake only for V3 mode and expose only the boolean connection fact. In `execute_job`, reject `galor_v3` before any local sandbox setup with a non-secret fail-closed error. Do not implement normal V3 dispatch in this slice.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run: `python3 -m unittest core.tests.test_main -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/main.py core/tests/test_main.py
git commit -m "feat: gate Core execution on Runner V3 connection"
```

### Task 4: Correct current Sites status provenance

**Files:**
- Modify: `lib/engineering-connection.ts`
- Modify: `tests/engineering-connection.test.mjs`

**Interfaces:**
- Current status advertises contract version `3.0.0` and execution host `galor-tweak-runner-01`.
- It does not claim `CONNECTED` from the existing `/healthz` probe.
- Historical V1/V2 references remain untouched outside the current-status module.

- [ ] **Step 1: Change the regression expectations first**

Update tests to expect:

```text
status.galor.version === "3.0.0"
status.galor.executionHost === "galor-tweak-runner-01"
```

and explicitly assert the bridge health result does not imply runner qualification.

- [ ] **Step 2: Run the focused Node test and verify RED**

Run: `node --test tests/engineering-connection.test.mjs`

Expected: FAIL because current source still reports V1 and `galor-private-cloud-01`.

- [ ] **Step 3: Implement the provenance correction**

Replace only current-status constants with the corrected V3 identity and keep the integration state `awaiting_runtime_probe` or an equivalently non-connected value.

- [ ] **Step 4: Run the focused Node test and verify GREEN**

Run: `node --test tests/engineering-connection.test.mjs`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add lib/engineering-connection.ts tests/engineering-connection.test.mjs
git commit -m "fix: report dedicated Runner V3 identity"
```

### Task 5: Exact-head repository verification and draft activation PR

**Files:**
- Modify: `docs/superpowers/specs/2026-09-03-runner-v3-core-activation-design.md` only if verification uncovers a spec mismatch.
- Modify: `docs/superpowers/plans/2026-09-03-runner-v3-core-handshake.md` only if implementation must be corrected to match reality.

**Interfaces:**
- Produces a draft PR from `infra/runner-v3-core-activation` to `main`.
- The PR must explicitly state `CONNECTED = NO` and `QUALIFIED = NO` until live supervisor/host evidence exists.

- [ ] **Step 1: Run focused verification**

Run:

```bash
python3 -m unittest core.tests.test_config core.tests.test_galor_runner_v3 core.tests.test_main -v
node --test tests/engineering-connection.test.mjs
```

Expected: PASS.

- [ ] **Step 2: Run full repository verification**

Run: `npm run verify`

Expected: PASS. If the environment cannot execute POSIX-specific Core tests, do not claim full verification; rely on exact-head GitHub CI instead.

- [ ] **Step 3: Inspect diff for scope**

Confirm no deployment, production, domain, browser-authority, or secret-value changes are present.

- [ ] **Step 4: Open a draft PR**

The PR body must record:

- source main SHA `63522fa027836b47808eeff201b84ce49a9ae1b6`;
- corrected V3 runner identity and digest;
- authenticated service handshake path;
- no local fallback under V3;
- GALOR Hub supervisor blocker still active;
- `CONNECTED = NO`, `QUALIFIED = NO`;
- no merge until exact-head CI and live qualification gates pass.

- [ ] **Step 5: Verify exact-head CI**

Fetch GitHub Actions runs for the PR head SHA and require all applicable repository checks to pass before describing the repository slice as verified.
