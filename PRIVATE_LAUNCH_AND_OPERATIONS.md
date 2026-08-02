# Lil Tweak Private Launch and Operations

## Evidence scope

| Item | Value |
|---|---|
| Repository | `islamismylifebey-web/lil-tweak` |
| Working branch | `codex/lil-tweak-live-workbench-build` |
| Draft pull request | [PR #6](https://github.com/islamismylifebey-web/lil-tweak/pull/6) |
| Audited remote baseline | `373400cb2b459dbf8a37dacceb0d3d1186eef949` |
| Working candidate commit | **PENDING** |
| Exact final tested tree | **MUTABLE CHECKPOINT ONLY** — candidate commit remains pending |
| Environment | Private Codex Linux workspace, Python 3.12, Chromium 149, literal IPv4 loopback bind; runner disconnected; GCP/public deployment disabled |
| Full-suite checkpoint | `.venv/bin/pytest -q`: **597 passed, 0 failed, 0 skipped**; one known Starlette/httpx deprecation warning |
| Browser checkpoint | Chromium 149: **30 PASS / 3 BLOCKED / 0 FAIL** |
| Browser artifact digests | Result `d0e150189eff95b10fb5e4fa68768020428bb4a1175c9c72aefc49295a87cb18`; screenshot `387e7ddce232bddbbb0f861dbcaa95b7f0797f5d16531d9d0a80243e3dd58542` |
| Live launch evidence | Invalid Host returned 400; cross-origin mutation returned 403; IPv6 connection was refused because no IPv6 listener was configured; all listeners were cleared after shutdown |
| Package build | Wheel and sdist passed after explicit `setuptools==82.0.1` / `wheel==0.47.0` build configuration |
| Immutable launch artifact/digest | **PENDING** |

This runbook describes a conservative private inspection launch. It deliberately keeps the live
model, repository execution, runner, publisher, owner-tree mutation, GCP, and public deployment
disabled. It is not a production-operations approval.

## Preconditions

1. Use only the exact candidate commit after it exists and after clean-checkout verification passes.
2. Keep the service on a literal loopback address (`127.0.0.1` or `::1`). Do not bind to
   `0.0.0.0`, `::`, a LAN address, a proxy, or a tunnel.
3. Supply a strong owner API key through a private environment file, operating-system secret
   service, or process supervisor. Do not put the key in source, command history, logs, screenshots,
   or this runbook.
4. Give the data, artifact, task-workspace, and runtime directories owner-only permissions. The
   runtime directory is reserved; its existence does not connect or qualify a runner.
5. Map only repositories the owner intends Lil Tweak to inspect. Use opaque repository IDs and
   POSIX relative paths beneath one absolute workspace root. Do not map a repository through a
   symlink or with an absolute/parent-traversal mapping value.

## Conservative environment

Create a private runtime tree, then place the following values in an owner-readable environment
file outside the repository. Replace every angle-bracket placeholder; never commit the file.

```dotenv
LILTWEAK_ENVIRONMENT=development
LILTWEAK_DB_PATH=/tmp/liltweak-private/data/liltweak.db
LILTWEAK_DEV_API_KEY=<owner-generated-high-entropy-secret>
LILTWEAK_OWNER_ID=owner:local
LILTWEAK_WORKSPACE_ROOT=<absolute-parent-of-mapped-repositories>
LILTWEAK_REPOSITORIES_JSON={"local:private-repository":"<relative-repository-directory>"}
LILTWEAK_ARTIFACT_ROOT=/tmp/liltweak-private/artifacts
LILTWEAK_EXECUTION_RUNTIME_ROOT=/tmp/liltweak-private/runtime
LILTWEAK_WORKBENCH_WORKSPACE_ROOT=/tmp/liltweak-private/workbench-tasks
LILTWEAK_SERVER_HOST=127.0.0.1
LILTWEAK_WORKBENCH_ENABLED=true
LILTWEAK_WORKBENCH_MODEL_ENABLED=false
LILTWEAK_WORKBENCH_MODEL=gpt-5.6-sol
LILTWEAK_WORKBENCH_REASONING_PROFILE=ordinary
LILTWEAK_WORKBENCH_REASONING_TIER=high
LILTWEAK_WORKBENCH_REASONING_MODE=standard
LILTWEAK_REPOSITORY_EXECUTION_ENABLED=false
LILTWEAK_LIVE_MODEL_ENABLED=false
PORT=8765
```

The `ordinary` profile requires the exact Sol/high/standard tuple shown. `OPENAI_API_KEY` is not
needed while both model flags are false. The default factory does not auto-connect either legacy
provider even if a key or legacy flag is present; still remove an inherited provider key from this
process to minimize credential exposure.

Prepare the private directories without storing secrets in them:

```bash
install -d -m 700 /tmp/liltweak-private/data
install -d -m 700 /tmp/liltweak-private/artifacts
install -d -m 700 /tmp/liltweak-private/runtime
install -d -m 700 /tmp/liltweak-private/workbench-tasks
install -d -m 700 /tmp/liltweak-private/uv-cache
```

## Start

From the repository root, load the private environment using the owner's normal secret mechanism
and run:

```bash
UV_CACHE_DIR=/tmp/liltweak-private/uv-cache uv run --no-sync --offline python main.py
```

Expected listener: `127.0.0.1:8765` only. Verify the actual listener before opening the UI:

```bash
ss -ltnp | rg '127\.0\.0\.1:8765'
```

Open `http://127.0.0.1:8765/workbench/` locally. Log in with the owner API key. The key exchange
creates a signed, HttpOnly, SameSite=Strict owner-session cookie. The UI uses the returned CSRF
token for state-changing requests.

## Acceptance checks

The mutable working-tree checkpoint completed these checks, but the eventual candidate commit must
repeat them before they become immutable launch evidence.

- A request with the configured loopback `Host` succeeds, while an unrecognized `Host` is
  rejected.
- A state-changing request with a cross-origin `Origin` is rejected. Same-origin browser requests
  include the session cookie and CSRF token.
- Repeated failed logins eventually return `429` with `Retry-After`.
- Logout revokes the current session for the life of the process.
- Security headers include the configured content security policy and anti-framing controls.
- The capability panel reports model, runner, external checkpoint, publisher, browser, and GCP as
  blocked or disabled with their exact reasons.
- No runner process starts, no repository mutation occurs, and the UI cannot reach apply, commit,
  rollback, remote push, merge, release, deployment, or `COMPLETED`.

Chromium 149 recorded 30 passes, three explicit blocks, and zero failures. The blocked cases were
live planning/approval without a complete qualification receipt, delivery/rollback without a
qualified runner and publisher, and real-time expiry with the minimum 300-second private TTL.
The result and screenshot digests are recorded in the evidence table. Separate negative probes
observed Host 400 and Origin 403, confirmed IPv6 refusal, and confirmed listener cleanup.

## Safe operating envelope

With the conservative environment above, the Workbench is suitable only for local inspection of
its interface, repository list, capability truth, and deterministic non-live paths. Its canonical
lifecycle and descriptor-pinned context integration are implemented and tested, but that does not
connect an external provider, runner, checkpoint, or publisher. Do not treat an enabled button or
a test implementation as production authority.

The Workbench controller stops at `VERIFIED` after local verification. Independent examiner,
external checkpoint, publisher, apply, commit, and completion gates are false. Owner approval in
the UI cannot bridge those missing capabilities.

Do not enable `LILTWEAK_WORKBENCH_MODEL_ENABLED` for the private launch represented by this
runbook. The first label-blind v2 Sol holdout passed live 15/15 in one call with zero retries, but
that is partial evidence rather than full provider qualification. Production Workbench provider
injection, live compaction, cache semantics/telemetry, timeout, active cancellation propagation,
refusal, and incomplete-response handling remain blocked. If model access is later separately
qualified and authorized, minimized task context is sent to OpenAI; repository-level egress policy
enforcement must also be proven before operational use.

Do not enable `LILTWEAK_REPOSITORY_EXECUTION_ENABLED`. The runner is disconnected and unqualified,
and production repository publishing is disabled. The pytest-only publisher must never be wired
into this process.

## Session and recovery cautions

Session revocation is currently held in process memory. A restart clears the revocation map; if the
same signing key is derived from the same owner API key, a previously issued unexpired signed cookie
may validate again. Rotate the owner API key before restarting after suspected compromise, and
clear site data in the browser. Durable revocation, rotation, and lockout have not been qualified.

The database and artifacts may contain private task metadata. Stop the process before copying them,
preserve owner-only permissions, and use an approved encrypted backup channel. No external
anti-rollback checkpoint is connected, so a local backup is not independent integrity proof.

## Shutdown

Stop the foreground process with `Ctrl-C`, then confirm the listener is gone:

```bash
ss -ltnp | rg '127\.0\.0\.1:8765'
```

A successful shutdown check has no matching output. Preserve or remove `/tmp/liltweak-private`
according to the owner's retention policy; it may contain private state. This runbook does not
authorize deletion.

## Explicitly unsupported operations

- public or LAN exposure;
- GCP or any other cloud deployment;
- live autonomous model operation;
- connected runner execution;
- owner-tree apply, local commit, or rollback;
- remote push, PR mutation, merge, release, or deployment.

All remain blocked until the exact evidence listed in
`MASTER_BUILDER_REMAINING_BLOCKERS.md` exists.

Current capability verdict: **ARCHITECTURE IMPLEMENTED AND TESTED — NOT OPERATIONAL**.
