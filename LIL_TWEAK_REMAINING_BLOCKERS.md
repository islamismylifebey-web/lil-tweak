# Lil Tweak Remaining Blockers

## Release classification

`PARTIALLY OPERATIONAL — BLOCKERS REMAIN`

The private Workbench and control plane are usable for repository inspection, immutable source
capture, authenticated database rows, evidence, exact approvals, expired-approval reissue,
audited emergency engage/reset, recovery controls, and offline evaluation. Public task creation is
limited to server-registered repositories; callers cannot supply source bindings or host paths.
The product is not yet a fully operational autonomous software-engineering agent on this host.

## Blocking prerequisites

### 1. Qualified command runner

No execution provider is connected. The host lacks the independent qualification
collector/destroyer, immutable pinned runtime root, delegated cgroup v2 controls, and working
namespace isolation. Bubblewrap cannot qualify under the available permissions. Python repair,
JavaScript repair, tests, builds, preview, cancellation, patch production, and rollback-after-real
execution therefore remain blocked.

The production Workbench must continue to report the runner as disconnected and execution
permission as false until a provider verifies a signed, task-bound connection authorization and
enforces those controls independently.

### 2. Live model provider

No OpenAI API key is configured and the Workbench model flag is off. The Agents SDK adapter and
server-bound repository planning context are implemented, but live source-grounded planning was
not called. Activation instructions are in `LOCAL_AGENT_MODEL_ACTIVATION.md`. Model activation is
independent of runner activation and cannot authorize execution.

### 3. Repository delivery actions

The task workspace can create a verified patch after a qualified execution, but applying that
patch to the owner repository and creating a local Git commit are not yet implemented as separate
purpose-bound repository actions. Push, merge, release, and deployment remain intentionally
absent.

### 4. External evidence anti-rollback

Task, approval, run, and submission rows are HMAC-authenticated and their redundant columns are
cross-checked. The SQLite evidence ledger is hash-chained and HMAC-anchored, append verifies the
prior chain inside the transaction, and emergency engage/reset has a separate signed control audit.
A separate monotonic external checkpoint is still required to detect restoration of an older,
internally valid database, evidence anchor, and control history.

### 5. Real browser acceptance

Static UI checks, route tests, CSRF tests, responsive CSS review, and JavaScript syntax checks pass.
No supported Chromium browser is installed in this workspace, so keyboard, focus, mobile touch,
and end-to-end browser behavior have not been proven with a real browser.

### 6. GCP and public deployment

Google Cloud is explicitly deferred. GCP access, credentials, network calls, and deployment were
not attempted. Public deployment is prohibited and absent.

## What must not be inferred

- Offline scripted planners do not prove live model reasoning.
- Control-plane tests do not prove process isolation.
- A passing repository materialization trial does not prove code repair.
- A disconnected runner must never be described as ready, qualified, or operational.
- The draft PR must not be merged until the remaining host and provider prerequisites are resolved
  and live capability trials pass.
