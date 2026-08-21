# Lil Tweak Live Workbench Architecture

The Workbench is an additive private owner plane above Creator 0.7.1.

Flow:

1. Accept a public task only through a server-configured opaque repository identity. The API does
   not accept a task source digest, host path, clone URL, or caller-constructed `TaskImport`.
2. Inspect the registered repository, capture dirty and untracked work, screen secrets, and create
   an immutable Git-free task copy with server-generated source bindings.
3. Reuse Creator compilation and routing.
4. Inspect the dedicated task workspace.
5. Ask the live Lil Tweak adapter for a typed plan with no tools.
6. Revalidate every tool through the server policy broker.
7. Bind a one-time approval to task, plan, source, repository, project, identity, attempt, runner
   grant, policy, network mode, and exact tool digests.
8. Reissue an expired approval only through the authenticated task-bound route; the replacement
   receives a new identity, nonce, digest, and expiry.
9. Snapshot recovery state only after runner and exact-approval preflight.
10. Refuse execution until a future independently qualified provider implements the transport.
11. Record redacted outputs, authenticated task/approval/run/submission rows, and HMAC-anchored
    hash-chained evidence.
12. Record emergency-stop engage/reset actions in a separate authenticated control audit. Reset
    requires fresh owner reauthentication, a disconnected runner, and terminal tasks.
13. Require test and verification evidence before VERIFIED and COMPLETED.
14. Generate and optionally lock the candidate submission.

Layers: Workbench UI; cookie/CSRF API; server repository registry; Creator control plane; model
adapter; controller; authenticated approval and store; policy broker; task workspace; command
transport; GCP guard; evidence and control audits; submission; recovery.

The model never receives operating-system authority. The browser never receives credentials or policy authority.

The current repository contains the model path and fail-closed command-transport abstraction, but
the production factory connects neither a live model nor a qualified runner by default. A model
credential cannot enable command execution, and a caller-supplied qualification digest or network
assertion cannot make the built-in dormant transport connected.
