# Lil Tweak Live Workbench Architecture

The Workbench is an additive private owner plane above Creator 0.7.1.

Flow:

1. Import one immutable task, an optional server-registered repository identity, and source digest.
2. Reuse Creator compilation and routing.
3. Inspect the dedicated task workspace.
4. Ask the live Lil Tweak adapter for a typed plan with no tools.
5. Revalidate every tool through the server policy broker.
6. Bind a one-time approval to task, plan, source, project, identity, attempt, and exact tool digests.
7. Snapshot recovery state.
8. Execute approved tools through the bounded executor and qualified transport.
9. Record redacted outputs and hash-chained evidence.
10. Require test and verification evidence before VERIFIED and COMPLETED.
11. Generate and optionally lock the candidate submission.

Layers: Workbench UI; cookie/CSRF API; Creator control plane; model adapter; controller; approval and store; policy broker; task workspace; command transport; GCP guard; evidence; submission; recovery.

The model never receives operating-system authority. The browser never receives credentials or policy authority.
