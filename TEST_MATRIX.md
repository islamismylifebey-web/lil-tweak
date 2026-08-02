# Test Matrix

Unit: schemas, digests, state transitions, approval bindings and expiry, path guards, redaction, GCP
flags and deny rules, authenticated row/column consistency, control-audit integrity, submission word
limits, and rendering.

API: login, secure cookie, CSRF, expiration, rate limiting, duplicate keys, repository listing and
inspection, repository-bound task creation, rejection of generic caller-supplied task imports,
task lifecycle, approval reissue, runs, evidence export, locked submission, emergency stop and
reauthenticated reset, and Creator regression.

Integration: Creator compile/route reuse, model plan validation, policy broker, recovery snapshot,
server-owned repository capture/materialization, typed tool execution with fakes, authenticated
rows and evidence chain, control audit, testing gate, completion gate, controller cancellation,
expired-approval recovery, emergency reset, and rollback.

Security: traversal, symlink, hardlink, shell strings, interpreter evaluation, unapproved executable, output limit, timeout, cancel, emergency stop, cross-project, wrong identity, key creation, billing, deletion, Owner/Editor, audit weakening, raw tokens, false status, and prompt injection inertness.

Frontend and accessibility: static mobile layout, keyboard order, visible focus, accessible labels,
loading and errors, preserved repository-bound task form, disabled explanations, and route/control
bindings. Real-browser interaction remains a separate acceptance blocker.

End-to-end: safe fake model and fake transport only. The suite must pass while the production runner
and default model are disconnected. Server-bound localhost acceptance verifies only startup,
authentication, repository-route availability, and truthful disconnected health. No test in this
matrix proves process isolation, process-tree termination, network enforcement, candidate identity,
live model quality, GCP confinement, or cloud execution.
