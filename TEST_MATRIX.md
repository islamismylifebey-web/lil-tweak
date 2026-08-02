# Test Matrix

Unit: schemas, digests, state transitions, approval bindings, path guards, redaction, GCP flags and deny rules, submission word limits and rendering.

API: login, secure cookie, CSRF, expiration, rate limiting, duplicate keys, task lifecycle, approvals, runs, evidence export, locked submission, emergency stop, and Creator regression.

Integration: Creator compile/route reuse, model plan validation, policy broker, recovery snapshot, typed tool execution, evidence chain, testing gate, completion gate, cancellation, and rollback.

Security: traversal, symlink, hardlink, shell strings, interpreter evaluation, unapproved executable, output limit, timeout, cancel, emergency stop, cross-project, wrong identity, key creation, billing, deletion, Owner/Editor, audit weakening, raw tokens, false status, and prompt injection inertness.

Frontend and accessibility: mobile layout, keyboard order, visible focus, accessible labels, loading and errors, preserved task form, disabled explanations, no dead-end routes, and color contrast.

End-to-end: safe fake model and fake transport only. Live acceptance is separate and cannot prove cloud execution.

