# Security Boundaries

Frontend: presentation and user intent only. No key, cloud credential, owner email, approval authority, policy, or executable allowlist is stored in HTML or JavaScript.

API: authenticates the owner with an HttpOnly SameSite session, validates CSRF on mutations, rate limits, rejects duplicate JSON keys, and returns no-store security headers.

Model: receives bounded untrusted task data and a trusted, secret-screened repository inspection
bundle. It has no tools or handoffs, no provider retries, and one bounded turn. Its plan is a
proposal only.

Policy broker: owns executable, network, filesystem, and GCP policy. It revalidates every step before execution.

Workspace: one canonical root per task. Absolute paths, traversal, symlinks, hardlinks, special files, unrelated repositories, and size-limit violations fail closed.

Runner: disconnected with no implemented provider. The dormant transport descriptor cannot
self-authorize from a caller-supplied digest or Boolean. All file and command execution fails before
approval consumption or recovery snapshot creation while disconnected.

GCP: task project, keyless candidate impersonation identity, region, and zone are checked for every
permitted cloud command. Direct HTTP cloud access and `kubectl` remain denied. Protected billing,
IAM, organization, audit, project-deletion, credential, and wide-admin-exposure actions are denied.

Evidence and submission: proposed actions, executed actions, model claims, tests, and verification
are distinguished. Every append verifies the prior chain and authenticated HMAC anchor inside the
write transaction. A separate external monotonic checkpoint is still required for database
anti-rollback. Locked submissions are immutable until an explicit owner reopen creates an
authenticated audit event.
