# Security Boundaries

Frontend: presentation and user intent only. No key, cloud credential, owner email, approval authority, policy, or executable allowlist is stored in HTML or JavaScript.

API: authenticates the owner with an HttpOnly SameSite session, validates CSRF on mutations, rate limits, rejects duplicate JSON keys, and returns no-store security headers.

Model: receives bounded untrusted task data and a trusted inspection summary. It has no tools or handoffs. Its plan is a proposal only.

Policy broker: owns executable, network, filesystem, and GCP policy. It revalidates every step before execution.

Workspace: one canonical root per task. Absolute paths, traversal, symlinks, hardlinks, special files, unrelated repositories, and size-limit violations fail closed.

Runner: disconnected by default. A qualified transport requires pinned sandbox bindings and enforced network namespaces.

GCP: task project, keyless candidate impersonation identity, region, and zone are checked for every cloud command. Protected billing, IAM, organization, audit, project-deletion, credential, and wide-admin-exposure actions are denied.

Evidence and submission: proposed actions, executed actions, model claims, tests, and verification are distinguished. Locked submissions are immutable until an explicit owner reopen creates a hash-chained audit event.
