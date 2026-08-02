# Threat Model

Protected assets include owner sessions, provider credentials, GCP identities, source code, approval authority, evidence integrity, recovery snapshots, and examiner controls.

Primary threats:

- Prompt injection attempts to grant authority.
- Reused, expired, stale, or modified approvals.
- Path traversal, symlink and hardlink escape.
- Shell and command injection.
- Cross-project or wrong-identity cloud operations.
- Secret leakage through output, logs, evidence, screenshots, or frontend assets.
- False connected, approved, tested, verified, or completed states.
- Concurrent duplicate task, approval, run, and submission operations.
- Process escape, orphaning, timeout bypass, output flooding, and network misuse.
- Submission or evidence mutation after locking.

Implemented controls include frozen schemas, canonical digests, exact one-time approval consumption,
dedicated workspaces, atomic conditional writes, executable allowlists, no shell strings, redaction,
GCP deny rules, HMAC-anchored evidence, server-only sessions, CSRF, rate limits, and immutable submissions.

Residual risk: no Workbench runner provider exists. Process isolation, output limits, timeout,
cancellation, process-tree termination, network policy, and GCP identity enforcement remain live
acceptance requirements for that future provider; a sandbox prefix alone is insufficient.
