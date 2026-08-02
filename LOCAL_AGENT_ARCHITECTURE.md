# Lil Tweak Local Agent Architecture

> Historical checkpoint — superseded by `MASTER_BUILDER_ARCHITECTURE.md`. The classification and
> environment facts below describe the earlier baseline only. Current controlling verdict:
> **ARCHITECTURE IMPLEMENTED AND TESTED — NOT OPERATIONAL**.

## Release status

`PARTIALLY OPERATIONAL — BLOCKERS REMAIN`

The private control plane, repository inspection, immutable task copies, exact plans, owner
approvals, evidence, recovery, Workbench UI, and disconnected provider paths are implemented.
This host cannot honestly provide the independently qualified process isolation required for code
execution, and no OpenAI provider credential is configured. Execution therefore remains fail
closed.

## Control flow

1. The owner authenticates to the Workbench with an HTTP-only, SameSite session cookie and a
   separate CSRF token.
2. The server resolves an opaque repository ID from `LILTWEAK_REPOSITORIES_JSON`; clients never
   submit or receive a host path.
3. `WorkbenchRepositoryRegistry` validates the Git repository, captures branch, commit, dirty and
   untracked state, screens credentials, and computes a source fingerprint.
4. The registry copies the exact worktree, excluding `.git`, into a private task workspace. It
   checks the source fingerprint before and after the copy and does not write to the owner tree.
5. Creator establishes the task/risk route. A one-turn Agents SDK planner may receive only the
   immutable task, Creator digests, bounded relative file facts, manifest clues, and screened
   source excerpts.
6. The returned structured plan is bound to the task and source. Plan phases must be monotonic:
   inspection, mutation, test, verification. Required command-based test and verification phases
   are mandatory.
7. The owner approval binds the task, purpose, repository, source, plan, exact tool digests,
   attempt, policy, runner grant, network mode, nonce, and expiry. The candidate cannot publish a
   pre-approved record.
8. Before execution, the controller rechecks the repository, source copy, emergency stop, runner
   connection, and approval. A disconnected runner stops before snapshot creation or approval
   consumption.
9. A future qualified runner must enforce the signed execution binding in an independently owned
   sandbox. No host-subprocess fallback exists.
10. Successful execution must produce separate test and verification evidence, verify declared
    artifacts, compute the final tree digest, and create a private patch before `COMPLETED` is
    reachable.

## Trust boundaries

| Boundary | Authority | Current state |
|---|---|---|
| Owner session and CSRF | Server | Operational |
| Repository ID to host path | Server configuration | Operational |
| Creator routing | Server | Operational offline |
| Model planning | OpenAI Agents SDK adapter | Disabled; no key configured |
| Tool policy | Server | Operational |
| Exact approval | Authenticated owner | Operational |
| Evidence chain and HMAC anchor | Server | Operational; external anti-rollback checkpoint absent |
| Command runner | Independent qualified provider | Disconnected |
| GCP | Deferred | Disabled |
| Public deployment | Prohibited | None |

## Provider invariants

- Model calls have one turn, no tools, no handoffs, no provider retries, a hard timeout, token and
  cost ceilings, disabled tracing, disabled storage, and secret screening of the full returned
  plan.
- Runner connection requires measured executables, an immutable runtime root, kernel isolation,
  cgroup delegation, an independent qualification decision, and a fresh signed owner
  authorization. A capability probe cannot create a transport.
- Direct GCP HTTP and Kubernetes clients are denied. GCP project IAM mutation, credential files,
  duplicate binding flags, and flags files are denied. GCP remains disabled in this release.
- The application has no push, merge, release, public deployment, or PR-merge control.
