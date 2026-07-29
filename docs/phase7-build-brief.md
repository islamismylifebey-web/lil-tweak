# Phase 7 Build Brief: Isolated Repository Verification

## Goal

Add the smallest repository execution plane that can preserve Lil Tweak's evidence and approval
invariants. Phase 7 verifies one exact committed source tree with server-owned offline commands.
It does not edit source, install dependencies, use models, contact Git hosting, deploy, or release
artifacts.

## Trusted inputs

- An authenticated Founder identity.
- An existing inspected job with organization, project, and opaque repository binding.
- A signed Creator brief and a route recomputed from that brief.
- One server-registered recipe and configured immutable image-reference label. Runtime-root
  provenance remains a future connection gate.
- One complete, clean, exact Git commit.

The caller cannot supply commands, executables, images, paths, resource limits, network rules,
approval authority, cost authority, or result evidence.

## Source contract

The snapshot builder reads only regular blobs from the exact committed Git tree. It rejects dirty
or ignored state, incomplete metadata, shallow or partial repositories, submodules, symlinks,
special files, unsafe paths, sensitive filenames, credential-shaped content, and configured size
limits. It creates a deterministic manifest and a read-only `.git`-free materialization. The
registered repository is never mounted into the sandbox.

## State contract

1. Prepare a plan bound to the job, brief, route, recipe, snapshot, runtime profile, limits, and
   15-minute expiry.
2. Require the Founder to approve that exact plan digest.
3. Reconcile terminal, expired, canceled, and emergency-stopped records before any snapshot or
   executor work.
4. Verify the source again immediately before dispatch.
5. Atomically check approval, expiry, cancellation, emergency stop, job state, and zero prior
   attempts, then consume the approval and claim exactly one attempt.
6. Accept a result only when all required observations and trusted isolation evidence match.
7. Persist one signed verified-success or verified-failure outcome.

Any dispatch failure consumes the attempt and is never retried automatically.

## Runtime contract

The permanently disconnected Bubblewrap candidate generates an invocation with a dedicated
read-only runtime root, isolated namespaces,
non-root UID/GID, no inherited environment, no host source mount, read-only input, disposable
temporary filesystems, exact argument-vector execution, process-group termination, output limits,
and destruction checks. Network, package installation, source writes, artifacts, Git operations,
credentials, and deployment are prohibited.

The managed build host denies the required namespace operation. Independently of that host result,
the 0.7 adapter is hard-disconnected because a smoke probe cannot prove production isolation. It
cannot be reached through the default application assembly.

## Exit criteria

Phase 7's control-plane release is acceptable when:

- the previous 0.6 API paths and all prior offline gates remain green;
- migration and concurrent startup are deterministic and fail closed;
- replay, tampering, source drift, command reordering, and duplicate claims are rejected;
- the 120-case Phase 7 offline suite passes with zero provider calls and zero real executions;
- source remains unchanged;
- the API and health surface report execution disconnected on this host;
- limitations are recorded without claiming production isolation.
