# Phase 7 Isolation Evidence

Date: 2026-07-29
Environment: managed local build workspace
Source used by probe: synthetic empty directory
Registered repository supplied to probe: No

## Candidate adapter

- Bubblewrap path: `/usr/bin/bwrap`
- Bubblewrap SHA-256:
  `52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712`
- `prlimit` path: `/usr/bin/prlimit`
- `prlimit` SHA-256:
  `f27cfd8c1512a4cc6541b59b80cb4cdfd6ef28c34aa21db4299b48264cd0d128`
- Runtime root requirement: dedicated, pinned, read-only directory; host root is rejected.
- Intended identity: non-root `65532:65532`.

## Probe result

The required Bubblewrap namespace creation failed:

```text
Creating new namespace failed: Operation not permitted
```

The adapter kept its connectivity flag false. Binary presence alone did not enable execution, and
the 0.7 candidate is coded to remain disconnected even if this narrow smoke probe succeeds.
No repository, credentials, API keys, network calls, provider calls, or paid resources were used.

## What the local result proves

- Host-path validation rejects the host root and symbolic-link traversal.
- The generated invocation requests all supported namespace isolation, disables nested user
  namespaces, drops capabilities, clears environment variables, sets a non-root identity, binds
  only a read-only materialized source, and creates disposable temporary filesystems.
- Failure to create the required namespace fails closed.

The configured image reference is a plan-bound label; this local probe does not prove that a
runtime-root filesystem matches an OCI digest. That missing provenance check is one reason the
candidate cannot connect.

## What it does not prove

This host did not run untrusted code in the adapter. Therefore the result does not prove network
denial, resource quotas, process cleanup under attack, syscall filtering, mandatory access
control, live cancellation, remote attestation, or sandbox destruction on a capable target.

The deterministic 120-case Phase 7 suite uses fixture evidence to test control-plane verification;
it is not represented as operating-system isolation evidence.

