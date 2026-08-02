# Lil Tweak Runner Qualification

## Current decision

`DISCONNECTED — HOST NOT QUALIFIED`

The local probe measured Bubblewrap and `prlimit`, kernel security state, cgroup delegation,
runtime-root state, the qualification collector/destroyer, and a synthetic namespace launch. It
does not create a transport.

Observed blockers in this workspace:

- Qualification collector is missing and unpinned.
- Qualification destroyer is missing and unpinned.
- Immutable runtime root and pinned manifest are missing.
- cgroup v2 exists but is not delegated to the process.
- The Bubblewrap namespace probe times out/fails under the available kernel permissions.
- No independent qualification decision is installed.
- No fresh, one-use, owner-signed runner connection authorization is installed.

## Required connection gates

All of these must pass on a capable local Linux host:

1. Root-owned, non-writable, SHA-pinned runtime, limiter, collector, and destroyer executables.
2. Root-owned immutable runtime tree with a pinned manifest.
3. Namespaces, seccomp, no-new-privileges, non-root identity, and no effective `CAP_SYS_ADMIN`.
4. Delegated cgroup v2 CPU, memory, PID, disk/inode, cancellation, and process-tree cleanup.
5. Verified denial of IPv4, IPv6, DNS, loopback, metadata, proxy, and Unix-socket escapes when
   network is denied.
6. Independent signed qualification evidence.
7. Fresh owner-signed, expiring, one-use authorization bound to provider, runner, runtime,
   repository, commit/tree, source, task, plan, attempt, sandbox, resources, and network.
8. Atomic replay, revocation, generation, and lease checks before every dispatch.

Chroot, an unqualified host subprocess, and a caller-supplied Boolean are not acceptable
substitutes. Until every gate passes, health must report `runner_connection=disconnected` and the
controller must stop before snapshot creation or approval consumption.
