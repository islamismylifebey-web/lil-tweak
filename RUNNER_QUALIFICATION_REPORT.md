# Runner Qualification Report

## Report identity

| Item | Value |
|---|---|
| Repository | `islamismylifebey-web/lil-tweak` |
| Branch / PR | `codex/lil-tweak-live-workbench-build` / draft PR #6 |
| Audited remote baseline | `373400cb2b459dbf8a37dacceb0d3d1186eef949` |
| Working candidate commit | **PENDING** |
| Exact final tested tree | **PENDING**; no immutable candidate tree is claimed |
| Environment | Current private Codex Linux workspace |
| Qualification suite | 47 checks, digest `45197dc51a04a0a8f1a7a56183d326ee2fb758c2f013ef4a9ba314e0ff53f531` |
| Focused command | `.venv/bin/pytest -q tests/test_tool_registry.py tests/test_runner_qualification.py tests/test_runner_qualification_cli.py tests/test_external_checkpoint.py tests/test_repository_delivery.py` |
| Focused result | 88/88 passed; contract and fault-injection evidence only |
| Live runner trial | Not run; no qualified host or production transport exists |
| Signed qualification artifact/digest | **PENDING / ABSENT** |
| Final status | **BLOCKED — DISCONNECTED AND UNQUALIFIED** |

## Evidence classification

| Evidence | Mode | Result | What it proves |
|---|---|---|---|
| Runner contract/unit tests | Offline/test-only | PASS | Schema, signatures, bindings, replay rejection, probe classification, and fail-closed behavior |
| Local capability discovery at audited baseline | Live host observation without execution authorization | BLOCKED | Current host lacks mandatory isolation/qualification prerequisites |
| Manual GitHub workflow | Dormant/manual | Not run for this candidate | Evidence collection design only; it fixes `connection_authorized=false` |
| Production task execution | Live | Not run | Nothing; execution remains disconnected |

Mocks, synthetic probes, and pytest-only transports are not live qualification.

## Current blockers observed on this host

The current capability probe reports the following unsatisfied prerequisites:

- qualifier executable absent and its SHA-256 not pinned;
- destroyer executable absent and its SHA-256 not pinned;
- dedicated runtime root absent and runtime-manifest digest not pinned;
- cgroup v2 is not delegated to the task authority;
- the bubblewrap namespace probe did not qualify within the host constraints;
- no independent signed qualification decision is installed;
- no fresh signed connection authorization is installed;
- no production process transport is wired into the application.

Any one of these blocks connection. Together they require the runner to remain unavailable or
unqualified in Workbench health.

## Mandatory qualification gates

| Gate | Current state |
|---|---|
| Exact host/kernel/runtime/image/policy binding | BLOCKED |
| Root-owned immutable collector, limiter, and destroyer | BLOCKED |
| Non-root identity and namespace isolation | BLOCKED |
| Seccomp/capability/security-policy enforcement | BLOCKED |
| Delegated cgroup v2 resource enforcement | BLOCKED |
| IPv4/IPv6/DNS/metadata/proxy/socket denial | BLOCKED |
| Process-tree cancellation and emergency kill | Interface/offline tested; live BLOCKED |
| Crash/OOM/fork/output/disk/inode cleanup | Interface/offline tested; live BLOCKED |
| Independent signed qualification | BLOCKED |
| Fresh one-use owner connection authorization | BLOCKED |
| Application-factory production transport | NOT IMPLEMENTED |
| End-to-end disposable repository execution | NOT RUN |

## Decision

`runner_connected = false`

`execution_permission = false`

No source code, local executable, workflow artifact, caller-supplied digest, or model statement may
override this decision. The exact unblocking evidence is a passing signed 47-check report on the
target private host, independently verified cleanup, a fresh purpose-bound connection grant, and a
production transport that consumes that grant atomically.

The source and test digests recorded while authoring this report are mutable working-tree evidence,
not final release evidence. The final commit, clean-checkout run, report digest, and artifact
manifest remain pending.
