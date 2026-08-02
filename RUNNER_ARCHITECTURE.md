# Lil Tweak Runner Architecture

## Evidence scope

| Item | Value |
|---|---|
| Repository / branch / PR | `islamismylifebey-web/lil-tweak` / `codex/lil-tweak-live-workbench-build` / draft PR #6 |
| Audited remote baseline | `373400cb2b459dbf8a37dacceb0d3d1186eef949` |
| Working candidate commit | **PENDING** |
| Exact final tested tree | **PENDING**; the earlier 523/523 checkpoint is not final after later changes |
| Environment | Private Codex Linux workspace, Python 3.12; host prerequisites below are unsatisfied |
| Current focused command | `.venv/bin/pytest -q tests/test_tool_registry.py tests/test_runner_qualification.py tests/test_runner_qualification_cli.py tests/test_external_checkpoint.py tests/test_repository_delivery.py` |
| Current focused checkpoint | 80/80 tool, runner, checkpoint, and publisher tests passed on the mutable working tree |
| Runner qualification suite | 47 checks; digest `45197dc51a04a0a8f1a7a56183d326ee2fb758c2f013ef4a9ba314e0ff53f531` |
| Runner source digest at authoring | `07809fb33a70d25f42c35d3ae13aa1fba1911c44b34b33b235e74444274038e0` |
| Final qualification artifact/digest | **PENDING**; no signed live 47-check receipt exists |
| Live runner status | **DISCONNECTED / UNQUALIFIED** |

## Trust boundary

The runner is a separate security principal. It accepts only an exact, fresh, one-use dispatch
authorized by the control plane after independent host/runtime qualification. It does not receive
model credentials, owner credentials, approval-signing material, evidence-signing material,
publisher authority, the control-plane database, another repository, or a raw host path.

The control plane may request work; it may not manufacture runner qualification. The runner may
execute an authorized invocation; it may not approve the task, change policy, issue a connection
grant, sign authoritative verification, or claim completion.

## Required production topology

1. A root-owned supervisor provisions one task sandbox from a digest-pinned runtime image and manifest.
2. A non-root task identity receives a read-only source mount and a separate disposable writable workspace.
3. User, mount, PID, IPC, UTS, and network namespaces isolate the task.
4. `no_new_privileges`, dropped capabilities, seccomp, and an enforced AppArmor/SELinux-equivalent policy constrain the process tree.
5. Delegated cgroup v2 controllers enforce CPU, memory, PID, wall-time, output, disk-byte, and inode limits.
6. Network defaults to denial across IPv4, IPv6, DNS, host loopback, metadata, proxies, and unrelated Unix sockets.
7. Cancellation, timeout, emergency stop, crash recovery, and cleanup terminate and reap the entire process tree.
8. The destroyer verifies cgroup, namespace, mount, workspace, socket, and process cleanup before producing evidence.
9. An independent qualifier signs evidence for the exact host, kernel, runtime, image, policy, and transport.
10. A separate owner authority signs a fresh connection authorization bound to repository, source, task, plan, attempt, resources, network, nonce, generation, and qualification evidence.

## Existing code boundary

- `DisconnectedProcessTransport` is the production default and always refuses execution.
- `QualifiedProcessTransport` is explicitly dormant; constructor assertions cannot qualify it.
- `BoundedToolExecutor.connected` can become true only for a pytest-only injected transport with a
  qualified status and a valid authorization digest. Production construction does not enable that override.
- `liltweak/runner_qualification.py` provides signed challenge, attestation, qualification,
  connection-authorization, local capability, replay, and cleanup contracts.
- `.github/workflows/runner-qualification.yml` is a manual, dormant evidence workflow. Its
  qualification decision does not authorize a production connection.
- No application-factory path constructs a live production process transport.

There is no host-subprocess fallback. This is intentional.

## Dispatch contract

A production dispatch must bind at least:

- runner, runtime, image, sandbox profile, qualifier, and qualification evidence;
- registered repository, immutable source fingerprint, opaque task workspace, task and plan;
- exact tool-registry and tool-definition digests;
- normalized arguments, working directory, environment, resources, output limits, network mode;
- owner, approval purpose, attempt, lease, generation, nonce, issue time, and expiry;
- expected evidence, artifacts, cancellation, cleanup, and rollback behavior.

The runner rechecks authorization, lease, generation, expiry, revocation, and registry bindings at
every dispatch. A model or candidate repository cannot supply or self-assert any of them.

## Hostile qualification

The 47-check suite covers namespace isolation, filesystem/credential/socket absence, network and
metadata denial, timeout/OOM/fork/output/disk/inode/sleeping-child behavior, cancellation,
emergency stop, crash recovery, source integrity, and complete cleanup. Qualification also rejects
stale evidence, signature forgery, replay, self-authorization, mismatched bindings, and missing
destroyer proof.

## Activation prerequisite

One exact environmental prerequisite remains: an owner-authorized capable private Linux host with
root-controlled digest-pinned qualifier/destroyer/runtime artifacts, delegated cgroup v2,
supported namespace and security-policy enforcement, an independent trusted qualification
principal, and a separate owner connection-authority key. That host must pass the exact 47-check
suite and application dispatch integration before `connected` may become true.

Until then, execution permission must remain false and every execution-dependent capability stays
blocked.
