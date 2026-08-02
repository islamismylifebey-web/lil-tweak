# Tool and Orchestration Security

## Evidence scope

| Item | Value |
|---|---|
| Repository / branch / PR | `islamismylifebey-web/lil-tweak` / `codex/lil-tweak-live-workbench-build` / draft PR #6 |
| Audited remote baseline | `373400cb2b459dbf8a37dacceb0d3d1186eef949` |
| Working candidate commit | **PENDING** |
| Exact final tested tree | **PENDING**; the 523-test uncommitted checkpoint predates later changes and is not release evidence |
| Environment | Private Codex Linux workspace, Python 3.12; production runner and tool dispatch disconnected |
| Current focused command | `.venv/bin/pytest -q tests/test_tool_registry.py tests/test_runner_qualification.py tests/test_runner_qualification_cli.py tests/test_external_checkpoint.py tests/test_repository_delivery.py` |
| Current focused result | 88/88 passed on the mutable working tree |
| Registry digest | `96f47167cffa63be212cffaeb45997841853abf2406352e56011ffac25404fec` |
| Registry source digest at authoring | `dd921daf78fc89dee4fe1b4a8c8d6f4d3bffe6b8a2ddcdc77b819a83a17f5ba0` |
| Final evidence artifact/digest | **PENDING**; the registry export is deterministic, but no exact-candidate evidence bundle is claimed |
| Live execution status | **DISCONNECTED**; tests use contract checks or pytest-only transports |

## Authority model

A model output is only a request. The server-owned registry must revalidate the exact invocation
immediately before dispatch. Registry, definition, task, plan, workspace, attempt, nonce, expiry,
arguments, and any network grant must be content-bound. This invariant is **not yet integrated**
into the production Workbench, which still uses the legacy command policy broker; production tool
dispatch therefore remains blocked.

The current default registry contains only:

| Tool | Authority | Mutation | Network | Status |
|---|---|---:|---|---|
| `repository.read_file` | `read` | No | Denied | Registered for secret-screened repository-relative reads |
| `verification.run_named_check` | `verify` | No | Denied | Registered as a named verification request; no production runner is connected |

There is no general shell, caller-selected executable, mutation tool, publisher tool, browser
tool, connector, GCP tool, deployment tool, or network-enabled tool in the registry.

## Invocation controls

`liltweak/tool_registry.py` enforces:

- stable tool and implementation IDs plus implementation digests;
- strict argument names, cardinality, length, patterns, and control-character rejection;
- repository-relative path policy that rejects absolute paths, parent traversal, and `.git`;
- registry and per-definition digest binding;
- task, plan, opaque workspace, attempt, nonce, and expiration binding;
- network denial unless the definition requires a separately supplied exact grant;
- mutation/rollback consistency: a mutating definition cannot exist without an explicit rollback contract;
- unknown, stale, expired, over-broad, or malformed invocations fail closed.

These checks authorize nothing by themselves. A qualified runner must independently enforce
filesystem, executable, environment, network, resource, cancellation, and cleanup policy.

## Untrusted output and secrets

Repository text, diagnostics, test output, model output, and tool output remain untrusted. Before
reuse they must be bounded, redacted, hashed, labeled with provenance, and screened for
credential-shaped content. The model, runner, and task workspace may not receive provider keys,
owner authentication material, signing keys, approval material, the control-plane database, host
paths, ambient environment, SSH agents, or publisher credentials.

## Network and external writes

Network is denied for both registered definitions. Future network access requires a separate,
task-bound, destination-bound, port-bound, method-bound, expiring grant and independent runner
enforcement. External connectors, browser actions, repository publication, GitHub writes,
messaging, cloud operations, and deployment are separate authority classes and are not implied by
ordinary execution. GCP remains disabled.

## Mutation graduation sequence

Mutation tools must remain absent until all of these gates pass:

1. full live provider qualification, including failure modes and context behavior;
2. exact orchestrator integration and reauthorization at dispatch;
3. independent runner qualification and fresh connection authorization;
4. authoritative verification and externally checkpointed evidence;
5. content-addressed patch and rollback qualification;
6. separate owner approvals for task-workspace mutation, owner-tree apply, commit, and discretionary rollback;
7. full adversarial and end-to-end evaluation.

## Known blockers

The current `ToolDefinition` is a safe minimal planning registry, not the directive’s complete
production tool schema. Per-tool output contracts, role allowlists, explicit working-directory and
mount scopes, environment allowlists, resource ceilings, retry policy, output ceilings, redaction
policy, approval purpose, artifact contract, and independent dispatch receipt still need to be
represented and enforced end to end before mutation registration.

No current evidence proves live model-directed dispatch, process isolation, cancellation through a
production transport, network enforcement, or mutation rollback. The final exact-commit registry
digest and clean-checkout results are pending.
