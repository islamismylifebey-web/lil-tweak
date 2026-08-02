# Repository Delivery and Rollback

## Evidence scope

| Item | Value |
|---|---|
| Repository / branch / PR | `islamismylifebey-web/lil-tweak` / `codex/lil-tweak-live-workbench-build` / draft PR #6 |
| Audited remote baseline | `373400cb2b459dbf8a37dacceb0d3d1186eef949` |
| Working candidate commit | **PENDING** |
| Exact final tested tree | **PENDING**; the 523-test checkpoint is not final after later changes |
| Environment | Private Codex Linux workspace, Python 3.12; production publisher disabled |
| Current focused command | `.venv/bin/pytest -q tests/test_tool_registry.py tests/test_runner_qualification.py tests/test_runner_qualification_cli.py tests/test_external_checkpoint.py tests/test_repository_delivery.py` |
| Current focused result | 80/80 passed on the mutable working tree |
| Delivery source digest at authoring | `8d3265dd7d0ba4c7d88be5ce0e42d9ab74e5ec33a3bfde2e9e2172f7caccce64` |
| Delivery test digest at authoring | `77a3ddd296530116b6f648621859b0229c132888cfbe6d4e9508b20d6b5db397` |
| Final delivery artifact/digest | **PENDING / ABSENT** |
| Production publisher | **DISABLED / NOT CONFIGURED** |
| Live owner-tree trial | Not run |

## Plane separation

Repository delivery belongs to a publisher principal separate from the model, runner, ordinary
control plane, verifier, and checkpoint. The runner may produce a candidate patch in a disposable
task workspace. It cannot touch the owner tree. The publisher may inspect or mutate only a
server-registered repository after verifying a fresh, exact owner approval.

Remote push, PR creation, merge, release, and deployment are not publisher capabilities.

## Working-candidate contracts

`liltweak/repository_delivery.py` defines strict, content-addressed contracts for:

- exact repository state: repository, branch, HEAD/tree, worktree/index/status digests, cleanliness;
- final-tree entries and manifests, including byte counts, executable mode, and content kind;
- patch manifests bound to patch bytes, pre-state, final tree, changed paths, and binary paths;
- structured Git commands restricted to exact per-operation argv templates, explicit stdin digests,
  and a complete deny-by-default environment;
- separate expiring one-use approvals for `apply_patch`, `local_commit`, and `rollback`;
- exact apply, commit, and rollback results;
- publisher capability status that distinguishes blocked, test-only, and operational.

The hardened Git environment disables ambient configuration, hooks, fsmonitor, credential helpers,
file protocol, submodule recursion, fetch recursion, LFS smudge, pagers, editors, prompts, SSH
askpass, and discovery outside the repository. Commands are argv arrays; `git push` and shells are
not allowed.

## Transaction design

### Apply

1. Reinspect the registered owner repository and require the approved exact pre-state.
2. Verify patch bytes, patch manifest, final-tree manifest, repository, HEAD/tree, and approval bindings.
3. Reject binary delivery unless a separate binary policy is qualified.
4. Consume the exact `apply_patch` approval once.
5. Apply through an isolated publisher transaction.
6. Verify the resulting tree and required post-apply checks.
7. If apply or post-apply verification fails, restore the captured exact pre-state as mandatory
   compensation inside the same approval.

### Local commit

Local commit requires a new `local_commit` approval bound to the exact applied state, final tree,
parent, commit-message digest, and verification evidence. It stages only the approved content,
rechecks the resulting tree, and creates no remote action.

### Discretionary rollback

A rollback after a successful apply/commit requires a separate `rollback` approval bound to the
current state, restore state, failed operation, and recovery snapshot. Rollback preserves evidence.

## Test-only evidence

`EphemeralTestRepositoryPublisher` is restricted to pytest and cannot touch an owner repository. It
exercises exact pre-state rejection, patch-byte rejection, separate one-use approvals, simulated
apply/commit/rollback, mandatory restoration after failed post-apply verification, and binary
denial. `DisabledRepositoryPublisherClient` is the production-safe default and refuses every
operation.

This evidence is **TEST ONLY**. It does not prove Git behavior, filesystem atomicity, owner-work
preservation, real hooks/filter denial, process cancellation, crash/restart recovery, concurrent
repository locking, or exact restoration on a real owner tree.

## Production blockers

- no isolated publisher process/security principal is implemented or configured;
- no production approval-proof verifier or durable one-use journal is wired;
- no production repository-handle resolver and structured Git executor is connected;
- Workbench has no authenticated apply, local-commit, or owner-tree rollback action;
- no clean/dirty owner-tree end-to-end trials have run;
- no real round-trip suite covers empty files, modes, renames, deletions, no-final-newline files,
  failed checks, cancellation, crash, restart, and concurrent edits;
- binary mutation remains intentionally blocked;
- the external checkpoint required around delivery is not operational.

## Decision

Owner-tree apply, local commit, and rollback are **BLOCKED IN PRODUCTION**. The contracts and
pytest-only protocol exerciser may not be described as an operational publisher. Activation
requires a separate qualified publisher, exact owner approvals, external checkpoint integration,
real Git/recovery trials, and clean-checkout evidence from the final candidate commit.
