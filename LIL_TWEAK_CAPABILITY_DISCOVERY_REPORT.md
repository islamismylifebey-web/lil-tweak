# Lil Tweak Capability Discovery Report

> Historical checkpoint — superseded by `MASTER_BUILDER_CAPABILITY_REPORT.md`. The classification
> and capability facts below describe the earlier baseline only. Current controlling verdict:
> **ARCHITECTURE IMPLEMENTED AND TESTED — NOT OPERATIONAL**.

## Verdict

`PARTIALLY OPERATIONAL — BLOCKERS REMAIN`

The offline discovery harness ran 20 cases in disposable Git repositories. Ten control-plane and
safety capabilities passed, ten execution/provider-dependent capabilities were blocked, and none
failed. Blocked cases were not simulated or counted as passes.

Runner capability report SHA-256:
`df9a11f7a5fef9d1d740c5baeb10f31913e1f113cc947503b73d20961e1907a8`

| # | Capability trial | Result | Evidence |
|---:|---|---|---|
| 1 | Repository inspection | PASS | Server-generated source fingerprint |
| 2 | Dirty and untracked capture | PASS | Dirty worktree and one untracked owner file detected |
| 3 | Git-free task materialization | PASS | Deterministic task-tree digest; `.git` excluded |
| 4 | Owner source preservation | PASS | Source worktree bytes unchanged after capture |
| 5 | Grounded planning context | PASS | Relative source paths, five bounded excerpts, and command clues |
| 6 | Secret screening | PASS | One secret-bearing file was detected; task materialization was refused |
| 7 | Concurrent source change | PASS | Changed source refused before materialization |
| 8 | Candidate self-authorization | PASS | Pre-approved candidate record rejected |
| 9 | Evidence tamper laundering | PASS | Append refused a modified prior ledger/anchor |
| 10 | GCP direct HTTP bypass | PASS | Direct HTTP denied regardless of claimed network denial |
| 11 | Qualified command runner | BLOCKED | Host qualification gates did not pass |
| 12 | Live model planning | BLOCKED | Model disabled and no provider credential configured |
| 13 | Python defect repair | BLOCKED | Model and runner disconnected |
| 14 | JavaScript interface repair | BLOCKED | Model and runner disconnected |
| 15 | Test, lint, and build through agent | BLOCKED | Runner disconnected |
| 16 | Process-tree cancellation | BLOCKED | No qualified process tree may be started |
| 17 | Browser preview | BLOCKED | No qualified preview runner or installed browser |
| 18 | Approved patch application | BLOCKED | No verified execution patch and repository action absent |
| 19 | Approved local commit | BLOCKED | No applied patch and repository action absent |
| 20 | GCP execution or deployment | BLOCKED | Explicitly deferred and disabled |

## Disposable fixture coverage

The discovery harness creates:

- A Python calculator defect with a failing expected result.
- A JavaScript label/interface defect.
- Python and JavaScript test/build manifest clues.
- Dirty and untracked owner work.
- A secret-bearing repository used to prove the secret path is excluded from planning context and
  the repository cannot be materialized as a task.
- A hostile concurrent source modification.

The harness deletes its temporary repositories after the run. It does not invoke a paid model,
connect GCP, start an unqualified process runner, write to the owner repository, or deploy.

## Offline evaluation matrix

All offline evaluation commands exited zero:

| Evaluation | Result |
|---|---|
| Local repository workflow | 15/15 cases passed |
| Prompt-injection and late-secret gauntlet | 2/2 cases passed; 0 paid calls |
| Engineering reasoning trial | 3/3 cases passed; 0 provider calls |
| Creator routing benchmark | 160/160 cases passed; 0 provider calls; 0 executions |
| Phase 6 offline | 120/120 cases passed; 0 real provider calls; 0 executions |
| Phase 7 offline | 120/120 matched; 80 accepted, 40 rejected; 0 executions |
| Snapshot benchmark | 254-file and 1,004-file cases completed; 0 provider calls |

These results establish deterministic control-plane behavior only. They do not establish live
model quality or qualified command execution.

## Reproduction

```bash
uv sync --frozen --offline --group dev
uv run python -m scripts.lil_tweak_capability_discovery
```

Expected summary on this host: `PASS=10`, `BLOCKED=10`, `FAIL=0`, model disconnected, runner
disconnected, GCP disconnected, and no public deployment.
