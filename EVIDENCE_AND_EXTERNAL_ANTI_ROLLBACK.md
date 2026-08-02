# Evidence and External Anti-Rollback Architecture

## Evidence scope

| Item | Value |
|---|---|
| Repository / branch / PR | `islamismylifebey-web/lil-tweak` / `codex/lil-tweak-live-workbench-build` / draft PR #6 |
| Audited remote baseline | `373400cb2b459dbf8a37dacceb0d3d1186eef949` |
| Working candidate commit | **PENDING** |
| Exact final tested tree | **PENDING**; the prior 523-test working-tree checkpoint predates later changes |
| Environment | Private Codex Linux workspace, Python 3.12; no independent checkpoint backend configured |
| Current focused command | `.venv/bin/pytest -q tests/test_tool_registry.py tests/test_runner_qualification.py tests/test_runner_qualification_cli.py tests/test_external_checkpoint.py tests/test_repository_delivery.py` |
| Current focused checkpoint | 80/80 tool, runner, checkpoint, and delivery tests passed on the mutable working tree |
| External-checkpoint source digest at authoring | `eb70542d2d7eb9ec2c0e54089d552f5f4d156407664f1c5293f724a28dc32e22` |
| External-checkpoint test digest at authoring | `4c1f6f20c0569e1b28b127f0e72766628f583de0652f829c33750031bb8b06bd` |
| Final checkpoint artifact/digest | **PENDING / ABSENT** |
| Independent backend | **ABSENT** |
| Current status | **BLOCKED — INTERFACE ONLY** |

## Local evidence controls

The existing evidence plane uses authenticated database rows, redundant-column validation, an
ordered hash chain, HMAC anchoring, transactional prior-head checks, signed approval/run/submission
records, and a separately audited emergency control history. These controls detect local mutation
when current signing material and anchors remain trustworthy.

They do not detect restoration of an older database and matching older local anchor. A local HMAC,
second local file, ordinary backup, or application-owned counter is not external anti-rollback
protection.

## External checkpoint contract

`liltweak/external_checkpoint.py` defines:

- `ExternalCheckpointAppend`: a purpose-bound request containing ledger, task, evidence sequence,
  evidence-chain head, prior receipt, and a local timestamp;
- `ExternalCheckpointReceipt`: provider identity/key/checkpoint, externally allocated sequence,
  trusted timestamp, exact request and evidence bindings, receipt digest, and opaque provider proof;
- `ExternalCheckpointExpectation`: the exact head and minimum external sequence required by a gate;
- `assert_receipt_binding`: rejection of stale sequence, wrong ledger/task/head, or unexpected receipt;
- `ExternalCheckpointClient`: submit and assert-current boundary;
- `DisabledExternalCheckpointClient`: truthful default that raises for every dependent operation.

The interface never treats locally generated sequence numbers or timestamps as trusted. A concrete
client must authenticate the provider proof with trust material outside the application database.

## Required independent backend

A production backend must be outside the database, repository, ordinary application backup, model,
runner, browser, and publisher trust boundaries. Lil Tweak receives submit/assert authority only.
It must not allocate or rewrite trusted sequence/time, delete, rewind, backdate, or sign a receipt.

The backend must bind:

- repository, task, evidence-chain head, control-audit head, sequence, and generation;
- previous external receipt and trusted external timestamp;
- provider identity, key version, retention policy, and recovery generation;
- startup, approval, dispatch, delivery, rollback, and audit checkpoints.

Mismatch, absence when required, stale generation, or detected rollback must fail closed and engage
emergency stop before new authority is issued.

## Current implementation gaps

No external provider, independent principal, provider-proof verifier, key-rotation procedure,
retention policy, recovery procedure, or disaster-restore drill is configured. The current append
contract does not yet carry all directive-required repository, control-audit, and generation
bindings. The private Workbench canonical approval, dispatch, rollback, and completion gates now
require the independent checkpoint capability, so they fail closed by default; no live receipt
submission/assertion path is wired to activate that capability. Startup, publisher delivery, and
audit receipt integration remain unimplemented.

Therefore:

- external anti-rollback is not operational;
- `durable_hmac` must not be interpreted as independent durability;
- approval, execution, apply, commit, and completion remain blocked wherever policy requires an
  external checkpoint;
- test receipts and opaque strings are not live provider evidence.

## Exact activation prerequisite

The owner must authorize a private append-only/monotonic backend with a separate security principal
and non-rewindable trusted sequence/time. A concrete client must authenticate its receipts, add the
missing bindings, prove startup and gate integration, exercise rollback/recovery/key rotation, and
pass adversarial database-restore tests on the exact candidate commit.

No immutable evidence digest or final checkpoint receipt is claimed in this report. Those remain
pending with the final candidate and backend qualification.
