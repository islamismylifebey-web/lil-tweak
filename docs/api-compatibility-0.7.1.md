# API and State Compatibility — 0.7.1

Phase 7.1 is a fail-closed patch release over private `main`
`43580205930718d45d3571b99033ff00e8952d41`.

## Preserved

- All 31 existing HTTP operations, including the five Phase 7 repository-verification routes.
- SQLite schema version 2 and every existing table, constraint, index, and migration.
- All persisted and signed Phase 7 models, field sets, schema literals, digests, HMAC domains,
  approvals, execution plans, attestations, and outcome records.
- The Creator, live-model, recovery, and legacy health fields.
- `execution_connected=false` and `source_execution_connected=false`.

## Added outside the production API

- `runner-qualification-challenge-v1`;
- `runner-qualification-v1`;
- `runner-qualification-decision-v1`;
- a local issue/verify command for bounded JSON evidence;
- automatic deterministic GitHub CI;
- a dormant manual evidence workflow for a future dedicated ephemeral runner.

Qualification evidence is not written to the Lil Tweak state database and has no HTTP write
route. Its decision structurally fixes `connection_authorized=false`, so parsing or verifying a
report cannot activate execution or invalidate existing signed records.

