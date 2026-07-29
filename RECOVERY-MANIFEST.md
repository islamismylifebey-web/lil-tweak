# Recovery Manifest

Date: 2026-07-29 (America/Chicago)  
Project: Lil Tweak the Super Geek  
Release: Creator Model Foundation 0.5.0

## Provenance

- Supplied archive:
  `LIL_TWEAK_PHASE_3_2_ENGINEERING (1)(1).zip`
- Supplied archive SHA-256:
  `1089820d491ee70356003447817e85e15e3b7dff86a8f3cde9e801047f890be5`
- Supplied archive entries: 66
- Supplied archive integrity test: passed
- Unsafe archive path check: passed
- Verified baseline commit:
  `7b30469b2e95093f5b42a69265e0d553cee3d1df`
- Creator Model implementation commit:
  `e9b09fc245bb593170abf2c255b2b655df47e2da`

The final packaging commit may be newer because this manifest is itself included in the release.
Use the Git bundle’s `main` head as the authoritative complete release revision.

## Verification state

- Dependency lock: frozen and synchronized
- Ruff lint: passed
- Ruff formatting: passed
- Tests: 174 passed
- Legacy workflow evaluations: 15 passed
- Offline hostile cases: 2 passed
- Offline engineering cases: 3 passed
- Creator routing simulations: 160 passed
- Creator signed-brief tampering probes: 16 rejected
- Phase 3 smoke: passed
- Creator smoke: passed
- Paid model calls: 0
- API keys created or stored: 0
- Real execution or deployment: 0

## Restore from the source ZIP

1. Extract the ZIP into an empty directory.
2. Run `uv sync --frozen`.
3. Run `uv run ruff check .`.
4. Run `uv run ruff format --check .`.
5. Run `uv run pytest`.
6. Run `uv run python evals/run_creator_benchmark.py`.
7. Run `uv run python main.py smoke`.
8. Run `uv run python main.py creator-smoke`.

## Restore from the Git bundle

1. Clone the bundle into an empty directory with `git clone <bundle-file> lil-tweak`.
2. Confirm `git log --oneline --decorate`.
3. Run the same verification commands listed above.

## Exclusions

- `.git` from the source ZIP
- `.venv`
- caches and bytecode
- generated evaluation result state
- local databases and journals
- artifact and repository workspaces
- environment files other than `.env.example`
- credentials, API keys, and secrets
- previous release archives
