# Lil Tweak production release source receipt

- Date: 2026-08-15
- Release branch: `release/lil-tweak-production-2026-08-15`
- Official base commit: `ba967d9761f1443802182bb86d091c1df8643b9d`
- Task 1 commit: `bb9f2a70ced5e1d8b0d90170cc7ea5d2b8604480`
- Task 2 commit: `ce9307c2ebd0339b8f6eb48f303e334b08d26abd`
- Task 2 tree: `bf5ad066b5181eb4bc4ddf987133ab5bf13016af`
- `package.json` SHA-256: `9788c15410193292c7d4c023e1a0231ffecd6cb2de4fb0cd606ee4978ab4a1ad`
- `package-lock.json` SHA-256: `581ac92c02c994c3148d9efd33d39d0fe28e0795d26fde40210cc40b78068063`
- Locked `lucide-react` version: `1.31.0`
- Exact clean install: PASS (`npm ci`, 479 packages, scripts disabled)
- Node tests: 107/107 PASS
- Core Python tests: 275/275 PASS
- Deployment Python tests: 158/158 PASS, with two environment-capability skips
- TypeScript typecheck: PASS
- ESLint: PASS
- Vinext production build: PASS
- Deployable Worker import: PASS
- `dist/.openai/hosting.json` project identity match: PASS
- Emitted Drizzle migration assets: PASS
- Tracked working-tree status entries after build: 0

No secret, generated dependency tree, npm cache, build output, Python bytecode, or private release-state artifact is included in this commit.

## Dedicated-host activation baseline, 2026-09-14 UTC

The preceding August record is historical, not evidence that the September
deployment is live. The latest verified baseline for this activation is:

- Repository: `islamismylifebey-web/lil-tweak`.
- Merged PR: <https://github.com/islamismylifebey-web/lil-tweak/pull/40>.
- Main commit: `174824ee6110dc0c41578a4ff35165e8c3792ec4`.
- Tested tree: `ac8b37034ad910cf09a1395fa3ce43d700c019eb`.
- Ubuntu Test World run: `34793941205`, job `103823301500`, success.
- Build Artifact run: `34793941212`, success.
- TypeScript, ESLint, production build: passed in that Ubuntu run.
- JavaScript: 131 passed, no failures or skips.
- Core Python: 485 passed; deployment Python: 163 passed.
- Focused Test World Core: 37 passed.

The private image publication workflow must independently run the full Ubuntu
verification against its own exact source commit before publishing. Its run ID,
source commit/tree, immutable image references, scan artifacts and archive
digests are separate release evidence. This tracked baseline receipt must not
be interpreted as a claim that subsequent changes passed before that run.

Production activation additionally requires the fresh release-bound host-GO
receipt, runtime manifest, rollback transaction, live runtime qualification,
owner-private native Sites publication and genuine owner-to-Actions evidence
round trip. No secret values or production PASS claims belong in this source
receipt.
