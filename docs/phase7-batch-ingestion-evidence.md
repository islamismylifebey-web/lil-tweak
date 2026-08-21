# Phase 7 Batch Snapshot Ingestion Evidence

Date: 2026-07-29
Baseline: verified Phase 7 tree `fbda50cd8246a5b28eba4bd9633dd192577a7385`
Environment: managed local build workspace
Baseline reader SHA-256: `dff82f902fee8ee5fc028d73b788ddf6137ee4475079a722f083546dc82e12a0`
Candidate reader SHA-256: `112b6674e974855aaa4cb4fcaa8f5f24c1970d4854ac2daf0bb2a54b3387315e`

## Change

The committed-tree snapshot reader now uses two bounded Git protocol stages in each independent
verification pass:

1. `git cat-file --batch-check` validates object identity, type, and declared size for the complete
   inventory before any blob content is requested.
2. `git cat-file --batch` streams each exact blob body after admission.

The existing two-pass inspection, inventory, content, archive, and manifest comparison remains in
place. No object data or verification result is reused across those passes.

## Paired local benchmark

The baseline and candidate used the same generated clean repositories and the same snapshot
preparation path. Each repository contains exactly the reported number of tracked files under
`fixtures/`. Every file is 128 bytes: an eight-digit index and colon followed by `x` bytes. The
table reports the median of five single-process local runs with no discarded sample.

| Tracked files | Phase 7 baseline | Batch candidate | Change |
|---:|---:|---:|---:|
| 254 | 1.245174 s | 0.301424 s | 75.8% faster |
| 1,004 | 4.569725 s | 0.914016 s | 80.0% faster |

For the 1,004-file case, direct snapshot Git processes fell from 4,018 to 6: two `ls-tree`, two
`--batch-check`, and two `--batch` processes across the two independent passes. The repository
inspector still performs a fixed set of safety checks outside this count.

Candidate raw samples:

- 254 files: `0.416092`, `0.296351`, `0.295500`, `0.309256`, `0.301424` seconds.
- 1,004 files: `0.885377`, `0.999160`, `0.914016`, `0.978198`, `0.897510` seconds.

Baseline raw samples:

- 254 files: `1.272375`, `1.173979`, `1.245174`, `1.254970`, `1.240442` seconds.
- 1,004 files: `4.162068`, `4.254840`, `4.610448`, `4.569725`, `4.997606` seconds.

The committed benchmark command is:

```text
uv run python evals/run_phase7_snapshot_benchmark.py \
  --files 254 1004 --file-bytes 128 --repetitions 5
```

To repeat the baseline measurement, set `LILTWEAK_BENCHMARK_SOURCE_ROOT` to a clean worktree at
the recorded baseline tree before running the same command. The benchmark output records the
loaded `source_snapshot.py` SHA-256 so a result cannot silently identify the wrong implementation.

## Safety evidence

- Golden tree and archive digests remain unchanged.
- Empty, executable, duplicate, binary, NUL-containing, newline-containing, and header-looking
  blob bodies round-trip byte for byte.
- SHA-1 and SHA-256 Git object IDs are recomputed from returned blob content.
- File-count, per-file-size, and aggregate-size rejection occurs before content streaming.
- Malformed headers, wrong object metadata, size drift, bad delimiters, premature EOF, trailing
  output, nonzero exit, and stalled processes fail closed.
- Each helper has a fixed aggregate deadline and a fresh process group that is terminated on
  protocol or timeout failure.
- Provider calls, paid calls, model calls, deployments, and repository executions: 0.

## Limits

These timings describe local filesystem and Git process behavior, not production HTTP, database,
model, network, or sandbox latency. Performance wall-clock thresholds are intentionally excluded
from the test suite because host load is variable; deterministic process topology and protocol
invariants are tested instead. Deadline enforcement retains focused bounded-time regressions.

