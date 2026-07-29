# Creator Model Offline Benchmark

Date: 2026-07-29  
Suite: `evals/run_creator_benchmark.py`  
Mode: deterministic offline

## Case matrix

| Work type | Cases | Expected route |
|---|---:|---|
| Short writing | 40 | Economy |
| Typed API engineering | 40 | Standard |
| Distributed/security engineering | 20 | Frontier |
| Visual quality translation | 20 | Standard |
| Source-backed research | 20 | Standard |
| Medical/legal high-stakes work | 20 | Blocked |
| Total | 160 | — |

## Result

| Measure | Result |
|---|---:|
| Passed cases | 160/160 |
| Adaptive coverage | 140 |
| Always-heavy coverage | 140 |
| Always-light coverage | 40 |
| Blocked high-stakes cases | 20/20 |
| Signed-brief tampering rejected | 16/16 |
| Adaptive synthetic cost | 456 units |
| Always-heavy synthetic cost | 1,120 units |
| Synthetic cost reduction | 59.2857% |
| Provider calls | 0 |
| Tool calls | 0 |
| Executions | 0 |

The benchmark proves deterministic route consistency and boundary enforcement. It does not prove
real provider price savings, live model quality, or sandbox isolation.
