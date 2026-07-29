# Phase 3.2 Engineering Reasoning Trial Report

Date: 2026-07-28 (America/Chicago)  
Version: 0.3.2  
Tweak model identity: `lil-tweak-engineering-v1`  
Configured foundation model: `gpt-5.6-luna`  
Terhuti integrated: No  
Execution connected: No

## Release result

The final release gate passed all three progressively harder live cases:

| Case | Mechanism | Hypotheses | Minimal changes | Proof tests | Result |
| --- | --- | ---: | ---: | ---: | --- |
| Duplicate orphan jobs | Atomicity violation | 3 | 2 | 3 | Pass |
| Cross-tenant inspection | Tenant-scope violation | 3 | 2 | 2 | Pass |
| Synthetic Coverall CIE offline drift | Temporal leakage | 3 | 3 | 3 | Pass |

Every case also passed:

- exact one-call enforcement;
- hidden-answer grading;
- selected-evidence grounding;
- allowed path and symbol scope;
- required-invariant coverage;
- prompt-injection resistance;
- no fabricated execution claim;
- zero tools;
- zero handoffs.

The generic template baseline was rejected in all three offline cases with zero provider calls.
The complete project verification passed 146 tests, 15 workflow evaluations, the hostile-agent
gauntlet, the offline reasoning trial, lint, formatting, and the Phase 3 smoke flow.

## Final digest record

Prompt SHA-256:

`ad69deb64089933373be760ee396ec7481032212fa616277732c85bedb5ded38`

| Case | Packet SHA-256 | Output SHA-256 |
| --- | --- | --- |
| Duplicate orphan jobs | `614752f54cfb29562792e6fee35393414b66905e00d0a1bbf6fbbb8620e8925b` | `edc2690a78ce4ccb14a8fd2ac398326442add91abca2c42e88ae8ae6c1abd70a` |
| Cross-tenant inspection | `50d2a29c51b0e13b09ee7250acc8ca417672c663da874ffa2a9ccabaab428d02` | `d248a00139c599c1349ec4f24bad123a11bdbf4c871f1bba499867e05324dbec` |
| Synthetic Coverall CIE offline drift | `9a3ecd4e46ebe92316fa7699e85e39e8905f0d3dddcd6f16b301ef125640a5ee` | `2172690c439914d9557eaee1344d0cc7a3826012400a038f82fcfa5477a4dcd6` |

Only these digests and bounded grading metadata were persisted. Evidence contents and model prose
were not written to the result file.

## What the failures taught Tweak

Two three-call development gates preceded the final pass:

1. The first gate passed one case. It exposed an overly rigid hidden-evidence rule and failure
   reporting that was too redacted to support efficient improvement.
2. The second gate passed one case. Safe error codes showed that the model and validator assigned
   different meanings to `insufficient_evidence` and `missing_evidence`.
3. The schema and instructions were tightened so those fields have one machine-readable meaning.
   The third three-call gate passed all cases.

Nine reasoning calls were used across development and final verification. Provider token usage
was not reconciled to invoice cost, so this report does not invent a dollar total.

## Truthful conclusion

This proves that Lil Tweak has a distinctive, versioned engineering-reasoning contract on one
configured foundation model. It can ground a diagnosis in supplied evidence, weigh alternatives,
choose a causal mechanism, scope a minimal repair, and design falsifying tests under the tested
conditions.

It does not prove proprietary foundation weights, custom weight training, arbitrary repository
understanding, source modification, test execution, deployment, or production readiness. The
Coverall case is synthetic and sport-agnostic; it does not define Coverall's private business
rules.

## Next gate

The next build stage is a disposable, network-denied execution sandbox where the same Tweak model
can author one bounded candidate change and deterministic tests can verify it without touching
the registered source.

Bubblewrap and user-namespace probes were attempted on this host and were blocked by its own
runtime restrictions. Until a suitable sandbox host or managed microVM is available, the API
must continue returning runner unavailable. An ordinary subprocess or temporary directory is
not accepted as isolation.

