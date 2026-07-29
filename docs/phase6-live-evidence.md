# Phase 6 Live Evidence

Date: 2026-07-29

The first two billable model probes were intentionally limited to one provider request each.
Neither was retried, neither received tools, and neither was allowed to claim execution or
completion.

## Probe 1

- Approved model-spend ceiling: $0.05
- Route: frontier
- Result: failed closed because a 512-token structured response did not complete in one turn
- Execution or tool use: none

## Probe 2

- Approved model-spend ceiling: $0.02
- Route: standard
- Result: failed closed because a 768-token structured JSON response ended before completion
- Execution or tool use: none

The second response contained a substantive analysis before truncation, but partial output is not
accepted as a work order. Lil Tweak recorded failure and made no success claim.

## Corrective gate

The live controller now refuses output ceilings below 1,024 tokens. The schema and trusted prompt
also impose tighter length and item-count bounds so a work order must be compact. A new paid retry
requires a new digest-bound proposal and Founder approval; none was attempted for this release.

## Hosted sandbox

The adapter is implemented with network disabled and synthetic inputs only. The probe was not run:
the hosted container has a $0.03 minimum charge, which did not fit the remaining announced spend
ceiling. Real repository execution remains disconnected and unproven.
