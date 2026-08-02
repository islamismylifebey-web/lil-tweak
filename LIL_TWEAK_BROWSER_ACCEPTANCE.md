# Lil Tweak Browser Acceptance

## Result

**PASSED** using a real Headless Chrome 149 CDP session against `127.0.0.1`. No browser mocks were
used. The server and browser were stopped after each run.

| Check | Result |
|---|---|
| Login and authenticated owner session | PASS |
| Project create/edit and zero-token labels | PASS |
| Requirements, milestones, board, and notes | PASS |
| Planning Chat live turn | PASS |
| Planning usage/cost ledger | PASS |
| Engineering Mode live Sol plan | PASS — `PLAN_READY` |
| Execution control | PASS — disabled |
| Approval UI | PASS — truthfully reports no approval while runner is disconnected |
| Delivery and rollback UI presence | PASS |
| Session-cookie revocation and login return | PASS |
| Desktop rendering | PASS |
| Mobile 390×844 rendering | PASS — no horizontal overflow |
| Console exceptions/log errors | PASS — zero |

The final mobile screenshot SHA-256 is
`6317a77d0aa723915fba40c70d2224650169326fec3cea35c654f83777416951`.

The Engineering plan was generated in a real browser workflow, bound to the screened read-only
repository snapshot, and stopped at `PLAN_READY`. The UI displayed no execution approval because
the runner, checkpoint, publisher, apply, and commit capabilities were disconnected. That absence
is the expected secure result, not a skipped test.

The full browser workflow and the session/mobile completion check were split only after a test
harness dereferenced the login panel before the reloaded DOM existed. The null-safe condition was
fixed; the completion check then passed with zero provider calls. Application code did not change
between the preserved Engineering evidence and that completion check.
