# Lil Tweak Updated Capability Report

## Activation profile

| Capability | Result | Model tokens |
|---|---|---:|
| Private loopback backend and owner authentication | PASS | 0 |
| OpenAI provider and exact model routing | PASS | qualification only |
| Project Workspace CRUD/import/export/search/attachments | PASS | 0 |
| Planning Chat | PASS | recorded per turn |
| Engineering repository inspection and plan generation | PASS | recorded per admission |
| Structured output/refusal/malformed/timeout/cancellation handling | PASS | bounded live + deterministic |
| Real desktop/mobile browser flow | PASS | only Planning/Engineering steps |
| Session revocation | PASS | 0 |
| Read-only repository binding and secret screening | PASS | 0 |
| Runner non-bypass boundary | PASS | 0 |

The existing offline discovery remains **10 PASS / 10 BLOCKED / 0 FAIL**. The blocked entries are
not weakened by activation:

1. Shell execution.
2. Patch application.
3. Filesystem mutation.
4. Git mutation or commit.
5. Browser automation authority.
6. Deployment.
7. GCP access.
8. External checkpoint writes.
9. Repository publisher writes.
10. Independent completion/examiner authority.

Project Workspace guarantees `NO MODEL CALL` and `ZERO TOKENS`. Planning Chat and Engineering Mode
have `ToolAuthority.NONE`. Engineering can produce a controller-reviewable plan, but without a
runner it does not publish an approval and cannot advance beyond `PLAN_READY`.
