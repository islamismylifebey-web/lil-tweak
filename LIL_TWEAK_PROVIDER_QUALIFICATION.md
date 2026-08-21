# Lil Tweak Provider Qualification

## Result

**PASSED** — the account returned the exact provider-facing model identifiers
`gpt-5.6-sol` and `gpt-5.6-terra` through the OpenAI Responses API.

| Profile | Model | Mode | Effort | State |
|---|---|---|---|---|
| Primary / ordinary | `gpt-5.6-sol` | standard | high | LIVE_QUALIFIED |
| Degraded read-only fallback | `gpt-5.6-terra` | standard | high | LIVE_QUALIFIED |

The qualification used synthetic nonsecret prompts, no tools, `store:false`, disabled sensitive
tracing, bounded output, and response-ID digests rather than provider response IDs. The two model
identity calls consumed 224 total tokens and recorded `$0.001606` combined estimated cost.

## Qualified behavior

- Authentication and exact effective-model identity.
- Strict structured output and malformed-output fail-closed handling.
- Refusal and incomplete-response handling.
- Timeout and cancellation classification.
- Provider token/usage reconciliation and cost calculation.
- Cached-input telemetry.
- Continuation/compaction preservation contracts.
- Retry behavior and fallback allowlist/denylist.
- One unbilled, pre-response retry for Sol on rate limit, timeout, or service unavailability only.

Terra fallback is forbidden for authentication, quota/billing, entitlement, invalid request/model,
owner/policy lock, refusal, incomplete response, malformed output, usage mismatch, model mismatch,
or sensitive-input rejection. Engineering plans never fallback to Terra because they are
authoritative work; transient Sol recovery is bounded to one unbilled pre-response retry.

## Live operational observations

- Planning Chat: Sol, no fallback, 173 input, 158 output, 44 reasoning, 331 total tokens,
  `$0.005605`; the UI and append-only SQLite ledger matched.
- Engineering Mode: Sol, 10,450 input and 1,847 output tokens; structured plan accepted and bound
  to the repository snapshot.
- A provider request using an unsupported verbosity hint was rejected as `INVALID_REQUEST` with
  zero usage during activation and was removed. This verified that SDK type acceptance is not
  treated as account/model support.
