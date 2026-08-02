# Lil Tweak Model Activation

The OpenAI Agents SDK planning adapter is implemented and tested offline, but it is intentionally
disabled when no provider credential is configured. The application never stores an API key in
the repository, browser, database, task evidence, or generated artifact.

## One activation step

Start the private server with both values supplied by the local secret manager or process
environment:

```bash
OPENAI_API_KEY='<owner-managed-key>' \
LILTWEAK_WORKBENCH_MODEL_ENABLED=true \
uv run uvicorn liltweak.api:create_app --factory --host 127.0.0.1 --port 8765
```

Keep all other private-launch variables from `LIL_TWEAK_LAUNCH_AND_OPERATIONS.md`. Do not put the
key in `.env.example`, source control, frontend storage, task text, or repository mappings.

## Activation gates

- `LILTWEAK_WORKBENCH_MODEL` must have a server-owned price schedule.
- `LILTWEAK_WORKBENCH_REASONING_TIER` must be an allowed tier.
- Per-call and monthly cost ceilings must pass before the request.
- The adapter performs exactly one model turn with no tools or handoffs.
- Provider retries are zero and a server timeout applies.
- Input/output token ceilings are checked.
- The full structured plan is secret-screened and policy-validated before owner approval.

Activating the model does not activate command execution. Runner qualification and a separately
signed connection authorization are still mandatory.
