# Lil Tweak Operational Status

## Private localhost profile

| Component | Status | Detail |
|---|---|---|
| Backend | CONNECTED when launched | Authenticated FastAPI service restricted to `127.0.0.1` |
| Provider | CONNECTED when launched with qualification evidence | OpenAI Responses |
| Primary model | CONNECTED | `gpt-5.6-sol`, standard/high |
| Fallback model | CONNECTED | `gpt-5.6-terra`, read-only transient fallback only |
| Project Workspace | CONNECTED | Local SQLite, `NO MODEL CALL`, `ZERO TOKENS` |
| Planning Chat | CONNECTED | Tool-free; persisted usage, cost, model, and fallback state |
| Engineering Mode | CONNECTED | Tool-free repository reasoning; stops at `PLAN_READY` |
| Repository | CONNECTED read-only | Server-owned registry, fingerprint and snapshot binding |
| Browser | QUALIFIED, not persistently connected | Real Chrome acceptance passed; no browser authority granted |
| Runner | DISCONNECTED | No process transport injected |
| Execution | DISCONNECTED | No shell, patch, Git, filesystem mutation, or deployment |
| Git mutation | DISCONNECTED | Outside private reasoning boundary |
| GCP/public deployment | DISCONNECTED | Deferred |

The localhost server is intentionally stopped after acceptance. A stopped service must not be
displayed as connected. On launch, the server requires an explicit validated qualification record;
environment configuration alone cannot promote provider state to connected.

## Launch safety

- The launcher refuses to start unless Workbench and live model flags are explicitly enabled.
- The launcher requires a validated qualification evidence file.
- The configured bind host must be loopback.
- The owner key stays server-side; `.env.local` is not tracked.
- No process transport is constructed by the private launcher.
