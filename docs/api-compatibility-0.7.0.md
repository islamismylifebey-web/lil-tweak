# API Compatibility: 0.6.0 to 0.7.0

Version 0.7.0 is additive at the HTTP operation level. An automated test asserts that every 0.6.0
health, job, inspection, planning, recovery, approval, emergency-stop, Creator, learning, and
live-model path-and-method pair remains registered.

Five authenticated repository verification routes are added:

- `POST /v1/creator/executions`
- `GET /v1/creator/executions/{execution_id}`
- `POST /v1/creator/executions/{execution_id}/decision`
- `POST /v1/creator/executions/{execution_id}/run`
- `GET /v1/creator/executions/{execution_id}/result`

Existing signed Creator briefs, route decisions, live proposals, work orders, job records, and
recovery contracts are unchanged. The Creator health version becomes `0.7.0`; its execution flags
remain false for the included candidate adapter. A future independently qualified executor must
be explicitly injected before those fields can report repository verification connectivity; the
0.7 Bubblewrap candidate cannot report connected even if its narrow smoke probe succeeds.

This compatibility evidence is intentionally path-and-method-level, plus the existing behavioral
regression suite. It is not presented as a byte-identical 0.6 OpenAPI schema: Creator health
widens its two repository-execution fields from literal false to booleans so a future qualified
runner can report state.

When no repository execution controller is configured, the new routes return a controlled
service-unavailable response. Existing routes keep their prior authentication and behavior.
