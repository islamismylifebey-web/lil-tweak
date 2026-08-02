# Operations Runbook

Default posture: localhost, owner-only, model disabled, runner disconnected, network denied.

Startup checks: database and workspace are private; durable signing key exists in production; owner API key exists outside source; emergency stop state is known; model and runner status match configuration.

Incident actions: activate Emergency Stop, preserve database and recovery roots, export redacted evidence, identify the last approval and run, rotate affected secrets outside the application, and do not resume until the cause is understood.

Routine checks: session expiry, rate-limit behavior, evidence-chain verification, locked submission immutability, workspace inventory, recovery retention, provider spending ledger, runner qualification digest, and GCP examination binding.

Never clear emergency stop automatically.

