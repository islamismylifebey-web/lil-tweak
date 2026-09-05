# Skill Forge V1 design

Approved direction: turn a solved problem into a reusable engineering method and export a portable Agent Skills `SKILL.md` package for other agents.

## Boundaries
Build an additive, standard-library-only Python subsystem in `core/lil_tweak/skill_forge`. No change to Sites, model routing, authentication, execution authority, existing runner, deployment, or existing database schemas. A command-line preview and a Python integration service make the compiler usable without enabling an unqualified production adapter. The library accepts structured, generalized methods; it does not claim that a deterministic compiler can invent/generalize an arbitrary transcript. Agent-authored candidates remain unverified until evaluated.

## Data and compilation
Strict, immutable drafts bind name, semantic version, originating agent, exact source SHA-256 and solution-evidence SHA-256. Include description, applicability, typed text inputs/outputs, ordered steps, required tools, stop conditions, public examples, and optional UTF-8 scripts/references/assets. No secret harvesting. Scan every export field and file for recognizable credential/private-data patterns and reject unsafe paths, reserved names, case collisions, excess size and unknown fields. The owner must review privacy and rights; scanning is not a complete privacy/security proof.

Compile deterministically to `SKILL.md`, `manifest.json`, `tests/examples.json` and optional resources. YAML frontmatter uses safe quoted strings, matching directory name, and no permission-granting `allowed-tools`. A content digest binds every byte. Descriptions/requirements are portable instructions, not new execution permissions.

## Verification
The trusted host supplies an evaluator adapter and a held-out test suite, never model-submitted success booleans. Each test receives only package instructional resources and its input, not expected answers, original conversation, other cases or credentials. A fresh request/session nonce and package digest bind observations. The host enforces tool requirements, time/case bounds and exact-output grading. Record internal and independent-agent evaluation separately; a different agent ID alone is not a proof of independent environment isolation. An adapter must explicitly implement a trusted isolation contract; absent adapters block evaluation. Failed/timeout/mismatched observations fail closed. Fresh-context behavior and real agent performance remain live qualification requirements.

## Durable library and release
Owner-scoped SQLite metadata records immutable drafts, bounded verification reports, approval and export events. Reusing name/version with different bytes is rejected. Reports are generated through the configured evaluator path, not imported from client JSON. Latest failed verification invalidates older approval. Export is bound to exact package plus report digests, explicit audience, privacy/rights review, expiry and a one-time grant issued through a trusted owner-approval callback. No default allow, no model access to approval issuance. ZIP bytes are deterministic and never extracted/executed by the compiler. Revocation blocks activation/export. A consumer can verify all package hashes; integrity is not publisher authenticity.

## Delivery and evidence
Add focused unittest tests, an example draft and a CLI for schema/template, validate, preview. Add a read-only GitHub-hosted CI workflow for exact-candidate focused/static/full canonical verification. Commit on `feature/skill-forge-v1` from `6f59d8ddc95db083e062a5b4b626df13fcdfcbf0`; open a PR. Do not merge or deploy. Clearly distinguish tested library functionality from missing live model/runner/UI activation.

## Specification references
https://agentskills.io/specification
https://agentskills.io/client-implementation/adding-skills-support
Checked 2026-09-05. The tests/evidence/approval conventions are Skill Forge extensions, not universal Agent Skills requirements.
