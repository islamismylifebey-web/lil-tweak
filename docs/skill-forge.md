# Skill Forge V1

Skill Forge turns a **generalized solution** into a portable Agent Skills package.
It includes a host-model authoring adapter, deterministic compiler, fresh-context
evaluation protocol, durable owner-scoped library, and one-time approval-gated
activation/export. It adds no production model, runner, authentication route or UI.

## What works now

The Python service and CLI are implemented and covered by focused tests. A configured
host can call `propose` to extract a method with its existing model, compile the result,
run internal and transfer holdouts, request owner approval, and return a verified ZIP.
The CLI can validate a draft or print its `SKILL.md` without any external service.

**Not activated in the deployed Tweeq application:** this change deliberately does not
register model tools in the current orchestration loop or add Sites routes. No real model,
source-evidence verifier, independent agent or owner-approval callback is installed by
importing this package. No live cross-agent qualification, merge or deployment is claimed.
Test adapters are deterministic fixtures, not evidence that a real agent learned a skill.

## Run the compiler

Use the repository's supported Python 3.12 environment, from the repository root:

```sh
PYTHONPATH=core python3 -m lil_tweak.skill_forge schema
PYTHONPATH=core python3 -m lil_tweak.skill_forge validate < examples/skill-forge-icon-inspector.json
PYTHONPATH=core python3 -m lil_tweak.skill_forge preview < examples/skill-forge-icon-inspector.json
python3 -m unittest discover -s core/tests -p 'test_skill_forge*.py'
```

The example is **synthetic and unverified**, including its example source/evidence
digests. It is an illustration of the input format, not a claimed solved production job.
`schema` describes the model-authored fields; the trusted host adds `origin` afterward.
The full draft accepted by `validate` also requires `origin.agent_id`,
`origin.source_digest` and `origin.evidence_digest` (SHA-256 values).

`preview` writes only `SKILL.md` to stdout and an unverified notice to stderr.
There is no CLI approve, activate, export, execute or publish command. Library export
returns bytes to an authenticated host; it does not write or send them anywhere.

## Portable package

```text
icon-inspector/
  SKILL.md
  manifest.json
  tests/examples.json
  references/notes.md
  evidence.json             # only in a qualified release
  scripts/                  # optional, never run by the compiler
  assets/                   # optional
```

The compiler emits the Agent Skills format with required `name` and `description`,
quoted YAML strings, compatibility requirements and version metadata. It deliberately
omits `allowed-tools`: instructions and tool requirements do not grant permissions.
`manifest.json`, `tests/examples.json` and `evidence.json` are Skill Forge extensions,
not universal Agent Skills requirements. An agent without skills support needs its
host to load the instructions; scripts also require the target runtime and tool access.

The manifest hashes every non-manifest file. The package digest hashes the complete
file-hash map, including the manifest. Release assembly adds evidence and updates the
manifest, yielding a different release digest. The ZIP is sorted, uncompressed, fixed-
timestamp, regular-file-only and deterministic for those exact bytes.

## Trusted integration boundary

Create a dedicated SQLite connection in the trusted core. Keep its database outside
all agent sandboxes, private to the host user, with owner-checked routing and suitable
backup/retention. Do not share the connection with unrelated application transactions.
This library is not an HTTP authentication layer or a production migration framework.

```python
from lil_tweak.skill_forge import Library, propose

# These dependencies are supplied by the authenticated host, not the model.
# authenticated_owner must come from the existing owner gate.
library = Library(private_connection, source_verifier=verify_source_evidence,
                  authorizer=request_exact_owner_decision)
candidate = await propose(
    library, authenticated_owner,
    name="icon-inspector", version="1.0.0",
    origin=verified_job_origin,
    solution_summary=generalized_privacy_reviewed_summary,
    author=existing_budget_authorized_model_adapter,
)
await library.evaluate(authenticated_owner, candidate, trusted_holdouts,
                       qualified_tweeq_adapter, "internal")
await library.evaluate(authenticated_owner, candidate, trusted_holdouts,
                       qualified_other_agent_adapter, "transfer")
summary = library.prepare_release(authenticated_owner, candidate)
# Show summary and exact package content through the private owner review route.
grant = library.approve(authenticated_owner, candidate, "recipient-agent", "export")
archive_bytes = library.export(authenticated_owner, candidate, "recipient-agent", grant)
```

The names above are application dependencies, not hidden configured implementations:

- `verify_source_evidence(owner, origin) -> bool` must resolve the exact source digest
  and successful solution-evidence digest in authoritative owner-scoped storage.
  Return literal `True` only after verification. Missing/failed verification blocks.
- The author adapter accepts `AuthorRequest` and returns JSON text. Use the existing
  model selection and cost approval, honor output/time limits, and do not give this
  authoring call side-effecting tools. It is called once, without retry or fallback.
- `Adapter` accepts `Request` and returns `Observation`. It is registered by the trusted
  host, never constructed from model JSON. The host must prove fresh sessions, package-
  only context, sandbox isolation, tool allowlists, cancellation, step and cost limits.
  The isolation-contract string is an explicit obligation, **not remote attestation**.
- The owner callback accepts `ApprovalRequest` and returns `Decision` tied to the owner,
  release digest, recipient, purpose and a unique decision ID. It must show the exact
  content for privacy/rights review and return literal booleans. No default allow exists.
  Never register `approve`, `revoke`, raw SQLite access, or the callback as model tools.

`catalog` reports stored candidate state; it does not automatically advertise or load
skills into Tweeq. `activate` requires a separate `activate` grant and the required
available tools. It returns instructional files, not execution authority. Publication,
installation, paid evaluation and production activation remain separate host decisions.

## Verification and invalidation

Each host-authored suite has 3–12 unique held-out cases: positive, malformed/negative
and missing-tool behavior. Public examples cannot be reused as holdout inputs. The
adapter sees only its case input, instructional resources and allowed tools; it never
receives holdout answers, original conversation, other cases, evidence or credentials.
Public examples are embedded in `SKILL.md`. Expected answers remain with the grader.

The grader checks exact output/status, tool usage, request digest, nonce and unique
session identifiers. A model-supplied success flag cannot pass a case. The first failure
stops evaluation. A cooperative callback has a 60-second maximum suite budget and
12-step request limit. A real runtime must enforce termination and resource/cost limits
outside the model; Python timeouts cannot qualify an arbitrary uncooperative backend.

Internal verification must use the originating agent ID; transfer verification must
use a different configured agent ID. This records the tested target, not universal
compatibility. A different name alone does not prove real independent-agent isolation.
The exact held-out suite and result hashes are recorded; raw outputs and exceptions
are not exported. Source evidence is rechecked before authoring, evaluation and release.

Candidates are immutable per owner/name/version. States are `COMPILED`,
`INTERNAL_VERIFIED`, `TRANSFER_VERIFIED`, and `REVOKED`. Approval is a separate bounded
grant. A new evaluation invalidates previous unused grants before calling the adapter.
Atomic database revision increments reject stale concurrent results. New package bytes,
failed/changed evidence, revocation or expiry block old grants. Export/activation consume
a grant atomically once; an already used owner decision ID cannot mint another grant.
Revocation is terminal for that version; a corrected skill needs a new version.

## Security and limits

At most 64 resources, 128 KiB per file, 1 MiB total package, 100 candidates and 10,000
append-only application audit events per owner. Export approvals last at most 900
seconds. Capacity exhaustion fails closed; retention must be an explicit host operation.

Reject traversal, absolute paths, dotfiles, Windows-reserved names, file/directory and
case-fold collisions, unknown fields, duplicate JSON keys, invalid UTF-8, selected
credential/private-data patterns and known privilege-bypass language. Large nonmatching
scanner input has a regression test against catastrophic regex backtracking.

Pattern scanning is **not a complete privacy, licensing, prompt-injection or malware
proof**. Owner privacy/rights review is mandatory; executable resources still require
code review and sandboxing. Hidden/encoded secrets can evade pattern scanning.

Hashes establish byte integrity, not publisher identity or trust. The evidence file is
an assertion by the configured trusted host, not a cryptographic signature. A recipient
must obtain an expected digest through a trusted channel and can then call:

```python
verify_package(files, expected_digest=trusted_release_digest)
```

Do not trust a self-reported digest bundled by an unknown publisher. This V1 does not
install arbitrary external skill archives or extract/run their contents.

## Source and implementation references

- https://agentskills.io/specification
- https://agentskills.io/client-implementation/adding-skills-support
- `docs/superpowers/specs/2026-09-05-skill-forge-v1-design.md`
- `docs/superpowers/plans/2026-09-05-skill-forge-v1.md`

References checked September 5, 2026. The existing runner, Sites UI, authentication,
models, infrastructure and deployment files are unchanged by this feature.
