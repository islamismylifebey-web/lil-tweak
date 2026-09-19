# Tueeq Forge Machine V1 design

Approved direction: build The Forge as a new additive subsystem beside Tueeq's durable Test World and the existing Skill Forge V1. The Forge discovers, tests, compares, generalizes, proves, versions, and safely clones reusable engineering Pieces. It never silently mutates a host project or rewrites a released artifact.

## Prime contract

Preserve inventions as independently understandable, reproducibly clonable, verifiably correct artifacts while never allowing reuse to create hidden coupling or unauthorized change.

A Forge Piece is implementation + contract + tests + provenance + clone policy. A released identity/version is immutable and content addressed.

## Machine boundaries

The Forge may discover, extract, index, test, try variants, compare, benchmark, break, repair, refine, recommend, temper, prove, version, and clone when explicitly authorized.

The Forge may not auto-install into a project, silently upgrade a Piece, modify a released version, copy secrets, or change host-project behavior without an explicit clone/adoption action.

## Components

### Forge Core and Vault

`core/lil_tweak/forge_machine/` is standard-library-only. `ForgeVault` is a content-addressed, append-only filesystem vault. Piece artifacts, evidence bundles, promotions, discoveries, Bellows events, and clone receipts are written once. The `(forge_id, version)` ref may never point at a different artifact hash.

### Crucible

The Forge does not build a second sandbox runtime. `TestWorldCrucible` adapts a Piece experiment into the existing durable Tueeq Test World contract. The Test World remains the execution authority: bounded repository/commit, deterministic checks, lease-controlled attempts, no external actions, and trusted-core judging. Forge experiments receive their own worlds/attempts and convert terminal Test World results into Forge evidence.

### Trial evidence

Evidence binds the exact Piece hash, experiment id, environment fingerprint, checks, metrics, and observation. Evidence can be trusted only when it came from a terminal judged execution. Claims of quality are never accepted from an agent self-report.

### Scale

Comparison evaluates hard gates before optimization. Correctness/security/contract/reproducibility failures cannot be traded for speed or cost. Surviving candidates are scored by an explicit optimization profile whose metric directions and weights are recorded. Different profiles may legitimately select different winners.

### Promotion

Maturity is `raw -> candidate -> tempered -> proven -> relic`.

- Candidate requires a valid, secret-free Piece contract.
- Tempered requires trustworthy evidence passing contract compliance, correctness, security, and reproducibility.
- Proven requires at least two trustworthy experiments with distinct environment fingerprints and at least one clean-clone proof.
- Released artifact bytes never change during promotion.

### Lens

Every tempered/proven Piece must be examined through The Lens. The mandatory question is: **What else can the mechanism inside this Piece do?**

The Lens separates verified applications from candidate applications. Hypotheses are never promoted to knowledge merely because they sound plausible. Mechanism compositions and candidate uses return to the Crucible for evidence.

### Bellows

The Bellows is an explicit knowledge bridge, not shared mutable state.

Forge -> mastery/skill systems: validated Discovery packages containing mechanism, verified uses, candidate uses, evidence references, tradeoffs/questions, and provenance.

Mastery/skill systems -> Forge: Novelty candidates. Novelty is stored as a hypothesis/event and must return to the Crucible before it can become a Discovery.

V1 includes a generic `MasterySink` protocol plus a deterministic intake structure that can feed the existing Skill Forge authoring layer without changing Skill Forge internals. This is intentionally an adapter boundary because the exact Tueeq Skill Mastery implementation is not present as a named module in this repository.

### Clone engine

Cloning is explicit and local to a caller-supplied target root. It rejects unauthorized requests, unsafe relative paths, secret-like material, and existing-path conflicts. A successful clone writes a receipt binding Piece hash, target, and files created. The canonical vault artifact is never modified.

## Piece contract

A Piece declares:

- stable `forge_id` and semantic version
- problem and intended use
- explicit inputs/outputs
- guarantees and failure modes
- side effects and dependencies
- source files
- verification commands/tests
- provenance

No hidden runtime context or secret material is permitted.

## Evidence invariants

1. Every evidence bundle names the exact Piece hash it evaluated.
2. Every comparison names the evidence used.
3. Hard-gate failure rejects a candidate before weighted scoring.
4. Proven requires independent evidence, not repeated scoring of one run.
5. Failed/losing experiments remain valid engineering knowledge and are not deleted.

## V1 scope

V1 builds the trusted deterministic substrate: Piece contracts, immutable Vault, promotion gate, Scale, Lens, Bellows, Crucible adapter, clone engine, tests, CI, and operator documentation.

V1 does not autonomously call an LLM, mutate GitHub repositories, deploy code, configure infrastructure, or replace the existing Skill Forge. Future Smith workers may generate variants only through these contracts.

## Success criteria

- Existing source remains untouched; implementation is additive.
- Exact identity/version cannot be silently replaced.
- Secret-like content is rejected before vault admission/cloning.
- Hard gates beat optimization weights.
- Context-specific profiles can select different valid winners.
- `proven` cannot be reached without independent trusted evidence and clean-clone proof.
- The Lens always asks the secondary-use question and separates hypotheses from verified uses.
- Bellows Discovery and Novelty flows are one-way contracts; Novelty cannot become knowledge without Forge evidence.
- Crucible experiments use the existing Test World store/attempt contract.
- Clone requires explicit authorization and emits a receipt.
- Focused CI, strict typing/linting, and full repository verification pass.
