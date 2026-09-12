# Tueeq Forge Machine V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build The Forge as an additive, evidence-governed invention machine that reuses Tueeq's Test World for experiments and connects validated discoveries to skill/mastery systems through The Bellows.

**Architecture:** Create a standard-library-only `core/lil_tweak/forge_machine` package. Use immutable content-addressed filesystem records for the Vault; pure deterministic functions for Scale/Lens/Bellows; an adapter over the existing `TestWorldStore` contract for Crucible execution; and an authorization-gated clone engine. Do not modify existing Test World or Skill Forge internals.

**Tech Stack:** Python 3.12 standard library, `unittest`, existing Tueeq Test World contracts, GitHub Actions, ruff 0.12.10, mypy 1.17.1.

**Spec:** `docs/superpowers/specs/2026-09-07-tueeq-forge-machine-v1-design.md`

## Global Constraints

- New Forge implementation is additive under `core/lil_tweak/forge_machine/`.
- Existing Test World and Skill Forge behavior must remain unchanged.
- Released Piece `(forge_id, version)` identities are immutable and content addressed.
- No secrets may enter the Vault or be cloned.
- Hard gates run before optimization scoring.
- `proven` requires two trustworthy experiments with distinct environments and one clean-clone proof.
- Novelty is a hypothesis until the Crucible produces validating evidence.
- Cloning requires explicit authorization and must never overwrite existing target files.
- No new runtime dependency, provider, deployment, credential, network permission, or production mutation.

---

### Task 1: Lock contracts with failing tests and CI

**Files:**
- Create: `core/tests/test_forge_machine.py`
- Create: `.github/workflows/forge-machine-ci.yml`

**Interfaces:**
- Consumes: existing `core.lil_tweak.test_world` domain contracts.
- Produces: executable behavioral contract for all V1 Forge modules.

- [ ] **Step 1: Write tests for immutable identity/version, secret rejection, promotion gates, hard-gate comparison, profile-specific winners, Lens questions, Bellows flows, Test World Crucible adaptation, and authorization-gated cloning.**
- [ ] **Step 2: Push tests without production Forge code and confirm focused CI fails because `core.lil_tweak.forge_machine` does not exist.**
- [ ] **Step 3: Keep the RED commit in branch history as evidence that the tests exercise new behavior.**

### Task 2: Piece contracts and immutable Vault

**Files:**
- Create: `core/lil_tweak/forge_machine/model.py`
- Create: `core/lil_tweak/forge_machine/vault.py`
- Create: `core/lil_tweak/forge_machine/__init__.py`

**Interfaces:**
- Consumes: `pathlib.Path`, standard-library hashing/JSON.
- Produces: `PieceContract`, `ArtifactFile`, `PieceArtifact`, `CheckEvidence`, `TrialMetric`, `EvidenceBundle`, `Maturity`, `ForgeVault`, typed Forge errors.

- [ ] **Step 1: Implement strict validation for Forge IDs, semantic versions, relative artifact paths, non-empty contracts, and immutable tuples.**
- [ ] **Step 2: Canonicalize Piece content and derive a SHA-256 artifact hash from exact contract/files/tests/provenance.**
- [ ] **Step 3: Reject common secret markers (`OPENAI_API_KEY=`, `sk-`, `ghp_`, PEM private-key headers) before Vault admission.**
- [ ] **Step 4: Implement append-only Vault records with create-exclusive writes for Pieces, refs, evidence, promotions, discoveries, Bellows events, and clone receipts.**
- [ ] **Step 5: Reject any attempt to repoint an existing `(forge_id, version)` reference to different bytes.**

### Task 3: Promotion engine

**Files:**
- Create: `core/lil_tweak/forge_machine/engine.py`

**Interfaces:**
- Consumes: `ForgeVault`, `PieceArtifact`, `EvidenceBundle`, `Maturity`.
- Produces: `ForgeEngine.register`, `record_evidence`, `promote`.

- [ ] **Step 1: Permit monotonic `raw -> candidate -> tempered -> proven -> relic` promotion only.**
- [ ] **Step 2: Require trustworthy contract-compliance, correctness, security, and reproducibility gates for `tempered`.**
- [ ] **Step 3: Require at least two trustworthy experiments with distinct environment fingerprints plus a passing `clean_clone` check for `proven`.**
- [ ] **Step 4: Record promotion as immutable evidence-linked events without rewriting Piece bytes.**

### Task 4: Scale comparison engine

**Files:**
- Create: `core/lil_tweak/forge_machine/scale.py`

**Interfaces:**
- Consumes: `EvidenceBundle`, `OptimizationProfile`.
- Produces: `ComparisonResult`, `compare_candidates`.

- [ ] **Step 1: Reject candidates missing or failing any hard gate before scoring.**
- [ ] **Step 2: Normalize surviving metric values per candidate set and support explicit `min`/`max` metric direction.**
- [ ] **Step 3: Compute deterministic weighted scores and preserve ties.**
- [ ] **Step 4: Return rejected candidates with gate reasons and the evidence IDs used.**

### Task 5: Lens and Bellows

**Files:**
- Create: `core/lil_tweak/forge_machine/lens.py`
- Create: `core/lil_tweak/forge_machine/bellows.py`

**Interfaces:**
- Consumes: `Mechanism`, `Discovery`, `Novelty`, `ForgeVault`.
- Produces: `secondary_use_questions`, `build_discovery`, `Bellows`, `MasterySink`, `MasteryIntake`.

- [ ] **Step 1: Make `What else can the mechanism inside this Piece do?` mandatory in every Lens question set.**
- [ ] **Step 2: Store verified applications separately from candidate applications; candidate uses cannot be promoted by construction.**
- [ ] **Step 3: Publish Discovery packages to a generic mastery sink with evidence references and provenance.**
- [ ] **Step 4: Accept Novelty only as a `novelty_candidate` Bellows event; do not create a Discovery or promotion.**
- [ ] **Step 5: Provide deterministic Skill Forge/mastery authoring intake text without invoking a model or changing Skill Forge.**

### Task 6: Crucible adapter over Tueeq Test World

**Files:**
- Create: `core/lil_tweak/forge_machine/crucible.py`

**Interfaces:**
- Consumes: existing `TestWorldStore`, `TestCheck`, terminal `TestWorldAttempt`.
- Produces: `CrucibleExperiment`, `TestWorldCrucible.open_experiment`, `capture_evidence`.

- [ ] **Step 1: Create a Forge-specific Test World whose objective binds the Piece hash and explicitly preserves the existing bounded/no-external-action execution contract.**
- [ ] **Step 2: Enqueue exactly one initial attempt through the existing store with deterministic idempotency keys.**
- [ ] **Step 3: Convert only terminal judged attempts into evidence; map Test World feedback to immutable Forge checks.**
- [ ] **Step 4: Mark runtime-error evidence untrustworthy so it cannot satisfy promotion gates.**

### Task 7: Explicit clone engine

**Files:**
- Create: `core/lil_tweak/forge_machine/clone.py`

**Interfaces:**
- Consumes: `PieceArtifact`, target `Path`, explicit `authorized: bool`.
- Produces: `ClonePlan`, `CloneReceipt`, `CloneEngine.plan`, `clone`.

- [ ] **Step 1: Plan files and surface conflicts without mutation.**
- [ ] **Step 2: Reject unauthorized cloning, unsafe paths, secret-like material, and any existing target path.**
- [ ] **Step 3: Create parent directories and exact Piece files only after all preflight checks pass.**
- [ ] **Step 4: Write an immutable clone receipt to the Vault after successful copy.**

### Task 8: Documentation and full verification

**Files:**
- Create: `docs/tueeq-forge-machine.md`
- Verify: all files above.

**Interfaces:**
- Consumes: completed V1 package.
- Produces: operator-facing explanation and verification evidence.

- [ ] **Step 1: Document the machine cycle `Invent -> Prove -> Generalize -> Learn -> Master -> Invent`, authority boundaries, and example flow.**
- [ ] **Step 2: Run focused Forge `unittest` suite.**
- [ ] **Step 3: Run ruff and strict mypy for `forge_machine`.**
- [ ] **Step 4: Run canonical `npm run verify` to prove the additive subsystem does not regress the repository.**
- [ ] **Step 5: Open a pull request from `feature/tueeq-forge-machine-v1` to `main` with exact CI evidence; do not merge without a separate explicit user instruction.**
