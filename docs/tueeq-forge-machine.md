# Tueeq Forge Machine V1

The Forge is Tueeq's reusable engineering invention machine. It is not a snippet folder and it does not silently install code. Its cycle is:

`Invent -> Prove -> Generalize -> Learn -> Master -> Invent`

## What it does

A **Piece** is a self-describing, content-addressed engineering artifact: implementation files, explicit contract, tests, provenance, and immutable identity/version. The Forge stores Pieces in an append-only Vault, exercises them in isolated Test World experiments, compares surviving implementations under explicit optimization profiles, studies the underlying mechanism through The Lens, and sends validated Discoveries toward skill/mastery systems through The Bellows.

## Trust model

The Forge deliberately separates experimentation from trust.

- The **Crucible** reuses Tueeq's existing durable Test World execution and judge contracts.
- The **Scale** applies hard gates before weighted optimization. A security/correctness failure cannot win because it is fast.
- The **Vault** never repoints an existing `(forge_id, version)` to different bytes.
- **Proven** requires independent trusted experiments in distinct environments plus clean-clone proof.
- **Novelty** received from a mastery system is a hypothesis only; it must return to the Crucible before becoming validated knowledge.
- **Clone** requires explicit authorization and refuses overwrites or secret-like material.

## The Lens

Every meaningful Piece must answer:

> What else can the mechanism inside this Piece do?

The Lens records verified uses separately from candidate uses. This is how The Forge can discover that technology created for one DAG, registry, evidence gate, lease protocol, or scheduler has a deeper structural use somewhere else without pretending the hypothesis is already true.

## The Bellows

The Bellows moves validated intellectual material between systems without merging their authority boundaries.

Forge -> mastery/skill:

- mechanism
- verified applications
- candidate applications clearly labeled as hypotheses
- evidence references
- questions and structural signature

Mastery/skill -> Forge:

- Novelty candidates
- novel combinations
- repeated failure patterns

A Novelty event never auto-promotes to a Discovery.

V1 exports a generic `MasterySink`/`MasteryIntake` interface. The existing `skill_forge` subsystem can consume the deterministic intake summary through its existing owner/evidence/model gates; The Forge does not bypass or modify Skill Forge authority.

## Example

```python
from pathlib import Path

from core.lil_tweak.forge_machine import (
    ArtifactFile,
    ForgeEngine,
    ForgeVault,
    Maturity,
    PieceArtifact,
    PieceContract,
)

vault = ForgeVault(Path(".forge-vault"))
engine = ForgeEngine(vault)

piece = PieceArtifact(
    forge_id="forge.optimization.contract-registry",
    name="Optimization Contract Registry",
    version="1.0.0",
    contract=PieceContract(
        problem="Resolve competing optimization objectives deterministically.",
        intended_use="Agent DAG arbitration.",
        inputs=("optimization contract", "runtime constraints"),
        outputs=("resolved policy", "decision evidence"),
        guarantees=("deterministic for identical inputs",),
        failure_modes=("invalid contract", "unsatisfiable contract"),
    ),
    files=(ArtifactFile("contract_registry.py", "..."),),
    tests=("python3 -m unittest",),
    provenance=(("origin_project", "tueiq-dag"),),
)

engine.register(piece)
engine.promote(piece.artifact_hash, Maturity.CANDIDATE, ())
```

Evidence from Crucible runs is then recorded before `TEMPERED` or `PROVEN` promotion.

## Authority boundaries

The Forge may test, try, compare, break, repair, refine, recommend, temper, prove, version, and clone when authorized.

It may not auto-install, silently upgrade, rewrite a released artifact, copy secrets, deploy, grant permissions, or change a host project merely because it found an improvement.

## Relationship to existing systems

- **Tueeq Test World**: execution/judging substrate for Crucible experiments.
- **Skill Forge V1**: existing portable-skill compiler and owner/evidence-gated export system; unchanged by this implementation.
- **Skill Mastery Machine**: connected through the generic Bellows mastery contract when its concrete runtime/module is installed. The Forge does not invent a fake implementation when one is not present.

This separation keeps code memory, engineering knowledge, and mastered capability distinct while allowing each to compound the others.
