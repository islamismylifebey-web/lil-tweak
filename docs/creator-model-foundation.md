# Creator Model Foundation 0.5.0

Lil Tweak now has a deterministic Creator Model control plane in front of any future model,
tool, sandbox, or provider call.

## Governing cycle

1. Perceive reality.
2. Identify the functional gap.
3. Discover constraints.
4. Determine what must exist.
5. Create the smallest effective intervention.
6. Test against reality.
7. Verify causality.
8. Retain verified causal learning.

The cycle is structural data in every compiled brief. It is not merely prompt language.

## Prompt compiler

`POST /v1/creator/compile` converts natural Founder direction into a signed, digest-bound
executable brief. It:

- preserves the exact direction;
- classifies the work without expanding authority;
- names deliverables and acceptance criteria;
- extracts explicit and negative constraints;
- converts subjective visual phrases such as “shine,” “electric,” “clean,” and “fluid” into
  controllable qualities and failure conditions;
- asks only when a missing target materially changes the work;
- detects high-stakes domains and records prerequisites that only the trusted harness may
  satisfy;
- rejects credential-shaped input before compilation.

The caller cannot submit an authority object. Authority is added only from authenticated
server context.

## Adaptive router

`POST /v1/creator/route` accepts only a signed brief envelope. It selects the least costly
capable tier by task complexity and capability requirements, then returns:

- model tier;
- reasoning effort;
- context and turn ceilings;
- suggested tools;
- escalation and de-escalation triggers;
- a synthetic cost score.

The decision is a preview. It grants no model, tool, spending, source-write, execution, or
deployment authority. High-stakes work remains blocked until current validated sources, safety
constraints, domain review, and authority arrive through the trusted harness. Caller-asserted
“evidence” is rejected by the API schema.

## Causal learning

Learning records are append-only SQLite rows. A record is accepted only when:

- a trusted-harness HMAC verifies the outcome envelope;
- the problem and intervention match the proposed learning;
- at least one observed check supplies an evidence digest;
- success or failure is recorded from observed checks rather than caller prose.

Duplicate verified outcomes return the existing immutable record. No public endpoint can create
learning records.

## Execution boundary

Version 0.5.0 does not connect a sandbox or authorize model calls. The official Agents SDK
control-plane split is preserved: approvals, budgets, signatures, learning, and recovery remain
in the trusted harness; future disposable compute will receive only bounded workspace work.

The next execution phase must add an isolated sandbox adapter, exact approval consumption,
artifact review, and test-result capture without moving trusted control state into model-directed
compute.
