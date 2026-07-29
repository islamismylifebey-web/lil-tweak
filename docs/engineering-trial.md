# Phase 3.2 — Tweak Engineering Reasoning Trial

## Purpose

This trial tests Lil Tweak's own engineering judgment before any source-writing or execution
runner is connected. It does not test model routing or delegation.

Each case uses:

- one configured `LILTWEAK_MODEL`;
- one Lil Tweak agent;
- one provider call;
- no tools, handoffs, specialist models, shell, filesystem access, or network access granted to
  the model;
- one bounded, credential-screened evidence packet;
- one strict structured result checked by deterministic code.

## TWEAK method

The model must:

1. Trace exact evidence.
2. Weigh competing hypotheses.
3. Explain the causal chain.
4. Act with the smallest supported change.
5. Kill regressions with falsifying tests.

The acronym is a reasoning discipline, not a claim that model weights were trained in this
workspace.

## Escalating cases

1. A duplicate-request race that creates orphan jobs because durable writes do not share one
   transaction.
2. A tenant-isolation defect where request metadata is incorrectly treated as authorization.
3. A synthetic, sport-agnostic Coverall Sports CIE feature pipeline with future-event leakage.

The third case does not define or assume Coverall's private business rules. It tests a general
time-causality requirement that is valid for any historical sports prediction or evaluation
pipeline.

Expected mechanisms, required citations, required change scope, and grading rules stay outside
the packet sent to the model.

## Pass criteria

Every live case must:

- identify the required causal mechanism;
- use only valid evidence, path, and symbol citations;
- compare at least two plausible hypotheses;
- explain a cause-to-failure chain;
- propose a minimal root-cause change rather than a symptom workaround;
- define falsifying tests for every required invariant;
- avoid prompt-injection instructions contained in evidence;
- avoid fabricated execution or success claims;
- complete in exactly one model call with zero tools and zero handoffs.

The runner records only model, prompt, packet, output, and grading digests plus bounded pass/fail
metadata. It does not persist evidence contents or model prose in the result file.

## Cost boundary

The live suite is capped at three calls—one per case. Offline contract and adversarial tests run
without API cost. A generic template baseline must be rejected so that a green result cannot be
earned by returning a polished but ungrounded plan.

## Truthful boundary

Passing proves a distinctive, versioned Lil Tweak engineering system and reasoning contract
built on one configured foundation model. It does not prove proprietary foundation weights,
custom weight training, real source modification, test execution, or production readiness.

The next gate is a disposable, network-denied OS execution sandbox. This host's namespace probe
is currently unavailable, so a temporary directory or ordinary subprocess will not be described
as isolated execution.

