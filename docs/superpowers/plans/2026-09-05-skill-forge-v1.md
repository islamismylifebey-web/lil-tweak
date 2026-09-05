# Skill Forge V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Compile generalized solutions into verified, owner-approved portable agent skills.
**Architecture:** Pure immutable compiler; bounded evaluator protocol; owner-scoped SQLite library and explicit trusted approval callback. CLI produces unverified previews only.
**Tech Stack:** Python 3.12, standard library, unittest, existing npm canonical verification.
**Spec:** docs/superpowers/specs/2026-09-05-skill-forge-v1-design.md

## Global Constraints
- Additive files only; no existing runner, UI, auth, deployment or execution authority changes.
- No external dependencies, network calls, subprocess execution or paid model calls in production compiler code.
- No automatic publication or self-issued approval; no unverified success claims.
- At most 64 resource files, 128 KiB/file, 1 MiB/package; 12 cases/evaluation; bounded time.

### Task 1: Immutable draft and portable compiler
Files: `core/lil_tweak/skill_forge/package.py`, `core/tests/test_skill_forge.py`.
- [ ] Write real format, deterministic hashing, schema, path and privacy rejection tests before implementation.
- [ ] Run `python3 -m unittest discover -s core/tests -p 'test_skill_forge.py'`; observe missing implementation.
- [ ] Implement `compile_draft(data: dict) -> Package`, `verify_package(files: Mapping[str, bytes]) -> str` with exact schema validation, quoted YAML, bounded immutable files and canonical digest.
- [ ] Re-run tests; verify forged manifest and case-collision tests fail without defenses.

### Task 2: Bounded fresh-context evaluator
Files: `core/lil_tweak/skill_forge/evaluation.py`, focused tests in same unittest file.
- [ ] Write async tests: correct output, wrong output, missing tools, wrong request binding, repeated session, timeout, oracle/transcript isolation and distinct origin/transfer reports.
- [ ] Observe RED, then implement `evaluate(package, cases, adapter, role) -> Report` with strict trusted adapter contract and deterministic grading.
- [ ] Ensure model success claims cannot set grading and first failure stops evaluation.

### Task 3: Durable owner library and approval-gated export
Files: `core/lil_tweak/skill_forge/library.py`, focused tests.
- [ ] Test persistence/reopen, owner isolation, immutable version collision, stale/forged/replayed approvals, changed evidence, revocation and deterministic ZIP integrity.
- [ ] Observe RED, then implement `Library.add`, `Library.evaluate`, `Library.prepare_release`, `Library.approve`, `Library.export`, `Library.activate`, `Library.revoke`.
- [ ] Approval is a trusted host callback, not model-facing boolean. Use exact release digest and explicit audience, privacy and rights review.

### Task 4: Runnable integration, docs and CI
Files: `core/lil_tweak/skill_forge/__init__.py`, `__main__.py`, `examples/skill-forge-icon-inspector.json`, `docs/skill-forge.md`, `.github/workflows/skill-forge-ci.yml`.
- [ ] Add CLI tests for template, validate and preview without any approval, publication or execution operation.
- [ ] Add example generalized icon inspection method and documented Python integration contract; explicitly document live adapter qualification.
- [ ] Run focused tests, compileall, Ruff, mypy where available; record actual environment limits.
- [ ] Push exact byte-matched files to feature branch and open PR.
- [ ] Run read-only GitHub-hosted canonical verification and report exact SHA and actual checks. No merge/deploy.
