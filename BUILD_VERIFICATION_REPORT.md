# Lil Tweak Live Workbench — Builder Verification Report

## Result

The supplied full source package was built and verified locally with the model,
repository runner, deployment, GCP access, and paid provider calls disabled.

The original authoring manifest was verified before builder changes: all 148
listed files were present and matched their recorded SHA-256 hashes.

## Builder corrections

- Restored route-specific invalid-JSON responses for Creator and Workbench APIs.
- Allowed legitimate empty-body Workbench actions to reach CSRF validation and
  their server-side action instead of treating the empty body as invalid JSON.
- Fixed FastAPI Workbench dependency resolution so a missing owner session
  returns `401` rather than request-validation `422`.
- Made the task-workspace guard identify symlink and hardlink violations before
  path resolution can mask them as a generic escape.
- Made Workbench evidence verification compare the persisted record hash with
  the serialized evidence and calculated chain.
- Bound approval decisions to the requested task and added a regression test
  preventing an approval from one task being used for another.
- Updated stale release and immutable-settings tests, then normalized the code
  base with the locked Ruff formatter.

## Final verification

- Frozen dependency environment synchronized successfully.
- `uv lock --check --offline` passed.
- `ruff check .` passed.
- `ruff format --check .` passed.
- `pytest` passed: **369 passed**, with one third-party FastAPI/Starlette
  deprecation warning.
- Every deterministic offline evaluation and smoke path passed:
  - local recovery/control evaluation;
  - 2-case gauntlet;
  - 3-case engineering trial;
  - 160-case Creator benchmark;
  - 120-case Phase 6 evaluation;
  - 120-case Phase 7 evaluation;
  - core and Creator smoke checks.
- The final evaluation asserted zero real provider calls, zero repository
  executions, and a disconnected runner.
- Localhost acceptance passed for owner login, anonymous API rejection,
  HttpOnly/SameSite-Strict session cookies, Secure cookies over HTTPS in the
  test harness, CSRF enforcement, disposable task import and inspection, and
  truthful disconnected-runner status.

## Boundaries retained

This package is not deployed, is not GCP-qualified, and did not access GCP.
The live model and command runner remain disabled by default. Do not use this
builder report as evidence of production execution, a cloud deployment, or
Sol's independent examination verification.

## Package integrity

`FILE_MANIFEST.json` is retained unchanged as the verified pre-build authoring
baseline. Because this builder corrected and formatted files, use the generated
`BUILD_FILE_MANIFEST.json` for the exact contents of this built package. Apply
the complete source tree rather than relying on the original `PATCH.diff` when
moving these builder-corrected sources to the pinned Git baseline.
