# Builder Handoff

Baseline: private GitHub repository islamismylifebey-web/lil-tweak, main commit 51f9fda931318b598b07b34d5b736daed6197593.

Apply the package to a clean checkout of that commit. Preserve all existing controls. Generate any lockfile only through the selected package manager after reviewing pyproject changes.

Builder may install, migrate locally, compile, test, launch privately, perform safe acceptance checks, and fix trivial import or path issues. Builder may not redesign security, bypass approval, enable an unqualified runner, add unrestricted shells, hardcode credentials, create service-account keys, alter evidence contracts, deploy publicly, or begin the GCP exam.

Required verification order:

1. Compare FILE_MANIFEST.json hashes.
2. Apply PATCH.diff or use the included full source.
3. Review environment defaults; the Workbench, model, and runner remain disabled until an owner key and private local configuration are supplied.
4. Generate or update the lockfile.
5. Configure only server-owned repository mappings. For source-backed acceptance, stage a copy—not the registered source itself—under the generated task workspace and bind the task to `TaskWorkspaceManager.tree_digest` of that copy.
6. Run lint, formatting check, complete tests, frontend accessibility checks, and live-safe acceptance steps.
7. Report every real result and failure without claiming GCP verification.
