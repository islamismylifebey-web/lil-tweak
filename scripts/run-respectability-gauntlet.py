#!/usr/bin/env python3
"""Run offline control-layer exercises and publish an honest, bounded scorecard.

GitHub CI supplies network isolation. Running this command alone is not a
network sandbox and does not certify deployment readiness or model quality.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class GauntletResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subtests_run = 0

    def addSubTest(self, test, subtest, err):
        self.subtests_run += 1
        super().addSubTest(test, subtest, err)


def summarize(result):
    gaps = bool(result.skipped or result.expectedFailures)
    passed = result.testsRun > 0 and result.wasSuccessful()
    return {
        "status": "FAIL" if not passed else "PASS_WITH_GAPS" if gaps else "PASS",
        "tests_run": result.testsRun,
        "subtests_run": getattr(result, "subtests_run", 0),
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
        "failed_test_ids": [test.id() for test, _ in result.failures + result.errors][:1000],
    }


def publish(path, report):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".respectability-", delete=False) as handle:
            temp_name = handle.name
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if temp_name is not None and os.path.exists(temp_name):
            os.unlink(temp_name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("focused", "core"), default="focused")
    parser.add_argument("--repeat", type=int, choices=range(1, 6), default=3)
    parser.add_argument("--output", type=Path, default=Path("respectability-results/focused.json"))
    args = parser.parse_args()
    os.chdir(ROOT)
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                                capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        commit = "UNKNOWN"
    started = datetime.now(timezone.utc).isoformat()
    runs = []
    for repetition in range(1, args.repeat + 1):
        loader = unittest.TestLoader()
        suite = (loader.loadTestsFromNames([
            "core.tests.test_respectability_gauntlet",
            "core.tests.test_respectability_runner",
        ]) if args.suite == "focused" else
            loader.discover(str(ROOT / "core/tests"), pattern="test_*.py"))
        result = unittest.TextTestRunner(verbosity=2, resultclass=GauntletResult).run(suite)
        runs.append({"repetition": repetition, **summarize(result)})
    statuses = {run["status"] for run in runs}
    status = "FAIL" if "FAIL" in statuses else "PASS_WITH_GAPS" if "PASS_WITH_GAPS" in statuses else "PASS"
    paths = ("core/lil_tweak/state.py", "core/lil_tweak/signing.py",
             "core/tests/test_respectability_gauntlet.py", "scripts/run-respectability-gauntlet.py")
    report = {
        "schema_version": 1, "source_commit": commit,
        "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
        "suite": args.suite, "status": status, "runs": runs,
        "seeded_attack_seeds": [7, 101, 20260918],
        "source_sha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths},
        "deployment_certified": False,
        "scope": "Control-layer tests only; live providers, production recovery, and full skill exit criteria are not certified.",
    }
    publish(args.output, report)
    print(json.dumps(report, sort_keys=True))
    return 1 if status == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
