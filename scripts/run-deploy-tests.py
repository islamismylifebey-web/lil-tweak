#!/usr/bin/env python3
"""Run deployment security tests, optionally as root on a hosted CI VM."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parent.parent
DISCOVERY = ("-B", "-m", "unittest", "discover", "-s", "deploy/tests", "-p", "test_*.py")


def run_suite(interpreter: str, environment: dict[str, str]) -> int:
    return subprocess.run(
        [interpreter, *DISCOVERY], cwd=ROOT, env=environment, check=False
    ).returncode


def root_child() -> int:
    if sys.platform != "linux" or getattr(os, "geteuid", lambda: -1)() != 0:
        print("deployment tests: root child requires Linux root", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="lil-tweak-deploy-tests-", dir="/tmp") as private:
        os.chmod(private, 0o700)
        return run_suite(
            "/usr/bin/python3",
            {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "TMPDIR": private,
                "TMP": private,
                "TEMP": private,
            },
        )


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if arguments == ["--root-child"]:
            return root_child()
        if arguments:
            print("deployment tests: unsupported arguments", file=sys.stderr)
            return 2
        if os.environ.get("LIL_TWEAK_DEPLOY_TEST_AS_ROOT") == "1":
            if (
                sys.platform != "linux"
                or os.environ.get("GITHUB_ACTIONS") != "true"
                or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            ):
                print("deployment tests: elevation requires an opted-in hosted Linux runner", file=sys.stderr)
                return 2
            return subprocess.run(
                ["/usr/bin/sudo", "-n", "/usr/bin/python3", "-B", str(SCRIPT), "--root-child"],
                cwd=ROOT,
                check=False,
            ).returncode
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return run_suite(sys.executable, environment)
    except OSError:
        print("deployment tests: unable to start or clean up test process", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
