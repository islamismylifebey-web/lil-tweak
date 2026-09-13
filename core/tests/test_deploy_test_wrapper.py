import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run-deploy-tests.py"


def load_wrapper():
    spec = importlib.util.spec_from_file_location("deploy_test_wrapper", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("deployment test wrapper could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DeploymentTestWrapperTests(unittest.TestCase):
    def setUp(self):
        self.wrapper = load_wrapper()

    def test_default_runs_complete_suite_without_elevation_and_returns_status(self):
        with patch.dict(os.environ, {"TMPDIR": "ordinary-temp"}, clear=True), patch.object(
            self.wrapper.subprocess, "run", return_value=SimpleNamespace(returncode=7)
        ) as run:
            self.assertEqual(self.wrapper.main([]), 7)
        command = run.call_args.args[0]
        self.assertEqual(command, [self.wrapper.sys.executable, "-B", "-m", "unittest", "discover", "-s", "deploy/tests", "-p", "test_*.py"])
        self.assertEqual(run.call_args.kwargs["cwd"], ROOT)
        self.assertEqual(run.call_args.kwargs["env"]["TMPDIR"], "ordinary-temp")
        self.assertEqual(run.call_args.kwargs["env"]["PYTHONDONTWRITEBYTECODE"], "1")

    def test_elevation_is_denied_outside_explicit_hosted_linux_context(self):
        valid = {"LIL_TWEAK_DEPLOY_TEST_AS_ROOT": "1", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
        for platform, changes in (("win32", {}), ("linux", {"GITHUB_ACTIONS": "false"}), ("linux", {"RUNNER_ENVIRONMENT": "self-hosted"}), ("linux", {"RUNNER_ENVIRONMENT": ""})):
            with self.subTest(platform=platform, changes=changes), patch.dict(
                os.environ, valid | changes, clear=True
            ), patch.object(self.wrapper.sys, "platform", platform), patch.object(
                self.wrapper.subprocess, "run"
            ) as run:
                self.assertEqual(self.wrapper.main([]), 2)
                run.assert_not_called()

    def test_hosted_opt_in_uses_only_fixed_noninteractive_root_child(self):
        environment = {"LIL_TWEAK_DEPLOY_TEST_AS_ROOT": "1", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
        with patch.dict(os.environ, environment, clear=True), patch.object(
            self.wrapper.sys, "platform", "linux"
        ), patch.object(self.wrapper.subprocess, "run", return_value=SimpleNamespace(returncode=9)) as run:
            self.assertEqual(self.wrapper.main([]), 9)
        run.assert_called_once_with(["/usr/bin/sudo", "-n", "/usr/bin/python3", "-B", str(SCRIPT), "--root-child"], cwd=ROOT, check=False)

    def test_root_child_rejects_non_root_before_creating_any_temp(self):
        with patch.object(self.wrapper.sys, "platform", "linux"), patch.object(
            self.wrapper.os, "geteuid", return_value=1001, create=True
        ), patch.object(self.wrapper.tempfile, "TemporaryDirectory") as temporary, patch.object(
            self.wrapper.subprocess, "run"
        ) as run:
            self.assertEqual(self.wrapper.main(["--root-child"]), 2)
            temporary.assert_not_called()
            run.assert_not_called()

    def test_root_child_isolates_temp_environment_cleans_and_propagates_failure(self):
        private = "/tmp/lil-tweak-deploy-tests-example"
        with patch.dict(os.environ, {"TMPDIR": "runner-owned", "PRIVATE_SECRET": "must-not-propagate", "PYTHONPATH": "candidate"}, clear=True), patch.object(
            self.wrapper.sys, "platform", "linux"
        ), patch.object(self.wrapper.os, "geteuid", return_value=0, create=True), patch.object(
            self.wrapper.tempfile, "TemporaryDirectory"
        ) as temporary, patch.object(self.wrapper.os, "chmod") as chmod, patch.object(
            self.wrapper.subprocess, "run", return_value=SimpleNamespace(returncode=11)
        ) as run:
            temporary.return_value.__enter__.return_value = private
            self.assertEqual(self.wrapper.main(["--root-child"]), 11)
        temporary.assert_called_once_with(prefix="lil-tweak-deploy-tests-", dir="/tmp")
        chmod.assert_called_once_with(private, 0o700)
        temporary.return_value.__exit__.assert_called_once()
        self.assertEqual(run.call_args.args[0], ["/usr/bin/python3", "-B", "-m", "unittest", "discover", "-s", "deploy/tests", "-p", "test_*.py"])
        self.assertEqual(run.call_args.kwargs["cwd"], ROOT)
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": private, "TMP": private, "TEMP": private})

    def test_root_child_cleans_temp_when_suite_cannot_start(self):
        with patch.object(self.wrapper.sys, "platform", "linux"), patch.object(
            self.wrapper.os, "geteuid", return_value=0, create=True
        ), patch.object(self.wrapper.tempfile, "TemporaryDirectory") as temporary, patch.object(
            self.wrapper.os, "chmod"
        ), patch.object(self.wrapper.subprocess, "run", side_effect=OSError("unavailable")):
            temporary.return_value.__enter__.return_value = "/tmp/lil-tweak-deploy-tests-example"
            self.assertEqual(self.wrapper.main(["--root-child"]), 2)
        temporary.return_value.__exit__.assert_called_once()


if __name__ == "__main__":
    unittest.main()
