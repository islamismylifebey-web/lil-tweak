import unittest
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

CORE_ROOT = Path(__file__).resolve().parents[1]
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

try:
    from core.main import _build_github_runner_verifier
except ImportError:
    _build_github_runner_verifier = None


class GitHubRunnerMainTests(unittest.TestCase):
    def test_github_backend_builds_verifier_from_server_only_configuration(self):
        if _build_github_runner_verifier is None:
            self.fail("GitHub runner main wiring is missing")
        config = SimpleNamespace(
            execution_backend="github_actions",
            github_token="g" * 40,
            github_repository="islamismylifebey-web/lil-tweak",
        )
        with patch("core.main.GitHubActionsRunner") as runner, patch(
            "core.main.GitHubPatchVerifier"
        ) as verifier:
            result = _build_github_runner_verifier(config)

        runner.assert_called_once_with(
            token="g" * 40,
            repository="islamismylifebey-web/lil-tweak",
        )
        verifier.assert_called_once_with(runner.return_value)
        self.assertIs(result, verifier.return_value)

    def test_local_backend_does_not_construct_github_client(self):
        if _build_github_runner_verifier is None:
            self.fail("GitHub runner main wiring is missing")
        config = SimpleNamespace(execution_backend="local_podman")
        with patch("core.main.GitHubActionsRunner") as runner:
            result = _build_github_runner_verifier(config)
        self.assertIsNone(result)
        runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
