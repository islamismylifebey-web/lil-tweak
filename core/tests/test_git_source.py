import subprocess
import tempfile
import unittest
from pathlib import Path

from core.lil_tweak.git_source import GitIntakeError, ingest_git_source
from core.lil_tweak.limits import MAX_EXPANDED_SOURCE_BYTES
from core.lil_tweak.store import GitSourceSpec


class GitSourceTests(unittest.TestCase):
    def test_fetches_exact_allowlisted_commit_without_shell_or_credentials(self):
        commit = "a" * 40
        calls = []

        def execute(argv, **kwargs):
            calls.append((list(argv), kwargs))
            if "checkout" in argv:
                (Path(kwargs["cwd"]) / "main.py").write_text("print('ok')\n")
            stdout = commit + "\n" if "rev-parse" in argv else ""
            return subprocess.CompletedProcess(argv, 0, stdout, "")

        with tempfile.TemporaryDirectory() as directory:
            inventory = ingest_git_source(
                GitSourceSpec("https://git.example/repository.git", commit),
                directory,
                allowed_hosts=("git.example",),
                execute=execute,
                resolve=lambda host, port: [(None, None, None, None, ("93.184.216.34", 443))],
            )
            self.assertEqual(inventory, ["main.py"])
            self.assertFalse((Path(directory) / ".git").exists())
        self.assertTrue(calls)
        self.assertTrue(all(call[1]["shell"] is False for call in calls))
        self.assertTrue(all("user:pass" not in " ".join(call[0]) for call in calls))
        self.assertTrue(
            all(
                "http.curloptResolve=git.example:443:93.184.216.34" in call[0]
                for call in calls
            )
        )
        expected_prefix = ["prlimit", f"--fsize={MAX_EXPANDED_SOURCE_BYTES}", "--"]
        self.assertTrue(all(call[0][:3] == expected_prefix for call in calls))
        self.assertTrue(all("preexec_fn" not in call[1] for call in calls))

    def test_checkout_must_follow_portable_archive_limits(self):
        commit = "b" * 40

        def collision(argv, **kwargs):
            if "checkout" in argv:
                (Path(kwargs["cwd"]) / "Readme.md").write_text("one")
                (Path(kwargs["cwd"]) / "README.md").write_text("two")
            stdout = commit + "\n" if "rev-parse" in argv else ""
            return subprocess.CompletedProcess(argv, 0, stdout, "")

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(GitIntakeError, "git_duplicate_path"):
                ingest_git_source(
                    GitSourceSpec("https://git.example/repository.git", commit),
                    directory,
                    allowed_hosts=("git.example",),
                    execute=collision,
                    resolve=lambda *_: [(None, None, None, None, ("93.184.216.34", 443))],
                )

        def oversized(argv, **kwargs):
            if "checkout" in argv:
                (Path(kwargs["cwd"]) / "large.bin").write_bytes(b"12345")
            stdout = commit + "\n" if "rev-parse" in argv else ""
            return subprocess.CompletedProcess(argv, 0, stdout, "")

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(GitIntakeError, "git_file_too_large"):
                ingest_git_source(
                    GitSourceSpec("https://git.example/repository.git", commit),
                    directory,
                    allowed_hosts=("git.example",),
                    execute=oversized,
                    resolve=lambda *_: [(None, None, None, None, ("93.184.216.34", 443))],
                    max_file_bytes=4,
                )

    def test_rejects_private_dns_and_non_allowlisted_hosts_before_git(self):
        called = []
        spec = GitSourceSpec("https://git.example/repository.git", "a" * 40)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(GitIntakeError, "git_host_not_allowed"):
                ingest_git_source(
                    spec,
                    directory,
                    allowed_hosts=("other.example",),
                    execute=lambda *args, **kwargs: called.append(args),
                )
            with self.assertRaisesRegex(GitIntakeError, "git_host_unsafe"):
                ingest_git_source(
                    spec,
                    directory,
                    allowed_hosts=("git.example",),
                    resolve=lambda host, port: [
                        (None, None, None, None, ("127.0.0.1", 443))
                    ],
                    execute=lambda *args, **kwargs: called.append(args),
                )
        self.assertEqual(called, [])


if __name__ == "__main__":
    unittest.main()
