from __future__ import annotations

import argparse
import os
import stat
import subprocess
from pathlib import Path

FILES = {
    "AGENTS.md": (
        "# Browser acceptance fixture\n\n"
        "Keep changes minimal, preserve tests, and never claim execution without evidence.\n"
    ),
    "pyproject.toml": (
        "[project]\n"
        'name = "liltweak-browser-acceptance-fixture"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.12"\n\n'
        "[tool.pytest.ini_options]\n"
        'testpaths = ["tests"]\n'
    ),
    "src/calculator.py": "def add(left: int, right: int) -> int:\n    return left + right\n",
    "tests/test_calculator.py": (
        "from src.calculator import add\n\n\ndef test_add() -> None:\n    assert add(2, 3) == 5\n"
    ),
}


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create the nonsecret disposable repository used by browser acceptance."
    )
    parser.add_argument("--root", type=Path, required=True)
    return parser.parse_args()


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        shell=False,
        env={
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        },
    )


def main() -> int:
    root = _arguments().root.absolute()
    if root == Path("/") or root.is_symlink():
        raise ValueError("fixture root must be a real bounded directory")
    root.mkdir(parents=True, exist_ok=False)
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_nlink < 2:
        raise ValueError("fixture root is not a directory")
    for relative, content in FILES.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8", newline="\n")
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "Lil Tweak Browser Fixture")
    _git(root, "config", "user.email", "browser-fixture@example.invalid")
    _git(root, "add", "--", *sorted(FILES))
    _git(root, "commit", "-q", "-m", "Create browser acceptance fixture")
    os.chmod(root / "src" / "calculator.py", 0o644)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
