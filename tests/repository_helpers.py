from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path


def run_git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def initialize_repository(workspace: Path, name: str = "repository") -> tuple[Path, str]:
    repository = workspace / name
    repository.mkdir(parents=True)
    (repository / "src").mkdir()
    (repository / "tests").mkdir()
    (repository / "src" / "app.py").write_text(
        "from fastapi import FastAPI\n\napp = FastAPI()\n",
        encoding="utf-8",
    )
    (repository / "tests" / "test_app.py").write_text(
        "def test_placeholder():\n    assert True\n",
        encoding="utf-8",
    )
    (repository / "pyproject.toml").write_text(
        (
            "[project]\n"
            'name = "fixture"\n'
            'version = "0.1.0"\n'
            'dependencies = ["fastapi>=0.100"]\n\n'
            "[tool.pytest.ini_options]\n"
            'testpaths = ["tests"]\n'
        ),
        encoding="utf-8",
    )
    (repository / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    run_git(repository, "init", "-q")
    run_git(repository, "config", "user.name", "Test User")
    run_git(repository, "config", "user.email", "test@example.invalid")
    run_git(repository, "add", ".")
    run_git(repository, "commit", "-q", "-m", "Initial fixture")
    return repository, run_git(repository, "rev-parse", "HEAD")


def repository_oracle(repository: Path) -> str:
    digest = hashlib.sha256()
    pending = [repository]
    while pending:
        current = pending.pop()
        metadata = current.lstat()
        relative = current.relative_to(repository).as_posix()
        target = os.readlink(current) if stat.S_ISLNK(metadata.st_mode) else ""
        content_digest = ""
        if stat.S_ISREG(metadata.st_mode):
            content_digest = hashlib.sha256(current.read_bytes()).hexdigest()
        digest.update(
            (
                f"{relative}\0{metadata.st_mode}\0{metadata.st_size}\0"
                f"{metadata.st_mtime_ns}\0{target}\0{content_digest}\n"
            ).encode("utf-8", errors="surrogateescape")
        )
        if stat.S_ISDIR(metadata.st_mode):
            pending.extend(
                sorted(
                    [entry for entry in current.iterdir() if entry.name != ".git"],
                    reverse=True,
                )
            )
    digest.update(run_git(repository, "rev-parse", "HEAD").encode())
    digest.update(
        subprocess.run(
            [
                "git",
                "--no-optional-locks",
                "-C",
                str(repository),
                "status",
                "--porcelain=v2",
                "-z",
                "--branch",
                "--untracked-files=all",
            ],
            check=True,
            capture_output=True,
        ).stdout
    )
    return digest.hexdigest()
