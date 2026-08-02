from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unicodedata
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field

from .repository import is_sensitive_path, secret_rule_ids

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{2,}")
_STOP_WORDS = {
    "add",
    "and",
    "build",
    "change",
    "code",
    "file",
    "fix",
    "for",
    "from",
    "into",
    "repository",
    "task",
    "test",
    "that",
    "the",
    "this",
    "with",
}
_LANGUAGES = {
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".css": "CSS",
    ".go": "Go",
    ".html": "HTML",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".json": "JSON",
    ".kt": "Kotlin",
    ".php": "PHP",
    ".py": "Python",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".sh": "Shell",
    ".sql": "SQL",
    ".swift": "Swift",
    ".toml": "TOML",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".vue": "Vue",
    ".yaml": "YAML",
    ".yml": "YAML",
}
_FRAMEWORK_CLUES = {
    "@angular/core": "Angular",
    "@nestjs/core": "NestJS",
    "django": "Django",
    "express": "Express",
    "fastapi": "FastAPI",
    "flask": "Flask",
    "next": "Next.js",
    "react": "React",
    "svelte": "Svelte",
    "vue": "Vue",
}
_PRIORITY_NAMES = {
    "cargo.toml",
    "go.mod",
    "package.json",
    "pyproject.toml",
    "readme.md",
    "requirements.txt",
}
_UNSAFE_GIT_CONFIG = {
    "core.attributesfile",
    "core.excludesfile",
    "core.fsmonitor",
    "core.sparsecheckout",
    "core.sparsecheckoutcone",
    "core.worktree",
    "extensions.partialclone",
    "extensions.worktreeconfig",
}


class WorkbenchRepositoryError(RuntimeError):
    """A repository could not cross the local Workbench trust boundary."""


@dataclass(frozen=True)
class WorkbenchRepositoryLimits:
    max_files: int = 10_000
    max_total_bytes: int = 250_000_000
    max_file_bytes: int = 20_000_000
    max_path_bytes: int = 512
    max_path_depth: int = 32
    git_timeout_seconds: float = 10.0
    max_git_output_bytes: int = 8_000_000
    max_excerpt_files: int = 8
    max_excerpt_file_bytes: int = 512_000
    max_excerpt_characters: int = 12_000
    max_excerpt_lines: int = 40

    def __post_init__(self) -> None:
        if not (1 <= self.max_files <= 100_000):
            raise ValueError("repository file limit is invalid")
        if not (1 <= self.max_file_bytes <= self.max_total_bytes <= 1_000_000_000):
            raise ValueError("repository byte limits are invalid")
        if not (64 <= self.max_path_bytes <= 4_096 and 1 <= self.max_path_depth <= 128):
            raise ValueError("repository path limits are invalid")
        if not (0.1 <= self.git_timeout_seconds <= 120):
            raise ValueError("repository Git timeout is invalid")
        if not (1_024 <= self.max_git_output_bytes <= 64_000_000):
            raise ValueError("repository Git output limit is invalid")
        if not (1 <= self.max_excerpt_files <= 32):
            raise ValueError("repository excerpt count is invalid")


class _Schema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RepositoryFileFact(_Schema):
    path: str = Field(min_length=1, max_length=512)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bytes: int = Field(ge=0)
    executable: bool
    language: str | None = None


class RepositoryExcerpt(_Schema):
    path: str = Field(min_length=1, max_length=512)
    file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    first_line: int = Field(ge=1)
    last_line: int = Field(ge=1)
    text: str = Field(max_length=8_000)


class RepositoryGitFacts(_Schema):
    branch: str = Field(min_length=1, max_length=256)
    head: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    dirty: bool
    staged_count: int = Field(ge=0)
    modified_count: int = Field(ge=0)
    untracked_count: int = Field(ge=0)
    status_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class WorkbenchRepositoryInspection(_Schema):
    schema_version: str = "workbench-repository-v1"
    repository_id: str = Field(min_length=1, max_length=128)
    source_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    git: RepositoryGitFacts
    file_count: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    files: tuple[RepositoryFileFact, ...]
    languages: dict[str, int]
    framework_clues: tuple[str, ...]
    candidate_commands: tuple[str, ...]
    excerpts: tuple[RepositoryExcerpt, ...]
    screened_file_count: int = Field(ge=0)
    secret_rule_ids: tuple[str, ...]
    source_unchanged: bool = True


class MaterializedRepository(_Schema):
    schema_version: str = "workbench-materialized-repository-v1"
    repository_id: str = Field(min_length=1, max_length=128)
    source_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    tree_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    file_count: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    git_metadata_included: bool = False
    source_writes_performed: bool = False


@dataclass(frozen=True)
class _Entry:
    path: str
    directory: bool
    executable: bool
    data: bytes
    sha256: str | None
    language: str | None
    sensitive: bool
    matched_rules: tuple[str, ...]


@dataclass(frozen=True)
class _Capture:
    entries: tuple[_Entry, ...]
    git: RepositoryGitFacts
    fingerprint: str
    file_count: int
    total_bytes: int

    @property
    def tree_digest(self) -> str:
        payload = [
            {
                "bytes": len(item.data),
                "executable": item.executable,
                "path": item.path,
                "sha256": item.sha256,
            }
            for item in self.entries
            if not item.directory
        ]
        return _digest(payload)


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class WorkbenchRepositoryRegistry:
    """Resolve configured local repositories without exposing their host paths.

    The registry is intentionally configuration-backed. The public identifier is the only
    repository locator that crosses the Workbench API boundary; configured relative paths remain
    private server state.
    """

    def __init__(
        self,
        root: Path | str,
        repositories: Mapping[str, str],
        *,
        limits: WorkbenchRepositoryLimits | None = None,
    ) -> None:
        configured_root = Path(root)
        try:
            root_metadata = configured_root.lstat()
            resolved_root = configured_root.resolve(strict=True)
        except OSError as exc:
            raise WorkbenchRepositoryError("configured repository root is unavailable") from exc
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
            raise WorkbenchRepositoryError("configured repository root must be a real directory")
        if resolved_root == Path("/"):
            raise WorkbenchRepositoryError("configured repository root is too broad")
        self._root = resolved_root
        self._repositories: dict[str, PurePosixPath] = {}
        for repository_id, raw_path in repositories.items():
            if _SAFE_ID.fullmatch(repository_id) is None:
                raise WorkbenchRepositoryError("configured repository identifier is invalid")
            if not raw_path or "\\" in raw_path:
                raise WorkbenchRepositoryError("configured repository mapping is invalid")
            pure = PurePosixPath(raw_path)
            if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
                raise WorkbenchRepositoryError("configured repository mapping is invalid")
            self._repositories[repository_id] = pure
        self.limits = limits or WorkbenchRepositoryLimits()
        binary = shutil.which("git", path="/usr/local/bin:/usr/bin:/bin")
        if binary is None:
            raise WorkbenchRepositoryError("Git is unavailable for repository onboarding")
        self._git_binary = str(Path(binary).resolve(strict=True))

    @property
    def repository_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._repositories))

    def inspect(
        self,
        repository_id: str,
        *,
        direction: str = "",
    ) -> WorkbenchRepositoryInspection:
        if secret_rule_ids(direction.encode("utf-8")):
            raise WorkbenchRepositoryError("task direction contains secret-like material")
        repository = self._resolve(repository_id)
        capture = self._stable_capture(repository)
        safe_entries = tuple(
            item for item in capture.entries if not item.directory and not item.sensitive
        )
        languages = Counter(item.language for item in safe_entries if item.language is not None)
        frameworks = self._framework_clues(safe_entries)
        rules = sorted({rule for item in capture.entries for rule in item.matched_rules})
        screened = sum(1 for item in capture.entries if not item.directory and item.sensitive)
        return WorkbenchRepositoryInspection(
            repository_id=repository_id,
            source_fingerprint=capture.fingerprint,
            git=capture.git,
            file_count=capture.file_count,
            total_bytes=capture.total_bytes,
            files=tuple(
                RepositoryFileFact(
                    path=item.path,
                    sha256=item.sha256 or "0" * 64,
                    bytes=len(item.data),
                    executable=item.executable,
                    language=item.language,
                )
                for item in safe_entries
            ),
            languages=dict(sorted(languages.items())),
            framework_clues=frameworks,
            candidate_commands=self._candidate_commands(safe_entries),
            excerpts=self._relevant_excerpts(safe_entries, direction),
            screened_file_count=screened,
            secret_rule_ids=tuple(rules),
        )

    def planning_context(
        self,
        inspection: WorkbenchRepositoryInspection,
    ) -> dict[str, object]:
        """Return only repository-relative, secret-screened facts for a planning model."""
        file_limit = min(256, self.limits.max_files)
        files = inspection.files[:file_limit]
        return {
            "schema_version": inspection.schema_version,
            "repository_id": inspection.repository_id,
            "source_fingerprint": inspection.source_fingerprint,
            "git": inspection.git.model_dump(mode="json"),
            "file_count": inspection.file_count,
            "total_bytes": inspection.total_bytes,
            "files": [item.model_dump(mode="json") for item in files],
            "files_truncated": len(inspection.files) > len(files),
            "languages": inspection.languages,
            "framework_clues": list(inspection.framework_clues),
            "candidate_commands": list(inspection.candidate_commands),
            "excerpts": [item.model_dump(mode="json") for item in inspection.excerpts],
            "screened_file_count": inspection.screened_file_count,
            "secret_rule_ids": list(inspection.secret_rule_ids),
        }

    def materialize(
        self,
        repository_id: str,
        *,
        expected_source_fingerprint: str,
        destination: Path,
        exclude_sensitive: bool = False,
    ) -> MaterializedRepository:
        if re.fullmatch(r"[0-9a-f]{64}", expected_source_fingerprint) is None:
            raise WorkbenchRepositoryError("expected source fingerprint is invalid")
        repository = self._resolve(repository_id)
        destination = destination.absolute()
        resolved_destination = destination.resolve(strict=False)
        if (
            resolved_destination == self._root
            or resolved_destination.is_relative_to(self._root)
            or self._root.is_relative_to(resolved_destination)
        ):
            raise WorkbenchRepositoryError("task destination must be outside repository storage")
        parent = destination.parent
        try:
            parent_metadata = parent.lstat()
            resolved_parent = parent.resolve(strict=True)
        except OSError as exc:
            raise WorkbenchRepositoryError("task destination parent is unavailable") from exc
        if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
            raise WorkbenchRepositoryError("task destination parent is unsafe")
        if resolved_parent != parent.resolve():
            raise WorkbenchRepositoryError("task destination parent is unsafe")
        if (destination.exists() or destination.is_symlink()) and (
            destination.is_symlink() or not destination.is_dir() or any(destination.iterdir())
        ):
            raise WorkbenchRepositoryError("task destination must be a fresh empty directory")

        capture = self._stable_capture(repository)
        if capture.fingerprint != expected_source_fingerprint:
            raise WorkbenchRepositoryError("registered source changed after inspection")
        has_sensitive_files = any(item.sensitive for item in capture.entries if not item.directory)
        if has_sensitive_files and not exclude_sensitive:
            raise WorkbenchRepositoryError(
                "repository contains secret-like material and cannot be materialized"
            )
        materialized_capture = (
            _Capture(
                entries=tuple(
                    item for item in capture.entries if item.directory or not item.sensitive
                ),
                git=capture.git,
                fingerprint=capture.fingerprint,
                file_count=sum(
                    1 for item in capture.entries if not item.directory and not item.sensitive
                ),
                total_bytes=sum(
                    len(item.data)
                    for item in capture.entries
                    if not item.directory and not item.sensitive
                ),
            )
            if has_sensitive_files
            else capture
        )

        staging = Path(tempfile.mkdtemp(prefix=".liltweak-source-", dir=resolved_parent))
        installed = False
        try:
            self._write_capture(materialized_capture, staging)
            if self._materialized_tree_digest(staging) != materialized_capture.tree_digest:
                raise WorkbenchRepositoryError("materialized source verification failed")
            repeated = self._stable_capture(repository)
            if repeated.fingerprint != capture.fingerprint:
                raise WorkbenchRepositoryError("registered source changed during materialization")
            if destination.exists():
                destination.rmdir()
            os.replace(staging, destination)
            installed = True
        finally:
            if not installed:
                shutil.rmtree(staging, ignore_errors=True)

        return MaterializedRepository(
            repository_id=repository_id,
            source_fingerprint=capture.fingerprint,
            tree_digest=materialized_capture.tree_digest,
            file_count=materialized_capture.file_count,
            total_bytes=materialized_capture.total_bytes,
        )

    def _resolve(self, repository_id: str) -> Path:
        try:
            relative = self._repositories[repository_id]
        except KeyError as exc:
            raise WorkbenchRepositoryError("repository identifier is not registered") from exc
        current = self._root
        for part in relative.parts:
            current = current / part
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise WorkbenchRepositoryError("registered repository is unavailable") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise WorkbenchRepositoryError("registered repository path contains a symlink")
        try:
            repository = current.resolve(strict=True)
        except OSError as exc:
            raise WorkbenchRepositoryError("registered repository is unavailable") from exc
        if not repository.is_relative_to(self._root) or not repository.is_dir():
            raise WorkbenchRepositoryError("registered repository escapes its configured root")
        self._validate_git_directory(repository)
        return repository

    def _validate_git_directory(self, repository: Path) -> None:
        git_directory = repository / ".git"
        try:
            metadata = git_directory.lstat()
        except OSError as exc:
            raise WorkbenchRepositoryError(
                "registered repository has no local Git metadata"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise WorkbenchRepositoryError(
                "registered repository requires an in-tree .git directory"
            )
        for relative, expected_directory in (
            ("HEAD", False),
            ("config", False),
            ("objects", True),
            ("refs", True),
        ):
            path = git_directory / relative
            try:
                item = path.lstat()
            except OSError as exc:
                raise WorkbenchRepositoryError("registered Git metadata is incomplete") from exc
            if stat.S_ISLNK(item.st_mode):
                raise WorkbenchRepositoryError("registered Git metadata contains a symlink")
            if expected_directory and not stat.S_ISDIR(item.st_mode):
                raise WorkbenchRepositoryError("registered Git metadata is invalid")
            if not expected_directory and (not stat.S_ISREG(item.st_mode) or item.st_nlink != 1):
                raise WorkbenchRepositoryError("registered Git metadata is invalid")
        alternates = git_directory / "objects" / "info" / "alternates"
        if alternates.exists() or alternates.is_symlink():
            raise WorkbenchRepositoryError("Git object alternates are not permitted")
        config = self._run_git(
            repository,
            (
                "config",
                "--file",
                str(git_directory / "config"),
                "--no-includes",
                "--name-only",
                "--get-regexp",
                ".*",
            ),
            allowed_return_codes={0, 1},
            output_limit=128_000,
        ).decode("utf-8", errors="strict")
        keys = {line.casefold() for line in config.splitlines()}
        if keys.intersection(_UNSAFE_GIT_CONFIG) or any(
            key.startswith(("include.", "includeif.", "filter."))
            or key.endswith((".promisor", ".command", ".textconv", ".driver"))
            for key in keys
        ):
            raise WorkbenchRepositoryError("Git configuration contains unsafe controls")

    def _stable_capture(self, repository: Path) -> _Capture:
        before_git = self._git_facts(repository)
        entries = self._scan_worktree(repository)
        after_git = self._git_facts(repository)
        if before_git != after_git:
            raise WorkbenchRepositoryError("registered source changed during inspection")
        file_count = sum(not item.directory for item in entries)
        total_bytes = sum(len(item.data) for item in entries if not item.directory)
        records = [
            {
                "bytes": len(item.data),
                "directory": item.directory,
                "executable": item.executable,
                "path": item.path,
                "sha256": item.sha256,
            }
            for item in entries
        ]
        fingerprint = _digest(
            {
                "entries": records,
                "git": before_git.model_dump(mode="json"),
            }
        )
        return _Capture(
            entries=entries,
            git=before_git,
            fingerprint=fingerprint,
            file_count=file_count,
            total_bytes=total_bytes,
        )

    def _scan_worktree(self, repository: Path) -> tuple[_Entry, ...]:
        entries: list[_Entry] = []
        pending: list[tuple[Path, str]] = [(repository, "")]
        collision_keys: set[str] = set()
        file_count = 0
        total_bytes = 0
        while pending:
            current, relative = pending.pop()
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise WorkbenchRepositoryError("repository entry became unavailable") from exc
            if relative:
                self._validate_relative_path(relative)
                collision = unicodedata.normalize("NFC", relative).casefold()
                if collision in collision_keys:
                    raise WorkbenchRepositoryError("repository contains a path collision")
                collision_keys.add(collision)
            if stat.S_ISLNK(metadata.st_mode):
                raise WorkbenchRepositoryError("repository contains a symlink")
            if stat.S_ISDIR(metadata.st_mode):
                if relative:
                    entries.append(_Entry(relative, True, False, b"", None, None, False, ()))
                try:
                    children = sorted(os.scandir(current), key=lambda item: item.name)
                except OSError as exc:
                    raise WorkbenchRepositoryError("repository directory is unreadable") from exc
                for child in reversed(children):
                    if not relative and child.name == ".git":
                        continue
                    if child.name == ".git":
                        raise WorkbenchRepositoryError("nested Git metadata is not permitted")
                    child_relative = f"{relative}/{child.name}" if relative else child.name
                    pending.append((Path(child.path), child_relative))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise WorkbenchRepositoryError("repository contains a special file")
            if metadata.st_nlink != 1:
                raise WorkbenchRepositoryError("repository contains a hardlinked file")
            if metadata.st_size > self.limits.max_file_bytes:
                raise WorkbenchRepositoryError("repository contains an oversized file")
            file_count += 1
            total_bytes += metadata.st_size
            if file_count > self.limits.max_files or total_bytes > self.limits.max_total_bytes:
                raise WorkbenchRepositoryError("repository exceeds configured inspection limits")
            data = self._read_regular(current, metadata)
            rules = tuple(secret_rule_ids(data))
            sensitive = is_sensitive_path(relative) or bool(rules)
            entries.append(
                _Entry(
                    path=relative,
                    directory=False,
                    executable=bool(metadata.st_mode & stat.S_IXUSR),
                    data=data,
                    sha256=hashlib.sha256(data).hexdigest(),
                    language=_LANGUAGES.get(PurePosixPath(relative).suffix.casefold()),
                    sensitive=sensitive,
                    matched_rules=rules,
                )
            )
        return tuple(sorted(entries, key=lambda item: item.path))

    def _read_regular(self, path: Path, expected: os.stat_result) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise WorkbenchRepositoryError("repository file could not be opened safely") from exc
        try:
            observed = os.fstat(descriptor)
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_nlink != 1
                or observed.st_dev != expected.st_dev
                or observed.st_ino != expected.st_ino
                or observed.st_size != expected.st_size
                or observed.st_mtime_ns != expected.st_mtime_ns
                or observed.st_ctime_ns != expected.st_ctime_ns
                or observed.st_mode != expected.st_mode
            ):
                raise WorkbenchRepositoryError("repository file changed during inspection")
            chunks: list[bytes] = []
            remaining = observed.st_size
            while remaining:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    raise WorkbenchRepositoryError("repository file was truncated")
                chunks.append(chunk)
                remaining -= len(chunk)
            final = os.fstat(descriptor)
            if (
                final.st_size != observed.st_size
                or final.st_mtime_ns != observed.st_mtime_ns
                or final.st_ctime_ns != observed.st_ctime_ns
                or final.st_mode != observed.st_mode
                or final.st_nlink != observed.st_nlink
            ):
                raise WorkbenchRepositoryError("repository file changed during inspection")
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def _git_facts(self, repository: Path) -> RepositoryGitFacts:
        head = (
            self._run_git(
                repository,
                ("rev-parse", "--verify", "HEAD^{commit}"),
                output_limit=256,
            )
            .decode("ascii")
            .strip()
        )
        if re.fullmatch(r"[0-9a-f]{40,64}", head) is None:
            raise WorkbenchRepositoryError("repository HEAD is invalid")
        branch_output = (
            self._run_git(
                repository,
                ("symbolic-ref", "--quiet", "--short", "HEAD"),
                allowed_return_codes={0, 1},
                output_limit=1_024,
            )
            .decode("utf-8", errors="strict")
            .strip()
        )
        branch = branch_output or "(detached)"
        if len(branch) > 256 or any(ord(character) < 32 for character in branch):
            raise WorkbenchRepositoryError("repository branch is invalid")
        status_output = self._run_git(
            repository,
            ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
            output_limit=self.limits.max_git_output_bytes,
        )
        staged = 0
        modified = 0
        untracked = 0
        for record in status_output.split(b"\0"):
            if len(record) < 3 or record[2:3] != b" ":
                continue
            x = record[0:1]
            y = record[1:2]
            if x == b"?" and y == b"?":
                untracked += 1
                continue
            staged += int(x not in {b" ", b"?"})
            modified += int(y not in {b" ", b"?"})
        return RepositoryGitFacts(
            branch=branch,
            head=head,
            dirty=bool(status_output),
            staged_count=staged,
            modified_count=modified,
            untracked_count=untracked,
            status_digest=hashlib.sha256(status_output).hexdigest(),
        )

    def _run_git(
        self,
        repository: Path,
        arguments: tuple[str, ...],
        *,
        allowed_return_codes: set[int] | None = None,
        output_limit: int,
    ) -> bytes:
        allowed = allowed_return_codes or {0}
        command = [
            self._git_binary,
            "--no-optional-locks",
            "-c",
            f"safe.directory={repository}",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "core.excludesFile=/dev/null",
            "-c",
            "protocol.allow=never",
            "-C",
            str(repository),
            *arguments,
        ]
        environment = {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        }
        try:
            result = subprocess.run(
                command,
                check=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env=environment,
                timeout=self.limits.git_timeout_seconds,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise WorkbenchRepositoryError("bounded Git inspection failed") from exc
        if (
            result.returncode not in allowed
            or len(result.stdout) > output_limit
            or len(result.stderr) > 64_000
        ):
            raise WorkbenchRepositoryError("bounded Git inspection failed")
        return result.stdout

    def _relevant_excerpts(
        self,
        entries: tuple[_Entry, ...],
        direction: str,
    ) -> tuple[RepositoryExcerpt, ...]:
        tokens = {
            item.casefold()
            for item in _WORD.findall(direction)
            if item.casefold() not in _STOP_WORDS
        }
        ranked: list[tuple[int, str, _Entry, str]] = []
        for item in entries:
            if len(item.data) > self.limits.max_excerpt_file_bytes or b"\0" in item.data[:8192]:
                continue
            try:
                text = item.data.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                continue
            lowered_path = item.path.casefold()
            lowered_text = text.casefold()
            score = sum(20 for token in tokens if token in lowered_path)
            score += sum(min(lowered_text.count(token), 5) * 3 for token in tokens)
            if PurePosixPath(item.path).name.casefold() in _PRIORITY_NAMES:
                score += 5
            if "/test" in f"/{lowered_path}" or lowered_path.startswith("test"):
                score += 3
            if not tokens and (item.language is not None or score):
                score += 1
            if score:
                ranked.append((-score, item.path, item, text))
        excerpts: list[RepositoryExcerpt] = []
        remaining = self.limits.max_excerpt_characters
        for _score, _path, item, text in sorted(ranked):
            if len(excerpts) >= self.limits.max_excerpt_files or remaining <= 0:
                break
            lines = text.splitlines()
            hit = 0
            for index, line in enumerate(lines):
                if any(token in line.casefold() for token in tokens):
                    hit = index
                    break
            start = max(0, hit - self.limits.max_excerpt_lines // 4)
            stop = min(len(lines), start + self.limits.max_excerpt_lines)
            excerpt = "\n".join(lines[start:stop])
            excerpt = excerpt[: min(remaining, 8_000)]
            if not excerpt or secret_rule_ids(excerpt.encode("utf-8")):
                continue
            remaining -= len(excerpt)
            excerpts.append(
                RepositoryExcerpt(
                    path=item.path,
                    file_sha256=item.sha256 or "0" * 64,
                    first_line=start + 1,
                    last_line=start + max(1, excerpt.count("\n") + 1),
                    text=excerpt,
                )
            )
        return tuple(excerpts)

    @staticmethod
    def _framework_clues(entries: tuple[_Entry, ...]) -> tuple[str, ...]:
        clues: set[str] = set()
        for item in entries:
            name = PurePosixPath(item.path).name.casefold()
            if name not in {"package.json", "pyproject.toml", "requirements.txt"}:
                continue
            text = item.data.decode("utf-8", errors="replace").casefold()
            for marker, framework in _FRAMEWORK_CLUES.items():
                if marker in text:
                    clues.add(framework)
        return tuple(sorted(clues))

    @staticmethod
    def _candidate_commands(entries: tuple[_Entry, ...]) -> tuple[str, ...]:
        by_name = {PurePosixPath(item.path).name.casefold(): item for item in entries}
        commands: set[str] = set()
        if "pyproject.toml" in by_name or "requirements.txt" in by_name:
            commands.update({"python -m pytest -q", "ruff check ."})
        package = by_name.get("package.json")
        if package is not None:
            try:
                scripts = json.loads(package.data).get("scripts", {})
            except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                scripts = {}
            if isinstance(scripts, dict):
                for name in ("test", "lint", "typecheck", "build"):
                    if isinstance(scripts.get(name), str):
                        commands.add("npm test" if name == "test" else f"npm run {name}")
        if "cargo.toml" in by_name:
            commands.add("cargo test")
        if "go.mod" in by_name:
            commands.add("go test ./...")
        return tuple(sorted(commands))

    def _validate_relative_path(self, value: str) -> None:
        pure = PurePosixPath(value)
        if (
            not value
            or len(value.encode("utf-8")) > self.limits.max_path_bytes
            or pure.is_absolute()
            or "\\" in value
            or len(pure.parts) > self.limits.max_path_depth
            or any(part in {"", ".", ".."} for part in pure.parts)
            or unicodedata.normalize("NFC", value) != value
            or any(
                ord(character) < 32
                or ord(character) == 127
                or unicodedata.bidirectional(character)
                in {"RLE", "LRE", "RLO", "LRO", "PDF", "RLI", "LRI", "FSI", "PDI"}
                for character in value
            )
        ):
            raise WorkbenchRepositoryError("repository contains an unsafe path")

    @staticmethod
    def _write_capture(capture: _Capture, destination: Path) -> None:
        for item in capture.entries:
            target = destination.joinpath(*PurePosixPath(item.path).parts)
            if item.directory:
                target.mkdir(mode=0o700, parents=True, exist_ok=False)
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(target, flags, 0o700 if item.executable else 0o600)
            try:
                with os.fdopen(descriptor, "wb", closefd=False) as stream:
                    stream.write(item.data)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                os.close(descriptor)
            os.chmod(target, 0o700 if item.executable else 0o600)

    def _materialized_tree_digest(self, root: Path) -> str:
        entries = self._scan_worktree(root)
        return _digest(
            [
                {
                    "bytes": len(item.data),
                    "executable": item.executable,
                    "path": item.path,
                    "sha256": item.sha256,
                }
                for item in entries
                if not item.directory
            ]
        )
