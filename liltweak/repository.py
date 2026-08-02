from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time
import tomllib
import unicodedata
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal, overload
from urllib.parse import urlsplit

from .models import (
    DependencyManifest,
    GitRemote,
    GitState,
    LanguageStat,
    PathFinding,
    RecoveryAssessment,
    RepositoryInspection,
    RepositoryRef,
    RiskLevel,
    SecretFinding,
)


class RepositoryInspectionError(RuntimeError):
    pass


class RepositoryAccessError(RepositoryInspectionError):
    pass


@dataclass(frozen=True)
class InspectionLimits:
    max_files: int = 10_000
    max_total_bytes: int = 2_000_000_000
    max_text_bytes: int = 50_000_000
    max_text_file_bytes: int = 512_000
    max_findings: int = 200
    max_list_items: int = 500
    large_file_bytes: int = 10_000_000
    git_timeout_seconds: float = 8.0
    max_git_output_bytes: int = 2_000_000
    max_recovery_blob_bytes: int = 8_000_000


@dataclass(frozen=True)
class _GitEntry:
    mode: str
    object_id: str
    path: str
    stage: int = 0


@dataclass(frozen=True)
class _SnapshotResult:
    digest: str | None
    file_count: int
    total_bytes: int
    complete: bool
    unsafe_reason: str | None = None


_EXCLUDED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "bower_components",
    "vendor",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".cache",
    "__pycache__",
    "target",
}

_LANGUAGES = {
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cs": "C#",
    ".css": "CSS",
    ".dart": "Dart",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".go": "Go",
    ".html": "HTML",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".lua": "Lua",
    ".php": "PHP",
    ".py": "Python",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".scala": "Scala",
    ".sh": "Shell",
    ".sql": "SQL",
    ".swift": "Swift",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".vue": "Vue",
}

_SECRET_RULES = (
    (
        "openai-api-key",
        RiskLevel.CRITICAL,
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "github-token",
        RiskLevel.CRITICAL,
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    ),
    (
        "aws-access-key",
        RiskLevel.CRITICAL,
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    (
        "private-key",
        RiskLevel.CRITICAL,
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    ),
    (
        "credential-assignment",
        RiskLevel.HIGH,
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
            r"password|secret)\b\s*[:=]\s*[\"']?[A-Za-z0-9_./+=-]{16,}"
        ),
    ),
)

_SECRET_FILENAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".npmrc",
    ".pypirc",
    "credentials.json",
    "service-account.json",
    "id_rsa",
    "id_ed25519",
}

_DEPENDENCY_FILES = {
    "package.json": "npm",
    "pyproject.toml": "python",
    "requirements.txt": "python",
    "requirements-dev.txt": "python",
    "Pipfile": "python",
    "poetry.lock": "python",
    "uv.lock": "python",
    "Cargo.toml": "cargo",
    "go.mod": "go",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "Gemfile": "ruby",
    "composer.json": "composer",
}

_TEST_CONFIG_NAMES = {
    "pytest.ini",
    "tox.ini",
    "jest.config.js",
    "jest.config.ts",
    "vitest.config.js",
    "vitest.config.ts",
    "playwright.config.js",
    "playwright.config.ts",
    "cypress.config.js",
    "cypress.config.ts",
    "phpunit.xml",
}

_BUILD_CONFIG_NAMES = {
    "Makefile",
    "CMakeLists.txt",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "vite.config.js",
    "vite.config.ts",
    "webpack.config.js",
    "turbo.json",
    "nx.json",
}

_DEPLOYMENT_CONFIG_NAMES = {
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "vercel.json",
    "netlify.toml",
    "fly.toml",
    "render.yaml",
    "Procfile",
    "wrangler.toml",
    "wrangler.json",
    "wrangler.jsonc",
    "serverless.yml",
    "serverless.yaml",
}

_CI_CONFIG_NAMES = {
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    "Jenkinsfile",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "bitbucket-pipelines.yml",
}

_FRAMEWORK_DEPENDENCIES = {
    "@angular/core": "Angular",
    "@cloudflare/workers-types": "Cloudflare Workers",
    "@nestjs/core": "NestJS",
    "@remix-run/react": "Remix",
    "@sveltejs/kit": "SvelteKit",
    "astro": "Astro",
    "django": "Django",
    "fastapi": "FastAPI",
    "flask": "Flask",
    "hono": "Hono",
    "next": "Next.js",
    "nuxt": "Nuxt",
    "react": "React",
    "rails": "Ruby on Rails",
    "spring-boot": "Spring Boot",
    "svelte": "Svelte",
    "vue": "Vue",
}

_BIDI_CONTROLS = {
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}


def _clean_path(value: str, limit: int = 512) -> str:
    cleaned = "".join(
        character if 32 <= ord(character) != 127 and character not in _BIDI_CONTROLS else "?"
        for character in value
    )
    return cleaned[:limit]


def _append_bounded(items: list[Any], item: Any, limit: int) -> bool:
    if len(items) >= limit:
        return False
    items.append(item)
    return True


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _is_sensitive_filename(name: str) -> bool:
    normalized = name.casefold()
    if normalized in _SECRET_FILENAMES:
        return True
    return normalized.startswith(".env.") and normalized not in {
        ".env.example",
        ".env.sample",
        ".env.template",
    }


def is_sensitive_path(value: str) -> bool:
    return any(_is_sensitive_filename(part) for part in PurePosixPath(value).parts)


def secret_rule_ids(data: bytes) -> list[str]:
    """Return only matching rule identifiers; never return credential material."""
    text = data.decode("utf-8", errors="replace")
    return sorted(
        {rule_id for rule_id, _severity, pattern in _SECRET_RULES if pattern.search(text)}
    )


class RepositoryInspector:
    def __init__(
        self,
        workspace_root: Path | str,
        repository_mappings: Mapping[str, str] | None = None,
        limits: InspectionLimits | None = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.repository_mappings = dict(repository_mappings or {})
        self.limits = limits or InspectionLimits()
        git_binary = shutil.which("git", path="/usr/local/bin:/usr/bin:/bin")
        self.git_binary = str(Path(git_binary).resolve()) if git_binary else None

    @property
    def enabled(self) -> bool:
        return self.workspace_root.is_dir() and bool(self.repository_mappings)

    def inspect(self, reference: RepositoryRef) -> RepositoryInspection:
        repository = self._resolve_repository(reference)
        scan_roots = self._resolve_scan_roots(repository, reference.allowed_paths)
        warnings: list[str] = []
        git_before = self._inspect_git(repository, reference, warnings)
        metadata_before = self._combined_metadata_fingerprint(repository, scan_roots)
        limits_reached: list[str] = []
        files: list[tuple[Path, str, os.stat_result]] = []
        directory_count = 0
        total_bytes = 0
        symlinks: list[PathFinding] = []
        large_files: list[PathFinding] = []

        seen_paths: set[Path] = set()
        pending = []
        for path in scan_roots:
            relative = path.relative_to(repository).as_posix()
            pending.append((path, "" if relative == "." else relative))
        while pending:
            current, current_relative = pending.pop()
            if current in seen_paths:
                continue
            seen_paths.add(current)
            try:
                current_stat = current.lstat()
            except OSError:
                warnings.append(f"Could not stat {_clean_path(current_relative or '.')}.")
                continue
            if stat.S_ISLNK(current_stat.st_mode):
                target = os.readlink(current)
                resolved_target = (current.parent / target).resolve(strict=False)
                detail = (
                    "inside repository"
                    if _is_relative_to(resolved_target, repository)
                    else "escapes repository"
                )
                _append_bounded(
                    symlinks,
                    PathFinding(
                        path=_clean_path(current_relative),
                        category="symlink",
                        detail=detail,
                    ),
                    self.limits.max_list_items,
                )
                continue
            if stat.S_ISREG(current_stat.st_mode):
                if len(files) >= self.limits.max_files:
                    limits_reached.append("file_count")
                    break
                files.append((current, _clean_path(current_relative), current_stat))
                total_bytes += current_stat.st_size
                if current_stat.st_size >= self.limits.large_file_bytes:
                    _append_bounded(
                        large_files,
                        PathFinding(
                            path=_clean_path(current_relative),
                            category="large_file",
                            detail=f"{current_stat.st_size} bytes",
                        ),
                        self.limits.max_list_items,
                    )
                if total_bytes > self.limits.max_total_bytes:
                    limits_reached.append("total_bytes")
                    break
                continue
            if not stat.S_ISDIR(current_stat.st_mode):
                continue

            if current != repository and (
                (current / ".git").is_dir() or (current / ".git").is_file()
            ):
                warnings.append(
                    f"Nested repository boundary skipped: {_clean_path(current_relative)}."
                )
                continue
            directory_count += 1
            try:
                entries = sorted(os.scandir(current), key=lambda entry: entry.name)
            except OSError:
                warnings.append(f"Could not read directory {_clean_path(current_relative or '.')}.")
                continue
            for entry in reversed(entries):
                relative = f"{current_relative}/{entry.name}" if current_relative else entry.name
                if entry.is_dir(follow_symlinks=False) and entry.name in _EXCLUDED_DIRECTORIES:
                    continue
                pending.append((Path(entry.path), relative))

        analysis = self._analyze_files(files, limits_reached)
        metadata_after = self._combined_metadata_fingerprint(repository, scan_roots)
        git_after = self._inspect_git(repository, reference, warnings)
        git_stable = git_before.model_dump(mode="json") == git_after.model_dump(mode="json")
        read_only_verified = metadata_before == metadata_after and git_stable
        if not read_only_verified:
            warnings.append("Repository or Git metadata changed during inspection.")
        if git_before.status_truncated:
            limits_reached.append("git_status_output")
        if not git_before.metadata_complete:
            limits_reached.append("git_metadata_incomplete")
        if git_before.is_repository and git_before.recovery_snapshot_digest is None:
            limits_reached.append("recovery_snapshot_incomplete")
        fingerprint_payload = json.dumps(
            {
                "metadata": metadata_before,
                "recovery_snapshot": git_before.recovery_snapshot_digest,
                "git": git_before.model_dump(mode="json"),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        repository_fingerprint = hashlib.sha256(fingerprint_payload.encode()).hexdigest()

        dirty = bool(
            git_before.staged_paths
            or git_before.modified_paths
            or git_before.deleted_paths
            or git_before.renamed_paths
            or git_before.untracked_paths
            or git_before.conflicted_paths
        )
        recovery_reasons: list[str] = []
        if (
            git_before.staged_paths
            or git_before.modified_paths
            or git_before.deleted_paths
            or git_before.renamed_paths
        ):
            recovery_reasons.append("Tracked working-tree changes are present.")
        if git_before.untracked_paths:
            recovery_reasons.append("Untracked files are present.")
        if git_before.ahead:
            recovery_reasons.append("Local commits are ahead of the configured upstream.")
        recovery = RecoveryAssessment(
            dirty_worktree=dirty,
            patch_recommended=bool(
                git_before.staged_paths
                or git_before.modified_paths
                or git_before.deleted_paths
                or git_before.renamed_paths
            ),
            untracked_archive_recommended=bool(git_before.untracked_paths),
            bundle_recommended=git_before.ahead > 0,
            reasons=recovery_reasons,
        )

        return RepositoryInspection(
            provider=reference.provider,
            repository_id=reference.repository_id,
            repository_fingerprint=repository_fingerprint,
            complete=not limits_reached and git_before.metadata_complete and read_only_verified,
            allowed_paths=list(reference.allowed_paths),
            file_count=len(files),
            directory_count=directory_count,
            total_bytes=total_bytes,
            scanned_text_bytes=analysis["scanned_text_bytes"],
            symlinks=symlinks,
            large_files=large_files,
            languages=analysis["languages"],
            frameworks=analysis["frameworks"],
            dependency_manifests=analysis["dependency_manifests"],
            test_configs=analysis["test_configs"],
            build_configs=analysis["build_configs"],
            deployment_configs=analysis["deployment_configs"],
            ci_configs=analysis["ci_configs"],
            secret_findings=analysis["secret_findings"],
            git=git_before,
            recovery=recovery,
            warnings=sorted(set(warnings)),
            limits_reached=sorted(set(limits_reached)),
            read_only_verified=read_only_verified,
        )

    def registered_path(self, reference: RepositoryRef) -> Path:
        """Resolve a server-registered repository for another bounded internal service."""
        return self._resolve_repository(reference)

    def validate_git_metadata_safety(self, repository: Path) -> None:
        """Revalidate a resolved registered repository before bounded Git operations."""
        resolved = repository.resolve(strict=True)
        if resolved != repository or not _is_relative_to(resolved, self.workspace_root):
            raise RepositoryAccessError("repository is outside the registered workspace")
        self._validate_git_metadata_safety(resolved)

    def planning_context(self, inspection: RepositoryInspection) -> dict[str, Any]:
        """Return only bounded, non-content facts safe to place in a model prompt."""
        return {
            "schema_version": inspection.schema_version,
            "provider": inspection.provider,
            "file_count": inspection.file_count,
            "directory_count": inspection.directory_count,
            "total_bytes": inspection.total_bytes,
            "complete": inspection.complete,
            "languages": [
                {"language": item.language, "files": item.files}
                for item in inspection.languages[:20]
            ],
            "frameworks": inspection.frameworks[:30],
            "dependency_ecosystems": sorted(
                {item.ecosystem for item in inspection.dependency_manifests}
            ),
            "test_config_count": len(inspection.test_configs),
            "build_config_count": len(inspection.build_configs),
            "deployment_config_count": len(inspection.deployment_configs),
            "ci_config_count": len(inspection.ci_configs),
            "secret_finding_rule_ids": sorted(
                {item.rule_id for item in inspection.secret_findings}
            ),
            "git": {
                "is_repository": inspection.git.is_repository,
                "metadata_complete": inspection.git.metadata_complete,
                "revision_matches_head": (
                    inspection.git.resolved_revision == inspection.git.head_revision
                    if inspection.git.resolved_revision and inspection.git.head_revision
                    else None
                ),
                "detached_head": inspection.git.detached_head,
                "ahead": inspection.git.ahead,
                "behind": inspection.git.behind,
                "staged_count": len(inspection.git.staged_paths),
                "modified_count": len(inspection.git.modified_paths),
                "deleted_count": len(inspection.git.deleted_paths),
                "renamed_count": len(inspection.git.renamed_paths),
                "untracked_count": len(inspection.git.untracked_paths),
                "ignored_count": len(inspection.git.ignored_paths),
                "conflicted_count": len(inspection.git.conflicted_paths),
                "submodule_count": len(inspection.git.submodules),
                "recovery_snapshot_bound": (inspection.git.recovery_snapshot_digest is not None),
                "snapshot_file_count": inspection.git.snapshot_file_count,
                "snapshot_total_bytes": inspection.git.snapshot_total_bytes,
                "ignored_paths_included": inspection.git.ignored_paths_included,
            },
            "recovery": inspection.recovery.model_dump(mode="json"),
            "limits_reached": inspection.limits_reached,
            "read_only_verified": inspection.read_only_verified,
        }

    def _resolve_repository(self, reference: RepositoryRef) -> Path:
        if not self.enabled:
            raise RepositoryAccessError("repository registry is not configured")
        mapping_key = f"{reference.provider}:{reference.repository_id}"
        raw = self.repository_mappings.get(mapping_key)
        if raw is None:
            raise RepositoryAccessError("repository is not registered for inspection")
        if "\\" in raw:
            raise RepositoryAccessError("registered repository path must use POSIX separators")
        pure = PurePosixPath(raw)
        if pure.is_absolute() or ".." in pure.parts:
            raise RepositoryAccessError("registered repository path escapes the workspace root")
        candidate = self.workspace_root / Path(*pure.parts)
        self._reject_symlink_components(candidate)
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise RepositoryAccessError("repository is not available in the workspace") from exc
        if not resolved.is_dir() or not _is_relative_to(resolved, self.workspace_root):
            raise RepositoryAccessError("repository must be a directory inside the workspace root")
        self._validate_git_pointer(resolved)
        return resolved

    def _validate_git_pointer(self, repository: Path) -> None:
        git_marker = repository / ".git"
        if git_marker.is_symlink():
            raise RepositoryAccessError("repository Git metadata cannot be a symlink")
        if not git_marker.is_file():
            return
        try:
            first_line = git_marker.read_text(encoding="utf-8", errors="replace").splitlines()[0]
        except (OSError, IndexError) as exc:
            raise RepositoryAccessError("repository Git pointer is invalid") from exc
        if not first_line.startswith("gitdir: "):
            raise RepositoryAccessError("repository Git pointer is invalid")
        target = (repository / first_line.removeprefix("gitdir: ").strip()).resolve(strict=False)
        if not _is_relative_to(target, self.workspace_root):
            raise RepositoryAccessError("repository Git pointer escapes the workspace root")

    def _reject_symlink_components(self, candidate: Path) -> None:
        relative = candidate.relative_to(self.workspace_root)
        current = self.workspace_root
        for part in relative.parts:
            current = current / part
            if current.exists() and current.is_symlink():
                raise RepositoryAccessError("repository path cannot contain symlink components")

    def _resolve_scan_roots(self, repository: Path, allowed_paths: list[str]) -> list[Path]:
        if not allowed_paths:
            return [repository]
        roots: list[Path] = []
        for raw in allowed_paths:
            candidate = repository / Path(*PurePosixPath(raw.replace("\\", "/")).parts)
            self._reject_repository_symlinks(repository, candidate)
            try:
                resolved = candidate.resolve(strict=True)
            except OSError as exc:
                raise RepositoryAccessError(
                    f"allowed path is unavailable: {_clean_path(raw)}"
                ) from exc
            if not _is_relative_to(resolved, repository):
                raise RepositoryAccessError("allowed path escapes repository")
            roots.append(resolved)
        return sorted(set(roots))

    @staticmethod
    def _reject_repository_symlinks(repository: Path, candidate: Path) -> None:
        relative = candidate.relative_to(repository)
        current = repository
        for part in relative.parts:
            current = current / part
            if current.exists() and current.is_symlink():
                raise RepositoryAccessError("allowed path cannot contain symlink components")

    def _metadata_fingerprint(self, repository: Path, roots: list[Path]) -> str:
        digest = hashlib.sha256()
        seen: set[Path] = set()
        pending = list(roots)
        count = 0
        while pending and count <= self.limits.max_files:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            try:
                metadata = current.lstat()
            except OSError:
                continue
            relative = current.relative_to(repository).as_posix()
            target = os.readlink(current) if stat.S_ISLNK(metadata.st_mode) else ""
            digest.update(
                (
                    f"{relative}\0{metadata.st_mode}\0{metadata.st_size}\0"
                    f"{metadata.st_mtime_ns}\0{target}\n"
                ).encode("utf-8", errors="surrogateescape")
            )
            count += 1
            if stat.S_ISDIR(metadata.st_mode):
                try:
                    entries = os.scandir(current)
                except OSError:
                    continue
                with entries:
                    for entry in entries:
                        if (
                            entry.is_dir(follow_symlinks=False)
                            and entry.name in _EXCLUDED_DIRECTORIES
                        ):
                            continue
                        pending.append(Path(entry.path))
        return digest.hexdigest()

    def _combined_metadata_fingerprint(self, repository: Path, roots: list[Path]) -> str:
        worktree = self._metadata_fingerprint(repository, roots)
        git_metadata = self._git_metadata_fingerprint(repository)
        return hashlib.sha256(f"{worktree}:{git_metadata}".encode()).hexdigest()

    def _git_metadata_fingerprint(self, repository: Path) -> str:
        git_marker = repository / ".git"
        if git_marker.is_dir():
            git_directory = git_marker
        elif git_marker.is_file():
            try:
                first_line = git_marker.read_text(encoding="utf-8", errors="replace").splitlines()[
                    0
                ]
            except (OSError, IndexError):
                return "unavailable"
            if not first_line.startswith("gitdir: "):
                return "unavailable"
            git_directory = (repository / first_line.removeprefix("gitdir: ").strip()).resolve(
                strict=False
            )
        else:
            return "not-a-git-repository"
        if not _is_relative_to(git_directory, self.workspace_root):
            return "outside-workspace"

        digest = hashlib.sha256()
        targets = [
            git_directory / "HEAD",
            git_directory / "index",
            git_directory / "config",
            git_directory / "packed-refs",
            git_directory / "shallow",
            git_directory / "refs",
            git_directory / "logs",
        ]
        seen: set[Path] = set()
        pending = targets.copy()
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            try:
                metadata = current.lstat()
            except OSError:
                continue
            relative = current.relative_to(git_directory).as_posix()
            digest.update(
                (
                    f"{relative}\0{metadata.st_mode}\0{metadata.st_size}\0{metadata.st_mtime_ns}\n"
                ).encode("utf-8", errors="surrogateescape")
            )
            if stat.S_ISLNK(metadata.st_mode):
                digest.update(os.readlink(current).encode("utf-8", errors="surrogateescape"))
            elif stat.S_ISDIR(metadata.st_mode):
                try:
                    pending.extend(sorted(current.iterdir(), reverse=True))
                except OSError:
                    continue
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_size <= 10_000_000:
                try:
                    content = self._read_regular_file(current, metadata, metadata.st_size)
                except OSError:
                    continue
                digest.update(hashlib.sha256(content).digest())
        return digest.hexdigest()

    def _analyze_files(
        self,
        files: list[tuple[Path, str, os.stat_result]],
        limits_reached: list[str],
    ) -> dict[str, Any]:
        language_counts: Counter[str] = Counter()
        language_bytes: Counter[str] = Counter()
        dependency_manifests: list[DependencyManifest] = []
        test_configs: list[PathFinding] = []
        build_configs: list[PathFinding] = []
        deployment_configs: list[PathFinding] = []
        ci_configs: list[PathFinding] = []
        secret_findings: list[SecretFinding] = []
        frameworks: set[str] = set()
        scanned_text_bytes = 0

        for path, relative, metadata in files:
            suffix = path.suffix.lower()
            language = _LANGUAGES.get(suffix)
            if language:
                language_counts[language] += 1
                language_bytes[language] += metadata.st_size

            name = path.name
            lower_relative = relative.lower()
            if name in _TEST_CONFIG_NAMES or "/tests/" in f"/{lower_relative}/":
                _append_bounded(
                    test_configs,
                    PathFinding(path=relative, category="test"),
                    self.limits.max_list_items,
                )
            if name in _BUILD_CONFIG_NAMES:
                _append_bounded(
                    build_configs,
                    PathFinding(path=relative, category="build"),
                    self.limits.max_list_items,
                )
            if name in _DEPLOYMENT_CONFIG_NAMES or lower_relative.startswith(
                ("k8s/", "kubernetes/", "terraform/")
            ):
                _append_bounded(
                    deployment_configs,
                    PathFinding(path=relative, category="deployment"),
                    self.limits.max_list_items,
                )
            if name in _CI_CONFIG_NAMES or lower_relative.startswith(".github/workflows/"):
                _append_bounded(
                    ci_configs,
                    PathFinding(path=relative, category="continuous_integration"),
                    self.limits.max_list_items,
                )

            sensitive_filename = _is_sensitive_filename(name)
            if sensitive_filename:
                _append_bounded(
                    secret_findings,
                    SecretFinding(
                        path=relative,
                        rule_id="sensitive-filename",
                        severity=RiskLevel.HIGH,
                    ),
                    self.limits.max_findings,
                )

            should_read = (
                metadata.st_size <= self.limits.max_text_file_bytes
                and scanned_text_bytes < self.limits.max_text_bytes
                and not sensitive_filename
                and metadata.st_nlink == 1
            )
            raw = b""
            text: str | None = None
            if should_read:
                remaining = self.limits.max_text_bytes - scanned_text_bytes
                try:
                    raw = self._read_regular_file(
                        path,
                        metadata,
                        min(self.limits.max_text_file_bytes, remaining),
                    )
                except OSError:
                    raw = b""
                scanned_text_bytes += len(raw)
                if raw and b"\x00" not in raw[:8192]:
                    text = raw.decode("utf-8", errors="replace")
            elif metadata.st_size <= self.limits.max_text_file_bytes and not sensitive_filename:
                limits_reached.append("text_bytes")

            if text is not None and len(secret_findings) < self.limits.max_findings:
                for line_number, line in enumerate(text.splitlines(), start=1):
                    for rule_id, severity, pattern in _SECRET_RULES:
                        if pattern.search(line):
                            _append_bounded(
                                secret_findings,
                                SecretFinding(
                                    path=relative,
                                    rule_id=rule_id,
                                    severity=severity,
                                    line=line_number,
                                ),
                                self.limits.max_findings,
                            )
                    if len(secret_findings) >= self.limits.max_findings:
                        limits_reached.append("secret_findings")
                        break

            if name == "pyproject.toml" and text is not None:
                if "[tool.pytest" in text:
                    _append_bounded(
                        test_configs,
                        PathFinding(path=relative, category="test"),
                        self.limits.max_list_items,
                    )
                if "[build-system]" in text:
                    _append_bounded(
                        build_configs,
                        PathFinding(path=relative, category="build"),
                        self.limits.max_list_items,
                    )
            if name == "package.json" and text is not None:
                try:
                    package_payload = json.loads(text)
                except json.JSONDecodeError:
                    package_payload = {}
                scripts = package_payload.get("scripts", {})
                if isinstance(scripts, dict):
                    if "test" in scripts:
                        _append_bounded(
                            test_configs,
                            PathFinding(
                                path=relative,
                                category="test",
                                detail="declared test script",
                            ),
                            self.limits.max_list_items,
                        )
                    if "build" in scripts:
                        _append_bounded(
                            build_configs,
                            PathFinding(
                                path=relative,
                                category="build",
                                detail="declared build script",
                            ),
                            self.limits.max_list_items,
                        )

            ecosystem = _DEPENDENCY_FILES.get(name)
            if ecosystem:
                manifest, dependencies = self._parse_manifest(relative, name, ecosystem, text)
                dependency_manifests.append(manifest)
                for dependency in dependencies:
                    framework = _FRAMEWORK_DEPENDENCIES.get(dependency.lower())
                    if framework:
                        frameworks.add(framework)

            for filename, framework in {
                "next.config.js": "Next.js",
                "next.config.mjs": "Next.js",
                "next.config.ts": "Next.js",
                "nuxt.config.js": "Nuxt",
                "nuxt.config.ts": "Nuxt",
                "astro.config.mjs": "Astro",
                "svelte.config.js": "SvelteKit",
                "wrangler.toml": "Cloudflare Workers",
                "wrangler.json": "Cloudflare Workers",
                "wrangler.jsonc": "Cloudflare Workers",
            }.items():
                if name == filename:
                    frameworks.add(framework)

        languages = [
            LanguageStat(
                language=language,
                files=language_counts[language],
                bytes=language_bytes[language],
            )
            for language in sorted(
                language_counts,
                key=lambda item: (-language_counts[item], item),
            )
        ]
        return {
            "scanned_text_bytes": scanned_text_bytes,
            "languages": languages,
            "frameworks": sorted(frameworks),
            "dependency_manifests": dependency_manifests[: self.limits.max_list_items],
            "test_configs": test_configs,
            "build_configs": build_configs,
            "deployment_configs": deployment_configs,
            "ci_configs": ci_configs,
            "secret_findings": secret_findings,
        }

    @staticmethod
    def _read_regular_file(path: Path, expected: os.stat_result, limit: int) -> bytes:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            observed = os.fstat(descriptor)
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_dev != expected.st_dev
                or observed.st_ino != expected.st_ino
                or observed.st_size != expected.st_size
            ):
                return b""
            return os.read(descriptor, limit)
        finally:
            os.close(descriptor)

    @staticmethod
    def _parse_manifest(
        relative: str,
        name: str,
        ecosystem: str,
        text: str | None,
    ) -> tuple[DependencyManifest, set[str]]:
        if text is None:
            return (
                DependencyManifest(
                    path=relative,
                    ecosystem=ecosystem,
                    parse_status="not_read",
                ),
                set(),
            )
        direct = 0
        development = 0
        dependencies: set[str] = set()
        try:
            if name == "package.json":
                payload = json.loads(text)
                runtime = payload.get("dependencies", {})
                dev = payload.get("devDependencies", {})
                if not isinstance(runtime, dict) or not isinstance(dev, dict):
                    raise ValueError("dependency sections must be objects")
                dependencies.update(str(item).lower() for item in runtime)
                dependencies.update(str(item).lower() for item in dev)
                direct = len(runtime)
                development = len(dev)
            elif name == "pyproject.toml":
                payload = tomllib.loads(text)
                project_dependencies = payload.get("project", {}).get("dependencies", [])
                if isinstance(project_dependencies, list):
                    direct = len(project_dependencies)
                    dependencies.update(
                        re.split(r"[\s<>=!~\[]", str(item), maxsplit=1)[0].lower()
                        for item in project_dependencies
                    )
                optional = payload.get("project", {}).get("optional-dependencies", {})
                if isinstance(optional, dict):
                    development = sum(
                        len(items) for items in optional.values() if isinstance(items, list)
                    )
            elif name.startswith("requirements") and name.endswith(".txt"):
                entries = [
                    line.strip()
                    for line in text.splitlines()
                    if line.strip() and not line.lstrip().startswith(("#", "-"))
                ]
                direct = len(entries)
                dependencies.update(
                    re.split(r"[\s<>=!~\[]", item, maxsplit=1)[0].lower() for item in entries
                )
            elif name == "Cargo.toml":
                payload = tomllib.loads(text)
                runtime = payload.get("dependencies", {})
                dev = payload.get("dev-dependencies", {})
                direct = len(runtime) if isinstance(runtime, dict) else 0
                development = len(dev) if isinstance(dev, dict) else 0
                if isinstance(runtime, dict):
                    dependencies.update(str(item).lower() for item in runtime)
                if isinstance(dev, dict):
                    dependencies.update(str(item).lower() for item in dev)
            elif name == "go.mod":
                direct = sum(
                    1
                    for line in text.splitlines()
                    if line.strip().startswith("require ") and "// indirect" not in line
                )
            else:
                return (
                    DependencyManifest(
                        path=relative,
                        ecosystem=ecosystem,
                        parse_status="detected",
                    ),
                    set(),
                )
        except (ValueError, TypeError, json.JSONDecodeError, tomllib.TOMLDecodeError):
            return (
                DependencyManifest(
                    path=relative,
                    ecosystem=ecosystem,
                    parse_status="invalid",
                ),
                set(),
            )
        return (
            DependencyManifest(
                path=relative,
                ecosystem=ecosystem,
                direct_dependencies=direct,
                development_dependencies=development,
                parse_status="parsed",
            ),
            dependencies,
        )

    def _inspect_git(
        self,
        repository: Path,
        reference: RepositoryRef,
        warnings: list[str],
    ) -> GitState:
        if not (repository / ".git").exists():
            if reference.revision != "WORKTREE":
                raise RepositoryAccessError("non-Git repositories must use the WORKTREE revision")
            return GitState(
                is_repository=False,
                requested_revision=reference.revision,
            )
        if self.git_binary is None:
            raise RepositoryInspectionError("Git metadata inspection is unavailable")
        if reference.revision != "WORKTREE" and not re.fullmatch(
            r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})",
            reference.revision,
        ):
            raise RepositoryAccessError(
                "requested revision must be WORKTREE or a full commit object id"
            )
        self._validate_git_metadata_safety(repository)
        configured_keys, _, config_ok = self._run_git(
            repository,
            [
                "config",
                "--file",
                str(repository / ".git" / "config"),
                "--no-includes",
                "--name-only",
                "--get-regexp",
                ".*",
            ],
            warnings,
            output_limit=64_000,
            allowed_return_codes={0, 1},
        )
        lowered_keys = {key.lower() for key in configured_keys.splitlines()}
        unsafe_configuration = {
            "core.worktree",
            "core.excludesfile",
            "core.attributesfile",
            "core.sparsecheckout",
            "core.sparsecheckoutcone",
            "extensions.partialclone",
            "extensions.worktreeconfig",
        }
        configured_filters = any(
            key.startswith("filter.")
            and key.endswith((".clean", ".smudge", ".process", ".required"))
            for key in lowered_keys
        )
        if configured_filters:
            raise RepositoryAccessError("Git content filters are not permitted during inspection")
        if (
            not config_ok
            or lowered_keys.intersection(unsafe_configuration)
            or any(
                key.startswith(("include.", "includeif.")) or key.endswith(".promisor")
                for key in lowered_keys
            )
        ):
            raise RepositoryAccessError(
                "Git configuration contains unsupported external or executable controls"
            )
        top_level, _, top_level_ok = self._run_git(
            repository,
            ["rev-parse", "--show-toplevel"],
            warnings,
            output_limit=4096,
        )
        try:
            resolved_top_level = Path(top_level.strip()).resolve(strict=True)
        except OSError as exc:
            raise RepositoryAccessError("Git worktree root is unavailable") from exc
        if not top_level_ok or resolved_top_level != repository:
            raise RepositoryAccessError(
                "Git worktree root does not match the registered repository"
            )

        head, _, head_ok = self._run_git(repository, ["rev-parse", "HEAD"], warnings)
        head_revision = head.strip() or None
        resolved_revision: str | None = None
        if reference.revision == "WORKTREE":
            resolved_revision = head_revision
        else:
            resolved, _, resolved_ok = self._run_git(
                repository,
                [
                    "rev-parse",
                    "--verify",
                    "--end-of-options",
                    f"{reference.revision}^{{commit}}",
                ],
                warnings,
            )
            resolved_revision = resolved.strip() or None
            if not resolved_ok or resolved_revision is None:
                raise RepositoryAccessError("requested revision could not be resolved")
            elif head_revision != resolved_revision:
                raise RepositoryAccessError(
                    "working-tree HEAD does not match the requested revision"
                )

        branch_output, _, branch_ok = self._run_git(
            repository,
            ["rev-parse", "--abbrev-ref", "HEAD"],
            warnings,
            output_limit=4096,
        )
        branch_value = branch_output.strip()
        branch = "(detached)" if branch_value == "HEAD" else branch_value or None
        upstream_output, _, upstream_ok = self._run_git(
            repository,
            ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
            warnings,
            output_limit=4096,
            allowed_return_codes={0, 128},
        )
        upstream = upstream_output.strip() or None
        ahead = 0
        behind = 0
        upstream_counts_ok = True
        if upstream is not None:
            counts_output, _, upstream_counts_ok = self._run_git(
                repository,
                ["rev-list", "--left-right", "--count", "HEAD...@{upstream}"],
                warnings,
                output_limit=4096,
            )
            match = re.fullmatch(r"(\d+)\s+(\d+)", counts_output.strip())
            if match:
                ahead, behind = int(match.group(1)), int(match.group(2))
            else:
                upstream_counts_ok = False

        object_format_output, _, object_format_ok = self._run_git(
            repository,
            ["rev-parse", "--show-object-format"],
            warnings,
            output_limit=128,
        )
        object_format = object_format_output.strip()
        if object_format not in {"sha1", "sha256"}:
            object_format_ok = False

        # Recovery safety is always inventoried across the full repository. Public
        # findings are filtered to allowed_paths only after cross-boundary checks.
        pathspec = ["--"]
        tree_output: bytes = b""
        tree_truncated = False
        tree_ok = False
        if head_revision is not None:
            tree_output, tree_truncated, tree_ok = self._run_git(
                repository,
                [
                    "ls-tree",
                    "-r",
                    "-z",
                    "--full-tree",
                    head_revision,
                    *pathspec,
                ],
                warnings,
                decode=False,
            )
        index_output, index_truncated, index_ok = self._run_git(
            repository,
            ["ls-files", "--stage", "-z", *pathspec],
            warnings,
            decode=False,
        )
        index_flags_output, index_flags_truncated, index_flags_ok = self._run_git(
            repository,
            ["ls-files", "-v", "-z", *pathspec],
            warnings,
            decode=False,
        )
        # No exclude rules are applied: ignored files are part of the recovery scope.
        untracked_output, untracked_truncated, untracked_ok = self._run_git(
            repository,
            ["ls-files", "--others", "-z", *pathspec],
            warnings,
            decode=False,
        )
        ignored_output, ignored_truncated, ignored_ok = self._run_git(
            repository,
            [
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "--directory",
                "--no-empty-directory",
                "-z",
                *pathspec,
            ],
            warnings,
            decode=False,
        )
        status_truncated = any(
            (
                tree_truncated,
                index_truncated,
                index_flags_truncated,
                untracked_truncated,
                ignored_truncated,
            )
        )

        head_entries: list[_GitEntry] = []
        index_entries: list[_GitEntry] = []
        untracked_paths: list[str] = []
        ignored_paths: list[str] = []
        snapshot = _SnapshotResult(None, 0, 0, False, "Git inventory is incomplete.")
        staged_paths: list[str] = []
        modified_paths: list[str] = []
        deleted_paths: list[str] = []
        renamed_paths: list[str] = []
        conflicted_paths: list[str] = []
        inventories_ok = (
            tree_ok
            and index_ok
            and index_flags_ok
            and untracked_ok
            and ignored_ok
            and not status_truncated
            and object_format_ok
            and head_revision is not None
        )
        if inventories_ok:
            assert head_revision is not None
            head_entries = self._parse_tree_inventory(tree_output, object_format)
            index_entries = self._parse_index_inventory(index_output, object_format)
            self._reject_unsupported_index_flags(index_flags_output)
            untracked_paths = self._decode_snapshot_paths(untracked_output)
            ignored_paths = self._decode_snapshot_paths(ignored_output)
            self._validate_full_inventory_paths(
                head_entries,
                index_entries,
                untracked_paths,
            )
            (
                full_staged_paths,
                full_modified_paths,
                full_deleted_paths,
                full_renamed_paths,
                full_conflicted_paths,
                snapshot,
            ) = self._build_recovery_snapshot(
                repository=repository,
                object_format=object_format,
                head_revision=head_revision,
                head_entries=head_entries,
                index_entries=index_entries,
                untracked_paths=untracked_paths,
                ignored_paths=ignored_paths,
                warnings=warnings,
            )
            self._reject_cross_scope_moves(
                repository=repository,
                allowed_paths=reference.allowed_paths,
                head_entries=head_entries,
                index_entries=index_entries,
                untracked_paths=untracked_paths,
                modified_paths=full_modified_paths,
                deleted_paths=full_deleted_paths,
            )
            staged_paths = self._filter_to_allowed_paths(
                full_staged_paths,
                reference.allowed_paths,
            )
            modified_paths = self._filter_to_allowed_paths(
                full_modified_paths,
                reference.allowed_paths,
            )
            deleted_paths = self._filter_to_allowed_paths(
                full_deleted_paths,
                reference.allowed_paths,
            )
            renamed_paths = self._filter_to_allowed_paths(
                full_renamed_paths,
                reference.allowed_paths,
            )
            conflicted_paths = self._filter_to_allowed_paths(
                full_conflicted_paths,
                reference.allowed_paths,
            )
            untracked_paths = self._filter_to_allowed_paths(
                untracked_paths,
                reference.allowed_paths,
            )
            ignored_paths = self._filter_to_allowed_paths(
                ignored_paths,
                reference.allowed_paths,
            )
            if not snapshot.complete and snapshot.unsafe_reason:
                warnings.append(snapshot.unsafe_reason)

        shallow_output, _, shallow_ok = self._run_git(
            repository, ["rev-parse", "--is-shallow-repository"], warnings
        )
        remotes_output, _, remotes_ok = self._run_git(repository, ["remote", "-v"], warnings)
        remotes = self._parse_remotes(remotes_output)
        submodules = self._parse_gitmodules(repository)
        self._validate_git_metadata_safety(repository)
        status_ok = inventories_ok and snapshot.complete
        return GitState(
            is_repository=True,
            metadata_complete=(
                status_ok
                and shallow_ok
                and remotes_ok
                and branch_ok
                and upstream_ok
                and upstream_counts_ok
                and head_ok
            ),
            requested_revision=reference.revision,
            resolved_revision=resolved_revision,
            head_revision=head_revision,
            branch=branch,
            detached_head=branch in {None, "(detached)"},
            upstream=upstream,
            ahead=ahead,
            behind=behind,
            shallow=shallow_output.strip() == "true",
            staged_paths=staged_paths,
            modified_paths=modified_paths,
            deleted_paths=deleted_paths,
            renamed_paths=renamed_paths,
            untracked_paths=untracked_paths,
            conflicted_paths=conflicted_paths,
            ignored_paths=ignored_paths,
            submodules=submodules,
            remotes=remotes,
            status_truncated=status_truncated,
            recovery_snapshot_digest=snapshot.digest,
            snapshot_file_count=snapshot.file_count,
            snapshot_total_bytes=snapshot.total_bytes,
            ignored_paths_included=True,
        )

    def _validate_git_metadata_safety(self, repository: Path) -> None:
        git_directory = repository / ".git"
        try:
            git_metadata = git_directory.lstat()
        except OSError as exc:
            raise RepositoryAccessError("Git metadata is unavailable") from exc
        if not stat.S_ISDIR(git_metadata.st_mode) or stat.S_ISLNK(git_metadata.st_mode):
            raise RepositoryAccessError("Git metadata must be an in-repository directory")

        forbidden_indirections = [
            git_directory / "objects" / "info" / "alternates",
            git_directory / "objects" / "info" / "http-alternates",
            git_directory / "info" / "grafts",
            git_directory / "info" / "attributes",
            git_directory / "commondir",
            git_directory / "gitdir",
        ]
        if any(path.exists() or path.is_symlink() for path in forbidden_indirections):
            raise RepositoryAccessError(
                "Git metadata indirection, attributes, and grafts are not permitted"
            )

        roots = [
            git_directory / "HEAD",
            git_directory / "index",
            git_directory / "config",
            git_directory / "config.worktree",
            git_directory / "packed-refs",
            git_directory / "shallow",
            git_directory / "info" / "exclude",
            git_directory / "refs",
            git_directory / "objects",
            *git_directory.glob("sharedindex.*"),
        ]
        pending = roots.copy()
        visited = 0
        maximum = max(self.limits.max_files * 4, 10_000)
        while pending:
            current = pending.pop()
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise RepositoryAccessError("Git metadata could not be validated") from exc
            visited += 1
            if visited > maximum:
                raise RepositoryAccessError("Git metadata exceeds the safety inventory limit")
            if stat.S_ISLNK(metadata.st_mode):
                raise RepositoryAccessError("Git metadata cannot contain symlinks")
            if stat.S_ISREG(metadata.st_mode):
                if current.name.endswith(".promisor"):
                    raise RepositoryAccessError("Git promisor object markers are not permitted")
                if metadata.st_nlink != 1:
                    raise RepositoryAccessError("Git metadata cannot contain hard-linked files")
                continue
            if stat.S_ISDIR(metadata.st_mode):
                try:
                    with os.scandir(current) as entries:
                        pending.extend(Path(entry.path) for entry in entries)
                except OSError as exc:
                    raise RepositoryAccessError("Git metadata could not be inventoried") from exc
                continue
            raise RepositoryAccessError("Git metadata contains an unsupported file type")

    def _parse_tree_inventory(
        self,
        raw: bytes,
        object_format: str,
    ) -> list[_GitEntry]:
        expected_length = 40 if object_format == "sha1" else 64
        entries: list[_GitEntry] = []
        for record in raw.split(b"\0"):
            if not record:
                continue
            try:
                metadata, encoded_path = record.split(b"\t", 1)
                mode_bytes, kind, object_id_bytes = metadata.split(b" ", 2)
                mode = mode_bytes.decode("ascii")
                object_id = object_id_bytes.decode("ascii").lower()
                path = self._decode_snapshot_path(encoded_path)
            except (ValueError, UnicodeDecodeError) as exc:
                raise RepositoryAccessError("Git tree inventory is malformed") from exc
            expected_kind = "commit" if mode == "160000" else "blob"
            if (
                mode not in {"100644", "100755", "120000", "160000"}
                or kind.decode("ascii", errors="replace") != expected_kind
                or not re.fullmatch(rf"[0-9a-f]{{{expected_length}}}", object_id)
            ):
                raise RepositoryAccessError("Git tree inventory has unsupported entries")
            entries.append(_GitEntry(mode=mode, object_id=object_id, path=path))
        return sorted(entries, key=lambda item: item.path)

    def _parse_index_inventory(
        self,
        raw: bytes,
        object_format: str,
    ) -> list[_GitEntry]:
        expected_length = 40 if object_format == "sha1" else 64
        entries: list[_GitEntry] = []
        for record in raw.split(b"\0"):
            if not record:
                continue
            try:
                metadata, encoded_path = record.split(b"\t", 1)
                mode_bytes, object_id_bytes, stage_bytes = metadata.split(b" ", 2)
                mode = mode_bytes.decode("ascii")
                object_id = object_id_bytes.decode("ascii").lower()
                stage = int(stage_bytes.decode("ascii"))
                path = self._decode_snapshot_path(encoded_path)
            except (ValueError, UnicodeDecodeError) as exc:
                raise RepositoryAccessError("Git index inventory is malformed") from exc
            if (
                mode not in {"100644", "100755", "120000", "160000"}
                or stage not in {0, 1, 2, 3}
                or not re.fullmatch(rf"[0-9a-f]{{{expected_length}}}", object_id)
            ):
                raise RepositoryAccessError("Git index has unsupported entries")
            entries.append(_GitEntry(mode=mode, object_id=object_id, path=path, stage=stage))
        return sorted(entries, key=lambda item: (item.path, item.stage))

    def _reject_unsupported_index_flags(self, raw: bytes) -> None:
        for record in raw.split(b"\0"):
            if not record:
                continue
            if len(record) < 3 or record[1:2] != b" ":
                raise RepositoryAccessError("Git index flag inventory is malformed")
            self._decode_snapshot_path(record[2:])
            if record[:1] != b"H":
                raise RepositoryAccessError(
                    "skip-worktree, sparse, and assume-unchanged index flags are unsupported"
                )

    def _decode_snapshot_paths(self, raw: bytes) -> list[str]:
        return sorted(self._decode_snapshot_path(item) for item in raw.split(b"\0") if item)

    @staticmethod
    def _decode_snapshot_path(raw: bytes) -> str:
        try:
            value = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise RepositoryAccessError("Git paths must use valid UTF-8") from exc
        pure = PurePosixPath(value)
        if (
            not value
            or len(raw) > 512
            or pure.is_absolute()
            or "\\" in value
            or len(pure.parts) > 32
            or any(part in {"", ".", ".."} for part in pure.parts)
            or any(len(part.encode("utf-8")) > 255 for part in pure.parts)
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or any(character in _BIDI_CONTROLS for character in value)
        ):
            raise RepositoryAccessError("Git inventory contains an unsafe path")
        return value

    def _validate_full_inventory_paths(
        self,
        head_entries: list[_GitEntry],
        index_entries: list[_GitEntry],
        untracked_paths: list[str],
    ) -> None:
        paths = {
            *(entry.path for entry in head_entries),
            *(entry.path for entry in index_entries),
            *untracked_paths,
        }
        normalized: dict[str, set[str]] = {}
        for path in paths:
            key = unicodedata.normalize("NFC", path).casefold()
            normalized.setdefault(key, set()).add(path)
        if any(len(raw_paths) > 1 for raw_paths in normalized.values()):
            raise RepositoryAccessError(
                "full Git inventory contains a normalized or case-fold path collision"
            )
        normalized_keys = set(normalized)
        for key in normalized_keys:
            parts = PurePosixPath(key).parts
            for length in range(1, len(parts)):
                if PurePosixPath(*parts[:length]).as_posix() in normalized_keys:
                    raise RepositoryAccessError(
                        "full Git inventory contains a file/ancestor path collision"
                    )

    def _reject_cross_scope_moves(
        self,
        *,
        repository: Path,
        allowed_paths: list[str],
        head_entries: list[_GitEntry],
        index_entries: list[_GitEntry],
        untracked_paths: list[str],
        modified_paths: list[str],
        deleted_paths: list[str],
    ) -> None:
        if not allowed_paths:
            return
        head = {entry.path: entry for entry in head_entries}
        index = {entry.path: entry for entry in index_entries if entry.stage == 0}
        changed = {
            path
            for path in set(head).union(index)
            if (
                path not in head
                or path not in index
                or (head[path].mode, head[path].object_id)
                != (index[path].mode, index[path].object_id)
            )
        }
        removed = set(head).difference(index)
        changed_destinations = changed.difference(removed)
        missing_index_paths = set(index).intersection(deleted_paths)
        worktree_destinations = set(untracked_paths).union(modified_paths)

        removed_inside = {path for path in removed if self._path_is_allowed(path, allowed_paths)}
        removed_outside = removed.difference(removed_inside)
        changed_inside = {
            path for path in changed_destinations if self._path_is_allowed(path, allowed_paths)
        }
        changed_outside = changed_destinations.difference(changed_inside)
        missing_inside = {
            path for path in missing_index_paths if self._path_is_allowed(path, allowed_paths)
        }
        missing_outside = missing_index_paths.difference(missing_inside)
        worktree_inside = {
            path for path in worktree_destinations if self._path_is_allowed(path, allowed_paths)
        }
        worktree_outside = worktree_destinations.difference(worktree_inside)

        if (
            (removed_outside and (changed_inside or worktree_inside))
            or (removed_inside and (changed_outside or worktree_outside))
            or (missing_outside and worktree_inside)
            or (missing_inside and worktree_outside)
        ):
            raise RepositoryAccessError(
                "cross-scope rename or move cannot be recovered within allowed_paths"
            )

        # Bind the repository descriptor to this check; resolving it again catches
        # a concurrent replacement before the approved snapshot is constructed.
        if repository.resolve(strict=True) != repository:
            raise RepositoryAccessError("repository changed during scope validation")

    @classmethod
    def _filter_to_allowed_paths(
        cls,
        paths: list[str],
        allowed_paths: list[str],
    ) -> list[str]:
        if not allowed_paths:
            return paths
        return sorted(path for path in paths if cls._path_is_allowed(path, allowed_paths))

    @staticmethod
    def _path_is_allowed(path: str, allowed_paths: list[str]) -> bool:
        normalized = path.rstrip("/")
        return any(
            normalized == allowed or normalized.startswith(f"{allowed}/")
            for allowed in allowed_paths
        )

    def _build_recovery_snapshot(
        self,
        *,
        repository: Path,
        object_format: str,
        head_revision: str,
        head_entries: list[_GitEntry],
        index_entries: list[_GitEntry],
        untracked_paths: list[str],
        ignored_paths: list[str],
        warnings: list[str],
    ) -> tuple[list[str], list[str], list[str], list[str], list[str], _SnapshotResult]:
        index_stage_zero = {entry.path: entry for entry in index_entries if entry.stage == 0}
        head_by_path = {entry.path: entry for entry in head_entries}
        conflicted = sorted({entry.path for entry in index_entries if entry.stage != 0})
        staged = sorted(
            path
            for path in set(head_by_path).union(index_stage_zero)
            if (
                path not in head_by_path
                or path not in index_stage_zero
                or (
                    head_by_path[path].mode,
                    head_by_path[path].object_id,
                )
                != (
                    index_stage_zero[path].mode,
                    index_stage_zero[path].object_id,
                )
            )
        )
        removed = {
            path: entry for path, entry in head_by_path.items() if path not in index_stage_zero
        }
        added = {
            path: entry for path, entry in index_stage_zero.items() if path not in head_by_path
        }
        renamed: set[str] = set()
        removed_by_identity: dict[tuple[str, str], list[str]] = {}
        for path, entry in removed.items():
            removed_by_identity.setdefault((entry.mode, entry.object_id), []).append(path)
        for path, entry in added.items():
            sources = removed_by_identity.get((entry.mode, entry.object_id), [])
            if sources:
                renamed.add(path)
                renamed.update(sources)

        snapshot_paths = sorted(set(index_stage_zero).union(untracked_paths))
        if len(snapshot_paths) > self.limits.max_files:
            return (
                staged,
                [],
                sorted(removed),
                sorted(renamed),
                conflicted,
                _SnapshotResult(
                    None,
                    len(snapshot_paths),
                    0,
                    False,
                    "Recovery snapshot exceeded the file-count limit.",
                ),
            )

        digest = hashlib.sha256()
        digest.update(b"LILTWEAK-RECOVERY-SNAPSHOT-V1\0")
        digest.update(object_format.encode("ascii") + b"\0")
        digest.update(head_revision.encode("ascii") + b"\0")
        for entry in head_entries:
            self._update_entry_digest(digest, b"head", entry)
        for entry in index_entries:
            self._update_entry_digest(digest, b"index", entry)
        for path in ignored_paths:
            digest.update(b"ignored\0" + path.encode("utf-8") + b"\0")

        modified: list[str] = []
        deleted: set[str] = set(removed)
        total_bytes = 0
        file_count = 0
        untracked_set = set(untracked_paths)
        for path in snapshot_paths:
            remaining = self.limits.max_total_bytes - total_bytes
            try:
                observed_kind, observed_mode, content = self._read_snapshot_path(
                    repository,
                    path,
                    remaining,
                )
            except RepositoryAccessError as exc:
                return (
                    staged,
                    sorted(modified),
                    sorted(deleted),
                    sorted(renamed),
                    conflicted,
                    _SnapshotResult(
                        None,
                        file_count,
                        total_bytes,
                        False,
                        f"Recovery snapshot was blocked: {exc}.",
                    ),
                )
            content_digest = hashlib.sha256(content).hexdigest()
            total_bytes += len(content)
            file_count += 1
            if total_bytes > self.limits.max_total_bytes:
                return (
                    staged,
                    sorted(modified),
                    sorted(deleted),
                    sorted(renamed),
                    conflicted,
                    _SnapshotResult(
                        None,
                        file_count,
                        total_bytes,
                        False,
                        "Recovery snapshot exceeded the byte limit.",
                    ),
                )
            if path in untracked_set and observed_kind in {"missing", "directory"}:
                return (
                    staged,
                    sorted(modified),
                    sorted(deleted),
                    sorted(renamed),
                    conflicted,
                    _SnapshotResult(
                        None,
                        file_count,
                        total_bytes,
                        False,
                        "A non-index recovery path disappeared or became a directory.",
                    ),
                )
            if observed_kind == "directory":
                return (
                    staged,
                    sorted(modified),
                    sorted(deleted),
                    sorted(renamed),
                    conflicted,
                    _SnapshotResult(
                        None,
                        file_count,
                        total_bytes,
                        False,
                        "Recovery snapshot paths cannot be directories.",
                    ),
                )
            digest.update(
                json.dumps(
                    {
                        "kind": "worktree",
                        "path": path,
                        "file_type": observed_kind,
                        "mode": observed_mode,
                        "bytes": len(content),
                        "sha256": content_digest,
                        "untracked": path in untracked_set,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\0"
            )
            index_entry = index_stage_zero.get(path)
            if index_entry is None:
                continue
            if observed_kind == "missing":
                deleted.add(path)
                continue
            expected_kind = "symlink" if index_entry.mode == "120000" else "regular"
            expected_mode = 0o755 if index_entry.mode == "100755" else 0o644
            if index_entry.mode == "160000":
                raise RepositoryAccessError(
                    "Git submodule entries are unsupported for byte-accurate recovery"
                )
            object_id = self._git_blob_object_id(content, object_format)
            if (
                observed_kind != expected_kind
                or object_id != index_entry.object_id
                or (
                    observed_kind == "regular"
                    and (observed_mode & 0o111) != (expected_mode & 0o111)
                )
            ):
                modified.append(path)

        required_blobs: set[str] = set()
        for path in set(staged).union(modified).union(deleted):
            for candidate_entry in (head_by_path.get(path), index_stage_zero.get(path)):
                if candidate_entry is not None and candidate_entry.mode != "160000":
                    required_blobs.add(candidate_entry.object_id)
        for object_id in sorted(required_blobs):
            remaining = self.limits.max_total_bytes - total_bytes
            output_limit = min(
                self.limits.max_recovery_blob_bytes,
                max(remaining, 0),
            )
            if output_limit <= 0:
                return (
                    staged,
                    sorted(set(modified)),
                    sorted(deleted),
                    sorted(renamed),
                    conflicted,
                    _SnapshotResult(
                        None,
                        file_count,
                        total_bytes,
                        False,
                        "Recovery snapshot exceeded the byte limit.",
                    ),
                )
            blob, truncated, blob_ok = self._run_git(
                repository,
                ["cat-file", "blob", object_id],
                warnings,
                decode=False,
                output_limit=output_limit,
            )
            if (
                not blob_ok
                or truncated
                or self._git_blob_object_id(blob, object_format) != object_id
            ):
                return (
                    staged,
                    sorted(set(modified)),
                    sorted(deleted),
                    sorted(renamed),
                    conflicted,
                    _SnapshotResult(
                        None,
                        file_count,
                        total_bytes,
                        False,
                        "A required local Git blob could not be verified.",
                    ),
                )
            total_bytes += len(blob)
            digest.update(
                b"blob\0"
                + object_id.encode("ascii")
                + b"\0"
                + hashlib.sha256(blob).hexdigest().encode("ascii")
                + b"\0"
                + str(len(blob)).encode("ascii")
                + b"\0"
            )

        return (
            staged,
            sorted(set(modified)),
            sorted(deleted),
            sorted(renamed),
            conflicted,
            _SnapshotResult(
                digest.hexdigest(),
                file_count,
                total_bytes,
                True,
            ),
        )

    @staticmethod
    def _update_entry_digest(
        digest: Any,
        source: bytes,
        entry: _GitEntry,
    ) -> None:
        digest.update(source + b"\0")
        digest.update(entry.mode.encode("ascii") + b"\0")
        digest.update(entry.object_id.encode("ascii") + b"\0")
        digest.update(str(entry.stage).encode("ascii") + b"\0")
        digest.update(entry.path.encode("utf-8") + b"\0")

    @staticmethod
    def _git_blob_object_id(content: bytes, object_format: str) -> str:
        digest = hashlib.new(object_format)
        digest.update(f"blob {len(content)}\0".encode("ascii"))
        digest.update(content)
        return digest.hexdigest()

    def _read_snapshot_path(
        self,
        repository: Path,
        relative: str,
        maximum_bytes: int,
    ) -> tuple[str, int, bytes]:
        parts = PurePosixPath(relative).parts
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            directory_flags |= os.O_CLOEXEC
        try:
            directory_descriptor = os.open(repository, directory_flags)
        except OSError as exc:
            raise RepositoryAccessError("repository changed during snapshot capture") from exc
        try:
            for component in parts[:-1]:
                try:
                    next_descriptor = os.open(
                        component,
                        directory_flags,
                        dir_fd=directory_descriptor,
                    )
                except FileNotFoundError:
                    return "missing", 0, b""
                except OSError as exc:
                    raise RepositoryAccessError("snapshot paths cannot traverse symlinks") from exc
                os.close(directory_descriptor)
                directory_descriptor = next_descriptor
            try:
                before = os.stat(
                    parts[-1],
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                return "missing", 0, b""
            except OSError as exc:
                raise RepositoryAccessError("snapshot path became unavailable") from exc
            mode = stat.S_IMODE(before.st_mode) & 0o777
            if before.st_nlink != 1:
                raise RepositoryAccessError("snapshot files and symlinks cannot be hard-linked")
            if stat.S_ISLNK(before.st_mode):
                try:
                    target = os.readlink(parts[-1], dir_fd=directory_descriptor)
                    after = os.stat(
                        parts[-1],
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                except OSError as exc:
                    raise RepositoryAccessError(
                        "snapshot symlink changed during inspection"
                    ) from exc
                if not self._same_snapshot_stat(before, after):
                    raise RepositoryAccessError("snapshot symlink changed during inspection")
                content = target.encode("utf-8", errors="surrogateescape")
                if len(content) > maximum_bytes:
                    raise RepositoryAccessError("recovery snapshot exceeded the byte limit")
                return "symlink", mode, content
            if stat.S_ISDIR(before.st_mode):
                return "directory", mode, b""
            if not stat.S_ISREG(before.st_mode):
                raise RepositoryAccessError("snapshot contains an unsupported file type")
            if before.st_size > maximum_bytes:
                raise RepositoryAccessError("recovery snapshot exceeded the byte limit")
            file_flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                file_flags |= os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                file_flags |= os.O_CLOEXEC
            try:
                descriptor = os.open(
                    parts[-1],
                    file_flags,
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                raise RepositoryAccessError("snapshot file changed before inspection") from exc
            try:
                observed = os.fstat(descriptor)
                if not self._same_snapshot_stat(before, observed):
                    raise RepositoryAccessError("snapshot file changed before inspection")
                chunks: list[bytes] = []
                remaining = observed.st_size
                while remaining:
                    chunk = os.read(descriptor, min(65_536, remaining))
                    if not chunk:
                        raise RepositoryAccessError("snapshot file was truncated during inspection")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if os.read(descriptor, 1):
                    raise RepositoryAccessError("snapshot file grew during inspection")
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            if not self._same_snapshot_stat(observed, after):
                raise RepositoryAccessError("snapshot file changed during inspection")
            return "regular", mode, b"".join(chunks)
        finally:
            os.close(directory_descriptor)

    @staticmethod
    def _same_snapshot_stat(left: os.stat_result, right: os.stat_result) -> bool:
        return (
            left.st_dev == right.st_dev
            and left.st_ino == right.st_ino
            and left.st_mode == right.st_mode
            and left.st_nlink == right.st_nlink
            and left.st_size == right.st_size
            and left.st_mtime_ns == right.st_mtime_ns
            and left.st_ctime_ns == right.st_ctime_ns
        )

    @overload
    def _run_git(
        self,
        repository: Path,
        arguments: list[str],
        warnings: list[str],
        *,
        decode: Literal[True] = True,
        output_limit: int | None = None,
        allowed_return_codes: set[int] | None = None,
    ) -> tuple[str, bool, bool]: ...

    @overload
    def _run_git(
        self,
        repository: Path,
        arguments: list[str],
        warnings: list[str],
        *,
        decode: Literal[False],
        output_limit: int | None = None,
        allowed_return_codes: set[int] | None = None,
    ) -> tuple[bytes, bool, bool]: ...

    def _run_git(
        self,
        repository: Path,
        arguments: list[str],
        warnings: list[str],
        *,
        decode: bool = True,
        output_limit: int | None = None,
        allowed_return_codes: set[int] | None = None,
    ) -> tuple[str | bytes, bool, bool]:
        max_output_bytes = output_limit or self.limits.max_git_output_bytes
        accepted_return_codes = allowed_return_codes or {0}
        command = [
            self.git_binary or "git",
            "-c",
            f"safe.directory={repository}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.excludesFile=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "--literal-pathspecs",
            "--no-optional-locks",
            "-C",
            str(repository),
            *arguments,
        ]
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": "/nonexistent-liltweak-home",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_ASKPASS": "/bin/false",
            "SSH_ASKPASS": "/bin/false",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_ATTR_NOSYSTEM": "1",
            "LC_ALL": "C",
            "LANG": "C",
        }
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                start_new_session=os.name == "posix",
            )
        except OSError:
            warnings.append("A bounded Git metadata command was unavailable.")
            return ("" if decode else b""), False, False
        if process.stdout is None or process.stderr is None:
            self._terminate_process(process)
            warnings.append("A bounded Git metadata command could not capture output.")
            return ("" if decode else b""), False, False

        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        output = bytearray()
        stderr_bytes = 0
        deadline = time.monotonic() + self.limits.git_timeout_seconds
        truncated = False
        timed_out = False
        try:
            while selector.get_map():
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    timed_out = True
                    break
                events = selector.select(timeout=remaining_time)
                if not events:
                    timed_out = True
                    break
                for key, _mask in events:
                    chunk = os.read(key.fd, 65_536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stdout":
                        available = max_output_bytes - len(output)
                        if available > 0:
                            output.extend(chunk[:available])
                        if len(chunk) > available:
                            truncated = True
                            break
                    else:
                        stderr_bytes += len(chunk)
                        if stderr_bytes > max_output_bytes:
                            truncated = True
                            break
                if truncated:
                    break
        finally:
            selector.close()

        if timed_out or truncated:
            self._terminate_process(process)
        try:
            return_code = process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self._terminate_process(process)
            return_code = process.wait(timeout=1)
        process.stdout.close()
        process.stderr.close()

        if timed_out:
            warnings.append("A bounded Git metadata command timed out.")
            return ("" if decode else b""), False, False
        if truncated:
            warnings.append("Git metadata output reached the inspection limit.")
            partial = bytes(output)
            if decode:
                return partial.decode("utf-8", errors="replace"), True, False
            return partial, True, False
        if return_code not in accepted_return_codes:
            warnings.append("A bounded Git metadata command did not complete successfully.")
            return ("" if decode else b""), False, False
        result = bytes(output)
        if decode:
            return result.decode("utf-8", errors="replace"), False, True
        return result, False, True

    @staticmethod
    def _terminate_process(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            return

    def _parse_status(self, raw: bytes | str, truncated: bool) -> dict[str, Any]:
        if isinstance(raw, str):
            raw = raw.encode()
        records = raw.decode("utf-8", errors="replace").split("\0")
        staged: list[str] = []
        modified: list[str] = []
        deleted: list[str] = []
        renamed: list[str] = []
        untracked: list[str] = []
        conflicted: list[str] = []
        branch: str | None = None
        upstream: str | None = None
        ahead = 0
        behind = 0
        index = 0
        while index < len(records):
            record = records[index]
            index += 1
            if not record:
                continue
            if record.startswith("# branch.head "):
                value = record.removeprefix("# branch.head ")
                branch = "(detached)" if value == "(detached)" else _clean_path(value, 256)
                continue
            if record.startswith("# branch.upstream "):
                upstream = _clean_path(record.removeprefix("# branch.upstream "), 256)
                continue
            if record.startswith("# branch.ab "):
                match = re.fullmatch(r"# branch\.ab \+(\d+) -(\d+)", record)
                if match:
                    ahead, behind = int(match.group(1)), int(match.group(2))
                continue
            if record.startswith("? "):
                _append_bounded(
                    untracked,
                    _clean_path(record[2:]),
                    self.limits.max_list_items,
                )
                continue
            if record.startswith("u "):
                parts = record.split(" ", 10)
                if len(parts) == 11:
                    _append_bounded(
                        conflicted,
                        _clean_path(parts[-1]),
                        self.limits.max_list_items,
                    )
                continue
            if record.startswith("1 "):
                parts = record.split(" ", 8)
                if len(parts) == 9:
                    self._categorize_status(
                        parts[1],
                        _clean_path(parts[-1]),
                        staged,
                        modified,
                        deleted,
                        renamed,
                    )
                continue
            if record.startswith("2 "):
                parts = record.split(" ", 9)
                if len(parts) == 10:
                    path = _clean_path(parts[-1])
                    self._categorize_status(
                        parts[1],
                        path,
                        staged,
                        modified,
                        deleted,
                        renamed,
                    )
                    if index < len(records):
                        index += 1
        return {
            "branch": branch,
            "upstream": upstream,
            "ahead": ahead,
            "behind": behind,
            "staged": sorted(set(staged)),
            "modified": sorted(set(modified)),
            "deleted": sorted(set(deleted)),
            "renamed": sorted(set(renamed)),
            "untracked": sorted(set(untracked)),
            "conflicted": sorted(set(conflicted)),
            "truncated": truncated,
        }

    def _categorize_status(
        self,
        xy: str,
        path: str,
        staged: list[str],
        modified: list[str],
        deleted: list[str],
        renamed: list[str],
    ) -> None:
        if len(xy) != 2:
            return
        index_state = xy[0]
        worktree_state = xy[1]
        if index_state not in {".", " "}:
            _append_bounded(staged, path, self.limits.max_list_items)
        if "D" in xy:
            _append_bounded(deleted, path, self.limits.max_list_items)
        elif "R" in xy or "C" in xy:
            _append_bounded(renamed, path, self.limits.max_list_items)
        elif worktree_state not in {".", " "}:
            _append_bounded(modified, path, self.limits.max_list_items)

    def _parse_remotes(self, output: str) -> list[GitRemote]:
        remotes: dict[str, GitRemote] = {}
        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 2:
                continue
            name, raw_url = fields[0], fields[1]
            host = self._remote_host(raw_url)
            provider = None
            if host:
                if host.endswith("github.com"):
                    provider = "github"
                elif host.endswith("gitlab.com"):
                    provider = "gitlab"
                elif host.endswith("bitbucket.org"):
                    provider = "bitbucket"
            remotes[_clean_path(name, 128)] = GitRemote(
                name=_clean_path(name, 128),
                host=_clean_path(host, 256) if host else None,
                provider=provider,
            )
        return list(remotes.values())[: self.limits.max_list_items]

    @staticmethod
    def _remote_host(raw_url: str) -> str | None:
        candidate = raw_url.strip()
        if "://" in candidate:
            parsed = urlsplit(candidate)
            return parsed.hostname
        scp_match = re.match(r"^(?:[^@/:]+@)?([^/:]+):", candidate)
        return scp_match.group(1).lower() if scp_match else None

    def _parse_gitmodules(self, repository: Path) -> list[str]:
        path = repository / ".gitmodules"
        try:
            metadata = path.lstat()
        except OSError:
            return []
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > self.limits.max_text_file_bytes
        ):
            return []
        try:
            raw = self._read_regular_file(path, metadata, metadata.st_size)
        except OSError:
            return []
        text = raw.decode("utf-8", errors="replace")
        modules = [
            _clean_path(match.group(1).strip())
            for match in re.finditer(r"(?m)^\s*path\s*=\s*(.+?)\s*$", text)
        ]
        return modules[: self.limits.max_list_items]
