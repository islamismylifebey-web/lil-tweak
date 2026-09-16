"""Language and project-boundary helpers used by the mapper."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any


@dataclass(frozen=True, slots=True)
class LanguageInfo:
    name: str
    supported: bool


_SUFFIXES: dict[str, LanguageInfo] = {
    ".py": LanguageInfo("Python", True),
    ".pyi": LanguageInfo("Python", True),
    ".js": LanguageInfo("JavaScript", True),
    ".jsx": LanguageInfo("JavaScript", True),
    ".mjs": LanguageInfo("JavaScript", True),
    ".cjs": LanguageInfo("JavaScript", True),
    ".ts": LanguageInfo("TypeScript", True),
    ".tsx": LanguageInfo("TypeScript", True),
    ".mts": LanguageInfo("TypeScript", True),
    ".cts": LanguageInfo("TypeScript", True),
    ".rb": LanguageInfo("Ruby", False),
    ".go": LanguageInfo("Go", False),
    ".rs": LanguageInfo("Rust", False),
    ".java": LanguageInfo("Java", False),
    ".kt": LanguageInfo("Kotlin", False),
    ".swift": LanguageInfo("Swift", False),
    ".php": LanguageInfo("PHP", False),
    ".cs": LanguageInfo("C#", False),
    ".c": LanguageInfo("C", False),
    ".h": LanguageInfo("C/C++ Header", False),
    ".cc": LanguageInfo("C++", False),
    ".cpp": LanguageInfo("C++", False),
    ".sh": LanguageInfo("Shell", False),
    ".sql": LanguageInfo("SQL", False),
    ".vue": LanguageInfo("Vue", False),
    ".svelte": LanguageInfo("Svelte", False),
}

_CONFIGURATION_NAMES = frozenset(
    {
        "package.json",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "requirements.txt",
        "pipfile",
        "poetry.lock",
        "uv.lock",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "tsconfig.json",
        "jsconfig.json",
        "vite.config.ts",
        "vite.config.js",
        "next.config.ts",
        "next.config.js",
        "eslint.config.mjs",
        "wrangler.toml",
        "vercel.json",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
        "makefile",
        "justfile",
        "cargo.toml",
        "go.mod",
    }
)


def language_for_path(path: str) -> LanguageInfo:
    pure = PurePosixPath(path)
    return _SUFFIXES.get(pure.suffix.lower(), LanguageInfo("Unknown", False))


def is_configuration_path(path: str) -> bool:
    pure = PurePosixPath(path)
    name = pure.name.lower()
    if name in _CONFIGURATION_NAMES:
        return True
    if name.startswith(("tsconfig.", "vite.config.", "next.config.", "webpack.config.")):
        return True
    if ".github/workflows/" in f"/{path.lower()}" and pure.suffix.lower() in {".yml", ".yaml"}:
        return True
    if any(part.lower() in {"infra", "infrastructure", "terraform", "k8s", "kubernetes"} for part in pure.parts):
        return pure.suffix.lower() in {".yml", ".yaml", ".tf", ".json", ".toml"}
    return False


def is_test_path(path: str) -> bool:
    pure = PurePosixPath(path)
    lowered = [part.lower() for part in pure.parts]
    name = pure.name.lower()
    return (
        any(part in {"test", "tests", "__tests__", "spec", "specs"} for part in lowered[:-1])
        or name.startswith("test_")
        or name.endswith(("_test.py", ".test.ts", ".test.tsx", ".test.js", ".spec.ts", ".spec.js"))
    )


def is_deployment_path(path: str) -> bool:
    pure = PurePosixPath(path)
    name = pure.name.lower()
    if name in {"dockerfile", "containerfile", "wrangler.toml", "vercel.json", "fly.toml", "render.yaml"}:
        return True
    if name.startswith(("dockerfile.", "containerfile.")):
        return True
    if name in {"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"}:
        return True
    if any(
        part.lower() in {"deploy", "deployment", "k8s", "kubernetes", "terraform"}
        for part in pure.parts[:-1]
    ):
        return (
            pure.suffix.lower()
            in {
                ".yml",
                ".yaml",
                ".toml",
                ".json",
                ".tf",
                ".container",
                ".service",
                ".socket",
                ".network",
                ".volume",
                ".kube",
            }
            or name.startswith(("dockerfile", "containerfile"))
        )
    return False


def is_entry_point_path(path: str) -> bool:
    pure = PurePosixPath(path)
    name = pure.name.lower()
    if name in {"main.py", "__main__.py", "manage.py", "server.py", "worker.py", "index.ts", "index.js"}:
        return True
    return name.startswith("route.") and "app" in {part.lower() for part in pure.parts}


def parse_json(content: str) -> dict[str, Any]:
    parsed = json.loads(content)
    return parsed if isinstance(parsed, dict) else {}


def parse_toml(content: str) -> dict[str, Any]:
    parsed = tomllib.loads(content)
    return parsed if isinstance(parsed, dict) else {}


def dependency_name(requirement: str) -> str:
    candidate = re.split(r"[<>=!~;\[\s]", requirement.strip(), maxsplit=1)[0]
    return candidate.strip().lower().replace("_", "-")


def python_module_name(path: str, source_roots: tuple[str, ...]) -> str:
    pure = PurePosixPath(path)
    parts = list(pure.with_suffix("").parts)
    for root in sorted(source_roots, key=lambda item: len(PurePosixPath(item).parts), reverse=True):
        root_parts = list(PurePosixPath(root).parts) if root else []
        if parts[: len(root_parts)] == root_parts:
            parts = parts[len(root_parts) :]
            break
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def javascript_module_name(path: str) -> str:
    pure = PurePosixPath(path).with_suffix("")
    parts = list(pure.parts)
    if parts and parts[-1] == "index":
        parts.pop()
    return ".".join(parts)
