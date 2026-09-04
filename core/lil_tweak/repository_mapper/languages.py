"""Language and role detection for repository mapper inputs."""

from __future__ import annotations

from pathlib import PurePosixPath

from .contracts import NodeKind


LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".json": "json",
    ".toml": "toml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".sql": "sql",
    ".md": "markdown",
    ".css": "css",
    ".html": "html",
    ".sh": "shell",
}

CONFIG_FILENAMES = {
    ".dockerignore",
    ".editorconfig",
    ".env.example",
    ".gitignore",
    "Containerfile",
    "Dockerfile",
    "docker-compose.yml",
    "drizzle.config.ts",
    "eslint.config.mjs",
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "postcss.config.mjs",
    "pyproject.toml",
    "requirements.txt",
    "tsconfig.json",
    "vite.config.ts",
    "wrangler.json",
    "wrangler.jsonc",
}

CONFIG_DIRS = {
    ".github",
    ".openai",
    "deploy",
    "drizzle",
    "migrations",
}


def language_for_path(path: str) -> str | None:
    return LANGUAGE_BY_SUFFIX.get(PurePosixPath(path).suffix)


def is_test_path(path: str) -> bool:
    pure = PurePosixPath(path)
    parts = set(pure.parts)
    name = pure.name
    return (
        "tests" in parts
        or name.startswith("test_")
        or name.endswith("_test.py")
        or ".test." in name
        or ".spec." in name
    )


def node_kind_for_path(path: str) -> NodeKind:
    pure = PurePosixPath(path)
    if is_test_path(path):
        return NodeKind.TEST_FILE
    if pure.name in CONFIG_FILENAMES or any(part in CONFIG_DIRS for part in pure.parts):
        return NodeKind.CONFIGURATION_FILE
    return NodeKind.SOURCE_FILE


def module_name_for_path(path: str) -> str | None:
    pure = PurePosixPath(path)
    suffix = pure.suffix
    if suffix == ".py":
        without_suffix = pure.with_suffix("")
        parts = list(without_suffix.parts)
        if parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts) if parts else pure.parent.as_posix().replace("/", ".")
    if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}:
        return pure.with_suffix("").as_posix()
    return None
