"""Dependency extraction helpers."""

from __future__ import annotations

import ast
import json
import posixpath
import re
from pathlib import PurePosixPath
from typing import Any


IMPORT_RE = re.compile(
    r"""(?mx)
    ^\s*import\s+(?:type\s+)?(?:[\w*{}\s,]+?\s+from\s+)?["'](?P<import>[^"']+)["']
    |^\s*export\s+[^;]*?\s+from\s+["'](?P<export>[^"']+)["']
    |\brequire\(\s*["'](?P<require>[^"']+)["']\s*\)
    |\bimport\(\s*["'](?P<dynamic>[^"']+)["']\s*\)
    """
)


def python_imports(source: str) -> list[str]:
    tree = ast.parse(source)
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append("." * node.level + node.module)
            elif node.level:
                imports.append("." * node.level)
    return sorted(set(imports))


def js_imports(source: str) -> list[str]:
    imports: set[str] = set()
    for match in IMPORT_RE.finditer(source):
        value = (
            match.group("import")
            or match.group("export")
            or match.group("require")
            or match.group("dynamic")
        )
        if value:
            imports.add(value)
    return sorted(imports)


def package_json_dependencies(source: str) -> dict[str, str]:
    try:
        payload = json.loads(source)
    except json.JSONDecodeError:
        return {}
    dependencies: dict[str, str] = {}
    for key in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        raw = payload.get(key, {})
        if isinstance(raw, dict):
            for name, version in raw.items():
                if isinstance(name, str):
                    dependencies[name] = str(version)
    return dict(sorted(dependencies.items()))


def pyproject_dependencies(source: str) -> dict[str, str]:
    try:
        import tomllib

        payload = tomllib.loads(source)
    except Exception:
        return {}
    project = payload.get("project", {})
    raw = project.get("dependencies", []) if isinstance(project, dict) else []
    dependencies: dict[str, str] = {}
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, str):
                continue
            name = re.split(r"[<>=!~;\[]", item, maxsplit=1)[0].strip()
            if name:
                dependencies[name] = item
    return dict(sorted(dependencies.items()))


def import_is_relative(name: str) -> bool:
    return name.startswith(".") or name.startswith("/")


def external_package_name(name: str) -> str:
    if name.startswith("@"):
        parts = name.split("/")
        return "/".join(parts[:2]) if len(parts) > 1 else name
    return name.split(".", 1)[0].split("/", 1)[0]


def candidate_js_paths(import_name: str, importer_path: str) -> list[str]:
    if not import_name.startswith("."):
        return []
    base = PurePosixPath(
        posixpath.normpath(PurePosixPath(importer_path).parent.joinpath(import_name).as_posix())
    )
    if base.as_posix().startswith("../"):
        return []
    candidates: list[str] = []
    for suffix in ("", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
        candidates.append(base.as_posix() + suffix)
    for suffix in ("ts", "tsx", "js", "jsx", "mjs", "cjs"):
        candidates.append(base.joinpath(f"index.{suffix}").as_posix())
    return candidates


def candidate_python_modules(import_name: str, importer_module: str | None) -> list[str]:
    if not import_name.startswith("."):
        return [import_name]
    if importer_module is None:
        return []
    level = len(import_name) - len(import_name.lstrip("."))
    rest = import_name[level:]
    parts = importer_module.split(".")[:-1]
    if level > 1:
        parts = parts[: -(level - 1)] if level - 1 <= len(parts) else []
    if rest:
        parts.extend(rest.split("."))
    return [".".join(part for part in parts if part)]


def safe_json_object(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): safe_json_object(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [safe_json_object(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
