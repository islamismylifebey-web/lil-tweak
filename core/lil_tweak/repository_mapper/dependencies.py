"""Import and dependency declaration extraction."""

from __future__ import annotations

import ast
import posixpath
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .languages import dependency_name, parse_json, parse_toml


@dataclass(frozen=True, slots=True)
class ImportReference:
    requested: str
    root_name: str
    location_line: int
    imported_names: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DependencyDeclaration:
    name: str
    source_path: str
    scope: str
    requirement: str


def discover_python_imports(
    tree: ast.AST, module_name: str, *, is_package: bool = False
) -> tuple[ImportReference, ...]:
    imports: list[ImportReference] = []
    current_parts = module_name.split(".") if module_name else []
    package_parts = current_parts if is_package else current_parts[:-1]
    if isinstance(tree, ast.Module):
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(
                        ImportReference(alias.name, alias.name.split(".", 1)[0], node.lineno)
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    trim = max(0, node.level - 1)
                    base = package_parts[: len(package_parts) - trim] if trim else list(package_parts)
                    if node.module:
                        base.extend(node.module.split("."))
                    requested = ".".join(base)
                else:
                    requested = node.module or ""
                names = tuple(alias.name for alias in node.names if alias.name != "*")
                root = requested.split(".", 1)[0] if requested else (names[0].split(".", 1)[0] if names else "")
                imports.append(ImportReference(requested, root, node.lineno, names))
    return tuple(imports)


_JS_IMPORT_FROM = re.compile(
    r"(?m)(?:^|\n)\s*(?:import|export)\s+(?:type\s+)?(?:[^;\n]*?\s+from\s+)?[\"']([^\"']+)[\"']"
)
_JS_REQUIRE = re.compile(r"\brequire\s*\(\s*[\"']([^\"']+)[\"']\s*\)")
_JS_DYNAMIC = re.compile(r"\bimport\s*\(\s*[\"']([^\"']+)[\"']\s*\)")


def discover_javascript_imports(content: str) -> tuple[ImportReference, ...]:
    values: dict[tuple[str, int], ImportReference] = {}
    for pattern in (_JS_IMPORT_FROM, _JS_REQUIRE, _JS_DYNAMIC):
        for match in pattern.finditer(content):
            requested = match.group(1)
            line = content.count("\n", 0, match.start()) + 1
            root = requested.split("/", 1)[0]
            if requested.startswith("@") and "/" in requested:
                root = "/".join(requested.split("/")[:2])
            values[(requested, line)] = ImportReference(requested, root, line)
    return tuple(values[key] for key in sorted(values))


def resolve_javascript_relative(source_path: str, requested: str, known_paths: set[str]) -> str | None:
    if not requested.startswith("."):
        return None
    parent = PurePosixPath(source_path).parent.as_posix()
    normalized = posixpath.normpath(posixpath.join(parent, requested))
    candidates = [
        normalized,
        *(normalized + suffix for suffix in (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")),
        *(f"{normalized}/index{suffix}" for suffix in (".ts", ".tsx", ".js", ".jsx")),
    ]
    return next((candidate for candidate in candidates if candidate in known_paths), None)


def declarations_from_config(path: str, content: str) -> tuple[DependencyDeclaration, ...]:
    declarations: list[DependencyDeclaration] = []
    name = PurePosixPath(path).name.lower()
    if name == "package.json":
        parsed = parse_json(content)
        for field, scope in (
            ("dependencies", "runtime"),
            ("devDependencies", "development"),
            ("peerDependencies", "peer"),
            ("optionalDependencies", "optional"),
        ):
            section = parsed.get(field, {})
            if not isinstance(section, dict):
                continue
            for dependency, requirement in sorted(section.items()):
                declarations.append(
                    DependencyDeclaration(str(dependency), path, scope, str(requirement))
                )
    elif name == "pyproject.toml":
        parsed = parse_toml(content)
        project = parsed.get("project", {})
        if isinstance(project, dict):
            dependencies = project.get("dependencies", [])
            if isinstance(dependencies, list):
                for requirement in dependencies:
                    if isinstance(requirement, str):
                        declarations.append(
                            DependencyDeclaration(
                                dependency_name(requirement), path, "runtime", requirement
                            )
                        )
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for group, requirements in sorted(optional.items()):
                    if isinstance(requirements, list):
                        for requirement in requirements:
                            if isinstance(requirement, str):
                                declarations.append(
                                    DependencyDeclaration(
                                        dependency_name(requirement),
                                        path,
                                        f"optional:{group}",
                                        requirement,
                                    )
                                )
    elif name == "requirements.txt":
        for line in content.splitlines():
            candidate = line.strip()
            if candidate and not candidate.startswith(("#", "-")):
                declarations.append(
                    DependencyDeclaration(dependency_name(candidate), path, "runtime", candidate)
                )
    return tuple(declarations)


def python_source_roots_from_pyproject(path: str, content: str) -> tuple[str, ...]:
    roots: set[str] = set()
    try:
        parsed = parse_toml(content)
    except (ValueError, TypeError):
        return ()
    parent = PurePosixPath(path).parent
    parent_prefix = "" if parent == PurePosixPath(".") else parent.as_posix()
    tool = parsed.get("tool", {})
    hatch = tool.get("hatch", {}) if isinstance(tool, dict) else {}
    build = hatch.get("build", {}) if isinstance(hatch, dict) else {}
    targets = build.get("targets", {}) if isinstance(build, dict) else {}
    wheel = targets.get("wheel", {}) if isinstance(targets, dict) else {}
    packages = wheel.get("packages", []) if isinstance(wheel, dict) else []
    if isinstance(packages, list):
        for package in packages:
            if not isinstance(package, str) or not package:
                continue
            full = PurePosixPath(parent_prefix, package).as_posix()
            package_parts = PurePosixPath(full).parts
            # Remove the package's import-name portion. For src/app this yields src;
            # for core/lil_tweak (pyproject in core, package lil_tweak) this yields core.
            if package_parts:
                roots.add(PurePosixPath(*package_parts[:-1]).as_posix() if len(package_parts) > 1 else "")
    return tuple(sorted(roots))
