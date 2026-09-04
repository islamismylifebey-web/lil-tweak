"""Deterministic repository mapper implementation."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

from ..archive import ArchiveLimits, validate_portable_path
from .contracts import (
    EdgeKind,
    MapEdge,
    MapFinding,
    MapNode,
    NodeKind,
    RepositoryMap,
    SourceBinding,
)
from .dependencies import (
    candidate_js_paths,
    candidate_python_modules,
    external_package_name,
    import_is_relative,
    js_imports,
    package_json_dependencies,
    pyproject_dependencies,
    python_imports,
)
from .languages import is_test_path, language_for_path, module_name_for_path, node_kind_for_path
from .routes import js_routes, python_routes
from .serialization import repository_map_digest
from .symbols import js_symbols, python_symbols
from .tests import imported_modules_in_test, production_candidates_for_test


TEXT_FILE_LIMIT = 1_000_000
SOURCE_DIGEST_VERSION = "source-tree-sha256-v1"
IGNORED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".next",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "dist",
    "node_modules",
}


def map_repository(
    root: str | os.PathLike[str],
    *,
    repository_identity: str,
    commit: str,
    source_digest: str | None = None,
) -> RepositoryMap:
    root_path = Path(root).resolve()
    files = _safe_file_inventory(root_path)
    source_digest = source_digest or source_tree_digest(root_path, files)
    builder = _MapBuilder(root_path, files, repository_identity, commit, source_digest)
    repository_map = builder.build()
    return repository_map.with_map_digest(repository_map_digest(repository_map))


def source_tree_digest(root: str | os.PathLike[str], files: tuple[str, ...] | None = None) -> str:
    root_path = Path(root).resolve()
    paths = files or _safe_file_inventory(root_path)
    digest = hashlib.sha256()
    digest.update(SOURCE_DIGEST_VERSION.encode("utf-8"))
    for path in paths:
        full = root_path / path
        digest.update(b"\0path\0")
        digest.update(path.encode("utf-8"))
        digest.update(b"\0size\0")
        digest.update(str(full.stat().st_size).encode("ascii"))
        digest.update(b"\0sha256\0")
        digest.update(hashlib.sha256(full.read_bytes()).hexdigest().encode("ascii"))
    return digest.hexdigest()


def _safe_file_inventory(root: Path) -> tuple[str, ...]:
    paths: list[str] = []
    limits = ArchiveLimits()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            continue
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if any(part in IGNORED_DIRECTORIES for part in PurePosixPath(relative).parts):
            continue
        paths.append(validate_portable_path(relative, limits=limits))
    return tuple(paths)


class _MapBuilder:
    def __init__(
        self,
        root: Path,
        files: tuple[str, ...],
        repository_identity: str,
        commit: str,
        source_digest: str,
    ) -> None:
        self.root = root
        self.files = files
        self.repository_identity = repository_identity
        self.commit = commit
        self.source_digest = source_digest
        self.nodes: dict[str, MapNode] = {}
        self.edges: dict[tuple[str, str, str, tuple[str, ...], str], MapEdge] = {}
        self.findings: list[MapFinding] = []
        self.file_node_by_path: dict[str, str] = {}
        self.module_node_by_name: dict[str, str] = {}
        self.module_name_by_path: dict[str, str] = {}
        self.imports_by_path: dict[str, list[str]] = {}

    def build(self) -> RepositoryMap:
        repository_id = "repository:root"
        self._node(repository_id, NodeKind.REPOSITORY, self.repository_identity, metadata={"commit": self.commit})
        self._discover_files(repository_id)
        self._discover_packages_and_applications(repository_id)
        self._discover_external_dependencies()
        self._analyze_source_files()
        self._connect_imports()
        self._connect_tests()
        self._detect_cycles()
        nodes = tuple(sorted(self.nodes.values(), key=lambda item: item.id))
        edges = tuple(sorted(self.edges.values(), key=lambda item: (item.source, item.kind, item.target, item.evidence)))
        findings = tuple(sorted(self.findings, key=lambda item: (item.path or "", item.code, item.message)))
        return RepositoryMap(
            SourceBinding(self.repository_identity, self.commit, self.source_digest),
            nodes,
            edges,
            findings,
        )

    def _discover_files(self, repository_id: str) -> None:
        for path in self.files:
            language = language_for_path(path)
            kind = node_kind_for_path(path)
            file_id = f"file:{path}"
            self.file_node_by_path[path] = file_id
            metadata: dict[str, Any] = {"size_bytes": (self.root / path).stat().st_size}
            if language is None:
                metadata["analysis"] = "unsupported"
            self._node(file_id, kind, PurePosixPath(path).name, path=path, language=language, metadata=metadata)
            self._edge(repository_id, file_id, EdgeKind.CONTAINS, path)
            module = module_name_for_path(path)
            if module and kind in {NodeKind.SOURCE_FILE, NodeKind.TEST_FILE}:
                module_id = f"module:{module}"
                self.module_node_by_name[module] = module_id
                self.module_name_by_path[path] = module
                self._node(module_id, NodeKind.MODULE, module, path=path, language=language)
                self._edge(file_id, module_id, EdgeKind.DEFINES, path)

    def _discover_packages_and_applications(self, repository_id: str) -> None:
        directories = {PurePosixPath(path).parent for path in self.files}
        for directory in sorted(directories, key=lambda item: item.as_posix()):
            if directory == PurePosixPath("."):
                continue
            dir_path = directory.as_posix()
            files_in_dir = {PurePosixPath(path).name for path in self.files if PurePosixPath(path).parent == directory}
            package_kind: NodeKind | None = None
            if "__init__.py" in files_in_dir or "package.json" in files_in_dir:
                package_kind = NodeKind.PACKAGE
            if directory.name in {"app", "apps", "core", "service", "services"} or "next.config.ts" in files_in_dir:
                package_kind = NodeKind.APPLICATION
            if package_kind is None:
                continue
            package_id = f"{package_kind.value}:{dir_path}"
            self._node(package_id, package_kind, directory.name, path=dir_path)
            self._edge(repository_id, package_id, EdgeKind.CONTAINS, dir_path)
            for path, file_id in sorted(self.file_node_by_path.items()):
                if path.startswith(dir_path.rstrip("/") + "/"):
                    self._edge(package_id, file_id, EdgeKind.CONTAINS, path)

    def _discover_external_dependencies(self) -> None:
        for path in self.files:
            source = self._read_text(path)
            declared: dict[str, str] = {}
            if PurePosixPath(path).name == "package.json" and source is not None:
                declared = package_json_dependencies(source)
            elif PurePosixPath(path).name == "pyproject.toml" and source is not None:
                declared = pyproject_dependencies(source)
            for name, specifier in declared.items():
                node_id = f"dependency:{name}"
                self._node(node_id, NodeKind.DEPENDENCY, name, metadata={"specifier": specifier, "declared_in": path})
                self._edge(self.file_node_by_path[path], node_id, EdgeKind.DEPENDS_ON, path)

    def _analyze_source_files(self) -> None:
        for path in self.files:
            language = language_for_path(path)
            source = self._read_text(path)
            if source is None:
                continue
            try:
                if language == "python":
                    self.imports_by_path[path] = python_imports(source)
                    self._add_symbols(path, python_symbols(source))
                    self._add_routes(path, python_routes(source))
                elif language in {"javascript", "typescript"}:
                    self.imports_by_path[path] = js_imports(source)
                    self._add_symbols(path, js_symbols(source))
                    self._add_routes(path, js_routes(source, path))
                    self._add_next_entrypoint(path, source)
                elif language in {"json", "toml", "yaml", "sql"}:
                    self._add_configuration_semantics(path, source)
            except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
                self.findings.append(
                    MapFinding(
                        "analysis_failed",
                        "warning",
                        "Static analysis could not parse this file.",
                        path,
                        {"error": type(exc).__name__},
                    )
                )

    def _add_symbols(self, path: str, symbols: list[Any]) -> None:
        file_id = self.file_node_by_path[path]
        for symbol in symbols:
            kind = NodeKind.SCHEMA_MODEL_CONTRACT if symbol.kind in {"class", "interface", "type"} else NodeKind.SYMBOL
            node_id = f"symbol:{path}:{symbol.name}"
            metadata = {"symbol_kind": symbol.kind, "line": symbol.line, "exported": symbol.exported}
            if symbol.bases:
                metadata["bases"] = list(symbol.bases)
            self._node(node_id, kind, symbol.name, path=path, language=language_for_path(path), metadata=metadata)
            self._edge(file_id, node_id, EdgeKind.DEFINES, f"{path}:{symbol.line}")
            if symbol.exported:
                self._edge(file_id, node_id, EdgeKind.EXPORTS, f"{path}:{symbol.line}")
            for base in symbol.bases:
                base_id = f"symbol-ref:{base}"
                self._node(base_id, NodeKind.SYMBOL, base, metadata={"analysis": "referenced"})
                self._edge(node_id, base_id, EdgeKind.EXTENDS, f"{path}:{symbol.line}")

    def _add_routes(self, path: str, routes: list[Any]) -> None:
        file_id = self.file_node_by_path[path]
        for route in routes:
            node_id = f"api_route:{route.method}:{route.path}"
            self._node(
                node_id,
                NodeKind.API_ROUTE,
                f"{route.method} {route.path}",
                path=path,
                metadata={"method": route.method, "route": route.path, "framework": route.framework, "line": route.line},
            )
            self._edge(file_id, node_id, EdgeKind.SERVES, f"{path}:{route.line}")

    def _add_next_entrypoint(self, path: str, source: str) -> None:
        pure = PurePosixPath(path)
        if pure.parts and pure.parts[0] == "app" and pure.name in {"page.tsx", "layout.tsx"}:
            node_id = f"entry_point:{path}"
            self._node(node_id, NodeKind.ENTRY_POINT, path, path=path, language=language_for_path(path), metadata={"framework": "next"})
            self._edge(self.file_node_by_path[path], node_id, EdgeKind.DEFINES, path)
        if pure.name == "main.py" or 'if __name__ == "__main__"' in source:
            node_id = f"entry_point:{path}"
            self._node(node_id, NodeKind.ENTRY_POINT, path, path=path, language=language_for_path(path))
            self._edge(self.file_node_by_path[path], node_id, EdgeKind.DEFINES, path)

    def _add_configuration_semantics(self, path: str, source: str) -> None:
        name = PurePosixPath(path).name
        file_id = self.file_node_by_path[path]
        if name == "package.json":
            try:
                payload = json.loads(source)
            except json.JSONDecodeError:
                return
            scripts = payload.get("scripts", {})
            if isinstance(scripts, dict):
                for script, command in sorted(scripts.items()):
                    target_id = f"build_target:npm:{script}"
                    self._node(target_id, NodeKind.BUILD_TARGET, f"npm {script}", metadata={"command": str(command)})
                    self._edge(file_id, target_id, EdgeKind.BUILDS, path)
        if path.startswith((".openai/", "deploy/")) or name in {"wrangler.json", "wrangler.jsonc"}:
            surface_id = f"deployment_surface:{path}"
            self._node(surface_id, NodeKind.DEPLOYMENT_SURFACE, path, path=path)
            self._edge(file_id, surface_id, EdgeKind.DEPLOYS, path)

    def _connect_imports(self) -> None:
        module_path_by_name = {module: path for path, module in self.module_name_by_path.items()}
        path_set = set(self.files)
        for path, imports in sorted(self.imports_by_path.items()):
            source_id = self.file_node_by_path[path]
            importer_module = self.module_name_by_path.get(path)
            for import_name in imports:
                targets = self._resolve_import(import_name, path, importer_module, module_path_by_name, path_set)
                if targets:
                    for target in targets:
                        self._edge(source_id, target, EdgeKind.IMPORTS, path, metadata={"import": import_name})
                    continue
                if import_is_relative(import_name):
                    self.findings.append(
                        MapFinding("unresolved_import", "info", "Relative import could not be resolved.", path, {"import": import_name})
                    )
                    continue
                package_name = external_package_name(import_name)
                dependency_id = f"dependency:{package_name}"
                self._node(dependency_id, NodeKind.DEPENDENCY, package_name, metadata={"declared": False})
                self._edge(source_id, dependency_id, EdgeKind.DEPENDS_ON, path, metadata={"import": import_name})

    def _resolve_import(
        self,
        import_name: str,
        path: str,
        importer_module: str | None,
        module_path_by_name: dict[str, str],
        path_set: set[str],
    ) -> list[str]:
        language = language_for_path(path)
        targets: list[str] = []
        if language == "python":
            for module in candidate_python_modules(import_name, importer_module):
                exact_path = module_path_by_name.get(module)
                if exact_path:
                    targets.append(self.file_node_by_path[exact_path])
                else:
                    prefix = module + "."
                    for candidate, candidate_path in sorted(module_path_by_name.items()):
                        if candidate.startswith(prefix):
                            targets.append(self.file_node_by_path[candidate_path])
        elif language in {"javascript", "typescript"}:
            for candidate in candidate_js_paths(import_name, path):
                if candidate in path_set:
                    targets.append(self.file_node_by_path[candidate])
        return sorted(set(targets))

    def _connect_tests(self) -> None:
        module_path_by_name = {module: path for path, module in self.module_name_by_path.items()}
        for path in self.files:
            if not is_test_path(path):
                continue
            test_id = self.file_node_by_path[path]
            candidates = set(production_candidates_for_test(path))
            for imported in imported_modules_in_test(self.imports_by_path.get(path, [])):
                source_path = module_path_by_name.get(imported)
                if source_path:
                    candidates.add(source_path)
            for candidate in sorted(candidates):
                target = self.file_node_by_path.get(candidate)
                if target and target != test_id:
                    self._edge(test_id, target, EdgeKind.TESTS, path)

    def _detect_cycles(self) -> None:
        graph: dict[str, set[str]] = defaultdict(set)
        for edge in self.edges.values():
            if edge.kind == EdgeKind.IMPORTS and edge.source.startswith("file:") and edge.target.startswith("file:"):
                graph[edge.source].add(edge.target)
        visiting: set[str] = set()
        visited: set[str] = set()
        stack: list[str] = []

        def visit(node: str) -> None:
            if node in visited:
                return
            if node in visiting:
                cycle = stack[stack.index(node) :] if node in stack else [node]
                self.findings.append(
                    MapFinding("module_cycle", "info", "A statically provable import cycle exists.", metadata={"nodes": cycle})
                )
                return
            visiting.add(node)
            stack.append(node)
            for target in sorted(graph.get(node, ())):
                visit(target)
            stack.pop()
            visiting.remove(node)
            visited.add(node)

        for node in sorted(graph):
            visit(node)

    def _read_text(self, path: str) -> str | None:
        full = self.root / path
        if full.stat().st_size > TEXT_FILE_LIMIT:
            self.findings.append(MapFinding("analysis_skipped", "info", "File exceeds mapper text-analysis limit.", path))
            return None
        try:
            return full.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            self.findings.append(MapFinding("analysis_skipped", "info", "File is not UTF-8 text.", path))
            return None

    def _node(
        self,
        node_id: str,
        kind: NodeKind,
        name: str,
        *,
        path: str | None = None,
        language: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if node_id in self.nodes:
            return
        self.nodes[node_id] = MapNode(node_id, kind.value, name, path, language, metadata or {})

    def _edge(
        self,
        source: str,
        target: str,
        kind: EdgeKind,
        evidence: str,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        edge = MapEdge(source, target, kind.value, (evidence,), metadata or {})
        metadata_key = json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"))
        self.edges[(source, target, kind.value, (evidence,), metadata_key)] = edge
