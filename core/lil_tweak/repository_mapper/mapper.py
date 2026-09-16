"""Deterministic, bounded, read-only repository mapper and query service."""

from __future__ import annotations

import ast
import hashlib
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping

from ..archive import ArchiveError, ArchiveLimits, validate_portable_path
from .contracts import (
    AnalysisStatus,
    ComponentNeighborhood,
    EdgeKind,
    EvidenceClass,
    Finding,
    GraphEdge,
    GraphNode,
    MapBinding,
    MapperLimits,
    MappingLimitError,
    NodeKind,
    RepositoryMap,
    RepositoryMutationError,
    RepositorySafetyError,
    SourceBindingError,
    SourceLocation,
    UnknownMapError,
    UnknownNodeError,
)
from .dependencies import (
    DependencyDeclaration,
    ImportReference,
    declarations_from_config,
    discover_javascript_imports,
    discover_python_imports,
    python_source_roots_from_pyproject,
    resolve_javascript_relative,
)
from .impact import analyze_impact
from .languages import (
    is_configuration_path,
    is_deployment_path,
    is_entry_point_path,
    is_test_path,
    javascript_module_name,
    language_for_path,
    parse_json,
    parse_toml,
    python_module_name,
)
from .routes import discover_javascript_routes, discover_python_routes
from .serialization import compute_map_digest
from .symbols import (
    DiscoveredCall,
    DiscoveredSymbol,
    discover_javascript_symbols,
    discover_python_symbols,
)
from .tests import predictable_test_targets


@dataclass(frozen=True, slots=True)
class _FileRecord:
    path: str
    absolute: Path
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class _ParsedModule:
    path: str
    module_node_id: str
    file_node_id: str
    qualified_name: str
    language: str
    imports: tuple[ImportReference, ...]
    symbols: tuple[DiscoveredSymbol, ...]
    calls: tuple[DiscoveredCall, ...]
    routes: tuple[Any, ...]
    is_test: bool


class _GraphBuilder:
    def __init__(self, binding: MapBinding, limits: MapperLimits) -> None:
        self.binding = binding
        self.limits = limits
        self.nodes: dict[str, GraphNode] = {}
        self.node_keys: dict[tuple[Any, ...], str] = {}
        self.edges: dict[tuple[EdgeKind, str, str], GraphEdge] = {}
        self.findings: list[Finding] = []
        self.symbol_count = 0

    def stable_node_id(
        self,
        kind: NodeKind,
        *,
        path: str | None,
        qualified_name: str | None,
        name: str,
    ) -> str:
        material = "\0".join(
            (
                self.binding.repository_id,
                self.binding.source_commit,
                self.binding.source_tree_digest,
                self.binding.schema_version,
                self.binding.mapper_version,
                kind.value,
                path or "",
                qualified_name or "",
                name,
            )
        )
        return "node:" + hashlib.sha256(material.encode("utf-8")).hexdigest()

    def add_node(
        self,
        kind: NodeKind,
        name: str,
        *,
        path: str | None = None,
        qualified_name: str | None = None,
        location: SourceLocation | None = None,
        attributes: Mapping[str, Any] | None = None,
        analysis_status: AnalysisStatus = AnalysisStatus.FULL,
    ) -> GraphNode:
        key = (kind, path, qualified_name, name)
        existing_id = self.node_keys.get(key)
        if existing_id is not None:
            return self.nodes[existing_id]
        if len(self.nodes) >= self.limits.max_nodes:
            raise MappingLimitError("node_limit")
        if kind in {NodeKind.SYMBOL, NodeKind.CONTRACT}:
            if self.symbol_count >= self.limits.max_symbols:
                raise MappingLimitError("symbol_limit")
            self.symbol_count += 1
        node = GraphNode(
            id=self.stable_node_id(
                kind, path=path, qualified_name=qualified_name, name=name
            ),
            kind=kind,
            name=name,
            path=path,
            qualified_name=qualified_name,
            location=location,
            attributes=attributes or {},
            analysis_status=analysis_status,
        )
        self.nodes[node.id] = node
        self.node_keys[key] = node.id
        return node

    def update_node(
        self,
        node_id: str,
        *,
        attributes: Mapping[str, Any] | None = None,
        analysis_status: AnalysisStatus | None = None,
    ) -> GraphNode:
        current = self.nodes[node_id]
        updated_attributes = dict(current.attributes)
        if attributes:
            updated_attributes.update(attributes)
        updated = replace(
            current,
            attributes=updated_attributes,
            analysis_status=analysis_status or current.analysis_status,
        )
        self.nodes[node_id] = updated
        return updated

    def add_edge(
        self,
        kind: EdgeKind,
        source: str,
        target: str,
        *,
        evidence: EvidenceClass = EvidenceClass.PROVEN,
        attributes: Mapping[str, Any] | None = None,
    ) -> GraphEdge:
        if source == target and kind in {EdgeKind.IMPORTS, EdgeKind.DEPENDS_ON}:
            # A self-import has no useful impact signal and can poison cycle output.
            return GraphEdge(
                id=self._edge_id(kind, source, target),
                kind=kind,
                source=source,
                target=target,
                evidence=evidence,
                attributes=attributes or {},
            )
        key = (kind, source, target)
        existing = self.edges.get(key)
        if existing is not None:
            if existing.evidence == EvidenceClass.INFERRED and evidence == EvidenceClass.PROVEN:
                existing = replace(existing, evidence=evidence, attributes=attributes or existing.attributes)
                self.edges[key] = existing
            return existing
        if len(self.edges) >= self.limits.max_edges:
            raise MappingLimitError("edge_limit")
        edge = GraphEdge(
            id=self._edge_id(kind, source, target),
            kind=kind,
            source=source,
            target=target,
            evidence=evidence,
            attributes=attributes or {},
        )
        self.edges[key] = edge
        return edge

    def _edge_id(self, kind: EdgeKind, source: str, target: str) -> str:
        material = "\0".join(
            (
                self.binding.repository_id,
                self.binding.source_commit,
                self.binding.source_tree_digest,
                self.binding.mapper_version,
                kind.value,
                source,
                target,
            )
        )
        return "edge:" + hashlib.sha256(material.encode("utf-8")).hexdigest()

    def add_finding(
        self,
        code: str,
        *,
        severity: str = "finding",
        path: str | None = None,
        node_ids: Iterable[str] = (),
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self.findings.append(
            Finding(
                code=code,
                severity=severity,
                path=path,
                node_ids=tuple(node_ids),
                details=details or {},
            )
        )

    def build(self) -> RepositoryMap:
        provisional = RepositoryMap(
            binding=self.binding,
            nodes=tuple(self.nodes.values()),
            edges=tuple(self.edges.values()),
            findings=tuple(self.findings),
            map_digest="",
        )
        return replace(provisional, map_digest=compute_map_digest(provisional))


class RepositoryMapper:
    """Map one already-materialized exact revision without executing or modifying it."""

    def __init__(
        self,
        *,
        limits: MapperLimits | None = None,
        _integrity_hook: Callable[[], Any] | None = None,
    ) -> None:
        self.limits = limits or MapperLimits()
        self._integrity_hook = _integrity_hook

    def map(self, repository_root: str | os.PathLike[str], binding: MapBinding) -> RepositoryMap:
        started = time.monotonic()
        root = Path(repository_root)
        try:
            if root.is_symlink():
                raise RepositorySafetyError("symlink_rejected")
            resolved = root.resolve(strict=True)
        except RepositorySafetyError:
            raise
        except (OSError, RuntimeError):
            raise RepositorySafetyError("repository_path_invalid") from None
        if not resolved.is_dir():
            raise RepositorySafetyError("repository_path_invalid")

        inventory, observed_digest = self._inventory(resolved)
        if observed_digest != binding.source_tree_digest.lower():
            raise SourceBindingError("source_tree_digest_mismatch")

        builder = _GraphBuilder(binding, self.limits)
        repository_node = builder.add_node(
            NodeKind.REPOSITORY,
            binding.repository_id,
            attributes={
                "sourceCommit": binding.source_commit,
                "sourceTreeDigest": binding.source_tree_digest,
                "mapperSchemaVersion": binding.schema_version,
                "mapperImplementationVersion": binding.mapper_version,
                "readOnly": True,
                "executionAuthority": "none",
            },
        )

        contents: dict[str, str] = {}
        source_roots: set[str] = {"", "src", "core"}
        dependency_declarations: list[DependencyDeclaration] = []
        config_nodes: dict[str, GraphNode] = {}
        file_nodes: dict[str, GraphNode] = {}
        module_nodes: dict[str, GraphNode] = {}
        module_names: dict[str, str] = {}
        package_nodes: dict[tuple[str, str], GraphNode] = {}
        application_nodes: dict[str, GraphNode] = {}
        parsed_modules: list[_ParsedModule] = []

        # Configurations are read first because they establish package roots and
        # declared external dependency evidence for the later source pass.
        for record in inventory:
            self._check_parser_deadline(started)
            if not is_configuration_path(record.path):
                continue
            content = self._read_text(record)
            if content is not None:
                contents[record.path] = content
                if PurePosixPath(record.path).name.lower() == "pyproject.toml":
                    source_roots.update(python_source_roots_from_pyproject(record.path, content))
                try:
                    dependency_declarations.extend(declarations_from_config(record.path, content))
                except (ValueError, TypeError):
                    builder.add_finding("malformed_configuration", path=record.path)

        applications, packages = self._project_boundaries(inventory, contents, source_roots)
        for app_path, app_name, framework in applications:
            node = builder.add_node(
                NodeKind.APPLICATION,
                app_name,
                path=app_path,
                qualified_name=f"application:{app_path}",
                attributes={"framework": framework},
            )
            application_nodes[app_path] = node
            builder.add_edge(EdgeKind.CONTAINS, repository_node.id, node.id)
        for package_path, package_name, package_type in packages:
            node = builder.add_node(
                NodeKind.PACKAGE,
                package_name,
                path=package_path,
                qualified_name=f"{package_type}:{package_name}",
                attributes={"packageType": package_type},
            )
            package_nodes[(package_path, package_type)] = node
            owner = self._owning_application(package_path, application_nodes)
            builder.add_edge(
                EdgeKind.CONTAINS,
                owner.id if owner else repository_node.id,
                node.id,
            )

        # File and module skeletons are established before import resolution.
        for record in inventory:
            self._check_parser_deadline(started)
            language = language_for_path(record.path)
            file_kind = (
                NodeKind.CONFIGURATION_FILE
                if is_configuration_path(record.path)
                else NodeKind.TEST_FILE
                if is_test_path(record.path)
                else NodeKind.SOURCE_FILE
            )
            status = (
                AnalysisStatus.SKIPPED_LIMIT
                if record.size > self.limits.max_file_bytes
                else AnalysisStatus.FULL
                if language.supported or file_kind == NodeKind.CONFIGURATION_FILE
                else AnalysisStatus.LIMITED
            )
            file_node = builder.add_node(
                file_kind,
                PurePosixPath(record.path).name,
                path=record.path,
                attributes={
                    "language": language.name,
                    "sizeBytes": record.size,
                    "sha256": record.sha256,
                    "supportedAnalysis": language.supported,
                },
                analysis_status=status,
            )
            file_nodes[record.path] = file_node
            if file_kind == NodeKind.CONFIGURATION_FILE:
                config_nodes[record.path] = file_node
            owner = self._owning_application(record.path, application_nodes)
            builder.add_edge(
                EdgeKind.CONTAINS,
                owner.id if owner else repository_node.id,
                file_node.id,
            )
            if record.size > self.limits.max_file_bytes:
                builder.add_finding(
                    "file_too_large",
                    path=record.path,
                    node_ids=(file_node.id,),
                    details={"maxFileBytes": self.limits.max_file_bytes, "sizeBytes": record.size},
                )
            elif not language.supported and not is_configuration_path(record.path):
                builder.add_finding(
                    "unsupported_language",
                    path=record.path,
                    node_ids=(file_node.id,),
                    details={"language": language.name},
                )

            if language.supported:
                qualified = (
                    python_module_name(record.path, tuple(sorted(source_roots)))
                    if language.name == "Python"
                    else javascript_module_name(record.path)
                )
                module = builder.add_node(
                    NodeKind.MODULE,
                    qualified.rsplit(".", 1)[-1] if qualified else PurePosixPath(record.path).stem,
                    path=record.path,
                    qualified_name=qualified,
                    attributes={"language": language.name, "testModule": is_test_path(record.path)},
                    analysis_status=status,
                )
                module_nodes[record.path] = module
                module_names[qualified] = module.id
                builder.add_edge(EdgeKind.DEFINES, file_node.id, module.id)
                owner_package = self._owning_package(record.path, package_nodes)
                if owner_package:
                    builder.add_edge(EdgeKind.CONTAINS, owner_package.id, module.id)
                else:
                    builder.add_edge(EdgeKind.CONTAINS, repository_node.id, module.id)

            if is_entry_point_path(record.path):
                entry = builder.add_node(
                    NodeKind.ENTRY_POINT,
                    PurePosixPath(record.path).name,
                    path=record.path,
                    qualified_name=f"entry:{record.path}",
                    attributes={"runtimeReachability": "unknown"},
                    analysis_status=status,
                )
                builder.add_edge(EdgeKind.DEFINES, file_node.id, entry.id)

        dependency_nodes = self._dependency_nodes(
            builder, dependency_declarations, repository_node, config_nodes
        )

        for record in inventory:
            self._check_parser_deadline(started)
            module = module_nodes.get(record.path)
            if module is None or record.size > self.limits.max_file_bytes:
                continue
            content = contents.get(record.path)
            if content is None:
                content = self._read_text(record)
                if content is None:
                    builder.update_node(module.id, analysis_status=AnalysisStatus.LIMITED)
                    builder.update_node(file_nodes[record.path].id, analysis_status=AnalysisStatus.LIMITED)
                    builder.add_finding("non_utf8_source", path=record.path, node_ids=(module.id,))
                    continue
                contents[record.path] = content
            language = language_for_path(record.path).name
            try:
                if language == "Python":
                    tree = ast.parse(content, filename=record.path, type_comments=True)
                    symbols, calls = discover_python_symbols(tree, module.qualified_name or "")
                    imports = discover_python_imports(
                        tree,
                        module.qualified_name or "",
                        is_package=PurePosixPath(record.path).name == "__init__.py",
                    )
                    routes = discover_python_routes(tree, module.qualified_name or "")
                else:
                    symbols, calls = discover_javascript_symbols(content, module.qualified_name or "")
                    imports = discover_javascript_imports(content)
                    routes = discover_javascript_routes(content, record.path, module.qualified_name or "")
            except (SyntaxError, ValueError, RecursionError, MemoryError) as error:
                builder.update_node(module.id, analysis_status=AnalysisStatus.ERROR)
                builder.update_node(file_nodes[record.path].id, analysis_status=AnalysisStatus.ERROR)
                builder.add_finding(
                    "malformed_source",
                    path=record.path,
                    node_ids=(module.id,),
                    details={"parser": language, "errorType": type(error).__name__},
                )
                continue
            parsed_modules.append(
                _ParsedModule(
                    path=record.path,
                    module_node_id=module.id,
                    file_node_id=file_nodes[record.path].id,
                    qualified_name=module.qualified_name or "",
                    language=language,
                    imports=imports,
                    symbols=symbols,
                    calls=calls,
                    routes=routes,
                    is_test=is_test_path(record.path),
                )
            )

        symbol_nodes: dict[str, GraphNode] = {}
        symbols_by_short_name: dict[str, list[GraphNode]] = defaultdict(list)
        route_nodes: list[GraphNode] = []
        for parsed in parsed_modules:
            for symbol in parsed.symbols:
                node = builder.add_node(
                    symbol.kind,
                    symbol.name,
                    path=parsed.path,
                    qualified_name=symbol.qualified_name,
                    location=symbol.location,
                    attributes={
                        "symbolType": symbol.symbol_type,
                        "exported": symbol.exported,
                        "bases": symbol.bases,
                    },
                )
                symbol_nodes[symbol.qualified_name] = node
                symbols_by_short_name[symbol.name].append(node)
                builder.add_edge(EdgeKind.DEFINES, parsed.module_node_id, node.id)
                if symbol.exported:
                    builder.add_edge(EdgeKind.EXPORTS, parsed.module_node_id, node.id)
            for route in parsed.routes:
                route = route  # type: ignore[assignment]
                node = builder.add_node(
                    NodeKind.API_ROUTE,
                    f"{route.method} {route.route_path}",
                    path=parsed.path,
                    qualified_name=f"{parsed.qualified_name}:{route.method}:{route.route_path}",
                    location=route.location,
                    attributes={
                        "method": route.method,
                        "routePath": route.route_path,
                        "definingSymbol": route.defining_symbol,
                        "framework": route.framework,
                        "runtimeReachability": "unknown",
                    },
                )
                route_nodes.append(node)
                builder.add_edge(EdgeKind.DEFINES, parsed.module_node_id, node.id)
                owner = self._owning_application(parsed.path, application_nodes)
                if owner:
                    builder.add_edge(EdgeKind.SERVES, owner.id, node.id)

        self._connect_inheritance(builder, parsed_modules, symbol_nodes, symbols_by_short_name)
        import_edges = self._connect_imports(
            builder,
            parsed_modules,
            module_nodes,
            module_names,
            dependency_nodes,
            dependency_declarations,
        )
        self._connect_calls(builder, parsed_modules, symbol_nodes, symbols_by_short_name)
        self._connect_tests(builder, parsed_modules, module_nodes, file_nodes, import_edges)
        self._connect_configs_builds_deployments(
            builder,
            inventory,
            contents,
            repository_node,
            config_nodes,
            file_nodes,
            application_nodes,
            package_nodes,
        )
        self._record_cycles(builder, module_nodes)

        if self._integrity_hook is not None:
            self._integrity_hook()
        _final_inventory, final_digest = self._inventory(resolved)
        if final_digest != observed_digest:
            raise RepositoryMutationError("repository_mutated")
        return builder.build()

    def _inventory(self, root: Path) -> tuple[tuple[_FileRecord, ...], str]:
        records: list[_FileRecord] = []
        seen: set[str] = set()
        stack: list[tuple[Path, int]] = [(root, 0)]
        archive_limits = ArchiveLimits(max_entries=self.limits.max_files, max_depth=self.limits.max_depth)
        while stack:
            directory, depth = stack.pop()
            if depth > self.limits.max_depth:
                raise RepositorySafetyError("path_too_deep")
            try:
                entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
            except OSError:
                raise RepositorySafetyError("repository_unreadable") from None
            next_directories: list[tuple[Path, int]] = []
            for entry in entries:
                absolute = Path(entry.path)
                relative = absolute.relative_to(root).as_posix()
                if entry.is_symlink():
                    raise RepositorySafetyError("symlink_rejected")
                try:
                    portable = validate_portable_path(relative, limits=archive_limits)
                except ArchiveError as error:
                    raise RepositorySafetyError(error.code) from None
                folded = portable.casefold()
                if folded in seen:
                    raise RepositorySafetyError("duplicate_path")
                seen.add(folded)
                try:
                    if entry.is_dir(follow_symlinks=False):
                        next_directories.append((absolute, depth + 1))
                    elif entry.is_file(follow_symlinks=False):
                        if len(records) >= self.limits.max_files:
                            raise MappingLimitError("file_limit")
                        size = entry.stat(follow_symlinks=False).st_size
                        digest = self._hash_file(absolute)
                        records.append(_FileRecord(portable, absolute, size, digest))
                    else:
                        raise RepositorySafetyError("unsupported_file_type")
                except MappingLimitError:
                    raise
                except RepositorySafetyError:
                    raise
                except OSError:
                    raise RepositorySafetyError("repository_unreadable") from None
            stack.extend(reversed(next_directories))
        records.sort(key=lambda record: record.path)
        digest = hashlib.sha256()
        for record in records:
            digest.update(record.path.encode("utf-8"))
            digest.update(b"\0")
            digest.update(bytes.fromhex(record.sha256))
        return tuple(records), digest.hexdigest()

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
        except OSError:
            raise RepositorySafetyError("repository_unreadable") from None
        return digest.hexdigest()

    def _read_text(self, record: _FileRecord) -> str | None:
        if record.size > self.limits.max_file_bytes:
            return None
        try:
            descriptor = os.open(record.absolute, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                data = stream.read(self.limits.max_file_bytes + 1)
        except OSError:
            raise RepositorySafetyError("repository_unreadable") from None
        if len(data) > self.limits.max_file_bytes:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def _check_parser_deadline(self, started: float) -> None:
        if time.monotonic() - started > self.limits.max_parser_seconds:
            raise MappingLimitError("parser_time_limit")

    @staticmethod
    def _project_boundaries(
        inventory: tuple[_FileRecord, ...],
        contents: Mapping[str, str],
        source_roots: set[str],
    ) -> tuple[tuple[tuple[str, str, str], ...], tuple[tuple[str, str, str], ...]]:
        paths = {record.path for record in inventory}
        applications: dict[str, tuple[str, str]] = {}
        packages: dict[tuple[str, str], str] = {}
        for path, content in sorted(contents.items()):
            name = PurePosixPath(path).name.lower()
            parent = PurePosixPath(path).parent
            parent_path = "." if parent == PurePosixPath(".") else parent.as_posix()
            if name == "package.json":
                package_name = PurePosixPath(parent_path).name if parent_path != "." else "repository"
                try:
                    parsed = parse_json(content)
                    package_name = str(parsed.get("name") or package_name)
                except (ValueError, TypeError):
                    pass
                packages[(parent_path, "node")] = package_name
                applications[parent_path] = (package_name, "node")
            elif name == "pyproject.toml":
                try:
                    parsed = parse_toml(content)
                    project = parsed.get("project", {})
                    project_name = (
                        str(project.get("name"))
                        if isinstance(project, dict) and project.get("name")
                        else (PurePosixPath(parent_path).name if parent_path != "." else "python")
                    )
                except (ValueError, TypeError):
                    project_name = PurePosixPath(parent_path).name if parent_path != "." else "python"
                applications[parent_path] = (project_name, "python")
        for path in sorted(paths):
            if PurePosixPath(path).name == "__init__.py":
                package_path = PurePosixPath(path).parent.as_posix()
                package_name = python_module_name(path, tuple(sorted(source_roots))) or PurePosixPath(package_path).name
                packages[(package_path, "python")] = package_name
                if PurePosixPath(package_path).name.lower() in {"app", "api", "service", "server", "core"}:
                    applications.setdefault(package_path, (package_name, "python"))
            if PurePosixPath(path).name.lower() == "wrangler.toml":
                parent = PurePosixPath(path).parent
                app_path = "." if parent == PurePosixPath(".") else parent.as_posix()
                applications.setdefault(app_path, (PurePosixPath(app_path).name if app_path != "." else "worker", "cloudflare-worker"))
        application_rows = tuple(
            (path, name, framework) for path, (name, framework) in sorted(applications.items())
        )
        package_rows = tuple(
            (path, name, package_type)
            for (path, package_type), name in sorted(packages.items())
        )
        return application_rows, package_rows

    @staticmethod
    def _owning_application(path: str, applications: Mapping[str, GraphNode]) -> GraphNode | None:
        candidates = [
            (prefix, node)
            for prefix, node in applications.items()
            if prefix == "." or path == prefix or path.startswith(prefix.rstrip("/") + "/")
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda item: (0 if item[0] == "." else len(PurePosixPath(item[0]).parts)))[1]

    @staticmethod
    def _owning_package(
        path: str, packages: Mapping[tuple[str, str], GraphNode]
    ) -> GraphNode | None:
        candidates = [
            (prefix, node)
            for (prefix, _package_type), node in packages.items()
            if prefix == "." or path == prefix or path.startswith(prefix.rstrip("/") + "/")
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda item: (0 if item[0] == "." else len(PurePosixPath(item[0]).parts)))[1]

    @staticmethod
    def _dependency_nodes(
        builder: _GraphBuilder,
        declarations: list[DependencyDeclaration],
        repository_node: GraphNode,
        config_nodes: Mapping[str, GraphNode],
    ) -> dict[str, GraphNode]:
        grouped: dict[str, list[DependencyDeclaration]] = defaultdict(list)
        for declaration in declarations:
            grouped[declaration.name].append(declaration)
        nodes: dict[str, GraphNode] = {}
        for name, values in sorted(grouped.items()):
            ordered = sorted(values, key=lambda item: (item.source_path, item.scope, item.requirement))
            node = builder.add_node(
                NodeKind.DEPENDENCY,
                name,
                qualified_name=f"dependency:{name}",
                attributes={
                    "resolution": "declared",
                    "declarationSource": ordered[0].source_path,
                    "declarationSources": tuple(sorted({item.source_path for item in ordered})),
                    "scopes": tuple(sorted({item.scope for item in ordered})),
                },
            )
            nodes[name] = node
            builder.add_edge(EdgeKind.CONTAINS, repository_node.id, node.id)
            for source_path in sorted({item.source_path for item in ordered}):
                config = config_nodes.get(source_path)
                if config is not None:
                    builder.add_edge(
                        EdgeKind.DEPENDS_ON,
                        config.id,
                        node.id,
                        attributes={"declarationSource": source_path},
                    )
        return nodes

    @staticmethod
    def _connect_imports(
        builder: _GraphBuilder,
        parsed_modules: list[_ParsedModule],
        module_nodes: Mapping[str, GraphNode],
        module_names: Mapping[str, str],
        dependency_nodes: dict[str, GraphNode],
        declarations: list[DependencyDeclaration],
    ) -> tuple[GraphEdge, ...]:
        known_paths = set(module_nodes)
        declared_names = {declaration.name for declaration in declarations}
        created: list[GraphEdge] = []
        for parsed in sorted(parsed_modules, key=lambda item: item.path):
            for reference in parsed.imports:
                targets: list[str] = []
                if parsed.language == "Python":
                    candidates: list[str] = []
                    if reference.requested:
                        candidates.append(reference.requested)
                    if reference.imported_names and reference.requested:
                        candidates[:0] = [
                            f"{reference.requested}.{name}" for name in reference.imported_names
                        ]
                    elif reference.imported_names and not reference.requested:
                        candidates.extend(reference.imported_names)
                    for candidate in candidates:
                        target = module_names.get(candidate)
                        if target and target not in targets:
                            targets.append(target)
                else:
                    resolved = resolve_javascript_relative(parsed.path, reference.requested, known_paths)
                    if resolved is not None:
                        targets.append(module_nodes[resolved].id)
                if targets:
                    for target in targets:
                        created.append(
                            builder.add_edge(
                                EdgeKind.IMPORTS,
                                parsed.module_node_id,
                                target,
                                attributes={
                                    "requested": reference.requested,
                                    "sourceLine": reference.location_line,
                                },
                            )
                        )
                    continue
                if parsed.language != "Python" and reference.requested.startswith("."):
                    dependency_name = reference.requested
                    resolution = "unresolved"
                else:
                    dependency_name = reference.root_name or reference.requested
                    normalized = dependency_name.lower().replace("_", "-")
                    resolution = "declared" if normalized in declared_names else "unresolved"
                    if resolution == "declared":
                        dependency_name = normalized
                if not dependency_name:
                    continue
                node = dependency_nodes.get(dependency_name)
                if node is None:
                    node = builder.add_node(
                        NodeKind.DEPENDENCY,
                        dependency_name,
                        qualified_name=f"dependency:{dependency_name}",
                        attributes={"resolution": resolution},
                    )
                    dependency_nodes[dependency_name] = node
                created.append(
                    builder.add_edge(
                        EdgeKind.IMPORTS,
                        parsed.module_node_id,
                        node.id,
                        attributes={
                            "requested": reference.requested,
                            "sourceLine": reference.location_line,
                            "resolution": resolution,
                        },
                    )
                )
        return tuple(created)

    @staticmethod
    def _connect_inheritance(
        builder: _GraphBuilder,
        parsed_modules: list[_ParsedModule],
        symbol_nodes: Mapping[str, GraphNode],
        symbols_by_short_name: Mapping[str, list[GraphNode]],
    ) -> None:
        del parsed_modules, symbols_by_short_name
        for qualified, node in sorted(symbol_nodes.items()):
            bases = node.attributes.get("bases", ())
            if not isinstance(bases, (tuple, list)):
                continue
            module_name = qualified.rsplit(".", 1)[0]
            for base in bases:
                base_text = str(base)
                exact = symbol_nodes.get(base_text)
                same_module = symbol_nodes.get(f"{module_name}.{base_text.rsplit('.', 1)[-1]}")
                target = exact or same_module
                if target is not None:
                    builder.add_edge(EdgeKind.EXTENDS, node.id, target.id)

    @staticmethod
    def _connect_calls(
        builder: _GraphBuilder,
        parsed_modules: list[_ParsedModule],
        symbol_nodes: Mapping[str, GraphNode],
        symbols_by_short_name: Mapping[str, list[GraphNode]],
    ) -> None:
        del symbols_by_short_name
        modules = {item.qualified_name: item.module_node_id for item in parsed_modules}
        for parsed in sorted(parsed_modules, key=lambda item: item.path):
            for call in parsed.calls:
                caller = symbol_nodes.get(call.caller_qualified_name) or builder.nodes.get(modules.get(parsed.qualified_name, ""))
                if caller is None:
                    continue
                short_name = call.callee_name.rsplit(".", 1)[-1]
                exact = symbol_nodes.get(call.callee_name)
                same_module = symbol_nodes.get(f"{parsed.qualified_name}.{short_name}")
                target = exact or same_module
                if target is not None:
                    builder.add_edge(
                        EdgeKind.CALLS,
                        caller.id,
                        target.id,
                        attributes={"sourceLine": call.location.start_line},
                    )

    @staticmethod
    def _connect_tests(
        builder: _GraphBuilder,
        parsed_modules: list[_ParsedModule],
        module_nodes: Mapping[str, GraphNode],
        file_nodes: Mapping[str, GraphNode],
        import_edges: tuple[GraphEdge, ...],
    ) -> None:
        test_module_ids = {item.module_node_id: item for item in parsed_modules if item.is_test}
        for edge in import_edges:
            parsed = test_module_ids.get(edge.source)
            if parsed is not None and edge.target in builder.nodes and builder.nodes[edge.target].kind == NodeKind.MODULE:
                builder.add_edge(
                    EdgeKind.TESTS,
                    file_nodes[parsed.path].id,
                    edge.target,
                    evidence=EvidenceClass.PROVEN,
                    attributes={"basis": "import"},
                )
        module_paths = tuple(sorted(module_nodes))
        for parsed in sorted((item for item in parsed_modules if item.is_test), key=lambda item: item.path):
            for target_path in predictable_test_targets(parsed.path, module_paths):
                builder.add_edge(
                    EdgeKind.TESTS,
                    file_nodes[parsed.path].id,
                    module_nodes[target_path].id,
                    evidence=EvidenceClass.INFERRED,
                    attributes={"basis": "predictable_test_name"},
                )

    @staticmethod
    def _connect_configs_builds_deployments(
        builder: _GraphBuilder,
        inventory: tuple[_FileRecord, ...],
        contents: Mapping[str, str],
        repository_node: GraphNode,
        config_nodes: Mapping[str, GraphNode],
        file_nodes: Mapping[str, GraphNode],
        applications: Mapping[str, GraphNode],
        packages: Mapping[tuple[str, str], GraphNode],
    ) -> None:
        for path, config in sorted(config_nodes.items()):
            parent = PurePosixPath(path).parent
            parent_path = "." if parent == PurePosixPath(".") else parent.as_posix()
            targets = [
                node
                for app_path, node in applications.items()
                if parent_path == "." or app_path == parent_path or app_path.startswith(parent_path + "/")
            ]
            targets.extend(
                node
                for (package_path, _kind), node in packages.items()
                if parent_path == "." or package_path == parent_path or package_path.startswith(parent_path + "/")
            )
            if not targets:
                targets = [repository_node]
            for target in sorted({node.id: node for node in targets}.values(), key=lambda node: node.id):
                builder.add_edge(EdgeKind.CONFIGURES, config.id, target.id)

            name = PurePosixPath(path).name.lower()
            content = contents.get(path)
            if name == "package.json" and content:
                try:
                    parsed = parse_json(content)
                except (ValueError, TypeError):
                    parsed = {}
                scripts = parsed.get("scripts", {})
                if isinstance(scripts, dict):
                    for script_name, command in sorted(scripts.items()):
                        build = builder.add_node(
                            NodeKind.BUILD_TARGET,
                            str(script_name),
                            path=path,
                            qualified_name=f"build:{path}:{script_name}",
                            attributes={
                                "declaration": "package-script",
                                "commandDigest": hashlib.sha256(
                                    str(command).encode("utf-8")
                                ).hexdigest(),
                            },
                        )
                        builder.add_edge(EdgeKind.BUILDS, config.id, build.id)
            elif name == "pyproject.toml" and content:
                try:
                    parsed = parse_toml(content)
                except (ValueError, TypeError):
                    parsed = {}
                tool = parsed.get("tool", {}) if isinstance(parsed, dict) else {}
                hatch = tool.get("hatch", {}) if isinstance(tool, dict) else {}
                build_section = hatch.get("build", {}) if isinstance(hatch, dict) else {}
                targets_section = build_section.get("targets", {}) if isinstance(build_section, dict) else {}
                if isinstance(targets_section, dict):
                    for target_name in sorted(targets_section):
                        build = builder.add_node(
                            NodeKind.BUILD_TARGET,
                            str(target_name),
                            path=path,
                            qualified_name=f"build:{path}:{target_name}",
                            attributes={"declaration": "pyproject-build-target"},
                        )
                        builder.add_edge(EdgeKind.BUILDS, config.id, build.id)

        for record in inventory:
            if not is_deployment_path(record.path):
                continue
            surface = builder.add_node(
                NodeKind.DEPLOYMENT_SURFACE,
                PurePosixPath(record.path).name,
                path=record.path,
                qualified_name=f"deployment:{record.path}",
                attributes={"runtimeReachability": "unknown", "declarationOnly": True},
            )
            builder.add_edge(EdgeKind.DEPLOYS, repository_node.id, surface.id)
            config = config_nodes.get(record.path)
            if config:
                builder.add_edge(EdgeKind.CONFIGURES, config.id, surface.id)
            file_node = file_nodes.get(record.path)
            if file_node and file_node.id != surface.id:
                builder.add_edge(EdgeKind.DEFINES, file_node.id, surface.id)

    @staticmethod
    def _record_cycles(builder: _GraphBuilder, module_nodes: Mapping[str, GraphNode]) -> None:
        module_ids = {node.id for node in module_nodes.values()}
        graph: dict[str, list[str]] = defaultdict(list)
        for edge in builder.edges.values():
            if edge.kind == EdgeKind.IMPORTS and edge.source in module_ids and edge.target in module_ids:
                graph[edge.source].append(edge.target)
        for values in graph.values():
            values.sort()

        index = 0
        indices: dict[str, int] = {}
        lowlinks: dict[str, int] = {}
        stack: list[str] = []
        on_stack: set[str] = set()
        components: list[tuple[str, ...]] = []

        def visit(node: str) -> None:
            nonlocal index
            indices[node] = index
            lowlinks[node] = index
            index += 1
            stack.append(node)
            on_stack.add(node)
            for target in graph.get(node, []):
                if target not in indices:
                    visit(target)
                    lowlinks[node] = min(lowlinks[node], lowlinks[target])
                elif target in on_stack:
                    lowlinks[node] = min(lowlinks[node], indices[target])
            if lowlinks[node] == indices[node]:
                component: list[str] = []
                while True:
                    current = stack.pop()
                    on_stack.remove(current)
                    component.append(current)
                    if current == node:
                        break
                if len(component) > 1:
                    components.append(tuple(sorted(component)))

        for node_id in sorted(module_ids):
            if node_id not in indices:
                visit(node_id)
        for component in sorted(components):
            builder.add_finding(
                "dependency_cycle",
                severity="finding",
                node_ids=component,
                details={"size": len(component)},
            )


class RepositoryMapService:
    """Narrow in-process map/query surface; it exposes no filesystem authority."""

    def __init__(self, *, limits: MapperLimits | None = None) -> None:
        self.limits = limits or MapperLimits()
        self._mapper = RepositoryMapper(limits=self.limits)
        self._maps: dict[str, RepositoryMap] = {}

    def create_map(
        self, repository_root: str | os.PathLike[str], binding: MapBinding
    ) -> RepositoryMap:
        repository_map = self._mapper.map(repository_root, binding)
        self._maps[repository_map.map_digest] = repository_map
        return repository_map

    def get_map(self, map_digest: str) -> RepositoryMap:
        try:
            return self._maps[map_digest]
        except KeyError:
            raise UnknownMapError("unknown_map") from None

    def query_nodes(
        self,
        map_digest: str,
        *,
        kind: NodeKind | None = None,
        path: str | None = None,
        name: str | None = None,
    ) -> tuple[GraphNode, ...]:
        repository_map = self.get_map(map_digest)
        return tuple(
            node
            for node in repository_map.nodes
            if (kind is None or node.kind == kind)
            and (path is None or node.path == path)
            and (name is None or node.name == name)
        )

    def query_relationships(
        self,
        map_digest: str,
        *,
        node_id: str,
        kind: EdgeKind | None = None,
    ) -> tuple[GraphEdge, ...]:
        repository_map = self.get_map(map_digest)
        if node_id not in {node.id for node in repository_map.nodes}:
            raise UnknownNodeError("unknown_node")
        return tuple(
            edge
            for edge in repository_map.edges
            if (edge.source == node_id or edge.target == node_id)
            and (kind is None or edge.kind == kind)
        )

    def impact_analysis(
        self, map_digest: str, target_node_ids: list[str] | tuple[str, ...]
    ):
        return analyze_impact(
            self.get_map(map_digest), target_node_ids, limits=self.limits
        )

    def inspect_component_neighborhood(
        self, map_digest: str, node_id: str, *, depth: int = 1
    ) -> ComponentNeighborhood:
        if depth < 0 or depth > self.limits.max_impact_depth:
            raise MappingLimitError("neighborhood_depth_limit")
        repository_map = self.get_map(map_digest)
        by_id = {node.id: node for node in repository_map.nodes}
        if node_id not in by_id:
            raise UnknownNodeError("unknown_node")
        adjacency: dict[str, set[str]] = defaultdict(set)
        for edge in repository_map.edges:
            adjacency[edge.source].add(edge.target)
            adjacency[edge.target].add(edge.source)
        selected = {node_id}
        queue = deque([(node_id, 0)])
        while queue:
            current, current_depth = queue.popleft()
            if current_depth >= depth:
                continue
            for neighbor in sorted(adjacency.get(current, set())):
                if neighbor in selected:
                    continue
                if len(selected) >= self.limits.max_impact_nodes:
                    break
                selected.add(neighbor)
                queue.append((neighbor, current_depth + 1))
        edges = tuple(
            edge
            for edge in repository_map.edges
            if edge.source in selected and edge.target in selected
        )
        return ComponentNeighborhood(
            nodes=tuple(by_id[item] for item in sorted(selected)),
            edges=edges,
        )
