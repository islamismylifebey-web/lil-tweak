"""Immutable contracts for deterministic, read-only repository maps."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping


SCHEMA_VERSION = "repository-map-v1"
MAPPER_VERSION = "1.0.0"
CONTEXT_SCHEMA_VERSION = "repository-context-v1"


class NodeKind(StrEnum):
    REPOSITORY = "repository"
    APPLICATION = "application"
    PACKAGE = "package"
    MODULE = "module"
    SOURCE_FILE = "source_file"
    CONFIGURATION_FILE = "configuration_file"
    TEST_FILE = "test_file"
    ENTRY_POINT = "entry_point"
    SYMBOL = "symbol"
    API_ROUTE = "api_route"
    CONTRACT = "contract"
    DEPENDENCY = "dependency"
    BUILD_TARGET = "build_target"
    DEPLOYMENT_SURFACE = "deployment_surface"


class EdgeKind(StrEnum):
    CONTAINS = "CONTAINS"
    IMPORTS = "IMPORTS"
    DEPENDS_ON = "DEPENDS_ON"
    EXPORTS = "EXPORTS"
    DEFINES = "DEFINES"
    CALLS = "CALLS"
    TESTS = "TESTS"
    CONFIGURES = "CONFIGURES"
    BUILDS = "BUILDS"
    DEPLOYS = "DEPLOYS"
    SERVES = "SERVES"
    IMPLEMENTS = "IMPLEMENTS"
    EXTENDS = "EXTENDS"
    REFERENCES = "REFERENCES"


class EvidenceClass(StrEnum):
    PROVEN = "PROVEN"
    INFERRED = "INFERRED"


class AnalysisStatus(StrEnum):
    FULL = "full"
    LIMITED = "limited"
    SKIPPED_LIMIT = "skipped_limit"
    ERROR = "error"


class RepositoryMapperError(RuntimeError):
    """Base mapper error with a stable content-free code."""

    code = "repository_mapper_error"

    def __init__(self, code: str | None = None) -> None:
        self.code = code or self.code
        super().__init__(self.code)


class RepositorySafetyError(RepositoryMapperError):
    code = "repository_safety_error"


class RepositoryMutationError(RepositoryMapperError):
    code = "repository_mutated"


class MappingLimitError(RepositoryMapperError):
    code = "mapping_limit"


class SourceBindingError(RepositoryMapperError):
    code = "source_binding_error"


class UnknownMapError(RepositoryMapperError):
    code = "unknown_map"


class UnknownNodeError(RepositoryMapperError):
    code = "unknown_node"


@dataclass(frozen=True, slots=True)
class MapperLimits:
    max_files: int = 20_000
    max_nodes: int = 100_000
    max_edges: int = 250_000
    max_symbols: int = 100_000
    max_file_bytes: int = 2 * 1024 * 1024
    max_depth: int = 32
    max_parser_seconds: float = 30.0
    max_impact_nodes: int = 5_000
    max_impact_depth: int = 32

    def __post_init__(self) -> None:
        numeric = (
            self.max_files,
            self.max_nodes,
            self.max_edges,
            self.max_symbols,
            self.max_file_bytes,
            self.max_depth,
            self.max_parser_seconds,
            self.max_impact_nodes,
            self.max_impact_depth,
        )
        if any(value <= 0 for value in numeric):
            raise ValueError("mapper_limits_must_be_positive")


@dataclass(frozen=True, slots=True)
class MapBinding:
    repository_id: str
    source_commit: str
    source_tree_digest: str
    schema_version: str = SCHEMA_VERSION
    mapper_version: str = MAPPER_VERSION

    def __post_init__(self) -> None:
        for value, code in (
            (self.repository_id, "repository_id_required"),
            (self.source_commit, "source_commit_required"),
            (self.source_tree_digest, "source_tree_digest_required"),
            (self.schema_version, "schema_version_required"),
            (self.mapper_version, "mapper_version_required"),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(code)
        commit = self.source_commit.lower()
        if len(commit) not in {40, 64} or any(
            character not in "0123456789abcdef" for character in commit
        ):
            raise ValueError("source_commit_invalid")
        digest = self.source_tree_digest.lower()
        if len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise ValueError("source_tree_digest_invalid")


@dataclass(frozen=True, slots=True)
class SourceLocation:
    start_line: int
    start_column: int = 0
    end_line: int | None = None
    end_column: int | None = None

    def __post_init__(self) -> None:
        if self.start_line < 1 or self.start_column < 0:
            raise ValueError("source_location_invalid")
        if self.end_line is not None and self.end_line < self.start_line:
            raise ValueError("source_location_invalid")


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {
                str(key): _freeze_value(item)
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            }
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return tuple(sorted((_freeze_value(item) for item in value), key=repr))
    return value


def _freeze_mapping(value: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if not value:
        return MappingProxyType({})
    frozen = _freeze_value(value)
    if not isinstance(frozen, Mapping):
        raise TypeError("attributes_must_be_mapping")
    return frozen


@dataclass(frozen=True, slots=True)
class GraphNode:
    id: str
    kind: NodeKind
    name: str
    path: str | None = None
    qualified_name: str | None = None
    location: SourceLocation | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)
    analysis_status: AnalysisStatus = AnalysisStatus.FULL

    def __post_init__(self) -> None:
        if not self.id.startswith("node:"):
            raise ValueError("node_id_invalid")
        if not self.name:
            raise ValueError("node_name_required")
        object.__setattr__(self, "attributes", _freeze_mapping(self.attributes))


@dataclass(frozen=True, slots=True)
class GraphEdge:
    id: str
    kind: EdgeKind
    source: str
    target: str
    evidence: EvidenceClass = EvidenceClass.PROVEN
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id.startswith("edge:"):
            raise ValueError("edge_id_invalid")
        if not self.source.startswith("node:") or not self.target.startswith("node:"):
            raise ValueError("edge_endpoint_invalid")
        object.__setattr__(self, "attributes", _freeze_mapping(self.attributes))


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    severity: str
    path: str | None = None
    node_ids: tuple[str, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_ids", tuple(sorted(set(self.node_ids))))
        object.__setattr__(self, "details", _freeze_mapping(self.details))


@dataclass(frozen=True, slots=True)
class RepositoryMap:
    binding: MapBinding
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    findings: tuple[Finding, ...]
    map_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "nodes", tuple(sorted(self.nodes, key=lambda node: node.id)))
        object.__setattr__(self, "edges", tuple(sorted(self.edges, key=lambda edge: edge.id)))
        object.__setattr__(
            self,
            "findings",
            tuple(
                sorted(
                    self.findings,
                    key=lambda item: (item.code, item.path or "", item.node_ids, item.severity),
                )
            ),
        )

    def context_manifest_fragment(self) -> dict[str, Any]:
        return {
            "schemaVersion": CONTEXT_SCHEMA_VERSION,
            "repositoryId": self.binding.repository_id,
            "sourceCommit": self.binding.source_commit,
            "sourceTreeDigest": self.binding.source_tree_digest,
            "mapDigest": self.map_digest,
            "authority": "none",
            "mayExecute": False,
            "mayAuthorizeChanges": False,
            "nodeCount": len(self.nodes),
            "edgeCount": len(self.edges),
        }


@dataclass(frozen=True, slots=True)
class ImpactReference:
    node_id: str
    name: str
    path: str | None = None
    qualified_name: str | None = None
    route_path: str | None = None
    evidence: EvidenceClass = EvidenceClass.PROVEN

    @classmethod
    def from_node(
        cls, node: GraphNode, *, evidence: EvidenceClass = EvidenceClass.PROVEN
    ) -> "ImpactReference":
        route_path = node.attributes.get("routePath")
        return cls(
            node_id=node.id,
            name=node.name,
            path=node.path,
            qualified_name=node.qualified_name,
            route_path=str(route_path) if route_path is not None else None,
            evidence=evidence,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodeId": self.node_id,
            "name": self.name,
            "path": self.path,
            "qualifiedName": self.qualified_name,
            "routePath": self.route_path,
            "evidence": self.evidence.value,
        }


@dataclass(frozen=True, slots=True)
class ImpactReport:
    target_nodes: tuple[ImpactReference, ...]
    direct_dependents: tuple[ImpactReference, ...]
    transitive_dependents: tuple[ImpactReference, ...]
    relevant_tests: tuple[ImpactReference, ...]
    relevant_configs: tuple[ImpactReference, ...]
    build_targets: tuple[ImpactReference, ...]
    deployment_surfaces: tuple[ImpactReference, ...]
    affected_routes: tuple[ImpactReference, ...]
    affected_contracts: tuple[ImpactReference, ...]
    cycles: tuple[tuple[str, ...], ...]
    recommended_inspection: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        def items(values: tuple[ImpactReference, ...]) -> list[dict[str, Any]]:
            return [value.to_dict() for value in values]

        return {
            "authority": "none",
            "mayExecute": False,
            "mayAuthorizeChanges": False,
            "targetNodes": items(self.target_nodes),
            "directDependents": items(self.direct_dependents),
            "transitiveDependents": items(self.transitive_dependents),
            "relevantTests": items(self.relevant_tests),
            "relevantConfigs": items(self.relevant_configs),
            "buildTargets": items(self.build_targets),
            "deploymentSurfaces": items(self.deployment_surfaces),
            "affectedRoutes": items(self.affected_routes),
            "affectedContracts": items(self.affected_contracts),
            "cycles": [list(cycle) for cycle in self.cycles],
            "recommendedInspection": list(self.recommended_inspection),
        }


@dataclass(frozen=True, slots=True)
class ComponentNeighborhood:
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
