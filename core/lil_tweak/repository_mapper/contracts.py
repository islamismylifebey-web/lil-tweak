"""Stable contracts for deterministic repository maps."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any


SCHEMA_VERSION = "repository-map-v1"
IMPLEMENTATION_VERSION = "1.0.0"


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
    SCHEMA_MODEL_CONTRACT = "schema_model_contract"
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


@dataclass(frozen=True, slots=True)
class SourceBinding:
    repository_identity: str
    commit: str
    source_digest: str
    mapper_schema_version: str = SCHEMA_VERSION
    mapper_implementation_version: str = IMPLEMENTATION_VERSION
    map_digest: str = ""

    def with_map_digest(self, digest: str) -> SourceBinding:
        return replace(self, map_digest=digest)


@dataclass(frozen=True, slots=True)
class MapNode:
    id: str
    kind: str
    name: str
    path: str | None = None
    language: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MapEdge:
    source: str
    target: str
    kind: str
    evidence: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MapFinding:
    code: str
    severity: str
    message: str
    path: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RepositoryMap:
    binding: SourceBinding
    nodes: tuple[MapNode, ...]
    edges: tuple[MapEdge, ...]
    findings: tuple[MapFinding, ...] = ()

    def with_map_digest(self, digest: str) -> RepositoryMap:
        return replace(self, binding=self.binding.with_map_digest(digest))
