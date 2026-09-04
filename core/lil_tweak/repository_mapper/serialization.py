"""Canonical JSON serialization and identity for repository maps."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import fields, is_dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from .contracts import RepositoryMap


def _primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (dict, MappingProxyType)) or isinstance(value, Mapping):
        return {str(key): _primitive(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (tuple, list)):
        return [_primitive(item) for item in value]
    if is_dataclass(value):
        return {field.name: _primitive(getattr(value, field.name)) for field in fields(value)}
    return value


def repository_map_payload(repository_map: RepositoryMap, *, include_digest: bool = True) -> dict[str, Any]:
    payload = {
        "binding": {
            "mapperVersion": repository_map.binding.mapper_version,
            "repositoryId": repository_map.binding.repository_id,
            "schemaVersion": repository_map.binding.schema_version,
            "sourceCommit": repository_map.binding.source_commit,
            "sourceTreeDigest": repository_map.binding.source_tree_digest,
        },
        "edges": [
            {
                "attributes": _primitive(edge.attributes),
                "evidence": edge.evidence.value,
                "id": edge.id,
                "kind": edge.kind.value,
                "source": edge.source,
                "target": edge.target,
            }
            for edge in repository_map.edges
        ],
        "findings": [
            {
                "code": finding.code,
                "details": _primitive(finding.details),
                "nodeIds": list(finding.node_ids),
                "path": finding.path,
                "severity": finding.severity,
            }
            for finding in repository_map.findings
        ],
        "nodes": [
            {
                "analysisStatus": node.analysis_status.value,
                "attributes": _primitive(node.attributes),
                "id": node.id,
                "kind": node.kind.value,
                "location": (
                    {
                        "endColumn": node.location.end_column,
                        "endLine": node.location.end_line,
                        "startColumn": node.location.start_column,
                        "startLine": node.location.start_line,
                    }
                    if node.location
                    else None
                ),
                "name": node.name,
                "path": node.path,
                "qualifiedName": node.qualified_name,
            }
            for node in repository_map.nodes
        ],
    }
    if include_digest:
        payload["mapDigest"] = repository_map.map_digest
    return payload


def _dump(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_json(repository_map: RepositoryMap) -> str:
    return _dump(repository_map_payload(repository_map, include_digest=True))


def compute_map_digest(repository_map: RepositoryMap) -> str:
    material = _dump(repository_map_payload(repository_map, include_digest=False)).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def verify_map_digest(repository_map: RepositoryMap) -> bool:
    return hmac.compare_digest(repository_map.map_digest, compute_map_digest(repository_map))
