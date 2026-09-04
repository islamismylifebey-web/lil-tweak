"""Canonical serialization for repository maps."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from typing import Any

from .contracts import RepositoryMap


def _plain(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return _plain(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(key): _plain(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def to_canonical_dict(repository_map: RepositoryMap, *, include_map_digest: bool = True) -> dict[str, Any]:
    data = _plain(repository_map)
    if not include_map_digest:
        data["binding"]["map_digest"] = ""
    return data


def to_canonical_json(repository_map: RepositoryMap, *, include_map_digest: bool = True) -> str:
    return json.dumps(
        to_canonical_dict(repository_map, include_map_digest=include_map_digest),
        sort_keys=True,
        separators=(",", ":"),
    )


def repository_map_digest(repository_map: RepositoryMap) -> str:
    material = to_canonical_json(repository_map, include_map_digest=False).encode("utf-8")
    return hashlib.sha256(material).hexdigest()
