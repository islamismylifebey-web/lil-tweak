"""Impact-query helpers for repository maps."""

from __future__ import annotations

from collections import defaultdict, deque

from .contracts import EdgeKind, RepositoryMap


DEPENDENCY_EDGES = {
    EdgeKind.IMPORTS,
    EdgeKind.DEPENDS_ON,
    EdgeKind.CONFIGURES,
    EdgeKind.BUILDS,
    EdgeKind.DEPLOYS,
    EdgeKind.SERVES,
    EdgeKind.TESTS,
    EdgeKind.REFERENCES,
}


def reverse_dependencies(repository_map: RepositoryMap, node_id: str) -> tuple[str, ...]:
    dependents = sorted(
        edge.source
        for edge in repository_map.edges
        if edge.target == node_id and edge.kind in DEPENDENCY_EDGES
    )
    return tuple(dependents)


def transitive_reverse_dependencies(repository_map: RepositoryMap, node_id: str) -> tuple[str, ...]:
    reverse: dict[str, list[str]] = defaultdict(list)
    for edge in repository_map.edges:
        if edge.kind in DEPENDENCY_EDGES:
            reverse[edge.target].append(edge.source)
    seen: set[str] = set()
    queue: deque[str] = deque(sorted(reverse.get(node_id, [])))
    while queue:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        queue.extend(sorted(reverse.get(current, [])))
    return tuple(sorted(seen))


def inspection_set(repository_map: RepositoryMap, node_id: str) -> tuple[str, ...]:
    by_id = {node.id: node for node in repository_map.nodes}
    paths: set[str] = set()
    for dependent in transitive_reverse_dependencies(repository_map, node_id):
        path = by_id.get(dependent).path
        if path:
            paths.add(path)
    target = by_id.get(node_id)
    if target and target.path:
        paths.add(target.path)
    return tuple(sorted(paths))
