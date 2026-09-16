"""Bounded deterministic reverse-dependency impact analysis."""

from __future__ import annotations

from collections import defaultdict, deque

from .contracts import (
    EdgeKind,
    EvidenceClass,
    GraphEdge,
    GraphNode,
    ImpactReference,
    ImpactReport,
    MapperLimits,
    NodeKind,
    RepositoryMap,
    UnknownNodeError,
)


_REVERSE_KINDS = frozenset(
    {
        EdgeKind.IMPORTS,
        EdgeKind.DEPENDS_ON,
        EdgeKind.CALLS,
        EdgeKind.REFERENCES,
        EdgeKind.IMPLEMENTS,
        EdgeKind.EXTENDS,
    }
)


def _reference(node: GraphNode, evidence: EvidenceClass = EvidenceClass.PROVEN) -> ImpactReference:
    return ImpactReference.from_node(node, evidence=evidence)


def analyze_impact(
    repository_map: RepositoryMap,
    target_ids: list[str] | tuple[str, ...],
    *,
    limits: MapperLimits,
) -> ImpactReport:
    by_id = {node.id: node for node in repository_map.nodes}
    targets: list[GraphNode] = []
    for target_id in sorted(set(target_ids)):
        node = by_id.get(target_id)
        if node is None:
            raise UnknownNodeError("unknown_node")
        targets.append(node)

    reverse: dict[str, list[GraphEdge]] = defaultdict(list)
    for edge in repository_map.edges:
        if edge.kind in _REVERSE_KINDS:
            reverse[edge.target].append(edge)
    for edges in reverse.values():
        edges.sort(key=lambda edge: (edge.source, edge.kind.value, edge.id))

    target_set = {node.id for node in targets}
    direct_evidence: dict[str, EvidenceClass] = {}
    for target_id in target_set:
        for edge in reverse.get(target_id, []):
            direct_evidence[edge.source] = _stronger(direct_evidence.get(edge.source), edge.evidence)

    visited = set(target_set) | set(direct_evidence)
    queue = deque((node_id, 1) for node_id in sorted(direct_evidence))
    transitive_evidence: dict[str, EvidenceClass] = {}
    while queue:
        current, depth = queue.popleft()
        if depth >= limits.max_impact_depth:
            continue
        for edge in reverse.get(current, []):
            dependent = edge.source
            if dependent in target_set or dependent in direct_evidence:
                continue
            evidence = _stronger(transitive_evidence.get(dependent), edge.evidence)
            transitive_evidence[dependent] = evidence
            if dependent not in visited:
                if len(visited) >= limits.max_impact_nodes:
                    queue.clear()
                    break
                visited.add(dependent)
                queue.append((dependent, depth + 1))

    impacted_ids = target_set | set(direct_evidence) | set(transitive_evidence)
    impacted_paths = {by_id[node_id].path for node_id in impacted_ids if by_id[node_id].path}

    test_evidence: dict[str, EvidenceClass] = {}
    for edge in repository_map.edges:
        if edge.kind != EdgeKind.TESTS or edge.target not in impacted_ids:
            continue
        test_evidence[edge.source] = _stronger(test_evidence.get(edge.source), edge.evidence)
    # A test importing an impacted/transitively impacted module may point to its
    # test module node instead of the file node; include every test-path peer.
    test_paths = {by_id[node_id].path for node_id in test_evidence if by_id[node_id].path}
    for node in repository_map.nodes:
        if node.kind == NodeKind.TEST_FILE and node.path in test_paths:
            test_evidence[node.id] = _stronger(test_evidence.get(node.id), EvidenceClass.PROVEN)

    configs = tuple(
        _reference(node)
        for node in repository_map.nodes
        if node.kind == NodeKind.CONFIGURATION_FILE
        and (_config_relevant(node.path, impacted_paths) or not (node.path and "/" in node.path))
    )
    builds = tuple(_reference(node) for node in repository_map.nodes if node.kind == NodeKind.BUILD_TARGET)
    deployments = tuple(
        _reference(node) for node in repository_map.nodes if node.kind == NodeKind.DEPLOYMENT_SURFACE
    )
    routes = tuple(
        _reference(node)
        for node in repository_map.nodes
        if node.kind == NodeKind.API_ROUTE and node.path in impacted_paths
    )
    contracts = tuple(
        _reference(node)
        for node in repository_map.nodes
        if node.kind == NodeKind.CONTRACT and node.path in impacted_paths
    )

    cycles: list[tuple[str, ...]] = []
    for finding in repository_map.findings:
        if finding.code == "dependency_cycle" and impacted_ids.intersection(finding.node_ids):
            cycles.append(tuple(finding.node_ids))

    direct = tuple(
        _reference(by_id[node_id], evidence)
        for node_id, evidence in sorted(direct_evidence.items(), key=lambda item: _node_sort(by_id[item[0]]))
    )
    transitive = tuple(
        _reference(by_id[node_id], evidence)
        for node_id, evidence in sorted(transitive_evidence.items(), key=lambda item: _node_sort(by_id[item[0]]))
    )
    relevant_tests = tuple(
        _reference(by_id[node_id], evidence)
        for node_id, evidence in sorted(test_evidence.items(), key=lambda item: _node_sort(by_id[item[0]]))
        if by_id[node_id].kind == NodeKind.TEST_FILE
    )

    inspection_candidates: list[str] = []
    for group in (
        tuple(_reference(node) for node in sorted(targets, key=_node_sort)),
        direct,
        transitive,
        relevant_tests,
        configs,
        routes,
        contracts,
        builds,
        deployments,
    ):
        for item in group:
            if item.path and item.path not in inspection_candidates:
                inspection_candidates.append(item.path)
            if len(inspection_candidates) >= limits.max_impact_nodes:
                break
        if len(inspection_candidates) >= limits.max_impact_nodes:
            break

    return ImpactReport(
        target_nodes=tuple(_reference(node) for node in sorted(targets, key=_node_sort)),
        direct_dependents=direct,
        transitive_dependents=transitive,
        relevant_tests=relevant_tests,
        relevant_configs=tuple(sorted(configs, key=_impact_sort)),
        build_targets=tuple(sorted(builds, key=_impact_sort)),
        deployment_surfaces=tuple(sorted(deployments, key=_impact_sort)),
        affected_routes=tuple(sorted(routes, key=_impact_sort)),
        affected_contracts=tuple(sorted(contracts, key=_impact_sort)),
        cycles=tuple(sorted(set(cycles))),
        recommended_inspection=tuple(inspection_candidates),
    )


def _stronger(current: EvidenceClass | None, candidate: EvidenceClass) -> EvidenceClass:
    if current == EvidenceClass.PROVEN or candidate == EvidenceClass.PROVEN:
        return EvidenceClass.PROVEN
    return EvidenceClass.INFERRED


def _node_sort(node: GraphNode) -> tuple[str, str, str]:
    return (node.path or "", node.qualified_name or "", node.id)


def _impact_sort(item: ImpactReference) -> tuple[str, str, str]:
    return (item.path or "", item.qualified_name or "", item.node_id)


def _config_relevant(path: str | None, impacted_paths: set[str | None]) -> bool:
    if not path:
        return False
    parent = path.rsplit("/", 1)[0] if "/" in path else ""
    return any(
        candidate is not None and (not parent or candidate == parent or candidate.startswith(parent + "/"))
        for candidate in impacted_paths
    )
