from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.tests.repository_mapper_fixture import make_repository, source_digest


class RepositoryMapperImpactTests(unittest.TestCase):
    def _service(self, root: Path):
        from core.lil_tweak.repository_mapper import MapBinding, RepositoryMapService

        service = RepositoryMapService()
        repository_map = service.create_map(
            root,
            MapBinding(
                repository_id="fixture",
                source_commit="d" * 40,
                source_tree_digest=source_digest(root),
            ),
        )
        return service, repository_map

    def test_direct_and_transitive_impact_follow_reverse_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            service, repository_map = self._service(root)
            target = next(node for node in repository_map.nodes if node.path == "src/app/models.py" and node.kind.value == "module")
            report = service.impact_analysis(repository_map.map_digest, [target.id])
            direct_paths = {item.path for item in report.direct_dependents}
            transitive_paths = {item.path for item in report.transitive_dependents}
            self.assertIn("src/app/service.py", direct_paths)
            self.assertIn("src/app/main.py", transitive_paths)
            self.assertTrue(all(item.evidence.value in {"PROVEN", "INFERRED"} for item in report.direct_dependents))

    def test_impact_includes_relevant_tests_routes_contracts_configs_builds_and_deployments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            service, repository_map = self._service(root)
            target = next(node for node in repository_map.nodes if node.path == "src/app/models.py" and node.kind.value == "module")
            report = service.impact_analysis(repository_map.map_digest, [target.id])
            self.assertIn("tests/test_service.py", {item.path for item in report.relevant_tests})
            self.assertIn("pyproject.toml", {item.path for item in report.relevant_configs})
            self.assertIn("/users/{user_id}", {item.route_path for item in report.affected_routes})
            self.assertIn("app.models.UserModel", {item.qualified_name for item in report.affected_contracts})
            self.assertTrue(report.build_targets)
            self.assertTrue(report.deployment_surfaces)

    def test_impact_reports_cycles_encountered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            service, repository_map = self._service(root)
            target = next(node for node in repository_map.nodes if node.path == "src/app/cycle_a.py" and node.kind.value == "module")
            report = service.impact_analysis(repository_map.map_digest, [target.id])
            self.assertEqual(len(report.cycles), 1)
            self.assertIn(target.id, report.cycles[0])

    def test_recommended_inspection_set_is_deterministic_and_bounded(self):
        from core.lil_tweak.repository_mapper import MapperLimits, RepositoryMapService

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            service = RepositoryMapService(limits=MapperLimits(max_impact_nodes=5))
            from core.lil_tweak.repository_mapper import MapBinding
            repository_map = service.create_map(
                root,
                MapBinding("fixture", "e" * 40, source_digest(root)),
            )
            target = next(node for node in repository_map.nodes if node.path == "src/app/models.py" and node.kind.value == "module")
            first = service.impact_analysis(repository_map.map_digest, [target.id])
            second = service.impact_analysis(repository_map.map_digest, [target.id])
            self.assertEqual(first.recommended_inspection, second.recommended_inspection)
            self.assertLessEqual(len(first.recommended_inspection), 5)

    def test_unknown_target_fails_without_authorizing_any_action(self):
        from core.lil_tweak.repository_mapper import UnknownNodeError

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            service, repository_map = self._service(root)
            with self.assertRaises(UnknownNodeError):
                service.impact_analysis(repository_map.map_digest, ["node:missing"])

    def test_acceptance_projection_matches_controlled_fixture_exactly(self):
        from core.lil_tweak.repository_mapper import EdgeKind, NodeKind

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            _service, repository_map = self._service(root)
            projection = sorted(
                (node.kind.value, node.path, node.name)
                for node in repository_map.nodes
                if node.kind in {NodeKind.API_ROUTE, NodeKind.CONTRACT, NodeKind.DEPLOYMENT_SURFACE}
            )
            expected = sorted(
                [
                    ("api_route", "src/app/main.py", "GET /users/{user_id}"),
                    ("api_route", "web/app/api/items/route.ts", "GET /api/items"),
                    ("api_route", "web/app/api/items/route.ts", "POST /api/items"),
                    ("contract", "src/app/models.py", "UserModel"),
                    ("contract", "web/src/contracts.ts", "UserContract"),
                    ("contract", "web/src/contracts.ts", "UserSchema"),
                    ("deployment_surface", "deploy/Containerfile", "Containerfile"),
                    ("deployment_surface", "wrangler.toml", "wrangler.toml"),
                ]
            )
            self.assertEqual(projection, expected)
            edge_projection = {
                edge.kind
                for edge in repository_map.edges
                if edge.kind in {EdgeKind.IMPORTS, EdgeKind.TESTS, EdgeKind.CONFIGURES, EdgeKind.BUILDS, EdgeKind.DEPLOYS}
            }
            self.assertEqual(
                edge_projection,
                {EdgeKind.IMPORTS, EdgeKind.TESTS, EdgeKind.CONFIGURES, EdgeKind.BUILDS, EdgeKind.DEPLOYS},
            )

    def test_component_change_finds_dependents_without_authority_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            service, repository_map = self._service(root)
            target = next(node for node in repository_map.nodes if node.path == "src/app/models.py" and node.kind.value == "module")
            report = service.impact_analysis(repository_map.map_digest, [target.id])
            payload = report.to_dict()
            self.assertEqual(payload["authority"], "none")
            self.assertFalse(payload["mayExecute"])
            self.assertFalse(payload["mayAuthorizeChanges"])
            self.assertIn("src/app/service.py", payload["recommendedInspection"])


if __name__ == "__main__":
    unittest.main()
