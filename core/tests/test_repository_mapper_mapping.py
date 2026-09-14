from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from core.tests.repository_mapper_fixture import make_repository, source_digest, write_files


class RepositoryMapperMappingTests(unittest.TestCase):
    def _map(self, root: Path, *, limits=None, mapper=None):
        from core.lil_tweak.repository_mapper import MapBinding, RepositoryMapper

        mapper = mapper or RepositoryMapper(limits=limits)
        return mapper.map(
            root,
            MapBinding(
                repository_id="fixture",
                source_commit="c" * 40,
                source_tree_digest=source_digest(root),
            ),
        )

    def test_discovers_repository_applications_packages_modules_and_files(self):
        from core.lil_tweak.repository_mapper import NodeKind

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            result = self._map(root)
            kinds = {node.kind for node in result.nodes}
            self.assertTrue(
                {
                    NodeKind.REPOSITORY,
                    NodeKind.APPLICATION,
                    NodeKind.PACKAGE,
                    NodeKind.MODULE,
                    NodeKind.SOURCE_FILE,
                    NodeKind.CONFIGURATION_FILE,
                    NodeKind.TEST_FILE,
                }.issubset(kinds)
            )
            paths = {node.path for node in result.nodes if node.path}
            self.assertIn("src/app/service.py", paths)
            self.assertIn("web/src/client.ts", paths)

    def test_python_symbols_methods_models_and_source_locations_are_mapped(self):
        from core.lil_tweak.repository_mapper import NodeKind

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            result = self._map(root)
            symbols = {
                (node.qualified_name, node.kind): node
                for node in result.nodes
                if node.kind in {NodeKind.SYMBOL, NodeKind.CONTRACT}
            }
            self.assertIn(("app.models.UserModel", NodeKind.CONTRACT), symbols)
            self.assertIn(("app.service.build_user", NodeKind.SYMBOL), symbols)
            location = symbols[("app.service.build_user", NodeKind.SYMBOL)].location
            self.assertIsNotNone(location)
            self.assertGreaterEqual(location.start_line, 1)

    def test_python_imports_map_internal_external_and_unresolved_dependencies(self):
        from core.lil_tweak.repository_mapper import EdgeKind, NodeKind

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            result = self._map(root)
            by_id = {node.id: node for node in result.nodes}
            imports = [edge for edge in result.edges if edge.kind == EdgeKind.IMPORTS]
            pairs = {(by_id[e.source].path, by_id[e.target].path or by_id[e.target].name) for e in imports}
            self.assertIn(("src/app/service.py", "src/app/models.py"), pairs)
            dependencies = {
                node.name: node
                for node in result.nodes
                if node.kind == NodeKind.DEPENDENCY
            }
            self.assertIn("pydantic", dependencies)
            self.assertIn("missing_vendor", dependencies)
            self.assertEqual(dependencies["missing_vendor"].attributes["resolution"], "unresolved")

    def test_typescript_javascript_modules_imports_symbols_and_contracts_are_mapped(self):
        from core.lil_tweak.repository_mapper import EdgeKind, NodeKind

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            result = self._map(root)
            by_id = {node.id: node for node in result.nodes}
            pairs = {
                (by_id[e.source].path, by_id[e.target].path)
                for e in result.edges
                if e.kind == EdgeKind.IMPORTS and by_id[e.target].path
            }
            self.assertIn(("web/src/client.ts", "web/src/api.ts"), pairs)
            contracts = {
                node.qualified_name
                for node in result.nodes
                if node.kind == NodeKind.CONTRACT
            }
            self.assertIn("web.src.contracts.UserContract", contracts)
            self.assertIn("web.src.contracts.UserSchema", contracts)

    def test_discovers_python_and_next_routes_without_runtime_reachability_claims(self):
        from core.lil_tweak.repository_mapper import NodeKind

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            result = self._map(root)
            routes = [node for node in result.nodes if node.kind == NodeKind.API_ROUTE]
            projection = {(node.attributes["method"], node.attributes["routePath"], node.path) for node in routes}
            self.assertIn(("GET", "/users/{user_id}", "src/app/main.py"), projection)
            self.assertIn(("GET", "/api/items", "web/app/api/items/route.ts"), projection)
            self.assertIn(("POST", "/api/items", "web/app/api/items/route.ts"), projection)
            self.assertTrue(all(node.attributes["runtimeReachability"] == "unknown" for node in routes))

    def test_external_dependency_declarations_are_separate_from_internal_modules(self):
        from core.lil_tweak.repository_mapper import NodeKind

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            result = self._map(root)
            dependencies = {
                (node.name, node.attributes.get("declarationSource"))
                for node in result.nodes
                if node.kind == NodeKind.DEPENDENCY
            }
            self.assertIn(("fastapi", "pyproject.toml"), dependencies)
            self.assertIn(("react", "package.json"), dependencies)
            self.assertIn(("zod", "web/package.json"), dependencies)


    def test_declared_dependencies_have_explicit_dependency_edges(self):
        from core.lil_tweak.repository_mapper import EdgeKind, NodeKind

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            result = self._map(root)
            by_id = {node.id: node for node in result.nodes}
            pairs = {
                (by_id[edge.source].path, by_id[edge.target].name)
                for edge in result.edges
                if edge.kind == EdgeKind.DEPENDS_ON
                and by_id[edge.target].kind == NodeKind.DEPENDENCY
            }
            self.assertIn(("pyproject.toml", "fastapi"), pairs)
            self.assertIn(("package.json", "react"), pairs)

    def test_test_relationships_distinguish_proven_and_inferred(self):
        from core.lil_tweak.repository_mapper import EdgeKind, EvidenceClass

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            result = self._map(root)
            test_edges = [edge for edge in result.edges if edge.kind == EdgeKind.TESTS]
            self.assertIn(EvidenceClass.PROVEN, {edge.evidence for edge in test_edges})
            self.assertIn(EvidenceClass.INFERRED, {edge.evidence for edge in test_edges})

    def test_entry_points_build_targets_configuration_and_deployment_surfaces_are_mapped(self):
        from core.lil_tweak.repository_mapper import NodeKind

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            result = self._map(root)
            kinds = {node.kind for node in result.nodes}
            self.assertIn(NodeKind.ENTRY_POINT, kinds)
            self.assertIn(NodeKind.BUILD_TARGET, kinds)
            self.assertIn(NodeKind.DEPLOYMENT_SURFACE, kinds)
            deploy_paths = {
                node.path for node in result.nodes if node.kind == NodeKind.DEPLOYMENT_SURFACE
            }
            self.assertIn("deploy/Containerfile", deploy_paths)
            self.assertIn("wrangler.toml", deploy_paths)

    def test_dependency_cycles_are_reported_as_findings_not_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            result = self._map(root)
            cycles = [finding for finding in result.findings if finding.code == "dependency_cycle"]
            self.assertEqual(len(cycles), 1)
            self.assertEqual(cycles[0].severity, "finding")

    def test_unsupported_language_files_remain_visible_with_limited_status(self):
        from core.lil_tweak.repository_mapper import AnalysisStatus

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            result = self._map(root)
            legacy = next(node for node in result.nodes if node.path == "notes/legacy.rb")
            self.assertEqual(legacy.attributes["language"], "Ruby")
            self.assertEqual(legacy.analysis_status, AnalysisStatus.LIMITED)

    def test_malformed_source_is_recorded_without_aborting_other_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            result = self._map(root)
            malformed = [finding for finding in result.findings if finding.code == "malformed_source"]
            self.assertEqual([finding.path for finding in malformed], ["src/app/broken.py"])
            self.assertTrue(any(node.path == "src/app/service.py" for node in result.nodes))

    def test_oversized_file_is_visible_but_not_parsed(self):
        from core.lil_tweak.repository_mapper import AnalysisStatus, MapperLimits

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, {"large.py": "x = 1\n" * 100})
            result = self._map(root, limits=MapperLimits(max_file_bytes=32))
            node = next(node for node in result.nodes if node.path == "large.py")
            self.assertEqual(node.analysis_status, AnalysisStatus.SKIPPED_LIMIT)
            self.assertTrue(any(f.code == "file_too_large" for f in result.findings))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_and_path_escape_are_rejected(self):
        from core.lil_tweak.repository_mapper import RepositorySafetyError

        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            Path(outside, "secret.py").write_text("SECRET = True\n")
            os.symlink(Path(outside, "secret.py"), root / "linked.py")
            with self.assertRaisesRegex(RepositorySafetyError, "symlink_rejected"):
                self._map(root)

    def test_secret_boundary_is_preserved_before_content_is_read(self):
        from core.lil_tweak.repository_mapper import RepositorySafetyError

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, {".env": "TOP_SECRET=never-read\n", "safe.py": "x = 1\n"})
            with self.assertRaisesRegex(RepositorySafetyError, "unsafe_path"):
                self._map(root)

    def test_repository_mutation_during_mapping_is_detected(self):
        from core.lil_tweak.repository_mapper import RepositoryMapper, RepositoryMutationError

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            mapper = RepositoryMapper(_integrity_hook=lambda: (root / "src/app/service.py").write_text("changed\n"))
            with self.assertRaisesRegex(RepositoryMutationError, "repository_mutated"):
                self._map(root, mapper=mapper)

    def test_mapper_does_not_execute_package_scripts_or_mutate_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            marker = root / "EXECUTED"
            (root / "package.json").write_text(
                '{"scripts":{"build":"touch EXECUTED"},"dependencies":{}}\n',
                encoding="utf-8",
            )
            before = {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file()
            }
            self._map(root)
            after = {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file()
            }
            self.assertFalse(marker.exists())
            self.assertEqual(before, after)

    def test_graph_size_limits_fail_closed(self):
        from core.lil_tweak.repository_mapper import MapperLimits, MappingLimitError

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, {f"module_{index}.py": f"VALUE = {index}\n" for index in range(8)})
            with self.assertRaisesRegex(MappingLimitError, "node_limit"):
                self._map(root, limits=MapperLimits(max_nodes=5))

    def test_adversarial_casefold_collisions_are_rejected(self):
        from core.lil_tweak.repository_mapper import RepositorySafetyError

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_files(root, {"Readme.py": "x = 1\n", "README.py": "x = 2\n"})
            with self.assertRaisesRegex(RepositorySafetyError, "duplicate_path"):
                self._map(root)


if __name__ == "__main__":
    unittest.main()
