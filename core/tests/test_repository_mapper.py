import tempfile
import unittest
from pathlib import Path

from core.lil_tweak.repository_mapper import (
    inspection_set,
    map_repository,
    to_canonical_json,
    transitive_reverse_dependencies,
)


def node(repository_map, node_id):
    return next(item for item in repository_map.nodes if item.id == node_id)


def edge_exists(repository_map, source, target, kind):
    return any(
        edge.source == source and edge.target == target and edge.kind == kind
        for edge in repository_map.edges
    )


class RepositoryMapperTests(unittest.TestCase):
    def test_binds_exact_source_and_produces_stable_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "core/lil_tweak").mkdir(parents=True)
            (root / "core/lil_tweak/__init__.py").write_text("", encoding="utf-8")
            (root / "core/lil_tweak/service.py").write_text(
                "class Service:\n    pass\n",
                encoding="utf-8",
            )

            first = map_repository(root, repository_identity="owner/repo", commit="a" * 40)
            second = map_repository(root, repository_identity="owner/repo", commit="a" * 40)

        self.assertEqual(first.binding.repository_identity, "owner/repo")
        self.assertEqual(first.binding.commit, "a" * 40)
        self.assertRegex(first.binding.source_digest, r"^[0-9a-f]{64}$")
        self.assertRegex(first.binding.map_digest, r"^[0-9a-f]{64}$")
        self.assertEqual(first.binding.map_digest, second.binding.map_digest)
        self.assertEqual(to_canonical_json(first), to_canonical_json(second))

    def test_maps_python_symbols_routes_internal_imports_and_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "core/lil_tweak").mkdir(parents=True)
            (root / "core/tests").mkdir(parents=True)
            (root / "core/lil_tweak/__init__.py").write_text("", encoding="utf-8")
            (root / "core/lil_tweak/models.py").write_text(
                "class Job:\n    pass\n",
                encoding="utf-8",
            )
            (root / "core/lil_tweak/api.py").write_text(
                "from core.lil_tweak.models import Job\n\n"
                "@app.get('/jobs')\n"
                "def list_jobs():\n"
                "    return Job()\n",
                encoding="utf-8",
            )
            (root / "core/tests/test_api.py").write_text(
                "from core.lil_tweak.api import list_jobs\n",
                encoding="utf-8",
            )

            repository_map = map_repository(root, repository_identity="owner/repo", commit="b" * 40)

        self.assertEqual(node(repository_map, "symbol:core/lil_tweak/models.py:Job").kind, "schema_model_contract")
        self.assertTrue(
            edge_exists(
                repository_map,
                "file:core/lil_tweak/api.py",
                "file:core/lil_tweak/models.py",
                "IMPORTS",
            )
        )
        self.assertTrue(
            edge_exists(
                repository_map,
                "file:core/lil_tweak/api.py",
                "api_route:GET:/jobs",
                "SERVES",
            )
        )
        self.assertTrue(
            edge_exists(
                repository_map,
                "file:core/tests/test_api.py",
                "file:core/lil_tweak/api.py",
                "TESTS",
            )
        )

    def test_maps_typescript_routes_dependencies_and_impact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app/api/chat").mkdir(parents=True)
            (root / "lib").mkdir()
            (root / "tests").mkdir()
            (root / "package.json").write_text(
                '{"scripts":{"build":"next build"},"dependencies":{"next":"1.0.0"}}',
                encoding="utf-8",
            )
            (root / "lib/core.ts").write_text(
                "export interface ChatRequest {}\nexport function parseChat() { return true }\n",
                encoding="utf-8",
            )
            (root / "app/api/chat/route.ts").write_text(
                "import { parseChat } from '../../../lib/core'\n"
                "export async function POST() { return parseChat() }\n",
                encoding="utf-8",
            )
            (root / "tests/core.test.mjs").write_text(
                "import { parseChat } from '../lib/core.js'\n",
                encoding="utf-8",
            )

            repository_map = map_repository(root, repository_identity="owner/repo", commit="c" * 40)

        self.assertTrue(
            edge_exists(repository_map, "file:app/api/chat/route.ts", "api_route:POST:/api/chat", "SERVES")
        )
        self.assertTrue(
            edge_exists(repository_map, "file:app/api/chat/route.ts", "file:lib/core.ts", "IMPORTS")
        )
        self.assertTrue(edge_exists(repository_map, "file:package.json", "dependency:next", "DEPENDS_ON"))
        dependents = transitive_reverse_dependencies(repository_map, "file:lib/core.ts")
        self.assertIn("file:app/api/chat/route.ts", dependents)
        self.assertIn("app/api/chat/route.ts", inspection_set(repository_map, "file:lib/core.ts"))

    def test_records_unsupported_files_without_inventing_edges(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.unknown").write_text("plain", encoding="utf-8")
            repository_map = map_repository(root, repository_identity="owner/repo", commit="d" * 40)

        unsupported = node(repository_map, "file:README.unknown")
        self.assertEqual(unsupported.metadata["analysis"], "unsupported")
        self.assertFalse(
            any(edge.source == "file:README.unknown" and edge.kind == "IMPORTS" for edge in repository_map.edges)
        )


if __name__ == "__main__":
    unittest.main()
