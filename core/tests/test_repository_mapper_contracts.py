from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from core.tests.repository_mapper_fixture import make_repository, source_digest


class RepositoryMapperContractTests(unittest.TestCase):
    def _map(self, root: Path, **changes):
        from core.lil_tweak.repository_mapper import MapBinding, RepositoryMapper

        values = {
            "repository_id": "islamismylifebey-web/fixture",
            "source_commit": "a" * 40,
            "source_tree_digest": source_digest(root),
            "schema_version": "repository-map-v1",
            "mapper_version": "1.0.0",
        }
        values.update(changes)
        return RepositoryMapper().map(root, MapBinding(**values))

    def test_canonical_serialization_is_sorted_and_digest_verified(self):
        from core.lil_tweak.repository_mapper import canonical_json, verify_map_digest

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            repository_map = self._map(root)
            serialized = canonical_json(repository_map)
            payload = json.loads(serialized)
            self.assertEqual(serialized, canonical_json(repository_map))
            self.assertEqual(payload["nodes"], sorted(payload["nodes"], key=lambda item: item["id"]))
            self.assertEqual(payload["edges"], sorted(payload["edges"], key=lambda item: item["id"]))
            self.assertTrue(verify_map_digest(repository_map))
            self.assertNotIn("timestamp", serialized.lower())

    def test_repeated_mapping_is_byte_for_byte_deterministic(self):
        from core.lil_tweak.repository_mapper import canonical_json

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            first = self._map(root)
            second = self._map(root)
            self.assertEqual(canonical_json(first), canonical_json(second))
            self.assertEqual(first.map_digest, second.map_digest)

    def test_exact_source_revision_binding_changes_map_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            first = self._map(root, source_commit="a" * 40)
            second = self._map(root, source_commit="b" * 40)
            self.assertEqual(first.binding.source_commit, "a" * 40)
            self.assertEqual(second.binding.source_commit, "b" * 40)
            self.assertNotEqual(first.map_digest, second.map_digest)

    def test_stable_ids_do_not_use_random_uuid_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            first = self._map(root)
            second = self._map(root)
            self.assertEqual([node.id for node in first.nodes], [node.id for node in second.nodes])
            self.assertTrue(all(node.id.startswith("node:") for node in first.nodes))

    def test_contracts_are_immutable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            repository_map = self._map(root)
            with self.assertRaises(FrozenInstanceError):
                repository_map.map_digest = "tampered"  # type: ignore[misc]


    def test_wrong_tree_digest_is_rejected_instead_of_relabeling_source(self):
        from core.lil_tweak.repository_mapper import SourceBindingError

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            with self.assertRaisesRegex(SourceBindingError, "source_tree_digest_mismatch"):
                self._map(root, source_tree_digest="0" * 64)

    def test_nested_attributes_are_immutable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            repository_map = self._map(root)
            dependency = next(
                node for node in repository_map.nodes if node.kind.value == "dependency"
            )
            with self.assertRaises(TypeError):
                dependency.attributes["resolution"] = "tampered"  # type: ignore[index]

    def test_context_manifest_fragment_is_evidence_without_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            fragment = self._map(root).context_manifest_fragment()
            self.assertEqual(fragment["schemaVersion"], "repository-context-v1")
            self.assertEqual(fragment["authority"], "none")
            self.assertFalse(fragment["mayExecute"])
            self.assertFalse(fragment["mayAuthorizeChanges"])
            self.assertNotIn("tool", json.dumps(fragment).lower())

    def test_service_get_query_relationship_and_neighborhood_interfaces(self):
        from core.lil_tweak.repository_mapper import MapBinding, NodeKind, RepositoryMapService

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_repository(root)
            binding = MapBinding(
                repository_id="fixture",
                source_commit="a" * 40,
                source_tree_digest=source_digest(root),
            )
            service = RepositoryMapService()
            created = service.create_map(root, binding)
            self.assertIs(service.get_map(created.map_digest), created)
            modules = service.query_nodes(created.map_digest, kind=NodeKind.MODULE)
            self.assertTrue(modules)
            relationships = service.query_relationships(created.map_digest, node_id=modules[0].id)
            self.assertIsInstance(relationships, tuple)
            neighborhood = service.inspect_component_neighborhood(
                created.map_digest, modules[0].id, depth=1
            )
            self.assertIn(modules[0].id, {node.id for node in neighborhood.nodes})


if __name__ == "__main__":
    unittest.main()
