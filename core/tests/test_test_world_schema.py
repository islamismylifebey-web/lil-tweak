import unittest
from pathlib import Path

from core.lil_tweak.test_world_postgres import PostgresTestWorldStore


ROOT = Path(__file__).resolve().parents[2]


class TestWorldSchemaContractTests(unittest.TestCase):
    def test_forward_migration_003_defines_worlds_attempts_leases_and_schema_version(self):
        migration = ROOT / "core" / "migrations" / "003_test_world.sql"
        self.assertTrue(migration.is_file(), "migration 003 must be a separately reviewed forward migration")
        text = migration.read_text()
        for required in (
            "CREATE TABLE lil_tweak_test_worlds",
            "CREATE TABLE lil_tweak_test_world_attempts",
            "lease_generation",
            "lease_owner",
            "lease_expires_at",
            "UNIQUE (world_id, attempt_number)",
            "CHECK (max_attempts BETWEEN 1 AND 10)",
            "CHECK (status IN ('ready','running','failed','passed','exhausted','blocked'))",
            "CHECK (status IN ('queued','running','passed','failed','error'))",
            "INSERT INTO lil_tweak_schema_version (version) VALUES (3)",
        ):
            self.assertIn(required, text)

    def test_postgres_adapter_is_connection_factory_based(self):
        calls = []

        def connect():
            calls.append(True)
            raise RuntimeError("not opened during construction")

        store = PostgresTestWorldStore(connect)
        self.assertIsNotNone(store)
        self.assertEqual(calls, [])

    def test_installer_stages_and_advances_the_exact_third_migration(self):
        installer = (ROOT / "scripts" / "install-digitalocean.sh").read_text()
        for required in (
            'MIGRATION_003_SOURCE="${PROJECT_DIR}/core/migrations/003_test_world.sql"',
            '003_test_world.sql',
            'schema_version" == "3"',
        ):
            self.assertIn(required, installer)

    def test_runtime_and_integrity_checks_require_schema_three(self):
        main = (ROOT / "core" / "main.py").read_text()
        integrity = (ROOT / "deploy" / "postgres-integrity.sql").read_text()
        self.assertIn("version=3", main)
        self.assertIn("ARRAY[1, 2, 3]", integrity)
        self.assertIn("lil_tweak_test_worlds", integrity)
        self.assertIn("lil_tweak_test_world_attempts", integrity)

    def test_service_and_rollback_inventories_include_migration_003(self):
        service_files = (ROOT / "scripts" / "lil-tweak-service-files.py").read_text()
        rollback = (ROOT / "scripts" / "lil-tweak-rollback.py").read_text()
        operations = (ROOT / "docs" / "operations" / "digitalocean.md").read_text()
        self.assertIn("migrations/003_test_world.sql", service_files)
        self.assertIn("migrations/003_test_world.sql", rollback)
        self.assertIn("schema version three", operations.lower())


if __name__ == "__main__":
    unittest.main()
