"""Real production-manifest verifier tests with harmless release fixtures.

Windows replaces only POSIX secure file read/write boundaries; parsing,
canonicalization, runtime validation, state and decision checks remain real.
On Linux the existing secure file implementation runs without replacement.
"""
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[1] / "scripts" / "lil-tweak-release.py"
SPEC = importlib.util.spec_from_file_location("release_candidate", SOURCE)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def runtime_fixture():
    images = {}
    for index, name in enumerate(("core", "runner", "postgres", "python_base", "runner_base"), 1):
        pin = "sha256:" + str(index) * 64
        images[name] = {"reference": "registry.example/" + name.replace("_", "-") + "@" + pin, "digest": pin}
    small = {"sha256": "a" * 64, "size": 100}
    return {"schema": "lil-tweak-runtime-manifest-v1",
            "source": {"commit": "1" * 40, "tree": "2" * 40, "manifest_sha256": "3" * 64,
                       "manifest_size": 500, "archive_sha256": "4" * 64, "archive_size": 600},
            "images": images, "receipts": {"host_go": small, "base_images": small,
            "image_scans": {"receipt_sha256": "b" * 64, "receipt_size": 200,
                "artifacts": [{"name": name, **small} for name in
                              ("core.grype.json", "core.sbom.json", "runner.grype.json", "runner.sbom.json")]}}}


class NativeProductionTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="native-sites-contract-test-"))
        prior = Path.cwd()
        os.chdir(self.temp)
        self.stack.callback(os.chdir, prior)
        if os.name == "nt":
            def read(path, *, maximum, **_options):
                data = Path(path).read_bytes()
                if len(data) > maximum:
                    raise release.ReleaseError("input_file_size")
                return data
            def write(path, value):
                data = release.canonical_json_bytes(value)
                with Path(path).open("xb") as output:
                    output.write(data)
                return digest(data)
            self.stack.enter_context(patch.object(release, "_read_secure", read))
            self.stack.enter_context(patch.object(release, "write_new_manifest", write))
        self.runtime = runtime_fixture()
        self.put("runtime.json", canonical(self.runtime), 0o444)
        self.put("bindings.json", b'{"fixture":"supported project-bound DB and FILES observation"}\n')
        self.put("schema.json", b'{"fixture":"supported structural schema and reviewed migration comparison"}\n')
        self.state = {
            "RUNTIME_MANIFEST": "runtime.json", "RUNTIME_MANIFEST_SHA256": digest(canonical(self.runtime)),
            "SOURCE_COMMIT": "1" * 40, "SOURCE_TREE": "2" * 40, "SITES_SOURCE_COMMIT": "1" * 40,
            "SITES_SOURCE_TREE": "2" * 40,
            "LIL_TWEAK_INGRESS_MODE": "sites_native", "SITES_PROJECT_ID": "appgprj_" + "5" * 32,
            "SITES_DB_BINDING": "DB", "SITES_FILES_BINDING": "FILES",
            "SITES_BINDING_EVIDENCE": "bindings.json", "SITES_DB_SCHEMA_EVIDENCE": "schema.json",
            "LIL_TWEAK_TUNNEL_ID": "tunnel-fixture", "ACCESS_APPLICATION_ID": "access-app-fixture",
            "ACCESS_POLICY_ID": "access-policy-fixture", "ACCESS_POLICY_REVISION": "access-policy-r1",
            "CORE_ORIGIN": "https://core.example.invalid", "SITES_VERSION_ID": "site-version-fixture",
            "SITES_VERSION_NUMBER": "35", "SITES_DEPLOYMENT_ID": "deployment-fixture",
            "SITES_ARCHIVE_HASH": "c" * 64, "SITES_ENVIRONMENT_REVISION": "3", "SITES_ACCESS_REVISION": "access-r1",
            "SITES_ACCESS_MODE": "custom", "SITES_ALLOWED_OWNER_COUNT": "1", "SITES_ALLOWED_GROUP_COUNT": "0",
            "SITES_ALLOWED_VISITOR_COUNT": "0", "PRODUCTION_URL": "https://fixture.chatgpt.site",
            "PUBLIC_ORIGIN": "https://fixture.chatgpt.site", "PRIOR_SITES_VERSION_NUMBER": "34"}

    def put(self, name, data, mode=0o600):
        path = Path(name)
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(data)
        path.chmod(mode)

    def owner(self, native=True, stale=False, overrides=None):
        state = self.state
        values = {"schema": "lil-tweak-owner-flow-receipt-v3" if native else "lil-tweak-owner-flow-receipt-v2",
                  "decision": "PASS", "runtime_manifest_sha256": state["RUNTIME_MANIFEST_SHA256"],
                  "source_commit": state["SOURCE_COMMIT"], "source_tree": state["SOURCE_TREE"],
                  "sites_version_id": state["SITES_VERSION_ID"], "sites_version_number": state["SITES_VERSION_NUMBER"],
                  "sites_deployment_id": state["SITES_DEPLOYMENT_ID"], "sites_archive_sha256": state["SITES_ARCHIVE_HASH"],
                  "production_url": state["PRODUCTION_URL"]}
        if native:
            values.update({"sites_project_id": state["SITES_PROJECT_ID"], "sites_ingress_mode": "sites_native",
                           "sites_environment_revision": state["SITES_ENVIRONMENT_REVISION"],
                           "sites_access_revision": state["SITES_ACCESS_REVISION"], "sites_access_mode": "custom",
                           "sites_allowed_owner_count": "1", "sites_allowed_group_count": "0", "sites_allowed_visitor_count": "0",
                           "db_binding": state["SITES_DB_BINDING"], "files_binding": state["SITES_FILES_BINDING"],
                           "binding_evidence_sha256": digest(Path("bindings.json").read_bytes()),
                           "db_schema_evidence_sha256": digest(Path("schema.json").read_bytes()),
                           "sites_source_commit": state["SITES_SOURCE_COMMIT"], "sites_source_tree": state["SITES_SOURCE_TREE"]})
        now = datetime.now(timezone.utc).replace(microsecond=0)
        if stale:
            now -= timedelta(hours=2)
        values.update({"issued_at": (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "expires_at": (now + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ"), "nonce": "e" * 32})
        values.update(overrides or {})
        self.put("owner.txt", "".join(key + "=" + value + "\n" for key, value in values.items()).encode())

    def run_manifest(self, name="production.json"):
        self.put("state.env", "".join(key + "=" + value + "\n" for key, value in self.state.items()).encode())
        return release.create_production_manifest(Path("runtime.json"), Path("state.env"), Path("owner.txt"), Path(name))

    def test_native_manifest_uses_truthful_logical_bindings_without_physical_identifiers(self):
        self.owner()
        try:
            actual = self.run_manifest()
        except release.ReleaseError as error:
            self.fail("native production contract rejected truthful logical bindings: " + error.code)
        data = Path("production.json").read_bytes()
        value = json.loads(data)
        self.assertEqual(actual, digest(data))
        self.assertEqual(value["schema"], "lil-tweak-production-manifest-v2")
        self.assertEqual(value["sites"]["project_id"], self.state["SITES_PROJECT_ID"])
        self.assertEqual(value["sites"]["ingress_mode"], "sites_native")
        self.assertEqual(value["sites"]["storage"]["db"]["binding"], "DB")
        self.assertEqual(value["sites"]["storage"]["files"]["binding"], "FILES")
        self.assertEqual(set(value["cloudflare"]), {"ingress"})
        self.assertNotIn("managed_rule_id", value["cloudflare"]["ingress"])
        self.assertEqual(value["cloudflare"]["ingress"]["access_application_id"], "access-app-fixture")

    def test_native_rejects_non_sites_origin_unknown_mode_wrong_binding_and_mixed_legacy_fields(self):
        self.owner()
        mutations = [{"PRODUCTION_URL": "https://example.invalid", "PUBLIC_ORIGIN": "https://example.invalid"},
                     {"LIL_TWEAK_INGRESS_MODE": "automatic"}, {"SITES_DB_BINDING": "OTHER"},
                     {"SITES_FILES_BINDING": "OTHER"}, {"SITES_PROJECT_ID": "invented-id"},
                     {"D1_DATABASE_ID": "fabricated"}, {"MANAGED_INGRESS_RULE_ID": "fabricated"}]
        baseline = self.state.copy()
        for mutation in mutations:
            self.state = {**baseline, **mutation}
            with self.subTest(mutation=mutation), self.assertRaisesRegex(release.ReleaseError, "sites_native_state_rejected|ingress_mode_rejected"):
                self.run_manifest()

    def test_native_owner_receipt_binds_project_access_environment_and_evidence(self):
        for field in ("sites_project_id", "sites_source_commit", "sites_source_tree", "sites_environment_revision", "sites_access_revision", "binding_evidence_sha256", "db_schema_evidence_sha256"):
            self.owner(overrides={field: "different"})
            with self.subTest(field=field), self.assertRaisesRegex(release.ReleaseError, "owner_flow_receipt_rejected"):
                self.run_manifest()
        self.owner(stale=True)
        with self.assertRaisesRegex(release.ReleaseError, "owner_flow_receipt_rejected"):
            self.run_manifest()

    def test_changed_empty_or_missing_native_evidence_is_not_accepted(self):
        self.owner()
        self.put("schema.json", b'{"changed":true}\n')
        with self.assertRaisesRegex(release.ReleaseError, "owner_flow_receipt_rejected"):
            self.run_manifest()
        self.put("schema.json", b"")
        with self.assertRaisesRegex(release.ReleaseError, "sites_native_evidence_rejected"):
            self.run_manifest()
        Path("schema.json").unlink()
        with self.assertRaises((release.ReleaseError, OSError)):
            self.run_manifest()

    def test_native_still_requires_owner_private_access_runtime_integrity_and_core_access(self):
        self.owner()
        self.state["SITES_ALLOWED_GROUP_COUNT"] = "1"
        with self.assertRaisesRegex(release.ReleaseError, "sites_access_rejected"):
            self.run_manifest()
        self.state["SITES_ALLOWED_GROUP_COUNT"] = "0"
        del self.state["ACCESS_APPLICATION_ID"]
        with self.assertRaises(release.ReleaseError):
            self.run_manifest()
        self.state["ACCESS_APPLICATION_ID"] = "access-app-fixture"
        self.runtime["images"]["core"]["digest"] = "sha256:" + "f" * 64
        self.put("runtime.json", canonical(self.runtime), 0o444)
        self.state["RUNTIME_MANIFEST_SHA256"] = digest(canonical(self.runtime))
        with self.assertRaisesRegex(release.ReleaseError, "runtime_manifest_mismatch"):
            self.run_manifest()

    def test_legacy_managed_assertion_contract_remains_v1(self):
        for field in list(self.state):
            if field in {"LIL_TWEAK_INGRESS_MODE", "SITES_PROJECT_ID", "SITES_DB_BINDING", "SITES_FILES_BINDING", "SITES_BINDING_EVIDENCE", "SITES_DB_SCHEMA_EVIDENCE"}:
                del self.state[field]
        self.state.update({"D1_DATABASE_ID": "actual-database-fixture", "D1_SCHEMA_REVISION": "schema-r1", "D1_BINDING_REVISION": "binding-r1",
                           "R2_ACCOUNT_ID": "account-fixture", "R2_BUCKET_NAME": "bucket-fixture", "R2_BINDING_REVISION": "binding-r2",
                           "MANAGED_INGRESS_RULE_ID": "managed-rule-fixture", "MANAGED_INGRESS_REVISION": "managed-r1"})
        self.owner(native=False)
        self.run_manifest()
        value = json.loads(Path("production.json").read_bytes())
        self.assertEqual(value["schema"], "lil-tweak-production-manifest-v1")
        self.assertEqual(value["cloudflare"]["d1"]["database_id"], "actual-database-fixture")
        self.assertEqual(value["cloudflare"]["ingress"]["managed_rule_id"], "managed-rule-fixture")

    def test_native_preserves_platform_composite_version_id_verbatim(self):
        version = "appgprj_" + "5" * 32 + "~appgver_" + "6" * 32
        self.state["SITES_VERSION_ID"] = version
        self.owner()
        try:
            self.run_manifest()
        except release.ReleaseError as error:
            self.fail("native platform version identity was rejected: " + error.code)
        self.assertEqual(json.loads(Path("production.json").read_bytes())["sites"]["version_id"], version)

    def test_native_preserves_independent_private_site_source_without_rewriting_history(self):
        self.state["SITES_SOURCE_COMMIT"] = "8" * 40
        self.state["SITES_SOURCE_TREE"] = "9" * 40
        self.owner()
        self.run_manifest()
        value = json.loads(Path("production.json").read_bytes())
        self.assertEqual(value["sites"]["source_commit"], "8" * 40)
        self.assertEqual(value["sites"]["source_tree"], "9" * 40)
        self.assertEqual(value["runtime"]["source_commit"], "1" * 40)

    def test_native_rejects_missing_or_malformed_source_identity(self):
        self.owner()
        baseline = self.state.copy()
        for field in ("SITES_SOURCE_COMMIT", "SITES_SOURCE_TREE"):
            for invalid in (None, "not-a-commit", "A" * 40):
                self.state = baseline.copy()
                if invalid is None:
                    del self.state[field]
                else:
                    self.state[field] = invalid
                with self.subTest(field=field, invalid=invalid), self.assertRaises(release.ReleaseError):
                    self.run_manifest()


if __name__ == "__main__":
    unittest.main()
