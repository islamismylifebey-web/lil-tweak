import subprocess
import sys
import unittest
import copy
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, Mock
from types import SimpleNamespace
from deploy.tests.test_activation_finalizer import ROOT, ActivationFixture, load


class LiveEvidenceTests(unittest.TestCase):
    def test_every_site_member_is_bound_to_its_semantically_validated_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                live = load("lil-tweak-live-evidence")
                directory = f.args.site_primary_evidence
                for path in sorted(directory.iterdir()):
                    original = path.read_bytes()
                    derive = live.derive_site
                    def substitute_after_real_semantics(*args, **kwargs):
                        value = derive(*args, **kwargs)
                        f.write(path, {})
                        return value
                    try:
                        with self.subTest(member=path.name), patch.object(live, "derive_site", side_effect=substitute_after_real_semantics), self.assertRaises(Exception):
                            live.reopen_site(directory)
                    finally: f.raw(path, original)
            finally: f.close()

    def test_resource_sealer_retains_only_strict_sanitized_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                script = ROOT / "scripts/lil-tweak-live-evidence.py"
                output = f.root / "sealed-resources.json"
                args = [sys.executable, str(script), "seal-resource-observations", "--observations-stdin", "--output", str(output)]
                result = subprocess.run(args, input=json.dumps(f.observations).encode(), capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.read_bytes(), f.a.canonical(f.observations))
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                output.unlink()
                for bad in ({**f.observations, "rawResponse": "SECRET-CANARY"}, {**f.observations, "token": "SECRET-CANARY"}):
                    result = subprocess.run(args, input=json.dumps(bad).encode(), capture_output=True)
                    self.assertEqual(result.returncode, 1)
                    self.assertFalse(output.exists())
                    self.assertNotIn(b"SECRET-CANARY", result.stdout + result.stderr)
                # Production must reopen the sealed source, not accept a
                # changed hash after the strict validator returns.
                release = f.a.release
                helper = release._activation_helper()
                validate = helper.validate_resource_observations
                def substitute(value):
                    result = validate(value)
                    f.write(f.root / "resource-observations.json", {})
                    return result
                with patch.object(release, "_activation_helper", return_value=helper), patch.object(helper, "validate_resource_observations", side_effect=substitute), self.assertRaises(Exception):
                    release.create_production_manifest(f.args.runtime_manifest, f.root / "state.env", f.args.owner_flow_receipt, f.root / "substituted-production.json")
                self.assertFalse((f.root / "substituted-production.json").exists())
            finally: f.close()

    def test_independent_guest_observation_executes_and_rejects_identity_or_cleanup_disagreement(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                live = load("lil-tweak-live-evidence")
                target = SimpleNamespace(droplet_id="597343619", hostname="galor-tweak-runner-01")
                boundaries = Mock()
                boundaries.source_head.return_value = f.head
                boundaries.images.return_value = f.guest["images"]
                boundaries.runtime_snapshot.return_value = {"containers": []}
                with patch.object(live.a, "SESSION_SECRET_DIRECTORY", f.secret_directory), patch.object(live.q, "target_module", return_value=SimpleNamespace(verify_target=lambda: target)), patch.object(live.platform, "machine", return_value="x86_64"), patch.object(live.platform, "freedesktop_os_release", return_value={"ID": "ubuntu", "VERSION_ID": "24.04"}), patch.object(live.pwd, "getpwnam", return_value=Mock()), patch.object(live.q, "load_core_environment", return_value={}), patch.object(live.q, "InstalledBoundaries", return_value=boundaries):
                    output = f.root / "guest-independent.json"
                    live.collect_guest(f.repo, f.args.provider_evidence, f.args.runtime_manifest, f.jobid, output)
                    self.assertEqual(f.a.read_json(output)["identity"], f.guest["identity"])
                    self.assertEqual(f.a.read_json(output)["secretDirectory"], f.directory_observation)
                    for kind in ("identity", "cleanup", "source", "images"):
                        target.droplet_id = "1" if kind == "identity" else "597343619"
                        boundaries.runtime_snapshot.return_value = {"containers": ["leftover"] if kind == "cleanup" else []}
                        boundaries.source_head.return_value = "0" * 40 if kind == "source" else f.head
                        boundaries.images.return_value = {} if kind == "images" else f.guest["images"]
                        rejected = f.root / ("guest-rejected-" + kind)
                        with self.subTest(kind=kind), self.assertRaises(Exception):
                            live.collect_guest(f.repo, f.args.provider_evidence, f.args.runtime_manifest, f.jobid, rejected)
                        self.assertFalse(rejected.exists())
                script = ROOT / "scripts/lil-tweak-live-evidence.py"
                result = subprocess.run([sys.executable, str(script), "seal-guest", "--provider-evidence", str(f.args.provider_evidence), "--runtime-manifest", str(f.args.runtime_manifest), "--verification-receipt", str(f.primary / "verification-receipt.json"), "--output", str(f.root / "guest-derived-cli.json")], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            finally: f.close()

    def test_existing_output_is_rejected_before_core_contact(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                live = load("lil-tweak-live-evidence")
                output = f.root / "existing.json"; f.write(output, {})
                client = Mock()
                with self.assertRaises(Exception): live.collect_core(f.root / "unused.env", f.args.d1_cross_check, output, client=client)
                client.json.assert_not_called()
            finally: f.close()

    def test_site_sealing_cli_preserves_primary_bytes_and_rejects_extra_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                script = ROOT / "scripts/lil-tweak-live-evidence.py"
                output = f.root / "sealed-again"
                command = [sys.executable, str(script), "seal-site", "--collector-stdin", "--site-deployment-record", str(f.root / "site-deployment.json"), "--output-dir", str(output)]
                result = subprocess.run(command, input=json.dumps(f.capture).encode(), capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((output / "status.body").read_bytes(), (f.args.site_primary_evidence / "status.body").read_bytes())
                self.assertEqual(output.stat().st_mode & 0o777, 0o700)
                for path in output.iterdir(): self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                live = load("lil-tweak-live-evidence")
                for field in ("headers", "cookie", "authorization", "Access", "signing", "Set-Cookie", "origin", "binding", "environment", "prompt", "objectKey"):
                    bad = copy.deepcopy(f.capture); bad["responses"][0][field] = "SECRET-CANARY"
                    rejected = f.root / ("reject-" + field)
                    with self.assertRaises(Exception): live.seal_site(bad, f.root / "site-deployment.json", rejected)
                    self.assertFalse(rejected.exists())
                for source, target in ((f.args.d1_cross_check, f.root / "d1-second.json"),):
                    result = subprocess.run([sys.executable, str(script), "seal-d1", "--response-stdin", "--job-id", f.jobid, "--output", str(target)], input=source.read_bytes(), capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(source.read_bytes(), target.read_bytes())
                wrong = copy.deepcopy(f.core); wrong["gitSource"]["commit"] = "0" * 40
                client = Mock(); client.json.return_value = wrong
                with self.assertRaises(Exception): live.collect_core(f.root / "unused.env", f.args.d1_cross_check, f.root / "wrong-core.json", client=client)
                self.assertFalse((f.root / "wrong-core.json").exists())
            finally: f.close()

    def test_all_live_interfaces_exist_but_check_is_offline(self):
        script = ROOT / "scripts/lil-tweak-live-evidence.py"
        result = subprocess.run([sys.executable, str(script), "--check"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        for command in ("seal-site", "seal-d1", "seal-guest", "collect-core", "collect-guest"):
            result = subprocess.run([sys.executable, str(script), command, "--help"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("--origin", result.stdout)
            self.assertNotIn("--host", result.stdout)
            self.assertNotIn("--secret", result.stdout)
