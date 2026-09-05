import copy
import json
import subprocess
import sys
import tempfile
import time
import unittest
import io
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from deploy.tests.test_activation_finalizer import ROOT, WITNESS_KEYS, REVIEW_KEYS, FINAL_KEYS, ORIGINAL_ARGUMENTS, ActivationFixture, load, objects, replace_at
from unittest.mock import patch
from deploy.tests.test_qualification import provider


class ActivationReviewTests(unittest.TestCase):
    def phase_fixture(self, root):
        f = ActivationFixture(root)
        r = f.a.helper("lil-tweak-independent-review")
        for name, raw, offset in zip(("preflight", "provider"), f.raw_providers, (-179, -129)):
            with patch.object(r.time, "time", return_value=f.now + offset):
                r.witness_provider(root / (name + ".json"), raw, root / (name + "-witness.json"))
        result = f.cli("build-candidate")
        self.assertEqual(result.returncode, 0, result.stderr)
        originals = []
        for name in ORIGINAL_ARGUMENTS: originals += ["--" + name, str(getattr(f.args, name.replace("-", "_")))]
        originals += ["--candidate", str(f.args.candidate), "--preflight-provider-witness", str(root / "preflight-witness.json"), "--provider-witness", str(root / "provider-witness.json")]
        return f, r, originals

    def test_review_rejects_cross_check_or_witness_substitution_after_real_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            f, r, originals = self.phase_fixture(Path(temporary))
            try:
                for name in ("d1.json", "core.json", "guest-cross.json", "preflight-witness.json", "provider-witness.json"):
                    path = f.root / name
                    before = path.read_bytes()
                    review = f.root / "attacked-review.json"
                    validate = r.validate_witness
                    calls = 0
                    def replace_after_validation(*args, **kwargs):
                        nonlocal calls
                        value = validate(*args, **kwargs)
                        calls += 1
                        if calls == 2: f.write(path, {})
                        return value
                    output = io.StringIO()
                    try:
                        with self.subTest(path=name), patch.object(r, "validate_witness", side_effect=replace_after_validation), redirect_stdout(output), redirect_stderr(output):
                            self.assertEqual(r.main(["review-candidate", *originals, "--review", str(review)]), 1)
                            self.assertEqual(calls, 2)
                            self.assertFalse(review.exists())
                            self.assertNotRegex(output.getvalue(), r"CONNECTED|QUALIFIED|READY_TO_WORK")
                    finally:
                        f.raw(path, before)
                        if review.exists(): review.unlink()
            finally: f.close()

    def assert_final_boundary_rejects_substitution(self, command):
        with tempfile.TemporaryDirectory() as temporary:
            f, r, originals = self.phase_fixture(Path(temporary))
            try:
                review, final = f.root / "review.json", f.root / "final.json"
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(r.main(["review-candidate", *originals, "--review", str(review)]), 0)
                arguments = [*originals, "--independent-review", str(review), "--activation", str(final)]
                if command == "verify-final":
                    with redirect_stdout(output): self.assertEqual(f.a.main(["finalize-reviewed", *arguments]), 0)
                verify = r.verify_review
                def replace_after_validation(*args, **kwargs):
                    value = verify(*args, **kwargs)
                    f.write(f.args.d1_cross_check, {})
                    return value
                output = io.StringIO()
                with patch.object(r, "verify_review", side_effect=replace_after_validation), redirect_stdout(output), redirect_stderr(output):
                    self.assertEqual(f.a.main([command, *arguments]), 1)
                self.assertNotRegex(output.getvalue(), r"CONNECTED|QUALIFIED|READY_TO_WORK")
                if command == "finalize-reviewed": self.assertFalse(final.exists())
            finally: f.close()

    def test_finalization_rechecks_originals_after_real_review_validation(self):
        self.assert_final_boundary_rejects_substitution("finalize-reviewed")

    def test_final_truth_rechecks_originals_after_real_review_validation(self):
        self.assert_final_boundary_rejects_substitution("verify-final")

    def test_full_phase_boundary_requires_review_and_reopens_originals(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = ActivationFixture(Path(temporary))
            try:
                r = load("lil-tweak-independent-review")
                for name, raw, offset in zip(("preflight", "provider"), f.raw_providers, (-179, -129)):
                    with patch.object(r.time, "time", return_value=f.now + offset):
                        r.witness_provider(f.root / (name + ".json"), raw, f.root / (name + "-witness.json"))
                result = f.cli("build-candidate")
                self.assertEqual(result.returncode, 0, result.stderr)
                witnesses = ["--preflight-provider-witness", str(f.root / "preflight-witness.json"), "--provider-witness", str(f.root / "provider-witness.json")]
                review = f.root / "review.json"
                final = f.root / "activation.json"
                finals = witnesses + ["--independent-review", str(review), "--activation", str(final)]
                result = f.cli("finalize-reviewed", extras=finals)
                self.assertNotEqual(result.returncode, 0); self.assertFalse(final.exists()); self.assertNotIn("CONNECTED", result.stdout)
                result = f.cli("review-candidate", script=ROOT / "scripts/lil-tweak-independent-review.py", extras=witnesses + ["--review", str(review)])
                self.assertEqual(result.returncode, 0, result.stderr)
                value = f.a.read_json(review)
                self.assertEqual(set(value), REVIEW_KEYS)
                self.assertEqual(set(value["providerWitnessDigests"]), {"preflight", "live"})
                self.assertEqual(set(value["crossCheckDigests"]), {"d1-cross-check", "core-cross-check", "guest-cross-check"})
                self.assertEqual(value["decision"], "pass"); self.assertNotIn("CONNECTED", review.read_text() + result.stdout)
                self.assertEqual(result.stdout.strip(), f.a.sha(review.read_bytes()))
                original_review = review.read_bytes()
                # Pin all review nested maps independently. The primary map is
                # descriptor-addressed; its exact keys come from reopened
                # inventories, and every individual map field is mutated below.
                self.assertTrue(value["primaryArtifactDigests"])
                self.assertTrue(all(key.startswith(("release/", "site/", "rollback/")) for key in value["primaryArtifactDigests"]))
                for digest in value["primaryArtifactDigests"].values(): self.assertRegex(digest, r"^[0-9a-f]{64}$")
                f.args.independent_review = review
                expected = {key: item for key, item in value.items() if key != "reviewerNonce"}
                with patch.object(r, "review_facts", return_value=(expected, [])):
                    for path, trail, obj in objects(value):
                        for field in list(obj) + ["authorization"]:
                            f.write(review, replace_at(value, trail, field, "SECRET-CANARY", remove=field in obj))
                            with self.subTest(path=path, field=field), self.assertRaises(Exception): r.verify_review(f.args)
                f.raw(review, original_review)
                for key, replacement in (("decision", "fail"), ("candidateSha256", "0" * 64), ("reviewedAt", f.t(-2000))):
                    bad = copy.deepcopy(value); bad[key] = replacement; f.write(review, bad)
                    result = f.cli("finalize-reviewed", extras=finals)
                    self.assertNotEqual(result.returncode, 0); self.assertFalse(final.exists()); self.assertNotIn("READY_TO_WORK", result.stdout)
                f.raw(review, original_review)
                result = f.cli("finalize-reviewed", extras=finals)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(set(f.a.read_json(final)), FINAL_KEYS)
                final_value = f.a.read_json(final)
                for key in ("CONNECTED", "QUALIFIED", "READY_TO_WORK"): self.assertIs(final_value[key], True)
                self.assertNotIn("CONNECTED", result.stdout)
                result = f.cli("verify-final", extras=finals)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines()[:3], ["CONNECTED = YES", "QUALIFIED = YES", "READY_TO_WORK = YES"])
                self.assertEqual(result.stdout.splitlines()[3], f.a.sha(final.read_bytes()))
                f.args.guest_cross_check.write_bytes(b"{}")
                result = f.cli("verify-final", extras=finals)
                self.assertNotEqual(result.returncode, 0); self.assertNotIn("CONNECTED", result.stdout)
            finally: f.close()

    def test_witness_recomputes_raw_hash_and_projection_without_retaining_raw(self):
        a = load()
        r = load("lil-tweak-independent-review")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            normalized = provider(time.time())
            raw_value = {"droplet": {"id": 597343619, "name": "galor-tweak-runner-01", "status": "active", "region": {"slug": "nyc1"},
                "image": normalized["droplet"]["image"], "size": {"slug": "s-4vcpu-8gb", "memory": 8192, "vcpus": 4, "disk": 160},
                "tags": ["role-tweak-runner"], "networks": {"secret-canary": "192.0.2.17"}}}
            raw = json.dumps(raw_value).encode()
            normalized["rawResponseSha256"] = a.sha(raw)
            path, witness = root / "provider.json", root / "witness.json"
            a.publish(path, normalized)
            result = subprocess.run([sys.executable, str(ROOT / "scripts/lil-tweak-independent-review.py"), "witness-provider", "--normalized", str(path), "--raw-response-stdin", "--witness", str(witness)], input=raw, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            value = a.read_json(witness)
            self.assertEqual(set(value), WITNESS_KEYS)
            self.assertEqual(value["rawResponseSha256"], a.sha(raw))
            self.assertNotIn(b"secret-canary", witness.read_bytes() + result.stdout + result.stderr)
            self.assertNotIn(b"192.0.2.17", witness.read_bytes() + result.stdout + result.stderr)
            self.assertEqual(len(value["reviewerNonce"]), 48)
            with self.assertRaises(Exception): r.provider_projection({"droplet": {**raw_value["droplet"], "id": 1}})
            rejected = root / "rejected.json"
            for changed in (raw + b" ", json.dumps({"droplet": {**raw_value["droplet"], "name": "wrong"}}).encode()):
                with self.assertRaises(Exception): r.witness_provider(path, changed, rejected)
                self.assertFalse(rejected.exists())

    def test_review_check_is_executable(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/lil-tweak-independent-review.py"), "--check"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
