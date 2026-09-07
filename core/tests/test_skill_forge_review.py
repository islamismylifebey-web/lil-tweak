# ruff: noqa: E402
"""Adversarial review regressions, written before the corresponding fixes."""
from dataclasses import replace
import json
from pathlib import Path
import signal
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lil_tweak.skill_forge.package import ForgeError, compile_draft, text, verify_package, sha
from test_skill_forge import draft


class ReviewTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(signal, "setitimer"), "POSIX scanner budget regression")
    def test_scanner_has_bounded_behavior_on_large_nonmatch(self):
        def expired(*args):
            raise AssertionError("scanner exceeded 2-second input budget")
        previous = signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, 2)
        try:
            text("x" * 131072, 131072)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)

    def test_package_fields_cannot_disagree_with_hashed_manifest(self):
        package = compile_draft(draft())
        for change in ({"requirements": ()}, {"origin_id": "fake"}, {"name": "fake"},
                       {"files": package.files + (package.files[0],)}):
            with self.subTest(change=list(change)), self.assertRaises(ForgeError):
                replace(package, **change)

    def test_external_trusted_digest_can_be_required_by_consumer(self):
        files = compile_draft(draft()).as_dict()
        with self.assertRaises(ForgeError):
            verify_package(files, expected_digest="0" * 64)

    def test_manifest_origin_and_requirements_are_validated(self):
        for change in ({"origin": {}}, {"requirements": []}, {"requirements": [True]}):
            files = compile_draft(draft()).as_dict()
            manifest = json.loads(files["manifest.json"])
            manifest.update(change)
            files["manifest.json"] = json.dumps(manifest).encode()
            with self.subTest(change=change), self.assertRaises(ForgeError):
                verify_package(files)

    def test_forged_frontmatter_cannot_add_permissions_or_invalid_yaml(self):
        for extra in ('allowed-tools: "Bash(*)"\n', 'description: true\n'):
            files = compile_draft(draft()).as_dict()
            files["SKILL.md"] = files["SKILL.md"].replace(b"metadata:\n", extra.encode() + b"metadata:\n")
            manifest = json.loads(files["manifest.json"])
            manifest["content_hashes"]["SKILL.md"] = sha(files["SKILL.md"])
            files["manifest.json"] = json.dumps(manifest).encode()
            with self.assertRaises(ForgeError):
                verify_package(files)

    def test_resource_file_cannot_also_be_a_directory(self):
        data = draft()
        data["resources"] = {"scripts/a": "x", "scripts/a/b.py": "y"}
        with self.assertRaises(ForgeError):
            compile_draft(data)

    def test_instruction_packet_contains_its_public_examples(self):
        package = compile_draft(draft())
        skill = dict(package.instruction_files())["SKILL.md"].decode()
        self.assertIn('example-a', skill)
        self.assertIn('example-b', skill)


if __name__ == "__main__":
    unittest.main()
