# ruff: noqa: E402
"""Authoring uses configured callbacks, not extra model or execution authority."""
import asyncio
import io
import json
from pathlib import Path
import sqlite3
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lil_tweak.skill_forge.package import ForgeError
from lil_tweak.skill_forge.library import Library
from test_skill_forge import draft

try:
    from lil_tweak.skill_forge.authoring import propose, AUTHOR_SCHEMA
    from lil_tweak.skill_forge.__main__ import main
    IMPLEMENTED = True
except ImportError:
    IMPLEMENTED = False


class AuthoringBootstrap(unittest.TestCase):
    def test_authoring_and_cli_exist(self):
        self.assertTrue(IMPLEMENTED, "Authoring adapter and CLI are missing")


@unittest.skipUnless(IMPLEMENTED, "Authoring and CLI not present yet")
class AuthoringTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.library = Library(self.db, source_verifier=lambda owner, origin: owner == "owner-a")
        self.calls = []
        self.origin = draft()["origin"]
        self.response = draft()
        del self.response["origin"]

    def tearDown(self):
        self.db.close()

    async def author(self, request):
        self.calls.append(request)
        return json.dumps(self.response)

    async def proposal(self, **changes):
        args = dict(name="icon-inspector", version="1.0.0", origin=self.origin,
                    solution_summary="Checked the supplied inventory and found missing references.",
                    author=self.author)
        args.update(changes)
        return await propose(self.library, "owner-a", **args)

    async def test_author_creates_real_unverified_library_candidate(self):
        digest = await self.proposal()
        self.assertEqual(self.library.status("owner-a", digest)["state"], "COMPILED")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0].max_output_bytes, 131072)
        self.assertNotIn("origin", AUTHOR_SCHEMA["properties"])
        self.assertNotIn("approved", self.calls[0].schema_json)
        with self.assertRaises(ForgeError):
            self.library.prepare_release("owner-a", digest)

    async def test_model_cannot_change_identity_or_add_approval_fields(self):
        for extra in ({"origin": self.origin}, {"approved": True},
                      {"name": "different"}, {"version": "9.0.0"}):
            self.response = draft()
            del self.response["origin"]
            self.response.update(extra)
            with self.subTest(extra=extra), self.assertRaises(ForgeError):
                await self.proposal()

    async def test_private_summary_blocks_before_model_call(self):
        with self.assertRaises(ForgeError):
            await self.proposal(solution_summary="Email customer@example.com with details.")
        self.assertEqual(self.calls, [])

    async def test_missing_author_and_unverified_source_stop_without_retry(self):
        with self.assertRaises(ForgeError):
            await self.proposal(author=None)
        self.library = Library(self.db)
        with self.assertRaises(ForgeError):
            await self.proposal()
        self.assertEqual(self.calls, [])

    async def test_author_budget_and_output_bounds(self):
        async def oversized(request):
            return "x" * 131073
        with self.assertRaises(ForgeError):
            await self.proposal(author=oversized)
        async def slow(request):
            self.calls.append(request)
            await asyncio.sleep(1)
            return "{}"
        with self.assertRaises(ForgeError):
            await self.proposal(author=slow, timeout_seconds=0.01)
        self.assertEqual(len(self.calls), 1)

    async def test_broken_json_is_rejected(self):
        async def malformed(request):
            return '{"name":"one","name":"two"}'
        with self.assertRaises(ForgeError):
            await self.proposal(author=malformed)


@unittest.skipUnless(IMPLEMENTED, "Authoring and CLI not present yet")
class CLITests(unittest.TestCase):
    def run_cli(self, command, value):
        output, error = io.StringIO(), io.StringIO()
        code = main([command], stdin=io.StringIO(value), stdout=output, stderr=error)
        return code, output.getvalue(), error.getvalue()

    def test_validate_outputs_truthful_compiled_status(self):
        code, output, error = self.run_cli("validate", json.dumps(draft()))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["state"], "COMPILED")
        self.assertEqual(error, "")

    def test_preview_contains_skill_and_explicit_unverified_notice(self):
        code, output, error = self.run_cli("preview", json.dumps(draft()))
        self.assertEqual(code, 0)
        self.assertTrue(output.startswith("---\n"))
        self.assertIn("UNVERIFIED", error)

    def test_bad_and_large_input_fail_safely(self):
        for content in ("not-json", "x" * (2 * 1024 * 1024 + 1)):
            code, output, error = self.run_cli("validate", content)
            self.assertEqual(code, 2)
            self.assertEqual(output, "")
            self.assertNotIn("Traceback", error)

    def test_schema_is_available_without_reading_input(self):
        code, output, error = self.run_cli("schema", "")
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(output)["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
