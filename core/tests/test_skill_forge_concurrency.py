# ruff: noqa: E402
"""Real SQLite concurrency: stale evaluations and one-time grants are serialized."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lil_tweak.skill_forge import Adapter, ForgeError, Library, Observation
from test_skill_forge import cases, draft


class ConcurrencyTests(unittest.TestCase):
    def test_concurrent_evaluations_cannot_share_a_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "forge.sqlite3")
            with sqlite3.connect(path) as db:
                digest = Library(db).add("owner", draft())
            reads, runs = threading.Barrier(2), threading.Barrier(2)

            def worker(agent):
                class RacingLibrary(Library):
                    first_read = True
                    def _row(self, owner, digest):
                        result = super()._row(owner, digest)
                        if self.first_read:
                            self.first_read = False
                            reads.wait(timeout=5)
                        return result
                first_run = True
                async def run(request):
                    nonlocal first_run
                    if first_run:
                        first_run = False
                        runs.wait(timeout=5)
                    status, output = {"held-out-a": ("ok", "present"),
                                      "held-out-invalid": ("blocked", "invalid"),
                                      "held-out-without-tool": ("blocked", "tool_missing")}[request.task]
                    return Observation(request.digest, request.nonce, request.nonce, status, output)
                with sqlite3.connect(path) as db:
                    lib = RacingLibrary(db, source_verifier=lambda owner, origin: True)
                    adapter = Adapter(agent, ("read_inventory",),
                                      "fresh-session/package-only/no-authority", run)
                    try:
                        report = asyncio.run(lib.evaluate("owner", digest, cases(), adapter, "transfer"))
                        return "passed" if report.passed else "failed"
                    except ForgeError as exc:
                        return exc.code
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(worker, agent) for agent in ("peer-a", "peer-b")]
                results = [future.result(timeout=12) for future in futures]
            self.assertEqual(sorted(results), ["passed", "stale_evaluation"])


if __name__ == "__main__":
    unittest.main()
