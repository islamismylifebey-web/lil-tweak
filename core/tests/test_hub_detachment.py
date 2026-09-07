import unittest
from pathlib import Path


CORE_ROOT = Path(__file__).resolve().parents[1]


class HubDetachmentTests(unittest.TestCase):
    def test_retired_hub_adapter_and_runtime_plumbing_are_absent(self):
        self.assertFalse((CORE_ROOT / "lil_tweak" / "galor.py").exists())

        retired_names = {
            "lil_tweak/config.py": ("galor_readonly_url",),
            "main.py": ("GalorClient", "lil_tweak.galor", "galor=galor"),
            "lil_tweak/orchestrator.py": (
                "galor_context",
                "galor_unavailable",
                "self.galor",
                "galor: Any",
            ),
            "lil_tweak/openai_agent.py": ("galor_context",),
            "lil_tweak/store.py": ('"galor_unavailable"',),
        }
        for relative_path, names in retired_names.items():
            source = (CORE_ROOT / relative_path).read_text(encoding="utf-8")
            for retired_name in names:
                with self.subTest(path=relative_path, name=retired_name):
                    self.assertNotIn(retired_name, source)

    def test_direct_podman_runner_path_remains_owned_by_core(self):
        source = (CORE_ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("PodmanSandbox(", source)
        self.assertIn("image=config.runner_image", source)


if __name__ == "__main__":
    unittest.main()
