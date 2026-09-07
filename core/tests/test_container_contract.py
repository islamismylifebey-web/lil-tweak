import unittest
from pathlib import Path


class CoreContainerContractTests(unittest.TestCase):
    def test_core_image_installs_trusted_git_intake_binary(self):
        root = Path(__file__).resolve().parents[2]
        containerfile = (root / "deploy" / "Containerfile.core").read_text()
        install = containerfile.split("apt-get install", 1)[1].split("rm -rf", 1)[0]
        self.assertIn("git", install.split())


if __name__ == "__main__":
    unittest.main()
