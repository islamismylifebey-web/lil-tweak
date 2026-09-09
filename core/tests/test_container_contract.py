import unittest
from pathlib import Path


class CoreContainerContractTests(unittest.TestCase):
    def test_core_image_installs_trusted_git_intake_binary(self):
        root = Path(__file__).resolve().parents[2]
        containerfile = (root / "deploy" / "Containerfile.core").read_text()
        install = containerfile.split("apk add --no-cache", 2)[2].splitlines()[0]
        self.assertIn("git", install.split())

    def test_core_rebuilds_digest_pinned_podman_source_with_fixed_modules(self):
        root = Path(__file__).resolve().parents[2]
        containerfile = (root / "deploy" / "Containerfile.core").read_text()
        builder = containerfile.split("FROM ${PYTHON_BASE_IMAGE} AS podman-builder", 1)[1]
        self.assertTrue(builder.lstrip().startswith("USER root"))
        self.assertIn("PODMAN_SOURCE_SHA256", containerfile)
        self.assertIn("sha256sum -c -", containerfile)
        self.assertIn("google.golang.org/grpc@v1.83.2", containerfile)
        self.assertIn("golang.org/x/crypto@v0.56.0", containerfile)
        self.assertIn("COPY --from=podman-builder /podman /usr/local/bin/podman", containerfile)

    def test_runner_image_uses_current_wolfi_toolchain_without_git(self):
        root = Path(__file__).resolve().parents[2]
        containerfile = (root / "deploy" / "Containerfile.runner").read_text()
        self.assertIn("apk add --no-cache", containerfile)
        for package in (
            "nodejs-22",
            "python-3.14",
            "go-1.26",
            "rust-1.97",
            "openjdk-26-default-jdk",
        ):
            self.assertIn(package, containerfile)
        self.assertIn("! command -v git", containerfile)


if __name__ == "__main__":
    unittest.main()
