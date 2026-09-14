from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts" / "lil-tweak-private-release.py"

REPOSITORY = "islamismylifebey-web/lil-tweak"
SOURCE_COMMIT = "174824ee6110dc0c41578a4ff35165e8c3792ec4"
CORE_DIGEST = "sha256:" + "a" * 64
RUNNER_DIGEST = "sha256:" + "b" * 64
CORE_IMAGE = f"ghcr.io/islamismylifebey-web/lil-tweak-core@{CORE_DIGEST}"
RUNNER_IMAGE = f"ghcr.io/islamismylifebey-web/lil-tweak-runner@{RUNNER_DIGEST}"

PYTHON_BASE = (
    "docker.io/library/python@sha256:"
    "9c47360a2a0355e2da18516d0b1c2126ec22c195d2185e97347c9d98398c5bef"
)
RUNNER_BASE = (
    "docker.io/library/node@sha256:"
    "4d676821dff059fd00d277ee4261ef34ea712317fed0737c03941481b5760c96"
)
POSTGRES_PARENT_IMAGE = (
    "docker.io/library/postgres@sha256:"
    "7bade6d532592ca8ce7ee32def7399dad2607c4ea5583839fc4352a095a11ea6"
)
POSTGRES_IMAGE = (
    "ghcr.io/islamismylifebey-web/lil-tweak-postgres@sha256:"
    "7bade6d532592ca8ce7ee32def7399dad2607c4ea5583839fc4352a095a11ea6"
)
SYFT_IMAGE = (
    "ghcr.io/anchore/syft@sha256:"
    "600896ff278677fb13b16dc35999452f4e79636fc098c9fee6ce3cffef9858e2"
)
GRYPE_IMAGE = (
    "ghcr.io/anchore/grype@sha256:"
    "461c87fefcd20d133f4d99db4623608637eecb439045f9fc8d6eebbb4149e766"
)


class PrivateReleaseHelperTests(unittest.TestCase):
    def run_helper(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(HELPER), *arguments],
            text=True,
            capture_output=True,
            check=False,
        )

    def write_json(self, path: Path, value: object) -> None:
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_context_accepts_only_manual_main_run_at_the_exact_source_commit(self) -> None:
        valid = [
            "validate-context",
            "--event-name",
            "workflow_dispatch",
            "--repository",
            REPOSITORY,
            "--ref",
            "refs/heads/main",
            "--source-commit",
            SOURCE_COMMIT,
            "--github-sha",
            SOURCE_COMMIT,
        ]
        result = self.run_helper(*valid)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, SOURCE_COMMIT + "\n")

        mutations = {
            "automatic event": ("--event-name", "push"),
            "non-main ref": ("--ref", "refs/heads/release"),
            "different repository": ("--repository", "someone/lil-tweak"),
            "uppercase source": ("--source-commit", SOURCE_COMMIT.upper()),
            "different event sha": ("--github-sha", "f" * 40),
        }
        for label, (argument, value) in mutations.items():
            mutated = list(valid)
            mutated[mutated.index(argument) + 1] = value
            with self.subTest(label=label):
                rejected = self.run_helper(*mutated)
                self.assertEqual(rejected.returncode, 2)
                self.assertEqual(rejected.stderr, "release_context_invalid\n")

    def test_package_metadata_requires_private_container_linked_to_exact_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            metadata = Path(temporary) / "package.json"
            valid = {
                "name": "lil-tweak-core",
                "package_type": "container",
                "visibility": "private",
                "repository": {"full_name": REPOSITORY},
            }
            self.write_json(metadata, valid)
            result = self.run_helper(
                "package-metadata",
                "--package",
                "lil-tweak-core",
                "--metadata",
                str(metadata),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "package_metadata_valid\n")

            mutations = {
                "public": {**valid, "visibility": "public"},
                "wrong repository": {
                    **valid,
                    "repository": {"full_name": "islamismylifebey-web/other"},
                },
                "unlinked": {**valid, "repository": None},
                "wrong package": {**valid, "name": "lil-tweak-runner"},
                "wrong type": {**valid, "package_type": "npm"},
            }
            for label, payload in mutations.items():
                with self.subTest(label=label):
                    self.write_json(metadata, payload)
                    rejected = self.run_helper(
                        "package-metadata",
                        "--package",
                        "lil-tweak-core",
                        "--metadata",
                        str(metadata),
                    )
                    self.assertEqual(rejected.returncode, 2)
                    self.assertEqual(rejected.stderr, "package_metadata_invalid\n")

    def test_package_inventory_validates_every_existing_release_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inventory = Path(temporary) / "packages.json"
            core = {
                "name": "lil-tweak-core",
                "package_type": "container",
                "visibility": "private",
                "repository": {"full_name": REPOSITORY},
            }
            unrelated = {
                "name": "unrelated-package",
                "package_type": "container",
                "visibility": "public",
                "repository": None,
            }
            self.write_json(inventory, [core, unrelated])
            result = self.run_helper(
                "package-inventory",
                "--metadata",
                str(inventory),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "package_inventory_valid\n")

            for label, payload in {
                "public existing release package": [{**core, "visibility": "public"}],
                "unlinked existing release package": [{**core, "repository": None}],
                "duplicate package": [core, core],
                "non-list response": {"message": "not a package inventory"},
            }.items():
                with self.subTest(label=label):
                    self.write_json(inventory, payload)
                    rejected = self.run_helper(
                        "package-inventory",
                        "--metadata",
                        str(inventory),
                    )
                    self.assertEqual(rejected.returncode, 2)
                    self.assertEqual(rejected.stderr, "package_inventory_invalid\n")

    def test_image_reference_uses_registry_digest_for_a_single_linux_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            metadata = root / "metadata.json"
            manifest_bytes = json.dumps(
                {
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "config": {
                        "mediaType": "application/vnd.oci.image.config.v1+json",
                        "digest": "sha256:" + "c" * 64,
                        "size": 2,
                    },
                    "layers": [],
                },
                separators=(",", ":"),
            ).encode("ascii")
            manifest.write_bytes(manifest_bytes)
            digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
            self.write_json(metadata, {"containerimage.digest": digest})

            result = self.run_helper(
                "image-reference",
                "--package",
                "lil-tweak-core",
                "--metadata",
                str(metadata),
                "--manifest",
                str(manifest),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout,
                f"ghcr.io/islamismylifebey-web/lil-tweak-core@{digest}\n",
            )

            index = {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [],
            }
            manifest_bytes = json.dumps(index, separators=(",", ":")).encode("ascii")
            manifest.write_bytes(manifest_bytes)
            self.write_json(
                metadata,
                {"containerimage.digest": "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()},
            )
            rejected = self.run_helper(
                "image-reference",
                "--package",
                "lil-tweak-core",
                "--metadata",
                str(metadata),
                "--manifest",
                str(manifest),
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(rejected.stderr, "published_image_invalid\n")

    def test_postgres_mirror_preserves_the_official_child_manifest_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            manifest_bytes = json.dumps(
                {
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                    "config": {
                        "mediaType": "application/vnd.docker.container.image.v1+json",
                        "digest": "sha256:" + "d" * 64,
                        "size": 3,
                    },
                    "layers": [],
                },
                separators=(",", ":"),
            ).encode("ascii")
            digest = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
            manifest.write_bytes(manifest_bytes + b"\n")
            result = self.run_helper(
                "image-reference",
                "--package",
                "lil-tweak-postgres",
                "--manifest",
                str(manifest),
                "--expected-digest",
                digest,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout,
                f"ghcr.io/islamismylifebey-web/lil-tweak-postgres@{digest}\n",
            )

            rejected = self.run_helper(
                "image-reference",
                "--package",
                "lil-tweak-postgres",
                "--manifest",
                str(manifest),
                "--expected-digest",
                "sha256:" + "e" * 64,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(rejected.stderr, "published_image_invalid\n")

    def test_pull_evidence_requires_exact_digest_and_linux_amd64(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inspect_path = Path(temporary) / "inspect.json"
            valid = [
                {
                    "RepoDigests": [CORE_IMAGE],
                    "Architecture": "amd64",
                    "Os": "linux",
                }
            ]
            self.write_json(inspect_path, valid)
            result = self.run_helper(
                "pull-evidence",
                "--reference",
                CORE_IMAGE,
                "--inspect",
                str(inspect_path),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "pull_evidence_valid\n")

            for label, payload in {
                "wrong digest": [{**valid[0], "RepoDigests": [RUNNER_IMAGE]}],
                "wrong architecture": [{**valid[0], "Architecture": "arm64"}],
                "multiple results": [valid[0], valid[0]],
            }.items():
                with self.subTest(label=label):
                    self.write_json(inspect_path, payload)
                    rejected = self.run_helper(
                        "pull-evidence",
                        "--reference",
                        CORE_IMAGE,
                        "--inspect",
                        str(inspect_path),
                    )
                    self.assertEqual(rejected.returncode, 2)
                    self.assertEqual(rejected.stderr, "pull_evidence_invalid\n")

    def test_anonymous_check_accepts_only_an_authentication_denial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            error_path = Path(temporary) / "anonymous.err"
            error_path.write_text("denied: requested access to the resource is denied\n")
            result = self.run_helper(
                "anonymous-denial",
                "--exit-code",
                "1",
                "--stderr",
                str(error_path),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "anonymous_pull_denied\n")

            for label, code, message in (
                ("anonymous success", "0", ""),
                ("network failure", "1", "dial tcp: temporary failure"),
                ("empty error", "1", ""),
            ):
                with self.subTest(label=label):
                    error_path.write_text(message)
                    rejected = self.run_helper(
                        "anonymous-denial",
                        "--exit-code",
                        code,
                        "--stderr",
                        str(error_path),
                    )
                    self.assertEqual(rejected.returncode, 2)
                    self.assertEqual(rejected.stderr, "anonymous_pull_check_invalid\n")

    def test_receipts_bind_frozen_bases_tools_final_images_and_four_scans(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "evidence"
            evidence.mkdir()
            scan_bytes = {
                "core.sbom.json": b'{"core":"sbom"}\n',
                "runner.sbom.json": b'{"runner":"sbom"}\n',
                "core.grype.json": b'{"core":"grype"}\n',
                "runner.grype.json": b'{"runner":"grype"}\n',
            }
            for name, contents in scan_bytes.items():
                (evidence / name).write_bytes(contents)

            result = self.run_helper(
                "write-receipts",
                "--directory",
                str(evidence),
                "--source-commit",
                SOURCE_COMMIT,
                "--core-image",
                CORE_IMAGE,
                "--runner-image",
                RUNNER_IMAGE,
                "--postgres-image",
                POSTGRES_IMAGE,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "release_receipts_written\n")
            self.assertEqual(
                (evidence / "base-image-receipt.txt").read_text(encoding="ascii"),
                f"{PYTHON_BASE} {PYTHON_BASE.rsplit('@', 1)[1]}\n"
                f"{RUNNER_BASE} {RUNNER_BASE.rsplit('@', 1)[1]}\n"
                f"{POSTGRES_IMAGE} {POSTGRES_IMAGE.rsplit('@', 1)[1]}\n",
            )
            expected_hash_lines = "".join(
                f"{hashlib.sha256(scan_bytes[name]).hexdigest()}  {name}\n"
                for name in (
                    "core.sbom.json",
                    "runner.sbom.json",
                    "core.grype.json",
                    "runner.grype.json",
                )
            )
            self.assertEqual(
                (evidence / "image-scan-hashes.txt").read_text(encoding="ascii"),
                expected_hash_lines,
            )
            release_inputs = json.loads(
                (evidence / "release-image-inputs.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                release_inputs,
                {
                    "schema": "lil-tweak-release-image-inputs-v1",
                    "source_commit": SOURCE_COMMIT,
                    "images": {
                        "core": CORE_IMAGE,
                        "runner": RUNNER_IMAGE,
                        "postgres": POSTGRES_IMAGE,
                        "python_base": PYTHON_BASE,
                        "runner_base": RUNNER_BASE,
                    },
                    "parent_images": {"postgres": POSTGRES_PARENT_IMAGE},
                    "tools": {"syft": SYFT_IMAGE, "grype": GRYPE_IMAGE},
                },
            )
            if os.name == "posix":
                for name in (
                    "base-image-receipt.txt",
                    "image-scan-hashes.txt",
                    "release-image-inputs.json",
                ):
                    mode = stat.S_IMODE((evidence / name).stat().st_mode)
                    self.assertEqual(mode, 0o600)

            rejected = self.run_helper(
                "write-receipts",
                "--directory",
                str(evidence),
                "--source-commit",
                SOURCE_COMMIT,
                "--core-image",
                CORE_IMAGE,
                "--runner-image",
                RUNNER_IMAGE,
                "--postgres-image",
                POSTGRES_IMAGE,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(rejected.stderr, "release_receipts_invalid\n")


if __name__ == "__main__":
    unittest.main()

