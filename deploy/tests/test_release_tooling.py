from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import tracemalloc
import unittest
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "lil-tweak-release.py"


def load_release_module():
    spec = importlib.util.spec_from_file_location("lil_tweak_release", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("release helper could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(*args: str, cwd: Path) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def decision_window(*, stale: bool = False) -> tuple[str, str]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    if stale:
        issued = now - timedelta(hours=2)
        expires = now - timedelta(hours=1)
    else:
        issued = now - timedelta(minutes=1)
        expires = now + timedelta(minutes=10)
    return (
        issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def write_host_go_receipt(
    path: Path,
    source_manifest: Path,
    archive: Path,
    images: dict[str, str],
    base_receipt: Path,
    scan_hashes: Path,
    *,
    stale: bool = False,
    overrides: dict[str, str] | None = None,
) -> None:
    source = json.loads(source_manifest.read_text())
    issued_at, expires_at = decision_window(stale=stale)
    values = {
        "schema": "lil-tweak-host-go-receipt-v2",
        "decision": "GO",
        "source_commit": source["source"]["commit"],
        "source_tree": source["source"]["tree"],
        "source_manifest_sha256": hashlib.sha256(source_manifest.read_bytes()).hexdigest(),
        "source_archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "core_image": images["core_image"],
        "runner_image": images["runner_image"],
        "postgres_image": images["postgres_image"],
        "python_base_image": images["python_base_image"],
        "runner_base_image": images["runner_base_image"],
        "base_image_receipt_sha256": hashlib.sha256(base_receipt.read_bytes()).hexdigest(),
        "image_scan_receipt_sha256": hashlib.sha256(scan_hashes.read_bytes()).hexdigest(),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": "a" * 32,
    }
    values.update(overrides or {})
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    path.chmod(0o600)


def write_owner_flow_receipt(
    path: Path,
    runtime_digest: str,
    state: dict[str, str],
    *,
    stale: bool = False,
    overrides: dict[str, str] | None = None,
) -> None:
    issued_at, expires_at = decision_window(stale=stale)
    values = {
        "schema": "lil-tweak-owner-flow-receipt-v3",
        "decision": "PASS",
        "runtime_manifest_sha256": runtime_digest,
        "source_commit": state["SOURCE_COMMIT"],
        "source_tree": state["SOURCE_TREE"],
        "sites_version_id": state["SITES_VERSION_ID"],
        "sites_version_number": state["SITES_VERSION_NUMBER"],
        "sites_deployment_id": state["SITES_DEPLOYMENT_ID"],
        "sites_archive_sha256": state["SITES_ARCHIVE_HASH"],
        "sites_deployed_at": state["SITES_DEPLOYED_AT"],
        "owner_flow_job_sha256": hashlib.sha256(Path(state["OWNER_FLOW_JOB"]).read_bytes()).hexdigest(),
        "production_url": state["PRODUCTION_URL"],
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": "b" * 32,
    }
    values.update(overrides or {})
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    path.chmod(0o600)


class ReleaseFixture:
    def __init__(self, root: Path) -> None:
        self.repo = root / "repo"
        self.repo.mkdir()
        run("git", "init", "-q", cwd=self.repo)
        run("git", "config", "user.name", "Lil Tweak Release Test", cwd=self.repo)
        run("git", "config", "user.email", "release-test@example.invalid", cwd=self.repo)
        (self.repo / "package.json").write_text('{"name":"fixture","version":"1.0.0"}\n')
        (self.repo / "package-lock.json").write_text(
            '{"name":"fixture","version":"1.0.0","lockfileVersion":3,"packages":{}}\n'
        )
        (self.repo / "README.md").write_text("base\n")
        (self.repo / "deleted.txt").write_text("remove me\n")
        migrations = self.repo / "core" / "migrations"
        migrations.mkdir(parents=True)
        (migrations / "0001_fixture.sql").write_text("SELECT 1;\n")
        icons = self.repo / "public" / "icons"
        icons.mkdir(parents=True)
        (icons / "icon.png").write_bytes(b"official-icon")
        (icons / "maskable.png").write_bytes(b"official-maskable")
        run("git", "add", ".", cwd=self.repo)
        run(
            "git",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "base",
            cwd=self.repo,
        )
        self.base = run("git", "rev-parse", "HEAD", cwd=self.repo)

        (self.repo / "README.md").write_text("release\n")
        (self.repo / "deleted.txt").unlink()
        (self.repo / "added.sh").write_text("#!/bin/sh\nexit 0\n")
        (self.repo / "added.sh").chmod(0o755)
        verification = self.repo / "docs" / "verification.md"
        verification.parent.mkdir()
        verification.write_text("verified\n")
        run("git", "add", "-A", cwd=self.repo)
        run(
            "git",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "release",
            cwd=self.repo,
        )
        self.commit = run("git", "rev-parse", "HEAD", cwd=self.repo)
        self.verification = verification

    def source_manifest(self, release, output: Path) -> str:
        return release.create_source_manifest(
            repo=self.repo,
            base=self.base,
            commit=self.commit,
            verification_receipt=self.verification,
            preserves=[Path("public/icons")],
            output=output,
        )

    def archive(self, output: Path) -> None:
        subprocess.run(
            [
                "git",
                "-c",
                "tar.umask=0022",
                "archive",
                "--format=tar.gz",
                f"--output={output}",
                self.commit,
            ],
            cwd=self.repo,
            check=True,
        )


class ReleaseToolingTests(unittest.TestCase):
    def test_release_target_gate_has_a_host_safe_offline_check(self) -> None:
        target = ROOT / "scripts" / "lil-tweak-digitalocean-target.py"
        result = subprocess.run(
            [sys.executable, str(target), "--check"],
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "DigitalOcean target check: ok\n")
        self.assertEqual(result.stderr, "")

    @classmethod
    def setUpClass(cls) -> None:
        cls.release = load_release_module()

    def _create_canonical_runtime_manifest(
        self, root: Path, fixture: ReleaseFixture
    ) -> tuple[Path, dict[str, object]]:
        source_manifest = root / "production-source.json"
        fixture.source_manifest(self.release, source_manifest)
        archive = root / "production-source.tar.gz"
        fixture.archive(archive)
        host_go = root / "production-host-go.txt"
        images = {
            "core_image": "registry.example/lil-tweak/core@sha256:" + "1" * 64,
            "runner_image": "registry.example/lil-tweak/runner@sha256:" + "2" * 64,
            "postgres_image": "registry.example/postgres@sha256:" + "3" * 64,
            "python_base_image": "registry.example/python@sha256:" + "4" * 64,
            "runner_base_image": "registry.example/node@sha256:" + "5" * 64,
        }
        base_receipt = root / "production-base-images.txt"
        base_receipt.write_text(
            "\n".join(
                f"{images[name]} sha256:{images[name].rsplit(':', 1)[1]}"
                for name in (
                    "python_base_image",
                    "runner_base_image",
                    "postgres_image",
                )
            )
            + "\n"
        )
        base_receipt.chmod(0o600)
        hashes = []
        for name in (
            "core.sbom.json",
            "runner.sbom.json",
            "core.grype.json",
            "runner.grype.json",
        ):
            artifact = root / f"production-{name}"
            artifact.write_text('{"ok":true}\n')
            canonical_name = root / name
            artifact.rename(canonical_name)
            hashes.append(
                f"{hashlib.sha256(canonical_name.read_bytes()).hexdigest()}  {canonical_name}"
            )
        scan_hashes = root / "production-image-scan-hashes.txt"
        scan_hashes.write_text("\n".join(hashes) + "\n")
        scan_hashes.chmod(0o600)
        write_host_go_receipt(
            host_go,
            source_manifest,
            archive,
            images,
            base_receipt,
            scan_hashes,
        )
        runtime = root / "runtime.json"
        self.release.create_runtime_manifest(
            source_manifest=source_manifest,
            source_archive=archive,
            host_go_receipt=host_go,
            base_image_receipt=base_receipt,
            image_scan_hashes=scan_hashes,
            output=runtime,
            **images,
        )
        return runtime, json.loads(runtime.read_text())

    def test_source_manifest_is_stable_and_enumerates_the_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ReleaseFixture(root)
            first = root / "first.json"
            second = root / "second.json"
            first_digest = fixture.source_manifest(self.release, first)
            second_digest = fixture.source_manifest(self.release, second)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertRegex(first_digest, r"^[0-9a-f]{64}$")
            self.assertEqual(first_digest, hashlib.sha256(first.read_bytes()).hexdigest())
            self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o444)
            manifest = json.loads(first.read_text())
            self.assertEqual(manifest["schema"], "lil-tweak-source-manifest-v1")
            self.assertEqual(manifest["official_base"]["commit"], fixture.base)
            self.assertEqual(manifest["source"]["commit"], fixture.commit)
            self.assertEqual(
                {(entry["status"], entry["path"]) for entry in manifest["changes"]},
                {("modify", "README.md"), ("add", "added.sh"), ("delete", "deleted.txt"), ("add", "docs/verification.md")},
            )
            files = {entry["path"]: entry for entry in manifest["files"]}
            self.assertEqual(files["added.sh"]["git_mode"], "100755")
            self.assertEqual(files["added.sh"]["extracted_mode"], "0755")
            self.assertEqual(manifest["packages"]["package_json"]["path"], "package.json")
            self.assertEqual(manifest["preserved"][0]["path"], "public/icons/icon.png")

    def test_source_manifest_rejects_dirty_links_and_case_collisions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ReleaseFixture(root)
            (fixture.repo / "README.md").write_text("dirty\n")
            with self.assertRaisesRegex(self.release.ReleaseError, "source_tree_dirty"):
                fixture.source_manifest(self.release, root / "dirty.json")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ReleaseFixture(root)
            tracked = fixture.repo / "README.md"
            tracked.unlink()
            os.symlink("package.json", tracked)
            with self.assertRaisesRegex(self.release.ReleaseError, "source_tree_dirty|source_path_unsafe"):
                fixture.source_manifest(self.release, root / "linked.json")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ReleaseFixture(root)
            (fixture.repo / "Readme.MD").write_text("collision\n")
            run("git", "add", "Readme.MD", cwd=fixture.repo)
            run("git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "collision", cwd=fixture.repo)
            fixture.commit = run("git", "rev-parse", "HEAD", cwd=fixture.repo)
            with self.assertRaisesRegex(self.release.ReleaseError, "source_path_collision"):
                fixture.source_manifest(self.release, root / "collision.json")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ReleaseFixture(root)
            (fixture.repo / "public/icons/maskable.png").unlink()
            run("git", "add", "-A", cwd=fixture.repo)
            run("git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "delete preserved icon", cwd=fixture.repo)
            fixture.commit = run("git", "rev-parse", "HEAD", cwd=fixture.repo)
            with self.assertRaisesRegex(self.release.ReleaseError, "preserved_path_changed"):
                fixture.source_manifest(self.release, root / "partial-preserve.json")

    def test_verify_extract_creates_only_a_new_exact_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ReleaseFixture(root)
            manifest = root / "source.json"
            fixture.source_manifest(self.release, manifest)
            archive = root / "source.tar.gz"
            fixture.archive(archive)
            destination = root / "extract"

            observed = self.release.verify_extract(archive, manifest, destination)

            self.assertEqual(observed, hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
            self.assertEqual((destination / "README.md").read_text(), "release\n")
            self.assertEqual(stat.S_IMODE((destination / "added.sh").stat().st_mode), 0o755)
            self.assertFalse((destination / ".git").exists())
            with self.assertRaisesRegex(self.release.ReleaseError, "extract_destination_exists"):
                self.release.verify_extract(archive, manifest, destination)

            manifest.chmod(0o644)
            unsafe_destination = root / "unsafe-mode-extract"
            with self.assertRaisesRegex(self.release.ReleaseError, "input_file_mode"):
                self.release.verify_extract(archive, manifest, unsafe_destination)
            self.assertFalse(unsafe_destination.exists())

    def test_verify_extract_rejects_a_link_archive_without_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ReleaseFixture(root)
            manifest = root / "source.json"
            fixture.source_manifest(self.release, manifest)
            archive = root / "malicious.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                info = tarfile.TarInfo("README.md")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                output.addfile(info)
            destination = root / "extract"
            with self.assertRaisesRegex(self.release.ReleaseError, "archive_entry_unsafe|archive_inventory_mismatch"):
                self.release.verify_extract(archive, manifest, destination)
            self.assertFalse(destination.exists())

    def test_verify_extract_rejects_every_unsafe_or_mismatched_archive_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ReleaseFixture(root)
            manifest = root / "source.json"
            fixture.source_manifest(self.release, manifest)
            valid = root / "valid.tar.gz"
            fixture.archive(valid)
            with tarfile.open(valid, "r:gz") as source:
                originals = []
                for member in source.getmembers():
                    extracted = source.extractfile(member) if member.isfile() else None
                    originals.append(
                        (copy.copy(member), extracted.read() if extracted is not None else None)
                    )

            def write_mutation(output: Path, kind: str) -> None:
                entries = [(copy.copy(member), data) for member, data in originals]
                readme_index = next(
                    index for index, (member, _data) in enumerate(entries)
                    if member.name == "README.md"
                )
                member, data = entries[readme_index]
                if kind == "hardlink":
                    member.type = tarfile.LNKTYPE
                    member.linkname = "package.json"
                    data = None
                elif kind == "absolute":
                    member.name = "/escape"
                elif kind == "dotdot":
                    member.name = "a/../escape"
                elif kind == "character":
                    member.type = tarfile.CHRTYPE
                    data = None
                elif kind == "fifo":
                    member.type = tarfile.FIFOTYPE
                    data = None
                elif kind == "mode":
                    member.mode = 0o666
                elif kind == "content":
                    data = b"forged!\n"
                    self.assertEqual(len(data), member.size)
                entries[readme_index] = (member, data)
                if kind == "duplicate":
                    entries.append((copy.copy(member), data))
                elif kind == "case-duplicate":
                    duplicate = copy.copy(member)
                    duplicate.name = "readme.md"
                    entries.append((duplicate, data))
                with tarfile.open(
                    output,
                    "w:gz",
                    format=tarfile.PAX_FORMAT,
                    pax_headers={"comment": fixture.commit},
                ) as bundle:
                    for item, payload in entries:
                        bundle.addfile(item, BytesIO(payload) if payload is not None else None)

            for kind in (
                "hardlink", "absolute", "dotdot", "character", "fifo",
                "duplicate", "case-duplicate", "mode", "content",
            ):
                with self.subTest(kind=kind):
                    archive = root / f"{kind}.tar.gz"
                    destination = root / f"extract-{kind}"
                    write_mutation(archive, kind)
                    with self.assertRaises(self.release.ReleaseError):
                        self.release.verify_extract(archive, manifest, destination)
                    self.assertFalse(destination.exists())

    def test_verify_extract_streams_large_content_with_bounded_memory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ReleaseFixture(root)
            large = fixture.repo / "large.bin"
            large.write_bytes(b"\0" * (12 * 1024 * 1024))
            run("git", "add", "large.bin", cwd=fixture.repo)
            run(
                "git", "-c", "commit.gpgsign=false", "commit", "-q",
                "-m", "large fixture", cwd=fixture.repo,
            )
            fixture.commit = run("git", "rev-parse", "HEAD", cwd=fixture.repo)
            manifest = root / "source.json"
            fixture.source_manifest(self.release, manifest)
            archive = root / "source.tar.gz"
            fixture.archive(archive)
            destination = root / "extract"

            tracemalloc.start()
            try:
                self.release.verify_extract(archive, manifest, destination)
                _current, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()

            self.assertEqual((destination / "large.bin").stat().st_size, 12 * 1024 * 1024)
            self.assertEqual(
                hashlib.sha256((destination / "large.bin").read_bytes()).hexdigest(),
                hashlib.sha256(b"\0" * (12 * 1024 * 1024)).hexdigest(),
            )
            self.assertLess(peak, 8 * 1024 * 1024)

    def test_verify_extract_caps_total_expanded_archive_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ReleaseFixture(root)
            manifest = root / "source.json"
            fixture.source_manifest(self.release, manifest)
            archive = root / "source.tar.gz"
            fixture.archive(archive)
            destination = root / "extract"

            with patch.object(self.release, "MAX_ARCHIVE_EXPANDED_BYTES", 1024):
                with self.assertRaisesRegex(
                    self.release.ReleaseError,
                    "archive_expanded_size",
                ):
                    self.release.verify_extract(archive, manifest, destination)
            self.assertFalse(destination.exists())

    def test_manifest_inventory_is_strictly_bounded_before_archive_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ReleaseFixture(root)
            source_manifest = root / "source.json"
            fixture.source_manifest(self.release, source_manifest)
            archive = root / "source.tar.gz"
            fixture.archive(archive)
            original = json.loads(source_manifest.read_text())
            mutations = []

            duplicate = json.loads(json.dumps(original))
            duplicate["files"].append(dict(duplicate["files"][0]))
            mutations.append(duplicate)

            oversized = json.loads(json.dumps(original))
            oversized["files"][0]["size"] = self.release.MAX_SOURCE_FILE_BYTES + 1
            mutations.append(oversized)

            boolean_size = json.loads(json.dumps(original))
            boolean_size["files"][0]["size"] = True
            mutations.append(boolean_size)

            bad_mode = json.loads(json.dumps(original))
            bad_mode["files"][0]["archive_mode"] = "0777"
            mutations.append(bad_mode)

            missing_key = json.loads(json.dumps(original))
            del missing_key["files"][0]["git_blob"]
            mutations.append(missing_key)

            extra_key = json.loads(json.dumps(original))
            extra_key["files"][0]["unexpected"] = "value"
            mutations.append(extra_key)

            negative_size = json.loads(json.dumps(original))
            negative_size["files"][0]["size"] = -1
            mutations.append(negative_size)

            excessive_total = json.loads(json.dumps(original))
            excessive_total["files"][0]["size"] = self.release.MAX_SOURCE_TOTAL_BYTES // 2 + 1
            excessive_total["files"][1]["size"] = self.release.MAX_SOURCE_TOTAL_BYTES // 2 + 1
            mutations.append(excessive_total)

            bad_blob = json.loads(json.dumps(original))
            bad_blob["files"][0]["git_blob"] = "g" * 40
            mutations.append(bad_blob)

            bad_digest = json.loads(json.dumps(original))
            bad_digest["files"][0]["sha256"] = "g" * 64
            mutations.append(bad_digest)

            overlap = json.loads(json.dumps(original))
            overlap["files"][1]["path"] = overlap["files"][0]["path"] + "/child"
            mutations.append(overlap)

            for index, payload in enumerate(mutations):
                with self.subTest(index=index):
                    manifest = root / f"forged-{index}.json"
                    manifest.write_bytes(self.release.canonical_json_bytes(payload))
                    manifest.chmod(0o444)
                    destination = root / f"extract-{index}"
                    with self.assertRaisesRegex(
                        self.release.ReleaseError,
                        "manifest_inventory_invalid",
                    ):
                        self.release.verify_extract(archive, manifest, destination)
                    self.assertFalse(destination.exists())

    def test_manifest_parent_replacement_never_redirects_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trusted = root / "trusted"
            pinned = root / "pinned"
            attacker = root / "attacker"
            trusted.mkdir()
            attacker.mkdir()
            output = trusted / "manifest.json"

            class SwappingPayload(dict):
                swapped = False

                def items(self):
                    if not self.swapped:
                        self.swapped = True
                        trusted.rename(pinned)
                        os.symlink(attacker, trusted)
                    return super().items()

            with self.assertRaisesRegex(
                self.release.ReleaseError,
                "manifest_parent_unsafe|manifest_write_failed",
            ):
                self.release.write_new_manifest(
                    output,
                    SwappingPayload({"schema": "test"}),
                )
            self.assertFalse((attacker / "manifest.json").exists())
            self.assertFalse((pinned / "manifest.json").exists())

    def test_runtime_manifest_binds_source_images_scans_and_go_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ReleaseFixture(root)
            source_manifest = root / "source.json"
            fixture.source_manifest(self.release, source_manifest)
            archive = root / "source.tar.gz"
            fixture.archive(archive)
            host_go = root / "host-go-receipt.txt"
            images = {
                "core_image": "registry.example/lil-tweak/core@sha256:" + "1" * 64,
                "runner_image": "registry.example/lil-tweak/runner@sha256:" + "2" * 64,
                "postgres_image": "registry.example/postgres@sha256:" + "3" * 64,
                "python_base_image": "registry.example/python@sha256:" + "4" * 64,
                "runner_base_image": "registry.example/node@sha256:" + "5" * 64,
            }
            base_receipt = root / "base-image-receipt.txt"
            base_receipt.write_text(
                "\n".join(
                    f"{images[name]} sha256:{images[name].rsplit(':', 1)[1]}"
                    for name in ("python_base_image", "runner_base_image", "postgres_image")
                )
                + "\n"
            )
            base_receipt.chmod(0o600)
            artifacts = []
            for name in ("core.sbom.json", "runner.sbom.json", "core.grype.json", "runner.grype.json"):
                path = root / name
                path.write_text('{"ok":true}\n')
                artifacts.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path}")
            scan_hashes = root / "image-scan-hashes.txt"
            scan_hashes.write_text("\n".join(artifacts) + "\n")
            scan_hashes.chmod(0o600)
            write_host_go_receipt(
                host_go,
                source_manifest,
                archive,
                images,
                base_receipt,
                scan_hashes,
            )
            output = root / "runtime.json"

            digest = self.release.create_runtime_manifest(
                source_manifest=source_manifest,
                source_archive=archive,
                host_go_receipt=host_go,
                base_image_receipt=base_receipt,
                image_scan_hashes=scan_hashes,
                output=output,
                **images,
            )

            manifest = json.loads(output.read_text())
            self.assertEqual(digest, hashlib.sha256(output.read_bytes()).hexdigest())
            self.assertEqual(manifest["source"]["commit"], fixture.commit)
            self.assertEqual(manifest["images"]["core"]["reference"], images["core_image"])
            self.assertEqual(len(manifest["receipts"]["image_scans"]["artifacts"]), 4)

            actual_source_size = len(source_manifest.read_bytes())
            actual_archive_size = len(archive.read_bytes())

            original_stat = Path.stat

            def fake_stat(path, *args, **kwargs):
                if (
                    kwargs.get("follow_symlinks", True)
                    and (path == source_manifest or path == archive)
                ):
                    return SimpleNamespace(st_size=999_999_999)
                return original_stat(path, *args, **kwargs)

            with patch.object(Path, "stat", fake_stat):
                raced_output = root / "runtime-raced-size.json"
                self.release.create_runtime_manifest(
                    source_manifest=source_manifest,
                    source_archive=archive,
                    host_go_receipt=host_go,
                    base_image_receipt=base_receipt,
                    image_scan_hashes=scan_hashes,
                    output=raced_output,
                    **images,
                )
            raced = json.loads(raced_output.read_text())
            self.assertEqual(raced["source"]["manifest_size"], actual_source_size)
            self.assertEqual(raced["source"]["archive_size"], actual_archive_size)

            for label, options in (
                ("stale", {"stale": True}),
                (
                    "mismatched-image",
                    {"overrides": {"core_image": images["runner_image"]}},
                ),
            ):
                with self.subTest(host_receipt=label):
                    write_host_go_receipt(
                        host_go,
                        source_manifest,
                        archive,
                        images,
                        base_receipt,
                        scan_hashes,
                        **options,
                    )
                    with self.assertRaisesRegex(
                        self.release.ReleaseError, "host_go_receipt_rejected"
                    ):
                        self.release.create_runtime_manifest(
                            source_manifest=source_manifest,
                            source_archive=archive,
                            host_go_receipt=host_go,
                            base_image_receipt=base_receipt,
                            image_scan_hashes=scan_hashes,
                            output=root / f"runtime-{label}.json",
                            **images,
                        )

            host_go.write_text(
                "schema=lil-tweak-host-go-receipt-v1\n"
                "decision=GO\n"
            )
            with self.assertRaisesRegex(
                self.release.ReleaseError, "host_go_receipt_rejected"
            ):
                self.release.create_runtime_manifest(
                    source_manifest=source_manifest,
                    source_archive=archive,
                    host_go_receipt=host_go,
                    base_image_receipt=base_receipt,
                    image_scan_hashes=scan_hashes,
                    output=root / "runtime-generic-go.json",
                    **images,
                )
            write_host_go_receipt(
                host_go,
                source_manifest,
                archive,
                images,
                base_receipt,
                scan_hashes,
                overrides={"decision": "NO-GO"},
            )
            with self.assertRaisesRegex(self.release.ReleaseError, "host_go_receipt_rejected"):
                self.release.create_runtime_manifest(
                    source_manifest=source_manifest,
                    source_archive=archive,
                    host_go_receipt=host_go,
                    base_image_receipt=base_receipt,
                    image_scan_hashes=scan_hashes,
                    output=root / "runtime-no-go.json",
                    **images,
                )

            host_go.write_text("schema=lil-tweak-host-go-receipt-v2\ndecision=GO\n")
            with self.assertRaisesRegex(self.release.ReleaseError, "host_go_receipt_rejected"):
                self.release.create_runtime_manifest(
                    source_manifest=source_manifest,
                    source_archive=archive,
                    host_go_receipt=host_go,
                    base_image_receipt=base_receipt,
                    image_scan_hashes=scan_hashes,
                    output=root / "runtime-contradictory-go.json",
                    **images,
                )

            for label, lines in (
                (
                    "too-many-fields",
                    ["schema=lil-tweak-host-go-receipt-v1", "decision=GO"]
                    + [f"field{index}=ok" for index in range(self.release.MAX_RECEIPT_FIELDS)],
                ),
                (
                    "oversized-value",
                    [
                        "schema=lil-tweak-host-go-receipt-v1",
                        "decision=GO",
                        "value=" + "x" * self.release.MAX_RECEIPT_LINE_BYTES,
                    ],
                ),
                (
                    "embedded-equals",
                    ["schema=lil-tweak-host-go-receipt-v1", "decision=GO", "value=a=b"],
                ),
            ):
                with self.subTest(label=label):
                    host_go.write_text("\n".join(lines) + "\n")
                    with self.assertRaisesRegex(
                        self.release.ReleaseError,
                        "host_go_receipt_rejected",
                    ):
                        self.release.create_runtime_manifest(
                            source_manifest=source_manifest,
                            source_archive=archive,
                            host_go_receipt=host_go,
                            base_image_receipt=base_receipt,
                            image_scan_hashes=scan_hashes,
                            output=root / f"runtime-malformed-{label}.json",
                            **images,
                        )

    def test_image_references_are_lowercase_untagged_and_exactly_digest_pinned(self) -> None:
        digest = "a" * 64
        valid = "registry.example:5000/lil-tweak/core@sha256:" + digest
        self.assertEqual(self.release._image_descriptor(valid)["reference"], valid)
        for invalid in (
            "registry.example/lil-tweak/core:latest@sha256:" + digest,
            "registry.example/lil-tweak/core@@sha256:" + digest,
            "Registry.example/lil-tweak/core@sha256:" + digest,
            "registry.example/lil-tweak//core@sha256:" + digest,
            "registry.example/lil-tweak/core@sha256:" + digest.upper(),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(self.release.ReleaseError, "image_reference_invalid"):
                    self.release._image_descriptor(invalid)

    def test_decision_receipt_requires_a_secure_bounded_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "go.txt"
            issued_at, expires_at = decision_window()
            receipt.write_text(
                "schema=test-decision-v1\n"
                "decision=GO\n"
                f"issued_at={issued_at}\n"
                f"expires_at={expires_at}\n"
                f"nonce={'a' * 32}\n"
            )
            receipt.chmod(0o600)
            expected = self.release._decision_receipt(
                receipt,
                [("schema", "test-decision-v1"), ("decision", "GO")],
                "host_go_receipt_rejected",
            )
            self.assertEqual(expected["size"], len(receipt.read_bytes()))

            receipt.chmod(0o644)
            with self.assertRaisesRegex(self.release.ReleaseError, "input_file_mode"):
                self.release._decision_receipt(
                    receipt,
                    [("schema", "test-decision-v1"), ("decision", "GO")],
                    "host_go_receipt_rejected",
                )
            receipt.chmod(0o600)

            linked = root / "linked.txt"
            os.link(receipt, linked)
            with self.assertRaisesRegex(self.release.ReleaseError, "input_file_unsafe"):
                self.release._decision_receipt(
                    receipt,
                    [("schema", "test-decision-v1"), ("decision", "GO")],
                    "host_go_receipt_rejected",
                )
            linked.unlink()

            symlink = root / "symlink.txt"
            os.symlink(receipt.name, symlink)
            with self.assertRaisesRegex(self.release.ReleaseError, "input_file_unsafe"):
                self.release._decision_receipt(
                    symlink,
                    [("schema", "test-decision-v1"), ("decision", "GO")],
                    "host_go_receipt_rejected",
                )

            fifo = root / "receipt.fifo"
            os.mkfifo(fifo, 0o600)
            with self.assertRaisesRegex(self.release.ReleaseError, "input_file_unsafe"):
                self.release._decision_receipt(
                    fifo,
                    [("schema", "test-decision-v1"), ("decision", "GO")],
                    "host_go_receipt_rejected",
                )

            with patch.object(self.release.os, "geteuid", return_value=os.geteuid() + 1):
                with self.assertRaisesRegex(self.release.ReleaseError, "input_file_owner"):
                    self.release._decision_receipt(
                        receipt,
                        [("schema", "test-decision-v1"), ("decision", "GO")],
                        "host_go_receipt_rejected",
                    )

    def test_production_origins_are_exact_https_origins(self) -> None:
        self.assertEqual(
            self.release._https_origin("https://tweak.example.invalid:443/"),
            "https://tweak.example.invalid:443",
        )
        for invalid in (
            "https://tweak.example.invalid/path",
            "https://tweak.example.invalid:0",
            "https://tweak.example.invalid:65536",
            "https://tweak.example.invalid:99999",
            "https://tweak.example.invalid:",
            "https://tweak.example.invalid?",
            "https://tweak.example.invalid#",
            "https://tweak.example.invalid//",
            "https://TWEAK.example.invalid",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(self.release.ReleaseError, "origin_invalid"):
                    self.release._https_origin(invalid)

    def test_production_manifest_binds_runtime_state_and_owner_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ReleaseFixture(root)
            runtime, runtime_payload = self._create_canonical_runtime_manifest(root, fixture)
            runtime_digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
            state = root / "release-state.env"
            from deploy.tests.test_activation_finalizer import load
            activation = load()
            q = activation.q
            job = {"schema": "tueiq-owner-flow-job-v1", "checkedAt": decision_window()[0], "requestId": "00000000-0000-4000-8000-000000000000", "jobId": "job:" + "a" * 32,
                "ownerScope": q.OWNER_SCOPE, "jobRevision": 3, "mode": "architect", "state": "completed", "gitSource": q.submission("architect")["gitSource"],
                "sourceDigest": q.BASELINE_TREE_SHA256, "proposalDigest": "b" * 64, "approvalProposal": None, "approvalConsumed": False,
                "evidence": [{"id": "evidence:" + str(i) * 32, "category": q.CATEGORIES[name], "filename": name, "mediaType": media, "sizeBytes": 0,
                    "sha256": q.EMPTY_SHA256, "createdAt": decision_window()[0]} for i, (name, media) in enumerate(q.ARTIFACTS.items(), 1)],
                "baselineTreeSha256": q.BASELINE_TREE_SHA256, "finalTreeSha256": q.BASELINE_TREE_SHA256, "fileSha256": q.SOURCE_SHA256, "commandDigest": "c" * 64, "editJournalDigest": "d" * 64}
            job_path = root / "owner-job.json"
            activation.publish(job_path, job)
            values = {
                "RUNTIME_MANIFEST": str(runtime),
                "RUNTIME_MANIFEST_SHA256": runtime_digest,
                "SOURCE_COMMIT": runtime_payload["source"]["commit"],
                "SOURCE_TREE": runtime_payload["source"]["tree"],
                "D1_DATABASE_ID": "d1-database",
                "D1_SCHEMA_REVISION": "0002",
                "D1_BINDING_REVISION": "d1-binding-r1",
                "R2_ACCOUNT_ID": "r2-account",
                "R2_BUCKET_NAME": "lil-tweak-evidence",
                "R2_BINDING_REVISION": "r2-binding-r1",
                "LIL_TWEAK_TUNNEL_ID": "123e4567-e89b-42d3-a456-426614174000",
                "ACCESS_APPLICATION_ID": "access-app",
                "ACCESS_POLICY_ID": "access-policy",
                "ACCESS_POLICY_REVISION": "access-r1",
                "MANAGED_INGRESS_RULE_ID": "managed-rule",
                "MANAGED_INGRESS_REVISION": "managed-r1",
                "CORE_ORIGIN": "https://core.example.invalid",
                "SITES_SOURCE_COMMIT": runtime_payload["source"]["commit"],
                "SITES_VERSION_ID": "site-version",
                "SITES_VERSION_NUMBER": "2",
                "SITES_DEPLOYMENT_ID": "site-deployment",
                "SITES_ARCHIVE_HASH": "c" * 64,
                "SITES_ENVIRONMENT_REVISION": "env-r1",
                "SITES_ACCESS_REVISION": "access-r2",
                "SITES_ACCESS_MODE": "custom",
                "SITES_ALLOWED_OWNER_COUNT": "1",
                "SITES_ALLOWED_GROUP_COUNT": "0",
                "SITES_ALLOWED_VISITOR_COUNT": "0",
                "PRODUCTION_URL": "https://tweak.example.invalid",
                "PUBLIC_ORIGIN": "https://tweak.example.invalid",
                "PRIOR_SITES_VERSION_NUMBER": "1",
                "SITES_DEPLOYED_AT": (datetime.now(timezone.utc) - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "OWNER_FLOW_JOB": str(job_path),
            }
            state.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
            state.chmod(0o600)
            owner = root / "owner-flow-receipt.txt"
            write_owner_flow_receipt(owner, runtime_digest, values)
            output = root / "production.json"

            digest = self.release.create_production_manifest(runtime, state, owner, output)

            manifest = json.loads(output.read_text())
            self.assertEqual(digest, hashlib.sha256(output.read_bytes()).hexdigest())
            self.assertEqual(manifest["runtime"]["manifest_sha256"], runtime_digest)
            self.assertEqual(manifest["sites"]["access_mode"], "custom")
            self.assertEqual(manifest["sites"]["allowed_owner_count"], 1)

            for label, options in (
                ("stale", {"stale": True}),
                ("old-v2", {"overrides": {"schema": "lil-tweak-owner-flow-receipt-v2"}}),
                ("before-deployment", {"overrides": {"issued_at": (datetime.now(timezone.utc) - timedelta(minutes=3)).strftime("%Y-%m-%dT%H:%M:%SZ")}}),
                ("changed-job", {"overrides": {"owner_flow_job_sha256": "0" * 64}}),
                (
                    "mismatched-deployment",
                    {"overrides": {"sites_deployment_id": "other-deployment"}},
                ),
            ):
                with self.subTest(owner_receipt=label):
                    write_owner_flow_receipt(
                        owner, runtime_digest, values, **options
                    )
                    with self.assertRaisesRegex(
                        self.release.ReleaseError, "owner_flow_receipt_rejected"
                    ):
                        self.release.create_production_manifest(
                            runtime,
                            state,
                            owner,
                            root / f"owner-{label}.json",
                        )
            owner.write_text(
                "schema=lil-tweak-owner-flow-receipt-v1\n"
                "decision=PASS\n"
            )
            with self.assertRaisesRegex(
                self.release.ReleaseError, "owner_flow_receipt_rejected"
            ):
                self.release.create_production_manifest(
                    runtime,
                    state,
                    owner,
                    root / "generic-owner-flow.json",
                )
            write_owner_flow_receipt(owner, runtime_digest, values)

            incomplete_runtime = root / "runtime-source-only.json"
            incomplete_runtime.write_bytes(
                self.release.canonical_json_bytes(
                    {
                        "schema": "lil-tweak-runtime-manifest-v1",
                        "source": {
                            "commit": runtime_payload["source"]["commit"],
                            "tree": runtime_payload["source"]["tree"],
                        },
                    }
                )
            )
            incomplete_runtime.chmod(0o444)
            values["RUNTIME_MANIFEST"] = str(incomplete_runtime)
            values["RUNTIME_MANIFEST_SHA256"] = hashlib.sha256(
                incomplete_runtime.read_bytes()
            ).hexdigest()
            state.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
            with self.assertRaisesRegex(
                self.release.ReleaseError, "runtime_manifest_mismatch"
            ):
                self.release.create_production_manifest(
                    incomplete_runtime,
                    state,
                    owner,
                    root / "source-only-runtime.json",
                )

            mutations: dict[str, dict[str, object]] = {}
            missing_archive = copy.deepcopy(runtime_payload)
            del missing_archive["source"]["archive_sha256"]
            mutations["missing-source-archive-binding"] = missing_archive
            missing_image = copy.deepcopy(runtime_payload)
            del missing_image["images"]["runner_base"]
            mutations["missing-base-image"] = missing_image
            mismatched_image = copy.deepcopy(runtime_payload)
            mismatched_image["images"]["core"]["digest"] = "sha256:" + "f" * 64
            mutations["mismatched-image-digest"] = mismatched_image
            missing_go = copy.deepcopy(runtime_payload)
            del missing_go["receipts"]["host_go"]
            mutations["missing-go-receipt"] = missing_go
            invalid_base_receipt = copy.deepcopy(runtime_payload)
            invalid_base_receipt["receipts"]["base_images"]["size"] = True
            mutations["invalid-base-receipt"] = invalid_base_receipt
            missing_scan_artifact = copy.deepcopy(runtime_payload)
            missing_scan_artifact["receipts"]["image_scans"]["artifacts"].pop()
            mutations["missing-scan-artifact"] = missing_scan_artifact
            renamed_scan_artifact = copy.deepcopy(runtime_payload)
            renamed_scan_artifact["receipts"]["image_scans"]["artifacts"][0][
                "name"
            ] = "unbound.sbom.json"
            mutations["renamed-scan-artifact"] = renamed_scan_artifact
            extra_runtime_field = copy.deepcopy(runtime_payload)
            extra_runtime_field["unreviewed"] = {}
            mutations["extra-runtime-field"] = extra_runtime_field

            for label, mutated_payload in mutations.items():
                with self.subTest(runtime_shape=label):
                    mutated = root / f"runtime-{label}.json"
                    mutated.write_bytes(
                        self.release.canonical_json_bytes(mutated_payload)
                    )
                    mutated.chmod(0o444)
                    values["RUNTIME_MANIFEST"] = str(mutated)
                    values["RUNTIME_MANIFEST_SHA256"] = hashlib.sha256(
                        mutated.read_bytes()
                    ).hexdigest()
                    state.write_text(
                        "".join(f"{key}={value}\n" for key, value in values.items())
                    )
                    with self.assertRaisesRegex(
                        self.release.ReleaseError, "runtime_manifest_mismatch"
                    ):
                        self.release.create_production_manifest(
                            mutated,
                            state,
                            owner,
                            root / f"production-{label}.json",
                        )

            values["RUNTIME_MANIFEST"] = str(runtime)
            values["RUNTIME_MANIFEST_SHA256"] = runtime_digest
            values["SITES_ALLOWED_VISITOR_COUNT"] = "1"
            state.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
            with self.assertRaisesRegex(self.release.ReleaseError, "sites_access_rejected"):
                self.release.create_production_manifest(runtime, state, owner, root / "bad.json")

            for noncanonical in ("+0", "00", "0_0"):
                with self.subTest(noncanonical=noncanonical):
                    values["SITES_ALLOWED_VISITOR_COUNT"] = noncanonical
                    state.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
                    with self.assertRaisesRegex(
                        self.release.ReleaseError,
                        "sites_access_rejected",
                    ):
                        self.release.create_production_manifest(
                            runtime,
                            state,
                            owner,
                            root / f"bad-decimal-{noncanonical.replace('+', 'plus')}.json",
                        )

            values["SITES_ALLOWED_VISITOR_COUNT"] = "0"
            values["RUNTIME_MANIFEST_SHA256"] = "f" * 64
            state.write_text("".join(f"{key}={value}\n" for key, value in values.items()))
            with self.assertRaisesRegex(self.release.ReleaseError, "runtime_manifest_mismatch"):
                self.release.create_production_manifest(
                    runtime,
                    state,
                    owner,
                    root / "parent-mismatch.json",
                )

    def test_verify_runtime_install_silently_binds_images_and_rollback_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ReleaseFixture(root)
            runtime, runtime_payload = self._create_canonical_runtime_manifest(root, fixture)
            runtime_digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
            source_manifest = root / "production-source.json"
            source_archive = root / "production-source.tar.gz"
            source_dir = root / "source"
            self.release.verify_extract(source_archive, source_manifest, source_dir)
            rollback = root / "rollback-manifest.json"
            rollback_payload = {
                "schema": "lil-tweak-rollback-receipt-v1",
                "hostname": "galor-tweak-runner-01",
                "captured_at": 1,
                "captured_at_iso": "2026-08-15T00:00:00Z",
                "source_commit": runtime_payload["source"]["commit"],
                "source_prefix": runtime_payload["source"]["commit"][:12],
                "identities": [],
                "managed_paths": [],
                "units": [],
                "podman_objects": [],
                "image_references": [],
                "listeners": [],
                "linger": [],
            }

            def write_rollback(payload: object = rollback_payload) -> str:
                rollback.write_bytes(self.release.canonical_json_bytes(payload))
                rollback.chmod(0o600)
                return hashlib.sha256(rollback.read_bytes()).hexdigest()

            def verify(
                *,
                expected_runtime_digest: str = runtime_digest,
                expected_rollback_digest: str | None = None,
                core: str = runtime_payload["images"]["core"]["reference"],
                postgres: str = runtime_payload["images"]["postgres"]["reference"],
                runner: str = runtime_payload["images"]["runner"]["reference"],
                runtime_path: Path = runtime,
                rollback_path: Path = rollback,
                source_manifest_path: Path = source_manifest,
                source_directory: Path = source_dir,
            ) -> subprocess.CompletedProcess[bytes]:
                return subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT),
                        "verify-runtime-install",
                        "--runtime-manifest",
                        str(runtime_path),
                        "--runtime-manifest-sha256",
                        expected_runtime_digest,
                        "--source-manifest",
                        str(source_manifest_path),
                        "--source-dir",
                        str(source_directory),
                        "--rollback-manifest",
                        str(rollback_path),
                        "--rollback-manifest-sha256",
                        expected_rollback_digest or hashlib.sha256(rollback_path.read_bytes()).hexdigest(),
                        "--core-image",
                        core,
                        "--postgres-image",
                        postgres,
                        "--runner-image",
                        runner,
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    check=False,
                )

            rollback_digest = write_rollback()
            accepted = verify(expected_rollback_digest=rollback_digest)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(accepted.stdout, b"")
            self.assertEqual(accepted.stderr, b"")

            def assert_source_rejected(**arguments: object) -> None:
                rejected = verify(**arguments)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual((rejected.stdout, rejected.stderr), (b"", b""))

            migration = source_dir / "core" / "migrations" / "0001_fixture.sql"
            migration_bytes = migration.read_bytes()
            migration.write_bytes(b"SELECT 2;\n")
            assert_source_rejected()
            migration.write_bytes(migration_bytes)

            readme = source_dir / "README.md"
            readme.chmod(0o600)
            assert_source_rejected()
            readme.chmod(0o644)

            extra = source_dir / "untracked.txt"
            extra.write_text("not in the release\n")
            assert_source_rejected()
            extra.unlink()

            package = source_dir / "package.json"
            package_bytes = package.read_bytes()
            package.unlink()
            assert_source_rejected()
            package.write_bytes(package_bytes)
            package.chmod(0o644)

            readme_bytes = readme.read_bytes()
            readme.unlink()
            readme.symlink_to("package.json")
            assert_source_rejected()
            readme.unlink()
            readme.write_bytes(readme_bytes)
            readme.chmod(0o644)

            wrong_hash_payload = json.loads(source_manifest.read_text())
            wrong_hash_payload["archive_policy"]["tar_umask"] = "0077"
            wrong_hash_manifest = root / "wrong-hash-source.json"
            wrong_hash_manifest.write_bytes(
                self.release.canonical_json_bytes(wrong_hash_payload)
            )
            wrong_hash_manifest.chmod(0o444)
            assert_source_rejected(source_manifest_path=wrong_hash_manifest)

            wrong_tree_payload = json.loads(source_manifest.read_text())
            wrong_tree_payload["source"]["tree"] = "f" * 40
            wrong_tree_manifest = root / "wrong-tree-source.json"
            wrong_tree_manifest.write_bytes(
                self.release.canonical_json_bytes(wrong_tree_payload)
            )
            wrong_tree_manifest.chmod(0o444)
            wrong_tree_runtime_payload = copy.deepcopy(runtime_payload)
            wrong_tree_runtime_payload["source"]["manifest_sha256"] = hashlib.sha256(
                wrong_tree_manifest.read_bytes()
            ).hexdigest()
            wrong_tree_runtime_payload["source"]["manifest_size"] = len(
                wrong_tree_manifest.read_bytes()
            )
            wrong_tree_runtime = root / "wrong-tree-runtime.json"
            wrong_tree_runtime.write_bytes(
                self.release.canonical_json_bytes(wrong_tree_runtime_payload)
            )
            wrong_tree_runtime.chmod(0o444)
            assert_source_rejected(
                runtime_path=wrong_tree_runtime,
                expected_runtime_digest=hashlib.sha256(
                    wrong_tree_runtime.read_bytes()
                ).hexdigest(),
                source_manifest_path=wrong_tree_manifest,
            )

            source_manifest.chmod(0o644)
            assert_source_rejected()
            source_manifest.chmod(0o444)

            mismatches = {
                "runtime digest": {"expected_runtime_digest": "f" * 64},
                "rollback digest": {"expected_rollback_digest": "e" * 64},
                "core image": {
                    "core": "registry.example/lil-tweak/other@sha256:" + "9" * 64
                },
            }
            for label, arguments in mismatches.items():
                with self.subTest(label=label):
                    rejected = verify(**arguments)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertEqual(rejected.stdout, b"")
                    self.assertEqual(rejected.stderr, b"")

            wrong_source = copy.deepcopy(rollback_payload)
            wrong_source["source_commit"] = "f" * 40
            wrong_source["source_prefix"] = "f" * 12
            write_rollback(wrong_source)
            rejected = verify()
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual((rejected.stdout, rejected.stderr), (b"", b""))

            rollback.write_bytes(b'{"schema":')
            rollback.chmod(0o600)
            rejected = verify()
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual((rejected.stdout, rejected.stderr), (b"", b""))

            write_rollback()
            rollback.chmod(0o644)
            rejected = verify()
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual((rejected.stdout, rejected.stderr), (b"", b""))

            rollback.chmod(0o600)
            linked = root / "rollback-link.json"
            linked.symlink_to(rollback)
            rejected = verify(rollback_path=linked)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual((rejected.stdout, rejected.stderr), (b"", b""))

            runtime.chmod(0o644)
            rejected = verify()
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual((rejected.stdout, rejected.stderr), (b"", b""))
            runtime.chmod(0o444)
            runtime_link = root / "runtime-link.json"
            runtime_link.symlink_to(runtime)
            rejected = verify(runtime_path=runtime_link)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual((rejected.stdout, rejected.stderr), (b"", b""))

    def test_manifest_writes_never_overwrite_existing_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "manifest.json"
            output.write_bytes(b"sentinel")
            with self.assertRaisesRegex(self.release.ReleaseError, "manifest_exists"):
                self.release.write_new_manifest(output, {"schema": "test"})
            self.assertEqual(output.read_bytes(), b"sentinel")


if __name__ == "__main__":
    unittest.main()
