import io
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from core.lil_tweak.archive import ArchiveError, ArchiveLimits, extract_zip, inspect_zip
from core.lil_tweak.limits import MAX_EXPANDED_SOURCE_BYTES, RUNNER_WORKSPACE_BYTES


def make_zip(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content, attrs in entries:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = attrs
            archive.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED)
    return buffer.getvalue()


class ArchiveTests(unittest.TestCase):
    def test_accepted_source_tree_fits_within_runner_workspace(self):
        self.assertEqual(ArchiveLimits().max_total_bytes, MAX_EXPANDED_SOURCE_BYTES)
        self.assertLess(MAX_EXPANDED_SOURCE_BYTES, RUNNER_WORKSPACE_BYTES)

    def test_valid_archive_is_inspected_then_extracted(self):
        payload = make_zip(
            [
                ("src/", b"", (stat.S_IFDIR | 0o755) << 16),
                ("src/main.py", b"print('safe')\n", (stat.S_IFREG | 0o644) << 16),
            ]
        )
        entries = inspect_zip(payload)
        self.assertEqual([entry.path for entry in entries], ["src", "src/main.py"])

        with tempfile.TemporaryDirectory() as directory:
            extracted = extract_zip(payload, directory)
            self.assertEqual((Path(directory) / "src/main.py").read_bytes(), b"print('safe')\n")
            self.assertEqual(extracted, [Path(directory) / "src/main.py"])

    def test_rejects_path_traversal_and_absolute_families(self):
        for unsafe in (
            "../escape",
            "/absolute",
            "C:/drive",
            "\\\\server\\share",
            "src/del\x7f.py",
        ):
            with self.subTest(path=unsafe):
                payload = make_zip([(unsafe, b"bad", (stat.S_IFREG | 0o644) << 16)])
                with self.assertRaisesRegex(ArchiveError, "unsafe_path"):
                    inspect_zip(payload)

    def test_rejects_vcs_metadata_and_sensitive_source_files(self):
        for unsafe in (".git/config", "nested/.hg/store", ".env.local"):
            with self.subTest(path=unsafe):
                payload = make_zip(
                    [(unsafe, b"sensitive", (stat.S_IFREG | 0o600) << 16)]
                )
                with self.assertRaisesRegex(ArchiveError, "unsafe_path"):
                    inspect_zip(payload)

    def test_rejects_symlinks_before_writing(self):
        payload = make_zip(
            [("link", b"../../target", (stat.S_IFLNK | 0o777) << 16)]
        )
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "marker"
            marker.write_text("untouched")
            with self.assertRaisesRegex(ArchiveError, "unsupported_type"):
                extract_zip(payload, directory)
            self.assertEqual(os.listdir(directory), ["marker"])

    def test_rejects_duplicate_and_casefold_colliding_paths(self):
        payload = make_zip(
            [
                ("Readme.md", b"one", (stat.S_IFREG | 0o644) << 16),
                ("README.md", b"two", (stat.S_IFREG | 0o644) << 16),
            ]
        )
        with self.assertRaisesRegex(ArchiveError, "duplicate_path"):
            inspect_zip(payload)

    def test_rejects_file_directory_prefix_conflict_during_preflight(self):
        payload = make_zip(
            [
                ("src", b"file", (stat.S_IFREG | 0o644) << 16),
                ("src/main.py", b"code", (stat.S_IFREG | 0o644) << 16),
            ]
        )
        with self.assertRaisesRegex(ArchiveError, "path_conflict"):
            inspect_zip(payload)

    def test_rejects_excessive_file_and_total_size(self):
        payload = make_zip(
            [
                ("a.txt", b"12345", (stat.S_IFREG | 0o644) << 16),
                ("b.txt", b"67890", (stat.S_IFREG | 0o644) << 16),
            ]
        )
        with self.assertRaisesRegex(ArchiveError, "file_too_large"):
            inspect_zip(payload, limits=ArchiveLimits(max_file_bytes=4))
        with self.assertRaisesRegex(ArchiveError, "archive_too_large"):
            inspect_zip(payload, limits=ArchiveLimits(max_total_bytes=9))

    def test_rejects_suspicious_compression_ratio(self):
        payload = make_zip(
            [("bomb.txt", b"0" * 50_000, (stat.S_IFREG | 0o644) << 16)]
        )
        with self.assertRaisesRegex(ArchiveError, "compression_ratio"):
            inspect_zip(payload, limits=ArchiveLimits(max_compression_ratio=2.0))

    def test_rejects_too_many_or_too_deep_entries(self):
        payload = make_zip(
            [
                ("a/b/c.txt", b"x", (stat.S_IFREG | 0o644) << 16),
                ("other.txt", b"y", (stat.S_IFREG | 0o644) << 16),
            ]
        )
        with self.assertRaisesRegex(ArchiveError, "too_many_entries"):
            inspect_zip(payload, limits=ArchiveLimits(max_entries=1))
        with self.assertRaisesRegex(ArchiveError, "path_too_deep"):
            inspect_zip(payload, limits=ArchiveLimits(max_depth=2))

    def test_invalid_zip_has_stable_error(self):
        with self.assertRaisesRegex(ArchiveError, "invalid_zip"):
            inspect_zip(b"not a zip")


if __name__ == "__main__":
    unittest.main()
