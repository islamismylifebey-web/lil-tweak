import hashlib
import io
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from core.lil_tweak.archive import SourceIntakeError, ingest_r2_sources
from core.lil_tweak.store import SourceSpec


class Body:
    def __init__(self, data):
        self.data = data
        self.closed = False

    def read(self, size=-1):
        return self.data[:size] if size >= 0 else self.data

    def close(self):
        self.closed = True


class FakeR2:
    def __init__(self, objects):
        self.objects = objects
        self.requests = []

    def get_object(self, **request):
        self.requests.append(request)
        data = self.objects[request["Key"]]
        return {"Body": Body(data), "ContentLength": len(data)}


def zip_bytes():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("src/main.py")
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(info, b"print('ok')\n", compress_type=zipfile.ZIP_DEFLATED)
    return buffer.getvalue()


def named_zip(name, content):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo(name)
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED)
    return buffer.getvalue()


class SourceIntakeTests(unittest.TestCase):
    def spec(self, **changes):
        values = {
            "source_id": "src:0123456789abcdef0123456789abcdef",
            "filename": "main.py",
            "media_type": "text/x-python",
            "size_bytes": 12,
            "object_key": "engineering/scope/jobs/job:0123456789abcdef0123456789abcdef/sources/src:0123456789abcdef0123456789abcdef",
            "sha256": hashlib.sha256(b"print('ok')\n").hexdigest(),
        }
        values.update(changes)
        return SourceSpec(**values)

    def test_regular_file_is_downloaded_verified_and_inventoried(self):
        spec = self.spec()
        r2 = FakeR2({spec.object_key: b"print('ok')\n"})
        with tempfile.TemporaryDirectory() as directory:
            inventory = ingest_r2_sources(r2, "bucket", [spec], directory)
            self.assertEqual(inventory, ["main.py"])
            self.assertEqual((Path(directory) / "main.py").read_bytes(), b"print('ok')\n")
        self.assertEqual(r2.requests, [{"Bucket": "bucket", "Key": spec.object_key}])

    def test_zip_is_extracted_through_safe_archive_preflight(self):
        data = zip_bytes()
        spec = self.spec(
            filename="source.zip",
            media_type="application/zip",
            size_bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )
        with tempfile.TemporaryDirectory() as directory:
            inventory = ingest_r2_sources(
                FakeR2({spec.object_key: data}), "bucket", [spec], directory
            )
            self.assertEqual(inventory, ["src/main.py"])
            self.assertEqual((Path(directory) / "src/main.py").read_bytes(), b"print('ok')\n")

    def test_size_digest_and_object_key_mismatches_are_rejected(self):
        data = b"print('ok')\n"
        cases = (
            self.spec(size_bytes=11),
            self.spec(sha256="0" * 64),
            self.spec(object_key="engineering/other/escape"),
            self.spec(filename="../escape"),
        )
        for spec in cases:
            with self.subTest(spec=spec):
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaises(SourceIntakeError):
                        ingest_r2_sources(
                            FakeR2({spec.object_key: data}),
                            "bucket",
                            [spec],
                            directory,
                            expected_prefix="engineering/scope/jobs/job:0123456789abcdef0123456789abcdef/sources/",
                        )

    def test_multiple_archives_share_one_expanded_workspace_budget(self):
        first_data = named_zip("first.txt", b"123456")
        second_data = named_zip("second.txt", b"123456")
        first = self.spec(
            source_id="src:11111111111111111111111111111111",
            filename="first.zip",
            media_type="application/zip",
            size_bytes=len(first_data),
            object_key="engineering/scope/jobs/job:0123456789abcdef0123456789abcdef/sources/src:11111111111111111111111111111111",
            sha256=hashlib.sha256(first_data).hexdigest(),
        )
        second = self.spec(
            source_id="src:22222222222222222222222222222222",
            filename="second.zip",
            media_type="application/zip",
            size_bytes=len(second_data),
            object_key="engineering/scope/jobs/job:0123456789abcdef0123456789abcdef/sources/src:22222222222222222222222222222222",
            sha256=hashlib.sha256(second_data).hexdigest(),
        )
        r2 = FakeR2(
            {first.object_key: first_data, second.object_key: second_data}
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(SourceIntakeError, "workspace_too_large"):
                ingest_r2_sources(
                    r2,
                    "bucket",
                    [first, second],
                    directory,
                    max_workspace_bytes=10,
                )


if __name__ == "__main__":
    unittest.main()
