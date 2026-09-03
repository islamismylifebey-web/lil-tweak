from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "lil-tweak-secret-snapshot.py"
RUNNER_IMAGE = (
    "registry.example.invalid/lil-tweak/runner@sha256:"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
ADMIN_PASSWORD = "B" * 32
APP_PASSWORD = "A" * 32
MIGRATOR_PASSWORD = "C" * 32
SECRET_NAMES = (
    "core.env",
    "postgres-admin-password",
    "postgres-app-password",
    "postgres-migrator-password",
)


def load_snapshot_module():
    specification = importlib.util.spec_from_file_location("lil_tweak_secret_snapshot", SCRIPT)
    if specification is None or specification.loader is None:
        raise AssertionError("secret snapshot helper could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def valid_core_environment() -> bytes:
    return (
        "# Canonical Lil Tweak core configuration.\n"
        "\n"
        f"LIL_TWEAK_DATABASE_URL=postgresql://lil_tweak_app:{APP_PASSWORD}"
        "@lil-tweak-postgres:5432/lil_tweak\n"
        'LIL_TWEAK_SIGNING_KEYS_JSON={"primary":"reviewed-base64url-signing-key-12"}\n'
        "LIL_TWEAK_CANONICAL_OWNER_ID=ab43c7488fb38a90c7bb9c4bcc0e23e5\n"
        "OPENAI_API_KEY=sk-reviewed-test-value\n"
        "LIL_TWEAK_OPENAI_MODEL=gpt-5.6-terra\n"
        f"LIL_TWEAK_RUNNER_IMAGE={RUNNER_IMAGE}\n"
        "LIL_TWEAK_WORK_ROOT=/var/lib/lil-tweak/work\n"
        "LIL_TWEAK_WORK_ROOT_INODES=204800\n"
        "LIL_TWEAK_MAX_ADMITTED_JOBS=1\n"
        "LIL_TWEAK_JOB_TIMEOUT_SECONDS=1200\n"
        "LIL_TWEAK_EVIDENCE_BUCKET=lil-tweak-evidence\n"
        "LIL_TWEAK_EVIDENCE_ENDPOINT=https://account.r2.cloudflarestorage.com\n"
        "LIL_TWEAK_R2_ACCESS_KEY_ID=reviewed-access-key\n"
        "LIL_TWEAK_R2_SECRET_ACCESS_KEY=reviewed-secret-key\n"
    ).encode("utf-8")


class SecretFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.source = root / "source"
        self.destination = root / "destination"
        self.source.mkdir(mode=0o700)
        self.destination.mkdir(mode=0o700)
        self.contents = {
            "core.env": valid_core_environment(),
            "postgres-admin-password": (ADMIN_PASSWORD + "\n").encode("ascii"),
            "postgres-app-password": (APP_PASSWORD + "\n").encode("ascii"),
            "postgres-migrator-password": (MIGRATOR_PASSWORD + "\n").encode("ascii"),
        }
        for name, contents in self.contents.items():
            path = self.source / name
            path.write_bytes(contents)
            path.chmod(0o600)

    def run(
        self,
        *,
        source: Path | None = None,
        destination: Path | None = None,
        timeout: float = 5,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "snapshot",
                "--source",
                str(source if source is not None else self.source),
                "--destination",
                str(destination if destination is not None else self.destination),
            ],
            cwd=ROOT,
            capture_output=True,
            check=False,
            timeout=timeout,
        )

    def replace(self, name: str, contents: bytes) -> None:
        path = self.source / name
        path.write_bytes(contents)
        path.chmod(0o600)
        self.contents[name] = contents


class SecretSnapshotTests(unittest.TestCase):
    def assert_rejected(self, fixture: SecretFixture) -> None:
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(list(fixture.destination.iterdir()), [])

    def test_valid_inputs_are_frozen_as_private_byte_identical_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SecretFixture(Path(temporary))
            result = fixture.run()

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, (RUNNER_IMAGE + "\n").encode("ascii"))
            self.assertEqual(result.stderr, b"")
            self.assertEqual(
                sorted(path.name for path in fixture.destination.iterdir()),
                sorted(SECRET_NAMES),
            )
            for name in SECRET_NAMES:
                path = fixture.destination / name
                metadata = path.stat(follow_symlinks=False)
                self.assertTrue(stat.S_ISREG(metadata.st_mode), name)
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600, name)
                self.assertEqual(metadata.st_uid, os.geteuid(), name)
                self.assertEqual(metadata.st_nlink, 1, name)
                self.assertEqual(path.read_bytes(), fixture.contents[name], name)

    def test_separate_registry_auth_input_may_share_the_source_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SecretFixture(Path(temporary))
            registry_auth = fixture.source / "registry-auth.json"
            registry_auth.write_bytes(b'{"auths":{"registry.example.invalid":{"auth":"token"}}}\n')
            registry_auth.chmod(0o600)
            result = fixture.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                sorted(path.name for path in fixture.destination.iterdir()),
                sorted(SECRET_NAMES),
            )

    def test_later_whitespace_prefixed_runner_override_is_rejected(self) -> None:
        evil_runner = (
            b"  LIL_TWEAK_RUNNER_IMAGE=registry.example.invalid/lil-tweak/evil@sha256:"
            + b"b" * 64
            + b"\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SecretFixture(Path(temporary))
            fixture.replace("core.env", fixture.contents["core.env"] + evil_runner)
            self.assert_rejected(fixture)

    def test_noncanonical_core_environment_forms_are_rejected(self) -> None:
        valid = valid_core_environment()
        replacements = {
            "duplicate required name": valid + b"OPENAI_API_KEY=other\n",
            "duplicate unknown name": valid + b"EXTRA=value\nEXTRA=other\n",
            "unknown assignment": valid + b"EXTRA=value\n",
            "leading assignment whitespace": valid.replace(
                b"OPENAI_API_KEY=", b" OPENAI_API_KEY=", 1
            ),
            "whitespace before equals": valid.replace(
                b"OPENAI_API_KEY=", b"OPENAI_API_KEY =", 1
            ),
            "leading value whitespace": valid.replace(
                b"OPENAI_API_KEY=sk-reviewed-test-value",
                b"OPENAI_API_KEY= sk-reviewed-test-value",
                1,
            ),
            "trailing value whitespace": valid.replace(
                b"OPENAI_API_KEY=sk-reviewed-test-value",
                b"OPENAI_API_KEY=sk-reviewed-test-value ",
                1,
            ),
            "quoted first value": valid.replace(
                b"OPENAI_API_KEY=sk-reviewed-test-value",
                b'OPENAI_API_KEY="sk-reviewed-test-value"',
                1,
            ),
            "backslash continuation": valid.replace(
                b"OPENAI_API_KEY=sk-reviewed-test-value\n",
                b"OPENAI_API_KEY=sk-reviewed\\\n-test-value\n",
                1,
            ),
            "carriage return": valid.replace(b"\n", b"\r\n"),
            "empty GALOR assignment": valid + b"LIL_TWEAK_GALOR_READONLY_URL=\n",
            "nonempty GALOR assignment": valid
            + b"LIL_TWEAK_GALOR_READONLY_URL=https://galor.invalid\n",
            "semicolon comment": valid + b"; ignored by some parsers\n",
            "leading comment whitespace": valid + b" # hidden comment\n",
            "comment backslash": valid + b"# hidden continuation\\\n",
            "comment carriage return": valid + b"# hidden carriage return\r\n",
            "comment nul": valid + b"# hidden nul\x00\n",
            "ignored non-assignment": valid + b"NOT_AN_ASSIGNMENT\n",
            "empty assignment": valid + b"EXTRA=\n",
            "tab control": valid + b"EXTRA=one\ttwo\n",
            "nul": valid + b"EXTRA=one\x00two\n",
            "byte order mark": b"\xef\xbb\xbf" + valid,
            "unicode noncharacter": valid + "EXTRA=bad\ufdd0\n".encode("utf-8"),
            "invalid UTF-8": valid + b"EXTRA=bad\xff\n",
            "missing final newline": valid.rstrip(b"\n"),
        }
        for label, contents in replacements.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = SecretFixture(Path(temporary))
                fixture.replace("core.env", contents)
                self.assert_rejected(fixture)

    def test_core_semantic_constraints_are_enforced(self) -> None:
        valid = valid_core_environment()
        changes = {
            "runner tag": valid.replace(
                RUNNER_IMAGE.encode("ascii"), b"registry.example.invalid/lil-tweak/runner:latest"
            ),
            "work root": valid.replace(
                b"LIL_TWEAK_WORK_ROOT=/var/lib/lil-tweak/work",
                b"LIL_TWEAK_WORK_ROOT=/tmp/work",
            ),
            "work root inodes": valid.replace(
                b"LIL_TWEAK_WORK_ROOT_INODES=204800",
                b"LIL_TWEAK_WORK_ROOT_INODES=204801",
            ),
            "admission": valid.replace(
                b"LIL_TWEAK_MAX_ADMITTED_JOBS=1", b"LIL_TWEAK_MAX_ADMITTED_JOBS=2"
            ),
            "timeout": valid.replace(
                b"LIL_TWEAK_JOB_TIMEOUT_SECONDS=1200",
                b"LIL_TWEAK_JOB_TIMEOUT_SECONDS=1201",
            ),
            "database host": valid.replace(b"@lil-tweak-postgres:5432", b"@postgres:5432"),
            "database password mismatch": valid.replace(
                APP_PASSWORD.encode("ascii"), b"D" * 32, 1
            ),
            "wrong owner scope": valid.replace(
                b"ab43c7488fb38a90c7bb9c4bcc0e23e5",
                b"0123456789abcdef0123456789abcdef",
            ),
            "owner uppercase": valid.replace(
                b"ab43c7488fb38a90c7bb9c4bcc0e23e5",
                b"AB43C7488FB38A90C7BB9C4BCC0E23E5",
            ),
            "signing JSON list": valid.replace(
                b'{"primary":"reviewed-base64url-signing-key-12"}',
                b'["reviewed-base64url-signing-key-12"]',
            ),
            "empty signing JSON": valid.replace(
                b'{"primary":"reviewed-base64url-signing-key-12"}', b"{}"
            ),
            "short signing secret": valid.replace(
                b"reviewed-base64url-signing-key-12", b"short"
            ),
            "invalid signing key ID": valid.replace(b'"primary":', b'"bad key":'),
            "non-string signing secret": valid.replace(
                b'"reviewed-base64url-signing-key-12"', b"123"
            ),
            "duplicate signing key ID": valid.replace(
                b'{"primary":"reviewed-base64url-signing-key-12"}',
                b'{"primary":"reviewed-base64url-signing-key-12",'
                b'"primary":"another-reviewed-base64url-key-123"}',
            ),
            "HTTP evidence endpoint": valid.replace(
                b"https://account.r2.cloudflarestorage.com",
                b"http://account.r2.cloudflarestorage.com",
            ),
            "credentialed evidence endpoint": valid.replace(
                b"https://account.r2.cloudflarestorage.com",
                b"https://user:pass@account.r2.cloudflarestorage.com",
            ),
            "queried evidence endpoint": valid.replace(
                b"https://account.r2.cloudflarestorage.com",
                b"https://account.r2.cloudflarestorage.com?redirect=other",
            ),
            "pathful evidence endpoint": valid.replace(
                b"https://account.r2.cloudflarestorage.com",
                b"https://account.r2.cloudflarestorage.com/prefix",
            ),
            "placeholder": valid.replace(b"reviewed-access-key", b"CHANGE_ME"),
            "missing required": valid.replace(
                b"LIL_TWEAK_EVIDENCE_BUCKET=lil-tweak-evidence\n", b""
            ),
        }
        for label, contents in changes.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = SecretFixture(Path(temporary))
                fixture.replace("core.env", contents)
                self.assert_rejected(fixture)

    def test_runner_image_uses_the_release_immutable_reference_grammar(self) -> None:
        valid = valid_core_environment()
        invalid_references = {
            "tag": "registry.example.invalid/lil-tweak/runner:latest",
            "double slash": "registry.example.invalid/lil-tweak//runner@sha256:" + "a" * 64,
            "empty repository component": "registry.example.invalid//runner@sha256:" + "a" * 64,
            "uppercase": "registry.example.invalid/Lil-Tweak/runner@sha256:" + "a" * 64,
            "zero port": "registry.example.invalid:0/lil-tweak/runner@sha256:" + "a" * 64,
            "oversized port": "registry.example.invalid:65536/lil-tweak/runner@sha256:"
            + "a" * 64,
            "double digest separator": RUNNER_IMAGE + "@sha256:" + "b" * 64,
        }
        for label, reference in invalid_references.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = SecretFixture(Path(temporary))
                fixture.replace(
                    "core.env",
                    valid.replace(RUNNER_IMAGE.encode("ascii"), reference.encode("ascii")),
                )
                self.assert_rejected(fixture)

    def test_optional_git_hosts_match_the_runtime_allowlist_grammar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SecretFixture(Path(temporary))
            fixture.replace(
                "core.env",
                fixture.contents["core.env"]
                + b"LIL_TWEAK_GIT_ALLOWED_HOSTS=github.com,git.example.invalid\n",
            )
            result = fixture.run()
            self.assertEqual(result.returncode, 0, result.stderr)

        for value in (b".github.com", b"github.com.", b"bad_host", b"a" * 254):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                fixture = SecretFixture(Path(temporary))
                fixture.replace(
                    "core.env",
                    fixture.contents["core.env"] + b"LIL_TWEAK_GIT_ALLOWED_HOSTS=" + value + b"\n",
                )
                self.assert_rejected(fixture)

    def test_password_files_require_one_final_newline_and_base64url_bytes(self) -> None:
        invalid_values = {
            "missing newline": b"A" * 32,
            "too short": b"A" * 31 + b"\n",
            "too long": b"A" * 129 + b"\n",
            "second newline": b"A" * 32 + b"\n\n",
            "non-base64url": b"A" * 31 + b"+\n",
        }
        for label, contents in invalid_values.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = SecretFixture(Path(temporary))
                fixture.replace("postgres-admin-password", contents)
                self.assert_rejected(fixture)

    def test_password_length_boundaries_are_accepted(self) -> None:
        for length in (32, 128):
            with self.subTest(length=length), tempfile.TemporaryDirectory() as temporary:
                fixture = SecretFixture(Path(temporary))
                contents = b"D" * length + b"\n"
                fixture.replace("postgres-admin-password", contents)
                result = fixture.run()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    (fixture.destination / "postgres-admin-password").read_bytes(), contents
                )

    def test_database_passwords_must_be_pairwise_distinct(self) -> None:
        duplicates = {
            "admin equals app": ("postgres-admin-password", APP_PASSWORD),
            "migrator equals app": ("postgres-migrator-password", APP_PASSWORD),
            "admin equals migrator": ("postgres-admin-password", MIGRATOR_PASSWORD),
        }
        for label, (name, password) in duplicates.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = SecretFixture(Path(temporary))
                fixture.replace(name, (password + "\n").encode("ascii"))
                self.assert_rejected(fixture)

    def test_unsafe_source_files_are_rejected_without_blocking_or_partial_output(self) -> None:
        for label in ("symlink", "hardlink", "wrong mode", "fifo", "oversized core"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = SecretFixture(Path(temporary))
                if label == "symlink":
                    target = fixture.root / "outside-secret"
                    target.write_bytes(fixture.contents["core.env"])
                    target.chmod(0o600)
                    (fixture.source / "core.env").unlink()
                    (fixture.source / "core.env").symlink_to(target)
                elif label == "hardlink":
                    target = fixture.root / "outside-secret"
                    target.write_bytes(fixture.contents["core.env"])
                    target.chmod(0o600)
                    (fixture.source / "core.env").unlink()
                    os.link(target, fixture.source / "core.env")
                elif label == "wrong mode":
                    (fixture.source / "core.env").chmod(0o640)
                elif label == "fifo":
                    path = fixture.source / "postgres-migrator-password"
                    path.unlink()
                    os.mkfifo(path, 0o600)
                else:
                    fixture.replace("core.env", b"X" * 65537)
                self.assert_rejected(fixture)

    @unittest.skipUnless(os.geteuid() == 0, "requires root to create a wrong-owner input")
    def test_wrong_owner_source_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SecretFixture(Path(temporary))
            try:
                os.chown(fixture.source / "core.env", 1, -1)
            except OSError as error:
                self.skipTest(f"filesystem cannot create a wrong-owner fixture: {error}")
            self.assert_rejected(fixture)

    def test_directories_must_be_private_distinct_empty_and_nonsymlinked(self) -> None:
        scenarios = ("source mode", "destination mode", "destination nonempty", "same", "symlink")
        for label in scenarios:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = SecretFixture(Path(temporary))
                source = fixture.source
                destination = fixture.destination
                if label == "source mode":
                    source.chmod(0o750)
                elif label == "destination mode":
                    destination.chmod(0o750)
                elif label == "destination nonempty":
                    (destination / "unexpected").write_bytes(b"x")
                elif label == "same":
                    destination = source
                else:
                    link = fixture.root / "source-link"
                    link.symlink_to(source, target_is_directory=True)
                    source = link
                result = fixture.run(source=source, destination=destination)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                if label not in {"destination nonempty", "same"}:
                    self.assertEqual(list(fixture.destination.iterdir()), [])

    def test_fourth_invalid_input_leaves_no_partial_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SecretFixture(Path(temporary))
            fixture.replace("postgres-migrator-password", b"invalid\n")
            self.assert_rejected(fixture)

    def test_write_failure_removes_the_file_that_was_in_progress(self) -> None:
        snapshot = load_snapshot_module()
        original_write_all = snapshot._write_all
        calls = 0

        def fail_on_fourth_write(descriptor: int, data: bytes) -> None:
            nonlocal calls
            calls += 1
            if calls == 4:
                os.write(descriptor, data[:1])
                raise OSError("injected output failure")
            original_write_all(descriptor, data)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = SecretFixture(Path(temporary))
            with (
                patch.object(snapshot, "_write_all", side_effect=fail_on_fourth_write),
                self.assertRaises(OSError),
            ):
                snapshot.snapshot_secrets(str(fixture.source), str(fixture.destination))
            self.assertEqual(list(fixture.destination.iterdir()), [])

    def test_permission_hardening_failure_removes_the_new_output(self) -> None:
        snapshot = load_snapshot_module()
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SecretFixture(Path(temporary))
            with (
                patch.object(
                    snapshot.os,
                    "fchmod",
                    side_effect=PermissionError("injected chmod failure"),
                ),
                self.assertRaises(PermissionError),
            ):
                snapshot.snapshot_secrets(str(fixture.source), str(fixture.destination))
            self.assertEqual(list(fixture.destination.iterdir()), [])

    def test_cleanup_failure_is_surfaced_instead_of_suppressed(self) -> None:
        snapshot = load_snapshot_module()
        original_write_all = snapshot._write_all
        calls = 0

        def fail_on_fourth_write(descriptor: int, data: bytes) -> None:
            nonlocal calls
            calls += 1
            if calls == 4:
                os.write(descriptor, data[:1])
                raise OSError("injected output failure")
            original_write_all(descriptor, data)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = SecretFixture(Path(temporary))
            with (
                patch.object(snapshot, "_write_all", side_effect=fail_on_fourth_write),
                patch.object(snapshot.os, "unlink", side_effect=PermissionError("injected cleanup failure")),
                self.assertRaisesRegex(snapshot.SnapshotError, "snapshot_cleanup_failed"),
            ):
                snapshot.snapshot_secrets(str(fixture.source), str(fixture.destination))

    def test_replaced_destination_entry_never_yields_a_successful_snapshot(self) -> None:
        snapshot = load_snapshot_module()
        original_write_snapshot = snapshot._write_snapshot

        def replace_first_after_fourth(
            directory_fd: int,
            name: str,
            data: bytes,
            created: dict[str, tuple[int, int]],
        ) -> None:
            original_write_snapshot(directory_fd, name, data, created)
            if name == "postgres-migrator-password":
                os.unlink("core.env", dir_fd=directory_fd)
                descriptor = os.open(
                    "core.env",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=directory_fd,
                )
                try:
                    os.write(descriptor, b"attacker replacement\n")
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = SecretFixture(Path(temporary))
            with (
                patch.object(
                    snapshot, "_write_snapshot", side_effect=replace_first_after_fourth
                ),
                self.assertRaises(snapshot.SnapshotError),
            ):
                snapshot.snapshot_secrets(str(fixture.source), str(fixture.destination))

    def test_snapshot_survives_source_replacement_and_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SecretFixture(Path(temporary))
            original = dict(fixture.contents)
            result = fixture.run()
            self.assertEqual(result.returncode, 0, result.stderr)

            for name in SECRET_NAMES:
                source = fixture.source / name
                source.unlink()
                source.write_bytes(b"replacement\n")
                source.unlink()
                self.assertEqual((fixture.destination / name).read_bytes(), original[name])

    def test_failure_message_does_not_disclose_paths_or_secret_values(self) -> None:
        marker = b"ultra-secret-marker"
        with tempfile.TemporaryDirectory() as temporary:
            fixture = SecretFixture(Path(temporary))
            fixture.replace("core.env", fixture.contents["core.env"] + b"EXTRA=" + marker + b" \\n")
            result = fixture.run()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertNotIn(marker, result.stderr)
            self.assertNotIn(str(fixture.source).encode(), result.stderr)
            self.assertNotIn(str(fixture.destination).encode(), result.stderr)

    def test_check_is_host_safe(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--check"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"lil-tweak-secret-snapshot check: ok\n")
        self.assertEqual(result.stderr, b"")

    def test_image_validation_subcommand_is_silent_and_uses_release_grammar(self) -> None:
        valid_images = (
            "registry.example.invalid/lil-tweak/core@sha256:" + "b" * 64,
            "registry.example.invalid:5443/library/postgres@sha256:" + "c" * 64,
        )
        valid = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "validate-images",
                "--image",
                valid_images[0],
                "--image",
                valid_images[1],
            ],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertEqual(valid.stdout, b"")
        self.assertEqual(valid.stderr, b"")

        invalid_images = (
            "registry.example.invalid/lil-tweak//core@sha256:" + "b" * 64,
            "registry.example.invalid:0/lil-tweak/core@sha256:" + "b" * 64,
            "registry.example.invalid:65536/lil-tweak/core@sha256:" + "b" * 64,
            "registry.example.invalid/lil-tweak/core:latest",
        )
        for reference in invalid_images:
            with self.subTest(reference=reference):
                invalid = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT),
                        "validate-images",
                        "--image",
                        reference,
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(invalid.returncode, 0)
                self.assertEqual(invalid.stdout, b"")


if __name__ == "__main__":
    unittest.main()
