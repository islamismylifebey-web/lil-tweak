from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "deploy" / "cloudflared" / "validate_credentials.py"
TUNNEL_ID = "123e4567-e89b-42d3-a456-426614174000"


def load_validator_module():
    specification = importlib.util.spec_from_file_location(
        "lil_tweak_tunnel_credentials", VALIDATOR
    )
    if specification is None or specification.loader is None:
        raise AssertionError("credential validator could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def credential_bytes(**changes: object) -> bytes:
    value: dict[str, object] = {
        "AccountTag": "a" * 32,
        "TunnelSecret": "reviewed-cloudflare-tunnel-secret-value",
        "TunnelID": TUNNEL_ID,
    }
    value.update(changes)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


class TunnelCredentialTests(unittest.TestCase):
    def run_validator(
        self,
        source: Path,
        destination: Path,
        *,
        tunnel_id: str = TUNNEL_ID,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--source",
                str(source),
                "--tunnel-id",
                tunnel_id,
                "--snapshot",
                str(destination),
            ],
            cwd=ROOT,
            capture_output=True,
            timeout=3,
            check=False,
        )

    def fixture(self, root: Path, data: bytes | None = None) -> tuple[Path, Path]:
        source = root / "tunnel.json"
        source.write_bytes(credential_bytes() if data is None else data)
        source.chmod(0o600)
        destination = root / "snapshot.json"
        destination.write_bytes(b"")
        destination.chmod(0o600)
        return source, destination

    def assert_rejected(self, result: subprocess.CompletedProcess[bytes], destination: Path) -> None:
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"TunnelSecret", result.stderr)
        self.assertEqual(destination.read_bytes(), b"")

    def test_valid_credentials_are_frozen_byte_for_byte(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source, destination = self.fixture(Path(temporary))
            original = source.read_bytes()

            result = self.run_validator(source, destination)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"")
            self.assertEqual(destination.read_bytes(), original)
            metadata = destination.stat(follow_symlinks=False)
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            self.assertEqual(metadata.st_uid, os.geteuid())
            self.assertEqual(metadata.st_nlink, 1)

            source.unlink()
            source.write_bytes(b"replacement")
            self.assertEqual(destination.read_bytes(), original)

    def test_malformed_or_mismatched_json_is_rejected_without_snapshot(self) -> None:
        variants = {
            "duplicate": (
                b'{"AccountTag":"' + b"a" * 32
                + b'","TunnelSecret":"one","TunnelSecret":"two","TunnelID":"'
                + TUNNEL_ID.encode() + b'"}\n'
            ),
            "nonfinite": (
                b'{"AccountTag":"' + b"a" * 32
                + b'","TunnelSecret":NaN,"TunnelID":"' + TUNNEL_ID.encode() + b'"}\n'
            ),
            "extra": credential_bytes(Extra="value"),
            "wrong tunnel": credential_bytes(TunnelID="123e4567-e89b-42d3-a456-426614174001"),
            "bad account": credential_bytes(AccountTag="account"),
            "empty secret": credential_bytes(TunnelSecret=""),
            "control secret": credential_bytes(TunnelSecret="bad\nsecret"),
        }
        for label, data in variants.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                source, destination = self.fixture(Path(temporary), data)
                self.assert_rejected(self.run_validator(source, destination), destination)

    def test_unsafe_input_types_and_modes_fail_without_blocking(self) -> None:
        for label in ("mode", "hardlink", "symlink", "fifo"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, destination = self.fixture(root)
                if label == "mode":
                    source.chmod(0o644)
                elif label == "hardlink":
                    os.link(source, root / "second-link")
                elif label == "symlink":
                    real = root / "real.json"
                    source.rename(real)
                    source.symlink_to(real.name)
                else:
                    source.unlink()
                    os.mkfifo(source, 0o600)
                self.assert_rejected(self.run_validator(source, destination), destination)

    def test_destination_must_be_an_empty_private_regular_file(self) -> None:
        for label in ("mode", "nonempty", "hardlink", "symlink"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, destination = self.fixture(root)
                if label == "mode":
                    destination.chmod(0o644)
                elif label == "nonempty":
                    destination.write_bytes(b"sentinel")
                elif label == "hardlink":
                    os.link(destination, root / "second-link")
                else:
                    destination.unlink()
                    destination.symlink_to(source.name)
                before = destination.read_bytes() if not destination.is_symlink() else b""
                result = self.run_validator(source, destination)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                if not destination.is_symlink():
                    self.assertEqual(destination.read_bytes(), before)

    def test_partial_write_failure_restores_the_empty_snapshot(self) -> None:
        module = load_validator_module()
        with tempfile.TemporaryDirectory() as temporary:
            source, destination = self.fixture(Path(temporary))
            original_write = module.os.write
            attempted = False

            def partial_write(descriptor: int, data: bytes) -> int:
                nonlocal attempted
                if not attempted:
                    attempted = True
                    original_write(descriptor, data[:7])
                    raise OSError("injected write failure")
                return original_write(descriptor, data)

            with patch.object(module.os, "write", side_effect=partial_write):
                with self.assertRaises(module.CredentialError):
                    module.validate_and_snapshot(source, TUNNEL_ID, destination)

            self.assertTrue(attempted)
            self.assertEqual(destination.read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
