from __future__ import annotations

import hashlib
import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "deploy" / "cloudflared" / "verify_binary.py"


def load_verifier_module():
    specification = importlib.util.spec_from_file_location(
        "lil_tweak_cloudflared_binary", VERIFIER
    )
    if specification is None or specification.loader is None:
        raise AssertionError("cloudflared binary verifier could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class CloudflaredBinaryTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, bytes]:
        root.chmod(0o700)
        usr = root / "usr"
        binary_dir = usr / "bin"
        usr.mkdir(mode=0o755)
        binary_dir.mkdir(mode=0o755)
        payload = b"#!/bin/sh\nexit 0\n"
        binary = binary_dir / "cloudflared"
        binary.write_bytes(payload)
        binary.chmod(0o755)
        return binary, payload

    def verify(self, module, root: Path, payload: bytes, **kwargs: object) -> None:
        module._verify_under_anchor(
            root,
            ("usr", "bin", "cloudflared"),
            hashlib.sha256(payload).hexdigest(),
            expected_uid=os.geteuid(),
            **kwargs,
        )

    def test_private_root_owned_executable_with_exact_digest_passes(self) -> None:
        module = load_verifier_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary, payload = self.fixture(root)

            self.verify(module, root, payload)

            metadata = binary.stat(follow_symlinks=False)
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o755)
            self.assertEqual(metadata.st_nlink, 1)

    def test_wrong_digest_or_unsafe_binary_is_rejected(self) -> None:
        module = load_verifier_module()
        for label in ("digest", "mode", "hardlink", "symlink", "fifo"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                binary, payload = self.fixture(root)
                digest_payload = payload
                if label == "digest":
                    digest_payload = b"different"
                elif label == "mode":
                    binary.chmod(0o775)
                elif label == "hardlink":
                    os.link(binary, binary.with_name("cloudflared-link"))
                elif label == "symlink":
                    target = binary.with_name("cloudflared-real")
                    binary.rename(target)
                    binary.symlink_to(target.name)
                else:
                    binary.unlink()
                    os.mkfifo(binary, 0o755)

                with self.assertRaises(module.BinaryVerificationError):
                    self.verify(module, root, digest_payload)

    def test_writable_or_replaced_parent_is_rejected(self) -> None:
        module = load_verifier_module()
        for label in ("writable", "symlink"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _binary, payload = self.fixture(root)
                binary_dir = root / "usr" / "bin"
                if label == "writable":
                    binary_dir.chmod(0o777)
                else:
                    real = root / "usr" / "real-bin"
                    binary_dir.rename(real)
                    binary_dir.symlink_to(real.name, target_is_directory=True)

                with self.assertRaises(module.BinaryVerificationError):
                    self.verify(module, root, payload)

    def test_non_root_binary_owner_is_rejected(self) -> None:
        module = load_verifier_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary, payload = self.fixture(root)
            try:
                os.chown(binary, 65534, 65534)
            except OSError:
                self.skipTest("the test user namespace cannot represent a second owner")

            with self.assertRaises(module.BinaryVerificationError):
                self.verify(module, root, payload)

    def test_path_replacement_or_content_mutation_during_hash_is_rejected(self) -> None:
        module = load_verifier_module()
        for label in ("replace", "mutate"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                binary, payload = self.fixture(root)

                def hook(phase: str) -> None:
                    if phase != "after_hash":
                        return
                    if label == "replace":
                        binary.rename(binary.with_name("cloudflared-old"))
                        binary.write_bytes(payload)
                        binary.chmod(0o755)
                    else:
                        with binary.open("r+b", buffering=0) as stream:
                            stream.seek(0)
                            stream.write(b"X")
                            os.fsync(stream.fileno())

                with self.assertRaises(module.BinaryVerificationError):
                    self.verify(module, root, payload, _test_hook=hook)

    def test_cli_check_is_content_free(self) -> None:
        module = load_verifier_module()
        self.assertEqual(module.main(["--check"]), 0)
        self.assertEqual(module.main(["--expected-sha256", "not-a-digest"]), 1)
        with patch.object(module.os, "supports_fd", set()):
            self.assertEqual(module.main(["--check"]), 1)

    def test_execute_uses_the_verified_descriptor_after_path_replacement(self) -> None:
        module = load_verifier_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary, payload = self.fixture(root)
            observed: list[tuple[list[str], bytes]] = []

            class ExecObserved(Exception):
                pass

            def replace_path() -> None:
                binary.rename(binary.with_name("cloudflared-reviewed"))
                binary.write_bytes(b"#!/bin/sh\nexit 99\n")
                binary.chmod(0o755)

            def observe_exec(
                descriptor: int,
                arguments: list[str],
                _environment: dict[str, str],
            ) -> None:
                os.lseek(descriptor, 0, os.SEEK_SET)
                observed.append((arguments, os.read(descriptor, 4096)))
                raise ExecObserved

            with patch.object(module.os, "execve", side_effect=observe_exec):
                with self.assertRaises(ExecObserved):
                    module._execute_under_anchor(
                        root,
                        ("usr", "bin", "cloudflared"),
                        hashlib.sha256(payload).hexdigest(),
                        ["--no-autoupdate", "tunnel", "run"],
                        expected_uid=os.geteuid(),
                        expected_gid=os.getegid(),
                        _before_exec_hook=replace_path,
                    )

            self.assertEqual(
                observed,
                [
                    (
                        ["/usr/bin/cloudflared", "--no-autoupdate", "tunnel", "run"],
                        payload,
                    )
                ],
            )


if __name__ == "__main__":
    unittest.main()
