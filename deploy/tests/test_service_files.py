from __future__ import annotations

import importlib.util
import contextlib
import io
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "lil-tweak-service-files.py"
UID = os.geteuid()
GID = os.getegid()
SERVICE_UID = 12345
SERVICE_GID = 12345
INVENTORY = {
    ".config/lil-tweak/core.env": (0o600, b"CORE=value\n"),
    ".local/share/lil-tweak/migrations/001_initial.sql": (0o400, b"select 1;\n"),
    ".local/share/lil-tweak/migrations/002_fencing.sql": (0o400, b"select 2;\n"),
    ".local/share/lil-tweak/migrations/postgres-bootstrap.sql": (0o400, b"select 3;\n"),
    ".local/share/lil-tweak/migrations/postgres-grants.sql": (0o400, b"select 4;\n"),
    ".config/containers/systemd/lil-tweak-core.container": (0o644, b"[Container]\n"),
    ".config/containers/systemd/lil-tweak-postgres.container": (0o644, b"[Container]\n"),
    ".config/containers/systemd/lil-tweak.network": (0o644, b"[Network]\n"),
    ".config/containers/systemd/lil-tweak-data.volume": (0o644, b"[Volume]\n"),
    ".config/containers/systemd/lil-tweak-postgres-data.volume": (0o644, b"[Volume]\n"),
    ".config/systemd/user/lil-tweak-core.service.d/hardening.conf": (0o644, b"[Service]\n"),
    ".config/systemd/user/lil-tweak-postgres.service.d/hardening.conf": (0o644, b"[Service]\n"),
}


def load_module():
    specification = importlib.util.spec_from_file_location("lil_tweak_service_files", SCRIPT)
    if specification is None or specification.loader is None:
        raise AssertionError("service-files helper could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class Fixture:
    def __init__(self, temporary: str) -> None:
        self.root = Path(temporary)
        self.root.chmod(0o700)
        for relative in ("var", "var/lib", "run", "run/user"):
            path = self.root / relative
            path.mkdir(mode=0o755)
        self.home = self.root / "var/lib/lil-tweak"
        self.home.mkdir(mode=0o700)
        self.runtime = self.root / f"run/user/{SERVICE_UID}"
        self.runtime.mkdir(mode=0o700)
        self.staging = self.root / "staging"
        self.staging.mkdir(mode=0o700)
        for relative, (mode, contents) in INVENTORY.items():
            path = self.staging / relative
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(contents)
            path.chmod(mode)
        for path in self.staging.rglob("*"):
            if path.is_dir():
                path.chmod(0o700)
        self.auth = self.root / "registry-auth"
        self.auth.write_bytes(b'{"auths":{"registry.invalid":{"auth":"token"}}}\n')
        self.auth.chmod(0o600)

    def controller(self, module, **kwargs):
        return module.ServiceFileController(
            test_root=str(self.root), test_filesystem_ids=(UID, GID), **kwargs
        )


class ServiceFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def test_install_tree_creates_exact_private_service_owned_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary)
            fixture.controller(self.module).install_tree(
                str(fixture.staging), SERVICE_UID, SERVICE_GID
            )

            for relative, (mode, contents) in INVENTORY.items():
                target = fixture.home / relative
                metadata = target.stat(follow_symlinks=False)
                self.assertTrue(stat.S_ISREG(metadata.st_mode), relative)
                self.assertEqual(stat.S_IMODE(metadata.st_mode), mode, relative)
                self.assertEqual((metadata.st_uid, metadata.st_gid), (UID, GID), relative)
                self.assertEqual(target.read_bytes(), contents, relative)
            for path in fixture.home.rglob("*"):
                if path.is_dir():
                    metadata = path.stat(follow_symlinks=False)
                    self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o700, path)
                    self.assertEqual((metadata.st_uid, metadata.st_gid), (UID, GID), path)

    def test_cli_parser_dispatches_every_operation_with_bounded_output(self) -> None:
        controller = mock.Mock()
        runtime_path = "/run/user/12345/lil-tweak-registry-auth.0123456789abcdef.1.2"
        controller.stage_runtime_auth.return_value = runtime_path
        cases = (
            (
                ["install-tree", "--staging", "/staging", "--uid", "12345", "--gid", "12345"],
                "install_tree",
                ("/staging", 12345, 12345),
                "",
            ),
            (
                ["stage-runtime-auth", "--source", "/auth", "--uid", "12345", "--gid", "12345"],
                "stage_runtime_auth",
                ("/auth", 12345, 12345),
                runtime_path + "\n",
            ),
            (
                ["remove-runtime-auth", "--path", runtime_path, "--uid", "12345", "--gid", "12345"],
                "remove_runtime_auth",
                (runtime_path, 12345, 12345),
                "",
            ),
        )
        for arguments, method, expected_arguments, expected_stdout in cases:
            with self.subTest(command=arguments[0]):
                controller.reset_mock()
                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    mock.patch.object(self.module, "check_platform"),
                    mock.patch.object(self.module.os, "geteuid", return_value=0),
                    mock.patch.object(
                        self.module, "ServiceFileController", return_value=controller
                    ),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    result = self.module.main(arguments)
                self.assertEqual(result, 0)
                self.assertEqual(stdout.getvalue(), expected_stdout)
                self.assertEqual(stderr.getvalue(), "")
                getattr(controller, method).assert_called_once_with(*expected_arguments)

    def test_intermediate_service_symlink_cannot_modify_victim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary)
            victim = fixture.root / "victim"
            victim.mkdir(mode=0o711)
            sentinel = victim / "sentinel"
            sentinel.write_bytes(b"unchanged")
            before = victim.stat(follow_symlinks=False)
            (fixture.home / ".config").symlink_to(victim, target_is_directory=True)

            with self.assertRaises(self.module.ServiceFilesError):
                fixture.controller(self.module).install_tree(
                    str(fixture.staging), SERVICE_UID, SERVICE_GID
                )

            after = victim.stat(follow_symlinks=False)
            self.assertEqual(sentinel.read_bytes(), b"unchanged")
            self.assertEqual(stat.S_IMODE(after.st_mode), stat.S_IMODE(before.st_mode))
            self.assertEqual((after.st_uid, after.st_gid), (before.st_uid, before.st_gid))
            self.assertEqual(sorted(path.name for path in victim.iterdir()), ["sentinel"])

    def test_final_symlink_is_replaced_without_following_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary)
            victim = fixture.root / "victim"
            victim.write_bytes(b"do not replace")
            target = fixture.home / ".config/lil-tweak/core.env"
            target.parent.mkdir(mode=0o700, parents=True)
            target.symlink_to(victim)

            fixture.controller(self.module).install_tree(
                str(fixture.staging), SERVICE_UID, SERVICE_GID
            )

            self.assertFalse(target.is_symlink())
            self.assertEqual(target.read_bytes(), INVENTORY[".config/lil-tweak/core.env"][1])
            self.assertEqual(victim.read_bytes(), b"do not replace")

    def test_directory_replacement_between_traversal_and_publish_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary)
            victim = fixture.root / "victim"
            victim.mkdir(mode=0o711)
            fired = False

            def hook(event: str, _details: object) -> None:
                nonlocal fired
                if event == "before_publish" and not fired:
                    fired = True
                    config = fixture.home / ".config"
                    config.rename(fixture.home / ".config-held-away")
                    config.symlink_to(victim, target_is_directory=True)

            with self.assertRaises(self.module.ServiceFilesError):
                fixture.controller(self.module, hook=hook).install_tree(
                    str(fixture.staging), SERVICE_UID, SERVICE_GID
                )

            self.assertTrue(fired)
            self.assertEqual(list(victim.iterdir()), [])

    def test_staging_rejects_fifo_hardlink_owner_mode_extra_and_missing_entries(self) -> None:
        mutations = ("fifo", "hardlink", "owner", "mode", "extra", "missing")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(temporary)
                path = fixture.staging / ".config/lil-tweak/core.env"
                if mutation == "fifo":
                    path.unlink()
                    os.mkfifo(path, 0o600)
                elif mutation == "hardlink":
                    os.link(path, fixture.root / "second-link")
                elif mutation == "owner":
                    pass
                elif mutation == "mode":
                    path.chmod(0o644)
                elif mutation == "extra":
                    extra = fixture.staging / "extra"
                    extra.write_bytes(b"extra")
                    extra.chmod(0o600)
                else:
                    path.unlink()

                owner_patch = self._wrong_owner_fstat(path) if mutation == "owner" else contextlib.nullcontext()
                with owner_patch, self.assertRaises(self.module.ServiceFilesError):
                    fixture.controller(self.module).install_tree(
                        str(fixture.staging), SERVICE_UID, SERVICE_GID
                    )
                self.assertEqual(list(fixture.home.iterdir()), [])

    def test_partial_write_fault_removes_same_directory_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary)
            calls = 0

            def partial_then_fail(descriptor: int, data: bytes) -> int:
                nonlocal calls
                calls += 1
                if calls == 1:
                    return os.write(descriptor, data[:1])
                raise OSError("injected")

            with self.assertRaises(self.module.ServiceFilesError):
                fixture.controller(self.module, write_func=partial_then_fail).install_tree(
                    str(fixture.staging), SERVICE_UID, SERVICE_GID
                )

            for directory in fixture.home.rglob("*"):
                if directory.is_dir():
                    self.assertFalse(
                        any(child.name.startswith(".lil-tweak-tmp-") for child in directory.iterdir())
                    )

    def test_rename_fault_removes_temporary_and_preserves_existing_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary)
            target = fixture.home / ".config/lil-tweak/core.env"
            target.parent.mkdir(mode=0o700, parents=True)
            target.write_bytes(b"old")

            def fail_rename(*_args, **_kwargs) -> None:
                raise OSError("injected")

            with self.assertRaises(self.module.ServiceFilesError):
                fixture.controller(self.module, rename_func=fail_rename).install_tree(
                    str(fixture.staging), SERVICE_UID, SERVICE_GID
                )

            self.assertEqual(target.read_bytes(), b"old")
            self.assertFalse(
                any(child.name.startswith(".lil-tweak-tmp-") for child in target.parent.iterdir())
            )

    def test_runtime_auth_is_private_service_owned_and_reports_only_fixed_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary)
            result = fixture.controller(self.module).stage_runtime_auth(
                str(fixture.auth), SERVICE_UID, SERVICE_GID
            )
            target = Path(result)

            self.assertEqual(target.parent, fixture.runtime)
            self.assertRegex(
                target.name,
                r"\Alil-tweak-registry-auth\.[0-9a-f]{16}\.[0-9a-f]+\.[0-9a-f]+\Z",
            )
            metadata = target.stat(follow_symlinks=False)
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            self.assertEqual((metadata.st_uid, metadata.st_gid), (UID, GID))
            self.assertEqual(target.read_bytes(), fixture.auth.read_bytes())

    def test_runtime_partial_write_failure_removes_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary)
            calls = 0

            def partial_then_fail(descriptor: int, data: bytes) -> int:
                nonlocal calls
                calls += 1
                if calls == 1:
                    return os.write(descriptor, data[:1])
                raise OSError("injected")

            with self.assertRaises(self.module.ServiceFilesError):
                fixture.controller(
                    self.module, write_func=partial_then_fail
                ).stage_runtime_auth(str(fixture.auth), SERVICE_UID, SERVICE_GID)
            self.assertEqual(list(fixture.runtime.iterdir()), [])

    def test_runtime_entry_symlink_and_replacement_race_never_write_to_victim(self) -> None:
        for mutation in ("initial-symlink", "race"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(temporary)
                victim = fixture.root / "victim"
                victim.mkdir(mode=0o711)
                real_runtime = fixture.root / "real-runtime"
                hook = None
                if mutation == "initial-symlink":
                    fixture.runtime.rmdir()
                    fixture.runtime.symlink_to(victim, target_is_directory=True)
                else:
                    def replace_runtime(event: str, _details: object) -> None:
                        if event == "before_runtime_create" and fixture.runtime.is_dir():
                            fixture.runtime.rename(real_runtime)
                            fixture.runtime.symlink_to(victim, target_is_directory=True)

                    hook = replace_runtime

                with self.assertRaises(self.module.ServiceFilesError):
                    fixture.controller(self.module, hook=hook).stage_runtime_auth(
                        str(fixture.auth), SERVICE_UID, SERVICE_GID
                    )
                self.assertEqual(list(victim.iterdir()), [])

    def test_source_auth_rejects_fifo_hardlink_wrong_owner_and_wrong_mode(self) -> None:
        for mutation in ("fifo", "hardlink", "owner", "mode"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(temporary)
                if mutation == "fifo":
                    fixture.auth.unlink()
                    os.mkfifo(fixture.auth, 0o600)
                elif mutation == "hardlink":
                    os.link(fixture.auth, fixture.root / "auth-link")
                else:
                    if mutation == "mode":
                        fixture.auth.chmod(0o644)

                owner_patch = (
                    self._wrong_owner_fstat(fixture.auth)
                    if mutation == "owner"
                    else contextlib.nullcontext()
                )
                with owner_patch, self.assertRaises(self.module.ServiceFilesError):
                    fixture.controller(self.module).stage_runtime_auth(
                        str(fixture.auth), SERVICE_UID, SERVICE_GID
                    )
                self.assertEqual(list(fixture.runtime.iterdir()), [])

    def test_zero_service_identity_is_rejected_before_any_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary)
            for uid, gid in ((0, SERVICE_GID), (SERVICE_UID, 0)):
                with self.subTest(uid=uid, gid=gid), self.assertRaises(
                    self.module.ServiceFilesError
                ):
                    fixture.controller(self.module).install_tree(
                        str(fixture.staging), uid, gid
                    )
            self.assertEqual(list(fixture.home.iterdir()), [])

    def test_same_uid_final_dentry_swap_is_detected_without_following_victim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary)
            victim = fixture.root / "victim"
            victim.write_bytes(b"unchanged")
            swapped = False

            def hook(event: str, details: object) -> None:
                nonlocal swapped
                if event == "after_publish" and not swapped:
                    swapped = True
                    target = fixture.home / ".config/lil-tweak" / str(details)
                    target.unlink()
                    target.symlink_to(victim)

            with self.assertRaises(self.module.ServiceFilesError):
                fixture.controller(self.module, hook=hook).install_tree(
                    str(fixture.staging), SERVICE_UID, SERVICE_GID
                )
            self.assertTrue(swapped)
            self.assertEqual(victim.read_bytes(), b"unchanged")

    def test_runtime_auth_removal_is_identity_bound_and_detects_a_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary)
            controller = fixture.controller(self.module)
            path = Path(
                controller.stage_runtime_auth(
                    str(fixture.auth), SERVICE_UID, SERVICE_GID
                )
            )
            held_away = fixture.runtime / "held-away"
            path.rename(held_away)
            path.write_bytes(b"replacement")
            path.chmod(0o600)

            with self.assertRaises(self.module.ServiceFilesError):
                controller.remove_runtime_auth(str(path), SERVICE_UID, SERVICE_GID)

            self.assertEqual(path.read_bytes(), b"replacement")
            self.assertEqual(held_away.read_bytes(), fixture.auth.read_bytes())

    def test_runtime_auth_removal_deletes_the_exact_staged_inode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(temporary)
            controller = fixture.controller(self.module)
            path = controller.stage_runtime_auth(
                str(fixture.auth), SERVICE_UID, SERVICE_GID
            )
            controller.remove_runtime_auth(path, SERVICE_UID, SERVICE_GID)
            self.assertFalse(Path(path).exists())

    def _wrong_owner_fstat(self, target: Path):
        real_fstat = os.fstat
        target_identity = target.stat(follow_symlinks=False)

        def changed_owner(descriptor: int):
            metadata = real_fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) == (
                target_identity.st_dev,
                target_identity.st_ino,
            ):
                values = list(metadata)
                values[4] = 1
                values[5] = 1
                return os.stat_result(values)
            return metadata

        return mock.patch.object(self.module.os, "fstat", side_effect=changed_owner)


if __name__ == "__main__":
    unittest.main()
