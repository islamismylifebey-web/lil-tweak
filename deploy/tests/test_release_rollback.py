from __future__ import annotations

import copy
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "lil-tweak-rollback.py"


def load_rollback_module():
    spec = importlib.util.spec_from_file_location("lil_tweak_rollback", SCRIPT)
    if spec is None or spec.loader is None:
        raise AssertionError("rollback helper could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def absent_identity(name: str) -> dict[str, object]:
    return {
        "name": name,
        "state": "absent",
        "uid": None,
        "gid": None,
        "home": None,
        "primary_group": None,
        "shell": None,
        "password_locked": None,
        "supplementary_groups": None,
    }


class FakeExecutor:
    def __init__(self) -> None:
        self.actions: list[str] = []
        self.removed_object_ids: list[str] = []
        self.image_removal_error: Exception | None = None
        self.image_inspection_error: Exception | None = None
        self.images: dict[str, dict[str, object]] = {}
        self.objects = {
            (kind, name): {
                "kind": kind,
                "name": name,
                "state": "absent",
                "id": None,
                "identity": None,
            }
            for kind, name in (
                ("container", "lil-tweak-core"),
                ("container", "lil-tweak-postgres"),
                ("network", "lil-tweak-private"),
                ("volume", "lil-tweak-data"),
                ("volume", "lil-tweak-postgres-data"),
                ("secret", "lil-tweak-postgres-admin-password"),
            )
        }

    def capture_state(self):
        return {
            "units": [
                {
                    "scope": scope,
                    "name": name,
                    "load_state": "not-found",
                    "unit_file_state": "disabled",
                    "active_state": "inactive",
                    "sub_state": "dead",
                }
                for scope, name in (
                    ("system", "lil-tweak-cloudflared.service"),
                    ("system", "user@lil-tweak.service"),
                    ("user", "podman.socket"),
                    ("user", "lil-tweak-core.service"),
                    ("user", "lil-tweak-postgres.service"),
                    ("user", "lil-tweak-network.service"),
                    ("user", "lil-tweak-data-volume.service"),
                    ("user", "lil-tweak-postgres-data-volume.service"),
                )
            ],
            "podman_objects": list(self.objects.values()),
            "image_references": [],
            "listeners": {"loopback_8017": False},
            "linger": False,
        }

    def stop_for_restore(self) -> None:
        self.actions.extend(["stop:tunnel", "stop:core", "stop:postgres"])

    def current_object(self, kind: str, name: str):
        return dict(self.objects[(kind, name)])

    def current_image(self, reference: str):
        if self.image_inspection_error is not None:
            raise self.image_inspection_error
        return dict(
            self.images.get(
                reference,
                {
                    "reference": reference,
                    "state": "absent",
                    "id": None,
                    "identity": None,
                },
            )
        )

    def remove_object(self, entry) -> None:
        current = self.objects[(entry["kind"], entry["name"])]
        if current != entry:
            raise AssertionError("remove_object received an unbound descriptor")
        self.actions.append(f"remove:{entry['kind']}:{entry['name']}")
        self.removed_object_ids.append(entry["id"])
        self.objects[(entry["kind"], entry["name"])] = {
            "kind": entry["kind"],
            "name": entry["name"],
            "state": "absent",
            "id": None,
            "identity": None,
        }

    def remove_image(self, entry) -> None:
        reference = entry["reference"]
        self.actions.append(f"remove:image:{reference}")
        if self.image_removal_error is not None:
            raise self.image_removal_error
        self.images[reference] = {
            "reference": reference,
            "state": "absent",
            "id": None,
            "identity": None,
        }

    def restore_units(self, units, linger=None) -> None:
        self.actions.append("restore:units")

    def verify_restored(self, manifest, retained_objects=None) -> None:
        self.actions.append("verify:restored")


class RollbackFixture:
    def __init__(self, root: Path, rollback) -> None:
        self.root = root
        self.rollback = rollback
        self.executor = FakeExecutor()
        self.commit = "a" * 40
        self.receipt = (
            root
            / "var/lib/lil-tweak-release-rollback"
            / "20260815T000000Z-aaaaaaaaaaaa"
        )
        core_env = root / "var/lib/lil-tweak/.config/lil-tweak/core.env"
        core_env.parent.mkdir(parents=True)
        core_env.write_bytes(b"OPENAI_API_KEY=canary-not-in-manifest\n")
        core_env.chmod(0o600)
        self.core_env = core_env

    def capture(self) -> str:
        return self.rollback.capture_receipt(
            output=self.receipt,
            source_commit=self.commit,
            root=self.root,
            hostname_getter=lambda: "galor-private-cloud-01",
            executor=self.executor,
        )


def populate_complete_forward_ledger(fixture: RollbackFixture, digest: str) -> None:
    rollback = fixture.rollback
    references = {
        "core": "registry.example/lil-tweak/core@sha256:" + "1" * 64,
        "postgres": "registry.example/postgres@sha256:" + "2" * 64,
        "runner": "registry.example/lil-tweak/runner@sha256:" + "3" * 64,
    }
    rollback.authorize_images(
        fixture.receipt,
        digest,
        references,
        executor=fixture.executor,
    )
    staged = fixture.root / "complete-forward-file"
    staged.write_bytes(b"reviewed-release-file\n")
    for logical_path, expected_type, _sensitive in rollback.MANAGED_PATHS:
        if expected_type != "regular":
            continue
        rollback.authorize_file(
            fixture.receipt,
            digest,
            logical_path,
            staged,
            0o640,
            os.geteuid(),
            os.getegid(),
        )
    objects = (
        ("container", "lil-tweak-core", references["core"]),
        ("container", "lil-tweak-postgres", references["postgres"]),
        ("network", "lil-tweak-private", "lil-tweak-private"),
        (
            "secret",
            "lil-tweak-postgres-admin-password",
            "lil-tweak-postgres-admin-password",
        ),
    )
    for kind, name, identity in objects:
        rollback.authorize_object(
            fixture.receipt,
            digest,
            kind,
            name,
            identity,
            executor=fixture.executor,
        )
        fixture.executor.objects[(kind, name)] = {
            "kind": kind,
            "name": name,
            "state": "present",
            "id": f"completed-{name}-id",
            "identity": identity,
        }
        rollback.finalize_object(
            fixture.receipt,
            digest,
            kind,
            name,
            identity,
            executor=fixture.executor,
        )


class ReleaseRollbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rollback = load_rollback_module()

    def test_capture_is_canonical_bounded_and_keeps_secret_bytes_only_in_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            manifest_path = fixture.receipt / "manifest.json"
            manifest_bytes = manifest_path.read_bytes()

            self.assertEqual(digest, hashlib.sha256(manifest_bytes).hexdigest())
            self.assertEqual(stat.S_IMODE(fixture.receipt.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)
            self.assertNotIn(b"canary-not-in-manifest", manifest_bytes)
            manifest = json.loads(manifest_bytes)
            self.assertEqual(manifest["schema"], "lil-tweak-rollback-receipt-v1")
            self.assertEqual(manifest["hostname"], "galor-private-cloud-01")
            forward = json.loads(
                (fixture.receipt / "forward-state.json").read_text()
            )
            self.assertEqual(forward["schema"], "lil-tweak-forward-state-v3")
            self.assertEqual(forward["transaction_state"], "open")
            for identity in manifest["identities"]:
                self.assertEqual(
                    set(identity),
                    {
                        "name",
                        "state",
                        "uid",
                        "gid",
                        "home",
                        "primary_group",
                        "shell",
                        "password_locked",
                        "supplementary_groups",
                    },
                )
            entry = next(
                item
                for item in manifest["managed_paths"]
                if item["path"] == "/var/lib/lil-tweak/.config/lil-tweak/core.env"
            )
            self.assertTrue(entry["sensitive"])
            payload = fixture.receipt / entry["payload"]
            self.assertIn(b"canary-not-in-manifest", payload.read_bytes())
            self.assertEqual(stat.S_IMODE(payload.stat().st_mode), 0o600)
            self.assertEqual(self.rollback.verify_receipt(fixture.receipt, digest), digest)

    def test_completed_receipt_rejects_install_reuse_but_allows_manual_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            populate_complete_forward_ledger(fixture, digest)
            self.rollback.mark_completed(fixture.receipt, digest)

            forward = json.loads(
                (fixture.receipt / "forward-state.json").read_text()
            )
            self.assertEqual(forward["transaction_state"], "completed")
            completed_bytes = (fixture.receipt / "forward-state.json").read_bytes()
            self.rollback.mark_completed(fixture.receipt, digest)
            self.assertEqual(
                (fixture.receipt / "forward-state.json").read_bytes(),
                completed_bytes,
            )

            marker = fixture.root / "stale-install-ran"
            with self.assertRaisesRegex(
                self.rollback.RollbackError,
                "^transaction_closed$",
            ):
                self.rollback.lease_exec(
                    fixture.receipt,
                    digest,
                    [
                        sys.executable,
                        "-c",
                        "from pathlib import Path; Path(__import__('sys').argv[1]).write_text('ran')",
                        str(marker),
                    ],
                )
            self.assertFalse(marker.exists())

            staged = fixture.root / "staged.yml"
            staged.write_bytes(b"stale\n")
            with self.assertRaisesRegex(
                self.rollback.RollbackError,
                "^transaction_closed$",
            ):
                self.rollback.authorize_file(
                    fixture.receipt,
                    digest,
                    "/etc/lil-tweak-cloudflared/config.yml",
                    staged,
                    0o640,
                    os.geteuid(),
                    os.getegid(),
                )

            references = {
                "core": "registry.example/lil-tweak/core@sha256:" + "1" * 64,
                "postgres": "registry.example/postgres@sha256:" + "2" * 64,
                "runner": "registry.example/lil-tweak/runner@sha256:" + "3" * 64,
            }
            blocked_operations = (
                lambda: self.rollback.authorize_images(
                    fixture.receipt,
                    digest,
                    references,
                    executor=fixture.executor,
                ),
                lambda: self.rollback.authorize_object(
                    fixture.receipt,
                    digest,
                    "network",
                    "lil-tweak-private",
                    "lil-tweak-private",
                    executor=fixture.executor,
                ),
                lambda: self.rollback.finalize_object(
                    fixture.receipt,
                    digest,
                    "network",
                    "lil-tweak-private",
                    "lil-tweak-private",
                    executor=fixture.executor,
                ),
                lambda: self.rollback.verify_fresh_install(
                    fixture.receipt,
                    digest,
                    root=fixture.root,
                    hostname_getter=lambda: "galor-private-cloud-01",
                    executor=fixture.executor,
                ),
            )
            for operation in blocked_operations:
                with self.assertRaisesRegex(
                    self.rollback.RollbackError,
                    "^transaction_closed$",
                ):
                    operation()

            self.rollback.restore_receipt(
                fixture.receipt,
                digest,
                root=fixture.root,
                hostname_getter=lambda: "galor-private-cloud-01",
                executor=fixture.executor,
            )
            self.assertIn("verify:restored", fixture.executor.actions)

            parsed = self.rollback._parser().parse_args(
                [
                    "mark-completed",
                    "--receipt",
                    str(fixture.receipt),
                    "--expected-manifest-sha256",
                    digest,
                ]
            )
            self.assertEqual(parsed.command, "mark-completed")

    def test_mark_completed_requires_every_mandatory_forward_entry_finalized(self) -> None:
        cases = ("empty", "missing-file", "missing-image-ledger", "missing-object", "intent")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                fixture = RollbackFixture(Path(temporary), self.rollback)
                digest = fixture.capture()
                if case != "empty":
                    populate_complete_forward_ledger(fixture, digest)
                    forward = json.loads(
                        (fixture.receipt / "forward-state.json").read_text()
                    )
                    if case == "missing-file":
                        forward["files"].pop(next(iter(forward["files"])))
                    elif case == "missing-image-ledger":
                        forward["images"] = {}
                    elif case == "missing-object":
                        forward["objects"].pop(next(iter(forward["objects"])))
                    elif case == "intent":
                        descriptor = next(iter(forward["objects"].values()))
                        descriptor["state"] = "intent"
                        descriptor["id"] = None
                    self.rollback._replace_canonical(
                        fixture.receipt / "forward-state.json",
                        forward,
                    )

                with self.assertRaisesRegex(
                    self.rollback.RollbackError,
                    "^transaction_incomplete$",
                ):
                    self.rollback.mark_completed(fixture.receipt, digest)

    def test_fresh_install_verifier_accepts_only_clean_baseline_and_current_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            shutil.rmtree(fixture.root / "var")
            with patch.object(
                self.rollback,
                "_identity",
                side_effect=lambda name: absent_identity(name),
            ):
                digest = fixture.capture()
                self.assertEqual(
                    self.rollback.verify_fresh_install(
                        fixture.receipt,
                        digest,
                        root=fixture.root,
                        hostname_getter=lambda: "galor-private-cloud-01",
                        executor=fixture.executor,
                    ),
                    digest,
                )

            parsed = self.rollback._parser().parse_args(
                [
                    "verify-fresh-install",
                    "--receipt",
                    str(fixture.receipt),
                    "--expected-manifest-sha256",
                    digest,
                ]
            )
            self.assertEqual(parsed.command, "verify-fresh-install")

        current_drift_cases = ("managed-path", "podman-object", "unit-identity")
        for drift in current_drift_cases:
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as temporary:
                fixture = RollbackFixture(Path(temporary), self.rollback)
                shutil.rmtree(fixture.root / "var")
                with patch.object(
                    self.rollback,
                    "_identity",
                    side_effect=lambda name: absent_identity(name),
                ):
                    digest = fixture.capture()
                    if drift == "managed-path":
                        path = fixture.root / "etc/lil-tweak-cloudflared/config.yml"
                        path.parent.mkdir(parents=True)
                        path.write_text("independent\n")
                    elif drift == "podman-object":
                        fixture.executor.objects[("network", "lil-tweak-private")] = {
                            "kind": "network",
                            "name": "lil-tweak-private",
                            "state": "present",
                            "id": "independent-network-id",
                            "identity": "lil-tweak-private",
                        }
                    else:
                        original_capture = fixture.executor.capture_state

                        def capture_wrong_unit_identity():
                            state = copy.deepcopy(original_capture())
                            state["units"][0]["name"] = "independent.service"
                            return state

                        fixture.executor.capture_state = capture_wrong_unit_identity
                    with self.assertRaisesRegex(
                        self.rollback.RollbackError,
                        "^fresh_install_required$",
                    ):
                        self.rollback.verify_fresh_install(
                            fixture.receipt,
                            digest,
                            root=fixture.root,
                            hostname_getter=lambda: "galor-private-cloud-01",
                            executor=fixture.executor,
                        )
                self.assertEqual(fixture.executor.actions, [])

    def test_fresh_install_verifier_rejects_every_nonfresh_baseline_dimension(self) -> None:
        cases = (
            "managed-path",
            "identity",
            "unit",
            "podman-object",
            "listener",
            "linger",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                fixture = RollbackFixture(Path(temporary), self.rollback)
                shutil.rmtree(fixture.root / "var")
                original_capture = fixture.executor.capture_state

                if case == "managed-path":
                    old_environment = (
                        fixture.root / "var/lib/lil-tweak/.config/lil-tweak/core.env"
                    )
                    old_environment.parent.mkdir(parents=True)
                    old_environment.write_text(
                        "DATABASE_URL=postgresql://lil_tweak_app:old-password@localhost/lil_tweak\n"
                    )

                def capture_state():
                    state = copy.deepcopy(original_capture())
                    if case == "unit":
                        state["units"][3].update(
                            {
                                "load_state": "loaded",
                                "unit_file_state": "enabled",
                                "active_state": "active",
                                "sub_state": "running",
                            }
                        )
                    elif case == "podman-object":
                        state["podman_objects"][4].update(
                            {
                                "state": "present",
                                "id": "existing-postgres-volume",
                                "identity": "lil-tweak-postgres-data",
                            }
                        )
                    elif case == "listener":
                        state["listeners"] = {"loopback_8017": True}
                    elif case == "linger":
                        state["linger"] = True
                    return state

                fixture.executor.capture_state = capture_state
                present_service = {
                    "name": "lil-tweak",
                    "state": "present",
                    "uid": 1001,
                    "gid": 1001,
                    "home": "/var/lib/lil-tweak",
                    "primary_group": "lil-tweak",
                    "shell": "/usr/sbin/nologin",
                    "password_locked": True,
                    "supplementary_groups": [],
                }

                def identity(name):
                    if case == "identity" and name == "lil-tweak":
                        return dict(present_service)
                    return absent_identity(name)

                with patch.object(self.rollback, "_identity", side_effect=identity):
                    digest = fixture.capture()
                    with self.assertRaisesRegex(
                        self.rollback.RollbackError,
                        "^fresh_install_required$",
                    ):
                        self.rollback.verify_fresh_install(
                            fixture.receipt,
                            digest,
                            root=fixture.root,
                            hostname_getter=lambda: "galor-private-cloud-01",
                            executor=fixture.executor,
                        )
                self.assertEqual(fixture.executor.actions, [])

    def test_receipt_tampering_and_unsafe_inputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            manifest = json.loads((fixture.receipt / "manifest.json").read_text())
            payload_name = next(item["payload"] for item in manifest["managed_paths"] if item["payload"])
            payload = fixture.receipt / payload_name
            payload.write_bytes(b"tampered")
            with self.assertRaisesRegex(self.rollback.RollbackError, "receipt_payload_mismatch"):
                self.rollback.verify_receipt(fixture.receipt, digest)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            os.symlink("0000.bin", fixture.receipt / "payload/extra-link")
            with self.assertRaisesRegex(self.rollback.RollbackError, "receipt_payload_mismatch"):
                self.rollback.verify_receipt(fixture.receipt, digest)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "var/lib/lil-tweak/.config/lil-tweak/core.env"
            target.parent.mkdir(parents=True)
            os.symlink("/etc/passwd", target)
            receipt = root / "var/lib/lil-tweak-release-rollback/20260815T000000Z-aaaaaaaaaaaa"
            with self.assertRaisesRegex(self.rollback.RollbackError, "managed_path_unsafe"):
                self.rollback.capture_receipt(
                    output=receipt,
                    source_commit="a" * 40,
                    root=root,
                    hostname_getter=lambda: "galor-private-cloud-01",
                    executor=FakeExecutor(),
                )
            self.assertFalse(receipt.exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            service_home = root / "var/lib/lil-tweak"
            service_home.mkdir(parents=True)
            outside = root / "outside/lil-tweak"
            outside.mkdir(parents=True)
            (outside / "core.env").write_bytes(b"outside\n")
            os.symlink(root / "outside", service_home / ".config")
            receipt = root / "var/lib/lil-tweak-release-rollback/20260815T000000Z-aaaaaaaaaaaa"
            with self.assertRaisesRegex(self.rollback.RollbackError, "managed_path_unsafe"):
                self.rollback.capture_receipt(
                    output=receipt,
                    source_commit="a" * 40,
                    root=root,
                    hostname_getter=lambda: "galor-private-cloud-01",
                    executor=FakeExecutor(),
                )
            self.assertFalse(receipt.exists())

    def test_regular_file_io_failures_are_content_free_and_zero_writes_terminate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"bounded")
            with (
                patch.object(self.rollback.os, "read", side_effect=OSError("secret-path")),
                self.assertRaisesRegex(
                    self.rollback.RollbackError,
                    "^managed_path_changed$",
                ),
            ):
                self.rollback._read_regular(source, maximum=64)

            target = root / "forward-state.json"
            target.write_bytes(b"original")
            target.chmod(0o600)
            with (
                patch.object(self.rollback.os, "write", return_value=0),
                self.assertRaisesRegex(
                    self.rollback.RollbackError,
                    "^receipt_write_failed$",
                ),
            ):
                self.rollback._replace_canonical(target, {"state": "new"})
            self.assertEqual(target.read_bytes(), b"original")

    def test_authorized_forward_files_restore_atomically_and_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            staged_core = fixture.root / "staged-core.env"
            staged_core.write_bytes(b"release-core\n")
            staged_core.chmod(0o600)
            tunnel_config = fixture.root / "staged-config.yml"
            tunnel_config.write_bytes(b"release-tunnel\n")
            tunnel_config.chmod(0o600)
            self.rollback.authorize_file(
                fixture.receipt,
                digest,
                "/var/lib/lil-tweak/.config/lil-tweak/core.env",
                staged_core,
                0o600,
                os.geteuid(),
                os.getegid(),
            )
            self.rollback.authorize_file(
                fixture.receipt,
                digest,
                "/etc/lil-tweak-cloudflared/config.yml",
                tunnel_config,
                0o640,
                os.geteuid(),
                os.getegid(),
            )
            fixture.core_env.write_bytes(staged_core.read_bytes())
            new_config = fixture.root / "etc/lil-tweak-cloudflared/config.yml"
            new_config.parent.mkdir(parents=True)
            new_config.write_bytes(tunnel_config.read_bytes())
            new_config.chmod(0o640)

            self.rollback.restore_receipt(
                fixture.receipt,
                digest,
                root=fixture.root,
                hostname_getter=lambda: "galor-private-cloud-01",
                executor=fixture.executor,
            )

            self.assertIn(b"canary-not-in-manifest", fixture.core_env.read_bytes())
            self.assertFalse(new_config.exists())
            self.assertEqual(fixture.executor.actions[:3], ["stop:tunnel", "stop:core", "stop:postgres"])
            self.assertNotIn("remove:volume:lil-tweak-data", fixture.executor.actions)
            self.rollback.restore_receipt(
                fixture.receipt,
                digest,
                root=fixture.root,
                hostname_getter=lambda: "galor-private-cloud-01",
                executor=fixture.executor,
            )
            self.assertIn(b"canary-not-in-manifest", fixture.core_env.read_bytes())

    def test_cloudflared_verifier_and_managed_parent_are_removed_on_fresh_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            staged = fixture.root / "staged-cloudflared-verifier.py"
            staged.write_bytes(b"#!/usr/bin/python3\nraise SystemExit(0)\n")
            staged.chmod(0o755)
            logical = "/usr/local/libexec/lil-tweak/cloudflared-verify-exec.py"
            self.rollback.authorize_file(
                fixture.receipt,
                digest,
                logical,
                staged,
                0o755,
                os.geteuid(),
                os.getegid(),
            )
            target = fixture.root / logical.removeprefix("/")
            target.parent.mkdir(parents=True)
            target.write_bytes(staged.read_bytes())
            target.chmod(0o755)

            self.rollback.restore_receipt(
                fixture.receipt,
                digest,
                root=fixture.root,
                hostname_getter=lambda: "galor-private-cloud-01",
                executor=fixture.executor,
            )

            self.assertFalse(target.exists())
            self.assertFalse(target.parent.exists())

    def test_quarantine_requires_locked_acknowledgement_before_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            initial_forward = json.loads(
                (fixture.receipt / "forward-state.json").read_text()
            )
            self.assertEqual(initial_forward["rollback_outcome"], "clean")
            with self.assertRaisesRegex(
                self.rollback.RollbackError, "quarantine_not_pending"
            ):
                self.rollback.acknowledge_quarantine(fixture.receipt, digest)
            unexpected = fixture.root / "etc/lil-tweak-cloudflared/tunnel.json"
            unexpected.parent.mkdir(parents=True)
            unexpected.write_bytes(b"unknown-credential")
            unexpected.chmod(0o640)

            with self.assertRaisesRegex(self.rollback.RollbackError, "rollback_drift_quarantined"):
                self.rollback.restore_receipt(
                    fixture.receipt,
                    digest,
                    root=fixture.root,
                    hostname_getter=lambda: "galor-private-cloud-01",
                    executor=fixture.executor,
                )

            self.assertFalse(unexpected.exists())
            quarantined = list((fixture.receipt / "quarantine").glob("*"))
            self.assertEqual(len(quarantined), 1)
            self.assertEqual(quarantined[0].read_bytes(), b"unknown-credential")
            quarantined_forward = json.loads(
                (fixture.receipt / "forward-state.json").read_text()
            )
            self.assertEqual(quarantined_forward["rollback_outcome"], "quarantined")
            with self.assertRaisesRegex(self.rollback.RollbackError, "rollback_drift_quarantined"):
                self.rollback.restore_receipt(
                    fixture.receipt,
                    digest,
                    root=fixture.root,
                    hostname_getter=lambda: "galor-private-cloud-01",
                    executor=fixture.executor,
                )
            self.assertEqual(len(list((fixture.receipt / "quarantine").glob("*"))), 1)

            parsed = self.rollback._parser().parse_args(
                [
                    "acknowledge-quarantine",
                    "--receipt",
                    str(fixture.receipt),
                    "--expected-manifest-sha256",
                    digest,
                ]
            )
            self.assertEqual(parsed.command, "acknowledge-quarantine")
            self.rollback.acknowledge_quarantine(fixture.receipt, digest)
            self.rollback.acknowledge_quarantine(fixture.receipt, digest)
            acknowledged = json.loads(
                (fixture.receipt / "forward-state.json").read_text()
            )
            self.assertEqual(acknowledged["rollback_outcome"], "acknowledged")
            with self.assertRaisesRegex(
                self.rollback.RollbackError, "rollback_drift_quarantined"
            ):
                self.rollback.authorize_object(
                    fixture.receipt,
                    digest,
                    "network",
                    "lil-tweak-private",
                    "lil-tweak-private",
                )

            self.rollback.restore_receipt(
                fixture.receipt,
                digest,
                root=fixture.root,
                hostname_getter=lambda: "galor-private-cloud-01",
                executor=fixture.executor,
            )
            replacement = fixture.root / "etc/lil-tweak-cloudflared/tunnel.json"
            replacement.parent.mkdir(parents=True)
            replacement.write_bytes(b"new-unknown-credential")
            replacement.chmod(0o640)
            with self.assertRaisesRegex(
                self.rollback.RollbackError, "rollback_drift_quarantined"
            ):
                self.rollback.restore_receipt(
                    fixture.receipt,
                    digest,
                    root=fixture.root,
                    hostname_getter=lambda: "galor-private-cloud-01",
                    executor=fixture.executor,
                )
            requarantined = json.loads(
                (fixture.receipt / "forward-state.json").read_text()
            )
            self.assertEqual(requarantined["rollback_outcome"], "quarantined")
            self.assertEqual(len(list((fixture.receipt / "quarantine").glob("*"))), 2)

    def test_cross_filesystem_quarantine_preserves_unknown_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "receipt"
            receipt.mkdir(mode=0o700)
            source_parent = root / "source"
            source_parent.mkdir(mode=0o700)
            source = source_parent / "unknown.conf"
            source.write_bytes(b"unknown-cross-filesystem-data")
            source.chmod(0o640)
            source_status = source.lstat()
            source_identity = (source_status.st_dev, source_status.st_ino)
            real_rename = self.rollback.os.rename

            def cross_device_rename(
                source_name,
                destination_name,
                *,
                src_dir_fd=None,
                dst_dir_fd=None,
            ):
                if (
                    source_name == "unknown.conf"
                    and src_dir_fd != dst_dir_fd
                ):
                    raise OSError(errno.EXDEV, "different filesystems")
                return real_rename(
                    source_name,
                    destination_name,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                )

            parent_descriptor = os.open(source_parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(
                    self.rollback.os,
                    "rename",
                    side_effect=cross_device_rename,
                ):
                    quarantined = self.rollback._quarantine_at(
                        receipt,
                        "/etc/lil-tweak-cloudflared/unknown.conf",
                        parent_descriptor,
                        "unknown.conf",
                        source_identity,
                    )
            finally:
                os.close(parent_descriptor)

            self.assertIs(quarantined, True)
            self.assertFalse(source.exists())
            evidence = list((receipt / "quarantine").iterdir())
            self.assertEqual(len(evidence), 1)
            self.assertEqual(evidence[0].read_bytes(), b"unknown-cross-filesystem-data")
            self.assertEqual(stat.S_IMODE(evidence[0].stat().st_mode), 0o640)
            self.assertEqual(evidence[0].stat().st_uid, source_status.st_uid)
            self.assertEqual(evidence[0].stat().st_gid, source_status.st_gid)

    def test_cross_filesystem_quarantine_copies_tree_without_following_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "receipt"
            receipt.mkdir(mode=0o700)
            source_parent = root / "source"
            source_parent.mkdir(mode=0o700)
            source = source_parent / "unknown-tree"
            nested = source / "nested"
            nested.mkdir(parents=True, mode=0o750)
            (nested / "data.txt").write_bytes(b"nested-evidence")
            outside = root / "outside.txt"
            outside.write_bytes(b"must-remain-untouched")
            os.symlink(outside, source / "outside-link")
            source_status = source.lstat()
            real_rename = self.rollback.os.rename

            def cross_device_rename(
                source_name,
                destination_name,
                *,
                src_dir_fd=None,
                dst_dir_fd=None,
            ):
                if source_name == "unknown-tree" and src_dir_fd != dst_dir_fd:
                    raise OSError(errno.EXDEV, "different filesystems")
                return real_rename(
                    source_name,
                    destination_name,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                )

            parent_descriptor = os.open(source_parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(
                    self.rollback.os,
                    "rename",
                    side_effect=cross_device_rename,
                ):
                    quarantined = self.rollback._quarantine_at(
                        receipt,
                        "/etc/lil-tweak-cloudflared/unknown-tree",
                        parent_descriptor,
                        "unknown-tree",
                        (source_status.st_dev, source_status.st_ino),
                    )
            finally:
                os.close(parent_descriptor)

            self.assertIs(quarantined, True)
            self.assertFalse(source.exists())
            evidence = list((receipt / "quarantine").iterdir())
            self.assertEqual(len(evidence), 1)
            self.assertEqual(
                (evidence[0] / "nested/data.txt").read_bytes(),
                b"nested-evidence",
            )
            copied_link = evidence[0] / "outside-link"
            self.assertTrue(copied_link.is_symlink())
            self.assertEqual(os.readlink(copied_link), str(outside))
            self.assertEqual(outside.read_bytes(), b"must-remain-untouched")

    def test_cross_filesystem_quarantine_never_publishes_partial_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "receipt"
            receipt.mkdir(mode=0o700)
            source_parent = root / "source"
            source_parent.mkdir(mode=0o700)
            source = source_parent / "unknown.conf"
            source.write_bytes(b"copy-must-fail-closed")
            source_status = source.lstat()
            real_rename = self.rollback.os.rename

            def cross_device_rename(
                source_name,
                destination_name,
                *,
                src_dir_fd=None,
                dst_dir_fd=None,
            ):
                if source_name == "unknown.conf" and src_dir_fd != dst_dir_fd:
                    raise OSError(errno.EXDEV, "different filesystems")
                return real_rename(
                    source_name,
                    destination_name,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                )

            parent_descriptor = os.open(source_parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with (
                    patch.object(
                        self.rollback.os,
                        "rename",
                        side_effect=cross_device_rename,
                    ),
                    patch.object(self.rollback.os, "write", return_value=0),
                    self.assertRaisesRegex(
                        self.rollback.RollbackError,
                        "^rollback_quarantine_failed$",
                    ),
                ):
                    self.rollback._quarantine_at(
                        receipt,
                        "/etc/lil-tweak-cloudflared/unknown.conf",
                        parent_descriptor,
                        "unknown.conf",
                        (source_status.st_dev, source_status.st_ino),
                    )
            finally:
                os.close(parent_descriptor)

            self.assertEqual(source.read_bytes(), b"copy-must-fail-closed")
            self.assertEqual(list((receipt / "quarantine").iterdir()), [])

    def test_cross_filesystem_authorized_file_is_deleted_without_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "receipt"
            receipt.mkdir(mode=0o700)
            source_parent = root / "source"
            source_parent.mkdir(mode=0o700)
            source = source_parent / "authorized.conf"
            source.write_bytes(b"authorized-release-file")
            source.chmod(0o640)
            source_status = source.lstat()
            real_rename = self.rollback.os.rename

            def cross_device_rename(
                source_name,
                destination_name,
                *,
                src_dir_fd=None,
                dst_dir_fd=None,
            ):
                if source_name == "authorized.conf" and src_dir_fd != dst_dir_fd:
                    raise OSError(errno.EXDEV, "different filesystems")
                return real_rename(
                    source_name,
                    destination_name,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                )

            descriptor = {
                "type": "regular",
                "mode": "0640",
                "uid": source_status.st_uid,
                "gid": source_status.st_gid,
                "size": source_status.st_size,
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            }
            parent_descriptor = os.open(source_parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(
                    self.rollback.os,
                    "rename",
                    side_effect=cross_device_rename,
                ):
                    quarantined = self.rollback._quarantine_at(
                        receipt,
                        "/etc/lil-tweak-cloudflared/authorized.conf",
                        parent_descriptor,
                        "authorized.conf",
                        (source_status.st_dev, source_status.st_ino),
                        delete_if_matches=descriptor,
                    )
            finally:
                os.close(parent_descriptor)

            self.assertIs(quarantined, False)
            self.assertFalse(source.exists())
            self.assertEqual(list((receipt / "quarantine").iterdir()), [])

    def test_untracked_child_in_new_managed_directory_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            unexpected = fixture.root / "etc/lil-tweak-cloudflared/untracked.txt"
            unexpected.parent.mkdir(parents=True)
            unexpected.write_bytes(b"unknown")

            with self.assertRaisesRegex(self.rollback.RollbackError, "rollback_drift_quarantined"):
                self.rollback.restore_receipt(
                    fixture.receipt,
                    digest,
                    root=fixture.root,
                    hostname_getter=lambda: "galor-private-cloud-01",
                    executor=fixture.executor,
                )

            quarantined = list((fixture.receipt / "quarantine").glob("*"))
            self.assertEqual(len(quarantined), 1)
            self.assertTrue(quarantined[0].is_dir())
            self.assertEqual((quarantined[0] / "untracked.txt").read_bytes(), b"unknown")

    def test_restore_never_follows_a_swapped_managed_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            managed = fixture.root / "var/lib/lil-tweak/.config/lil-tweak"
            displaced = fixture.root / "var/lib/lil-tweak/.config/lil-tweak-displaced"
            unrelated = fixture.root / "unrelated"
            unrelated.mkdir(mode=0o777)
            unrelated.chmod(0o777)
            managed.rename(displaced)
            os.symlink(unrelated, managed)

            with self.assertRaisesRegex(self.rollback.RollbackError, "rollback_drift_quarantined"):
                self.rollback.restore_receipt(
                    fixture.receipt,
                    digest,
                    root=fixture.root,
                    hostname_getter=lambda: "galor-private-cloud-01",
                    executor=fixture.executor,
                )

            self.assertEqual(stat.S_IMODE(unrelated.stat().st_mode), 0o777)
            self.assertFalse(managed.is_symlink())
            self.assertIn(b"canary-not-in-manifest", (managed / "core.env").read_bytes())

    def test_object_intent_requires_the_exact_captured_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            fixture.executor.objects[("network", "lil-tweak-private")] = {
                "kind": "network",
                "name": "lil-tweak-private",
                "state": "present",
                "id": "independent-network-id",
                "identity": "lil-tweak-private",
            }

            with self.assertRaisesRegex(
                self.rollback.RollbackError,
                "^host_state_invalid$",
            ):
                self.rollback.authorize_object(
                    fixture.receipt,
                    digest,
                    "network",
                    "lil-tweak-private",
                    "lil-tweak-private",
                    executor=fixture.executor,
                )

            forward = json.loads(
                (fixture.receipt / "forward-state.json").read_text()
            )
            self.assertEqual(forward["objects"], {})
            self.assertEqual(fixture.executor.actions, [])

    def test_object_finalization_atomically_binds_the_exact_created_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            self.rollback.authorize_object(
                fixture.receipt,
                digest,
                "network",
                "lil-tweak-private",
                "lil-tweak-private",
                executor=fixture.executor,
            )
            key = "network:lil-tweak-private"
            intent = {
                "kind": "network",
                "name": "lil-tweak-private",
                "state": "intent",
                "id": None,
                "identity": "lil-tweak-private",
            }
            self.assertEqual(
                json.loads((fixture.receipt / "forward-state.json").read_text())[
                    "objects"
                ][key],
                intent,
            )
            fixture.executor.objects[("network", "lil-tweak-private")] = {
                "kind": "network",
                "name": "lil-tweak-private",
                "state": "present",
                "id": "release-network-id",
                "identity": "lil-tweak-private",
            }

            with (
                patch.object(
                    self.rollback,
                    "_replace_canonical",
                    side_effect=self.rollback.RollbackError("receipt_write_failed"),
                ),
                self.assertRaisesRegex(
                    self.rollback.RollbackError,
                    "^receipt_write_failed$",
                ),
            ):
                self.rollback.finalize_object(
                    fixture.receipt,
                    digest,
                    "network",
                    "lil-tweak-private",
                    "lil-tweak-private",
                    executor=fixture.executor,
                )
            self.assertEqual(
                json.loads((fixture.receipt / "forward-state.json").read_text())[
                    "objects"
                ][key],
                intent,
            )

            self.rollback.finalize_object(
                fixture.receipt,
                digest,
                "network",
                "lil-tweak-private",
                "lil-tweak-private",
                executor=fixture.executor,
            )
            self.assertEqual(
                json.loads((fixture.receipt / "forward-state.json").read_text())[
                    "objects"
                ][key],
                {
                    **intent,
                    "state": "finalized",
                    "id": "release-network-id",
                },
            )

    def test_rollback_removes_only_an_exact_finalized_object_id(self) -> None:
        cases = ("intent", "replaced", "exact")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                fixture = RollbackFixture(Path(temporary), self.rollback)
                digest = fixture.capture()
                self.rollback.authorize_object(
                    fixture.receipt,
                    digest,
                    "network",
                    "lil-tweak-private",
                    "lil-tweak-private",
                    executor=fixture.executor,
                )
                fixture.executor.objects[("network", "lil-tweak-private")] = {
                    "kind": "network",
                    "name": "lil-tweak-private",
                    "state": "present",
                    "id": "owned-network-id",
                    "identity": "lil-tweak-private",
                }
                if case != "intent":
                    self.rollback.finalize_object(
                        fixture.receipt,
                        digest,
                        "network",
                        "lil-tweak-private",
                        "lil-tweak-private",
                        executor=fixture.executor,
                    )
                if case == "replaced":
                    fixture.executor.objects[("network", "lil-tweak-private")][
                        "id"
                    ] = "replacement-network-id"

                if case == "exact":
                    self.rollback.restore_receipt(
                        fixture.receipt,
                        digest,
                        root=fixture.root,
                        hostname_getter=lambda: "galor-private-cloud-01",
                        executor=fixture.executor,
                    )
                    self.assertEqual(
                        fixture.executor.removed_object_ids,
                        ["owned-network-id"],
                    )
                    continue

                with self.assertRaisesRegex(
                    self.rollback.RollbackError,
                    "^rollback_incomplete$",
                ):
                    self.rollback.restore_receipt(
                        fixture.receipt,
                        digest,
                        root=fixture.root,
                        hostname_getter=lambda: "galor-private-cloud-01",
                        executor=fixture.executor,
                    )
                self.assertEqual(fixture.executor.actions, [])
                self.assertEqual(fixture.executor.removed_object_ids, [])
                if case == "intent":
                    with self.assertRaisesRegex(
                        self.rollback.RollbackError,
                        "^transaction_incomplete$",
                    ):
                        self.rollback.mark_completed(fixture.receipt, digest)

    def test_authorized_forward_objects_are_removed_but_retained_new_volumes_block_clean_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            references = {
                "core": "registry.example/lil-tweak/core@sha256:" + "1" * 64,
                "postgres": "registry.example/postgres@sha256:" + "2" * 64,
                "runner": "registry.example/lil-tweak/runner@sha256:" + "3" * 64,
            }
            self.rollback.authorize_images(
                fixture.receipt,
                digest,
                references,
                executor=fixture.executor,
            )
            fixture.executor.images[references["runner"]] = {
                "reference": references["runner"],
                "state": "present",
                "id": "c" * 64,
                "identity": references["runner"],
            }
            staged_config = fixture.root / "staged-config.yml"
            staged_config.write_bytes(b"release-config\n")
            staged_config.chmod(0o600)
            self.rollback.authorize_file(
                fixture.receipt,
                digest,
                "/etc/lil-tweak-cloudflared/config.yml",
                staged_config,
                0o640,
                os.geteuid(),
                os.getegid(),
            )
            release_config = fixture.root / "etc/lil-tweak-cloudflared/config.yml"
            release_config.parent.mkdir(parents=True)
            release_config.write_bytes(staged_config.read_bytes())
            release_config.chmod(0o640)
            authorized = (
                ("container", "lil-tweak-core", references["core"]),
                ("container", "lil-tweak-postgres", references["postgres"]),
                ("network", "lil-tweak-private", "lil-tweak-private"),
                ("secret", "lil-tweak-postgres-admin-password", "lil-tweak-postgres-admin-password"),
            )
            for kind, name, identity in authorized:
                self.rollback.authorize_object(
                    fixture.receipt,
                    digest,
                    kind,
                    name,
                    identity,
                    executor=fixture.executor,
                )
                fixture.executor.objects[(kind, name)] = {
                    "kind": kind,
                    "name": name,
                    "state": "present",
                    "id": f"id-{name}",
                    "identity": identity,
                }
                self.rollback.finalize_object(
                    fixture.receipt,
                    digest,
                    kind,
                    name,
                    identity,
                    executor=fixture.executor,
                )
            for name in ("lil-tweak-data", "lil-tweak-postgres-data"):
                fixture.executor.objects[("volume", name)] = {
                    "kind": "volume",
                    "name": name,
                    "state": "present",
                    "id": f"id-{name}",
                    "identity": name,
                }

            with self.assertRaisesRegex(self.rollback.RollbackError, "rollback_incomplete"):
                self.rollback.restore_receipt(
                    fixture.receipt,
                    digest,
                    root=fixture.root,
                    hostname_getter=lambda: "galor-private-cloud-01",
                    executor=fixture.executor,
                )

            removals = [value for value in fixture.executor.actions if value.startswith("remove:")]
            self.assertEqual(
                removals,
                [
                    "remove:container:lil-tweak-core",
                    "remove:container:lil-tweak-postgres",
                    "remove:network:lil-tweak-private",
                    "remove:secret:lil-tweak-postgres-admin-password",
                    f"remove:image:{references['runner']}",
                ],
            )
            for kind, name, _identity in authorized:
                self.assertEqual(fixture.executor.objects[(kind, name)]["state"], "absent")
            for name in ("lil-tweak-data", "lil-tweak-postgres-data"):
                self.assertEqual(
                    fixture.executor.objects[("volume", name)]["state"], "present"
                )
            self.assertFalse(release_config.exists())
            self.assertIn("restore:units", fixture.executor.actions)
            self.assertIn("verify:restored", fixture.executor.actions)
            forward = json.loads(
                (fixture.receipt / "forward-state.json").read_text()
            )
            self.assertEqual(forward["rollback_outcome"], "retained-data")

            removal_count = len(removals)
            with self.assertRaisesRegex(
                self.rollback.RollbackError, "^rollback_incomplete$"
            ):
                self.rollback.restore_receipt(
                    fixture.receipt,
                    digest,
                    root=fixture.root,
                    hostname_getter=lambda: "galor-private-cloud-01",
                    executor=fixture.executor,
                )
            self.assertEqual(
                len(
                    [
                        value
                        for value in fixture.executor.actions
                        if value.startswith("remove:")
                    ]
                ),
                removal_count,
            )

    def test_baseline_podman_objects_must_still_match_exactly(self) -> None:
        image = "registry.example/lil-tweak/core@sha256:" + "1" * 64
        for replacement in (
            {
                "kind": "container",
                "name": "lil-tweak-core",
                "state": "absent",
                "id": None,
                "identity": None,
            },
            {
                "kind": "container",
                "name": "lil-tweak-core",
                "state": "present",
                "id": "replacement-id",
                "identity": image,
            },
        ):
            with self.subTest(replacement=replacement["state"] + str(replacement["id"])):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = RollbackFixture(Path(temporary), self.rollback)
                    fixture.executor.objects[("container", "lil-tweak-core")] = {
                        "kind": "container",
                        "name": "lil-tweak-core",
                        "state": "present",
                        "id": "baseline-id",
                        "identity": image,
                    }
                    digest = fixture.capture()
                    fixture.executor.objects[("container", "lil-tweak-core")] = replacement

                    with self.assertRaisesRegex(self.rollback.RollbackError, "rollback_incomplete"):
                        self.rollback.restore_receipt(
                            fixture.receipt,
                            digest,
                            root=fixture.root,
                            hostname_getter=lambda: "galor-private-cloud-01",
                            executor=fixture.executor,
                        )
                    self.assertEqual(fixture.executor.actions, [])

    def test_image_ledger_retains_cached_image_and_removes_only_new_exact_refs(self) -> None:
        references = {
            "core": "registry.example/lil-tweak/core@sha256:" + "1" * 64,
            "postgres": "registry.example/postgres@sha256:" + "2" * 64,
            "runner": "registry.example/lil-tweak/runner@sha256:" + "3" * 64,
        }
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            cached_id = "a" * 64
            fixture.executor.images[references["core"]] = {
                "reference": references["core"],
                "state": "present",
                "id": cached_id,
                "identity": references["core"],
            }

            self.rollback.authorize_images(
                fixture.receipt,
                digest,
                references,
                executor=fixture.executor,
            )
            forward = json.loads(
                (fixture.receipt / "forward-state.json").read_text()
            )
            self.assertEqual(
                forward["images"],
                {
                    "core": {
                        "reference": references["core"],
                        "state": "present",
                        "id": cached_id,
                        "identity": references["core"],
                    },
                    "postgres": {
                        "reference": references["postgres"],
                        "state": "absent",
                        "id": None,
                        "identity": None,
                    },
                    "runner": {
                        "reference": references["runner"],
                        "state": "absent",
                        "id": None,
                        "identity": None,
                    },
                },
            )

            for role, reference in references.items():
                fixture.executor.images[reference] = {
                    "reference": reference,
                    "state": "present",
                    "id": {
                        "core": cached_id,
                        "postgres": "b" * 64,
                        "runner": "c" * 64,
                    }[role],
                    "identity": reference,
                }

            # Authorization is retry-safe and must not recapture post-pull state.
            self.rollback.authorize_images(
                fixture.receipt,
                digest,
                references,
                executor=fixture.executor,
            )
            self.assertEqual(
                json.loads((fixture.receipt / "forward-state.json").read_text())["images"],
                forward["images"],
            )
            changed_references = dict(references)
            changed_references["runner"] = (
                "registry.example/lil-tweak/runner@sha256:" + "4" * 64
            )
            with self.assertRaisesRegex(
                self.rollback.RollbackError, "^forward_state_invalid$"
            ):
                self.rollback.authorize_images(
                    fixture.receipt,
                    digest,
                    changed_references,
                    executor=fixture.executor,
                )

            self.rollback.restore_receipt(
                fixture.receipt,
                digest,
                root=fixture.root,
                hostname_getter=lambda: "galor-private-cloud-01",
                executor=fixture.executor,
            )

            self.assertEqual(
                fixture.executor.images[references["core"]]["id"], cached_id
            )
            self.assertEqual(
                fixture.executor.images[references["postgres"]]["state"], "absent"
            )
            self.assertEqual(
                fixture.executor.images[references["runner"]]["state"], "absent"
            )
            self.assertEqual(
                [
                    action
                    for action in fixture.executor.actions
                    if action.startswith("remove:image:")
                ],
                [
                    f"remove:image:{references['postgres']}",
                    f"remove:image:{references['runner']}",
                ],
            )

            parsed = self.rollback._parser().parse_args(
                [
                    "authorize-images",
                    "--receipt",
                    str(fixture.receipt),
                    "--expected-manifest-sha256",
                    digest,
                    "--core-reference",
                    references["core"],
                    "--postgres-reference",
                    references["postgres"],
                    "--runner-reference",
                    references["runner"],
                ]
            )
            self.assertEqual(parsed.command, "authorize-images")
            self.assertEqual(parsed.runner_reference, references["runner"])

    def test_authorize_images_cli_passes_the_exact_three_role_ledger(self) -> None:
        digest = "a" * 64
        receipt = Path(
            "/var/lib/lil-tweak-release-rollback/20260815T120000Z-0123456789ab"
        )
        references = {
            "core": "registry.example/lil-tweak/core@sha256:" + "1" * 64,
            "postgres": "registry.example/postgres@sha256:" + "2" * 64,
            "runner": "registry.example/lil-tweak/runner@sha256:" + "3" * 64,
        }
        arguments = [
            "authorize-images",
            "--receipt",
            str(receipt),
            "--expected-manifest-sha256",
            digest,
            "--core-reference",
            references["core"],
            "--postgres-reference",
            references["postgres"],
            "--runner-reference",
            references["runner"],
        ]
        with (
            patch.object(self.rollback, "_require_production"),
            patch.object(self.rollback, "_require_production_receipt_path"),
            patch.object(self.rollback, "authorize_images") as authorized,
            patch("builtins.print"),
        ):
            self.assertEqual(self.rollback.main(arguments), 0)

        authorized.assert_called_once_with(receipt, digest, references)

    def test_image_identity_mismatch_blocks_all_forward_removals(self) -> None:
        references = {
            "core": "registry.example/lil-tweak/core@sha256:" + "1" * 64,
            "postgres": "registry.example/postgres@sha256:" + "2" * 64,
            "runner": "registry.example/lil-tweak/runner@sha256:" + "3" * 64,
        }
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            baseline_id = "a" * 64
            fixture.executor.images[references["core"]] = {
                "reference": references["core"],
                "state": "present",
                "id": baseline_id,
                "identity": references["core"],
            }
            digest = fixture.capture()
            self.rollback.authorize_images(
                fixture.receipt,
                digest,
                references,
                executor=fixture.executor,
            )
            self.rollback.authorize_object(
                fixture.receipt,
                digest,
                "network",
                "lil-tweak-private",
                "lil-tweak-private",
                executor=fixture.executor,
            )
            fixture.executor.objects[("network", "lil-tweak-private")] = {
                "kind": "network",
                "name": "lil-tweak-private",
                "state": "present",
                "id": "release-network-id",
                "identity": "lil-tweak-private",
            }
            self.rollback.finalize_object(
                fixture.receipt,
                digest,
                "network",
                "lil-tweak-private",
                "lil-tweak-private",
                executor=fixture.executor,
            )
            fixture.executor.images[references["core"]]["id"] = "b" * 64

            with self.assertRaisesRegex(
                self.rollback.RollbackError, "^rollback_incomplete$"
            ):
                self.rollback.restore_receipt(
                    fixture.receipt,
                    digest,
                    root=fixture.root,
                    hostname_getter=lambda: "galor-private-cloud-01",
                    executor=fixture.executor,
                )

            self.assertEqual(
                [action for action in fixture.executor.actions if action.startswith("remove:")],
                [],
            )
            self.assertEqual(
                fixture.executor.objects[("network", "lil-tweak-private")]["state"],
                "present",
            )

    def test_new_image_removal_failure_is_content_free_and_never_forced(self) -> None:
        references = {
            "core": "registry.example/lil-tweak/core@sha256:" + "1" * 64,
            "postgres": "registry.example/postgres@sha256:" + "2" * 64,
            "runner": "registry.example/lil-tweak/runner@sha256:" + "3" * 64,
        }
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            self.rollback.authorize_images(
                fixture.receipt,
                digest,
                references,
                executor=fixture.executor,
            )
            runner = references["runner"]
            fixture.executor.images[runner] = {
                "reference": runner,
                "state": "present",
                "id": "c" * 64,
                "identity": runner,
            }
            fixture.executor.image_removal_error = self.rollback.RollbackError(
                "podman_restore_failed"
            )

            with self.assertRaisesRegex(
                self.rollback.RollbackError, "^podman_restore_failed$"
            ):
                self.rollback.restore_receipt(
                    fixture.receipt,
                    digest,
                    root=fixture.root,
                    hostname_getter=lambda: "galor-private-cloud-01",
                    executor=fixture.executor,
                )
            self.assertEqual(fixture.executor.images[runner]["state"], "present")
            self.assertEqual(
                [
                    action
                    for action in fixture.executor.actions
                    if action.startswith("remove:image:")
                ],
                [f"remove:image:{runner}"],
            )

    def test_image_authorization_failure_writes_no_partial_ledger(self) -> None:
        references = {
            "core": "registry.example/lil-tweak/core@sha256:" + "1" * 64,
            "postgres": "registry.example/postgres@sha256:" + "2" * 64,
            "runner": "registry.example/lil-tweak/runner@sha256:" + "3" * 64,
        }
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            current_image = fixture.executor.current_image

            def fail_second_inspection(reference):
                if reference == references["postgres"]:
                    raise self.rollback.RollbackError("host_state_command_failed")
                return current_image(reference)

            with (
                patch.object(
                    fixture.executor,
                    "current_image",
                    side_effect=fail_second_inspection,
                ),
                self.assertRaisesRegex(
                    self.rollback.RollbackError, "^host_state_command_failed$"
                ),
            ):
                self.rollback.authorize_images(
                    fixture.receipt,
                    digest,
                    references,
                    executor=fixture.executor,
                )

            self.assertEqual(
                json.loads((fixture.receipt / "forward-state.json").read_text())["images"],
                {},
            )

    def test_system_executor_uses_exact_object_identity_templates(self) -> None:
        executor = self.rollback.SystemExecutor()
        executor.service_uid = os.geteuid()
        volume_tuple = (
            "lil-tweak-data|local|local|"
            "/var/lib/containers/storage/volumes/lil-tweak-data/_data|"
            "2026-08-15T12:00:00Z"
        )
        cases = (
            (
                "container",
                "lil-tweak-core",
                "container-id|registry.example/lil-tweak/core@sha256:" + "1" * 64,
                "{{.Id}}|{{.ImageName}}",
                "container-id",
                "registry.example/lil-tweak/core@sha256:" + "1" * 64,
            ),
            (
                "network",
                "lil-tweak-private",
                "network-id|lil-tweak-private",
                "{{.ID}}|{{.Name}}",
                "network-id",
                "lil-tweak-private",
            ),
            (
                "volume",
                "lil-tweak-data",
                volume_tuple,
                "{{.Name}}|{{.Driver}}|{{.Scope}}|{{.Mountpoint}}|{{.CreatedAt}}",
                hashlib.sha256(volume_tuple.encode()).hexdigest(),
                "lil-tweak-data",
            ),
            (
                "secret",
                "lil-tweak-postgres-admin-password",
                "secret-id|lil-tweak-postgres-admin-password",
                "{{.ID}}|{{.Spec.Name}}",
                "secret-id",
                "lil-tweak-postgres-admin-password",
            ),
        )
        for kind, name, output, expected_template, expected_id, expected_identity in cases:
            with self.subTest(kind=kind):
                calls = []

                def command(arguments, **_kwargs):
                    calls.append(arguments)
                    if arguments[:3] == ["podman", kind, "exists"]:
                        return subprocess.CompletedProcess(arguments, 0, "", "")
                    return subprocess.CompletedProcess(arguments, 0, output + "\n", "")

                executor._command = command
                observed = executor.current_object(kind, name)
                self.assertEqual(observed["id"], expected_id)
                self.assertEqual(observed["identity"], expected_identity)
                inspect = next(arguments for arguments in calls if "inspect" in arguments)
                self.assertEqual(inspect[4], expected_template)
                if kind == "volume":
                    self.assertNotIn("StorageID", inspect[4])

        recreated_tuple = volume_tuple.rsplit("|", 1)[0] + "|2026-08-15T12:00:01Z"
        executor._command = lambda arguments, **_kwargs: subprocess.CompletedProcess(
            arguments,
            0,
            "" if arguments[:3] == ["podman", "volume", "exists"] else recreated_tuple + "\n",
            "",
        )
        recreated = executor.current_object("volume", "lil-tweak-data")
        self.assertNotEqual(
            recreated["id"],
            hashlib.sha256(volume_tuple.encode()).hexdigest(),
        )
        self.assertEqual(recreated["identity"], "lil-tweak-data")

    def test_system_executor_revalidates_and_removes_only_by_exact_object_id(self) -> None:
        cases = (
            (
                "container",
                "lil-tweak-core",
                "container-id",
                "registry.example/lil-tweak/core@sha256:" + "1" * 64,
                "rm",
            ),
            (
                "network",
                "lil-tweak-private",
                "network-id",
                "lil-tweak-private",
                "remove",
            ),
            (
                "secret",
                "lil-tweak-postgres-admin-password",
                "secret-id",
                "lil-tweak-postgres-admin-password",
                "rm",
            ),
        )
        for kind, name, object_id, identity, action in cases:
            with self.subTest(kind=kind):
                executor = self.rollback.SystemExecutor()
                executor.service_uid = os.geteuid()
                entry = {
                    "kind": kind,
                    "name": name,
                    "state": "present",
                    "id": object_id,
                    "identity": identity,
                }
                absent = {
                    "kind": kind,
                    "name": name,
                    "state": "absent",
                    "id": None,
                    "identity": None,
                }
                commands = []
                executor.current_object = Mock(side_effect=[dict(entry), absent])
                executor._command = lambda arguments, **_kwargs: (
                    commands.append(arguments)
                    or subprocess.CompletedProcess(arguments, 0, "", "")
                )
                executor.remove_object(entry)
                self.assertEqual(
                    commands,
                    [["podman", kind, action, object_id]],
                )

                commands.clear()
                executor.current_object = lambda _kind, _name: {
                    **entry,
                    "id": f"replacement-{object_id}",
                }
                with self.assertRaisesRegex(
                    self.rollback.RollbackError,
                    "^podman_restore_failed$",
                ):
                    executor.remove_object(entry)
                self.assertEqual(commands, [])

                with self.assertRaisesRegex(
                    self.rollback.RollbackError,
                    "^podman_restore_failed$",
                ):
                    executor.remove_object({**entry, "id": ""})

    def test_quadlet_stop_removed_containers_do_not_block_remaining_restore(self) -> None:
        references = {
            "lil-tweak-core": (
                "registry.example/lil-tweak/core@sha256:" + "1" * 64
            ),
            "lil-tweak-postgres": (
                "registry.example/postgres@sha256:" + "2" * 64
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            authorized = (
                ("container", "lil-tweak-core", references["lil-tweak-core"]),
                (
                    "container",
                    "lil-tweak-postgres",
                    references["lil-tweak-postgres"],
                ),
                ("network", "lil-tweak-private", "lil-tweak-private"),
                (
                    "secret",
                    "lil-tweak-postgres-admin-password",
                    "lil-tweak-postgres-admin-password",
                ),
            )
            for kind, name, identity in authorized:
                self.rollback.authorize_object(
                    fixture.receipt,
                    digest,
                    kind,
                    name,
                    identity,
                    executor=fixture.executor,
                )
                fixture.executor.objects[(kind, name)] = {
                    "kind": kind,
                    "name": name,
                    "state": "present",
                    "id": f"owned-{kind}-id",
                    "identity": identity,
                }
                self.rollback.finalize_object(
                    fixture.receipt,
                    digest,
                    kind,
                    name,
                    identity,
                    executor=fixture.executor,
                )

            def quadlet_stop():
                fixture.executor.actions.extend(
                    ["stop:tunnel", "stop:core", "stop:postgres", "stop:network"]
                )
                for name in references:
                    fixture.executor.objects[("container", name)] = {
                        "kind": "container",
                        "name": name,
                        "state": "absent",
                        "id": None,
                        "identity": None,
                    }

            def podman_command(arguments, **_kwargs):
                object_id = arguments[-1]
                matches = [
                    (key, value)
                    for key, value in fixture.executor.objects.items()
                    if value.get("id") == object_id
                ]
                self.assertEqual(len(matches), 1)
                (kind, name), _value = matches[0]
                fixture.executor.actions.append(f"remove-by-id:{kind}:{object_id}")
                fixture.executor.objects[(kind, name)] = {
                    "kind": kind,
                    "name": name,
                    "state": "absent",
                    "id": None,
                    "identity": None,
                }
                return subprocess.CompletedProcess(arguments, 0, "", "")

            fixture.executor.stop_for_restore = quadlet_stop
            fixture.executor._command = podman_command
            fixture.executor.remove_object = (
                self.rollback.SystemExecutor.remove_object.__get__(
                    fixture.executor,
                    type(fixture.executor),
                )
            )

            self.rollback.restore_receipt(
                fixture.receipt,
                digest,
                root=fixture.root,
                hostname_getter=lambda: "galor-private-cloud-01",
                executor=fixture.executor,
            )

            self.assertEqual(
                [
                    action
                    for action in fixture.executor.actions
                    if action.startswith("remove-by-id:")
                ],
                [
                    "remove-by-id:network:owned-network-id",
                    "remove-by-id:secret:owned-secret-id",
                ],
            )
            self.assertIn("restore:units", fixture.executor.actions)
            self.assertIn("verify:restored", fixture.executor.actions)

    def test_system_executor_uses_absolute_tools_and_exact_empty_environments(self) -> None:
        executor = self.rollback.SystemExecutor()
        executor.service_uid = 1234
        calls: list[tuple[list[str], dict[str, object]]] = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch.object(self.rollback.subprocess, "run", side_effect=run):
            executor._command(["systemctl", "daemon-reload"])
            executor._command(
                ["podman", "image", "exists", "reviewed-reference"],
                user=True,
            )

        root_command, root_options = calls[0]
        self.assertEqual(root_command, ["/usr/bin/systemctl", "daemon-reload"])
        self.assertEqual(
            root_options["env"],
            {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        self.assertEqual(root_options["cwd"], "/")

        user_command, user_options = calls[1]
        self.assertEqual(
            user_command,
            [
                "/usr/sbin/runuser",
                "--user",
                "lil-tweak",
                "--",
                "/usr/bin/env",
                "-i",
                "HOME=/var/lib/lil-tweak",
                "USER=lil-tweak",
                "LOGNAME=lil-tweak",
                "PATH=/usr/bin:/bin",
                "LC_ALL=C",
                "XDG_RUNTIME_DIR=/run/user/1234",
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1234/bus",
                "/usr/bin/podman",
                "image",
                "exists",
                "reviewed-reference",
            ],
        )
        self.assertEqual(user_options["env"], root_options["env"])
        self.assertEqual(user_options["cwd"], "/")

    def test_system_executor_rejects_an_unverified_existing_identity_before_queries(self) -> None:
        account = SimpleNamespace(
            pw_uid=0,
            pw_gid=0,
            pw_dir="/var/lib/lil-tweak",
            pw_shell="/usr/sbin/nologin",
        )
        calls: list[tuple[list[str], dict[str, object]]] = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 1, "", "")

        with (
            patch.object(self.rollback.pwd, "getpwnam", return_value=account),
            patch.object(self.rollback.subprocess, "run", side_effect=run),
            self.assertRaisesRegex(
                self.rollback.RollbackError,
                "^host_identity_invalid$",
            ),
        ):
            self.rollback.SystemExecutor()

        self.assertEqual(len(calls), 1)
        command, options = calls[0]
        self.assertEqual(command[:3], ["/usr/bin/python3", "-I", "-B"])
        self.assertEqual(command[-2:], ["--user", "lil-tweak"])
        self.assertIn("lil-tweak-host-identity.py", command[3])
        self.assertNotIn("runuser", " ".join(command))
        self.assertEqual(
            options["env"],
            {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        self.assertEqual(options["cwd"], "/")

    def test_system_executor_uses_exact_image_identity_and_nonpruning_removal(self) -> None:
        executor = self.rollback.SystemExecutor()
        executor.service_uid = os.geteuid()
        reference = "registry.example/lil-tweak/runner@sha256:" + "3" * 64
        image_id = "a" * 64
        removed = False
        calls: list[list[str]] = []

        def command(arguments, **_kwargs):
            nonlocal removed
            calls.append(arguments)
            if arguments == ["podman", "image", "exists", reference]:
                return subprocess.CompletedProcess(
                    arguments,
                    1 if removed else 0,
                    "",
                    "",
                )
            if arguments == [
                "podman",
                "image",
                "inspect",
                "--format",
                "{{.Id}}|{{.Digest}}",
                reference,
            ]:
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    f"{image_id}|sha256:{'3' * 64}\n",
                    "",
                )
            if arguments == [
                "podman",
                "image",
                "inspect",
                "--format",
                "{{range .RepoDigests}}{{println .}}{{end}}",
                reference,
            ]:
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    reference + "\n",
                    "",
                )
            if arguments == [
                "podman",
                "image",
                "rm",
                "--no-prune",
                reference,
            ]:
                removed = True
                return subprocess.CompletedProcess(arguments, 0, "", "")
            raise AssertionError(f"unexpected command: {arguments!r}")

        executor._command = command
        observed = executor.current_image(reference)
        self.assertEqual(
            observed,
            {
                "reference": reference,
                "state": "present",
                "id": image_id,
                "identity": reference,
            },
        )
        executor.remove_image(observed)
        self.assertNotIn("--force", calls[-1])
        self.assertEqual(executor.current_image(reference)["state"], "absent")

        def mismatched_digest(arguments, **_kwargs):
            if arguments[:3] == ["podman", "image", "exists"]:
                return subprocess.CompletedProcess(arguments, 0, "", "")
            return subprocess.CompletedProcess(
                arguments,
                0,
                f"{image_id}|sha256:{'4' * 64}\n",
                "",
            )

        executor._command = mismatched_digest
        with self.assertRaisesRegex(
            self.rollback.RollbackError, "^host_state_invalid$"
        ):
            executor.current_image(reference)

        def wrong_repository(arguments, **_kwargs):
            if arguments[:3] == ["podman", "image", "exists"]:
                return subprocess.CompletedProcess(arguments, 0, "", "")
            if arguments[4] == "{{.Id}}|{{.Digest}}":
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    f"{image_id}|sha256:{'3' * 64}\n",
                    "",
                )
            return subprocess.CompletedProcess(
                arguments,
                0,
                "registry.example/other/runner@sha256:" + "3" * 64 + "\n",
                "",
            )

        executor._command = wrong_repository
        with self.assertRaisesRegex(
            self.rollback.RollbackError, "^host_state_invalid$"
        ):
            executor.current_image(reference)

    def test_identity_captures_password_lock_and_canonical_supplementary_groups(self) -> None:
        account = SimpleNamespace(
            pw_uid=1001,
            pw_gid=1001,
            pw_dir="/var/lib/lil-tweak",
            pw_shell="/usr/sbin/nologin",
        )

        def group(group_id):
            return SimpleNamespace(gr_name={1001: "lil-tweak", 27: "sudo"}[group_id])

        with (
            patch.object(self.rollback.pwd, "getpwnam", return_value=account),
            patch.object(self.rollback.grp, "getgrgid", side_effect=group),
            patch.object(self.rollback.os, "getgrouplist", return_value=[27, 1001, 27]),
            patch.object(
                self.rollback.spwd,
                "getspnam",
                return_value=SimpleNamespace(sp_pwdp="!locked-hash"),
            ),
        ):
            identity = self.rollback._identity("lil-tweak")
        self.assertIs(identity["password_locked"], True)
        self.assertEqual(identity["supplementary_groups"], ["sudo"])

        with (
            patch.object(self.rollback.pwd, "getpwnam", return_value=account),
            patch.object(self.rollback.grp, "getgrgid", side_effect=group),
            patch.object(self.rollback.os, "getgrouplist", return_value=[1001]),
            patch.object(
                self.rollback.spwd,
                "getspnam",
                return_value=SimpleNamespace(sp_pwdp="$6$usable-hash"),
            ),
        ):
            self.assertIs(
                self.rollback._identity("lil-tweak")["password_locked"],
                False,
            )

    def test_global_receipt_lock_reuses_inherited_lease_and_blocks_other_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt_parent = Path(temporary) / "rollback-receipts"
            receipt_parent.mkdir(mode=0o700)
            receipt_a = receipt_parent / "receipt-a"
            receipt_b = receipt_parent / "receipt-b"
            receipt_a.mkdir(mode=0o700)
            receipt_b.mkdir(mode=0o700)
            lock_path = receipt_parent / ".transaction.lock"
            lease = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            os.fchmod(lease, 0o600)
            fcntl.flock(lease, fcntl.LOCK_EX)
            try:
                child_source = """
import fcntl
import importlib.util
import os
import pathlib
import sys

spec = importlib.util.spec_from_file_location("rollback_child", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
receipt = pathlib.Path(sys.argv[2])
with module._receipt_lock(receipt):
    with module._receipt_lock(receipt):
        contender = os.open(receipt.parent / ".transaction.lock", os.O_RDWR)
        try:
            try:
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise SystemExit("competing_lock_acquired")
        finally:
            os.close(contender)
print("nested-lease-ok")
"""
                environment = dict(os.environ)
                environment["LIL_TWEAK_ROLLBACK_LEASE_FD"] = str(lease)
                child = subprocess.Popen(
                    [sys.executable, "-c", child_source, str(SCRIPT), str(receipt_b)],
                    env=environment,
                    pass_fds=(lease,),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    stdout, stderr = child.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.communicate()
                    self.fail("inherited rollback lease was not reentrant")
                self.assertEqual(child.returncode, 0, stderr)
                self.assertEqual(stdout.strip(), "nested-lease-ok")
                contender = os.open(lock_path, os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(contender)

                blocking_source = """
import importlib.util
import pathlib
import signal
import sys

signal.alarm(1)
spec = importlib.util.spec_from_file_location("rollback_competitor", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with module._receipt_lock(pathlib.Path(sys.argv[2])):
    raise SystemExit(97)
"""
                competing_environment = dict(os.environ)
                competing_environment.pop("LIL_TWEAK_ROLLBACK_LEASE_FD", None)
                competing = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        blocking_source,
                        str(SCRIPT),
                        str(receipt_a),
                    ],
                    env=competing_environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=3,
                    check=False,
                )
                self.assertLess(competing.returncode, 0)
            finally:
                os.close(lease)

            wrong_path = Path(temporary) / "wrong.lock"
            wrong = os.open(wrong_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                with patch.dict(
                    os.environ,
                    {"LIL_TWEAK_ROLLBACK_LEASE_FD": str(wrong)},
                ):
                    with self.assertRaisesRegex(
                        self.rollback.RollbackError, "receipt_lock_invalid"
                    ):
                        with self.rollback._receipt_lock(receipt_b):
                            pass
            finally:
                os.close(wrong)

    def test_capture_serializes_before_receipt_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt_parent = root / "var/lib/lil-tweak-release-rollback"
            receipt_parent.mkdir(parents=True, mode=0o700)
            held_receipt = receipt_parent / "held-receipt"
            held_receipt.mkdir(mode=0o700)
            output = receipt_parent / "20260815T000001Z-bbbbbbbbbbbb"
            marker = root / "capture-entered"
            child_source = """
import importlib.util
import pathlib
import signal
import sys

signal.alarm(1)
spec = importlib.util.spec_from_file_location("rollback_capture_child", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class MarkerExecutor:
    def capture_state(self):
        pathlib.Path(sys.argv[4]).write_text("entered")
        raise RuntimeError("marker")

try:
    module.capture_receipt(
        output=pathlib.Path(sys.argv[2]),
        source_commit="b" * 40,
        root=pathlib.Path(sys.argv[3]),
        hostname_getter=lambda: "galor-private-cloud-01",
        executor=MarkerExecutor(),
    )
except Exception:
    pass
"""
            environment = dict(os.environ)
            environment.pop("LIL_TWEAK_ROLLBACK_LEASE_FD", None)
            with self.rollback._receipt_lock(held_receipt):
                child = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        child_source,
                        str(SCRIPT),
                        str(output),
                        str(root),
                        str(marker),
                    ],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=3,
                    check=False,
                )
                self.assertLess(child.returncode, 0)
                self.assertFalse(marker.exists())
                self.assertFalse(output.exists())

    def test_lease_exec_holds_verified_lease_for_bounded_child_and_returns_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            child_source = """
import fcntl
import importlib.util
import os
import pathlib
import signal
import sys

signal.alarm(2)
spec = importlib.util.spec_from_file_location("rollback_lease_child", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
receipt = pathlib.Path(sys.argv[2])
with module._receipt_lock(receipt):
    with module._receipt_lock(receipt):
        contender = os.open(receipt.parent / ".transaction.lock", os.O_RDWR)
        try:
            try:
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise SystemExit(97)
        finally:
            os.close(contender)
raise SystemExit(23)
"""
            command = [
                sys.executable,
                "-c",
                child_source,
                str(SCRIPT),
                str(fixture.receipt),
            ]
            self.assertEqual(
                self.rollback.lease_exec(fixture.receipt, digest, command),
                23,
            )
            self.assertEqual(
                self.rollback.lease_exec(
                    fixture.receipt,
                    digest,
                    ["/bin/sh", "-c", "sleep 1 &"],
                ),
                0,
            )
            contender = os.open(
                fixture.receipt.parent / ".transaction.lock",
                os.O_RDWR,
            )
            try:
                try:
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    self.fail("lease-exec leaked the lease into a residual child")
            finally:
                os.close(contender)
            with self.assertRaisesRegex(
                self.rollback.RollbackError, "lease_command_invalid"
            ):
                self.rollback.lease_exec(fixture.receipt, digest, [])

            parsed = self.rollback._parser().parse_args(
                [
                    "lease-exec",
                    "--receipt",
                    str(fixture.receipt),
                    "--expected-manifest-sha256",
                    digest,
                    "--",
                    "/bin/true",
                ]
            )
            self.assertEqual(parsed.command, "lease-exec")
            self.assertEqual(parsed.lease_command, ["--", "/bin/true"])
            with (
                patch.object(self.rollback, "_require_production"),
                patch.object(self.rollback, "_require_production_receipt_path"),
                patch.object(self.rollback, "lease_exec", return_value=29) as leased,
            ):
                self.assertEqual(
                    self.rollback.main(
                        [
                            "lease-exec",
                            "--receipt",
                            str(fixture.receipt),
                            "--expected-manifest-sha256",
                            digest,
                            "--",
                            "/bin/false",
                        ]
                    ),
                    29,
                )
            leased.assert_called_once_with(
                fixture.receipt,
                digest,
                ["/bin/false"],
            )

    def test_lease_exec_terminates_a_detached_process_that_retains_the_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            pid_file = fixture.root / "detached.pid"
            child_source = """
import os
import pathlib
import sys
import time

pid = os.fork()
if pid == 0:
    os.setsid()
    pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
    time.sleep(30)
    os._exit(0)
os._exit(0)
"""
            command = [
                sys.executable,
                "-c",
                child_source,
                str(pid_file),
            ]
            detached_pid: int | None = None
            try:
                self.assertEqual(
                    self.rollback.lease_exec(fixture.receipt, digest, command),
                    0,
                )
                detached_pid = int(pid_file.read_text().strip())
                contender = os.open(
                    fixture.receipt.parent / ".transaction.lock", os.O_RDWR
                )
                try:
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    self.fail("detached child retained the rollback lease")
                finally:
                    os.close(contender)
                with self.assertRaises(ProcessLookupError):
                    os.kill(detached_pid, 0)
            finally:
                if detached_pid is not None:
                    try:
                        os.kill(detached_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_lease_cleanup_does_not_kill_an_independent_waiting_contender(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            fixture.capture()
            marker = fixture.root / "contender.marker"
            child_source = """
import fcntl
import os
import pathlib
import sys

descriptor = os.open(sys.argv[1], os.O_RDWR)
pathlib.Path(sys.argv[2]).write_text("waiting")
fcntl.flock(descriptor, fcntl.LOCK_EX)
pathlib.Path(sys.argv[2]).write_text("acquired")
os.close(descriptor)
"""
            environment = dict(os.environ)
            environment.pop("LIL_TWEAK_ROLLBACK_LEASE_FD", None)
            contender: subprocess.Popen[str] | None = None
            with self.rollback._receipt_lock(fixture.receipt) as descriptor:
                contender = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        child_source,
                        str(fixture.receipt.parent / ".transaction.lock"),
                        str(marker),
                    ],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    if marker.exists() and marker.read_text() == "waiting":
                        break
                    time.sleep(0.01)
                else:
                    contender.kill()
                    self.fail("independent lease contender did not block")
                self.rollback._terminate_residual_lease_holders(descriptor)
                self.assertIsNone(contender.poll())
            assert contender is not None
            _stdout, stderr = contender.communicate(timeout=3)
            self.assertEqual(contender.returncode, 0, stderr)
            self.assertEqual(marker.read_text(), "acquired")

    def test_lease_exec_allows_slow_signal_rollback_to_finish_under_the_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            marker = fixture.root / "signal-marker"
            worker = fixture.root / "slow-rollback.sh"
            worker.write_text(
                "#!/usr/bin/bash\n"
                "set -eu\n"
                "marker=$1\n"
                "finish() {\n"
                "  printf 'rollback-started\\n' >>\"$marker\"\n"
                "  sleep 5.5\n"
                "  printf 'rollback-complete\\n' >>\"$marker\"\n"
                "  exit 143\n"
                "}\n"
                "trap finish TERM INT HUP\n"
                "printf 'ready\\n' >>\"$marker\"\n"
                "while :; do sleep 0.1; done\n"
            )
            worker.chmod(0o700)
            child_source = """
import importlib.util
import pathlib
import sys

spec = importlib.util.spec_from_file_location("rollback_signal_child", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
result = module.lease_exec(
    pathlib.Path(sys.argv[2]),
    sys.argv[3],
    ["/usr/bin/bash", sys.argv[4], sys.argv[5]],
)
raise SystemExit(result)
"""
            environment = dict(os.environ)
            environment.pop("LIL_TWEAK_ROLLBACK_LEASE_FD", None)
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    child_source,
                    str(SCRIPT),
                    str(fixture.receipt),
                    digest,
                    str(worker),
                    str(marker),
                ],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                if marker.exists() and "ready" in marker.read_text():
                    break
                time.sleep(0.02)
            else:
                process.kill()
                self.fail("leased child did not become ready")
            os.kill(process.pid, signal.SIGTERM)
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                if "rollback-started" in marker.read_text():
                    break
                time.sleep(0.02)
            else:
                process.kill()
                self.fail("leased child did not start signal rollback")
            os.kill(process.pid, signal.SIGINT)
            _stdout, stderr = process.communicate(timeout=12)
            self.assertEqual(process.returncode, 143, stderr)
            self.assertEqual(
                marker.read_text().splitlines(),
                ["ready", "rollback-started", "rollback-complete"],
            )

    def test_fresh_host_retains_locked_service_identity_without_reactivating_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            digest = fixture.capture()
            manifest = json.loads((fixture.receipt / "manifest.json").read_text())
            executor = self.rollback.SystemExecutor()
            executor.service_uid = os.geteuid()

            def unit_state(scope, name):
                if name == "user@lil-tweak.service":
                    return {
                        "scope": scope,
                        "name": name,
                        "load_state": "loaded",
                        "unit_file_state": "static",
                        "active_state": "inactive",
                        "sub_state": "dead",
                    }
                return next(
                    dict(item)
                    for item in manifest["units"]
                    if item["scope"] == scope and item["name"] == name
                )

            executor._unit_state = unit_state
            executor._linger_enabled = lambda: False
            executor._command = lambda arguments, **_kwargs: subprocess.CompletedProcess(
                arguments, 0, "", ""
            )
            executor.current_object = lambda kind, name: next(
                dict(item)
                for item in manifest["podman_objects"]
                if item["kind"] == kind and item["name"] == name
            )
            identities = {
                "lil-tweak": {
                    "name": "lil-tweak",
                    "state": "present",
                    "uid": 1001,
                    "gid": 1001,
                    "home": "/var/lib/lil-tweak",
                    "primary_group": "lil-tweak",
                    "shell": "/usr/sbin/nologin",
                    "password_locked": True,
                    "supplementary_groups": [],
                },
                "lil-tweak-tunnel": {
                    "name": "lil-tweak-tunnel",
                    "state": "present",
                    "uid": 1002,
                    "gid": 1002,
                    "home": "/var/lib/lil-tweak-tunnel",
                    "primary_group": "lil-tweak-tunnel",
                    "shell": "/usr/sbin/nologin",
                    "password_locked": True,
                    "supplementary_groups": [],
                },
            }
            with patch.object(self.rollback, "_identity", side_effect=lambda name: identities[name]):
                executor.verify_restored(manifest)

            identities["lil-tweak"]["password_locked"] = False
            with (
                patch.object(self.rollback, "_identity", side_effect=lambda name: identities[name]),
                self.assertRaisesRegex(self.rollback.RollbackError, "rollback_verification_failed"),
            ):
                executor.verify_restored(manifest)
            identities["lil-tweak"]["password_locked"] = True
            identities["lil-tweak"]["supplementary_groups"] = ["sudo"]
            with (
                patch.object(self.rollback, "_identity", side_effect=lambda name: identities[name]),
                self.assertRaisesRegex(self.rollback.RollbackError, "rollback_verification_failed"),
            ):
                executor.verify_restored(manifest)
            identities["lil-tweak"]["supplementary_groups"] = []

            identities["lil-tweak"]["uid"] = 0
            with (
                patch.object(self.rollback, "_identity", side_effect=lambda name: identities[name]),
                self.assertRaisesRegex(self.rollback.RollbackError, "rollback_verification_failed"),
            ):
                executor.verify_restored(manifest)
            identities["lil-tweak"]["uid"] = 1001
            identities["lil-tweak-tunnel"]["uid"] = 1001
            with (
                patch.object(self.rollback, "_identity", side_effect=lambda name: identities[name]),
                self.assertRaisesRegex(self.rollback.RollbackError, "rollback_verification_failed"),
            ):
                executor.verify_restored(manifest)
            identities["lil-tweak-tunnel"]["uid"] = 1002

            executor._linger_enabled = lambda: True
            with (
                patch.object(self.rollback, "_identity", side_effect=lambda name: identities[name]),
                self.assertRaisesRegex(self.rollback.RollbackError, "rollback_verification_failed"),
            ):
                executor.verify_restored(manifest)

    def test_fresh_host_verifies_user_units_before_stopping_user_manager(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = RollbackFixture(Path(temporary), self.rollback)
            fixture.capture()
            manifest = json.loads((fixture.receipt / "manifest.json").read_text())
            executor = self.rollback.SystemExecutor()
            executor.service_uid = os.geteuid()
            commands = []

            def unit_state(scope, name):
                if name in {"podman.socket", "lil-tweak-core.service"}:
                    return {
                        "scope": scope,
                        "name": name,
                        "load_state": "loaded",
                        "unit_file_state": "disabled",
                        "active_state": "inactive",
                        "sub_state": "dead",
                    }
                if name == "user@lil-tweak.service":
                    return {
                        "scope": scope,
                        "name": name,
                        "load_state": "loaded",
                        "unit_file_state": "static",
                        "active_state": "active",
                        "sub_state": "running",
                    }
                return next(
                    dict(item)
                    for item in manifest["units"]
                    if item["scope"] == scope and item["name"] == name
                )

            executor._unit_state = unit_state
            executor._command = lambda arguments, **_kwargs: (
                commands.append(arguments)
                or subprocess.CompletedProcess(arguments, 0, "", "")
            )
            with self.assertRaisesRegex(
                self.rollback.RollbackError, "rollback_verification_failed"
            ):
                executor.restore_units(manifest["units"], manifest["linger"])

            manager_name = f"user@{os.geteuid()}.service"
            self.assertFalse(
                any(manager_name in argument for command in commands for argument in command)
            )

            def allowed_unit_state(scope, name):
                if name == "podman.socket":
                    return {
                        "scope": scope,
                        "name": name,
                        "load_state": "loaded",
                        "unit_file_state": "disabled",
                        "active_state": "inactive",
                        "sub_state": "dead",
                    }
                if name == "user@lil-tweak.service":
                    return {
                        "scope": scope,
                        "name": name,
                        "load_state": "loaded",
                        "unit_file_state": "static",
                        "active_state": "active",
                        "sub_state": "running",
                    }
                return next(
                    dict(item)
                    for item in manifest["units"]
                    if item["scope"] == scope and item["name"] == name
                )

            commands.clear()
            executor._unit_state = allowed_unit_state
            executor.restore_units(manifest["units"], manifest["linger"])
            self.assertTrue(
                any(manager_name in argument for command in commands for argument in command)
            )

    def test_system_executor_propagates_unit_command_failures(self) -> None:
        executor = self.rollback.SystemExecutor()
        executor.service_uid = os.geteuid()
        executor._unit_state = lambda _scope, name: {
            "scope": "system",
            "name": name,
            "load_state": "loaded",
            "unit_file_state": "enabled",
            "active_state": "active",
            "sub_state": "running",
        }
        executor._command = lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, "", "")
        with self.assertRaisesRegex(self.rollback.RollbackError, "host_state_command_failed"):
            executor.stop_for_restore()
        with self.assertRaisesRegex(self.rollback.RollbackError, "host_state_command_failed"):
            executor.restore_units([])

    def test_system_executor_stops_network_before_object_removal(self) -> None:
        executor = self.rollback.SystemExecutor.__new__(self.rollback.SystemExecutor)
        executor.service_uid = 12345
        active = {
            "lil-tweak-core.service",
            "lil-tweak-postgres.service",
            "lil-tweak-network.service",
        }
        commands: list[list[str]] = []

        def unit_state(scope, name):
            if scope == "system":
                return {
                    "scope": scope,
                    "name": name,
                    "load_state": "not-found",
                    "unit_file_state": "disabled",
                    "active_state": "inactive",
                    "sub_state": "dead",
                }
            return {
                "scope": scope,
                "name": name,
                "load_state": "loaded",
                "unit_file_state": "enabled",
                "active_state": "active" if name in active else "inactive",
                "sub_state": "running" if name in active else "dead",
            }

        def command(arguments, **_kwargs):
            commands.append(list(arguments))
            if arguments[:3] == ["systemctl", "--user", "stop"]:
                active.discard(arguments[3])
            return subprocess.CompletedProcess(arguments, 0, "", "")

        executor._unit_state = unit_state
        executor._command = command
        executor.stop_for_restore()

        self.assertEqual(
            [command[-1] for command in commands],
            [
                "lil-tweak-core.service",
                "lil-tweak-postgres.service",
                "lil-tweak-network.service",
            ],
        )

    def test_installer_contracts_bind_one_receipt_and_private_registry_auth(self) -> None:
        core = (ROOT / "scripts/install-digitalocean.sh").read_text()
        tunnel = (ROOT / "scripts/install-cloudflare-tunnel.sh").read_text()
        for source in (core, tunnel):
            self.assertIn("LIL_TWEAK_ROLLBACK_RECEIPT", source)
            self.assertIn("ROLLBACK_MANIFEST_SHA256", source)
            self.assertIn("lil-tweak-rollback.py", source)
            self.assertRegex(source, r"lil-tweak-rollback\.py[^\n]*verify")
            self.assertRegex(source, r"lil-tweak-rollback\.py[^\n]*restore")
            self.assertNotRegex(source, r"rm[^\n]*LIL_TWEAK_ROLLBACK_RECEIPT")
        self.assertIn("LIL_TWEAK_REGISTRY_AUTH_SOURCE", core)
        self.assertIn("--authfile", core)
        self.assertIn("podman image inspect", core)
        markers = [
            'systemctl start "user@${service_uid}.service"',
            'runtime_auth_file="$("${PYTHON}" -I -B "${SERVICE_FILES_HELPER}" stage-runtime-auth',
            '"${PYTHON}" -I -B "${PROJECT_DIR}/scripts/lil-tweak-rollback.py" authorize-images',
            'for image in "${core_image}" "${postgres_image}" "${runner_image}"; do',
            'as_service podman pull --authfile "${runtime_auth_file}" "${image}" >/dev/null',
            'verify_pulled_image "${image}"',
            "remove_runtime_auth || die 'runtime registry authentication cleanup failed'",
            'as_service systemctl --user enable --now podman.socket',
            '"${PYTHON}" -I -B "${SERVICE_FILES_HELPER}" install-tree',
            'as_service systemctl --user daemon-reload',
            'as_service systemctl --user start lil-tweak-postgres.service',
            'as_service systemctl --user restart lil-tweak-core.service',
        ]
        positions = [core.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(core.count('podman pull --authfile "${runtime_auth_file}"'), 1)
        self.assertEqual(core.count(" authorize-images"), 1)
        image_authorization = core.split(" authorize-images", 1)[1].split(
            ">/dev/null", 1
        )[0]
        for role in ("core", "postgres", "runner"):
            self.assertIn(
                f'--{role}-reference "${{{role}_image}}"',
                image_authorization,
            )
        self.assertLess(
            core.index('authorize_release_file "${SERVICE_HOME}/.config/lil-tweak/core.env"'),
            core.index('"${PYTHON}" -I -B "${SERVICE_FILES_HELPER}" install-tree'),
        )
        self.assertIn("lil-tweak-secret-snapshot.py", core)
        image_validation_marker = (
            '"${PYTHON}" -I -B "${SECRET_SNAPSHOT_HELPER}" validate-images'
        )
        self.assertIn(image_validation_marker, core)
        image_validation = core.index(image_validation_marker)
        rollback_verify = core.index(
            '"${PYTHON}" -I -B "${PROJECT_DIR}/scripts/lil-tweak-rollback.py" verify'
        )
        snapshot_call = core.index(
            'runner_image="$("${PYTHON}" -I -B "${SECRET_SNAPSHOT_HELPER}" snapshot'
        )
        unset_source = core.index("unset secrets_source", snapshot_call)
        self.assertLess(image_validation, rollback_verify)
        self.assertLess(rollback_verify, snapshot_call)
        self.assertLess(snapshot_call, unset_source)
        self.assertLess(unset_source, core.index("mutation_started=1"))
        self.assertNotIn("secrets_source", core[unset_source + len("unset secrets_source") :])
        for snapshot_use in (
            'install -D -m 0600 "${core_env_snapshot}"',
            '"${staging_dir}/.config/lil-tweak/core.env" 0600 "${service_uid}" "${service_gid}"',
            '<"${admin_password_snapshot}"',
            'app_password="$(<"${app_password_snapshot}")"',
            'migrator_password="$(<"${migrator_password_snapshot}")"',
        ):
            self.assertIn(snapshot_use, core)
        cleanup_function = core.split("cleanup_release_state() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("local cleanup_status=0", cleanup_function)
        self.assertIn('remove_runtime_auth || cleanup_status=1', cleanup_function)
        self.assertNotIn('rm -f -- "${runtime_auth_file}"', cleanup_function)
        self.assertIn('rm -f -- "${registry_auth_snapshot}" || cleanup_status=1', cleanup_function)
        self.assertIn('rm -rf -- "${secret_snapshot_dir}" || cleanup_status=1', cleanup_function)
        self.assertIn('[[ ! -e "${secret_snapshot_dir}" && ! -L "${secret_snapshot_dir}" ]]', cleanup_function)
        self.assertIn('return "${cleanup_status}"', cleanup_function)
        self.assertNotIn("LIL_TWEAK_REGISTRY_AUTH_SOURCE", (ROOT / "deploy/core.env.example").read_text())
        tunnel_verify = tunnel.index(
            '"${PYTHON}" -I -B "${PROJECT_DIR}/scripts/lil-tweak-rollback.py" verify'
        )
        tunnel_snapshot = tunnel.index(
            'credentials_snapshot="$(mktemp -p /tmp lil-tweak-tunnel-credentials.'
        )
        tunnel_unset = tunnel.index("unset credentials_source", tunnel_snapshot)
        self.assertLess(tunnel_verify, tunnel_snapshot)
        self.assertLess(tunnel_snapshot, tunnel_unset)
        self.assertLess(tunnel_unset, tunnel.index("mutation_started=1"))
        self.assertNotIn(
            "credentials_source",
            tunnel[tunnel_unset + len("unset credentials_source") :],
        )
        self.assertIn('--source "${credentials_source}"', tunnel[:tunnel_unset])
        self.assertIn('--snapshot "${credentials_snapshot}"', tunnel[:tunnel_unset])
        self.assertIn(
            'authorize_release_file "${CONFIG_DIR}/tunnel.json" "${credentials_snapshot}"',
            tunnel,
        )
        tunnel_cleanup = tunnel.split("cleanup_release_state() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn('rm -f -- "${credentials_snapshot}" || cleanup_status=1', tunnel_cleanup)
        self.assertIn('return "${cleanup_status}"', tunnel_cleanup)


if __name__ == "__main__":
    unittest.main()
