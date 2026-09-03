from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts" / "lil-tweak-host-identity.py"


class IdentityFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.etc = root / "etc"
        self.etc.mkdir(mode=0o755)
        self.files = {
            "passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "lil-tweak:x:1001:1001::/var/lib/lil-tweak:/usr/sbin/nologin\n"
                "lil-tweak-tunnel:x:1002:1002::/var/lib/lil-tweak-tunnel:/usr/sbin/nologin\n"
            ),
            "group": "root:x:0:\nshadow:x:42:\nlil-tweak:x:1001:\nlil-tweak-tunnel:x:1002:\n",
            "shadow": "root:*:1:0:99999:7:::\nlil-tweak:!:1:0:99999:7:::\nlil-tweak-tunnel:!:1:0:99999:7:::\n",
            "gshadow": "root:*::\nshadow:!::\nlil-tweak:!::\nlil-tweak-tunnel:!::\n",
            "subuid": "lil-tweak:100000:65536\nother:200000:65536\n",
            "subgid": "lil-tweak:100000:65536\nother:200000:65536\n",
            "nsswitch.conf": (
                "# Local identities only for the dedicated host.\n"
                "passwd: files systemd\n"
                "group: files systemd\n"
                "shadow: files\n"
                "gshadow: files\n"
                "initgroups: files systemd\n"
                "hosts: files dns\n"
            ),
        }
        for name, contents in self.files.items():
            path = self.etc / name
            path.write_text(contents)
            path.chmod(0o640 if name in {"shadow", "gshadow"} else 0o644)

    def replace(self, name: str, old: str, new: str) -> None:
        path = self.etc / name
        contents = path.read_text().replace(old, new)
        path.write_text(contents)

    def run(self, user: str = "lil-tweak") -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(HELPER), "--user", user, "--database-root", str(self.root)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )


class HostIdentityTests(unittest.TestCase):
    def assert_rejected(self, fixture: IdentityFixture, user: str = "lil-tweak") -> None:
        result = fixture.run(user)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(str(fixture.root), result.stderr)

    def test_valid_dedicated_core_and_tunnel_identities_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = IdentityFixture(Path(temporary))
            for user in ("lil-tweak", "lil-tweak-tunnel"):
                with self.subTest(user=user):
                    result = fixture.run(user)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, "")

    def test_root_shared_or_interactive_service_identity_is_rejected(self) -> None:
        changes = {
            "root uid": ("passwd", "lil-tweak:x:1001:1001", "lil-tweak:x:0:1001"),
            "root gid": ("passwd", "lil-tweak:x:1001:1001", "lil-tweak:x:1001:0"),
            "duplicate uid": ("passwd", "root:x:0:0", "root:x:0:0\nalias:x:1001:2001"),
            "shared primary gid": ("passwd", "root:x:0:0", "root:x:0:0\nother:x:2001:1001"),
            "duplicate group gid": ("group", "root:x:0:", "root:x:0:\nalias:x:1001:"),
            "group member disclosure": ("group", "lil-tweak:x:1001:", "lil-tweak:x:1001:attacker"),
            "supplementary group": ("group", "root:x:0:", "root:x:0:lil-tweak"),
            "interactive shell": ("passwd", "/usr/sbin/nologin", "/bin/bash"),
            "public passwd hash": ("passwd", "lil-tweak:x:1001", "lil-tweak:$6$hash:1001"),
            "public group hash": ("group", "lil-tweak:x:1001", "lil-tweak:$6$hash:1001"),
            "unlocked password": ("shadow", "lil-tweak:!:", "lil-tweak:$6$hash:"),
            "shared service uid": ("passwd", "lil-tweak-tunnel:x:1002", "lil-tweak-tunnel:x:1001"),
            "shared service gid": ("passwd", "lil-tweak-tunnel:x:1002:1002", "lil-tweak-tunnel:x:1002:1001"),
        }
        for label, (name, old, new) in changes.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = IdentityFixture(Path(temporary))
                fixture.replace(name, old, new)
                self.assert_rejected(fixture)

    def test_subordinate_ranges_are_exact_unique_and_nonoverlapping(self) -> None:
        replacements = {
            "zero range": ("lil-tweak:100000:65536", "lil-tweak:0:0"),
            "short range": ("lil-tweak:100000:65536", "lil-tweak:100000:65535"),
            "duplicate": ("other:200000:65536", "lil-tweak:300000:65536"),
            "overlap": ("other:200000:65536", "other:150000:65536"),
        }
        for label, (old, new) in replacements.items():
            for database in ("subuid", "subgid"):
                with (
                    self.subTest(label=label, database=database),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    fixture = IdentityFixture(Path(temporary))
                    fixture.replace(database, old, new)
                    self.assert_rejected(fixture)

    def test_tunnel_group_cannot_delegate_credential_access(self) -> None:
        changes = {
            "group member": (
                "group",
                "lil-tweak-tunnel:x:1002:",
                "lil-tweak-tunnel:x:1002:attacker",
            ),
            "gshadow password": (
                "gshadow",
                "lil-tweak-tunnel:!::",
                "lil-tweak-tunnel:$6$usable::",
            ),
            "gshadow administrator": (
                "gshadow",
                "lil-tweak-tunnel:!::",
                "lil-tweak-tunnel:!:attacker:",
            ),
            "gshadow member": (
                "gshadow",
                "lil-tweak-tunnel:!::",
                "lil-tweak-tunnel:!::attacker",
            ),
        }
        for label, (name, old, new) in changes.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = IdentityFixture(Path(temporary))
                fixture.replace(name, old, new)
                self.assert_rejected(fixture, "lil-tweak-tunnel")

    def test_service_identity_cannot_be_a_private_member_or_admin_of_another_group(self) -> None:
        for user in ("lil-tweak", "lil-tweak-tunnel"):
            for role in ("admin", "member"):
                with (
                    self.subTest(user=user, role=role),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    fixture = IdentityFixture(Path(temporary))
                    suffix = f"privileged:!:{user}:\n" if role == "admin" else f"privileged:!::{user}\n"
                    path = fixture.etc / "gshadow"
                    path.write_text(path.read_text() + suffix)
                    path.chmod(0o640)
                    self.assert_rejected(fixture, user)

    def test_core_subordinate_ranges_cannot_cover_host_service_ids(self) -> None:
        changes = {
            "tunnel uid": (
                "passwd",
                "lil-tweak-tunnel:x:1002:1002",
                "lil-tweak-tunnel:x:100100:1002",
            ),
            "tunnel primary gid": (
                "passwd",
                "lil-tweak-tunnel:x:1002:1002",
                "lil-tweak-tunnel:x:1002:100100",
            ),
            "unrelated group gid": (
                "group",
                "root:x:0:",
                "root:x:0:\ninside-range:x:100100:",
            ),
        }
        for label, (name, old, new) in changes.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = IdentityFixture(Path(temporary))
                fixture.replace(name, old, new)
                self.assert_rejected(fixture)

    def test_numeric_subordinate_owner_cannot_add_a_second_core_mapping(self) -> None:
        for database, added_range in (
            ("subuid", "1001:300000:1\n"),
            ("subgid", "1001:1002:1\n"),
        ):
            with self.subTest(database=database), tempfile.TemporaryDirectory() as temporary:
                fixture = IdentityFixture(Path(temporary))
                path = fixture.etc / database
                path.write_text(path.read_text() + added_range)
                self.assert_rejected(fixture)

    def test_database_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = IdentityFixture(Path(temporary))
            outside = fixture.root / "outside"
            outside.write_text(fixture.files["passwd"])
            path = fixture.etc / "passwd"
            path.unlink()
            path.symlink_to(outside)
            self.assert_rejected(fixture)

    def test_account_database_permissions_and_parents_are_private(self) -> None:
        for label in ("world-readable shadow", "world-readable gshadow", "writable etc"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = IdentityFixture(Path(temporary))
                if label == "writable etc":
                    fixture.etc.chmod(0o777)
                else:
                    name = "shadow" if label == "world-readable shadow" else "gshadow"
                    (fixture.etc / name).chmod(0o644)
                self.assert_rejected(fixture)

    def test_remote_or_ambiguous_nss_identity_sources_are_rejected(self) -> None:
        changes = {
            "remote passwd": ("passwd: files systemd", "passwd: files sss"),
            "remote group": ("group: files systemd", "group: compat ldap"),
            "missing files": ("shadow: files", "shadow: systemd"),
            "duplicate rule": ("hosts: files dns", "hosts: files dns\npasswd: files"),
            "remote initgroups": ("initgroups: files systemd", "initgroups: files sss"),
        }
        for label, (old, new) in changes.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                fixture = IdentityFixture(Path(temporary))
                fixture.replace("nsswitch.conf", old, new)
                self.assert_rejected(fixture)

    def test_check_is_host_safe(self) -> None:
        result = subprocess.run(
            [sys.executable, str(HELPER), "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "lil-tweak-host-identity check: ok\n")


if __name__ == "__main__":
    unittest.main()
