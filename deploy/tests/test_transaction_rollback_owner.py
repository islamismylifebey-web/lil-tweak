from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts" / "install-lil-tweak-release.sh"


class TransactionRollbackOwnerTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path, Path]:
        wrapper = root / "install-lil-tweak-release.sh"
        shutil.copy2(WRAPPER, wrapper)
        wrapper.write_text(
            wrapper.read_text().replace(
                '[[ ${EUID} -eq 0 ]] || die \'run the release transaction as root on the target droplet\'',
                '[[ 0 -eq 0 ]]',
            )
        )
        wrapper.chmod(0o755)
        log = root / "restore.log"
        events = root / "events.log"

        helper = root / "lil-tweak-rollback.py"
        helper.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/python3
                import os
                import sys
                from pathlib import Path

                command = sys.argv[1]
                if command == "--check":
                    raise SystemExit(0)
                with Path(os.environ["EVENT_LOG"]).open("a", encoding="utf-8") as stream:
                    stream.write(command + "\\n")
                if command == "verify-fresh-install":
                    raise SystemExit(int(os.environ.get("FRESH_STATUS", "0")))
                if command == "mark-completed":
                    raise SystemExit(int(os.environ.get("COMPLETE_STATUS", "0")))
                if command == "restore":
                    path = Path(os.environ["RESTORE_LOG"])
                    with path.open("a", encoding="utf-8") as stream:
                        stream.write("restore\\n")
                raise SystemExit(0)
                """
            )
        )
        helper.chmod(0o755)

        target = root / "lil-tweak-digitalocean-target.py"
        target.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/python3
                import os
                import sys
                from pathlib import Path

                if sys.argv[1:] == ["--check"]:
                    raise SystemExit(0)
                with Path(os.environ["EVENT_LOG"]).open("a", encoding="utf-8") as stream:
                    stream.write("target\\n")
                raise SystemExit(int(os.environ.get("TARGET_STATUS", "0")))
                """
            )
        )
        target.chmod(0o755)

        installer = textwrap.dedent(
            """\
            #!/usr/bin/bash -p
            set -euo pipefail
            if [[ "${1:-}" == "--check" ]]; then
              exit 0
            fi
            name="$(basename -- "$0")"
            event_name=core
            [[ "${name}" == "install-cloudflare-tunnel.sh" ]] && event_name=tunnel
            printf '%s\\n' "${event_name}" >>"${EVENT_LOG}"
            owned=0
            if [[ "${1:-}" == "--install-under-wrapper" \
                && "${2:-}" =~ ^[1-9][0-9]*$ && "${2}" == "${PPID}" ]]; then
              owned=1
            fi
            if [[ ${owned} -ne 1 ]]; then
              /usr/bin/python3 -I -B "$(dirname -- "$0")/lil-tweak-rollback.py" restore
            fi
            if [[ "${name}" == "install-digitalocean.sh" \
                && "${SIGNAL_CORE:-0}" == "1" ]]; then
              kill -TERM "${PPID}"
              exit 143
            fi
            if [[ "${name}" == "install-digitalocean.sh" ]]; then
              exit "${CORE_STATUS:-0}"
            fi
            exit "${TUNNEL_STATUS:-0}"
            """
        )
        for name in ("install-digitalocean.sh", "install-cloudflare-tunnel.sh"):
            path = root / name
            path.write_text(installer)
            path.chmod(0o755)
        return wrapper, log, events

    def run_case(
        self,
        wrapper: Path,
        log: Path,
        events: Path,
        *,
        core_status: int = 0,
        tunnel_status: int = 0,
        signal_core: bool = False,
        fresh_status: int = 0,
        complete_status: int = 0,
        target_status: int = 0,
    ) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment.update(
            {
                "CORE_STATUS": str(core_status),
                "TUNNEL_STATUS": str(tunnel_status),
                "SIGNAL_CORE": "1" if signal_core else "0",
                "RESTORE_LOG": str(log),
                "EVENT_LOG": str(events),
                "FRESH_STATUS": str(fresh_status),
                "COMPLETE_STATUS": str(complete_status),
                "TARGET_STATUS": str(target_status),
                "LIL_TWEAK_ROLLBACK_LEASE_FD": "9",
                "LIL_TWEAK_ROLLBACK_RECEIPT": (
                    "/var/lib/lil-tweak-release-rollback/20260815T120000Z-"
                    "0123456789ab"
                ),
                "ROLLBACK_MANIFEST_SHA256": "a" * 64,
            }
        )
        return subprocess.run(
            [str(wrapper), "--under-lease"],
            cwd=wrapper.parent,
            env=environment,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )

    def test_wrapper_is_the_only_rollback_owner_for_child_and_signal_failures(self) -> None:
        cases = (
            ("core", {"core_status": 42}),
            ("tunnel", {"tunnel_status": 43}),
            ("signal", {"signal_core": True}),
        )
        for label, options in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                wrapper, log, events = self.fixture(Path(temporary))
                result = self.run_case(wrapper, log, events, **options)

                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(log.read_text().splitlines(), ["restore"])
                self.assertNotIn("mark-completed", events.read_text().splitlines())

    def test_fresh_preflight_failure_never_starts_or_restores(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wrapper, log, events = self.fixture(Path(temporary))
            result = self.run_case(wrapper, log, events, fresh_status=41)

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(
                events.read_text().splitlines(),
                ["target", "lease-exec", "verify-fresh-install"],
            )
            self.assertFalse(log.exists())

    def test_success_marks_completed_only_after_both_installers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wrapper, log, events = self.fixture(Path(temporary))
            result = self.run_case(wrapper, log, events)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                events.read_text().splitlines(),
                [
                    "target",
                    "lease-exec",
                    "verify-fresh-install",
                    "core",
                    "tunnel",
                    "mark-completed",
                ],
            )
            self.assertFalse(log.exists())

    def test_mark_completed_failure_triggers_one_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wrapper, log, events = self.fixture(Path(temporary))
            result = self.run_case(wrapper, log, events, complete_status=44)

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(
                events.read_text().splitlines(),
                [
                    "target",
                    "lease-exec",
                    "verify-fresh-install",
                    "core",
                    "tunnel",
                    "mark-completed",
                    "restore",
                ],
            )
            self.assertEqual(log.read_text().splitlines(), ["restore"])

    def test_under_lease_target_failure_runs_no_lease_child_or_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wrapper, log, events = self.fixture(Path(temporary))
            result = self.run_case(wrapper, log, events, target_status=47)

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(events.read_text().splitlines(), ["target"])
            self.assertFalse(log.exists())
            self.assertEqual(
                result.stderr,
                "install-lil-tweak-release: DigitalOcean target verification failed\n",
            )

    def test_normal_target_failure_runs_no_rollback_lease_or_child(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wrapper, log, events = self.fixture(Path(temporary))
            environment = dict(os.environ)
            environment.update(
                {
                    "RESTORE_LOG": str(log),
                    "EVENT_LOG": str(events),
                    "TARGET_STATUS": "48",
                    "LIL_TWEAK_ROLLBACK_RECEIPT": (
                        "/var/lib/lil-tweak-release-rollback/20260815T120000Z-"
                        "0123456789ab"
                    ),
                    "ROLLBACK_MANIFEST_SHA256": "a" * 64,
                }
            )
            result = subprocess.run(
                [str(wrapper), "--install"],
                cwd=wrapper.parent,
                env=environment,
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(events.read_text().splitlines(), ["target"])
            self.assertFalse(log.exists())
            self.assertEqual(
                result.stderr,
                "install-lil-tweak-release: DigitalOcean target verification failed\n",
            )


if __name__ == "__main__":
    unittest.main()
