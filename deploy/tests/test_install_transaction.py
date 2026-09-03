from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts" / "install-lil-tweak-release.sh"
SERVICE_FILES = ROOT / "scripts" / "lil-tweak-service-files.py"


class InstallTransactionTests(unittest.TestCase):
    def test_service_file_controller_is_checked_and_used_for_both_service_roots(self) -> None:
        check = subprocess.run(
            [str(SERVICE_FILES), "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertEqual(check.stdout, "lil-tweak-service-files check: ok\n")

        source = (ROOT / "scripts" / "install-digitalocean.sh").read_text()
        self.assertIn('SERVICE_FILES_HELPER="${PROJECT_DIR}/scripts/lil-tweak-service-files.py"', source)
        checked = source.index('"${PYTHON}" -I -B "${SERVICE_FILES_HELPER}" --check')
        staged = source.index('"${staging_dir}/.config/lil-tweak/core.env"')
        authorized = source.index(
            'authorize_release_file "${SERVICE_HOME}/.config/lil-tweak/core.env"'
        )
        installed = source.index('"${SERVICE_FILES_HELPER}" install-tree')
        runtime = source.index('"${SERVICE_FILES_HELPER}" stage-runtime-auth')
        removed = source.index("remove_runtime_auth || die", runtime)
        self.assertEqual([checked, staged, authorized, runtime, installed], sorted(
            [checked, staged, authorized, runtime, installed]
        ))
        self.assertGreater(removed, runtime)
        self.assertIn('"${SERVICE_FILES_HELPER}" remove-runtime-auth', source)
        self.assertNotRegex(source, r'rm -f -- "\$\{runtime_auth_file\}"')

    def test_core_installer_has_no_root_install_target_under_service_owned_roots(self) -> None:
        source = (ROOT / "scripts" / "install-digitalocean.sh").read_text()
        commands = re.sub(r"\\\n\s*", " ", source)
        for line in commands.splitlines():
            if re.match(r"\s*install\s", line):
                self.assertNotIn("${SERVICE_HOME}", line)
                self.assertNotIn("/run/user/", line)
        self.assertNotIn('mktemp -p "/run/user/${service_uid}"', commands)

    def test_wrapper_holds_one_verified_lease_across_both_installers(self) -> None:
        source = WRAPPER.read_text()
        self.assertIn("lease-exec", source)
        self.assertIn("LIL_TWEAK_ROLLBACK_RECEIPT", source)
        self.assertIn("ROLLBACK_MANIFEST_SHA256", source)
        self.assertIn("LIL_TWEAK_ROLLBACK_LEASE_FD", source)
        self.assertIn("--under-lease", source)
        leased = source.index('"${CORE_INSTALLER}" --install-under-wrapper "$$"')
        tunneled = source.index('"${TUNNEL_INSTALLER}" --install-under-wrapper "$$"')
        self.assertLess(leased, tunneled)
        self.assertIn('"${ROLLBACK_HELPER}" restore', source)
        self.assertIn("trap finish_transaction EXIT", source)

        fresh = source.index('"${ROLLBACK_HELPER}" verify-fresh-install')
        core = source.index('"${CORE_INSTALLER}" --install-under-wrapper "$$"')
        tunnel = source.index('"${TUNNEL_INSTALLER}" --install-under-wrapper "$$"')
        completed = source.index('"${ROLLBACK_HELPER}" mark-completed')
        closed = source.index("transaction_started=0", completed)
        self.assertEqual([fresh, core, tunnel, completed, closed], sorted(
            [fresh, core, tunnel, completed, closed]
        ))

    def test_core_proves_fresh_state_and_runtime_provenance_before_mutation(self) -> None:
        source = (ROOT / "scripts" / "install-digitalocean.sh").read_text()

        self.assertIn('RELEASE_HELPER="${PROJECT_DIR}/scripts/lil-tweak-release.py"', source)
        self.assertIn('"${PYTHON}" -I -B "${RELEASE_HELPER}" --help', source)
        self.assertIn("LIL_TWEAK_SOURCE_MANIFEST", source)
        self.assertIn("LIL_TWEAK_RUNTIME_MANIFEST", source)
        self.assertIn("LIL_TWEAK_RUNTIME_MANIFEST_SHA256", source)
        verified = source.index('lil-tweak-rollback.py" verify')
        fresh = source.index('"${ROLLBACK_HELPER}" verify-fresh-install')
        snapshot = source.index('runner_image="$("${PYTHON}" -I -B "${SECRET_SNAPSHOT_HELPER}" snapshot')
        runtime = source.index('"${RELEASE_HELPER}" verify-runtime-install')
        mutation = source.index("mutation_started=1")
        self.assertEqual(
            [verified, fresh, snapshot, runtime, mutation],
            sorted([verified, fresh, snapshot, runtime, mutation]),
        )
        runtime_call = source[runtime:mutation]
        for argument in (
            '--source-manifest "${source_manifest}"',
            '--source-dir "${PROJECT_DIR}"',
            '--runtime-manifest "${runtime_manifest}"',
            '--runtime-manifest-sha256 "${runtime_manifest_sha256}"',
            '--rollback-manifest "${rollback_receipt}/manifest.json"',
            '--rollback-manifest-sha256 "${rollback_manifest_sha256}"',
            '--core-image "${core_image}"',
            '--postgres-image "${postgres_image}"',
            '--runner-image "${runner_image}"',
        ):
            self.assertIn(argument, runtime_call)
        self.assertIn(">/dev/null 2>&1", runtime_call)

    def test_core_finalizes_each_object_immediately_after_creation(self) -> None:
        source = (ROOT / "scripts" / "install-digitalocean.sh").read_text()
        self.assertIn("finalize_release_object() {", source)
        self.assertNotIn("if ! as_service podman secret inspect", source)

        markers = (
            "authorize_release_object secret lil-tweak-postgres-admin-password",
            "as_service podman secret create lil-tweak-postgres-admin-password -",
            "finalize_release_object secret lil-tweak-postgres-admin-password",
            "as_service systemctl --user start lil-tweak-network.service",
            "finalize_release_object network lil-tweak-private",
            "as_service systemctl --user start lil-tweak-postgres.service",
            "finalize_release_object container lil-tweak-postgres",
            "as_service podman exec lil-tweak-postgres pg_isready",
            "as_service systemctl --user restart lil-tweak-core.service",
            "finalize_release_object container lil-tweak-core",
        )
        positions = [source.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))

    def test_child_installers_restore_only_when_the_wrapper_does_not_own_rollback(self) -> None:
        for relative in (
            "scripts/install-digitalocean.sh",
            "scripts/install-cloudflare-tunnel.sh",
        ):
            with self.subTest(relative=relative):
                source = (ROOT / relative).read_text()
                self.assertIn('"${1:-}" == "--install-under-wrapper"', source)
                self.assertIn('"${2}" == "${PPID}"', source)
                self.assertIn("rollback_owned_by_wrapper=1", source)
                self.assertIn(
                    "${rollback_owned_by_wrapper} -eq 0",
                    source,
                )

    def test_standalone_children_require_fresh_state_before_mutation(self) -> None:
        core = (ROOT / "scripts" / "install-digitalocean.sh").read_text()
        tunnel = (ROOT / "scripts" / "install-cloudflare-tunnel.sh").read_text()

        self.assertLess(
            core.index('"${ROLLBACK_HELPER}" verify-fresh-install'),
            core.index("mutation_started=1"),
        )
        conditional = tunnel.index("if [[ ${rollback_owned_by_wrapper} -eq 0 ]]")
        fresh = tunnel.index('"${ROLLBACK_HELPER}" verify-fresh-install', conditional)
        mutation = tunnel.index("mutation_started=1")
        self.assertLess(conditional, fresh)
        self.assertLess(fresh, mutation)

    def test_wrapper_offline_check_is_host_safe(self) -> None:
        result = subprocess.run(
            ["bash", str(WRAPPER), "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("check: ok", result.stdout.lower())

    def test_root_installers_ignore_shell_startup_and_untrusted_path(self) -> None:
        for script in (
            ROOT / "scripts" / "install-lil-tweak-release.sh",
            ROOT / "scripts" / "install-digitalocean.sh",
            ROOT / "scripts" / "install-cloudflare-tunnel.sh",
        ):
            with self.subTest(script=script.name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                sentinel = directory / "startup-ran"
                python_sentinel = directory / "python-startup-ran"
                startup = directory / "bash-env"
                startup.write_text(f"printf attacked > {sentinel}\n")
                (directory / "sitecustomize.py").write_text(
                    "from pathlib import Path\n"
                    f"Path({str(python_sentinel)!r}).write_text('attacked')\n"
                )
                environment = dict(os.environ)
                environment.update(
                    {
                        "BASH_ENV": str(startup),
                        "ENV": str(startup),
                        "CDPATH": str(directory),
                        "PATH": f"{directory}:/usr/bin:/bin",
                        "PYTHONPATH": str(directory),
                        "PYTHONHOME": str(directory / "fake-python-home"),
                    }
                )
                result = subprocess.run(
                    [str(script), "--check"],
                    cwd=ROOT,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(sentinel.exists())
                self.assertFalse(python_sentinel.exists())
                self.assertIn("check: ok", result.stdout.lower())

    def test_service_commands_run_with_an_exact_empty_environment(self) -> None:
        core = (ROOT / "scripts" / "install-digitalocean.sh").read_text()
        tunnel = (ROOT / "scripts" / "install-cloudflare-tunnel.sh").read_text()
        self.assertIn('runuser --user "${SERVICE_USER}" -- \\\n    /usr/bin/env -i', core)
        self.assertIn('"HOME=${SERVICE_HOME}" "USER=${SERVICE_USER}"', core)
        self.assertIn('"XDG_RUNTIME_DIR=/run/user/${service_uid}"', core)
        self.assertIn('runuser --user "${TUNNEL_USER}" -- \\\n    /usr/bin/env -i', tunnel)
        self.assertIn('"HOME=/var/lib/lil-tweak-tunnel" "USER=${TUNNEL_USER}"', tunnel)

    def test_service_exec_closes_and_unsets_the_root_rollback_lease(self) -> None:
        for relative in (
            "scripts/install-digitalocean.sh",
            "scripts/install-cloudflare-tunnel.sh",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                source = (ROOT / relative).read_text()
                start = source.index("exec_without_rollback_lease() {")
                end = source.index("\n}\n", start) + len("\n}\n")
                function = source[start:end]
                lock = Path(temporary) / "transaction.lock"
                lock.touch(mode=0o600)
                program = function + r'''
exec 9<>"$1"
export LIL_TWEAK_ROLLBACK_LEASE_FD=9
exec_without_rollback_lease /usr/bin/python3 -I -c '
import os
if "LIL_TWEAK_ROLLBACK_LEASE_FD" in os.environ:
    raise SystemExit(7)
try:
    os.fstat(9)
except OSError:
    raise SystemExit(0)
raise SystemExit(8)
'
'''
                result = subprocess.run(
                    ["/usr/bin/bash", "-c", program, "lease-test", str(lock)],
                    cwd=ROOT,
                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_each_installer_falls_back_to_the_same_lease_protocol(self) -> None:
        for relative in (
            "scripts/install-digitalocean.sh",
            "scripts/install-cloudflare-tunnel.sh",
        ):
            with self.subTest(relative=relative):
                source = (ROOT / relative).read_text()
                fallback = source.index('if [[ -z "${LIL_TWEAK_ROLLBACK_LEASE_FD:-}" ]]')
                nested_proof = source.index('  -- /bin/true >/dev/null', fallback)
                verification = source.index('lil-tweak-rollback.py" verify', nested_proof)
                mutation = source.index("mutation_started=1")
                self.assertLess(fallback, nested_proof)
                self.assertLess(nested_proof, verification)
                self.assertLess(verification, mutation)

    def test_installers_require_locked_noninteractive_dedicated_identities(self) -> None:
        core = (ROOT / "scripts" / "install-digitalocean.sh").read_text()
        tunnel = (ROOT / "scripts" / "install-cloudflare-tunnel.sh").read_text()

        for source, user, first_privileged_use in (
            (core, "${SERVICE_USER}", 'loginctl enable-linger "${SERVICE_USER}"'),
            (tunnel, "${TUNNEL_USER}", 'install -d -m 0750'),
        ):
            with self.subTest(user=user):
                self.assertIn("HOST_IDENTITY_HELPER", source)
                self.assertIn(
                    '"${PYTHON}" -I -B "${HOST_IDENTITY_HELPER}" --check', source
                )
                created = source.index("useradd")
                validated = source.index(
                    f'"${{PYTHON}}" -I -B "${{HOST_IDENTITY_HELPER}}" --user "{user}"',
                    created,
                )
                privileged = source.index(first_privileged_use, validated)
                self.assertLess(created, validated)
                self.assertLess(validated, privileged)

    def test_tunnel_verifies_the_fixed_binary_before_host_mutation(self) -> None:
        tunnel = (ROOT / "scripts" / "install-cloudflare-tunnel.sh").read_text()
        self.assertIn(
            'BINARY_VERIFIER_SOURCE="${PROJECT_DIR}/deploy/cloudflared/verify_binary.py"',
            tunnel,
        )
        self.assertIn(
            'BINARY_VERIFIER_TARGET="/usr/local/libexec/lil-tweak/cloudflared-verify-exec.py"',
            tunnel,
        )
        self.assertNotIn("sha256sum --check", tunnel)
        verified = tunnel.index(
            '"${PYTHON}" -I -B "${BINARY_VERIFIER_SOURCE}" '
            '--expected-sha256 "${cloudflared_sha256}"'
        )
        mutation = tunnel.index("mutation_started=1")
        created = tunnel.index("useradd", verified)
        self.assertLess(verified, mutation)
        self.assertLess(mutation, created)
        self.assertNotIn("command -v cloudflared", tunnel)
        rendered = tunnel.index(
            'unit_staging_file="$(mktemp -p /tmp lil-tweak-cloudflared-unit.'
        )
        authorized_helper = tunnel.index(
            'authorize_release_file "${BINARY_VERIFIER_TARGET}" '
            '"${BINARY_VERIFIER_SOURCE}"'
        )
        authorized_unit = tunnel.index(
            'authorize_release_file /etc/systemd/system/lil-tweak-cloudflared.service '
            '"${unit_staging_file}"'
        )
        installed_helper = tunnel.index(
            'install -D -m 0755 -o root -g root "${BINARY_VERIFIER_SOURCE}" '
            '"${BINARY_VERIFIER_TARGET}"'
        )
        validated = tunnel.index(
            '"${PYTHON}" -I -B "${BINARY_VERIFIER_TARGET}" '
            '--expected-sha256 "${cloudflared_sha256}"'
        )
        self.assertIn("--execute -- --config", tunnel[validated:])
        self.assertEqual(
            [rendered, authorized_helper, authorized_unit, installed_helper, validated],
            sorted([rendered, authorized_helper, authorized_unit, installed_helper, validated]),
        )

    def test_core_cleanup_aggregates_failure_and_continues_other_removals(self) -> None:
        source = (ROOT / "scripts" / "install-digitalocean.sh").read_text()
        remove_start = source.index("remove_runtime_auth() {")
        cleanup_end = source.index(
            "\n}\n", source.index("cleanup_release_state() {")
        ) + len("\n}\n")
        cleanup_functions = source[remove_start:cleanup_end]

        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            base = Path(temporary)
            runtime_auth = base / "runtime-auth.json"
            runtime_auth.write_text("runtime")
            registry_auth = Path(f"/tmp/lil-tweak-registry-auth.{base.name}")
            registry_auth.write_text("registry")
            secret_snapshot = Path(f"/tmp/lil-tweak-secrets.{uuid.uuid4().hex[:8]}")
            secret_snapshot.mkdir()
            (secret_snapshot / "core.env").write_text("secret")
            staging = Path(f"/tmp/lil-tweak-install.{base.name}")
            staging.mkdir()
            (staging / "unit").write_text("staged")
            try:
                program = cleanup_functions + r'''
cleanup_release_state
'''
                result = subprocess.run(
                    ["bash", "-c", program],
                    env={
                        "PATH": "/usr/bin:/bin",
                        "PYTHON": "/usr/bin/python3",
                        "SERVICE_FILES_HELPER": str(
                            ROOT / "scripts" / "lil-tweak-service-files.py"
                        ),
                        "service_uid": "12345",
                        "service_gid": "12345",
                        "runtime_auth_file": str(runtime_auth),
                        "registry_auth_snapshot": str(registry_auth),
                        "secret_snapshot_dir": str(secret_snapshot),
                        "staging_dir": str(staging),
                    },
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("command not found", result.stderr)
                self.assertTrue(runtime_auth.exists())
                self.assertFalse(registry_auth.exists())
                self.assertFalse(secret_snapshot.exists())
                self.assertFalse(staging.exists())
            finally:
                for leftover in (runtime_auth, registry_auth):
                    if leftover.exists() or leftover.is_symlink():
                        leftover.unlink()
                for leftover in (secret_snapshot, staging):
                    if leftover.exists():
                        for child in leftover.iterdir():
                            child.unlink()
                        leftover.rmdir()


if __name__ == "__main__":
    unittest.main()
