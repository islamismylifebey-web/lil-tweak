from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.lil_tweak import limits as runtime_limits
from deploy import verify_runtime


ROOT = Path(__file__).resolve().parents[2]


def text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class TunnelContractTests(unittest.TestCase):
    def test_tunnel_access_and_managed_ingress_artifacts_are_concrete(self) -> None:
        required = (
            "deploy/cloudflare/access-application.json",
            "deploy/cloudflare/access-policy.json",
            "deploy/cloudflare/worker.production.env.example",
            "deploy/cloudflared/config.yml.example",
            "deploy/cloudflared/lil-tweak-cloudflared.service",
            "scripts/install-cloudflare-tunnel.sh",
            "docs/operations/cloudflare-private-ingress.md",
        )
        for relative in required:
            self.assertTrue((ROOT / relative).is_file(), relative)

        config = text("deploy/cloudflared/config.yml.example")
        self.assertIn("service: http://127.0.0.1:8017", config)
        self.assertRegex(config, r"(?m)^\s*- service: http_status:404\s*$")
        self.assertNotIn("noTLSVerify: true", config)
        self.assertNotRegex(config, r"(?i)galor[-_.]?(network|volume|database)")

        policy = json.loads(text("deploy/cloudflare/access-policy.json"))
        self.assertEqual(policy["decision"], "non_identity")
        self.assertEqual(policy["include"], [{"service_token": {"token_id": "__SERVICE_TOKEN_ID__"}}])
        self.assertNotIn("everyone", json.dumps(policy).lower())
        self.assertNotIn("bypass", json.dumps(policy).lower())

        env_contract = text("deploy/cloudflare/worker.production.env.example")
        self.assertRegex(env_contract, r"(?m)^LIL_TWEAK_ENVIRONMENT=production$")
        for name in (
            "LIL_TWEAK_ENVIRONMENT",
            "PUBLIC_ORIGIN",
            "MANAGED_INGRESS_SECRET",
            "CORE_ORIGIN",
            "CORE_ACCESS_CLIENT_ID",
            "CORE_ACCESS_CLIENT_SECRET",
            "CORE_SIGNING_KEY_ID",
            "CORE_SIGNING_SECRET",
        ):
            self.assertRegex(env_contract, rf"(?m)^{name}=")

        runbook = text("docs/operations/cloudflare-private-ingress.md")
        for phrase in (
            "CF-Access-Client-Id",
            "CF-Access-Client-Secret",
            "X-Lil-Tweak-Managed-Ingress",
            "PUBLIC_ORIGIN",
            "workers.dev",
            "never open port 8017",
            "GALOR Hub",
            "missing LIL_TWEAK_ENVIRONMENT fails closed",
            "at least 32 UTF-8 bytes",
            "[A-Za-z0-9][A-Za-z0-9._-]{0,63}",
        ):
            self.assertIn(phrase.lower(), runbook.lower())

    def test_cloudflared_unit_and_installer_are_separate_and_hardened(self) -> None:
        unit = text("deploy/cloudflared/lil-tweak-cloudflared.service")
        for value in (
            "User=lil-tweak-tunnel",
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "PrivateTmp=true",
            "RestrictSUIDSGID=true",
        ):
            self.assertIn(value, unit)
        self.assertIn(
            "/usr/local/libexec/lil-tweak/cloudflared-verify-exec.py",
            unit,
        )
        self.assertIn("@@LIL_TWEAK_CLOUDFLARED_SHA256@@", unit)
        self.assertEqual(unit.count("@@LIL_TWEAK_CLOUDFLARED_SHA256@@"), 2)
        self.assertIn("--execute -- --no-autoupdate", unit)
        self.assertNotIn("ExecStart=/usr/bin/cloudflared", unit)

        installer = text("scripts/install-cloudflare-tunnel.sh")
        self.assertIn('TUNNEL_USER="lil-tweak-tunnel"', installer)
        self.assertIn('EXPECTED_HOST="galor-private-cloud-01"', installer)
        self.assertIn("--user-group", installer)
        self.assertIn("deploy/cloudflared/verify_binary.py", installer)
        self.assertIn("--expected-sha256", installer)
        self.assertNotIn("sha256sum --check", installer)
        self.assertIn("systemctl restart lil-tweak-cloudflared.service", installer)
        self.assertNotIn("(?:", installer)
        self.assertNotRegex(installer, r"\beval\b")
        self.assertNotRegex(installer, r"curl\s+[^\n]*\|\s*(?:ba)?sh")
        result = subprocess.run(
            ["bash", "scripts/install-cloudflare-tunnel.sh", "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("check: ok", result.stdout.lower())


class OfflineDependencyTests(unittest.TestCase):
    def run_audit(self, source: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", "scripts/verify-offline-dependencies.py", str(source)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_no_lockfile_is_truthfully_limited_to_runner_toolchains(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.run_audit(Path(temporary))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("runner-preinstalled", result.stdout)

    def test_network_resolved_npm_lock_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "node_modules/a": {
                                "resolved": "https://registry.invalid/a.tgz",
                                "integrity": "sha512-" + base64.b64encode(b"x" * 64).decode(),
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = self.run_audit(source)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("network-resolved npm dependency", result.stderr)

    def test_vendored_npm_tarball_lock_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            vendor = source / "vendor" / "npm"
            vendor.mkdir(parents=True)
            package_bytes = b"reviewed-package"
            (vendor / "a.tgz").write_bytes(package_bytes)
            (source / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"name": "offline-example", "version": "1.0.0"},
                            "node_modules/a": {
                                "resolved": "file:vendor/npm/a.tgz",
                                "integrity": "sha512-"
                                + base64.b64encode(hashlib.sha512(package_bytes).digest()).decode(),
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = self.run_audit(source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("npm: vendored", result.stdout)

    def test_tampered_vendored_npm_tarball_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            vendor = source / "vendor" / "npm"
            vendor.mkdir(parents=True)
            (vendor / "a.tgz").write_bytes(b"tampered-package")
            (source / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"name": "offline-example", "version": "1.0.0"},
                            "node_modules/a": {
                                "resolved": "file:vendor/npm/a.tgz",
                                "integrity": "sha512-"
                                + base64.b64encode(hashlib.sha512(b"reviewed-package").digest()).decode(),
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            result = self.run_audit(source)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("integrity mismatch", result.stderr)

    def test_go_and_rust_locks_require_vendored_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / "go.mod").write_text("module example.invalid/x\n", encoding="utf-8")
            (source / "go.sum").write_text("example.invalid/mod v1.0.0 h1:digest\n", encoding="utf-8")
            (source / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
            result = self.run_audit(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("vendor/modules.txt", result.stderr)

            (source / "vendor").mkdir()
            (source / "vendor" / "modules.txt").write_text("# vendored\n", encoding="utf-8")
            cargo = source / ".cargo"
            cargo.mkdir()
            (cargo / "config.toml").write_text(
                '[source.crates-io]\nreplace-with = "vendored-sources"\n'
                '[source.vendored-sources]\ndirectory = "vendor"\n',
                encoding="utf-8",
            )
            result = self.run_audit(source)
        self.assertEqual(result.returncode, 0, result.stderr)


class RuntimeAndBackupTests(unittest.TestCase):
    def test_environment_loader_requires_secure_bounded_file_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "core.env"
            path.write_text("A=one\nB=two\n", encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(
                verify_runtime.load_environment(path),
                {"A": "one", "B": "two"},
            )

            path.chmod(0o644)
            with self.assertRaises(verify_runtime.ProbeError):
                verify_runtime.load_environment(path)
            path.chmod(0o600)

            hardlink = root / "hardlink.env"
            os.link(path, hardlink)
            with self.assertRaises(verify_runtime.ProbeError):
                verify_runtime.load_environment(path)
            hardlink.unlink()

            alias = root / "alias.env"
            alias.symlink_to(path)
            with self.assertRaises(verify_runtime.ProbeError):
                verify_runtime.load_environment(alias)

            path.write_bytes(b"A=" + b"x" * (64 * 1024))
            with self.assertRaises(verify_runtime.ProbeError):
                verify_runtime.load_environment(path)

    def test_podman_socket_symlink_is_rejected_before_connect(self) -> None:
        socket_metadata = SimpleNamespace(
            st_mode=stat.S_IFSOCK | 0o600,
            st_uid=os.getuid(),
            st_gid=os.getgid(),
            st_dev=1,
            st_ino=2,
        )

        class SymlinkSocketPath:
            def stat(self):
                return socket_metadata

            def lstat(self):
                return SimpleNamespace(
                    **{
                        **socket_metadata.__dict__,
                        "st_mode": stat.S_IFLNK | 0o777,
                    }
                )

            def __str__(self):
                return "/run/user/10001/podman/podman.sock"

        with patch.object(verify_runtime.socket, "socket") as factory:
            with self.assertRaises(verify_runtime.ProbeError):
                verify_runtime.probe_socket(SymlinkSocketPath())
        factory.assert_not_called()

    def test_trusted_inode_and_swap_contract_is_exact_across_deployment(self) -> None:
        self.assertEqual(
            getattr(runtime_limits, "TRUSTED_WORK_ROOT_TREE_SLOTS", None), 3
        )
        self.assertEqual(
            getattr(runtime_limits, "TRUSTED_WORK_ROOT_BOOKKEEPING_INODES", None),
            8_192,
        )
        self.assertEqual(
            runtime_limits.TRUSTED_WORK_ROOT_INODES,
            3 * runtime_limits.RUNNER_WORKSPACE_INODES + 8_192,
        )
        self.assertEqual(runtime_limits.TRUSTED_WORK_ROOT_INODES, 204_800)
        self.assertEqual(verify_runtime.CORE_WORK_ROOT_INODES, 204_800)

        quadlet = text("deploy/quadlet/lil-tweak-core.container")
        self.assertIn("nr_inodes=204800", quadlet)
        environment = text("deploy/core.env.example")
        self.assertRegex(
            environment,
            r"(?m)^LIL_TWEAK_WORK_ROOT_INODES=204800$",
        )
        hardening = text("deploy/lil-tweak-core.service.d/hardening.conf")
        self.assertRegex(hardening, r"(?m)^MemorySwapMax=0$")
        runbook = text("docs/operations/digitalocean.md")
        self.assertIn("204,800-inode", runbook)

    def test_runtime_probe_uses_installed_production_path_without_fallback(self) -> None:
        probe = text("deploy/verify_runtime.py")
        for fragment in (
            "/podman/podman.sock",
            "LIL_TWEAK_RUNNER_IMAGE",
            "LIL_TWEAK_WORK_ROOT",
            '"lil_tweak.runtime_probe"',
            "CORE_WORK_ROOT_BYTES = 1024 * 1024 * 1024",
            "CORE_WORK_ROOT_INODES = 204_800",
            "memory.swap.max",
            "MemorySwapMax",
        ):
            self.assertIn(fragment, probe)
        self.assertNotIn("shell=True", probe)
        self.assertNotIn('"podman", "run"', probe)
        self.assertNotIn("def smoke_runner", probe)
        self.assertIn("metadata.st_gid != os.getgid()", probe)

        verifier = text("scripts/verify-deployment.sh")
        self.assertIn("verify_runtime.py", verifier)
        self.assertIn("LIL_TWEAK_VERIFY_R2", verifier)
        self.assertIn("verify_r2.py", verifier)
        self.assertIn("verify-data-integrity.sh", verifier)

        quadlet = text("deploy/quadlet/lil-tweak-core.container")
        self.assertIn("Environment=LIL_TWEAK_MAX_ADMITTED_JOBS=1", quadlet)
        for core_env in (text("deploy/core.env.example"), text("core/.env.example")):
            self.assertRegex(core_env, r"(?m)^LIL_TWEAK_WORK_ROOT_INODES=204800$")
            self.assertRegex(core_env, r"(?m)^LIL_TWEAK_MAX_ADMITTED_JOBS=1$")
            self.assertRegex(core_env, r"(?m)^LIL_TWEAK_JOB_TIMEOUT_SECONDS=1200$")

    def test_outer_probe_invokes_exact_installed_module_and_strictly_parses(self) -> None:
        image = "runner@sha256:" + "a" * 64
        calls = []

        def execute(argv, **kwargs):
            calls.append((list(argv), kwargs))
            return subprocess.CompletedProcess(
                argv,
                0,
                stdout=(
                    verify_runtime.RUNTIME_PROBE_SENTINEL
                    + '{"schema":"lil-tweak-runtime-probe-v1","status":"ok"}\n'
                ),
                stderr="",
            )

        verify_runtime.probe_installed_runtime(image, executor=execute)
        self.assertEqual(
            calls[0][0],
            [
                "podman",
                "exec",
                "lil-tweak-core",
                "python",
                "-I",
                "-m",
                "lil_tweak.runtime_probe",
                "--image",
                image,
            ],
        )
        self.assertFalse(calls[0][1]["shell"])

        valid = calls[0][0]
        outputs = (
            "",
            "noise\n" + verify_runtime.RUNTIME_PROBE_SENTINEL + "{}\n",
            verify_runtime.RUNTIME_PROBE_SENTINEL + "{}\n",
            (
                verify_runtime.RUNTIME_PROBE_SENTINEL
                + '{"schema":"lil-tweak-runtime-probe-v1","status":"ok"}\n'
            )
            * 2,
            "x" * (verify_runtime.MAX_PROBE_OUTPUT_BYTES + 1),
        )
        for output in outputs:
            with self.subTest(output=output[:30]):
                with self.assertRaises(verify_runtime.ProbeError):
                    verify_runtime.probe_installed_runtime(
                        image,
                        executor=lambda _argv, **_kwargs: subprocess.CompletedProcess(
                            valid, 0, stdout=output, stderr=""
                        ),
                    )

    def test_effective_service_swap_gate_is_exact_zero(self) -> None:
        calls = []

        def execute(argv, **_kwargs):
            calls.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, stdout="0\n", stderr="")

        verify_runtime.probe_service_swap(executor=execute)
        self.assertEqual(
            calls,
            [[
                "systemctl",
                "--user",
                "show",
                "lil-tweak-core.service",
                "-p",
                "MemorySwapMax",
                "--value",
            ]],
        )
        for value in ("", "1\n", "infinity\n", "0\nnoise\n"):
            with self.subTest(value=value):
                with self.assertRaises(verify_runtime.ProbeError):
                    verify_runtime.probe_service_swap(
                        executor=lambda argv, **_kwargs: subprocess.CompletedProcess(
                            argv, 0, stdout=value, stderr=""
                        )
                    )

    def test_runner_image_metadata_parser_is_strict_and_content_free(self) -> None:
        image = "runner@sha256:" + "a" * 64
        digest = "sha256:" + "a" * 64

        def probe_with(payload):
            return verify_runtime.probe_image(
                image,
                executor=lambda argv, **_kwargs: subprocess.CompletedProcess(
                    argv, 0, stdout=payload, stderr=""
                ),
            )

        probe_with(json.dumps([{"Digest": digest, "RepoDigests": [image]}]))
        malformed = (
            "[1]",
            json.dumps(
                [
                    {"Digest": digest, "RepoDigests": [image]},
                    {"Digest": digest, "RepoDigests": [image]},
                ]
            ),
            json.dumps(
                [{"Digest": digest, "RepoDigests": f"prefix-{image}-suffix"}]
            ),
            '[{"Digest":"bad","Digest":"' + digest + '","RepoDigests":[]}]',
            '[{"Digest":NaN,"RepoDigests":[]}]',
            json.dumps([{"Digest": digest, "RepoDigests": [1, image]}]),
        )
        for payload in malformed:
            with self.subTest(payload=payload[:50]):
                with self.assertRaises(verify_runtime.ProbeError):
                    probe_with(payload)

    def test_main_requires_exact_work_root_inode_environment(self) -> None:
        base = {
            "LIL_TWEAK_RUNNER_IMAGE": "runner@sha256:" + "a" * 64,
            "LIL_TWEAK_WORK_ROOT": "/var/lib/lil-tweak/work",
            "LIL_TWEAK_WORK_ROOT_INODES": "204800",
        }
        with tempfile.TemporaryDirectory() as directory:
            environment_path = Path(directory) / "core.env"
            for value in (None, "204799", "204_800", "204800 "):
                environment = dict(base)
                if value is None:
                    del environment["LIL_TWEAK_WORK_ROOT_INODES"]
                else:
                    environment["LIL_TWEAK_WORK_ROOT_INODES"] = value
                environment_path.write_text(
                    "".join(f"{name}={item}\n" for name, item in environment.items()),
                    encoding="utf-8",
                )
                environment_path.chmod(0o600)
                with (
                    patch.dict(
                        verify_runtime.os.environ,
                        {"XDG_RUNTIME_DIR": f"/run/user/{verify_runtime.os.getuid()}"},
                        clear=False,
                    ),
                    patch.object(verify_runtime, "probe_socket"),
                    patch.object(verify_runtime, "probe_image"),
                    patch.object(verify_runtime, "probe_core_work_root"),
                    patch.object(verify_runtime, "probe_service_swap"),
                    patch.object(verify_runtime, "probe_installed_runtime"),
                ):
                    self.assertEqual(verify_runtime.main([str(environment_path)]), 1)

    def test_main_rejects_any_effective_galor_configuration_before_live_probes(self) -> None:
        base = (
            "LIL_TWEAK_RUNNER_IMAGE=runner@sha256:" + "a" * 64 + "\n"
            "LIL_TWEAK_WORK_ROOT=/var/lib/lil-tweak/work\n"
            "LIL_TWEAK_WORK_ROOT_INODES=204800\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            environment_path = Path(directory) / "core.env"
            for galor_line in (
                "LIL_TWEAK_GALOR_READONLY_URL=\n",
                "LIL_TWEAK_GALOR_READONLY_URL=https://galor.invalid/v1\n",
                "  LIL_TWEAK_GALOR_READONLY_URL=https://galor.invalid/v1\n",
            ):
                with self.subTest(galor_line=galor_line):
                    environment_path.write_text(base + galor_line, encoding="utf-8")
                    environment_path.chmod(0o600)
                    with (
                        patch.dict(
                            verify_runtime.os.environ,
                            {"XDG_RUNTIME_DIR": f"/run/user/{verify_runtime.os.getuid()}"},
                            clear=False,
                        ),
                        patch.object(verify_runtime, "probe_socket") as socket_probe,
                        patch.object(verify_runtime, "probe_image"),
                        patch.object(verify_runtime, "probe_core_work_root"),
                        patch.object(verify_runtime, "probe_service_swap"),
                        patch.object(verify_runtime, "probe_installed_runtime"),
                    ):
                        self.assertEqual(verify_runtime.main([str(environment_path)]), 1)
                    socket_probe.assert_not_called()

    def test_r2_probe_is_read_only(self) -> None:
        probe = text("deploy/verify_r2.py")
        self.assertIn("head_bucket", probe)
        for mutation in ("put_object", "delete_object", "create_bucket"):
            self.assertNotIn(mutation, probe)

    def test_normalized_row_integrity_is_part_of_restore_verification(self) -> None:
        sql = text("deploy/postgres-integrity.sql").lower()
        for table in ("lil_tweak_sources", "lil_tweak_evidence", "lil_tweak_jobs"):
            self.assertIn(table, sql)
        for check in ("owner_id", "source_digest", "sha256", "object_key"):
            self.assertIn(check, sql)
        for schema_check in (
            "array[1, 2, 3]",
            "lil_tweak_test_worlds",
            "lil_tweak_test_world_attempts",
            "lease_generation",
            "lil_tweak_approvals_one_proposal",
        ):
            self.assertIn(schema_check, sql)
        self.assertIn("> 0 as normalized_integrity_failed", sql)
        self.assertNotRegex(sql, r"\b(delete|update|insert|truncate|drop)\b")

        normalized_export = text("deploy/postgres-normalized-export.sql").lower()
        for field in (
            "schema_version",
            "lease_owner",
            "lease_expires_at",
            "attempt",
            "source_id",
            "filename",
            "media_type",
        ):
            self.assertIn(field, normalized_export)

        result = subprocess.run(
            ["bash", "scripts/verify-data-integrity.sh", "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("check: ok", result.stdout.lower())

        runbook = text("docs/operations/digitalocean.md")
        self.assertIn("verify-data-integrity.sh --snapshot", runbook)
        self.assertIn("verify-data-integrity.sh --compare", runbook)
        self.assertIn("LIL_TWEAK_VERIFY_R2=1", runbook)


if __name__ == "__main__":
    unittest.main()
