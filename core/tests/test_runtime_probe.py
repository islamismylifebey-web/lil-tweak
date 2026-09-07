import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.lil_tweak.runtime_lock import (
    RUNTIME_PROBE_LATCH_NAME,
    RuntimeExecutionBusy,
    runtime_execution_lock,
)
from core.lil_tweak.runtime_probe import (
    ProbeFailure,
    RUNNER_OBSERVATION_SENTINEL,
    _remove_latch,
    parse_runner_observation,
    run_runtime_probe,
    validate_core_runtime,
    validate_runner_observation,
)


def valid_observation():
    return {
        "schema": "lil-tweak-runner-observation-v1",
        "seed": "seeded-input\n",
        "uid": 65532,
        "gid": 65532,
        "workspace": {
            "mountinfo": (
                "36 25 0:32 / /workspace rw,nosuid,nodev - "
                "tmpfs tmpfs rw,size=268435456,nr_inodes=65536\n"
            ),
            "mode": 0o700,
            "uid": 65532,
            "gid": 65532,
            "bytes": 256 * 1024 * 1024,
            "inodes": 65_536,
        },
        "uid_map": (
            "         0     100000      65532\n"
            "     65532      10001          1\n"
        ),
        "gid_map": (
            "         0     200000      65532\n"
            "     65532      10001          1\n"
        ),
        "workspace_executed": True,
        "cpu_max": "100000 100000\n",
        "memory_max": "1073741824\n",
        "memory_swap_max": "0\n",
        "interfaces": ["lo"],
        "network_denied": True,
        "git": None,
        "patch": "/usr/bin/patch",
    }


def encoded_observation():
    return RUNNER_OBSERVATION_SENTINEL + json.dumps(
        valid_observation(), sort_keys=True, separators=(",", ":")
    ) + "\n"


def probe_environment(root, image):
    return {
        "LIL_TWEAK_RUNNER_IMAGE": image,
        "LIL_TWEAK_WORK_ROOT": str(root),
        "LIL_TWEAK_WORK_ROOT_INODES": "204800",
    }


class RuntimeProbeParserTests(unittest.TestCase):
    def test_running_core_runtime_requires_exact_tmpfs_capacity_and_zero_swap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            mountinfo = (
                f"36 25 0:32 / {root} rw,nosuid,nodev - "
                "tmpfs tmpfs rw,size=1073741824,nr_inodes=204800\n"
            )
            capacity = SimpleNamespace(
                f_frsize=4096,
                f_blocks=(1024 * 1024 * 1024) // 4096,
                f_files=204_800,
            )
            validate_core_runtime(
                root,
                mountinfo_text=mountinfo,
                statvfs=lambda _root: capacity,
                swap_text="0\n",
            )
            mutations = {
                "wrong_filesystem": (
                    mountinfo.replace("tmpfs tmpfs", "ext4 /dev/vda"),
                    capacity,
                    "0\n",
                ),
                "noexec": (
                    mountinfo.replace("rw,nosuid,nodev", "rw,noexec,nosuid,nodev"),
                    capacity,
                    "0\n",
                ),
                "bytes_below": (
                    mountinfo,
                    SimpleNamespace(
                        f_frsize=4096,
                        f_blocks=capacity.f_blocks - 1,
                        f_files=204_800,
                    ),
                    "0\n",
                ),
                "inodes_below": (
                    mountinfo,
                    SimpleNamespace(
                        f_frsize=4096,
                        f_blocks=capacity.f_blocks,
                        f_files=204_799,
                    ),
                    "0\n",
                ),
                "swap_enabled": (mountinfo, capacity, "1\n"),
            }
            for case, (candidate_mount, candidate_capacity, swap) in mutations.items():
                with self.subTest(case=case):
                    with self.assertRaisesRegex(
                        ProbeFailure, "^runtime probe failed$"
                    ):
                        validate_core_runtime(
                            root,
                            mountinfo_text=candidate_mount,
                            statvfs=lambda _root, value=candidate_capacity: value,
                            swap_text=swap,
                        )

    def test_valid_observation_proves_mount_identity_cgroups_network_and_tools(self):
        value = parse_runner_observation(encoded_observation())
        validate_runner_observation(value)

    def test_unprovable_observation_fails_closed(self):
        mutations = {
            "missing_mount": lambda value: value["workspace"].__setitem__(
                "mountinfo", ""
            ),
            "wrong_filesystem": lambda value: value["workspace"].__setitem__(
                "mountinfo",
                value["workspace"]["mountinfo"].replace("tmpfs tmpfs", "ext4 /dev/vda"),
            ),
            "noexec": lambda value: value["workspace"].__setitem__(
                "mountinfo",
                value["workspace"]["mountinfo"].replace(
                    "rw,nosuid,nodev", "rw,noexec,nosuid,nodev"
                ),
            ),
            "wrong_owner": lambda value: value["workspace"].__setitem__("uid", 0),
            "wrong_mode": lambda value: value["workspace"].__setitem__("mode", 0o755),
            "workspace_not_executable": lambda value: value.__setitem__(
                "workspace_executed", False
            ),
            "oversize": lambda value: value["workspace"].__setitem__(
                "bytes", 256 * 1024 * 1024 + 1
            ),
            "over_inode": lambda value: value["workspace"].__setitem__(
                "inodes", 65_537
            ),
            "uid_unmapped": lambda value: value.__setitem__("uid_map", "0 100000 1\n"),
            "gid_malformed": lambda value: value.__setitem__("gid_map", "bad\n"),
            "cpu_unbounded": lambda value: value.__setitem__(
                "cpu_max", "max 100000\n"
            ),
            "cpu_over_one": lambda value: value.__setitem__(
                "cpu_max", "200000 100000\n"
            ),
            "memory_unbounded": lambda value: value.__setitem__(
                "memory_max", "max\n"
            ),
            "memory_wrong": lambda value: value.__setitem__(
                "memory_max", "1073741823\n"
            ),
            "swap_enabled": lambda value: value.__setitem__(
                "memory_swap_max", "1\n"
            ),
            "extra_interface": lambda value: value.__setitem__(
                "interfaces", ["eth0", "lo"]
            ),
            "network_connected": lambda value: value.__setitem__(
                "network_denied", False
            ),
            "git_present": lambda value: value.__setitem__("git", "/usr/bin/git"),
            "patch_missing": lambda value: value.__setitem__("patch", None),
            "seed_missing": lambda value: value.__setitem__("seed", ""),
        }
        for case, mutate in mutations.items():
            with self.subTest(case=case):
                value = copy.deepcopy(valid_observation())
                mutate(value)
                with self.assertRaisesRegex(
                    ProbeFailure, "^runtime probe failed$"
                ):
                    validate_runner_observation(value)

        for payload in (
            "",
            RUNNER_OBSERVATION_SENTINEL + "{}\n",
            encoded_observation() + encoded_observation(),
            "noise\n" + encoded_observation(),
        ):
            with self.subTest(payload=payload[:30]):
                with self.assertRaisesRegex(
                    ProbeFailure, "^runtime probe failed$"
                ):
                    parse_runner_observation(payload)

    def test_parser_rejects_duplicate_nonfinite_and_noncanonical_numbers(self):
        payload = json.dumps(valid_observation(), separators=(",", ":"))
        duplicate = payload.replace(
            '"schema":',
            '"schema":"invalid","schema":',
            1,
        )
        nonfinite = payload.replace('"bytes":268435456', '"bytes":NaN', 1)
        infinite = payload.replace('"bytes":268435456', '"bytes":Infinity', 1)
        unknown = payload[:-1] + ',"unknown":true}'
        missing_execution = payload.replace('"workspace_executed":true,', "", 1)
        for raw in (duplicate, nonfinite, infinite, unknown, missing_execution):
            with self.subTest(raw=raw[:50]):
                with self.assertRaisesRegex(
                    ProbeFailure, "^runtime probe failed$"
                ):
                    parse_runner_observation(
                        RUNNER_OBSERVATION_SENTINEL + raw + "\n"
                    )

        mutations = {
            "uid_map_plus_underscore": lambda value: value.__setitem__(
                "uid_map", "+0 1_00000 65_532\n+65_532 +10_001 +1\n"
            ),
            "cpu_plus": lambda value: value.__setitem__(
                "cpu_max", "+100000 100000\n"
            ),
            "cpu_underscore": lambda value: value.__setitem__(
                "cpu_max", "100_000 100000\n"
            ),
            "memory_plus": lambda value: value.__setitem__(
                "memory_max", "+1073741824\n"
            ),
            "swap_underscore": lambda value: value.__setitem__(
                "memory_swap_max", "0_0\n"
            ),
            "mountinfo_type": lambda value: value["workspace"].__setitem__(
                "mountinfo", None
            ),
            "cpu_type": lambda value: value.__setitem__("cpu_max", 100000),
            "interfaces_type": lambda value: value.__setitem__(
                "interfaces", ("lo",)
            ),
            "unknown_field": lambda value: value.__setitem__("unknown", True),
        }
        for case, mutate in mutations.items():
            with self.subTest(case=case):
                value = copy.deepcopy(valid_observation())
                mutate(value)
                with self.assertRaisesRegex(
                    ProbeFailure, "^runtime probe failed$"
                ):
                    validate_runner_observation(value)


class RuntimeProbeFlowTests(unittest.TestCase):
    def test_latch_removal_requires_exact_content_and_parent_fsync(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            latch = root / RUNTIME_PROBE_LATCH_NAME
            expected = b"lil-tweak-runtime-probe-v1\n"
            latch.write_bytes(b"x" * len(expected))
            latch.chmod(0o600)
            identity = (latch.stat().st_dev, latch.stat().st_ino)
            with self.assertRaisesRegex(ProbeFailure, "^runtime probe failed$"):
                _remove_latch(root, identity)
            self.assertTrue(latch.exists())

            latch.write_bytes(expected)
            with patch(
                "core.lil_tweak.runtime_probe._fsync_parent",
                side_effect=OSError("fsync failed"),
            ):
                with self.assertRaisesRegex(
                    ProbeFailure, "^runtime probe failed$"
                ):
                    _remove_latch(root, identity)
            self.assertTrue(latch.exists())

    def test_probe_uses_ephemeral_then_patch_paths_and_cleans_everything(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []
            lock_blocked_during_create = []

            def execute(argv, **_kwargs):
                calls.append(list(argv))
                if argv[:2] == ["podman", "create"]:
                    try:
                        with runtime_execution_lock(root):
                            pass
                    except RuntimeExecutionBusy:
                        lock_blocked_during_create.append(True)
                    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
                if argv[:2] == ["podman", "exec"]:
                    if "patch" in argv:
                        return subprocess.CompletedProcess(
                            argv, 0, stdout="", stderr=""
                        )
                    return subprocess.CompletedProcess(
                        argv, 0, stdout=encoded_observation(), stderr=""
                    )
                if (
                    argv[:2] == ["podman", "cp"]
                    and len(argv) >= 4
                    and argv[2].endswith(":/workspace/.")
                ):
                    candidate = Path(argv[3])
                    workspace = next(
                        item
                        for item in root.iterdir()
                        if item.name.startswith("runtime-probe-")
                        and item.is_dir()
                    )
                    shutil.copytree(workspace, candidate, dirs_exist_ok=True)
                    (candidate / "result.txt").write_text(
                        "runtime-probe-ok\n", encoding="utf-8"
                    )
                if argv[:2] == ["podman", "ps"]:
                    return subprocess.CompletedProcess(
                        argv, 0, stdout="", stderr=""
                    )
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            image = "runner@sha256:" + "a" * 64
            result = run_runtime_probe(
                image=image,
                work_root=root,
                executor=execute,
                token_factory=lambda: "0123456789abcdef",
                environ=probe_environment(root, image),
                runtime_validator=lambda _root: None,
            )

            self.assertEqual(
                result,
                {"schema": "lil-tweak-runtime-probe-v1", "status": "ok"},
            )
            self.assertEqual(lock_blocked_during_create, [True, True])
            creates = [
                index
                for index, call in enumerate(calls)
                if call[:2] == ["podman", "create"]
            ]
            starts = [
                index
                for index, call in enumerate(calls)
                if call[:2] == ["podman", "start"]
            ]
            execs = [
                index
                for index, call in enumerate(calls)
                if call[:2] == ["podman", "exec"]
            ]
            removes = [
                index
                for index, call in enumerate(calls)
                if call[:2] == ["podman", "rm"]
            ]
            copy_out = [
                index
                for index, call in enumerate(calls)
                if call[:2] == ["podman", "cp"]
                and call[2].endswith(":/workspace/.")
            ]
            self.assertEqual(len(creates), 2)
            self.assertEqual(len(starts), 2)
            self.assertEqual(len(execs), 2)
            self.assertEqual(len(copy_out), 1)
            self.assertGreaterEqual(len(removes), 3)
            self.assertLess(creates[0], starts[0])
            self.assertLess(starts[0], execs[0])
            self.assertLess(execs[0], removes[0])
            self.assertLess(creates[1], starts[1])
            self.assertLess(starts[1], execs[1])
            self.assertLess(execs[1], copy_out[0])
            self.assertFalse(any(path.name.startswith("runtime-probe-") for path in root.iterdir()))
            self.assertFalse((root / RUNTIME_PROBE_LATCH_NAME).exists())
            self.assertIn("scratch-only.py", calls[execs[0]][-1])
            self.assertIn("scratch-only.bin", calls[execs[0]][-1])
            self.assertIn(
                [
                    "podman",
                    "ps",
                    "--all",
                    "--quiet",
                    "--no-trunc",
                    "--filter=name=^lt-runtime-probe-0123456789abcdef$",
                ],
                calls,
            )

    def test_busy_production_lock_prevents_probe_before_container_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []

            def execute(argv, **_kwargs):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            with runtime_execution_lock(root):
                with self.assertRaisesRegex(
                    ProbeFailure, "^runtime probe failed$"
                ):
                    image = "runner@sha256:" + "a" * 64
                    run_runtime_probe(
                        image=image,
                        work_root=root,
                        executor=execute,
                        token_factory=lambda: "0123456789abcdef",
                        environ=probe_environment(root, image),
                        runtime_validator=lambda _root: None,
                    )

            self.assertEqual(calls, [])

    def test_cleanup_failure_preserves_workspace_latch_and_closes_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def execute(argv, **_kwargs):
                if argv[:2] == ["podman", "rm"]:
                    return subprocess.CompletedProcess(argv, 1, stdout="", stderr="")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            image = "runner@sha256:" + "a" * 64
            with self.assertRaisesRegex(ProbeFailure, "^runtime probe failed$"):
                run_runtime_probe(
                    image=image,
                    work_root=root,
                    executor=execute,
                    token_factory=lambda: "0123456789abcdef",
                    environ=probe_environment(root, image),
                    runtime_validator=lambda _root: None,
                )

            self.assertTrue((root / RUNTIME_PROBE_LATCH_NAME).is_file())
            self.assertTrue((root / "runtime-probe-0123456789abcdef").is_dir())
            with self.assertRaisesRegex(
                RuntimeExecutionBusy, "^runtime execution busy$"
            ):
                with runtime_execution_lock(root):
                    pass

    def test_system_exit_preserves_base_exception_and_failed_cleanup_latch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def execute(argv, **_kwargs):
                if argv[:2] == ["podman", "create"]:
                    raise SystemExit("terminated")
                if argv[:2] == ["podman", "rm"]:
                    return subprocess.CompletedProcess(argv, 1, stdout="", stderr="")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            image = "runner@sha256:" + "a" * 64
            with self.assertRaisesRegex(SystemExit, "^terminated$"):
                run_runtime_probe(
                    image=image,
                    work_root=root,
                    executor=execute,
                    token_factory=lambda: "0123456789abcdef",
                    environ=probe_environment(root, image),
                    runtime_validator=lambda _root: None,
                )

            self.assertTrue((root / RUNTIME_PROBE_LATCH_NAME).is_file())
            self.assertTrue((root / "runtime-probe-0123456789abcdef").is_dir())
            with self.assertRaisesRegex(
                RuntimeExecutionBusy, "^runtime execution busy$"
            ):
                with runtime_execution_lock(root):
                    pass

    def test_running_core_environment_mismatch_fails_before_lock_or_create(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = "runner@sha256:" + "a" * 64
            valid = probe_environment(root, image)
            mutations = {
                "image": {**valid, "LIL_TWEAK_RUNNER_IMAGE": "other@sha256:" + "b" * 64},
                "root": {**valid, "LIL_TWEAK_WORK_ROOT": str(root / "other")},
                "inodes": {**valid, "LIL_TWEAK_WORK_ROOT_INODES": "204799"},
            }
            for case, environment in mutations.items():
                calls = []

                def execute(argv, **_kwargs):
                    calls.append(argv)
                    return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

                with self.subTest(case=case):
                    with self.assertRaisesRegex(
                        ProbeFailure, "^runtime probe failed$"
                    ):
                        run_runtime_probe(
                            image=image,
                            work_root=root,
                            executor=execute,
                            token_factory=lambda: "0123456789abcdef",
                            environ=environment,
                            runtime_validator=lambda _root: self.fail(
                                "mismatched environment reached runtime validation"
                            ),
                        )
                    self.assertEqual(calls, [])
                    self.assertFalse((root / ".execution.lock").exists())

    def test_unpinned_image_fails_before_runtime_validation_or_create(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for image in (
                "runner:latest",
                "runner@sha256:" + "A" * 64,
                "runner image@sha256:" + "a" * 64,
                "runner@sha256:abc",
            ):
                calls = []
                validations = []
                with self.subTest(image=image):
                    with self.assertRaisesRegex(
                        ProbeFailure, "^runtime probe failed$"
                    ):
                        run_runtime_probe(
                            image=image,
                            work_root=root,
                            executor=lambda argv, **_kwargs: calls.append(argv),
                            token_factory=lambda: "0123456789abcdef",
                            environ=probe_environment(root, image),
                            runtime_validator=lambda candidate: validations.append(
                                candidate
                            ),
                        )
                    self.assertEqual(validations, [])
                    self.assertEqual(calls, [])
                    self.assertFalse((root / ".execution.lock").exists())

    def test_running_core_runtime_validation_fails_before_lock_or_create(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = "runner@sha256:" + "a" * 64
            calls = []

            def execute(argv, **_kwargs):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            with self.assertRaisesRegex(ProbeFailure, "^runtime probe failed$"):
                run_runtime_probe(
                    image=image,
                    work_root=root,
                    executor=execute,
                    token_factory=lambda: "0123456789abcdef",
                    environ=probe_environment(root, image),
                    runtime_validator=lambda _root: (_ for _ in ()).throw(
                        OSError("secret cgroup detail")
                    ),
                )

            self.assertEqual(calls, [])
            self.assertFalse((root / ".execution.lock").exists())


if __name__ == "__main__":
    unittest.main()
