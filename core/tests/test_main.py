import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import ANY, Mock, patch

CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CORE_ROOT))
try:
    import main as core_main
    from lil_tweak import limits as runtime_limits
    from lil_tweak.contracts import JobMode, JobState
    from lil_tweak.store import MemoryJobStore
finally:
    sys.path.pop(0)


def make_config(directory):
    return SimpleNamespace(
        database_url="postgresql://local/test",
        evidence_endpoint="https://account.r2.cloudflarestorage.com",
        aws_access_key_id="test-access",
        aws_secret_access_key="test-secret",
        evidence_bucket="evidence",
        openai_api_key="not-used",
        work_root=Path(directory),
        runner_image="runner@sha256:" + "a" * 64,
        work_root_inodes=204_800,
        openai_model="gpt-5.6-terra",
        signing_keys={"primary": b"s" * 32},
        canonical_owner_id="0123456789abcdef0123456789abcdef",
        git_allowed_hosts=(),
        max_admitted_jobs=1,
        job_timeout_seconds=1200,
    )


def sdk_modules(boto3, psycopg):
    botocore = ModuleType("botocore")
    botocore_config = ModuleType("botocore.config")
    botocore_config.Config = lambda **values: values
    return {
        "boto3": boto3,
        "psycopg": psycopg,
        "botocore": botocore,
        "botocore.config": botocore_config,
    }


class MainWiringTests(unittest.TestCase):
    def test_startup_reconciliation_finishes_before_runner_and_scheduler(self):
        boto3 = Mock()
        psycopg = Mock()
        events = []

        class Runner:
            has_capacity = True

            def __init__(self, *_args, **_kwargs):
                events.append("runner")

        class Scheduler:
            def __init__(self, *_args, **_kwargs):
                events.append("scheduler")

            def start(self):
                events.append("start")

            def notify(self):
                return None

        original_rmtree = core_main.shutil.rmtree

        def remove_snapshot(path, *args, **kwargs):
            events.append("snapshots")
            return original_rmtree(path, *args, **kwargs)

        @contextmanager
        def validate_execution_lock(_root):
            events.append("execution-lock")
            yield

        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / ".snapshots").mkdir()
            config = make_config(directory)
            with (
                patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                patch.object(core_main.Config, "from_env", return_value=config),
                patch.object(core_main, "PostgresJobStore"),
                patch.object(core_main, "R2EvidenceStore"),
                patch.object(core_main, "ResponsesClient"),
                patch.object(core_main, "is_bounded_work_root", return_value=True),
                patch.object(
                    core_main.PodmanSandbox,
                    "cleanup_stale",
                    side_effect=lambda: events.append("stale-runners"),
                ),
                patch.object(
                    core_main,
                    "reconcile_promotion_markers",
                    side_effect=lambda _root: events.append("promotion-markers"),
                ),
                patch.object(
                    core_main,
                    "cleanup_patch_remnants",
                    side_effect=lambda _root: events.append("ordinary-remnants"),
                ),
                patch.object(core_main.shutil, "rmtree", side_effect=remove_snapshot),
                patch.object(
                    core_main,
                    "runtime_execution_lock",
                    side_effect=validate_execution_lock,
                ),
                patch.object(core_main, "BackgroundJobRunner", Runner),
                patch.object(core_main, "DurableJobScheduler", Scheduler),
                patch.object(core_main, "create_app", return_value=object()),
            ):
                core_main.build_app({})

        self.assertEqual(
            events,
            [
                "execution-lock",
                "stale-runners",
                "promotion-markers",
                "ordinary-remnants",
                "snapshots",
                "runner",
                "scheduler",
                "start",
            ],
        )

    def test_startup_rejects_unprovable_execution_lock_before_admission(self):
        boto3 = Mock()
        psycopg = Mock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "not-a-lock"
            target.write_text("unsafe\n", encoding="utf-8")
            (root / ".execution.lock").symlink_to(target)
            config = make_config(directory)
            runner = Mock()
            scheduler = Mock()
            stale_cleanup = Mock()
            with (
                patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                patch.object(core_main.Config, "from_env", return_value=config),
                patch.object(core_main, "PostgresJobStore"),
                patch.object(core_main, "R2EvidenceStore"),
                patch.object(core_main, "ResponsesClient"),
                patch.object(core_main, "is_bounded_work_root", return_value=True),
                patch.object(
                    core_main.PodmanSandbox,
                    "cleanup_stale",
                    stale_cleanup,
                ),
                patch.object(core_main, "BackgroundJobRunner", runner),
                patch.object(core_main, "DurableJobScheduler", scheduler),
            ):
                with self.assertRaisesRegex(
                    core_main.RuntimeExecutionBusy,
                    "^runtime execution busy$",
                ):
                    core_main.build_app({})

            runner.assert_not_called()
            scheduler.assert_not_called()
            stale_cleanup.assert_not_called()

    def test_held_execution_lock_prevents_all_startup_cleanup(self):
        boto3 = Mock()
        psycopg = Mock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(directory)
            stale_cleanup = Mock()
            marker_cleanup = Mock()
            remnant_cleanup = Mock()
            snapshot_cleanup = Mock()
            runner = Mock()
            scheduler = Mock()
            with core_main.runtime_execution_lock(root):
                with (
                    patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                    patch.object(core_main.Config, "from_env", return_value=config),
                    patch.object(core_main, "PostgresJobStore"),
                    patch.object(core_main, "R2EvidenceStore"),
                    patch.object(core_main, "ResponsesClient"),
                    patch.object(core_main, "is_bounded_work_root", return_value=True),
                    patch.object(
                        core_main.PodmanSandbox,
                        "cleanup_stale",
                        stale_cleanup,
                    ),
                    patch.object(
                        core_main,
                        "reconcile_promotion_markers",
                        marker_cleanup,
                    ),
                    patch.object(
                        core_main,
                        "cleanup_patch_remnants",
                        remnant_cleanup,
                    ),
                    patch.object(
                        core_main.shutil,
                        "rmtree",
                        snapshot_cleanup,
                    ),
                    patch.object(core_main, "BackgroundJobRunner", runner),
                    patch.object(core_main, "DurableJobScheduler", scheduler),
                ):
                    with self.assertRaisesRegex(
                        core_main.RuntimeExecutionBusy,
                        "^runtime execution busy$",
                    ):
                        core_main.build_app({})

            stale_cleanup.assert_not_called()
            marker_cleanup.assert_not_called()
            remnant_cleanup.assert_not_called()
            snapshot_cleanup.assert_not_called()
            runner.assert_not_called()
            scheduler.assert_not_called()

    def test_held_execution_lock_closes_admission_and_readiness(self):
        boto3 = Mock()
        psycopg = Mock()
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            with (
                patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                patch.object(core_main.Config, "from_env", return_value=config),
                patch.object(core_main, "PostgresJobStore"),
                patch.object(core_main, "R2EvidenceStore"),
                patch.object(core_main, "ResponsesClient"),
                patch.object(core_main, "is_bounded_work_root", return_value=True),
                patch.object(core_main.PodmanSandbox, "cleanup_stale"),
                patch.object(core_main, "DurableJobScheduler"),
                patch.object(
                    core_main, "create_app", return_value=object()
                ) as app_factory,
            ):
                core_main.build_app({})
                readiness = app_factory.call_args.kwargs["readiness"]
                with core_main.runtime_execution_lock(Path(directory)):
                    self.assertFalse(readiness()["admission"])

    def test_every_startup_reconciliation_failure_blocks_admission(self):
        for failure in ("stale-runners", "promotion-markers", "ordinary-remnants", "snapshots"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                boto3 = Mock()
                psycopg = Mock()
                config = make_config(directory)
                snapshot_root = Path(directory) / ".snapshots"
                snapshot_root.mkdir()
                runner = Mock()
                scheduler = Mock()
                original_rmtree = core_main.shutil.rmtree

                def stale_cleanup():
                    if failure == "stale-runners":
                        raise RuntimeError("sandbox lifecycle failed")

                def marker_cleanup(_root):
                    if failure == "promotion-markers":
                        raise core_main.PromotionRecoveryRequired(
                            "patch_reconciliation_required"
                        )

                def remnant_cleanup(_root):
                    if failure == "ordinary-remnants":
                        raise core_main.PromotionRecoveryRequired(
                            "patch_cleanup_failed"
                        )

                def snapshot_cleanup(path, *args, **kwargs):
                    if failure == "snapshots":
                        raise OSError("snapshot cleanup failed")
                    return original_rmtree(path, *args, **kwargs)

                expected = {
                    "stale-runners": "sandbox lifecycle failed",
                    "promotion-markers": "patch_reconciliation_required",
                    "ordinary-remnants": "patch_cleanup_failed",
                    "snapshots": "patch_cleanup_failed",
                }[failure]
                with (
                    patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                    patch.object(core_main.Config, "from_env", return_value=config),
                    patch.object(core_main, "PostgresJobStore"),
                    patch.object(core_main, "R2EvidenceStore"),
                    patch.object(core_main, "ResponsesClient"),
                    patch.object(core_main, "is_bounded_work_root", return_value=True),
                    patch.object(
                        core_main.PodmanSandbox,
                        "cleanup_stale",
                        side_effect=stale_cleanup,
                    ),
                    patch.object(
                        core_main,
                        "reconcile_promotion_markers",
                        side_effect=marker_cleanup,
                    ),
                    patch.object(
                        core_main,
                        "cleanup_patch_remnants",
                        side_effect=remnant_cleanup,
                    ),
                    patch.object(
                        core_main.shutil,
                        "rmtree",
                        side_effect=snapshot_cleanup,
                    ),
                    patch.object(core_main, "BackgroundJobRunner", runner),
                    patch.object(core_main, "DurableJobScheduler", scheduler),
                ):
                    with self.assertRaisesRegex(Exception, f"^{expected}$"):
                        core_main.build_app({})

                runner.assert_not_called()
                scheduler.assert_not_called()

    def test_startup_snapshot_recreation_failure_is_content_free(self):
        boto3 = Mock()
        psycopg = Mock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = make_config(directory)
            runner = Mock()
            scheduler = Mock()
            original_mkdir = core_main.Path.mkdir

            def fail_snapshot_create(path, *args, **kwargs):
                if Path(path) == root / ".snapshots":
                    raise OSError("secret snapshot path")
                return original_mkdir(path, *args, **kwargs)

            with (
                patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                patch.object(core_main.Config, "from_env", return_value=config),
                patch.object(core_main, "PostgresJobStore"),
                patch.object(core_main, "R2EvidenceStore"),
                patch.object(core_main, "ResponsesClient"),
                patch.object(core_main, "is_bounded_work_root", return_value=True),
                patch.object(core_main.PodmanSandbox, "cleanup_stale"),
                patch.object(
                    core_main.Path,
                    "mkdir",
                    autospec=True,
                    side_effect=fail_snapshot_create,
                ),
                patch.object(core_main, "BackgroundJobRunner", runner),
                patch.object(core_main, "DurableJobScheduler", scheduler),
            ):
                with self.assertRaisesRegex(
                    core_main.PromotionRecoveryRequired,
                    "^patch_cleanup_failed$",
                ):
                    core_main.build_app({})

            runner.assert_not_called()
            scheduler.assert_not_called()

    def test_startup_rejects_malformed_promotion_marker_before_snapshot_or_scheduler(self):
        boto3 = Mock()
        psycopg = Mock()
        with tempfile.TemporaryDirectory() as directory:
            work_root = Path(directory)
            snapshot = work_root / ".snapshots" / "job" / "baseline"
            snapshot.mkdir(parents=True)
            sentinel = snapshot / "source.py"
            sentinel.write_text("preserve\n")
            marker = work_root / ".job-promotion-v1.json"
            marker.write_text("{}")
            marker.chmod(0o600)
            config = make_config(directory)
            events = []
            scheduler = Mock()
            with (
                patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                patch.object(core_main.Config, "from_env", return_value=config),
                patch.object(core_main, "PostgresJobStore"),
                patch.object(core_main, "R2EvidenceStore"),
                patch.object(core_main, "ResponsesClient"),
                patch.object(core_main, "is_bounded_work_root", return_value=True),
                patch.object(
                    core_main.PodmanSandbox,
                    "cleanup_stale",
                    side_effect=lambda: events.append("runners"),
                ),
                patch.object(core_main, "DurableJobScheduler", scheduler),
            ):
                with self.assertRaisesRegex(
                    core_main.PromotionRecoveryRequired,
                    "patch_reconciliation_required",
                ):
                    core_main.build_app({})

            self.assertEqual(events, ["runners"])
            self.assertEqual(sentinel.read_text(), "preserve\n")
            scheduler.assert_not_called()

    def test_system_exit_with_recovery_marker_preserves_workspace_and_snapshots(self):
        boto3 = Mock()
        psycopg = Mock()

        class Sandbox:
            lifecycle_failed = False

            @classmethod
            def cleanup_stale(cls):
                return None

            def __init__(self, **_kwargs):
                pass

            def teardown(self):
                pass

        with tempfile.TemporaryDirectory() as directory:
            work_root = Path(directory)
            config = make_config(directory)
            runner = Mock()
            with (
                patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                patch.object(core_main.Config, "from_env", return_value=config),
                patch.object(core_main, "PostgresJobStore"),
                patch.object(core_main, "R2EvidenceStore"),
                patch.object(core_main, "ResponsesClient"),
                patch.object(core_main, "is_bounded_work_root", return_value=True),
                patch.object(core_main, "PodmanSandbox", Sandbox),
                patch.object(core_main, "BackgroundJobRunner", runner),
                patch.object(core_main, "DurableJobScheduler"),
                patch.object(core_main, "create_app", return_value=object()),
            ):
                core_main.build_app({})
                execute_job = runner.call_args.args[0]
                workspace = work_root / "job"
                workspace.mkdir()
                (workspace / "source.py").write_text("preserve\n")
                baseline = work_root / ".snapshots" / "job" / "attempt" / "baseline"
                baseline.mkdir(parents=True)
                (baseline / "source.py").write_text("preserve\n")
                marker = work_root / ".job-promotion-v1.json"
                marker.write_text("{}")
                marker.chmod(0o600)
                with patch.object(
                    core_main.EngineeringOrchestrator,
                    "run_job",
                    side_effect=SystemExit("crash"),
                ):
                    with self.assertRaises(SystemExit):
                        execute_job("job", "owner", [])

            self.assertEqual((workspace / "source.py").read_text(), "preserve\n")
            self.assertTrue(marker.exists())
            self.assertEqual((baseline / "source.py").read_text(), "preserve\n")

    def test_runtime_reconciliation_failure_latches_admission_closed(self):
        boto3 = Mock()
        psycopg = Mock()
        store = MemoryJobStore()
        job = store.create_job("owner", "runtime-marker", JobMode.BUILD, "Build")
        store.update_job(
            job.id, owner_id="owner", expected_revision=0, state=JobState.QUEUED
        )
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            runner = Mock()
            reconcile = Mock(
                side_effect=[(), core_main.PromotionRecoveryRequired("blocked")]
            )
            with (
                patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                patch.object(core_main.Config, "from_env", return_value=config),
                patch.object(core_main, "PostgresJobStore", return_value=store),
                patch.object(core_main, "R2EvidenceStore"),
                patch.object(core_main, "ResponsesClient"),
                patch.object(core_main, "is_bounded_work_root", return_value=True),
                patch.object(core_main.PodmanSandbox, "cleanup_stale"),
                patch.object(core_main, "reconcile_promotion_markers", reconcile),
                patch.object(core_main, "cleanup_patch_remnants"),
                patch.object(core_main, "BackgroundJobRunner", runner),
                patch.object(core_main, "DurableJobScheduler"),
                patch.object(core_main, "create_app", return_value=object()),
            ):
                core_main.build_app({})
                prepare = runner.call_args.kwargs["source_intake"]
                guard = runner.call_args.kwargs["admission_guard"]
                with self.assertRaises(core_main.PromotionRecoveryRequired):
                    prepare(job.id, "owner")
                self.assertFalse(guard())
                with self.assertRaises(core_main.PromotionRecoveryRequired):
                    prepare(job.id, "owner")

            self.assertEqual(reconcile.call_count, 2)

    def test_work_root_requires_its_own_size_and_inode_bounded_tmpfs_mount(self):
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
        mountinfo = "36 25 0:32 / /work rw,nosuid,nodev - tmpfs tmpfs rw,size=1073741824,nr_inodes=204800\n"
        valid = SimpleNamespace(
            f_frsize=4096,
            f_blocks=(1024 * 1024 * 1024) // 4096,
            f_files=204_800,
        )
        self.assertTrue(
            core_main.is_bounded_work_root(
                Path("/work"),
                mountinfo_text=mountinfo,
                statvfs=lambda _path: valid,
            )
        )
        for bad_mountinfo, stats in (
            (mountinfo.replace(" - tmpfs ", " - ext4 "), valid),
            (mountinfo.replace(" /work ", " / "), valid),
            (mountinfo, SimpleNamespace(f_frsize=4096, f_blocks=262_143, f_files=204_800)),
            (mountinfo, SimpleNamespace(f_frsize=4096, f_blocks=300_000, f_files=204_800)),
            (mountinfo, SimpleNamespace(f_frsize=4096, f_blocks=262_144, f_files=204_799)),
            (mountinfo, SimpleNamespace(f_frsize=4096, f_blocks=262_144, f_files=204_801)),
        ):
            with self.subTest(mountinfo=bad_mountinfo, stats=stats):
                self.assertFalse(
                    core_main.is_bounded_work_root(
                        Path("/work"),
                        mountinfo_text=bad_mountinfo,
                        statvfs=lambda _path, value=stats: value,
                    )
                )

    def test_teardown_failure_preserves_workspace_and_latches_admission_closed(self):
        boto3 = Mock()
        psycopg = Mock()

        class Sandbox:
            lifecycle_failed = False

            @classmethod
            def cleanup_stale(cls):
                return None

            def __init__(self, **_kwargs):
                pass

            def teardown(self):
                self.lifecycle_failed = True
                raise RuntimeError("sandbox lifecycle failed")

        with tempfile.TemporaryDirectory() as directory:
            work_root = Path(directory)
            config = make_config(directory)
            runner = Mock()
            with (
                patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                patch.object(core_main.Config, "from_env", return_value=config),
                patch.object(core_main, "PostgresJobStore"),
                patch.object(core_main, "R2EvidenceStore"),
                patch.object(core_main, "ResponsesClient"),
                patch.object(core_main, "is_bounded_work_root", return_value=True),
                patch.object(core_main, "PodmanSandbox", Sandbox),
                patch.object(core_main, "BackgroundJobRunner", runner),
                patch.object(core_main, "DurableJobScheduler"),
                patch.object(core_main, "create_app", return_value=object()),
            ):
                core_main.build_app({})
                execute_job = runner.call_args.args[0]
                guard = runner.call_args.kwargs["admission_guard"]
                workspace = work_root / "job"
                workspace.mkdir()
                (workspace / "source.py").write_text("preserve\n")
                with patch.object(
                    core_main.EngineeringOrchestrator,
                    "run_job",
                    return_value=object(),
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "sandbox lifecycle failed"
                    ):
                        execute_job("job", "owner", [])

            self.assertTrue(workspace.exists())
            self.assertFalse(guard())

    def test_final_workspace_cleanup_failure_latches_admission_closed(self):
        boto3 = Mock()
        psycopg = Mock()

        class Sandbox:
            lifecycle_failed = False

            @classmethod
            def cleanup_stale(cls):
                return None

            def __init__(self, **_kwargs):
                pass

            def teardown(self):
                return None

        with tempfile.TemporaryDirectory() as directory:
            work_root = Path(directory)
            config = make_config(directory)
            runner = Mock()
            original_rmtree = core_main.shutil.rmtree
            with (
                patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                patch.object(core_main.Config, "from_env", return_value=config),
                patch.object(core_main, "PostgresJobStore"),
                patch.object(core_main, "R2EvidenceStore"),
                patch.object(core_main, "ResponsesClient"),
                patch.object(core_main, "is_bounded_work_root", return_value=True),
                patch.object(core_main, "PodmanSandbox", Sandbox),
                patch.object(core_main, "BackgroundJobRunner", runner),
                patch.object(core_main, "DurableJobScheduler"),
                patch.object(core_main, "create_app", return_value=object()),
            ):
                core_main.build_app({})
                execute_job = runner.call_args.args[0]
                guard = runner.call_args.kwargs["admission_guard"]
                workspace = work_root / "job"
                workspace.mkdir()
                (workspace / "source.py").write_text("preserve\n")

                def fail_workspace_cleanup(path, *args, **kwargs):
                    if Path(path) == workspace:
                        raise OSError("secret cleanup detail")
                    return original_rmtree(path, *args, **kwargs)

                with (
                    patch.object(
                        core_main.EngineeringOrchestrator,
                        "run_job",
                        return_value=object(),
                    ),
                    patch.object(
                        core_main.shutil,
                        "rmtree",
                        side_effect=fail_workspace_cleanup,
                    ),
                ):
                    with self.assertRaisesRegex(
                        core_main.PromotionRecoveryRequired,
                        "^patch_cleanup_failed$",
                    ):
                        execute_job("job", "owner", [])

            self.assertTrue(workspace.exists())
            self.assertFalse(guard())

    def test_source_intake_cleanup_failures_preserve_tree_and_latch_admission(self):
        for phase in ("preexisting-snapshot", "preexisting-workspace", "failed-intake"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                boto3 = Mock()
                psycopg = Mock()
                store = MemoryJobStore()
                job = store.create_job("owner", phase, JobMode.BUILD, "Build")
                store.update_job(
                    job.id,
                    owner_id="owner",
                    expected_revision=0,
                    state=JobState.QUEUED,
                )
                work_root = Path(directory)
                config = make_config(directory)
                runner = Mock()
                with (
                    patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                    patch.object(core_main.Config, "from_env", return_value=config),
                    patch.object(core_main, "PostgresJobStore", return_value=store),
                    patch.object(core_main, "R2EvidenceStore"),
                    patch.object(core_main, "ResponsesClient"),
                    patch.object(core_main, "is_bounded_work_root", return_value=True),
                    patch.object(core_main.PodmanSandbox, "cleanup_stale"),
                    patch.object(core_main, "reconcile_promotion_markers"),
                    patch.object(core_main, "cleanup_patch_remnants"),
                    patch.object(core_main, "BackgroundJobRunner", runner),
                    patch.object(core_main, "DurableJobScheduler"),
                    patch.object(core_main, "create_app", return_value=object()),
                ):
                    core_main.build_app({})
                    prepare = runner.call_args.kwargs["source_intake"]
                    guard = runner.call_args.kwargs["admission_guard"]
                    workspace = work_root / job.id
                    snapshot = work_root / ".snapshots" / job.id
                    target = snapshot if phase == "preexisting-snapshot" else workspace
                    if phase != "failed-intake":
                        target.mkdir(parents=True)
                        (target / "preserve.txt").write_text("preserve\n")
                    original_rmtree = core_main.shutil.rmtree

                    def fail_cleanup(path, *args, **kwargs):
                        if Path(path) == target and target.exists():
                            if kwargs.get("ignore_errors"):
                                return None
                            raise OSError("secret cleanup detail")
                        return original_rmtree(path, *args, **kwargs)

                    def ingest_failure(*_args):
                        (workspace / "preserve.txt").write_text("preserve\n")
                        raise RuntimeError("intake failed")

                    ingest_error = ingest_failure if phase == "failed-intake" else None
                    with (
                        patch.object(
                            core_main,
                            "ingest_r2_sources",
                            side_effect=ingest_error,
                        ),
                        patch.object(
                            core_main.shutil,
                            "rmtree",
                            side_effect=fail_cleanup,
                        ),
                    ):
                        with self.assertRaisesRegex(
                            core_main.PromotionRecoveryRequired,
                            "^patch_cleanup_failed$",
                        ):
                            prepare(job.id, "owner")

                    self.assertTrue(target.exists())
                    self.assertFalse(guard())

    def test_source_allocation_and_failure_recording_cannot_skip_cleanup(self):
        class RecordingFailureStore(MemoryJobStore):
            fail_recording = False

            def get_job(self, *args, **kwargs):
                if self.fail_recording:
                    raise RuntimeError("database unavailable")
                return super().get_job(*args, **kwargs)

        for phase in ("partial-mkdir", "recording-failure"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                boto3 = Mock()
                psycopg = Mock()
                store = RecordingFailureStore()
                job = store.create_job("owner", phase, JobMode.BUILD, "Build")
                store.update_job(
                    job.id,
                    owner_id="owner",
                    expected_revision=0,
                    state=JobState.QUEUED,
                )
                work_root = Path(directory)
                workspace = work_root / job.id
                config = make_config(directory)
                runner = Mock()
                with (
                    patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                    patch.object(core_main.Config, "from_env", return_value=config),
                    patch.object(core_main, "PostgresJobStore", return_value=store),
                    patch.object(core_main, "R2EvidenceStore"),
                    patch.object(core_main, "ResponsesClient"),
                    patch.object(core_main, "is_bounded_work_root", return_value=True),
                    patch.object(core_main.PodmanSandbox, "cleanup_stale"),
                    patch.object(core_main, "reconcile_promotion_markers"),
                    patch.object(core_main, "cleanup_patch_remnants"),
                    patch.object(core_main, "BackgroundJobRunner", runner),
                    patch.object(core_main, "DurableJobScheduler"),
                    patch.object(core_main, "create_app", return_value=object()),
                ):
                    core_main.build_app({})
                    prepare = runner.call_args.kwargs["source_intake"]
                    guard = runner.call_args.kwargs["admission_guard"]
                    original_mkdir = core_main.Path.mkdir

                    def allocate_then_fail(path, *args, **kwargs):
                        result = original_mkdir(path, *args, **kwargs)
                        if phase == "partial-mkdir" and Path(path) == workspace:
                            (workspace / "preserve.txt").write_text("preserve\n")
                            raise OSError("allocation failed")
                        return result

                    def ingest_then_fail(*_args):
                        (workspace / "preserve.txt").write_text("preserve\n")
                        store.fail_recording = True
                        raise RuntimeError("intake failed")

                    def fail_cleanup(path, *_args, **_kwargs):
                        if Path(path) == workspace and workspace.exists():
                            raise OSError("cleanup failed")
                        return None

                    with (
                        patch.object(
                            core_main.Path,
                            "mkdir",
                            side_effect=allocate_then_fail,
                            autospec=True,
                        ),
                        patch.object(
                            core_main,
                            "ingest_r2_sources",
                            side_effect=(
                                ingest_then_fail
                                if phase == "recording-failure"
                                else None
                            ),
                        ),
                        patch.object(
                            core_main.shutil,
                            "rmtree",
                            side_effect=fail_cleanup,
                        ),
                    ):
                        with self.assertRaisesRegex(
                            core_main.PromotionRecoveryRequired,
                            "^patch_cleanup_failed$",
                        ):
                            prepare(job.id, "owner")

                    self.assertTrue(workspace.exists())
                    self.assertFalse(guard())

    def test_source_intake_runs_while_job_is_ingesting(self):
        boto3 = Mock()
        psycopg = Mock()
        store = MemoryJobStore()
        job = store.create_job("owner", "source-state", JobMode.BUILD, "Build")
        job = store.update_job(
            job.id, owner_id="owner", expected_revision=0, state=JobState.QUEUED
        )
        observed_states = []

        def ingest(*args):
            observed_states.append(store.get_job(job.id, "owner").state)
            return ["src/main.py"]

        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            runner = Mock()
            with (
                patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                patch.object(core_main.Config, "from_env", return_value=config),
                patch.object(core_main, "PostgresJobStore", return_value=store),
                patch.object(core_main, "R2EvidenceStore"),
                patch.object(core_main, "ResponsesClient"),
                patch.object(core_main, "is_bounded_work_root", return_value=True),
                patch.object(core_main.PodmanSandbox, "cleanup_stale"),
                patch.object(core_main, "ingest_r2_sources", side_effect=ingest),
                patch.object(core_main, "BackgroundJobRunner", runner),
                patch.object(core_main, "DurableJobScheduler"),
                patch.object(core_main, "create_app", return_value=object()),
            ):
                core_main.build_app({})
                prepare_sources = runner.call_args.kwargs["source_intake"]
                inventory = prepare_sources(job.id, "owner")
        self.assertEqual(inventory, ["src/main.py"])
        self.assertEqual(observed_states, [JobState.INGESTING])
        self.assertEqual(store.get_job(job.id, "owner").state, JobState.INGESTING)

    def test_source_intake_failure_terminates_the_ingesting_job(self):
        boto3 = Mock()
        psycopg = Mock()
        store = MemoryJobStore()
        job = store.create_job("owner", "source-failure", JobMode.BUILD, "Build")
        job = store.update_job(
            job.id, owner_id="owner", expected_revision=0, state=JobState.QUEUED
        )
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            runner = Mock()
            with (
                patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                patch.object(core_main.Config, "from_env", return_value=config),
                patch.object(core_main, "PostgresJobStore", return_value=store),
                patch.object(core_main, "R2EvidenceStore"),
                patch.object(core_main, "ResponsesClient"),
                patch.object(core_main, "is_bounded_work_root", return_value=True),
                patch.object(core_main.PodmanSandbox, "cleanup_stale"),
                patch.object(
                    core_main,
                    "ingest_r2_sources",
                    side_effect=RuntimeError("download failed"),
                ),
                patch.object(core_main, "BackgroundJobRunner", runner),
                patch.object(core_main, "DurableJobScheduler"),
                patch.object(core_main, "create_app", return_value=object()),
            ):
                core_main.build_app({})
                prepare_sources = runner.call_args.kwargs["source_intake"]
                with self.assertRaisesRegex(RuntimeError, "download failed"):
                    prepare_sources(job.id, "owner")
                self.assertFalse((Path(directory) / job.id).exists())
        failed = store.get_job(job.id, "owner")
        self.assertEqual(failed.state, JobState.FAILED)
        self.assertEqual(
            store.list_events(job.id, "owner")[-1].kind,
            "source_intake_failed",
        )

    def test_r2_client_uses_cloudflare_auto_region(self):
        boto3 = Mock()
        psycopg = Mock()
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            with (
                patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
                patch.object(core_main.Config, "from_env", return_value=config),
                patch.object(core_main, "PostgresJobStore"),
                patch.object(core_main, "R2EvidenceStore"),
                patch.object(core_main, "ResponsesClient"),
                patch.object(core_main, "is_bounded_work_root", return_value=True),
                patch.object(core_main.PodmanSandbox, "cleanup_stale"),
                patch.object(core_main, "BackgroundJobRunner") as runner_type,
                patch.object(core_main, "DurableJobScheduler"),
                patch.object(core_main.shutil, "which", return_value="/usr/bin/podman"),
                patch.object(
                    core_main.subprocess,
                    "run",
                    return_value=SimpleNamespace(returncode=0),
                ) as podman_probe,
                patch.object(
                    core_main, "create_app", return_value=object()
                ) as app_factory,
            ):
                runner_type.return_value.has_capacity = False
                core_main.build_app({})
                readiness = app_factory.call_args.kwargs["readiness"]
                self.assertFalse(readiness()["admission"])
                self.assertTrue(readiness()["runner"])
                self.assertTrue(readiness()["git"])
                self.assertTrue(readiness()["evidence"])
                self.assertTrue(readiness()["workspace"])
                self.assertFalse(podman_probe.call_args.kwargs["shell"])
                boto3.client.return_value.head_bucket.assert_called_with(
                    Bucket=config.evidence_bucket
                )
        boto3.client.assert_called_once_with(
            "s3",
            endpoint_url=config.evidence_endpoint,
            region_name="auto",
            aws_access_key_id=config.aws_access_key_id,
            aws_secret_access_key=config.aws_secret_access_key,
            config=ANY,
        )


if __name__ == "__main__":
    unittest.main()
