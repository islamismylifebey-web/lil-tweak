import inspect
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CORE_ROOT))
try:
    import main as core_main
finally:
    sys.path.pop(0)


OWNER = "0123456789abcdef0123456789abcdef"


def make_config(directory):
    return SimpleNamespace(
        database_url="postgresql://local/test",
        runner_image="registry.example/runner@sha256:" + "a" * 64,
        git_allowed_hosts=("github.com",),
        openai_model="gpt-test",
        job_timeout_seconds=1200,
        signing_keys={"primary": b"s" * 32},
        canonical_owner_id=OWNER,
    )


class TestWorldMainWiringTests(unittest.TestCase):
    def test_builder_reuses_host_client_signed_owner_and_execution_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            job_store = Mock(name="job_store")
            responses = object()
            base_app = object()
            world_store = Mock(name="world_store")
            runtime = Mock(name="runtime")
            runner = Mock(name="runner")
            scheduler = Mock(name="scheduler")
            wrapped = object()
            lock_entries = []

            @contextmanager
            def lock(root):
                lock_entries.append(Path(root))
                yield

            with (
                patch.object(core_main, "PostgresTestWorldStore", return_value=world_store) as store_factory,
                patch.object(core_main, "TestWorldRuntime", return_value=runtime) as runtime_factory,
                patch.object(core_main, "TestWorldAttemptRunner", return_value=runner) as runner_factory,
                patch.object(core_main, "TestWorldScheduler", return_value=scheduler) as scheduler_factory,
                patch.object(core_main, "TestWorldApi", return_value=wrapped) as api_factory,
                patch.object(core_main, "runtime_execution_lock", side_effect=lock),
            ):
                result = core_main._build_test_world_app(
                    config=config,
                    job_store=job_store,
                    responses=responses,
                    reviewed_instructions="reviewed",
                    work_root=Path(directory),
                    connect=lambda: object(),
                    fallback=base_app,
                )

            self.assertIs(result, wrapped)
            self.assertTrue(callable(store_factory.call_args.args[0]))
            runtime_kwargs = runtime_factory.call_args.kwargs
            self.assertIs(runtime_kwargs["responses_client"], responses)
            self.assertEqual(runtime_kwargs["work_root"], Path(directory))
            self.assertEqual(runtime_kwargs["git_allowed_hosts"], ("github.com",))
            self.assertEqual(runtime_kwargs["runner_image"], config.runner_image)

            runner_kwargs = runner_factory.call_args.kwargs
            self.assertIs(runner_kwargs["store"], world_store)
            self.assertIs(runner_kwargs["prepare_workspace"], runtime.prepare_workspace)

            scheduler_args = scheduler_factory.call_args.args
            scheduler_kwargs = scheduler_factory.call_args.kwargs
            self.assertEqual(scheduler_args, (world_store, runner))
            self.assertEqual(runner_kwargs["worker_id"], scheduler_kwargs["worker_id"])
            with scheduler_kwargs["execution_guard"]():
                pass
            self.assertEqual(lock_entries, [Path(directory)])
            scheduler.start.assert_called_once_with()

            api_kwargs = api_factory.call_args.kwargs
            self.assertIs(api_kwargs["fallback"], base_app)
            self.assertIs(api_kwargs["nonce_store"], job_store)
            self.assertIs(api_kwargs["world_store"], world_store)
            self.assertEqual(api_kwargs["signing_keys"], config.signing_keys)
            self.assertEqual(api_kwargs["canonical_owner_id"], OWNER)
            self.assertIs(api_kwargs["on_attempt_queued"], scheduler.notify)

    def test_build_app_wraps_existing_core_app_in_test_world_boundary(self):
        source = inspect.getsource(core_main.build_app)
        self.assertIn("base_app = create_app(", source)
        self.assertIn("return _build_test_world_app(", source)
        self.assertIn("fallback=base_app", source)


if __name__ == "__main__":
    unittest.main()
