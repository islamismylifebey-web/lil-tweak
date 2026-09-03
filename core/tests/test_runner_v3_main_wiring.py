import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CORE_ROOT))
try:
    import main as core_main
finally:
    sys.path.pop(0)


def v3_config(directory):
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
        galor_readonly_url=None,
        max_admitted_jobs=1,
        job_timeout_seconds=1200,
        execution_backend="galor_v3",
        galor_runner_gateway_url="https://galor.example",
        galor_lil_tweak_service_token="s" * 32,
        repository_commit="a" * 40,
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


class RunnerV3MainWiringTests(unittest.TestCase):
    def build(self, directory, *, connected):
        boto3 = Mock()
        psycopg = Mock()
        runner = Mock()
        scheduler = Mock()
        app_factory = Mock(return_value=object())
        podman = Mock()
        handshake = SimpleNamespace(connected=connected)
        client = Mock()
        client.handshake.return_value = handshake
        client_ctor = Mock(return_value=client)
        config = v3_config(directory)

        stack = (
            patch.dict(sys.modules, sdk_modules(boto3, psycopg)),
            patch.object(core_main.Config, "from_env", return_value=config),
            patch.object(core_main, "PostgresJobStore"),
            patch.object(core_main, "R2EvidenceStore"),
            patch.object(core_main, "ResponsesClient"),
            patch.object(core_main, "is_bounded_work_root", return_value=True),
            patch.object(core_main, "reconcile_promotion_markers"),
            patch.object(core_main, "cleanup_patch_remnants"),
            patch.object(core_main, "PodmanSandbox", podman),
            patch.object(core_main, "BackgroundJobRunner", runner),
            patch.object(core_main, "DurableJobScheduler", scheduler),
            patch.object(core_main, "create_app", app_factory),
            patch.object(core_main, "GalorRunnerV3Client", new=client_ctor),
        )
        return stack, config, runner, app_factory, podman, client, client_ctor

    def test_v3_readiness_reports_authenticated_connection_without_qualification(self):
        for connected in (False, True):
            with self.subTest(connected=connected), tempfile.TemporaryDirectory() as directory:
                stack, config, _runner, app_factory, podman, client, client_ctor = self.build(
                    directory, connected=connected
                )
                with stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7], stack[8], stack[9], stack[10], stack[11], stack[12]:
                    core_main.build_app({})
                    readiness = app_factory.call_args.kwargs["readiness"]()

                self.assertEqual(readiness["galor_runner_connected"], connected)
                self.assertFalse(readiness["galor_runner_qualified"])
                self.assertEqual(readiness["runner"], connected)
                podman.cleanup_stale.assert_not_called()
                client.handshake.assert_called_once_with()
                client_ctor.assert_called_once_with(
                    config.galor_runner_gateway_url,
                    service_token=config.galor_lil_tweak_service_token,
                    repository_commit=config.repository_commit,
                )

    def test_v3_execution_never_falls_back_to_local_podman(self):
        with tempfile.TemporaryDirectory() as directory:
            stack, _config, runner, _app_factory, podman, _client, _client_ctor = self.build(
                directory, connected=True
            )
            with stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7], stack[8], stack[9], stack[10], stack[11], stack[12]:
                core_main.build_app({})
                execute_job = runner.call_args.args[0]
                with self.assertRaisesRegex(
                    RuntimeError, "^GALOR_RUNNER_V3_NOT_QUALIFIED$"
                ):
                    execute_job("job", "owner", [])

            podman.assert_not_called()
            podman.cleanup_stale.assert_not_called()


if __name__ == "__main__":
    unittest.main()
