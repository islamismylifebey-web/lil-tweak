import json
import unittest

from core.lil_tweak.config import Config


def valid_environment():
    return {
        "LIL_TWEAK_DATABASE_URL": "postgresql://localhost/lil_tweak",
        "LIL_TWEAK_SIGNING_KEYS_JSON": json.dumps({"primary": "s" * 32}),
        "LIL_TWEAK_CANONICAL_OWNER_ID": "ab43c7488fb38a90c7bb9c4bcc0e23e5",
        "OPENAI_API_KEY": "test-only",
        "LIL_TWEAK_OPENAI_MODEL": "gpt-5.6-terra",
        "LIL_TWEAK_RUNNER_IMAGE": "runner@sha256:" + "a" * 64,
        "LIL_TWEAK_WORK_ROOT": "/srv/lil-tweak/jobs",
        "LIL_TWEAK_WORK_ROOT_INODES": "204800",
        "LIL_TWEAK_EVIDENCE_BUCKET": "evidence",
        "LIL_TWEAK_EVIDENCE_ENDPOINT": "https://account.r2.cloudflarestorage.com",
        "LIL_TWEAK_R2_ACCESS_KEY_ID": "access",
        "LIL_TWEAK_R2_SECRET_ACCESS_KEY": "secret",
    }


class ConfigTests(unittest.TestCase):
    def test_github_runner_is_explicit_and_requires_server_credentials(self):
        local = Config.from_env(valid_environment())
        self.assertEqual(getattr(local, "execution_backend", None), "local_podman")
        self.assertIsNone(getattr(local, "github_token", None))

        environment = valid_environment()
        environment.update(
            {
                "LIL_TWEAK_EXECUTION_BACKEND": "github_actions",
                "LIL_TWEAK_GITHUB_TOKEN": "g" * 40,
                "LIL_TWEAK_GITHUB_REPOSITORY": "islamismylifebey-web/lil-tweak",
            }
        )
        remote = Config.from_env(environment)
        self.assertEqual(remote.execution_backend, "github_actions")
        self.assertEqual(remote.github_repository, "islamismylifebey-web/lil-tweak")

        for missing in ("LIL_TWEAK_GITHUB_TOKEN", "LIL_TWEAK_GITHUB_REPOSITORY"):
            with self.subTest(missing=missing):
                invalid = dict(environment)
                del invalid[missing]
                with self.assertRaisesRegex(ValueError, "GitHub runner configuration"):
                    Config.from_env(invalid)

    def test_trusted_work_root_inode_capacity_is_exact_and_required(self):
        config = Config.from_env(valid_environment())
        self.assertEqual(getattr(config, "work_root_inodes", None), 204_800)

        for value in (None, "131072", "204801", "not-an-integer"):
            with self.subTest(value=value):
                environment = valid_environment()
                if value is None:
                    del environment["LIL_TWEAK_WORK_ROOT_INODES"]
                else:
                    environment["LIL_TWEAK_WORK_ROOT_INODES"] = value
                with self.assertRaisesRegex(
                    ValueError, "invalid work root inode capacity"
                ):
                    Config.from_env(environment)

    def test_canonical_owner_is_the_exact_control_plane_scope_shape(self):
        for owner in ("owner", "A" * 32, "a" * 31, "g" * 32, "0" * 32):
            with self.subTest(owner=owner):
                environment = valid_environment()
                environment["LIL_TWEAK_CANONICAL_OWNER_ID"] = owner
                with self.assertRaises(ValueError):
                    Config.from_env(environment)

    def test_galor_endpoint_requires_exact_credential_free_https_url(self):
        for url in (
            "http://galor.internal/context",
            "https://user:pass@galor.internal/context",
            "https://galor.internal/context?redirect=other",
        ):
            with self.subTest(url=url):
                environment = valid_environment()
                environment["LIL_TWEAK_GALOR_READONLY_URL"] = url
                with self.assertRaises(ValueError):
                    Config.from_env(environment)
        environment = valid_environment()
        environment["LIL_TWEAK_GALOR_READONLY_URL"] = (
            "https://galor-readonly.internal/v1/project-context"
        )
        self.assertEqual(
            Config.from_env(environment).galor_readonly_url,
            environment["LIL_TWEAK_GALOR_READONLY_URL"],
        )

    def test_admission_and_job_deadline_are_bounded(self):
        environment = valid_environment()
        environment.update(
            {
                "LIL_TWEAK_MAX_ADMITTED_JOBS": "1",
                "LIL_TWEAK_JOB_TIMEOUT_SECONDS": "900",
            }
        )
        config = Config.from_env(environment)
        self.assertEqual(config.max_admitted_jobs, 1)
        self.assertEqual(config.job_timeout_seconds, 900)
        for name, value in (
            ("LIL_TWEAK_MAX_ADMITTED_JOBS", "2"),
            ("LIL_TWEAK_JOB_TIMEOUT_SECONDS", "59"),
            ("LIL_TWEAK_JOB_TIMEOUT_SECONDS", "3601"),
        ):
            with self.subTest(name=name, value=value):
                invalid = valid_environment()
                invalid[name] = value
                with self.assertRaises(ValueError):
                    Config.from_env(invalid)

    def test_signing_keys_require_at_least_32_utf8_bytes(self):
        environment = valid_environment()
        environment["LIL_TWEAK_SIGNING_KEYS_JSON"] = json.dumps(
            {"primary": "too-short"}
        )
        with self.assertRaisesRegex(ValueError, "invalid signing key configuration"):
            Config.from_env(environment)

    def test_signing_key_ids_are_bounded_protocol_tokens(self):
        for key_id in ("bad key", "a" * 65, "line\nfeed"):
            with self.subTest(key_id=key_id):
                environment = valid_environment()
                environment["LIL_TWEAK_SIGNING_KEYS_JSON"] = json.dumps(
                    {key_id: "s" * 32}
                )
                with self.assertRaisesRegex(
                    ValueError, "invalid signing key configuration"
                ):
                    Config.from_env(environment)


if __name__ == "__main__":
    unittest.main()
