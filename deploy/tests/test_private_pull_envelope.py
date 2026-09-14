from __future__ import annotations

from datetime import UTC, datetime, timedelta
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "lil-tweak-private-pull-envelope.py"
SOURCE_COMMIT = "1" * 40
NONCE = "2" * 64
CORE_IMAGE = "ghcr.io/example/lil-tweak-core@sha256:" + "a" * 64
POSTGRES_IMAGE = "ghcr.io/example/lil-tweak-postgres@sha256:" + "b" * 64
RUNNER_IMAGE = "ghcr.io/example/lil-tweak-runner@sha256:" + "c" * 64
FAKE_PUBLIC_KEY = (
    "-----BEGIN PUBLIC KEY-----\nQQ==\n-----END PUBLIC KEY-----\n"
)
TOKEN = "github-test-token-that-must-never-be-printed"


def future_deadline(minutes: int = 10) -> str:
    value = datetime.now(UTC) + timedelta(minutes=minutes)
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_module():
    specification = importlib.util.spec_from_file_location(
        "lil_tweak_private_pull_envelope", SCRIPT
    )
    if specification is None or specification.loader is None:
        raise AssertionError("private pull envelope helper could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def invoke(
    *,
    workflow_ref: str = "refs/heads/main",
    openssl: str = "/definitely/missing/openssl",
    workflow_sha: str = SOURCE_COMMIT,
    source_commit: str = SOURCE_COMMIT,
    nonce: str = NONCE,
    recipient_expires_at: str | None = None,
    repository: str = "example/lil-tweak",
    run_id: str = "123456789",
    run_attempt: str = "1",
    core_image: str = CORE_IMAGE,
    postgres_image: str = POSTGRES_IMAGE,
    runner_image: str = RUNNER_IMAGE,
    recipient_public_key_base64: str | None = None,
    actor: str = "release-operator",
    token: str = TOKEN,
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment.update(
        {
            "LIL_TWEAK_GHCR_ACTOR": actor,
            "LIL_TWEAK_GHCR_TOKEN": token,
        }
    )
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            str(SCRIPT),
            "issue",
            "--openssl",
            openssl,
            "--recipient-public-key-base64",
            recipient_public_key_base64
            or base64.b64encode(FAKE_PUBLIC_KEY.encode()).decode(),
            "--nonce",
            nonce,
            "--recipient-expires-at",
            recipient_expires_at or future_deadline(),
            "--repository",
            repository,
            "--run-id",
            run_id,
            "--run-attempt",
            run_attempt,
            "--workflow-ref",
            workflow_ref,
            "--workflow-sha",
            workflow_sha,
            "--source-commit",
            source_commit,
            "--core-image",
            core_image,
            "--postgres-image",
            postgres_image,
            "--runner-image",
            runner_image,
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


class PrivatePullEnvelopeTests(unittest.TestCase):
    @unittest.skipUnless(Path('/usr/bin/openssl').is_file(), 'real OpenSSL requires Linux CI')
    def test_real_rsa_oaep_roundtrip_does_not_disclose_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / 'private.pem'
            subprocess.run(['/usr/bin/openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:4096', '-out', str(key)], check=True, capture_output=True)
            public = subprocess.run(['/usr/bin/openssl', 'pkey', '-in', str(key), '-pubout'], check=True, capture_output=True).stdout
            result = invoke(openssl='/usr/bin/openssl', recipient_public_key_base64=base64.b64encode(public).decode())
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(TOKEN, result.stdout + result.stderr)
            fields = dict(line.split('=', 1) for line in result.stdout.splitlines())
            context = base64.b64decode(fields['PRIVATE_PULL_CONTEXT_BASE64'], validate=True)
            encrypted = base64.b64decode(fields['PRIVATE_PULL_CIPHERTEXT_BASE64'], validate=True)
            self.assertEqual(len(encrypted), 512)
            plain = subprocess.run(['/usr/bin/openssl', 'pkeyutl', '-decrypt', '-inkey', str(key), '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256', '-pkeyopt', 'rsa_mgf1_md:sha256'], input=encrypted, check=True, capture_output=True).stdout
            payload = json.loads(plain)
            self.assertEqual(payload['binding_sha256'], hashlib.sha256(context).hexdigest())
            self.assertEqual(payload['nonce'], NONCE)
            self.assertEqual(base64.b64decode(payload['auths']['ghcr.io']['auth']), ('release-operator:' + TOKEN).encode())

    def test_non_main_workflow_ref_is_rejected_without_exposing_token(self) -> None:
        result = invoke(workflow_ref="refs/heads/release")

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            "private-pull-envelope: invalid request\n",
        )
        self.assertNotIn(TOKEN, result.stderr)

    def test_missing_openssl_fails_closed_after_local_request_validation(self) -> None:
        result = invoke()

        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            result.stderr,
            "private-pull-envelope: cryptography unavailable\n",
        )
        self.assertNotIn(TOKEN, result.stderr)

    def test_public_release_binding_is_validated_before_cryptography(self) -> None:
        invalid_requests = {
            "workflow/source mismatch": {"workflow_sha": "3" * 40},
            "uppercase source commit": {"source_commit": "A" * 40},
            "non-GHCR core": {
                "core_image": "docker.io/example/core@sha256:" + "a" * 64
            },
            "public PostgreSQL instead of private mirror": {
                "postgres_image": "docker.io/library/postgres@sha256:" + "b" * 64
            },
            "mutable runner": {"runner_image": "ghcr.io/example/runner:latest"},
            "short nonce": {"nonce": "2" * 63},
            "expired recipient": {"recipient_expires_at": future_deadline(-1)},
            "recipient over twenty minutes": {
                "recipient_expires_at": future_deadline(25)
            },
            "nonnumeric run": {"run_id": "run-123"},
            "unsafe repository": {"repository": "example/lil tweak"},
        }
        for label, changes in invalid_requests.items():
            with self.subTest(label=label):
                result = invoke(**changes)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr,
                    "private-pull-envelope: invalid request\n",
                )
                self.assertNotIn(TOKEN, result.stderr)

    def test_recipient_public_key_encoding_is_validated_before_openssl(self) -> None:
        invalid_keys = {
            "not base64": "not+base64!",
            "wrong PEM type": base64.b64encode(
                b"-----BEGIN PRIVATE KEY-----\nQQ==\n-----END PRIVATE KEY-----\n"
            ).decode("ascii"),
            "trailing data": base64.b64encode(
                FAKE_PUBLIC_KEY.encode("ascii") + b"unexpected"
            ).decode("ascii"),
            "oversized": base64.b64encode(
                b"-----BEGIN PUBLIC KEY-----\n"
                + b"A" * 5000
                + b"\n-----END PUBLIC KEY-----\n"
            ).decode("ascii"),
        }
        for label, encoded_key in invalid_keys.items():
            with self.subTest(label=label):
                result = invoke(recipient_public_key_base64=encoded_key)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(
                    result.stderr,
                    "private-pull-envelope: invalid request\n",
                )
                self.assertNotIn(TOKEN, result.stderr)

    def test_payload_contains_only_ghcr_auth_nonce_and_public_binding(self) -> None:
        module = load_module()
        now = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
        expires_at = "2030-01-02T03:14:05Z"

        context_bytes, payload = module.build_context_and_payload(
            recipient_public_key=FAKE_PUBLIC_KEY.encode("ascii"),
            nonce=NONCE,
            recipient_expires_at=expires_at,
            repository="example/lil-tweak",
            run_id="123456789",
            run_attempt="1",
            workflow_ref="refs/heads/main",
            workflow_sha=SOURCE_COMMIT,
            source_commit=SOURCE_COMMIT,
            core_image=CORE_IMAGE,
            postgres_image=POSTGRES_IMAGE,
            runner_image=RUNNER_IMAGE,
            actor="release-operator",
            token=TOKEN,
            now=now,
        )

        expected_context = {
            "deadline": expires_at,
            "images": {
                "core": CORE_IMAGE,
                "postgres": POSTGRES_IMAGE,
                "runner": RUNNER_IMAGE,
            },
            "nonce": NONCE,
            "recipient_public_key_sha256": hashlib.sha256(
                FAKE_PUBLIC_KEY.encode("ascii")
            ).hexdigest(),
            "repository": "example/lil-tweak",
            "run_attempt": "1",
            "run_id": "123456789",
            "schema": "lil-tweak-private-pull-context/v1",
            "source_commit": SOURCE_COMMIT,
        }
        self.assertEqual(json.loads(context_bytes), expected_context)
        decoded_payload = json.loads(payload)
        self.assertEqual(
            set(decoded_payload), {"auths", "binding_sha256", "nonce"}
        )
        self.assertEqual(decoded_payload["nonce"], NONCE)
        self.assertEqual(
            decoded_payload["binding_sha256"],
            hashlib.sha256(context_bytes).hexdigest(),
        )
        self.assertEqual(set(decoded_payload["auths"]), {"ghcr.io"})
        self.assertEqual(
            base64.b64decode(
                decoded_payload["auths"]["ghcr.io"]["auth"], validate=True
            ),
            f"release-operator:{TOKEN}".encode("ascii"),
        )
        self.assertLessEqual(len(payload), 446)
        self.assertNotIn(TOKEN.encode(), context_bytes)

    def test_payload_over_rsa_oaep_sha256_limit_is_rejected(self) -> None:
        module = load_module()
        now = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)

        with self.assertRaises(module.EnvelopeError):
            module.build_context_and_payload(
                recipient_public_key=FAKE_PUBLIC_KEY.encode("ascii"),
                nonce=NONCE,
                recipient_expires_at="2030-01-02T03:14:05Z",
                repository="example/lil-tweak",
                run_id="123456789",
                run_attempt="1",
                workflow_ref="refs/heads/main",
                workflow_sha=SOURCE_COMMIT,
                source_commit=SOURCE_COMMIT,
                core_image=CORE_IMAGE,
                postgres_image=POSTGRES_IMAGE,
                runner_image=RUNNER_IMAGE,
                actor="release-operator",
                token="x" * 400,
                now=now,
            )


if __name__ == "__main__":
    unittest.main()

