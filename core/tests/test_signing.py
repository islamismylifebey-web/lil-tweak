import hashlib
import hmac
import json
import unittest
from pathlib import Path

from core.lil_tweak.signing import (
    AuthenticationError,
    ReplayError,
    canonical_request,
    sign_request,
    verify_request,
)


class SigningTests(unittest.TestCase):
    def test_shared_v2_query_fixture_matches_python_canonicalization(self):
        fixture_path = (
            Path(__file__).resolve().parents[2]
            / "tests"
            / "fixtures"
            / "core-signing-query-v2.json"
        )
        fixture = json.loads(fixture_path.read_text())
        fields = fixture["fields"]
        arguments = {
            "key_id": fields["keyId"],
            "method": fields["method"],
            "path_and_query": fields["pathAndQuery"],
            "timestamp": fields["timestamp"],
            "nonce": fields["nonce"],
            "body_sha256": fields["bodySha256"],
            "request_id": fields["requestId"],
            "idempotency_key": fields["idempotencyKey"],
            "owner_id": fields["ownerKey"],
        }
        self.assertEqual(canonical_request(**arguments), fixture["canonical"])
        self.assertEqual(
            sign_request(fixture["secret"], **arguments), fixture["signature"]
        )

    def setUp(self):
        self.body = b'{"mode":"build"}'
        self.digest = hashlib.sha256(self.body).hexdigest()
        self.fields = {
            "method": "post",
            "path_and_query": "/v1/jobs?b=two&a=one",
            "timestamp": "1786636800",
            "nonce": "nonce-123",
            "body_sha256": self.digest,
            "request_id": "request-456",
            "idempotency_key": "idem-789",
            "owner_id": "owner-canonical",
        }

    def test_canonical_request_has_exact_protocol_shape(self):
        self.assertEqual(
            canonical_request(key_id="primary", **self.fields),
            "v2\nprimary\nPOST\n/v1/jobs?a=one&b=two\n1786636800\nnonce-123\n"
            + self.digest
            + "\nrequest-456\nidem-789\nowner-canonical",
        )

    def test_sign_request_matches_independent_hmac(self):
        canonical = canonical_request(key_id="primary", **self.fields).encode("utf-8")
        expected = hmac.new(b"shared-secret", canonical, hashlib.sha256).hexdigest()
        self.assertEqual(
            sign_request(b"shared-secret", key_id="primary", **self.fields), expected
        )

    def test_key_id_owner_and_idempotency_are_signature_bound(self):
        signature = sign_request(
            b"shared-secret", key_id="primary", **self.fields
        )
        for changed in (
            {"key_id": "secondary"},
            {"owner_id": "other-owner"},
            {"idempotency_key": "other-idem"},
        ):
            arguments = {**self.fields, **changed}
            key_id = arguments.pop("key_id", "primary")
            self.assertNotEqual(
                sign_request(b"shared-secret", key_id=key_id, **arguments), signature
            )

    def test_verify_request_accepts_valid_request_and_consumes_nonce(self):
        signature = sign_request(b"shared-secret", key_id="primary", **self.fields)
        consumed = []

        result = verify_request(
            key_id="primary",
            signature=signature,
            body=self.body,
            keys={"primary": b"shared-secret"},
            now=1786636800,
            consume_nonce=lambda key_id, nonce, timestamp: consumed.append(
                (key_id, nonce, timestamp)
            )
            or True,
            **self.fields,
        )

        self.assertTrue(result)
        self.assertEqual(consumed, [("primary", "nonce-123", 1786636800)])

    def test_verify_request_rejects_tampered_body_without_consuming_nonce(self):
        signature = sign_request(b"shared-secret", key_id="primary", **self.fields)
        consumed = []

        with self.assertRaisesRegex(AuthenticationError, "authentication failed"):
            verify_request(
                key_id="primary",
                signature=signature,
                body=b'{"mode":"debug"}',
                keys={"primary": b"shared-secret"},
                now=1786636800,
                consume_nonce=lambda *_: consumed.append(True) or True,
                **self.fields,
            )

        self.assertEqual(consumed, [])

    def test_verify_request_rejects_clock_skew(self):
        signature = sign_request(b"shared-secret", key_id="primary", **self.fields)
        with self.assertRaisesRegex(AuthenticationError, "authentication failed"):
            verify_request(
                key_id="primary",
                signature=signature,
                body=self.body,
                keys={"primary": b"shared-secret"},
                now=1786637101,
                consume_nonce=lambda *_: True,
                **self.fields,
            )

    def test_verify_request_reports_replay_with_stable_error(self):
        signature = sign_request(b"shared-secret", key_id="primary", **self.fields)
        with self.assertRaisesRegex(ReplayError, "request replayed"):
            verify_request(
                key_id="primary",
                signature=signature,
                body=self.body,
                keys={"primary": b"shared-secret"},
                now=1786636800,
                consume_nonce=lambda *_: False,
                **self.fields,
            )

    def test_unknown_key_and_bad_signature_share_generic_error(self):
        for key_id, signature in (("unknown", "0" * 64), ("primary", "0" * 64)):
            with self.subTest(key_id=key_id):
                with self.assertRaisesRegex(AuthenticationError, "^authentication failed$"):
                    verify_request(
                        key_id=key_id,
                        signature=signature,
                        body=self.body,
                        keys={"primary": b"shared-secret"},
                        now=1786636800,
                        consume_nonce=lambda *_: True,
                        **self.fields,
                    )


if __name__ == "__main__":
    unittest.main()
