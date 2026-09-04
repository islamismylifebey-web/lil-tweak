from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timezone

from core.lil_tweak.registry_canonical import (
    CanonicalizationError,
    canonical_json,
    decision_binding,
    sha256_digest,
)
from core.lil_tweak.registry_types import (
    ActionClass,
    ContractVersionRef,
    DecisionRequest,
    Environment,
    OperationIntent,
)


OWNER = "owner-12345678"
REVISION = "b" * 40
REQUEST = DecisionRequest(
    owner_id=OWNER,
    requester_id="principal:requester",
    agent_id="principal:lil-tweak",
    asset_id="asset:lil-tweak",
    action_class=ActionClass.CODE_GENERATION,
    operation_intent=OperationIntent.PROPOSE,
    environment=Environment.REPOSITORY,
    source_revision=REVISION,
)


class RegistryCanonicalTests(unittest.TestCase):
    def test_canonical_json_is_key_and_input_order_independent(self):
        left = {"b": [2, 1], "a": {"z": True}}
        right = {"a": {"z": True}, "b": [2, 1]}
        expected = b'{"a":{"z":true},"b":[2,1]}'
        self.assertEqual(canonical_json(left), expected)
        self.assertEqual(canonical_json(right), expected)
        self.assertEqual(
            sha256_digest(left),
            "0d3f0a5994ccf0b626e6a80b97fff75ec1b3f82d6f0560a81972a2fa46d86a22",
        )

    def test_enums_tuples_and_dataclasses_normalize_deterministically(self):
        self.assertEqual(
            canonical_json({"mode": Environment.REPOSITORY, "items": ("a", "b")}),
            b'{"items":["a","b"],"mode":"REPOSITORY"}',
        )
        encoded = canonical_json(REQUEST)
        self.assertIn(b'"action_class":"CODE_GENERATION"', encoded)
        self.assertIn(b'"source_revision":"' + REVISION.encode("ascii") + b'"', encoded)

    def test_aware_timestamp_is_normalized_to_utc_z(self):
        value = datetime(2026, 9, 4, 6, 30, 15, 123456, tzinfo=timezone.utc)
        self.assertEqual(canonical_json({"at": value}), b'{"at":"2026-09-04T06:30:15.123456Z"}')

    def test_canonical_json_rejects_float_bytes_naive_datetime_and_unsupported_object(self):
        bad_values = (
            {"unsafe": 1.2},
            {"unsafe": b"bytes"},
            {"unsafe": datetime(2026, 9, 4, 6, 30)},
            {"unsafe": object()},
        )
        for value in bad_values:
            with self.subTest(value=value):
                with self.assertRaises(CanonicalizationError):
                    canonical_json(value)

    def test_secret_bearing_field_names_are_rejected_at_any_depth(self):
        for field in ("password", "token", "secret", "credential", "api_token", "dbPassword"):
            with self.subTest(field=field):
                with self.assertRaises(CanonicalizationError):
                    canonical_json({"outer": {field: "redacted"}})

    def test_non_string_dictionary_keys_are_rejected(self):
        with self.assertRaises(CanonicalizationError):
            canonical_json({1: "value"})

    def test_decision_binding_binds_complete_request_and_ordered_contract_digests(self):
        first = "1" * 64
        second = "2" * 64
        binding = decision_binding(REQUEST, (first, second))
        self.assertEqual(len(binding), 64)
        self.assertNotEqual(binding, decision_binding(REQUEST, (second, first)))
        changed = replace(REQUEST, requester_id="principal:other")
        self.assertNotEqual(binding, decision_binding(changed, (first, second)))

    def test_decision_binding_requires_lowercase_sha256_digests(self):
        for invalid in ("a" * 63, "A" * 64, "g" * 64):
            with self.subTest(invalid=invalid):
                with self.assertRaises(CanonicalizationError):
                    decision_binding(REQUEST, (invalid,))

    def test_contract_version_ref_canonical_output_is_deterministic(self):
        reference = ContractVersionRef("contract:a", 2, "c" * 64)
        expected = (
            b'{"contract_id":"contract:a","digest":"'
            + ("c" * 64).encode("ascii")
            + b'","version":2}'
        )
        self.assertEqual(canonical_json(reference), expected)
        self.assertEqual(canonical_json(reference), canonical_json(reference))


if __name__ == "__main__":
    unittest.main()
