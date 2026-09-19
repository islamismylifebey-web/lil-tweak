"""Offline adversarial exercises against the real control-layer functions.

No models, providers, deployment, or production state are used. These tests do
not certify HTTP reachability, database concurrency, or model intelligence.
"""
from __future__ import annotations

import hashlib
import itertools
import random
import unittest
from unittest.mock import Mock

from core.lil_tweak.contracts import JobState, SideEffect, TERMINAL_STATES
from core.lil_tweak.signing import (
    AuthenticationError,
    ReplayError,
    sign_request,
    verify_request,
)
from core.lil_tweak.state import ApprovalRequired, InvalidTransition, approval_required, transition


class AuthorityGauntlet(unittest.TestCase):
    def apply(self, **overrides):
        fields = dict(
            proposal_digest="a" * 64,
            approved_digest="a" * 64,
            approval_recorded=True,
            approval_consumed=False,
        )
        fields.update(overrides)
        return transition(JobState.AWAITING_APPROVAL, JobState.APPLYING, **fields)

    def test_recorded_approval_requires_literal_true(self):
        # These are untrusted serialized values, not an NLP approval parser.
        values = ("false", "not approved", "What if I approve it?", "approved",
                  "I approved earlier, but cancel that", 1, -1, [True], {"approved": True},
                  False, None, "", [], {})
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(ApprovalRequired):
                    self.apply(approval_recorded=value)

    def test_consumed_approval_requires_literal_false(self):
        for value in (None, 0, 0.0, "", [], {}, True, 1, "false", "true"):
            with self.subTest(value=value):
                with self.assertRaises(ApprovalRequired):
                    self.apply(approval_consumed=value)

    def test_exact_boolean_approval_remains_usable(self):
        self.assertIs(self.apply(), JobState.APPLYING)

    def test_changed_proposal_cannot_reuse_approval(self):
        for seed in (7, 101, 20260918):
            rng = random.Random(seed)
            for case in range(100):
                proposal = list("a" * 64)
                proposal[rng.randrange(64)] = rng.choice("0123456789bcdef")
                with self.subTest(seed=seed, case=case):
                    with self.assertRaises(ApprovalRequired):
                        self.apply(proposal_digest="".join(proposal))

    def test_malformed_approval_digests_fail_closed(self):
        for value in (123, True, ["a"], {"hash": "a"}, "☃" * 64, b"a" * 64):
            with self.subTest(value=value):
                with self.assertRaises(ApprovalRequired):
                    self.apply(proposal_digest=value, approved_digest=value)

    def test_every_terminal_state_stays_terminal(self):
        for current, target in itertools.product(TERMINAL_STATES, JobState):
            with self.subTest(current=current, target=target):
                with self.assertRaises(InvalidTransition):
                    transition(current, target, proposal_digest="a" * 64,
                               approved_digest="a" * 64, approval_recorded=True)

    def test_only_awaiting_approval_can_enter_applying(self):
        for current in JobState:
            if current is JobState.AWAITING_APPROVAL:
                continue
            with self.subTest(current=current):
                with self.assertRaises(InvalidTransition):
                    transition(current, JobState.APPLYING, proposal_digest="a" * 64,
                               approved_digest="a" * 64, approval_recorded=True)

    def test_side_effect_authority_map_is_explicit(self):
        local = {SideEffect.READ_LOCAL, SideEffect.WRITE_LOCAL, SideEffect.TEST_LOCAL}
        for effect in SideEffect:
            with self.subTest(effect=effect):
                self.assertIs(approval_required(effect), effect not in local)
        for effect in ("unknown", "DEPLOY", "spend ", "not approved", None):
            with self.subTest(effect=effect):
                with self.assertRaises(ValueError):
                    approval_required(effect)


class SigningGauntlet(unittest.TestCase):
    def setUp(self):
        # Public test-only material, never a deployment credential.
        self.secret = "respectability-public-test-key-not-for-deployment"
        self.body = b'{"operation":"test-only"}'
        self.fields = dict(
            key_id="test-key", method="POST", path_and_query="/v2/jobs?b=2&a=1",
            timestamp=1_800_000_000, nonce="nonce-1",
            body_sha256=hashlib.sha256(self.body).hexdigest(), request_id="request-1",
            idempotency_key="operation-1", owner_id="test-owner",
        )
        self.signature = sign_request(self.secret, **self.fields)

    def verify(self, *, overrides=None, body=None, signature=None, hook=None, now=None):
        fields = dict(self.fields)
        fields.update(overrides or {})
        return verify_request(
            signature=self.signature if signature is None else signature,
            body=self.body if body is None else body,
            keys={"test-key": self.secret},
            consume_nonce=hook if hook is not None else Mock(return_value=True),
            now=self.fields["timestamp"] if now is None else now,
            **fields,
        )

    def test_valid_request_consumes_exact_authenticated_nonce(self):
        hook = Mock(return_value=True)
        self.assertTrue(self.verify(hook=hook))
        hook.assert_called_once_with("test-key", "nonce-1", self.fields["timestamp"])

    def test_all_signed_fields_resist_seeded_substitution(self):
        for seed in (7, 101, 20260918):
            rng = random.Random(seed)
            for case in range(100):
                field = rng.choice(tuple(self.fields))
                value = self.fields[field]
                changed = value + 1 if isinstance(value, int) else str(value) + f"-changed-{case}"
                hook = Mock(return_value=True)
                with self.subTest(seed=seed, case=case, field=field):
                    with self.assertRaises(AuthenticationError):
                        self.verify(overrides={field: changed}, hook=hook)
                    hook.assert_not_called()

    def test_tampered_body_does_not_burn_valid_nonce(self):
        hook = Mock(return_value=True)
        with self.assertRaises(AuthenticationError):
            self.verify(body=self.body + b" ", hook=hook)
        hook.assert_not_called()
        self.assertTrue(self.verify(hook=hook))
        hook.assert_called_once()

    def test_replay_is_rejected_after_first_verified_request(self):
        hook = Mock(side_effect=[True, False])
        self.assertTrue(self.verify(hook=hook))
        with self.assertRaises(ReplayError):
            self.verify(hook=hook)
        self.assertEqual(hook.call_count, 2)

    def test_nonce_claim_requires_literal_true(self):
        for value in ("false", "true", "already consumed", 1, [True], {"ok": True},
                      False, None, 0, "", [], {}):
            with self.subTest(value=value):
                with self.assertRaises(ReplayError):
                    self.verify(hook=Mock(return_value=value))

    def test_malformed_signatures_have_uniform_authentication_failure(self):
        for value in (None, True, 123, [], {}, b"a" * 64, "", "g" * 64, "☃" * 64):
            hook = Mock(return_value=True)
            with self.subTest(value=value):
                with self.assertRaises(AuthenticationError):
                    verify_request(signature=value, body=self.body,
                                   keys={"test-key": self.secret}, consume_nonce=hook,
                                   now=self.fields["timestamp"], **self.fields)
                hook.assert_not_called()

    def test_malformed_targets_have_uniform_authentication_failure(self):
        for value in (None, 1, [], {}, "//example.invalid/a", "https://example.invalid/a",
                      "/v2/jobs#fragment", "/v2/jobs\r\ninjected"):
            hook = Mock(return_value=True)
            with self.subTest(value=value):
                with self.assertRaises(AuthenticationError):
                    self.verify(overrides={"path_and_query": value}, hook=hook)
                hook.assert_not_called()

    def test_stale_and_future_requests_are_rejected_before_nonce_claim(self):
        for delta in (-301, 301, -10_000, 10_000):
            hook = Mock(return_value=True)
            with self.subTest(delta=delta):
                with self.assertRaises(AuthenticationError):
                    self.verify(now=self.fields["timestamp"] + delta, hook=hook)
                hook.assert_not_called()

    def test_clock_skew_boundary_remains_usable(self):
        for delta in (-300, 0, 300):
            with self.subTest(delta=delta):
                self.assertTrue(self.verify(now=self.fields["timestamp"] + delta))

    def test_equivalent_query_order_and_uppercase_signature_remain_usable(self):
        self.assertTrue(self.verify(overrides={"path_and_query": "/v2/jobs?a=1&b=2"},
                                    signature=self.signature.upper()))

    def test_hook_failure_is_not_reported_as_success(self):
        with self.assertRaisesRegex(RuntimeError, "test-only storage unavailable"):
            self.verify(hook=Mock(side_effect=RuntimeError("test-only storage unavailable")))


if __name__ == "__main__":
    unittest.main()
