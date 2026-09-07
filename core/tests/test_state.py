import unittest

from core.lil_tweak.contracts import JobMode, JobState, SideEffect
from core.lil_tweak.state import (
    ApprovalRequired,
    InvalidTransition,
    approval_required,
    transition,
)


class ContractTests(unittest.TestCase):
    def test_protocol_enum_values_are_stable(self):
        self.assertEqual(
            [mode.value for mode in JobMode],
            ["build", "debug", "refactor", "test", "architect", "chat"],
        )
        self.assertEqual(JobState.AWAITING_APPROVAL.value, "awaiting_approval")

    def test_external_side_effects_require_approval(self):
        for effect in (
            SideEffect.COMMIT,
            SideEffect.PUSH,
            SideEffect.DEPLOY,
            SideEffect.PUBLISH,
            SideEffect.EXTERNAL_DELETE,
            SideEffect.SEND_MESSAGE,
            SideEffect.SPEND,
        ):
            with self.subTest(effect=effect):
                self.assertTrue(approval_required(effect))

        for effect in (SideEffect.READ_LOCAL, SideEffect.WRITE_LOCAL, SideEffect.TEST_LOCAL):
            with self.subTest(effect=effect):
                self.assertFalse(approval_required(effect))


class StateTransitionTests(unittest.TestCase):
    def test_happy_path_transition(self):
        self.assertEqual(transition(JobState.DRAFT, JobState.QUEUED), JobState.QUEUED)
        self.assertEqual(
            transition(JobState.COLLECTING, JobState.COMPLETED), JobState.COMPLETED
        )

    def test_awaiting_approval_requires_digest_and_manifest(self):
        with self.assertRaises(ApprovalRequired):
            transition(JobState.COLLECTING, JobState.AWAITING_APPROVAL)
        with self.assertRaises(ApprovalRequired):
            transition(
                JobState.COLLECTING,
                JobState.AWAITING_APPROVAL,
                proposal_digest="a" * 64,
            )

        self.assertEqual(
            transition(
                JobState.COLLECTING,
                JobState.AWAITING_APPROVAL,
                proposal_digest="a" * 64,
                evidence_manifest={"manifest.json": "b" * 64},
            ),
            JobState.AWAITING_APPROVAL,
        )

    def test_illegal_transition_has_stable_error_code(self):
        with self.assertRaises(InvalidTransition) as caught:
            transition(JobState.DRAFT, JobState.EXECUTING)
        self.assertEqual(caught.exception.code, "invalid_transition")

    def test_terminal_states_cannot_transition(self):
        for current in (
            JobState.COMPLETED,
            JobState.REJECTED,
            JobState.CANCELLED,
            JobState.FAILED,
            JobState.TIMED_OUT,
        ):
            with self.subTest(current=current):
                with self.assertRaises(InvalidTransition):
                    transition(current, JobState.QUEUED)

    def test_applying_requires_a_recorded_unconsumed_matching_approval(self):
        with self.assertRaises(ApprovalRequired):
            transition(
                JobState.AWAITING_APPROVAL,
                JobState.APPLYING,
                proposal_digest="a" * 64,
                approved_digest="a" * 64,
                approval_recorded=False,
            )
        with self.assertRaises(ApprovalRequired):
            transition(
                JobState.AWAITING_APPROVAL,
                JobState.APPLYING,
                proposal_digest="a" * 64,
                approved_digest="b" * 64,
                approval_recorded=True,
            )
        with self.assertRaises(ApprovalRequired):
            transition(
                JobState.AWAITING_APPROVAL,
                JobState.APPLYING,
                proposal_digest="a" * 64,
                approved_digest="a" * 64,
                approval_recorded=True,
                approval_consumed=True,
            )
        self.assertEqual(
            transition(
                JobState.AWAITING_APPROVAL,
                JobState.APPLYING,
                proposal_digest="a" * 64,
                approved_digest="a" * 64,
                approval_recorded=True,
                approval_consumed=False,
            ),
            JobState.APPLYING,
        )


if __name__ == "__main__":
    unittest.main()
