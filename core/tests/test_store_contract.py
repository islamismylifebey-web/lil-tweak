import hashlib
import json
import threading
import unittest
from dataclasses import replace
from pathlib import Path

from core.lil_tweak.contracts import JobMode, JobState
from core.lil_tweak.api import _job_json
from core.lil_tweak.state import InvalidTransition
from core.lil_tweak.store import (
    ApprovalError,
    IdempotencyConflict,
    Job,
    MemoryJobStore,
    PostgresJobStore,
    StaleLease,
    StaleRevision,
    SourceSpec,
)


class MemoryJobStoreContractTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryJobStore()

    def test_nonce_consumption_is_atomic_and_single_use(self):
        barrier = threading.Barrier(8)
        results = []

        def consume():
            barrier.wait()
            results.append(self.store.consume_nonce("key", "nonce", 100))

        threads = [threading.Thread(target=consume) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 7)

    def test_expired_nonce_records_are_pruned_and_may_be_reused(self):
        now = [100.0]
        store = MemoryJobStore(clock=lambda: now[0])
        self.assertTrue(store.consume_nonce("key", "nonce", 100))
        self.assertFalse(store.consume_nonce("key", "nonce", 100))
        now[0] = 701.0
        self.assertTrue(store.consume_nonce("key", "other", 701))
        self.assertTrue(store.consume_nonce("key", "nonce", 701))

    def test_job_claims_are_generation_fenced_renewable_and_reconciled(self):
        store = MemoryJobStore(clock=lambda: 100)
        job = store.create_job("owner", "lease", JobMode.BUILD, "Build")
        job = store.update_job(
            job.id, owner_id="owner", expected_revision=0, state=JobState.QUEUED
        )
        first = store.claim_job(
            job.id, "owner", "worker-a", lease_seconds=30, now=100
        )
        self.assertEqual(first.generation, 1)
        self.assertIsNone(
            store.claim_job(job.id, "owner", "worker-b", lease_seconds=30, now=110)
        )
        active = store.update_job(
            job.id,
            owner_id="owner",
            expected_revision=job.revision,
            state=JobState.INGESTING,
            lease=first,
        )
        renewed = store.renew_claim(first, lease_seconds=30, now=120)
        self.assertEqual((renewed.generation, renewed.expires_at), (1, 150))
        second = store.claim_job(
            job.id, "owner", "worker-b", lease_seconds=30, now=151
        )
        self.assertEqual(second.generation, 2)
        with self.assertRaises(StaleLease):
            store.update_job(
                job.id,
                owner_id="owner",
                expected_revision=active.revision,
                state=JobState.PLANNING,
                lease=first,
            )
        active = store.update_job(
            job.id,
            owner_id="owner",
            expected_revision=active.revision,
            state=JobState.PLANNING,
            lease=second,
        )
        recovered = store.reconcile_active_jobs(now=182, limit=10)
        self.assertEqual([item.id for item in recovered], [job.id])
        self.assertEqual(recovered[0].state, JobState.QUEUED)
        self.assertEqual(recovered[0].revision, active.revision + 1)
        self.assertEqual(store.list_events(job.id, "owner")[-1].kind, "queued")

    def test_released_new_generation_still_fences_an_older_lease(self):
        store = MemoryJobStore(clock=lambda: 200)
        job = store.create_job("owner", "released-fence", JobMode.BUILD, "Build")
        job = store.update_job(
            job.id, owner_id="owner", expected_revision=0, state=JobState.QUEUED
        )
        first = store.claim_job(
            job.id, "owner", "worker-a", lease_seconds=10, now=100
        )
        second = store.claim_job(
            job.id, "owner", "worker-b", lease_seconds=30, now=111
        )
        self.assertIsNotNone(second)
        store.release_claim(second)
        with self.assertRaises(StaleLease):
            store.update_job(
                job.id,
                owner_id="owner",
                expected_revision=job.revision,
                state=JobState.INGESTING,
                lease=first,
            )

    def test_job_creation_is_idempotent_for_same_payload(self):
        first = self.store.create_job(
            owner_id="owner",
            idempotency_key="idem-1",
            mode=JobMode.BUILD,
            prompt="Build it",
        )
        second = self.store.create_job(
            owner_id="owner",
            idempotency_key="idem-1",
            mode=JobMode.BUILD,
            prompt="Build it",
        )
        self.assertEqual(first.id, second.id)
        self.assertEqual(first.revision, 0)

        with self.assertRaises(IdempotencyConflict):
            self.store.create_job(
                owner_id="owner",
                idempotency_key="idem-1",
                mode=JobMode.DEBUG,
                prompt="Different",
            )

    def test_revision_check_rejects_stale_state_mutation(self):
        job = self.store.create_job("owner", "idem", JobMode.BUILD, "Build")
        updated = self.store.update_job(
            job.id, owner_id="owner", expected_revision=0, state=JobState.QUEUED
        )
        self.assertEqual(updated.revision, 1)
        with self.assertRaises(StaleRevision):
            self.store.update_job(
                job.id,
                owner_id="owner",
                expected_revision=0,
                state=JobState.INGESTING,
            )

    def test_events_are_append_only_and_returned_as_copies(self):
        job = self.store.create_job("owner", "idem", JobMode.BUILD, "Build")
        event = self.store.append_event(job.id, "owner", "queued", {})
        events = self.store.list_events(job.id, "owner")
        self.assertEqual(events[0].sequence, 1)
        self.assertEqual(events[0].data, {})
        events[0].data["safe"] = False
        self.assertEqual(self.store.list_events(job.id, "owner")[0].data, {})
        self.assertEqual(event.kind, "queued")

    def test_audit_events_reject_unknown_fields_that_could_contain_secrets(self):
        job = self.store.create_job("owner", "audit-schema", JobMode.BUILD, "Build")
        with self.assertRaises(ValueError):
            self.store.append_event(
                job.id,
                "owner",
                "queued",
                {"prompt": "secret model content"},
            )

    def test_approval_is_digest_bound_revision_bound_and_single_use(self):
        raw_token = "legacy-low-level-token"
        job = self.store.create_job("owner", "idem", JobMode.BUILD, "Build")
        queued = self.store.update_job(
            job.id,
            owner_id="owner",
            expected_revision=0,
            state=JobState.QUEUED,
            proposal_digest="a" * 64,
            source_digest="c" * 64,
        )
        approval = self.store.create_approval(
            job.id,
            owner_id="owner",
            revision=queued.revision,
            proposal_digest="a" * 64,
            source_digest="c" * 64,
            action="export_patch",
            target="download",
            policy_version="v1",
            resource_profile={"cpus": 1},
            approval_token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
            expires_at=200,
            now=100,
        )
        with self.assertRaises(ApprovalError):
            self.store.consume_approval(
                raw_token,
                owner_id="owner",
                job_id=job.id,
                revision=queued.revision,
                proposal_digest="a" * 64,
                source_digest="c" * 64,
                policy_version="v1",
                resource_profile={"cpus": 2},
                now=149,
            )
        with self.assertRaises(ApprovalError):
            self.store.consume_approval(
                raw_token,
                owner_id="owner",
                job_id=job.id,
                revision=queued.revision,
                proposal_digest="a" * 64,
                source_digest="c" * 64,
                policy_version="v1",
                resource_profile={"cpus": True},
                now=149,
            )
        consumed = self.store.consume_approval(
            raw_token,
            owner_id="owner",
            job_id=job.id,
            revision=queued.revision,
            proposal_digest="a" * 64,
            source_digest="c" * 64,
            policy_version="v1",
            resource_profile={"cpus": 1},
            now=150,
        )
        self.assertEqual(consumed.policy_version, "v1")
        self.assertEqual(consumed.resource_profile, {"cpus": 1})
        self.assertTrue(consumed.consumed)
        with self.assertRaises(ApprovalError):
            self.store.consume_approval(
                raw_token,
                owner_id="owner",
                job_id=job.id,
                revision=queued.revision,
                proposal_digest="a" * 64,
                source_digest="c" * 64,
                policy_version="v1",
                resource_profile={"cpus": 1},
                now=151,
            )

    def test_approval_rejects_wrong_source_digest(self):
        job = self.store.create_job("owner", "source-bound", JobMode.BUILD, "Build")
        job = self.store.update_job(
            job.id,
            owner_id="owner",
            expected_revision=0,
            state=JobState.QUEUED,
            proposal_digest="a" * 64,
            source_digest="c" * 64,
        )
        with self.assertRaises(ApprovalError):
            self.store.create_approval(
                job.id,
                owner_id="owner",
                revision=job.revision,
                proposal_digest="a" * 64,
                source_digest="d" * 64,
                action="export_patch",
                target="download",
                policy_version="v1",
                resource_profile={"cpus": 1},
                approval_token_hash="f" * 64,
                expires_at=200,
                now=100,
            )

    def test_cancel_awaiting_approval_is_an_atomic_terminal_transition(self):
        job = self.store.create_job("owner", "cancel-waiting", JobMode.BUILD, "Build")
        for state in (
            JobState.QUEUED,
            JobState.INGESTING,
            JobState.PLANNING,
            JobState.EXECUTING,
            JobState.COLLECTING,
        ):
            job = self.store.update_job(
                job.id, owner_id="owner", expected_revision=job.revision, state=state
            )
        job = self.store.update_job(
            job.id,
            owner_id="owner",
            expected_revision=job.revision,
            state=JobState.AWAITING_APPROVAL,
            proposal_digest="a" * 64,
            evidence_manifest={"manifest.json": "b" * 64},
            source_digest="c" * 64,
        )
        cancelled = self.store.request_cancel(
            job.id, owner_id="owner", expected_revision=job.revision
        )
        self.assertEqual(cancelled.state, JobState.CANCELLED)
        self.assertTrue(cancelled.cancel_requested)
        self.assertEqual(cancelled.revision, job.revision + 1)
        with self.assertRaises(StaleRevision):
            self.store.request_cancel(
                job.id, owner_id="owner", expected_revision=job.revision
            )

    def test_fresh_cancel_rejects_every_terminal_job_before_memory_mutation(self):
        terminal_states = (
            JobState.COMPLETED,
            JobState.REJECTED,
            JobState.CANCELLED,
            JobState.FAILED,
            JobState.TIMED_OUT,
        )
        for cancel_method in ("request_cancel", "request_cancel_idempotent"):
            for state in terminal_states:
                with self.subTest(cancel_method=cancel_method, state=state.value):
                    job = self._terminal_job(state, f"{cancel_method}:{state.value}")
                    events_before = self.store.list_events(job.id, "owner")
                    kwargs = {
                        "owner_id": "owner",
                        "expected_revision": job.revision,
                    }
                    if cancel_method == "request_cancel_idempotent":
                        kwargs.update(
                            idempotency_key=f"cancel:{state.value}",
                            request_hash=state.value.ljust(64, "0"),
                        )

                    with self.assertRaises(InvalidTransition):
                        getattr(self.store, cancel_method)(job.id, **kwargs)

                    self.assertEqual(self.store.get_job(job.id, "owner"), job)
                    self.assertEqual(
                        self.store.list_events(job.id, "owner"), events_before
                    )
                    if cancel_method == "request_cancel_idempotent":
                        self.assertIsNone(
                            self.store.get_decision(
                                "owner",
                                f"cancel:{state.value}",
                                state.value.ljust(64, "0"),
                            )
                        )

    def test_idempotent_cancel_mutates_state_and_event_as_one_store_operation(self):
        job = self.store.create_job("owner", "atomic-cancel", JobMode.BUILD, "Build")
        job = self.store.transition_job(
            job.id,
            owner_id="owner",
            expected_revision=job.revision,
            state=JobState.QUEUED,
            event_kind="queued",
        )
        cancelled = self.store.request_cancel_idempotent(
            job.id,
            owner_id="owner",
            expected_revision=job.revision,
            idempotency_key="cancel:key",
            request_hash="a" * 64,
        )
        replay = self.store.request_cancel_idempotent(
            job.id,
            owner_id="owner",
            expected_revision=job.revision,
            idempotency_key="cancel:key",
            request_hash="a" * 64,
        )
        self.assertEqual(replay, cancelled)
        self.assertEqual(
            [event.kind for event in self.store.list_events(job.id, "owner")],
            ["queued", "cancel_requested"],
        )

    def test_terminal_cancel_replay_returns_original_result_without_mutation(self):
        job = self.store.create_job("owner", "terminal-replay", JobMode.BUILD, "Build")
        for state in (
            JobState.QUEUED,
            JobState.INGESTING,
            JobState.PLANNING,
            JobState.EXECUTING,
            JobState.COLLECTING,
        ):
            job = self.store.update_job(
                job.id, owner_id="owner", expected_revision=job.revision, state=state
            )
        job = self.store.update_job(
            job.id,
            owner_id="owner",
            expected_revision=job.revision,
            state=JobState.AWAITING_APPROVAL,
            proposal_digest="a" * 64,
            evidence_manifest={"manifest.json": "b" * 64},
        )
        cancelled = self.store.request_cancel_idempotent(
            job.id,
            owner_id="owner",
            expected_revision=job.revision,
            idempotency_key="cancel:terminal-replay",
            request_hash="c" * 64,
        )
        events_after_cancel = self.store.list_events(job.id, "owner")

        replay = self.store.request_cancel_idempotent(
            job.id,
            owner_id="owner",
            expected_revision=job.revision,
            idempotency_key="cancel:terminal-replay",
            request_hash="c" * 64,
        )

        self.assertEqual(replay, cancelled)
        self.assertEqual(self.store.get_job(job.id, "owner"), cancelled)
        self.assertEqual(
            self.store.list_events(job.id, "owner"), events_after_cancel
        )

    def _approved_export_job(self, key="atomic-approve", *, expires_at=200):
        job = self.store.create_job("owner", "atomic-approve", JobMode.BUILD, "Build")
        for state in (
            JobState.QUEUED,
            JobState.INGESTING,
            JobState.PLANNING,
            JobState.EXECUTING,
            JobState.COLLECTING,
        ):
            job = self.store.update_job(
                job.id, owner_id="owner", expected_revision=job.revision, state=state
            )
        proposal = {
            "action": "export_patch",
            "target": "owner_download",
            "policyVersion": "v1",
            "resourceProfile": {"cpus": 1},
            "sourceDigest": "c" * 64,
            "proposalDigest": "a" * 64,
            "expiresAt": "ignored-by-store",
        }
        job = self.store.update_job(
            job.id,
            owner_id="owner",
            expected_revision=job.revision,
            state=JobState.AWAITING_APPROVAL,
            proposal_digest="a" * 64,
            source_digest="c" * 64,
            evidence_manifest={"changes.patch": {"sha256": "b" * 64, "bytes": 4}},
            approval_proposal=proposal,
        )
        token = "A" * 43
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        applying = self.store.decide_job_idempotent(
            job.id,
            owner_id="owner",
            expected_revision=job.revision,
            idempotency_key=f"approve:{key}",
            request_hash="d" * 64,
            decision="approve",
            proposal_digest="a" * 64,
            approval_proposal=proposal,
            approval_token_hash=token_hash,
            expires_at=expires_at,
            now=100,
        )
        return job, applying, proposal, token

    def test_approval_records_browser_hash_unconsumed_and_enters_applying_once(self):
        job, applying, proposal, token = self._approved_export_job()
        replay = self.store.decide_job_idempotent(
            job.id,
            owner_id="owner",
            expected_revision=job.revision,
            idempotency_key="approve:atomic-approve",
            request_hash="d" * 64,
            decision="approve",
            proposal_digest="a" * 64,
            approval_proposal=proposal,
            approval_token_hash=hashlib.sha256(token.encode()).hexdigest(),
            expires_at=200,
            now=101,
        )
        self.assertEqual(applying, replay)
        self.assertEqual(applying.state, JobState.APPLYING)
        self.assertFalse(applying.approval_consumed)
        approvals = list(self.store._approvals.values())
        self.assertEqual(len(approvals), 1)
        self.assertFalse(approvals[0].consumed)
        self.assertEqual(
            approvals[0].token_hash,
            hashlib.sha256(token.encode()).hexdigest(),
        )
        self.assertEqual(
            [event.kind for event in self.store.list_events(job.id, "owner")[-2:]],
            ["approved", "applying"],
        )

    def test_export_consumption_is_exact_and_same_attempt_replays_until_expiry(self):
        original, applying, proposal, token = self._approved_export_job("consume")
        fields = {
            "owner_id": "owner",
            "expected_revision": applying.revision,
            "idempotency_key": "attempt:one",
            "request_hash": "e" * 64,
            "approval_token": token,
            "proposal_digest": proposal["proposalDigest"],
            "source_digest": proposal["sourceDigest"],
            "policy_version": proposal["policyVersion"],
            "resource_profile": proposal["resourceProfile"],
            "evidence_name": "changes.patch",
            "evidence_sha256": "b" * 64,
            "evidence_size_bytes": 4,
        }
        completed = self.store.consume_export_idempotent(
            original.id, **fields, now=150
        )
        replay = self.store.consume_export_idempotent(
            original.id, **fields, now=199
        )
        self.assertEqual(replay, completed)
        self.assertEqual(completed.state, JobState.COMPLETED)
        self.assertTrue(completed.approval_consumed)
        self.assertEqual(
            [event.kind for event in self.store.list_events(original.id, "owner")[-1:]],
            ["completed"],
        )
        with self.assertRaises(ApprovalError):
            self.store.consume_export_idempotent(original.id, **fields, now=200)
        with self.assertRaises(ApprovalError):
            self.store.consume_export_idempotent(
                original.id,
                **{**fields, "idempotency_key": "attempt:two", "request_hash": "f" * 64},
                now=151,
            )

    def test_shared_browser_capability_fixture_consumes_in_core(self):
        fixture = json.loads(
            (Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "approval-token-hash-v1.json").read_text()
        )
        self.assertEqual(
            hashlib.sha256(fixture["approvalToken"].encode("ascii")).hexdigest(),
            fixture["approvalTokenHash"],
        )
        original, applying, proposal, _ = self._approved_export_job("shared-fixture")
        approval = next(iter(self.store._approvals.values()))
        self.store._approvals.clear()
        self.store._approvals[fixture["approvalTokenHash"]] = replace(
            approval, token_hash=fixture["approvalTokenHash"]
        )
        completed = self.store.consume_export_idempotent(
            original.id,
            owner_id="owner",
            expected_revision=applying.revision,
            idempotency_key="attempt:shared-fixture",
            request_hash="e" * 64,
            approval_token=fixture["approvalToken"],
            proposal_digest=proposal["proposalDigest"],
            source_digest=proposal["sourceDigest"],
            policy_version=proposal["policyVersion"],
            resource_profile=proposal["resourceProfile"],
            evidence_name="changes.patch",
            evidence_sha256="b" * 64,
            evidence_size_bytes=4,
            now=150,
        )
        self.assertEqual(completed.state, JobState.COMPLETED)

    def test_export_rejects_a_noncanonical_capability_even_when_its_hash_matches(self):
        original, applying, proposal, _ = self._approved_export_job("noncanonical-token")
        approval = next(iter(self.store._approvals.values()))
        noncanonical_token = "A" * 42 + "B"
        noncanonical_hash = hashlib.sha256(noncanonical_token.encode("ascii")).hexdigest()
        self.store._approvals.clear()
        self.store._approvals[noncanonical_hash] = replace(
            approval, token_hash=noncanonical_hash
        )
        with self.assertRaises(ApprovalError):
            self.store.consume_export_idempotent(
                original.id,
                owner_id="owner",
                expected_revision=applying.revision,
                idempotency_key="attempt:noncanonical-token",
                request_hash="e" * 64,
                approval_token=noncanonical_token,
                proposal_digest=proposal["proposalDigest"],
                source_digest=proposal["sourceDigest"],
                policy_version=proposal["policyVersion"],
                resource_profile=proposal["resourceProfile"],
                evidence_name="changes.patch",
                evidence_sha256="b" * 64,
                evidence_size_bytes=4,
                now=150,
            )

    def test_cancelling_pending_export_is_terminal_and_revokes_consumption(self):
        original, applying, proposal, token = self._approved_export_job("cancel-export")
        cancelled = self.store.request_cancel_idempotent(
            original.id,
            owner_id="owner",
            expected_revision=applying.revision,
            idempotency_key="cancel:pending-export",
            request_hash="c" * 64,
        )
        replay = self.store.request_cancel_idempotent(
            original.id,
            owner_id="owner",
            expected_revision=applying.revision,
            idempotency_key="cancel:pending-export",
            request_hash="c" * 64,
        )
        self.assertEqual(replay, cancelled)
        self.assertEqual(cancelled.state, JobState.CANCELLED)
        self.assertTrue(cancelled.cancel_requested)
        with self.assertRaises(ApprovalError):
            self.store.consume_export_idempotent(
                original.id,
                owner_id="owner",
                expected_revision=applying.revision,
                idempotency_key="attempt:after-cancel",
                request_hash="e" * 64,
                approval_token=token,
                proposal_digest=proposal["proposalDigest"],
                source_digest=proposal["sourceDigest"],
                policy_version=proposal["policyVersion"],
                resource_profile=proposal["resourceProfile"],
                evidence_name="changes.patch",
                evidence_sha256="b" * 64,
                evidence_size_bytes=4,
                now=150,
            )
        self.assertEqual(self.store.get_job(original.id, "owner"), cancelled)
        self.assertEqual(self.store.list_events(original.id, "owner")[-1].kind, "cancelled")

    def test_pending_export_cancel_and_consume_race_has_one_terminal_winner(self):
        original, applying, proposal, token = self._approved_export_job("cancel-consume-race")
        barrier = threading.Barrier(2)
        outcomes = []

        def cancel():
            barrier.wait()
            try:
                outcomes.append(self.store.request_cancel_idempotent(
                    original.id,
                    owner_id="owner",
                    expected_revision=applying.revision,
                    idempotency_key="cancel:race",
                    request_hash="c" * 64,
                ))
            except Exception as error:
                outcomes.append(error)

        def consume():
            barrier.wait()
            try:
                outcomes.append(self.store.consume_export_idempotent(
                    original.id,
                    owner_id="owner",
                    expected_revision=applying.revision,
                    idempotency_key="attempt:race",
                    request_hash="e" * 64,
                    approval_token=token,
                    proposal_digest=proposal["proposalDigest"],
                    source_digest=proposal["sourceDigest"],
                    policy_version=proposal["policyVersion"],
                    resource_profile=proposal["resourceProfile"],
                    evidence_name="changes.patch",
                    evidence_sha256="b" * 64,
                    evidence_size_bytes=4,
                    now=150,
                ))
            except Exception as error:
                outcomes.append(error)

        threads = [threading.Thread(target=cancel), threading.Thread(target=consume)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        final = self.store.get_job(original.id, "owner")
        self.assertIn(final.state, {JobState.CANCELLED, JobState.COMPLETED})
        self.assertEqual(sum(isinstance(item, Job) for item in outcomes), 1)
        self.assertEqual(final.approval_consumed, final.state is JobState.COMPLETED)
        self.assertEqual(
            [event.kind for event in self.store.list_events(original.id, "owner")].count(final.state.value),
            1,
        )

    def test_export_rejects_wrong_token_and_evidence_without_partial_mutation(self):
        original, applying, proposal, _token = self._approved_export_job("rollback")
        common = {
            "owner_id": "owner",
            "expected_revision": applying.revision,
            "idempotency_key": "attempt:rollback",
            "request_hash": "f" * 64,
            "approval_token": "wrong-token",
            "proposal_digest": proposal["proposalDigest"],
            "source_digest": proposal["sourceDigest"],
            "policy_version": proposal["policyVersion"],
            "resource_profile": proposal["resourceProfile"],
            "evidence_name": "changes.patch",
            "evidence_sha256": "0" * 64,
            "evidence_size_bytes": 4,
        }
        with self.assertRaises(ApprovalError):
            self.store.consume_export_idempotent(original.id, **common, now=150)
        unchanged = self.store.get_job(original.id, "owner")
        self.assertEqual(unchanged, applying)
        self.assertFalse(next(iter(self.store._approvals.values())).consumed)
        self.assertEqual(
            [event.kind for event in self.store.list_events(original.id, "owner")[-2:]],
            ["approved", "applying"],
        )

    def test_distinct_export_attempts_race_to_one_logical_consumption(self):
        original, applying, proposal, token = self._approved_export_job("race")
        barrier = threading.Barrier(2)
        outcomes = []

        def consume(attempt):
            barrier.wait()
            try:
                outcomes.append(self.store.consume_export_idempotent(
                    original.id,
                    owner_id="owner",
                    expected_revision=applying.revision,
                    idempotency_key=f"attempt:{attempt}",
                    request_hash=attempt * 64,
                    approval_token=token,
                    proposal_digest=proposal["proposalDigest"],
                    source_digest=proposal["sourceDigest"],
                    policy_version=proposal["policyVersion"],
                    resource_profile=proposal["resourceProfile"],
                    evidence_name="changes.patch",
                    evidence_sha256="b" * 64,
                    evidence_size_bytes=4,
                    now=150,
                ))
            except ApprovalError as error:
                outcomes.append(error)

        threads = [threading.Thread(target=consume, args=(value,)) for value in ("1", "2")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(isinstance(item, Job) for item in outcomes), 1)
        self.assertEqual(sum(isinstance(item, ApprovalError) for item in outcomes), 1)

    def test_reconciliation_keeps_pending_export_then_times_it_out_once(self):
        original, applying, _proposal, _token = self._approved_export_job(
            "reconcile", expires_at=200
        )
        self.assertEqual(self.store.reconcile_active_jobs(now=199), [])
        self.assertEqual(self.store.get_job(original.id, "owner"), applying)
        self.assertEqual(self.store.reconcile_active_jobs(now=200), [])
        timed_out = self.store.get_job(original.id, "owner")
        self.assertEqual(timed_out.state, JobState.TIMED_OUT)
        events = self.store.list_events(original.id, "owner")
        self.assertEqual([event.kind for event in events].count("timed_out"), 1)
        self.assertEqual(self.store.reconcile_active_jobs(now=201), [])
        self.assertEqual([event.kind for event in self.store.list_events(original.id, "owner")].count("timed_out"), 1)

    def test_owner_isolation_looks_like_missing_job(self):
        job = self.store.create_job("owner-a", "idem", JobMode.BUILD, "Build")
        self.assertIsNone(self.store.get_job(job.id, "owner-b"))

    def test_source_manifest_is_persisted_immutably_and_idempotency_bound(self):
        source = SourceSpec(
            source_id="src:0123456789abcdef0123456789abcdef",
            filename="source.zip",
            media_type="application/zip",
            size_bytes=100,
            object_key="engineering/scope/jobs/job:0123456789abcdef0123456789abcdef/sources/src:0123456789abcdef0123456789abcdef",
            sha256="a" * 64,
        )
        job = self.store.create_job(
            "owner", "sources", JobMode.BUILD, "Build", sources=[source]
        )
        self.assertEqual(job.sources, (source,))
        fetched = self.store.get_job(job.id, "owner")
        self.assertEqual(fetched.sources, (source,))
        with self.assertRaises(IdempotencyConflict):
            self.store.create_job(
                "owner", "sources", JobMode.BUILD, "Build", sources=[]
            )

    def _terminal_job(self, state: JobState, idempotency_key: str):
        job = self.store.create_job("owner", idempotency_key, JobMode.BUILD, "Build")
        if state in {JobState.CANCELLED, JobState.FAILED, JobState.TIMED_OUT}:
            return self.store.update_job(
                job.id,
                owner_id="owner",
                expected_revision=job.revision,
                state=state,
            )
        for next_state in (
            JobState.QUEUED,
            JobState.INGESTING,
            JobState.PLANNING,
            JobState.EXECUTING,
            JobState.COLLECTING,
        ):
            job = self.store.update_job(
                job.id,
                owner_id="owner",
                expected_revision=job.revision,
                state=next_state,
            )
        if state is JobState.COMPLETED:
            return self.store.update_job(
                job.id,
                owner_id="owner",
                expected_revision=job.revision,
                state=state,
            )
        job = self.store.update_job(
            job.id,
            owner_id="owner",
            expected_revision=job.revision,
            state=JobState.AWAITING_APPROVAL,
            proposal_digest="a" * 64,
            evidence_manifest={"manifest.json": "b" * 64},
        )
        return self.store.update_job(
            job.id,
            owner_id="owner",
            expected_revision=job.revision,
            state=state,
        )


class PostgresAdapterSurfaceTests(unittest.TestCase):
    class _Cursor:
        def __init__(self, decision=None):
            self.decision = decision
            self.mutations = []
            self.rowcount = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, parameters):
            if query.startswith(("UPDATE ", "INSERT ", "DELETE ")):
                self.mutations.append((query, parameters))
            if query.startswith("UPDATE "):
                self.rowcount = 1

        def fetchone(self):
            return self.decision

    class _Connection:
        def __init__(self, cursor):
            self._cursor = cursor

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return self._cursor

    class _TerminalStore(PostgresJobStore):
        def __init__(self, job, cursor):
            super().__init__(lambda: PostgresAdapterSurfaceTests._Connection(cursor))
            self.job = job
            self.events = []

        def _fetch_job(self, _cursor, job_id, owner_id, *, for_update=False):
            if job_id != self.job.id or owner_id != self.job.owner_id:
                raise AssertionError("unexpected job lookup")
            return self.job

        def _insert_event_cursor(self, _cursor, job_id, owner_id, kind, data):
            self.events.append((job_id, owner_id, kind, data))

    def test_fresh_cancel_rejects_every_terminal_job_before_postgres_mutation(self):
        for cancel_method in ("request_cancel", "request_cancel_idempotent"):
            for state in (
                JobState.COMPLETED,
                JobState.REJECTED,
                JobState.CANCELLED,
                JobState.FAILED,
                JobState.TIMED_OUT,
            ):
                with self.subTest(cancel_method=cancel_method, state=state.value):
                    cursor = self._Cursor()
                    job = Job(
                        id=f"job-{state.value}",
                        owner_id="owner",
                        mode=JobMode.BUILD,
                        prompt="Build",
                        state=state,
                        revision=7,
                        created_at=100,
                        updated_at=200,
                    )
                    store = self._TerminalStore(job, cursor)
                    kwargs = {"owner_id": "owner", "expected_revision": 7}
                    if cancel_method == "request_cancel_idempotent":
                        kwargs.update(
                            idempotency_key=f"cancel:{state.value}",
                            request_hash=state.value.ljust(64, "0"),
                        )

                    with self.assertRaises(InvalidTransition):
                        getattr(store, cancel_method)(job.id, **kwargs)

                    self.assertEqual(store.job, job)
                    self.assertEqual(cursor.mutations, [])
                    self.assertEqual(store.events, [])

    def test_postgres_terminal_cancel_replay_returns_authoritative_result(self):
        request_hash = "c" * 64
        job = Job(
            id="job-cancelled",
            owner_id="owner",
            mode=JobMode.BUILD,
            prompt="Build",
            state=JobState.CANCELLED,
            revision=8,
            cancel_requested=True,
            created_at=100,
            updated_at=200,
        )
        cursor = self._Cursor((request_hash, job.id))
        store = self._TerminalStore(job, cursor)

        replay = store.request_cancel_idempotent(
            job.id,
            owner_id="owner",
            expected_revision=7,
            idempotency_key="cancel:terminal-replay",
            request_hash=request_hash,
        )

        self.assertEqual(replay, job)
        self.assertEqual(cursor.mutations, [])
        self.assertEqual(store.events, [])

    def test_postgres_pending_export_cancel_writes_terminal_state(self):
        job = Job(
            id="job-applying",
            owner_id="owner",
            mode=JobMode.BUILD,
            prompt="Build",
            state=JobState.APPLYING,
            revision=8,
            proposal_digest="a" * 64,
            source_digest="c" * 64,
            approval_consumed=False,
            created_at=100,
            updated_at=200,
        )
        cursor = self._Cursor()

        class ApplyingStore(self._TerminalStore):
            def _fetch_job(inner_self, _cursor, job_id, owner_id, *, for_update=False):
                current = super(ApplyingStore, inner_self)._fetch_job(
                    _cursor, job_id, owner_id, for_update=for_update
                )
                if _cursor.mutations:
                    return replace(
                        current,
                        state=JobState.CANCELLED,
                        revision=current.revision + 1,
                        cancel_requested=True,
                    )
                return current

        store = ApplyingStore(job, cursor)
        cancelled = store.request_cancel_idempotent(
            job.id,
            owner_id="owner",
            expected_revision=job.revision,
            idempotency_key="cancel:applying",
            request_hash="c" * 64,
        )
        self.assertEqual(cancelled.state, JobState.CANCELLED)
        update = next(parameters for query, parameters in cursor.mutations if query.startswith("UPDATE lil_tweak_jobs"))
        self.assertEqual(update[0], "cancelled")
        self.assertEqual(store.events[-1][2], "cancelled")

    def test_postgres_snapshot_uses_normalized_evidence_creation_time(self):
        class Cursor:
            def __init__(self, job_row):
                self.job_row = job_row
                self.query = ""

            def execute(self, query, parameters):
                self.query = query

            def fetchone(self):
                return self.job_row

            def fetchall(self):
                return [("changes.patch", 150.0)]

        proposal = {
            "action": "export_patch",
            "target": "owner_download",
            "policyVersion": "v1",
            "resourceProfile": {"cpus": 1},
            "sourceDigest": "c" * 64,
            "proposalDigest": "a" * 64,
            "expiresAt": "1970-01-01T00:05:00Z",
        }
        manifest = {"changes.patch": {"sha256": "b" * 64, "bytes": 4}}

        def row(state, revision, updated, consumed):
            return (
                "00000000-0000-0000-0000-000000000001",
                "owner",
                "build",
                "Build",
                state,
                revision,
                "a" * 64,
                manifest,
                "Ready",
                [],
                "c" * 64,
                proposal,
                consumed,
                None,
                None,
                100.0,
                updated,
                False,
                None,
                0,
                None,
            )

        store = PostgresJobStore(lambda: None)
        awaiting_cursor = Cursor(row("awaiting_approval", 6, 200.0, False))
        completed_cursor = Cursor(row("completed", 8, 300.0, True))
        awaiting = store._fetch_job(awaiting_cursor, "id", "owner")
        completed = store._fetch_job(completed_cursor, "id", "owner")
        self.assertIn("lil_tweak_evidence", awaiting_cursor.query)
        self.assertIn("created_at", completed_cursor.query)
        self.assertEqual(_job_json(awaiting)["evidence"], _job_json(completed)["evidence"])
        self.assertEqual(
            _job_json(completed)["evidence"][0]["createdAt"],
            "1970-01-01T00:02:30Z",
        )

    def test_migration_contains_leases_and_normalized_source_evidence_rows(self):
        initial = (
            Path(__file__).resolve().parents[1] / "migrations" / "001_initial.sql"
        ).read_text()
        for required in (
            "lease_owner text",
            "lease_expires_at timestamptz",
            "CREATE TABLE lil_tweak_sources",
            "UNIQUE (job_id, source_id)",
            "CREATE TABLE lil_tweak_evidence",
            "UNIQUE (job_id, name)",
        ):
            self.assertIn(required, initial)
        self.assertNotIn("lease_generation", initial)
        upgrade = (
            Path(__file__).resolve().parents[1] / "migrations" / "002_fencing.sql"
        ).read_text()
        self.assertIn("ADD COLUMN lease_generation", upgrade)
        self.assertIn("UNIQUE (job_id, revision, proposal_digest)", upgrade)
        self.assertIn("VALUES (2)", upgrade)

    def test_production_adapter_implements_complete_store_surface(self):
        required = (
            "consume_nonce",
            "create_job",
            "get_job",
            "update_job",
            "transition_job",
            "request_cancel",
            "request_cancel_idempotent",
            "decide_job_idempotent",
            "consume_export_idempotent",
            "append_event",
            "list_events",
            "create_approval",
            "consume_approval",
            "get_decision",
            "record_decision",
            "claim_job",
            "renew_claim",
            "release_claim",
            "list_schedulable_jobs",
            "reconcile_active_jobs",
        )
        missing = [name for name in required if not callable(getattr(PostgresJobStore, name, None))]
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
