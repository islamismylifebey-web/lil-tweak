from __future__ import annotations

import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from liltweak.canonical_lifecycle import (
    LEGAL_TRANSITIONS,
    ApprovalPurpose,
    ApprovalStatus,
    CapabilityName,
    CapabilityStatus,
    DispatchLeaseStatus,
    TaskState,
)
from liltweak.canonical_store import (
    MIGRATION_PATH,
    CanonicalCapabilityBlocked,
    CanonicalConflict,
    CanonicalStateStore,
)

TASK_DIGEST = "a" * 64
SOURCE_DIGEST = "b" * 64
PLAN_DIGEST = "c" * 64
POLICY_DIGEST = "d" * 64
REQUEST_DIGEST = "e" * 64
CHECKPOINT_DIGEST = "f" * 64
FINAL_TREE_DIGEST = "1" * 64
PATCH_DIGEST = "2" * 64
RESULT_DIGEST = "3" * 64
COMMIT_OPERATION_DIGEST = "4" * 64
VERIFICATION_DIGEST = "a1" * 32


def store(tmp_path: Path, *, runtime_id: str = "runtime:test") -> CanonicalStateStore:
    return CanonicalStateStore(tmp_path / "canonical.db", runtime_id=runtime_id)


def enable(store: CanonicalStateStore, *names: CapabilityName) -> None:
    for name in names:
        current = store.capability(name)
        store.update_capability(
            name,
            expected_version=current.version,
            status=CapabilityStatus.OPERATIONAL,
            feature_enabled=True,
            installed=True,
            configured=True,
            connected=True,
            healthy=True,
            qualified=True,
            authorized=True,
            operational=True,
            detail_code="test_qualified",
            actor_id="test:authority",
        )


def create_and_propose(store: CanonicalStateStore) -> None:
    store.create_task(
        task_id="task:canonical",
        task_digest=TASK_DIGEST,
        source_snapshot_digest=SOURCE_DIGEST,
    )
    store.transition_with_evidence(
        "task:canonical",
        expected_version=0,
        target=TaskState.INSPECTED,
        event_type="source.inspected",
        payload={"source_snapshot_digest": SOURCE_DIGEST},
    )
    store.transition_with_evidence(
        "task:canonical",
        expected_version=1,
        target=TaskState.PLANNING,
        event_type="planning.started",
        payload={"profile_digest": POLICY_DIGEST},
    )
    store.propose_plan_atomic(
        "task:canonical",
        expected_version=2,
        plan_digest=PLAN_DIGEST,
    )


def approve_execution(store: CanonicalStateStore) -> str:
    approval = store.build_approval(
        "task:canonical",
        purpose=ApprovalPurpose.EXECUTION,
        operation_digest=REQUEST_DIGEST,
        policy_digest=POLICY_DIGEST,
    )
    store.publish_approval_atomic(
        "task:canonical",
        expected_version=3,
        approval=approval,
    )
    store.approve_atomic(
        "task:canonical",
        approval.id,
        expected_version=4,
        owner_id="owner",
        decision_proof_digest="5" * 64,
    )
    return approval.id


def advance_to_applied(store: CanonicalStateStore) -> None:
    enable(
        store,
        CapabilityName.MODEL,
        CapabilityName.RUNNER,
        CapabilityName.EXTERNAL_CHECKPOINT,
        CapabilityName.OWNER_TREE_APPLY,
        CapabilityName.LOCAL_COMMIT,
    )
    create_and_propose(store)
    execution_approval_id = approve_execution(store)
    store.transition_with_evidence(
        "task:canonical",
        expected_version=5,
        target=TaskState.RUNNER_PREFLIGHT,
        event_type="runner.preflight.satisfied",
        payload={"qualification_digest": "6" * 64},
    )
    _, lease, token = store.claim_dispatch_atomic(
        "task:canonical",
        execution_approval_id,
        expected_version=6,
        request_digest=REQUEST_DIGEST,
        policy_digest=POLICY_DIGEST,
    )
    store.complete_dispatch_atomic(
        "task:canonical",
        lease.id,
        expected_version=7,
        lease_token=token,
        result_digest=RESULT_DIGEST,
    )
    store.transition_with_evidence(
        "task:canonical",
        expected_version=8,
        target=TaskState.VERIFYING,
        event_type="verification.started",
        payload={"verifier_principal": "independent:verifier"},
    )
    store.seal_evidence_atomic(
        "task:canonical",
        expected_version=9,
        verification_decision_digest=VERIFICATION_DIGEST,
        checkpoint_receipt_digest=CHECKPOINT_DIGEST,
    )
    store.mark_patch_ready_atomic(
        "task:canonical",
        expected_version=10,
        final_tree_manifest_digest=FINAL_TREE_DIGEST,
        patch_manifest_digest=PATCH_DIGEST,
        changed_path_count=1,
    )
    apply_approval = store.build_approval(
        "task:canonical",
        purpose=ApprovalPurpose.APPLY_PATCH,
        operation_digest=PATCH_DIGEST,
        policy_digest=POLICY_DIGEST,
    )
    store.publish_approval_atomic(
        "task:canonical",
        expected_version=11,
        approval=apply_approval,
    )
    store.approve_atomic(
        "task:canonical",
        apply_approval.id,
        expected_version=12,
        owner_id="owner",
        decision_proof_digest="7" * 64,
    )
    store.consume_delivery_approval_atomic(
        "task:canonical",
        apply_approval.id,
        expected_version=13,
        purpose=ApprovalPurpose.APPLY_PATCH,
        operation_digest=PATCH_DIGEST,
        policy_digest=POLICY_DIGEST,
        result_digest="8" * 64,
    )


def advance_to_locally_committed(store: CanonicalStateStore) -> None:
    advance_to_applied(store)
    commit_approval = store.build_approval(
        "task:canonical",
        purpose=ApprovalPurpose.LOCAL_COMMIT,
        operation_digest=COMMIT_OPERATION_DIGEST,
        policy_digest=POLICY_DIGEST,
    )
    store.publish_approval_atomic(
        "task:canonical",
        expected_version=14,
        approval=commit_approval,
    )
    store.approve_atomic(
        "task:canonical",
        commit_approval.id,
        expected_version=15,
        owner_id="owner",
        decision_proof_digest="9" * 64,
    )
    store.consume_delivery_approval_atomic(
        "task:canonical",
        commit_approval.id,
        expected_version=16,
        purpose=ApprovalPurpose.LOCAL_COMMIT,
        operation_digest=COMMIT_OPERATION_DIGEST,
        policy_digest=POLICY_DIGEST,
        result_digest="0" * 64,
    )


def test_migration_is_additive_idempotent_and_preserves_legacy_schema(tmp_path: Path) -> None:
    database = tmp_path / "migration.db"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE legacy_sentinel(value TEXT NOT NULL)")
    connection.execute("INSERT INTO legacy_sentinel(value) VALUES ('preserved')")
    connection.execute("PRAGMA user_version=2")
    connection.commit()

    migration = MIGRATION_PATH.read_text(encoding="utf-8")
    connection.executescript(migration)
    connection.executescript(migration)

    assert connection.execute("SELECT value FROM legacy_sentinel").fetchone()[0] == "preserved"
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
    assert (
        connection.execute(
            "SELECT COUNT(*) FROM canonical_schema_migrations "
            "WHERE migration_id='0009_canonical_control_plane'"
        ).fetchone()[0]
        == 1
    )
    connection.close()


def test_database_trigger_rejects_illegal_state_and_version_updates(tmp_path: Path) -> None:
    control = store(tmp_path)
    control.create_task(
        task_id="task:canonical",
        task_digest=TASK_DIGEST,
        source_snapshot_digest=SOURCE_DIGEST,
    )

    with pytest.raises(sqlite3.IntegrityError, match="illegal canonical task transition"):
        control._connection.execute(
            "UPDATE canonical_tasks SET state='COMPLETED', version=1 WHERE id='task:canonical'"
        )
    control._connection.rollback()
    with pytest.raises(sqlite3.IntegrityError, match="version must increment"):
        control._connection.execute(
            "UPDATE canonical_tasks SET state='INSPECTED', version=2 WHERE id='task:canonical'"
        )
    control._connection.rollback()
    assert control.get_task("task:canonical").state == TaskState.RECEIVED


def test_database_trigger_exhaustively_matches_the_authoritative_transition_graph(
    tmp_path: Path,
) -> None:
    connection = sqlite3.connect(tmp_path / "transition-matrix.db")
    connection.executescript(MIGRATION_PATH.read_text(encoding="utf-8"))
    for current in TaskState:
        for target in TaskState:
            connection.execute("SAVEPOINT transition_pair")
            pair_digest = hashlib.sha256(f"{current.value}:{target.value}".encode()).hexdigest()
            connection.execute(
                """
                INSERT INTO canonical_tasks(
                    id, task_digest, source_snapshot_digest, state, version,
                    record_json, created_at, updated_at
                ) VALUES ('probe', ?, ?, ?, 0, '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (pair_digest, SOURCE_DIGEST, current.value),
            )
            allowed = current == target or target in LEGAL_TRANSITIONS[current]
            if allowed:
                connection.execute(
                    "UPDATE canonical_tasks SET state=?, version=1 WHERE id='probe'",
                    (target.value,),
                )
            else:
                with pytest.raises(sqlite3.IntegrityError, match="illegal canonical"):
                    connection.execute(
                        "UPDATE canonical_tasks SET state=?, version=1 WHERE id='probe'",
                        (target.value,),
                    )
            connection.execute("ROLLBACK TO transition_pair")
            connection.execute("RELEASE transition_pair")
    connection.close()


def test_execution_and_checkpoint_gates_are_independent_and_default_off(tmp_path: Path) -> None:
    control = store(tmp_path)
    assert all(not gate.operational for gate in control.capabilities())
    enable(control, CapabilityName.MODEL)
    create_and_propose(control)
    approval = control.build_approval(
        "task:canonical",
        purpose=ApprovalPurpose.EXECUTION,
        operation_digest=REQUEST_DIGEST,
        policy_digest=POLICY_DIGEST,
    )

    with pytest.raises(CanonicalCapabilityBlocked, match="runner, external_checkpoint"):
        control.publish_approval_atomic(
            "task:canonical",
            expected_version=3,
            approval=approval,
        )
    enable(control, CapabilityName.RUNNER)
    approval = control.build_approval(
        "task:canonical",
        purpose=ApprovalPurpose.EXECUTION,
        operation_digest=REQUEST_DIGEST,
        policy_digest=POLICY_DIGEST,
    )
    with pytest.raises(CanonicalCapabilityBlocked, match="external_checkpoint"):
        control.publish_approval_atomic(
            "task:canonical",
            expected_version=3,
            approval=approval,
        )
    enable(control, CapabilityName.EXTERNAL_CHECKPOINT)
    approval = control.build_approval(
        "task:canonical",
        purpose=ApprovalPurpose.EXECUTION,
        operation_digest=REQUEST_DIGEST,
        policy_digest=POLICY_DIGEST,
    )
    pending = control.publish_approval_atomic(
        "task:canonical",
        expected_version=3,
        approval=approval,
    )

    assert pending.state == TaskState.APPROVAL_PENDING
    assert control.capability(CapabilityName.OWNER_TREE_APPLY).operational is False
    assert control.capability(CapabilityName.LOCAL_COMMIT).operational is False
    assert control.capability(CapabilityName.BROWSER_EXECUTION).operational is False


def test_full_lifecycle_uses_atomic_approval_dispatch_and_delivery_operations(
    tmp_path: Path,
) -> None:
    control = store(tmp_path)
    enable(
        control,
        CapabilityName.MODEL,
        CapabilityName.RUNNER,
        CapabilityName.EXTERNAL_CHECKPOINT,
        CapabilityName.OWNER_TREE_APPLY,
        CapabilityName.LOCAL_COMMIT,
    )
    create_and_propose(control)
    execution_approval_id = approve_execution(control)
    preflight = control.transition_with_evidence(
        "task:canonical",
        expected_version=5,
        target=TaskState.RUNNER_PREFLIGHT,
        event_type="runner.preflight.satisfied",
        payload={"qualification_digest": "6" * 64},
    )
    assert preflight.state == TaskState.RUNNER_PREFLIGHT

    executing, lease, token = control.claim_dispatch_atomic(
        "task:canonical",
        execution_approval_id,
        expected_version=6,
        request_digest=REQUEST_DIGEST,
        policy_digest=POLICY_DIGEST,
    )
    assert executing.state == TaskState.EXECUTING
    assert control.get_approval(execution_approval_id).status == ApprovalStatus.CONSUMED
    assert lease.status == DispatchLeaseStatus.ACTIVE
    testing = control.complete_dispatch_atomic(
        "task:canonical",
        lease.id,
        expected_version=7,
        lease_token=token,
        result_digest=RESULT_DIGEST,
    )
    assert testing.state == TaskState.TESTING
    assert control.get_lease(lease.id).status == DispatchLeaseStatus.COMPLETED
    verifying = control.transition_with_evidence(
        "task:canonical",
        expected_version=8,
        target=TaskState.VERIFYING,
        event_type="verification.started",
        payload={"verifier_principal": "independent:verifier"},
    )
    assert verifying.state == TaskState.VERIFYING
    sealed = control.seal_evidence_atomic(
        "task:canonical",
        expected_version=9,
        verification_decision_digest=VERIFICATION_DIGEST,
        checkpoint_receipt_digest=CHECKPOINT_DIGEST,
    )
    assert sealed.state == TaskState.EVIDENCE_SEALED
    patch_ready = control.mark_patch_ready_atomic(
        "task:canonical",
        expected_version=10,
        final_tree_manifest_digest=FINAL_TREE_DIGEST,
        patch_manifest_digest=PATCH_DIGEST,
        changed_path_count=1,
    )
    assert patch_ready.state == TaskState.PATCH_READY

    apply_approval = control.build_approval(
        "task:canonical",
        purpose=ApprovalPurpose.APPLY_PATCH,
        operation_digest=PATCH_DIGEST,
        policy_digest=POLICY_DIGEST,
    )
    control.publish_approval_atomic(
        "task:canonical",
        expected_version=11,
        approval=apply_approval,
    )
    control.approve_atomic(
        "task:canonical",
        apply_approval.id,
        expected_version=12,
        owner_id="owner",
        decision_proof_digest="7" * 64,
    )
    applied = control.consume_delivery_approval_atomic(
        "task:canonical",
        apply_approval.id,
        expected_version=13,
        purpose=ApprovalPurpose.APPLY_PATCH,
        operation_digest=PATCH_DIGEST,
        policy_digest=POLICY_DIGEST,
        result_digest="8" * 64,
    )
    assert applied.state == TaskState.APPLIED

    commit_approval = control.build_approval(
        "task:canonical",
        purpose=ApprovalPurpose.LOCAL_COMMIT,
        operation_digest=COMMIT_OPERATION_DIGEST,
        policy_digest=POLICY_DIGEST,
    )
    control.publish_approval_atomic(
        "task:canonical",
        expected_version=14,
        approval=commit_approval,
    )
    control.approve_atomic(
        "task:canonical",
        commit_approval.id,
        expected_version=15,
        owner_id="owner",
        decision_proof_digest="9" * 64,
    )
    committed = control.consume_delivery_approval_atomic(
        "task:canonical",
        commit_approval.id,
        expected_version=16,
        purpose=ApprovalPurpose.LOCAL_COMMIT,
        operation_digest=COMMIT_OPERATION_DIGEST,
        policy_digest=POLICY_DIGEST,
        result_digest="0" * 64,
    )
    completed = control.complete_atomic(
        "task:canonical",
        expected_version=17,
    )

    assert committed.state == TaskState.LOCALLY_COMMITTED
    assert completed.state == TaskState.COMPLETED
    evidence = control.list_evidence("task:canonical")
    assert [item.sequence for item in evidence] == list(range(1, len(evidence) + 1))
    assert evidence[-1].event_type == "task.completed"


def test_capability_change_invalidates_an_already_approved_dispatch(tmp_path: Path) -> None:
    control = store(tmp_path)
    enable(
        control,
        CapabilityName.MODEL,
        CapabilityName.RUNNER,
        CapabilityName.EXTERNAL_CHECKPOINT,
    )
    create_and_propose(control)
    approval_id = approve_execution(control)
    control.transition_with_evidence(
        "task:canonical",
        expected_version=5,
        target=TaskState.RUNNER_PREFLIGHT,
        event_type="runner.preflight.satisfied",
        payload={"qualification_digest": "6" * 64},
    )
    runner = control.capability(CapabilityName.RUNNER)
    control.update_capability(
        CapabilityName.RUNNER,
        expected_version=runner.version,
        status=CapabilityStatus.OPERATIONAL,
        feature_enabled=True,
        installed=True,
        configured=True,
        connected=True,
        healthy=True,
        qualified=True,
        authorized=True,
        operational=True,
        detail_code="requalified",
        actor_id="test:authority",
    )

    before = control.get_task("task:canonical")
    with pytest.raises(CanonicalConflict, match="stale, changed"):
        control.claim_dispatch_atomic(
            "task:canonical",
            approval_id,
            expected_version=before.version,
            request_digest=REQUEST_DIGEST,
            policy_digest=POLICY_DIGEST,
        )
    assert control.get_task("task:canonical") == before
    assert control.get_approval(approval_id).status == ApprovalStatus.APPROVED


def test_task_cas_allows_only_one_concurrent_transition(tmp_path: Path) -> None:
    first = store(tmp_path, runtime_id="runtime:shared")
    first.create_task(
        task_id="task:canonical",
        task_digest=TASK_DIGEST,
        source_snapshot_digest=SOURCE_DIGEST,
    )
    second = store(tmp_path, runtime_id="runtime:shared")
    barrier = Barrier(2)

    def transition(candidate: CanonicalStateStore) -> str:
        barrier.wait()
        try:
            return candidate.transition_with_evidence(
                "task:canonical",
                expected_version=0,
                target=TaskState.INSPECTED,
                event_type="source.inspected",
                payload={"worker": id(candidate)},
            ).state.value
        except CanonicalConflict:
            return "STALE"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(transition, (first, second)))

    assert sorted(results) == ["INSPECTED", "STALE"]
    assert first.get_task("task:canonical").version == 1
    assert len(first.list_evidence("task:canonical")) == 2


def test_approval_consumption_and_dispatch_lease_are_single_winner_under_concurrency(
    tmp_path: Path,
) -> None:
    first = store(tmp_path, runtime_id="runtime:shared")
    enable(
        first,
        CapabilityName.MODEL,
        CapabilityName.RUNNER,
        CapabilityName.EXTERNAL_CHECKPOINT,
    )
    create_and_propose(first)
    approval_id = approve_execution(first)
    first.transition_with_evidence(
        "task:canonical",
        expected_version=5,
        target=TaskState.RUNNER_PREFLIGHT,
        event_type="runner.preflight.satisfied",
        payload={"qualification_digest": "6" * 64},
    )
    second = store(tmp_path, runtime_id="runtime:shared")
    barrier = Barrier(2)

    def claim(candidate: CanonicalStateStore) -> str:
        barrier.wait()
        try:
            candidate.claim_dispatch_atomic(
                "task:canonical",
                approval_id,
                expected_version=6,
                request_digest=REQUEST_DIGEST,
                policy_digest=POLICY_DIGEST,
            )
            return "CLAIMED"
        except CanonicalConflict:
            return "STALE"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, (first, second)))

    assert sorted(results) == ["CLAIMED", "STALE"]
    assert first.get_task("task:canonical").state == TaskState.EXECUTING
    assert first.get_approval(approval_id).status == ApprovalStatus.CONSUMED
    leases = first.list_leases("task:canonical")
    assert len(leases) == 1
    assert leases[0].status == DispatchLeaseStatus.ACTIVE


def test_rollback_has_its_own_approval_and_atomic_terminal_transition(tmp_path: Path) -> None:
    control = store(tmp_path)
    enable(
        control,
        CapabilityName.OWNER_TREE_APPLY,
        CapabilityName.EXTERNAL_CHECKPOINT,
    )
    control.create_task(
        task_id="task:canonical",
        task_digest=TASK_DIGEST,
        source_snapshot_digest=SOURCE_DIGEST,
    )
    control.transition_with_evidence(
        "task:canonical",
        expected_version=0,
        target=TaskState.INSPECTED,
        event_type="source.inspected",
        payload={"source_snapshot_digest": SOURCE_DIGEST},
    )
    control.transition_with_evidence(
        "task:canonical",
        expected_version=1,
        target=TaskState.FAILED,
        event_type="task.failed",
        payload={"failure_code": "inspection_failed"},
        failure_reason="inspection failed",
    )
    recovery_digest = "7" * 64
    approval = control.build_approval(
        "task:canonical",
        purpose=ApprovalPurpose.ROLLBACK,
        operation_digest=recovery_digest,
        policy_digest=POLICY_DIGEST,
    )
    control.publish_approval_atomic(
        "task:canonical",
        expected_version=2,
        approval=approval,
    )
    control.approve_atomic(
        "task:canonical",
        approval.id,
        expected_version=3,
        owner_id="owner",
        decision_proof_digest="8" * 64,
    )
    rolled_back = control.consume_delivery_approval_atomic(
        "task:canonical",
        approval.id,
        expected_version=4,
        purpose=ApprovalPurpose.ROLLBACK,
        operation_digest=recovery_digest,
        policy_digest=POLICY_DIGEST,
        result_digest="9" * 64,
    )

    assert rolled_back.state == TaskState.ROLLED_BACK
    assert control.get_approval(approval.id).status == ApprovalStatus.CONSUMED


def test_emergency_stop_revokes_unconsumed_approvals_and_never_revives_task(
    tmp_path: Path,
) -> None:
    control = store(tmp_path)
    enable(
        control,
        CapabilityName.MODEL,
        CapabilityName.RUNNER,
        CapabilityName.EXTERNAL_CHECKPOINT,
    )
    create_and_propose(control)
    approval_id = approve_execution(control)

    stopped = control.engage_emergency_stop(actor_id="owner", reason_code="owner_stop")

    assert stopped.emergency_stopped is True
    assert control.get_task("task:canonical").state == TaskState.EMERGENCY_STOPPED
    assert control.get_approval(approval_id).status == ApprovalStatus.REVOKED
    control.clear_emergency_stop(actor_id="owner", reason_code="owner_reset")
    assert control.get_task("task:canonical").state == TaskState.EMERGENCY_STOPPED


def test_restart_reconciliation_fences_runtime_and_engages_emergency_stop(
    tmp_path: Path,
) -> None:
    old = store(tmp_path, runtime_id="runtime:old")
    enable(
        old,
        CapabilityName.MODEL,
        CapabilityName.RUNNER,
        CapabilityName.EXTERNAL_CHECKPOINT,
    )
    create_and_propose(old)
    approval_id = approve_execution(old)
    old.transition_with_evidence(
        "task:canonical",
        expected_version=5,
        target=TaskState.RUNNER_PREFLIGHT,
        event_type="runner.preflight.satisfied",
        payload={"qualification_digest": "6" * 64},
    )
    _, lease, token = old.claim_dispatch_atomic(
        "task:canonical",
        approval_id,
        expected_version=6,
        request_digest=REQUEST_DIGEST,
        policy_digest=POLICY_DIGEST,
    )

    restarted = store(tmp_path, runtime_id="runtime:new")

    assert restarted.control().emergency_stopped is True
    assert restarted.get_task("task:canonical").state == TaskState.EMERGENCY_STOPPED
    assert restarted.get_lease(lease.id).status == DispatchLeaseStatus.CANCELED
    assert restarted.get_approval(approval_id).status == ApprovalStatus.CONSUMED
    with pytest.raises(CanonicalConflict, match="fenced"):
        old.complete_dispatch_atomic(
            "task:canonical",
            lease.id,
            expected_version=7,
            lease_token=token,
            result_digest=RESULT_DIGEST,
        )

    restarted.clear_emergency_stop(actor_id="owner", reason_code="owner_reset")
    assert restarted.control().emergency_stopped is False
    assert restarted.get_task("task:canonical").state == TaskState.EMERGENCY_STOPPED
    fresh = restarted.create_task(
        task_id="task:fresh",
        task_digest="6" * 64,
        source_snapshot_digest=SOURCE_DIGEST,
    )
    assert fresh.state == TaskState.RECEIVED


@pytest.mark.parametrize(
    ("unsafe_state", "advance"),
    (
        (TaskState.APPLIED, advance_to_applied),
        (TaskState.LOCALLY_COMMITTED, advance_to_locally_committed),
    ),
)
def test_restart_reconciles_owner_tree_side_effect_states(
    tmp_path: Path,
    unsafe_state: TaskState,
    advance,
) -> None:
    old = store(tmp_path, runtime_id="runtime:old")
    advance(old)
    assert old.get_task("task:canonical").state == unsafe_state

    restarted = store(tmp_path, runtime_id="runtime:new")

    assert restarted.control().emergency_stopped is True
    assert restarted.get_task("task:canonical").state == TaskState.EMERGENCY_STOPPED
    with pytest.raises(CanonicalConflict, match="fenced"):
        old.create_task(
            task_id="task:stale-runtime",
            task_digest="6" * 64,
            source_snapshot_digest=SOURCE_DIGEST,
        )
