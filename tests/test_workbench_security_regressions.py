from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from liltweak.workbench_contract import (
    ApprovalPurpose,
    CommandRequest,
    EvidenceKind,
    FileRequest,
    GcpExamConfig,
    NetworkMode,
    StepPhase,
    TaskImport,
    ToolKind,
    ToolRequest,
    WorkbenchApproval,
    WorkbenchMode,
    WorkbenchPlan,
    WorkbenchState,
    WorkbenchTask,
    content_digest,
    utc_now,
)
from liltweak.workbench_policy import ToolPolicyBroker, ToolPolicyError
from liltweak.workbench_store import WorkbenchConflict, WorkbenchStore

DIGEST = "a" * 64
PROJECT = "valid-project-1"
CANDIDATE = f"candidate@{PROJECT}.iam.gserviceaccount.com"


def _command(tool_id: str, phase: StepPhase) -> ToolRequest:
    return ToolRequest(
        tool_id=tool_id,
        kind=ToolKind.COMMAND,
        phase=phase,
        purpose=f"run {phase.value}",
        command=CommandRequest(executable="pytest", args=("-q",)),
    )


def _mutation() -> ToolRequest:
    return ToolRequest(
        tool_id="late-mutation",
        kind=ToolKind.WRITE_FILE,
        phase=StepPhase.MUTATION,
        purpose="attempt a mutation after testing started",
        file=FileRequest(path="changed.txt", content="changed"),
    )


def _plan() -> WorkbenchPlan:
    return WorkbenchPlan(
        summary="bounded security regression plan",
        reasoning="Run a required test and verification.",
        source_snapshot_digest=DIGEST,
        steps=(
            _command("test-1", StepPhase.TEST),
            _command("verify-1", StepPhase.VERIFICATION),
        ),
        rollback_steps=("restore the source snapshot",),
    )


def _received_task(identifier: str = "task:security-regression") -> WorkbenchTask:
    imported = TaskImport(
        title="security regression",
        direction="verify a fail-closed boundary",
        source_snapshot_digest=DIGEST,
    )
    return WorkbenchTask(
        id=identifier,
        imported=imported,
        task_digest=imported.task_digest,
        state=WorkbenchState.RECEIVED,
    )


def _awaiting_task(store: WorkbenchStore) -> WorkbenchTask:
    task = store.create_task(_received_task())
    store.transition(task.id, WorkbenchState.INSPECTING)
    store.transition(task.id, WorkbenchState.ANALYZED)
    task = store.transition(task.id, WorkbenchState.PLAN_READY, plan=_plan())
    return store.transition(task.id, WorkbenchState.AWAITING_APPROVAL)


def _preapproved(task: WorkbenchTask) -> WorkbenchApproval:
    assert task.plan is not None
    now = utc_now()
    bindings = {
        "task_id": task.id,
        "task_digest": task.task_digest,
        "purpose": ApprovalPurpose.EXECUTE.value,
        "plan_digest": task.plan.plan_digest,
        "source_snapshot_digest": task.imported.source_snapshot_digest,
        "repository_id": task.imported.repository_id,
        "examination_digest": None,
        "project": None,
        "candidate_identity": None,
        "execution_attempt": 1,
        "approved_tool_digests": tuple(step.request_digest for step in task.plan.steps),
        "policy_digest": ToolPolicyBroker().policy_digest,
        "runner_grant_digest": None,
        "network_mode": NetworkMode.DENIED.value,
        "nonce": "nonce:preapproved-regression",
    }
    return WorkbenchApproval(
        id="approval:preapproved-regression",
        **bindings,
        approval_digest=content_digest(bindings),
        status="approved",
        approved_by="owner",
        created_at=now,
        expires_at=now + timedelta(minutes=10),
        decided_at=now,
    )


def _gcp_task() -> WorkbenchTask:
    exam = GcpExamConfig(
        examination_id="exam-1",
        authorized_project=PROJECT,
        candidate_service_account=CANDIDATE,
        region="us-central1",
        zone="us-central1-a",
        spending_ceiling_usd=5,
        current_task_number=1,
    )
    imported = TaskImport(
        mode=WorkbenchMode.GCP_QUALIFICATION,
        title="GCP security regression",
        direction="verify the bounded GCP policy",
        source_snapshot_digest=DIGEST,
        examination=exam,
    )
    return WorkbenchTask(
        id="task:gcp-security-regression",
        imported=imported,
        task_digest=imported.task_digest,
        state=WorkbenchState.ANALYZED,
    )


def _gcloud_request(*args: str) -> ToolRequest:
    return ToolRequest(
        tool_id="gcloud-security-regression",
        kind=ToolKind.COMMAND,
        phase=StepPhase.VERIFICATION,
        purpose="verify a protected GCP boundary",
        command=CommandRequest(
            executable="gcloud",
            args=args,
            network=NetworkMode.TASK_SCOPED,
        ),
    )


def _bound_gcloud_args(*extra: str) -> tuple[str, ...]:
    return (
        "compute",
        "instances",
        "list",
        f"--project={PROJECT}",
        f"--impersonate-service-account={CANDIDATE}",
        *extra,
    )


@pytest.mark.parametrize(
    "steps",
    [
        (
            _command("test-1", StepPhase.TEST),
            _mutation(),
            _command("verify-1", StepPhase.VERIFICATION),
        ),
        (
            _command("test-1", StepPhase.TEST),
            _command("verify-1", StepPhase.VERIFICATION),
            _mutation(),
        ),
    ],
    ids=("mutation-after-test", "mutation-after-verification"),
)
def test_mutation_after_test_or_verification_is_rejected(
    steps: tuple[ToolRequest, ...],
) -> None:
    with pytest.raises(ValidationError, match="plan phases must be ordered"):
        WorkbenchPlan(
            summary="invalid phase order",
            reasoning="A mutation cannot follow an executed check.",
            source_snapshot_digest=DIGEST,
            steps=steps,
            rollback_steps=("restore the source snapshot",),
        )


def test_preapproved_approval_cannot_be_published(tmp_path: Path) -> None:
    store = WorkbenchStore(tmp_path / "workbench.db", signing_key=b"e" * 32)
    task = _awaiting_task(store)

    with pytest.raises(WorkbenchConflict, match="only pending owner approvals"):
        store.publish_approval(_preapproved(task))


@pytest.mark.parametrize("tamper_target", ["row", "anchor"])
def test_evidence_append_rejects_tampered_prior_ledger(
    tmp_path: Path,
    tamper_target: str,
) -> None:
    store = WorkbenchStore(tmp_path / "workbench.db", signing_key=b"e" * 32)
    task = store.create_task(_received_task())
    evidence = store.append_evidence(
        task.id,
        kind=EvidenceKind.TASK,
        event_type="task_received",
        payload={"truth": True},
    )
    if tamper_target == "row":
        store._connection.execute(
            "UPDATE workbench_evidence SET record_hash=? WHERE id=?",
            ("b" * 64, evidence.id),
        )
    else:
        store._connection.execute(
            "UPDATE workbench_evidence_anchors SET anchor_signature=? WHERE task_id=?",
            ("c" * 64, task.id),
        )
    store._connection.commit()

    with pytest.raises(WorkbenchConflict, match=r"integrity|authenticated anchor"):
        store.append_evidence(
            task.id,
            kind=EvidenceKind.CONTROL,
            event_type="tamper_must_not_be_laundered",
            payload={"truth": False},
        )

    count = store._connection.execute(
        "SELECT COUNT(*) FROM workbench_evidence WHERE task_id=?",
        (task.id,),
    ).fetchone()[0]
    assert count == 1


def test_duplicate_gcloud_binding_flags_are_rejected() -> None:
    request = _gcloud_request(
        *_bound_gcloud_args(
            f"--project={PROJECT}",
            f"--impersonate-service-account={CANDIDATE}",
        )
    )

    with pytest.raises(ToolPolicyError, match="duplicate gcloud flag"):
        ToolPolicyBroker().authorize(_gcp_task(), request)


def test_gcloud_flags_file_is_rejected() -> None:
    request = _gcloud_request(*_bound_gcloud_args("--flags-file=override.yaml"))

    with pytest.raises(ToolPolicyError, match="credential files and raw tokens"):
        ToolPolicyBroker().authorize(_gcp_task(), request)


@pytest.mark.parametrize("network", [NetworkMode.DENIED, NetworkMode.TASK_SCOPED])
def test_direct_http_client_is_rejected_in_gcp_mode_regardless_of_network(
    network: NetworkMode,
) -> None:
    request = ToolRequest(
        tool_id=f"gcp-http-{network.value}",
        kind=ToolKind.COMMAND,
        phase=StepPhase.VERIFICATION,
        purpose="attempt direct Cloud API access",
        command=CommandRequest(
            executable="curl",
            args=(f"https://compute.googleapis.com/compute/v1/projects/{PROJECT}",),
            network=network,
        ),
    )

    with pytest.raises(ToolPolicyError, match="direct HTTP"):
        ToolPolicyBroker().authorize(_gcp_task(), request)


def test_non_owner_iam_privilege_escalation_is_rejected() -> None:
    request = _gcloud_request(
        "projects",
        "add-iam-policy-binding",
        PROJECT,
        f"--member=serviceAccount:{CANDIDATE}",
        "--role=roles/iam.serviceAccountTokenCreator",
        f"--project={PROJECT}",
        f"--impersonate-service-account={CANDIDATE}",
    )

    with pytest.raises(ToolPolicyError, match="examiner-protected control"):
        ToolPolicyBroker().authorize(_gcp_task(), request)
