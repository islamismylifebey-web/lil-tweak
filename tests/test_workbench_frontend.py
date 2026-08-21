from __future__ import annotations

from pathlib import Path


def test_frontend_has_required_screens_controls_and_no_embedded_secrets() -> None:
    root = Path(__file__).parents[1] / "web" / "workbench"
    html = (root / "index.html").read_text(encoding="utf-8")
    script = (root / "app.js").read_text(encoding="utf-8")
    for label in (
        "New Task",
        "Active Task",
        "GCP Qualification",
        "Projects / Repositories",
        "Approvals",
        "Runs",
        "Evidence / Artifacts",
        "Recovery",
        "Audit",
        "Settings",
        "Approve Exact Plan",
        "Emergency Stop",
        "Lock Submission",
        "Reopen Submission",
        "Export Submission",
        "Reissue Expired Approval",
        "Reset Emergency Stop",
        "Capability Gates",
        "Exact blockers",
    ):
        assert label in html
    assert "OPENAI_API_KEY" not in html + script
    assert "@gmail.com" not in html + script
    assert "prefill" not in html.casefold()
    assert 'class="skip-link"' in html
    assert 'aria-live="polite"' in html
    assert 'type="password"' in html
    assert 'tabindex="-1"' in html
    assert "escapeHtml" in script
    assert "disabled = true" in script


def test_disconnected_model_and_runner_disable_their_controls_with_exact_reasons() -> None:
    script = (Path(__file__).parents[1] / "web" / "workbench" / "app.js").read_text(
        encoding="utf-8"
    )
    assert "!state.health.model_connected" in script
    assert "!state.health.runner_connected" in script
    assert "model adapter is disconnected" in script
    assert "no independently qualified runner provider is connected" in script
    assert '$("revision-button").disabled = true' in script
    assert "ROLLED_BACK: []" in script
    assert "Rolled-back tasks are terminal" in script


def test_capability_gates_and_exact_blockers_are_rendered_without_hiding_them() -> None:
    root = Path(__file__).parents[1] / "web" / "workbench"
    html = (root / "index.html").read_text(encoding="utf-8")
    script = (root / "app.js").read_text(encoding="utf-8")
    assert 'id="capability-status"' in html
    assert 'id="capability-blockers"' in html
    assert "Array.isArray(health.capabilities)" in script
    assert "Array.isArray(health.missing_prerequisites)" in script
    assert "Array.isArray(capability.blockers)" in script
    for gate in ("configured", "connected", "authorized", "healthy", "qualified"):
        assert f'"{gate}"' in script


def test_terminal_tasks_allow_submission_and_emergency_stop_requires_confirmation() -> None:
    script = (Path(__file__).parents[1] / "web" / "workbench" / "app.js").read_text(
        encoding="utf-8"
    )
    assert 'new Set(["COMPLETED", "BLOCKED", "FAILED"])' in script
    assert "terminalSubmissionStates.has(state.task.state)" in script
    assert '$("submission-button").disabled = false' in script
    assert "window.confirm(" in script
    assert "Emergency Stop blocks approvals and execution and cancels active tasks" in script
    assert "if (!confirmed) return" in script
    assert 'await action("/v1/workbench/emergency-stop")' in script
    assert "state.approval = null" in script
    assert 'item.event_type === "approval_reissued"' in script
    assert 'state.approval.status !== "expired"' in script
    assert 'action("/v1/workbench/emergency-stop/reset", { owner_key: ownerKey })' in script
