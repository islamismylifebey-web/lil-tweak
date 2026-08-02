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
