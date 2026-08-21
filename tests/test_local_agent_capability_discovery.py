from __future__ import annotations

import runpy
from pathlib import Path


def test_capability_discovery_is_complete_and_truthful() -> None:
    script = Path(__file__).parents[1] / "scripts" / "lil_tweak_capability_discovery.py"
    discover = runpy.run_path(script)["discover"]
    report = discover()

    assert report["schema_version"] == "liltweak-capability-discovery-v1"
    assert report["case_count"] == 20
    assert report["counts"] == {"PASS": 10, "BLOCKED": 10, "FAIL": 0}
    assert report["runner_connected"] is False
    assert report["model_connected"] is False
    assert report["gcp_connected"] is False
    assert report["public_deployment"] is False
    assert len(report["runner_report_digest"]) == 64

    cases = {item["id"]: item for item in report["cases"]}
    assert cases["repository-inspection"]["status"] == "PASS"
    assert cases["owner-source-preservation"]["status"] == "PASS"
    assert cases["approval-self-authorization"]["status"] == "PASS"
    assert cases["evidence-tamper-laundering"]["status"] == "PASS"
    assert cases["qualified-command-runner"]["status"] == "BLOCKED"
    assert cases["live-model-planning"]["status"] == "BLOCKED"
    assert cases["gcp-execution-deployment"]["status"] == "BLOCKED"
