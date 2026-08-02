from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

import pytest

from scripts.generate_supply_chain_artifacts import (
    APP_ROOT,
    MAX_SECRET_SCAN_FILE_BYTES,
    REQUIRED_SOURCE_DATE_EPOCH,
    REQUIRED_WHEEL_PAYLOAD,
    SYNTHETIC_SECRET_FIXTURE_ALLOWLIST,
    ArtifactValidationError,
    package_artifact_subjects,
    provenance,
    security_report,
)


def _report_root(tmp_path: Path) -> Path:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    return tmp_path


def _package_artifacts(
    tmp_path: Path,
    *,
    omitted_payload: str | None = None,
    extra_payload: tuple[str, ...] = (),
) -> tuple[Path, Path]:
    wheel = tmp_path / "lil_tweak_engine-0.7.1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(REQUIRED_WHEEL_PAYLOAD - {omitted_payload}):
            archive.writestr(name, f"payload:{name}\n")
        for name in extra_payload:
            archive.writestr(name, f"payload:{name}\n")
        archive.writestr("lil_tweak_engine-0.7.1.dist-info/METADATA", "Name: lil-tweak-engine\n")
    sdist = tmp_path / "lil_tweak_engine-0.7.1.tar.gz"
    sdist.write_bytes(b"synthetic-focused-test-sdist")
    return wheel, sdist


def test_package_artifacts_become_provenance_subjects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel, sdist = _package_artifacts(tmp_path)
    subjects = package_artifact_subjects(wheel, sdist)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", REQUIRED_SOURCE_DATE_EPOCH)
    evidence = {
        "SUPPLY_CHAIN_SBOM.json": b"sbom\n",
        "LICENSE_INVENTORY.json": b"licenses\n",
        "DEPENDENCY_SECURITY_SCAN_REPORT.json": b"security\n",
    }

    report = provenance(evidence, subjects)

    assert report["subjects"] == [
        {
            "artifact_type": "wheel",
            "path": wheel.name,
            "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "byte_count": wheel.stat().st_size,
        },
        {
            "artifact_type": "sdist",
            "path": sdist.name,
            "sha256": hashlib.sha256(sdist.read_bytes()).hexdigest(),
            "byte_count": sdist.stat().st_size,
        },
    ]
    assert report["evidence_artifacts"] == [
        {
            "path": name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "byte_count": len(data),
        }
        for name, data in sorted(evidence.items())
    ]
    assert report["build_system"] == {
        "requires": ["setuptools==82.0.1", "wheel==0.47.0"],
        "build_backend": "setuptools.build_meta",
    }
    assert report["environment"]["SOURCE_DATE_EPOCH"] == REQUIRED_SOURCE_DATE_EPOCH
    assert report["generated_at"] == "2025-01-01T00:00:00+00:00"


def test_wheel_missing_required_payload_fails_closed(tmp_path: Path) -> None:
    missing = "docs/workbench-agent-prompt.md"
    wheel, sdist = _package_artifacts(tmp_path, omitted_payload=missing)

    with pytest.raises(ArtifactValidationError, match=missing):
        package_artifact_subjects(wheel, sdist)


def test_wheel_with_development_payload_fails_closed(tmp_path: Path) -> None:
    wheel, sdist = _package_artifacts(tmp_path, extra_payload=("tests/test_private.py",))

    with pytest.raises(ArtifactValidationError, match="forbidden development payload"):
        package_artifact_subjects(wheel, sdist)


@pytest.mark.parametrize("missing_kind", ["wheel", "sdist"])
def test_missing_package_artifact_fails_closed(tmp_path: Path, missing_kind: str) -> None:
    wheel, sdist = _package_artifacts(tmp_path)
    missing = tmp_path / ("missing.whl" if missing_kind == "wheel" else "missing.tar.gz")
    if missing_kind == "wheel":
        wheel = missing
    else:
        sdist = missing

    with pytest.raises(ArtifactValidationError, match="cannot be inspected"):
        package_artifact_subjects(wheel, sdist)


@pytest.mark.parametrize("invalid_kind", ["wheel", "sdist"])
def test_package_artifact_suffix_fails_closed(tmp_path: Path, invalid_kind: str) -> None:
    wheel, sdist = _package_artifacts(tmp_path)
    if invalid_kind == "wheel":
        invalid = tmp_path / "package.zip"
        invalid.write_bytes(wheel.read_bytes())
        wheel = invalid
    else:
        invalid = tmp_path / "package.tgz"
        invalid.write_bytes(sdist.read_bytes())
        sdist = invalid

    with pytest.raises(ArtifactValidationError, match="must have the"):
        package_artifact_subjects(wheel, sdist)


def test_provenance_requires_pinned_source_date_epoch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel, sdist = _package_artifacts(tmp_path)
    subjects = package_artifact_subjects(wheel, sdist)
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)

    with pytest.raises(ArtifactValidationError, match="SOURCE_DATE_EPOCH=1735689600"):
        provenance({}, subjects)


def test_secret_fixture_requires_exact_full_file_digest_and_rules(tmp_path: Path) -> None:
    root = _report_root(tmp_path)
    relative = "tests/test_context_manifest.py"
    destination = root / relative
    destination.parent.mkdir(parents=True)
    exact_fixture = (APP_ROOT / relative).read_bytes()
    destination.write_bytes(exact_fixture)

    report = security_report([], root=root, files=(relative,))

    assert report["secret_scan"]["status"] == "PASSED"
    assert report["secret_scan"]["release_findings"] == []
    assert report["secret_scan"]["synthetic_test_fixture_findings"] == [
        {
            "path": relative,
            "rule_ids": list(SYNTHETIC_SECRET_FIXTURE_ALLOWLIST[relative]["rule_ids"]),
            "content_sha256": SYNTHETIC_SECRET_FIXTURE_ALLOWLIST[relative]["content_sha256"],
        }
    ]

    synthetic_token = b"sk-" + b"proj-" + b"realisticbutstilltestonly987654321"
    destination.write_bytes(exact_fixture + b'\nEXTRA_TOKEN = "' + synthetic_token + b'"\n')
    changed_report = security_report([], root=root, files=(relative,))

    assert changed_report["secret_scan"]["status"] == "FAILED"
    assert changed_report["secret_scan"]["synthetic_test_fixture_findings"] == []
    assert changed_report["secret_scan"]["release_findings"][0]["path"] == relative


def test_oversize_file_blocks_secret_scan_with_explicit_finding(tmp_path: Path) -> None:
    root = _report_root(tmp_path)
    relative = "oversize.bin"
    (root / relative).write_bytes(b"x" * (MAX_SECRET_SCAN_FILE_BYTES + 1))

    report = security_report([], root=root, files=(relative,))

    secret_scan = report["secret_scan"]
    assert secret_scan["status"] == "BLOCKED"
    assert secret_scan["files_considered"] == 1
    assert secret_scan["files_scanned"] == 0
    assert secret_scan["scan_blockers"] == [
        {
            "path": relative,
            "reason": "file_exceeds_scan_limit",
            "byte_count": MAX_SECRET_SCAN_FILE_BYTES + 1,
            "limit_bytes": MAX_SECRET_SCAN_FILE_BYTES,
        }
    ]


def test_workflow_pin_scan_covers_yml_and_yaml(tmp_path: Path) -> None:
    root = _report_root(tmp_path)
    pinned = "11bd71901bbe5b1630ceea73d27597364c9af683"
    (root / ".github" / "workflows" / "pinned.yml").write_text(
        f"steps:\n  - uses: 'actions/checkout@{pinned}'\n  - uses: ./local-action\n",
        encoding="utf-8",
    )
    (root / ".github" / "workflows" / "unpinned.yaml").write_text(
        "steps:\n  - uses : actions/checkout@v4\n",
        encoding="utf-8",
    )

    report = security_report([], root=root, files=())

    assert report["workflow_action_pin_scan"] == {
        "status": "FAILED",
        "findings": [".github/workflows/unpinned.yaml:2"],
    }
