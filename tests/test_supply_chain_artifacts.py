from __future__ import annotations

import gzip
import hashlib
import io
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts.generate_supply_chain_artifacts import (
    APP_ROOT,
    MAX_SECRET_SCAN_FILE_BYTES,
    REQUIRED_SDIST_PAYLOAD,
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
    wheel_metadata: str = "Name: lil-tweak-engine\n",
    sdist_extra_payload: tuple[str, ...] = (),
) -> tuple[Path, Path]:
    wheel = tmp_path / "lil_tweak_engine-0.7.1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(REQUIRED_WHEEL_PAYLOAD - {omitted_payload}):
            archive.writestr(name, f"payload:{name}\n")
        for name in extra_payload:
            archive.writestr(name, f"payload:{name}\n")
        archive.writestr("lil_tweak_engine-0.7.1.dist-info/METADATA", wheel_metadata)
    sdist = tmp_path / "lil_tweak_engine-0.7.1.tar.gz"
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(REQUIRED_SDIST_PAYLOAD | set(sdist_extra_payload)):
            data = f"payload:{name}\n".encode()
            info = tarfile.TarInfo(f"lil_tweak_engine-0.7.1/{name}")
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = int(REQUIRED_SOURCE_DATE_EPOCH)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    with (
        sdist.open("wb") as output,
        gzip.GzipFile(
            filename="",
            fileobj=output,
            mode="wb",
            mtime=int(REQUIRED_SOURCE_DATE_EPOCH),
        ) as compressed,
    ):
        compressed.write(tar_buffer.getvalue())
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
        "build_backend": "build_backend",
        "backend_path": ["."],
    }
    assert [material["path"] for material in report["materials"]] == [
        "MANIFEST.in",
        "build_backend.py",
        "pyproject.toml",
        "uv.lock",
    ]
    assert report["environment"]["SOURCE_DATE_EPOCH"] == REQUIRED_SOURCE_DATE_EPOCH
    assert report["reproducible_build_epoch"] == "2025-01-01T00:00:00+00:00"
    assert report["observation_time"] == "recorded externally with exact-commit verification"


def test_wheel_missing_required_payload_fails_closed(tmp_path: Path) -> None:
    missing = "docs/workbench-agent-prompt.md"
    wheel, sdist = _package_artifacts(tmp_path, omitted_payload=missing)

    with pytest.raises(ArtifactValidationError, match=missing):
        package_artifact_subjects(wheel, sdist)


def test_wheel_with_development_payload_fails_closed(tmp_path: Path) -> None:
    wheel, sdist = _package_artifacts(tmp_path, extra_payload=("tests/test_private.py",))

    with pytest.raises(ArtifactValidationError, match="forbidden development payload"):
        package_artifact_subjects(wheel, sdist)


def test_generated_inventory_cannot_be_mislabeled_as_project_license(tmp_path: Path) -> None:
    wheel, sdist = _package_artifacts(
        tmp_path,
        wheel_metadata=("Name: lil-tweak-engine\nLicense-File: LICENSE_INVENTORY.json\n"),
    )

    with pytest.raises(ArtifactValidationError, match="falsely classifies"):
        package_artifact_subjects(wheel, sdist)

    wheel, sdist = _package_artifacts(
        tmp_path,
        sdist_extra_payload=("LICENSE_INVENTORY.json",),
    )
    with pytest.raises(ArtifactValidationError, match="falsely packages"):
        package_artifact_subjects(wheel, sdist)


@pytest.mark.parametrize("evidence_name", ["BUILD_PROVENANCE.json", "FINAL_FILE_MANIFEST.json"])
def test_generated_evidence_cannot_enter_package_artifacts(
    tmp_path: Path,
    evidence_name: str,
) -> None:
    wheel, sdist = _package_artifacts(tmp_path, extra_payload=(evidence_name,))
    with pytest.raises(ArtifactValidationError, match="provenance cycle"):
        package_artifact_subjects(wheel, sdist)

    wheel, sdist = _package_artifacts(tmp_path, sdist_extra_payload=(evidence_name,))
    with pytest.raises(ArtifactValidationError, match="provenance cycle"):
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


def test_malformed_sdist_fails_closed(tmp_path: Path) -> None:
    wheel, sdist = _package_artifacts(tmp_path)
    sdist.write_bytes(b"not-a-source-archive")

    with pytest.raises(ArtifactValidationError, match="valid gzip tar"):
        package_artifact_subjects(wheel, sdist)


def test_nondeterministic_sdist_metadata_fails_closed(tmp_path: Path) -> None:
    wheel, sdist = _package_artifacts(tmp_path)
    with tarfile.open(sdist, "w:gz") as archive:
        data = b"noncanonical\n"
        info = tarfile.TarInfo("lil_tweak_engine-0.7.1/pyproject.toml")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))

    with pytest.raises(ArtifactValidationError, match="gzip"):
        package_artifact_subjects(wheel, sdist)


def test_sdist_rejects_concatenated_gzip_payload(tmp_path: Path) -> None:
    wheel, sdist = _package_artifacts(tmp_path)
    hidden = gzip.compress(b"hidden trailing payload", mtime=int(REQUIRED_SOURCE_DATE_EPOCH))
    sdist.write_bytes(sdist.read_bytes() + hidden)

    with pytest.raises(ArtifactValidationError, match="trailing gzip payload"):
        package_artifact_subjects(wheel, sdist)


def test_sdist_rejects_unknown_tar_member_type(tmp_path: Path) -> None:
    wheel, sdist = _package_artifacts(tmp_path)
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("lil_tweak_engine-0.7.1/unknown")
        member.type = b"Z"
        member.mode = 0o644
        member.mtime = int(REQUIRED_SOURCE_DATE_EPOCH)
        archive.addfile(member)
    with (
        sdist.open("wb") as output,
        gzip.GzipFile(
            filename="",
            fileobj=output,
            mode="wb",
            mtime=int(REQUIRED_SOURCE_DATE_EPOCH),
        ) as compressed,
    ):
        compressed.write(tar_buffer.getvalue())

    with pytest.raises(ArtifactValidationError, match="cannot be normalized safely"):
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
    exact_fixture = subprocess.run(
        ("git", "show", f":{relative}"),
        cwd=APP_ROOT,
        check=True,
        capture_output=True,
        shell=False,
    ).stdout
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
