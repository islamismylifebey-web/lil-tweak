from __future__ import annotations

import pytest
from pydantic import ValidationError

from liltweak.providers.self_hosted.qualification_manifest import (
    JOB_B_ARTIFACT_CONTENT_SHA256,
    JOB_B_ARTIFACT_EXPECTED_BEFORE_SHA256,
    QualificationBoundedWriteManifest,
    QualificationReadOnlyManifest,
    QualificationSource,
)


def _source() -> QualificationSource:
    return QualificationSource(
        commit_sha="f" * 40,
        tree_sha="e" * 40,
    )


def test_read_only_manifest_is_a_fixed_action_without_shell_or_write_fields() -> None:
    manifest = QualificationReadOnlyManifest(
        source=_source(),
        timeout_seconds=900,
    )

    assert manifest.model_dump(mode="json") == {
        "schema_version": "lil-tweak.runner-job-manifest/v1",
        "job_type": "read_only",
        "action": "qualification_read_only_v1",
        "source": {
            "repository": "islamismylifebey-web/lil-tweak",
            "commit_sha": "f" * 40,
            "tree_sha": "e" * 40,
        },
        "verification_profile": "runner_qualification_subset_v1",
        "timeout_seconds": 900,
        "network_scope": "github_repository_only",
        "allow_package_install": False,
        "allow_production_access": False,
        "allow_deploy": False,
    }
    assert manifest.commands_digest == (
        "1d1d8fe06879ff6b57921ddce4ab221560b36a5c6e1f9e9f83852070e1c9fcbd"
    )


def test_read_only_manifest_rejects_arbitrary_commands_or_arguments() -> None:
    payload = QualificationReadOnlyManifest(
        source=_source(),
        timeout_seconds=900,
    ).model_dump(mode="json")
    payload["argv"] = ["sh", "-c", "anything"]

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        QualificationReadOnlyManifest.model_validate(payload)


def test_bounded_write_manifest_pins_one_nonproduction_document_artifact() -> None:
    manifest = QualificationBoundedWriteManifest(
        source=_source(),
        timeout_seconds=1_200,
        qualification_branch="qualification/galor-tweak-runner-01/probe-001",
    )

    assert manifest.model_dump(mode="json") == {
        "schema_version": "lil-tweak.runner-job-manifest/v1",
        "job_type": "bounded_write",
        "action": "qualification_bounded_docs_v1",
        "source": {
            "repository": "islamismylifebey-web/lil-tweak",
            "commit_sha": "f" * 40,
            "tree_sha": "e" * 40,
        },
        "verification_profile": "runner_qualification_subset_v1",
        "timeout_seconds": 1_200,
        "network_scope": "github_repository_only",
        "allow_package_install": False,
        "allow_production_access": False,
        "allow_deploy": False,
        "qualification_branch": "qualification/galor-tweak-runner-01/probe-001",
        "artifact": {
            "path": "docs/runner-qualification/galor-tweak-runner-01.md",
            "expected_before_sha256": JOB_B_ARTIFACT_EXPECTED_BEFORE_SHA256,
            "content_sha256": JOB_B_ARTIFACT_CONTENT_SHA256,
        },
    }
    assert manifest.commands_digest == (
        "2d816a968c58ff0e4961a6ea1e340f77567b92e46eb869e89e4c59b521021ac6"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("path", "liltweak/api.py"),
        ("expected_before_sha256", "a" * 64),
        ("content_sha256", "b" * 64),
    ),
)
def test_bounded_write_manifest_rejects_any_other_patch(
    field: str,
    value: str,
) -> None:
    payload = QualificationBoundedWriteManifest(
        source=_source(),
        timeout_seconds=1_200,
        qualification_branch="qualification/galor-tweak-runner-01/probe-001",
    ).model_dump(mode="json")
    payload["artifact"][field] = value

    with pytest.raises(ValidationError):
        QualificationBoundedWriteManifest.model_validate(payload)


def test_bounded_write_manifest_rejects_embedded_content_or_arbitrary_branch() -> None:
    payload = QualificationBoundedWriteManifest(
        source=_source(),
        timeout_seconds=1_200,
        qualification_branch="qualification/galor-tweak-runner-01/probe-001",
    ).model_dump(mode="json")
    payload["artifact"]["content"] = "unreviewed content"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        QualificationBoundedWriteManifest.model_validate(payload)
    with pytest.raises(ValidationError, match="qualification_branch"):
        QualificationBoundedWriteManifest(
            source=_source(),
            timeout_seconds=1_200,
            qualification_branch="main",
        )
