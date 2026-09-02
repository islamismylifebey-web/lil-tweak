from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import Field, StrictInt, StrictStr

from ...creator_contract import CreatorSchema, content_digest

_GIT_SHA_PATTERN = r"^[0-9a-f]{40}$"
_QUALIFICATION_BRANCH_PATTERN = r"^qualification/galor-tweak-runner-01/[a-z0-9][a-z0-9-]{0,31}$"

JOB_B_ARTIFACT_PATH: Literal["docs/runner-qualification/galor-tweak-runner-01.md"] = (
    "docs/runner-qualification/galor-tweak-runner-01.md"
)
JOB_B_ARTIFACT_EXPECTED_BEFORE_SHA256: Literal[
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
JOB_B_ARTIFACT_CONTENT = (
    "# Lil' Tweak private runner qualification\n\n"
    "Bounded-write probe for `galor-tweak-runner-01`; this branch must not be merged.\n"
)
_JOB_B_ARTIFACT_CONTENT_SHA256: Literal[
    "62253a2945ea498f3b206a0449e5a97a0cf5783dd7858d7a11fbb365f4c04a91"
] = "62253a2945ea498f3b206a0449e5a97a0cf5783dd7858d7a11fbb365f4c04a91"
JOB_B_ARTIFACT_CONTENT_SHA256 = hashlib.sha256(JOB_B_ARTIFACT_CONTENT.encode("utf-8")).hexdigest()
if JOB_B_ARTIFACT_CONTENT_SHA256 != _JOB_B_ARTIFACT_CONTENT_SHA256:
    raise RuntimeError("fixed Job B artifact content digest is inconsistent")


class QualificationSource(CreatorSchema):
    """The one repository and exact Git objects a qualification job may inspect."""

    repository: Literal["islamismylifebey-web/lil-tweak"] = "islamismylifebey-web/lil-tweak"
    commit_sha: StrictStr = Field(pattern=_GIT_SHA_PATTERN)
    tree_sha: StrictStr = Field(pattern=_GIT_SHA_PATTERN)


class _QualificationManifest(CreatorSchema):
    schema_version: Literal["lil-tweak.runner-job-manifest/v1"] = "lil-tweak.runner-job-manifest/v1"
    source: QualificationSource
    verification_profile: Literal["runner_qualification_subset_v1"] = (
        "runner_qualification_subset_v1"
    )
    timeout_seconds: StrictInt = Field(ge=60, le=1_800)
    network_scope: Literal["github_repository_only"] = "github_repository_only"
    allow_package_install: Literal[False] = False
    allow_production_access: Literal[False] = False
    allow_deploy: Literal[False] = False

    @property
    def commands_digest(self) -> str:
        """Digest the complete canonical manifest for the execution-contract binding."""

        return content_digest(self)


class QualificationReadOnlyManifest(_QualificationManifest):
    """Pinned Job A: inspect and verify exact source without any workspace mutation."""

    job_type: Literal["read_only"] = "read_only"
    action: Literal["qualification_read_only_v1"] = "qualification_read_only_v1"


class QualificationArtifact(CreatorSchema):
    """The only artifact the bounded-write qualification action may create."""

    path: Literal["docs/runner-qualification/galor-tweak-runner-01.md"] = JOB_B_ARTIFACT_PATH
    expected_before_sha256: Literal[
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ] = JOB_B_ARTIFACT_EXPECTED_BEFORE_SHA256
    content_sha256: Literal["62253a2945ea498f3b206a0449e5a97a0cf5783dd7858d7a11fbb365f4c04a91"] = (
        _JOB_B_ARTIFACT_CONTENT_SHA256
    )


class QualificationBoundedWriteManifest(_QualificationManifest):
    """Pinned Job B: create one fixed non-production documentation probe."""

    job_type: Literal["bounded_write"] = "bounded_write"
    action: Literal["qualification_bounded_docs_v1"] = "qualification_bounded_docs_v1"
    qualification_branch: StrictStr = Field(pattern=_QUALIFICATION_BRANCH_PATTERN)
    artifact: QualificationArtifact = Field(default_factory=QualificationArtifact)


type QualificationJobManifest = Annotated[
    QualificationReadOnlyManifest | QualificationBoundedWriteManifest,
    Field(discriminator="job_type"),
]
