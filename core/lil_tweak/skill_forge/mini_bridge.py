"""Skill Forge -> Mini activation envelope.

This module packages an already-qualified Skill Forge release for one explicit
recipient. It transfers instructions and qualification evidence, never authority.
"""
from __future__ import annotations

from typing import Any, Mapping

from .package import ForgeError, canonical, digest_value, identifier, parse_json, verify_package

_PERMISSION_NOTICE = "No credentials or execution permissions are transferred."


def _qualified_evidence(files: Mapping[str, bytes]) -> dict[str, Any]:
    raw = files.get("evidence.json")
    if raw is None:
        raise ForgeError("mini_bridge_evidence_missing")
    evidence = parse_json(raw)
    if not isinstance(evidence, dict):
        raise ForgeError("mini_bridge_evidence_invalid")
    base_digest = evidence.get("base_package_digest")
    internal = evidence.get("internal")
    transfer = evidence.get("transfer")
    if (
        evidence.get("schema_version") != 1
        or evidence.get("source_status") != "verified_by_trusted_host"
        or evidence.get("permission_notice") != _PERMISSION_NOTICE
        or not isinstance(base_digest, str)
        or not isinstance(internal, dict)
        or not isinstance(transfer, dict)
    ):
        raise ForgeError("mini_bridge_evidence_invalid")
    digest_value(base_digest)
    if (
        internal.get("role") != "internal"
        or internal.get("passed") is not True
        or internal.get("package_digest") != base_digest
        or transfer.get("role") != "transfer"
        or transfer.get("passed") is not True
        or transfer.get("package_digest") != base_digest
        or not isinstance(internal.get("agent_id"), str)
        or not isinstance(transfer.get("agent_id"), str)
        or internal["agent_id"] == transfer["agent_id"]
    ):
        raise ForgeError("mini_bridge_qualification_invalid")
    identifier(internal["agent_id"])
    identifier(transfer["agent_id"])
    return evidence


def build_mini_activation_envelope(
    files: Mapping[str, bytes],
    *,
    audience: str,
    release_digest: str,
) -> bytes:
    """Create a canonical, recipient-bound Mini activation envelope.

    The caller must still enforce Skill Forge's owner approval/one-time grant.
    """
    identifier(audience)
    expected = digest_value(release_digest)
    if verify_package(files) != expected:
        raise ForgeError("mini_bridge_release_digest_mismatch")
    _qualified_evidence(files)

    text_files: dict[str, str] = {}
    for path, content in sorted(files.items()):
        try:
            text_files[path] = content.decode("utf-8")
        except UnicodeError:
            raise ForgeError("mini_bridge_non_text_file") from None

    return canonical(
        {
            "schema_version": 1,
            "issuer": "skill-forge-v1",
            "audience": audience,
            "purpose": "activate",
            "release_digest": expected,
            "files": text_files,
        }
    )
