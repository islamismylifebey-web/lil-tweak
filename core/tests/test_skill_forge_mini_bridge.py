from __future__ import annotations

import json
import sqlite3

import unittest

from lil_tweak.skill_forge import Decision, ForgeError, Library
from lil_tweak.skill_forge.package import canonical, parse_json, sha


def draft() -> dict[str, object]:
    return {
        "name": "root-cause-discipline",
        "version": "1.0.0",
        "description": "Trace failures to the producer and preserve proof.",
        "when_to_use": "Use for misleading or repeated failures.",
        "inputs": ["Observed failure"],
        "outputs": ["Evidence-grounded diagnosis"],
        "steps": ["Inspect the producer", "Reproduce the failure", "Preserve a regression test"],
        "requirements": ["inspect_file", "execute_command"],
        "stop_conditions": ["Required authority or evidence is unavailable"],
        "examples": [
            {"input": "Failure moved downstream", "expected": "Trace upstream"},
            {"input": "Parser failure repeats", "expected": "Inspect producer"},
        ],
        "origin": {
            "agent_id": "skill-author",
            "source_digest": "1" * 64,
            "evidence_digest": "2" * 64,
        },
    }


def qualified_library() -> tuple[Library, str]:
    db = sqlite3.connect(":memory:")
    now = 1_700_000_000

    def authorize(request):
        return Decision(
            owner=request.owner,
            release_digest=request.release_digest,
            audience=request.audience,
            purpose=request.purpose,
            approved=True,
            privacy_reviewed=True,
            rights_reviewed=True,
            expires_at=now + 300,
            decision_id="decision-1",
        )

    library = Library(
        db,
        source_verifier=lambda owner, origin: True,
        authorizer=authorize,
        clock=lambda: now,
    )
    digest = library.add("owner-1", draft())
    internal = canonical({
        "package_digest": digest,
        "suite_digest": "3" * 64,
        "agent_id": "skill-author",
        "role": "internal",
        "results": [],
        "expected_cases": 0,
        "passed": True,
    }).decode()
    transfer = canonical({
        "package_digest": digest,
        "suite_digest": "4" * 64,
        "agent_id": "independent-agent",
        "role": "transfer",
        "results": [],
        "expected_cases": 0,
        "passed": True,
    }).decode()
    db.execute(
        "UPDATE skill_forge_candidates SET internal_report=?, transfer_report=?, source_verified=1 WHERE owner=? AND digest=?",
        (internal, transfer, "owner-1", digest),
    )
    db.commit()
    return library, digest


class MiniBridgeTests(unittest.TestCase):
    def test_mini_activation_requires_owner_activation_and_emits_verifiable_envelope(self):
    library, digest = qualified_library()
    token = library.approve("owner-1", digest, "lil-tueiq-mini", "activate")

    payload = library.activate_for_mini(
        "owner-1",
        digest,
        "lil-tueiq-mini",
        token,
        ("inspect_file", "execute_command"),
    )

    envelope = parse_json(payload)
    assert envelope["schema_version"] == 1
    assert envelope["issuer"] == "skill-forge-v1"
    assert envelope["audience"] == "lil-tueiq-mini"
    assert envelope["purpose"] == "activate"
    assert set(envelope["files"]) >= {"SKILL.md", "manifest.json", "tests/examples.json", "evidence.json"}

    raw_files = {path: content.encode("utf-8") for path, content in envelope["files"].items()}
    actual_release = sha(canonical({path: sha(content) for path, content in sorted(raw_files.items())}))
    assert envelope["release_digest"] == actual_release

    evidence = json.loads(envelope["files"]["evidence.json"])
    assert evidence["source_status"] == "verified_by_trusted_host"
    assert evidence["internal"]["passed"] is True
    assert evidence["transfer"]["passed"] is True
    assert evidence["permission_notice"] == "No credentials or execution permissions are transferred."


    def test_mini_activation_fails_closed_without_required_tools(self):
    library, digest = qualified_library()
    token = library.approve("owner-1", digest, "lil-tueiq-mini", "activate")

        with self.assertRaisesRegex(ForgeError, "required_tools_missing"):
            library.activate_for_mini("owner-1", digest, "lil-tueiq-mini", token, ("inspect_file",))


    def test_mini_activation_does_not_create_new_authority_fields(self):
    library, digest = qualified_library()
    token = library.approve("owner-1", digest, "lil-tueiq-mini", "activate")
    envelope = parse_json(
        library.activate_for_mini(
            "owner-1",
            digest,
            "lil-tueiq-mini",
            token,
            ("inspect_file", "execute_command"),
        )
    )

    assert set(envelope) == {
        "schema_version",
        "issuer",
        "audience",
        "purpose",
        "release_digest",
        "files",
    }
