"""Private owner-scoped library with separate trusted approval and agent surfaces.

The SQLite connection and callbacks belong to the trusted host, never a sandbox.
This library is not an authentication server: callers must supply the authenticated
owner identity and must not expose `approve` as a model tool.
"""
from __future__ import annotations

from dataclasses import dataclass
import io
import secrets
import sqlite3
import time
from typing import Any, Callable, Mapping
import zipfile

from .evaluation import Adapter, Case, Report, evaluate
from .package import (
    ForgeError, Package, attach_evidence, canonical, compile_draft, digest_value,
    identifier, parse_json, sha, verify_package,
)


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    owner: str
    base_package_digest: str
    release_digest: str
    archive_sha256: str
    audience: str
    purpose: str


@dataclass(frozen=True, slots=True)
class Decision:
    owner: str
    release_digest: str
    audience: str
    purpose: str
    approved: bool
    privacy_reviewed: bool
    rights_reviewed: bool
    expires_at: int
    decision_id: str


def _archive(name: str, files: Mapping[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as archive:
        for path, content in sorted(files.items()):
            info = zipfile.ZipInfo(name + "/" + path, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    result = out.getvalue()
    if len(result) > 2 * 1024 * 1024:
        raise ForgeError("archive_size_limit")
    return result


class Library:
    def __init__(self, connection: sqlite3.Connection, *,
                 authorizer: Callable[[ApprovalRequest], Decision] | None = None,
                 source_verifier: Callable[[str, Mapping[str, str]], bool] | None = None,
                 clock: Callable[[], float] = time.time):
        self._db = connection
        self._authorizer = authorizer
        self._source_verifier = source_verifier
        self._clock = clock
        self._db.row_factory = sqlite3.Row
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS skill_forge_candidates (
                owner TEXT NOT NULL, digest TEXT NOT NULL, name TEXT NOT NULL,
                version TEXT NOT NULL, draft TEXT NOT NULL,
                internal_report TEXT, transfer_report TEXT,
                source_verified INTEGER NOT NULL DEFAULT 0,
                revision INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(owner, digest), UNIQUE(owner, name, version)
            );
            CREATE TABLE IF NOT EXISTS skill_forge_grants (
                token_hash TEXT PRIMARY KEY, owner TEXT NOT NULL, digest TEXT NOT NULL,
                release_digest TEXT NOT NULL, audience TEXT NOT NULL,
                purpose TEXT NOT NULL, expires_at INTEGER NOT NULL,
                decision_id TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0,
                UNIQUE(owner, decision_id)
            );
            CREATE TABLE IF NOT EXISTS skill_forge_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                owner TEXT NOT NULL, digest TEXT NOT NULL,
                action TEXT NOT NULL, detail_digest TEXT NOT NULL
            );
        """)

    def _event(self, owner: str, digest: str, action: str, detail: str = "") -> None:
        count = self._db.execute(
            "SELECT COUNT(*) FROM skill_forge_events WHERE owner=?", (owner,)
        ).fetchone()[0]
        if count >= 10000:
            raise ForgeError("audit_capacity_exceeded")
        self._db.execute(
            "INSERT INTO skill_forge_events(owner,digest,action,detail_digest) VALUES(?,?,?,?)",
            (owner, digest, action, sha(detail.encode())),
        )

    def _row(self, owner: str, digest: str) -> tuple[sqlite3.Row, Package]:
        identifier(owner)
        digest_value(digest)
        row = self._db.execute(
            "SELECT * FROM skill_forge_candidates WHERE owner=? AND digest=?", (owner, digest)
        ).fetchone()
        if row is None:
            raise ForgeError("skill_not_found")
        package = compile_draft(parse_json(row["draft"]))
        if package.digest != digest or package.name != row["name"] or package.version != row["version"]:
            raise ForgeError("stored_skill_integrity_mismatch")
        return row, package

    def add(self, owner: str, draft: Mapping[str, Any]) -> str:
        identifier(owner)
        package = compile_draft(draft)
        digest = package.digest
        with self._db:
            existing = self._db.execute(
                "SELECT digest FROM skill_forge_candidates WHERE owner=? AND name=? AND version=?",
                (owner, package.name, package.version),
            ).fetchone()
            if existing:
                if existing["digest"] != digest:
                    raise ForgeError("immutable_version_conflict")
                self._row(owner, digest)
                return digest
            count = self._db.execute(
                "SELECT COUNT(*) FROM skill_forge_candidates WHERE owner=?", (owner,)
            ).fetchone()[0]
            if count >= 100:
                raise ForgeError("library_capacity_exceeded")
            self._db.execute(
                "INSERT INTO skill_forge_candidates(owner,digest,name,version,draft) VALUES(?,?,?,?,?)",
                (owner, digest, package.name, package.version, canonical(draft).decode()),
            )
            self._event(owner, digest, "compiled")
        return digest

    @staticmethod
    def _report(row: sqlite3.Row, package: Package, role: str) -> dict[str, Any] | None:
        raw = row[role + "_report"]
        if raw is None:
            return None
        report = parse_json(raw)
        if (not isinstance(report, dict) or report.get("role") != role
                or report.get("package_digest") != package.digest
                or (report.get("agent_id") == package.origin_id) != (role == "internal")):
            raise ForgeError("stored_report_integrity_mismatch")
        return report

    def status(self, owner: str, digest: str) -> dict[str, Any]:
        row, package = self._row(owner, digest)
        internal = self._report(row, package, "internal")
        transfer = self._report(row, package, "transfer")
        state = "COMPILED"
        if internal and internal.get("passed") is True and row["source_verified"] == 1:
            state = "INTERNAL_VERIFIED"
            if transfer and transfer.get("passed") is True:
                state = "TRANSFER_VERIFIED"
        if row["revoked"]:
            state = "REVOKED"
        return {"name": package.name, "version": package.version, "digest": digest,
                "state": state, "revision": row["revision"],
                "internal": internal, "transfer": transfer}

    def catalog(self, owner: str) -> list[dict[str, Any]]:
        identifier(owner)
        rows = self._db.execute(
            "SELECT digest FROM skill_forge_candidates WHERE owner=? ORDER BY name,version", (owner,)
        ).fetchall()
        return [self.status(owner, row["digest"]) for row in rows]

    def verify_origin(self, owner: str, origin: Mapping[str, str]) -> dict[str, str]:
        """Require the host to resolve owner-bound source and successful solution evidence."""
        identifier(owner)
        if not isinstance(origin, Mapping) or set(origin) != {"agent_id", "source_digest", "evidence_digest"}:
            raise ForgeError("invalid_origin")
        normalized = {"agent_id": identifier(origin["agent_id"]),
                      "source_digest": digest_value(origin["source_digest"]),
                      "evidence_digest": digest_value(origin["evidence_digest"])}
        if self._source_verifier is None:
            raise ForgeError("source_verifier_unavailable")
        try:
            accepted = self._source_verifier(owner, dict(normalized))
        except Exception:
            raise ForgeError("source_verification_failed") from None
        if accepted is not True:
            raise ForgeError("source_evidence_unverified")
        return normalized

    def _verify_source(self, owner: str, package: Package) -> None:
        self.verify_origin(owner, parse_json(package.as_dict()["manifest.json"])["origin"])

    async def evaluate(self, owner: str, digest: str, cases: tuple[Case, ...],
                       adapter: Adapter, role: str, *, timeout_seconds: float = 30.0) -> Report:
        if role not in {"internal", "transfer"}:
            raise ForgeError("invalid_evaluation_role")
        # Invalidate old grants before calling any external adapter. An interrupted
        # or failed recheck must never leave an older success authorized for export.
        with self._db:
            row, package = self._row(owner, digest)
            if row["revoked"]:
                raise ForgeError("skill_revoked")
            updated = self._db.execute(
                f"UPDATE skill_forge_candidates SET {role}_report=NULL, source_verified=0, "
                "revision=revision+1 WHERE owner=? AND digest=? AND revoked=0 RETURNING revision",
                (owner, digest),
            ).fetchone()
            if updated is None:
                raise ForgeError("skill_revoked")
            revision = updated["revision"]
            self._db.execute("UPDATE skill_forge_grants SET used=1 WHERE owner=? AND digest=? AND used=0",
                             (owner, digest))
            self._event(owner, digest, "evaluation_started", role)
        self._verify_source(owner, package)
        report = await evaluate(package, cases, adapter, role, timeout_seconds=timeout_seconds)
        with self._db:
            row, _ = self._row(owner, digest)
            if row["revoked"] or row["revision"] != revision:
                raise ForgeError("stale_evaluation")
            self._db.execute(
                f"UPDATE skill_forge_candidates SET {role}_report=?, source_verified=1 "
                "WHERE owner=? AND digest=?", (report.to_json(), owner, digest),
            )
            self._event(owner, digest, "evaluation_recorded", report.to_json())
        return report

    def _release(self, owner: str, digest: str) -> tuple[str, dict[str, bytes], bytes]:
        row, package = self._row(owner, digest)
        if self.status(owner, digest)["state"] != "TRANSFER_VERIFIED":
            raise ForgeError("release_not_verified")
        self._verify_source(owner, package)
        evidence = {"schema_version": 1, "base_package_digest": digest,
                    "source_status": "verified_by_trusted_host",
                    "internal": self._report(row, package, "internal"),
                    "transfer": self._report(row, package, "transfer"),
                    "permission_notice": "No credentials or execution permissions are transferred."}
        files = attach_evidence(package, evidence)
        return verify_package(files), files, _archive(package.name, files)

    def prepare_release(self, owner: str, digest: str) -> dict[str, str]:
        release_digest, _, archive = self._release(owner, digest)
        return {"base_package_digest": digest, "release_digest": release_digest,
                "archive_sha256": sha(archive)}

    def approve(self, owner: str, digest: str, audience: str, purpose: str) -> str:
        """Trusted owner route only. Never register this method as a model tool."""
        identifier(audience)
        if purpose not in {"export", "activate"}:
            raise ForgeError("invalid_approval_purpose")
        if self._authorizer is None:
            raise ForgeError("owner_authorizer_unavailable")
        summary = self.prepare_release(owner, digest)
        request = ApprovalRequest(owner, digest, summary["release_digest"],
                                  summary["archive_sha256"], audience, purpose)
        try:
            decision = self._authorizer(request)
        except Exception:
            raise ForgeError("owner_authorization_failed") from None
        if (not isinstance(decision, Decision) or decision.approved is not True
                or decision.privacy_reviewed is not True or decision.rights_reviewed is not True
                or decision.owner != owner or decision.release_digest != request.release_digest
                or decision.audience != audience or decision.purpose != purpose
                or type(decision.expires_at) is not int
                or not self._clock() < decision.expires_at <= self._clock() + 900):
            raise ForgeError("owner_approval_rejected")
        identifier(decision.decision_id)
        token = secrets.token_urlsafe(32)
        with self._db:
            if self.prepare_release(owner, digest) != summary:
                raise ForgeError("stale_owner_decision")
            try:
                self._db.execute(
                    "INSERT INTO skill_forge_grants "
                    "(token_hash,owner,digest,release_digest,audience,purpose,expires_at,decision_id) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (sha(token.encode()), owner, digest, request.release_digest, audience,
                     purpose, decision.expires_at, decision.decision_id),
                )
            except sqlite3.IntegrityError:
                raise ForgeError("owner_decision_replayed") from None
            self._event(owner, digest, "owner_approved", request.release_digest)
        return token

    def _consume(self, owner: str, digest: str, audience: str, token: str,
                 purpose: str) -> tuple[Package, bytes]:
        identifier(audience)
        if not isinstance(token, str) or not 16 <= len(token) <= 128:
            raise ForgeError("invalid_grant")
        # BEGIN IMMEDIATE serializes the check-and-consume against another connection.
        if self._db.in_transaction:
            raise ForgeError("nested_export_transaction")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            _, package = self._row(owner, digest)
            release_digest, _, archive = self._release(owner, digest)
            updated = self._db.execute(
                "UPDATE skill_forge_grants SET used=1 WHERE token_hash=? AND owner=? "
                "AND digest=? AND release_digest=? AND audience=? AND purpose=? "
                "AND expires_at>? AND used=0",
                (sha(token.encode()), owner, digest, release_digest, audience, purpose, self._clock()),
            )
            if updated.rowcount != 1:
                raise ForgeError("invalid_stale_or_consumed_grant")
            self._event(owner, digest, purpose, release_digest)
            self._db.commit()
            return package, archive
        except Exception:
            self._db.rollback()
            raise

    def export(self, owner: str, digest: str, audience: str, token: str) -> bytes:
        """Return approved bytes once. No network publication or filesystem writes."""
        return self._consume(owner, digest, audience, token, "export")[1]

    def activate(self, owner: str, digest: str, audience: str, token: str,
                 available_tools: tuple[str, ...]) -> tuple[tuple[str, bytes], ...]:
        _, package = self._row(owner, digest)
        if not isinstance(available_tools, tuple) or not set(package.requirements).issubset(available_tools):
            raise ForgeError("required_tools_missing")
        return self._consume(owner, digest, audience, token, "activate")[0].instruction_files()

    def revoke(self, owner: str, digest: str) -> None:
        """Authenticated owner/host operation; never an untrusted skill instruction."""
        with self._db:
            self._row(owner, digest)
            self._db.execute("UPDATE skill_forge_candidates SET revoked=1,revision=revision+1 "
                             "WHERE owner=? AND digest=?", (owner, digest))
            self._db.execute("UPDATE skill_forge_grants SET used=1 WHERE owner=? AND digest=? AND used=0",
                             (owner, digest))
            self._event(owner, digest, "revoked")
