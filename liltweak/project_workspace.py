from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator


class ProjectWorkspaceError(RuntimeError):
    pass


class WorkspaceSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Requirement(WorkspaceSchema):
    id: StrictStr = Field(pattern=r"^requirement:[0-9a-f]{32}$")
    text: StrictStr = Field(min_length=1, max_length=4_000)
    status: Literal["planned", "active", "complete", "blocked"] = "planned"


class Milestone(WorkspaceSchema):
    id: StrictStr = Field(pattern=r"^milestone:[0-9a-f]{32}$")
    title: StrictStr = Field(min_length=1, max_length=256)
    target_date: StrictStr | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    status: Literal["planned", "active", "complete", "blocked"] = "planned"


class BoardItem(WorkspaceSchema):
    id: StrictStr = Field(pattern=r"^board:[0-9a-f]{32}$")
    title: StrictStr = Field(min_length=1, max_length=256)
    detail: StrictStr = Field(default="", max_length=4_000)
    column: Literal["backlog", "ready", "active", "review", "done"] = "backlog"


class ProjectNote(WorkspaceSchema):
    # Datetimes cross the HTTP boundary as RFC 3339 strings.
    model_config = ConfigDict(extra="forbid", frozen=True, strict=False)

    id: StrictStr = Field(pattern=r"^note:[0-9a-f]{32}$")
    text: StrictStr = Field(min_length=1, max_length=16_000)
    created_at: datetime


class Attachment(WorkspaceSchema):
    id: StrictStr = Field(pattern=r"^attachment:[0-9a-f]{32}$")
    filename: StrictStr = Field(min_length=1, max_length=255)
    media_type: StrictStr = Field(min_length=1, max_length=128)
    size_bytes: StrictInt = Field(ge=0, le=1_000_000)
    sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("filename")
    @classmethod
    def filename_is_portable(cls, value: str) -> str:
        if (
            value in {".", ".."}
            or "/" in value
            or "\\" in value
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("attachment filename must be a portable basename")
        return value


class ProjectDocument(WorkspaceSchema):
    schema_version: Literal["project-workspace-v1"] = "project-workspace-v1"
    id: StrictStr = Field(pattern=r"^project:[0-9a-f]{32}$")
    name: StrictStr = Field(min_length=1, max_length=256)
    description: StrictStr = Field(default="", max_length=16_000)
    status: Literal["planned", "active", "complete", "archived"] = "planned"
    requirements: tuple[Requirement, ...] = Field(default_factory=tuple, max_length=500)
    milestones: tuple[Milestone, ...] = Field(default_factory=tuple, max_length=200)
    board: tuple[BoardItem, ...] = Field(default_factory=tuple, max_length=1_000)
    notes: tuple[ProjectNote, ...] = Field(default_factory=tuple, max_length=1_000)
    attachments: tuple[Attachment, ...] = Field(default_factory=tuple, max_length=100)
    created_at: datetime
    updated_at: datetime
    model_call: Literal["NO MODEL CALL"] = "NO MODEL CALL"
    model_tokens: Literal[0] = 0


class ProjectCreate(WorkspaceSchema):
    name: StrictStr = Field(min_length=1, max_length=256)
    description: StrictStr = Field(default="", max_length=16_000)


class ProjectUpdate(WorkspaceSchema):
    # HTTP JSON necessarily represents immutable tuples as arrays. The request
    # boundary normalizes those arrays into the frozen tuple-backed document.
    model_config = ConfigDict(extra="forbid", frozen=True, strict=False)

    name: StrictStr = Field(min_length=1, max_length=256)
    description: StrictStr = Field(default="", max_length=16_000)
    status: Literal["planned", "active", "complete", "archived"] = "planned"
    requirements: tuple[Requirement, ...] = Field(default_factory=tuple, max_length=500)
    milestones: tuple[Milestone, ...] = Field(default_factory=tuple, max_length=200)
    board: tuple[BoardItem, ...] = Field(default_factory=tuple, max_length=1_000)
    notes: tuple[ProjectNote, ...] = Field(default_factory=tuple, max_length=1_000)


class AttachmentCreate(WorkspaceSchema):
    filename: StrictStr = Field(min_length=1, max_length=255)
    media_type: StrictStr = Field(min_length=1, max_length=128)
    content_base64: StrictStr = Field(min_length=1, max_length=1_400_000)


class ProjectExport(WorkspaceSchema):
    schema_version: Literal["project-workspace-export-v1"] = "project-workspace-export-v1"
    project: ProjectDocument
    attachment_content: dict[StrictStr, StrictStr] = Field(default_factory=dict)
    export_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")


def new_requirement(
    text: str,
    *,
    status: Literal["planned", "active", "complete", "blocked"] = "planned",
) -> Requirement:
    return Requirement(id=f"requirement:{uuid.uuid4().hex}", text=text, status=status)


def new_milestone(title: str, *, target_date: str | None = None) -> Milestone:
    return Milestone(id=f"milestone:{uuid.uuid4().hex}", title=title, target_date=target_date)


def new_board_item(title: str, *, detail: str = "") -> BoardItem:
    return BoardItem(id=f"board:{uuid.uuid4().hex}", title=title, detail=detail)


def new_note(text: str) -> ProjectNote:
    return ProjectNote(id=f"note:{uuid.uuid4().hex}", text=text, created_at=datetime.now(UTC))


class ProjectWorkspaceStore:
    """Local project records with no model/provider dependency by construction."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS project_workspace (
                    id TEXT PRIMARY KEY,
                    record_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS project_attachments (
                    project_id TEXT NOT NULL,
                    attachment_id TEXT NOT NULL,
                    content BLOB NOT NULL,
                    PRIMARY KEY(project_id, attachment_id),
                    FOREIGN KEY(project_id) REFERENCES project_workspace(id) ON DELETE CASCADE
                );
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @staticmethod
    def _encoded(project: ProjectDocument) -> str:
        return project.model_dump_json()

    @staticmethod
    def _decoded(value: str) -> ProjectDocument:
        return ProjectDocument.model_validate_json(value)

    def create(self, request: ProjectCreate) -> ProjectDocument:
        now = datetime.now(UTC)
        project = ProjectDocument(
            id=f"project:{uuid.uuid4().hex}",
            name=request.name,
            description=request.description,
            created_at=now,
            updated_at=now,
        )
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO project_workspace(id, record_json, updated_at) VALUES (?, ?, ?)",
                (project.id, self._encoded(project), now.isoformat()),
            )
        return project

    def get(self, project_id: str) -> ProjectDocument:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json FROM project_workspace WHERE id=?", (project_id,)
            ).fetchone()
        if row is None:
            raise ProjectWorkspaceError("project was not found")
        return self._decoded(str(row[0]))

    def list(self, *, query: str = "", status: str | None = None) -> tuple[ProjectDocument, ...]:
        normalized = query.strip().casefold()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_json FROM project_workspace ORDER BY updated_at DESC LIMIT 1000"
            ).fetchall()
        projects = tuple(self._decoded(str(row[0])) for row in rows)
        return tuple(
            project
            for project in projects
            if (status is None or project.status == status)
            and (
                not normalized
                or normalized in project.name.casefold()
                or normalized in project.description.casefold()
                or any(normalized in item.text.casefold() for item in project.requirements)
                or any(normalized in item.title.casefold() for item in project.milestones)
                or any(
                    normalized in item.title.casefold() or normalized in item.detail.casefold()
                    for item in project.board
                )
                or any(normalized in item.text.casefold() for item in project.notes)
            )
        )

    def update(self, project_id: str, request: ProjectUpdate) -> ProjectDocument:
        existing = self.get(project_id)
        ids = [
            *(item.id for item in request.requirements),
            *(item.id for item in request.milestones),
            *(item.id for item in request.board),
            *(item.id for item in request.notes),
        ]
        if len(ids) != len(set(ids)):
            raise ProjectWorkspaceError("project item identifiers must be unique")
        updated = ProjectDocument(
            id=existing.id,
            name=request.name,
            description=request.description,
            status=request.status,
            requirements=request.requirements,
            milestones=request.milestones,
            board=request.board,
            notes=request.notes,
            attachments=existing.attachments,
            created_at=existing.created_at,
            updated_at=datetime.now(UTC),
        )
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE project_workspace SET record_json=?, updated_at=? WHERE id=?",
                (self._encoded(updated), updated.updated_at.isoformat(), project_id),
            )
            if cursor.rowcount != 1:
                raise ProjectWorkspaceError("project update conflicted")
        return updated

    def attach(self, project_id: str, request: AttachmentCreate) -> ProjectDocument:
        project = self.get(project_id)
        Attachment(
            id=f"attachment:{'0' * 32}",
            filename=request.filename,
            media_type=request.media_type,
            size_bytes=0,
            sha256="0" * 64,
        )
        try:
            content = base64.b64decode(request.content_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ProjectWorkspaceError("attachment content must be canonical base64") from exc
        if not content or len(content) > 1_000_000:
            raise ProjectWorkspaceError("attachment size must be between 1 byte and 1 MB")
        if sum(item.size_bytes for item in project.attachments) + len(content) > 2_000_000:
            raise ProjectWorkspaceError("project attachment total exceeds 2 MB")
        attachment = Attachment(
            id=f"attachment:{uuid.uuid4().hex}",
            filename=request.filename,
            media_type=request.media_type,
            size_bytes=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
        )
        updated = project.model_copy(
            update={
                "attachments": (*project.attachments, attachment),
                "updated_at": datetime.now(UTC),
            }
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO project_attachments(project_id, attachment_id, content) "
                "VALUES (?, ?, ?)",
                (project_id, attachment.id, content),
            )
            connection.execute(
                "UPDATE project_workspace SET record_json=?, updated_at=? WHERE id=?",
                (self._encoded(updated), updated.updated_at.isoformat(), project_id),
            )
        return updated

    def export(self, project_id: str) -> ProjectExport:
        project = self.get(project_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT attachment_id, content FROM project_attachments "
                "WHERE project_id=? ORDER BY attachment_id",
                (project_id,),
            ).fetchall()
        content = {str(row[0]): base64.b64encode(bytes(row[1])).decode("ascii") for row in rows}
        payload = {
            "schema_version": "project-workspace-export-v1",
            "project": project.model_dump(mode="json"),
            "attachment_content": content,
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return ProjectExport(
            project=project,
            attachment_content=content,
            export_sha256=digest,
        )

    def import_project(self, exported: ProjectExport) -> ProjectDocument:
        payload = {
            "schema_version": exported.schema_version,
            "project": exported.project.model_dump(mode="json"),
            "attachment_content": exported.attachment_content,
        }
        expected = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if expected != exported.export_sha256:
            raise ProjectWorkspaceError("project export digest is invalid")
        if not re.fullmatch(r"project:[0-9a-f]{32}", exported.project.id):
            raise ProjectWorkspaceError("project export identity is invalid")
        decoded: dict[str, bytes] = {}
        for attachment in exported.project.attachments:
            raw = exported.attachment_content.get(attachment.id)
            if raw is None:
                raise ProjectWorkspaceError("project export is missing attachment content")
            try:
                value = base64.b64decode(raw, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ProjectWorkspaceError("project export attachment is invalid") from exc
            if (
                len(value) != attachment.size_bytes
                or hashlib.sha256(value).hexdigest() != attachment.sha256
            ):
                raise ProjectWorkspaceError("project export attachment digest is invalid")
            decoded[attachment.id] = value
        if set(exported.attachment_content) != set(decoded):
            raise ProjectWorkspaceError("project export contains undeclared attachments")
        imported = exported.project.model_copy(
            update={"id": f"project:{uuid.uuid4().hex}", "updated_at": datetime.now(UTC)}
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO project_workspace(id, record_json, updated_at) VALUES (?, ?, ?)",
                (imported.id, self._encoded(imported), imported.updated_at.isoformat()),
            )
            connection.executemany(
                "INSERT INTO project_attachments(project_id, attachment_id, content) "
                "VALUES (?, ?, ?)",
                ((imported.id, attachment_id, value) for attachment_id, value in decoded.items()),
            )
        return imported
