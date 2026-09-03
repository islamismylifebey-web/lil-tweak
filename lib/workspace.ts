import { env } from "cloudflare:workers";

export const PROJECT_STATUSES = [
  "planned",
  "active",
  "complete",
  "archived",
] as const;
export const REQUIREMENT_STATUSES = [
  "planned",
  "active",
  "complete",
  "blocked",
] as const;
export const MILESTONE_STATUSES = REQUIREMENT_STATUSES;
export const BOARD_COLUMNS = [
  "backlog",
  "ready",
  "active",
  "review",
  "done",
] as const;

export type ProjectStatus = (typeof PROJECT_STATUSES)[number];
export type RequirementStatus = (typeof REQUIREMENT_STATUSES)[number];
export type BoardColumn = (typeof BOARD_COLUMNS)[number];

export interface Requirement {
  id: string;
  text: string;
  status: RequirementStatus;
}

export interface Milestone {
  id: string;
  title: string;
  target_date: string | null;
  status: RequirementStatus;
}

export interface BoardItem {
  id: string;
  title: string;
  detail: string;
  column: BoardColumn;
}

export interface ProjectNote {
  id: string;
  text: string;
  created_at: string;
}

export interface Attachment {
  id: string;
  filename: string;
  media_type: string;
  size_bytes: number;
  sha256: string;
}

export interface ProjectDocument {
  schema_version: "project-workspace-v1";
  id: string;
  revision: number;
  name: string;
  description: string;
  status: ProjectStatus;
  requirements: Requirement[];
  milestones: Milestone[];
  board: BoardItem[];
  notes: ProjectNote[];
  attachments: Attachment[];
  created_at: string;
  updated_at: string;
  model_call: "NO MODEL CALL";
  model_tokens: 0;
}

interface Bindings {
  DB: D1Database;
  FILES: R2Bucket;
}

interface ProjectRow {
  record_json: string;
}

interface LoadedProject {
  project: ProjectDocument;
  recordJson: string;
}

export class ProjectConflictError extends Error {
  readonly code = "stale_project_revision";
  readonly currentProject: ProjectDocument | null;

  constructor(currentProject: ProjectDocument | null) {
    super("Project changed since it was loaded.");
    this.name = "ProjectConflictError";
    this.currentProject = currentProject;
  }
}

class ProjectWriteIndeterminateError extends Error {
  constructor() {
    super("Project update outcome could not be verified.");
    this.name = "ProjectWriteIndeterminateError";
  }
}

const MAX_PROJECTS = 100;
const MAX_PROJECT_DOCUMENT_BYTES = 256 * 1024;
const MAX_ATTACHMENT_BYTES = 1_000_000;
const MAX_PROJECT_ATTACHMENT_BYTES = 2_000_000;

function bindings() {
  return env as unknown as Bindings;
}

function stringValue(value: unknown, label: string, maxLength: number) {
  if (typeof value !== "string") throw new Error(`${label} must be text.`);
  const trimmed = value.trim();
  if (!trimmed) throw new Error(`${label} is required.`);
  if (trimmed.length > maxLength) {
    throw new Error(`${label} is longer than ${maxLength.toLocaleString()} characters.`);
  }
  return trimmed;
}

function optionalString(value: unknown, label: string, maxLength: number) {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string") throw new Error(`${label} must be text.`);
  const trimmed = value.trim();
  if (trimmed.length > maxLength) {
    throw new Error(`${label} is longer than ${maxLength.toLocaleString()} characters.`);
  }
  return trimmed;
}

function valueFrom<const T extends readonly string[]>(
  value: unknown,
  allowed: T,
  fallback: T[number],
): T[number] {
  return typeof value === "string" && (allowed as readonly string[]).includes(value)
    ? (value as T[number])
    : fallback;
}

function newId(prefix: string) {
  return `${prefix}:${crypto.randomUUID().replaceAll("-", "")}`;
}

function portableFilename(value: unknown) {
  const filename = stringValue(value, "Attachment filename", 255);
  if (
    filename === "." ||
    filename === ".." ||
    filename.includes("/") ||
    filename.includes("\\") ||
    [...filename].some((character) => {
      const code = character.charCodeAt(0);
      return code < 32 || code === 127;
    })
  ) {
    throw new Error("Attachment filename must be a portable basename.");
  }
  return filename;
}

function listValue(value: unknown, label: string, maxLength: number) {
  if (!Array.isArray(value)) throw new Error(`${label} must be a list.`);
  if (value.length > maxLength) {
    throw new Error(`${label} exceeds the ${maxLength.toLocaleString()} item limit.`);
  }
  return value;
}

function sanitizedProject(
  value: unknown,
  existing?: ProjectDocument,
): ProjectDocument {
  if (!value || typeof value !== "object") throw new Error("Project data is required.");
  const input = value as Record<string, unknown>;
  const now = new Date().toISOString();

  const requirements = listValue(input.requirements ?? [], "Requirements", 500).map(
    (item, index) => {
      if (!item || typeof item !== "object") {
        throw new Error(`Requirement ${index + 1} is invalid.`);
      }
      const record = item as Record<string, unknown>;
      return {
        id:
          typeof record.id === "string" && /^requirement:[0-9a-f]{32}$/.test(record.id)
            ? record.id
            : newId("requirement"),
        text: stringValue(record.text, `Requirement ${index + 1}`, 4000),
        status: valueFrom(record.status, REQUIREMENT_STATUSES, "planned"),
      } satisfies Requirement;
    },
  );

  const milestones = listValue(input.milestones ?? [], "Milestones", 200).map(
    (item, index) => {
      if (!item || typeof item !== "object") {
        throw new Error(`Milestone ${index + 1} is invalid.`);
      }
      const record = item as Record<string, unknown>;
      const targetDate = record.target_date;
      if (
        targetDate !== undefined &&
        targetDate !== null &&
        (typeof targetDate !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(targetDate))
      ) {
        throw new Error(`Milestone ${index + 1} has an invalid target date.`);
      }
      return {
        id:
          typeof record.id === "string" && /^milestone:[0-9a-f]{32}$/.test(record.id)
            ? record.id
            : newId("milestone"),
        title: stringValue(record.title, `Milestone ${index + 1}`, 256),
        target_date: typeof targetDate === "string" ? targetDate : null,
        status: valueFrom(record.status, MILESTONE_STATUSES, "planned"),
      } satisfies Milestone;
    },
  );

  const board = listValue(input.board ?? [], "Task board", 1000).map(
    (item, index) => {
      if (!item || typeof item !== "object") {
        throw new Error(`Task ${index + 1} is invalid.`);
      }
      const record = item as Record<string, unknown>;
      return {
        id:
          typeof record.id === "string" && /^board:[0-9a-f]{32}$/.test(record.id)
            ? record.id
            : newId("board"),
        title: stringValue(record.title, `Task ${index + 1}`, 256),
        detail: optionalString(record.detail, `Task ${index + 1} detail`, 4000),
        column: valueFrom(record.column, BOARD_COLUMNS, "backlog"),
      } satisfies BoardItem;
    },
  );

  const notes = listValue(input.notes ?? [], "Notes", 1000).map((item, index) => {
    if (!item || typeof item !== "object") {
      throw new Error(`Note ${index + 1} is invalid.`);
    }
    const record = item as Record<string, unknown>;
    return {
      id:
        typeof record.id === "string" && /^note:[0-9a-f]{32}$/.test(record.id)
          ? record.id
          : newId("note"),
      text: stringValue(record.text, `Note ${index + 1}`, 16000),
      created_at:
        typeof record.created_at === "string" && !Number.isNaN(Date.parse(record.created_at))
          ? new Date(record.created_at).toISOString()
          : now,
    } satisfies ProjectNote;
  });

  const itemIds = [
    ...requirements.map((item) => item.id),
    ...milestones.map((item) => item.id),
    ...board.map((item) => item.id),
    ...notes.map((item) => item.id),
  ];
  if (new Set(itemIds).size !== itemIds.length) {
    throw new Error("Project item identifiers must be unique.");
  }

  return {
    schema_version: "project-workspace-v1",
    id: existing?.id ?? newId("project"),
    revision: existing?.revision ?? 0,
    name: stringValue(input.name, "Project name", 256),
    description: optionalString(input.description, "Project description", 16000),
    status: valueFrom(input.status, PROJECT_STATUSES, "planned"),
    requirements,
    milestones,
    board,
    notes,
    attachments: existing?.attachments ?? [],
    created_at: existing?.created_at ?? now,
    updated_at: now,
    model_call: "NO MODEL CALL",
    model_tokens: 0,
  };
}

function encodedByteLength(value: string) {
  return new TextEncoder().encode(value).byteLength;
}

function projectRecord(project: ProjectDocument) {
  const record = JSON.stringify(project);
  if (encodedByteLength(record) > MAX_PROJECT_DOCUMENT_BYTES) {
    throw new Error("Project document exceeds the 256 KB limit.");
  }
  return record;
}

function decodeProject(value: string): ProjectDocument {
  if (encodedByteLength(value) > MAX_PROJECT_DOCUMENT_BYTES) {
    throw new Error("Workspace project record exceeds its storage limit.");
  }
  const project = JSON.parse(value) as ProjectDocument & { revision?: unknown };
  return {
    ...project,
    revision:
      typeof project.revision === "number" &&
      Number.isSafeInteger(project.revision) &&
      project.revision >= 0
        ? project.revision
        : 0,
  };
}

function requiredRevision(value: unknown) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error("Project revision is required.");
  }
  return value;
}

async function loadProject(ownerEmail: string, projectId: string): Promise<LoadedProject> {
  if (!/^project:[0-9a-f]{32}$/.test(projectId)) throw new Error("Project ID is invalid.");
  const row = await bindings().DB.prepare(
    "SELECT record_json FROM workspace_projects WHERE id=? AND owner_email=? LIMIT 1",
  )
    .bind(projectId, ownerEmail)
    .first<ProjectRow>();
  if (!row) throw new Error("Project was not found.");
  return { project: decodeProject(row.record_json), recordJson: row.record_json };
}

async function writeProject(
  project: ProjectDocument,
  ownerEmail: string,
  insert: boolean,
  expectedRecordJson?: string,
) {
  const database = bindings().DB;
  const record = projectRecord(project);
  if (insert) {
    await database
      .prepare(
        "INSERT INTO workspace_projects " +
          "(id, owner_email, name, description, status, record_json, created_at, updated_at) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .bind(
        project.id,
        ownerEmail,
        project.name,
        project.description,
        project.status,
        record,
        project.created_at,
        project.updated_at,
      )
      .run();
    return;
  }

  let result: D1Result;
  try {
    result = await database
      .prepare(
        "UPDATE workspace_projects SET name=?, description=?, status=?, record_json=?, " +
          "updated_at=? WHERE id=? AND owner_email=? AND record_json=?",
      )
      .bind(
        project.name,
        project.description,
        project.status,
        record,
        project.updated_at,
        project.id,
        ownerEmail,
        expectedRecordJson,
      )
      .run();
  } catch (error) {
    let current: LoadedProject;
    try {
      current = await loadProject(ownerEmail, project.id);
    } catch {
      throw new ProjectWriteIndeterminateError();
    }
    if (current.recordJson === record) return;
    if (current.recordJson !== expectedRecordJson) {
      throw new ProjectConflictError(current.project);
    }
    throw error;
  }
  if (!result.meta.changes) {
    let currentProject: ProjectDocument | null = null;
    try {
      currentProject = (await loadProject(ownerEmail, project.id)).project;
    } catch {
      // A concurrent deletion is still a stale write from the caller's perspective.
    }
    throw new ProjectConflictError(currentProject);
  }
}

export async function listProjects(
  ownerEmail: string,
  query = "",
  status = "",
) {
  const result = await bindings().DB.prepare(
    "SELECT record_json FROM workspace_projects WHERE owner_email=? " +
      "ORDER BY updated_at DESC LIMIT ?",
  )
    .bind(ownerEmail, MAX_PROJECTS)
    .all<ProjectRow>();
  const normalized = query.trim().toLocaleLowerCase();
  return result.results
    .map((row) => decodeProject(row.record_json))
    .filter(
      (project) =>
        (!status || project.status === status) &&
        (!normalized ||
          project.name.toLocaleLowerCase().includes(normalized) ||
          project.description.toLocaleLowerCase().includes(normalized) ||
          project.requirements.some((item) =>
            item.text.toLocaleLowerCase().includes(normalized),
          ) ||
          project.milestones.some((item) =>
            item.title.toLocaleLowerCase().includes(normalized),
          ) ||
          project.board.some(
            (item) =>
              item.title.toLocaleLowerCase().includes(normalized) ||
              item.detail.toLocaleLowerCase().includes(normalized),
          ) ||
          project.notes.some((item) =>
            item.text.toLocaleLowerCase().includes(normalized),
          )),
    );
}

export async function getProject(ownerEmail: string, projectId: string) {
  return (await loadProject(ownerEmail, projectId)).project;
}

export async function createProject(ownerEmail: string, value: unknown) {
  const project = sanitizedProject(value);
  await writeProject(project, ownerEmail, true);
  return project;
}

export async function updateProject(
  ownerEmail: string,
  projectId: string,
  value: unknown,
  expectedRevision: number,
) {
  const expected = requiredRevision(expectedRevision);
  const existing = await loadProject(ownerEmail, projectId);
  if (existing.project.revision !== expected) {
    throw new ProjectConflictError(existing.project);
  }
  const project = {
    ...sanitizedProject(value, existing.project),
    revision: existing.project.revision + 1,
  };
  await writeProject(project, ownerEmail, false, existing.recordJson);
  return project;
}

function bytesFromBase64(value: unknown) {
  if (typeof value !== "string" || value.length > 1_400_000) {
    throw new Error("Attachment content is invalid.");
  }
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    throw new Error("Attachment content must be canonical base64.");
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (!bytes.length || bytes.length > MAX_ATTACHMENT_BYTES) {
    throw new Error("Attachment size must be between 1 byte and 1 MB.");
  }
  return bytes;
}

async function sha256(bytes: Uint8Array) {
  const digest = await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes).buffer);
  return [...new Uint8Array(digest)]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

function attachmentKey(projectId: string, attachmentId: string) {
  return `projects/${projectId}/${attachmentId}`;
}

function projectHasAttachment(project: ProjectDocument, attachment: Attachment) {
  return project.attachments.some(
    (item) =>
      item.id === attachment.id &&
      item.filename === attachment.filename &&
      item.media_type === attachment.media_type &&
      item.size_bytes === attachment.size_bytes &&
      item.sha256 === attachment.sha256,
  );
}

export async function attachFile(
  ownerEmail: string,
  projectId: string,
  value: unknown,
  expectedRevision: number,
) {
  const expected = requiredRevision(expectedRevision);
  const existing = await loadProject(ownerEmail, projectId);
  const project = existing.project;
  if (project.revision !== expected) {
    throw new ProjectConflictError(project);
  }
  if (!value || typeof value !== "object") throw new Error("Attachment data is required.");
  const input = value as Record<string, unknown>;
  const bytes = bytesFromBase64(input.content_base64);
  if (
    project.attachments.reduce((total, item) => total + item.size_bytes, 0) +
      bytes.length >
    MAX_PROJECT_ATTACHMENT_BYTES
  ) {
    throw new Error("Project attachment total exceeds 2 MB.");
  }
  const attachment: Attachment = {
    id: newId("attachment"),
    filename: portableFilename(input.filename),
    media_type: optionalString(input.media_type, "Attachment media type", 128) ||
      "application/octet-stream",
    size_bytes: bytes.length,
    sha256: await sha256(bytes),
  };
  const key = attachmentKey(project.id, attachment.id);
  const updated: ProjectDocument = {
    ...project,
    revision: project.revision + 1,
    attachments: [...project.attachments, attachment],
    updated_at: new Date().toISOString(),
  };
  try {
    await bindings().FILES.put(key, bytes, {
      httpMetadata: { contentType: attachment.media_type },
      customMetadata: { sha256: attachment.sha256 },
    });
    await writeProject(updated, ownerEmail, false, existing.recordJson);
  } catch (error) {
    if (
      error instanceof ProjectConflictError &&
      error.currentProject &&
      projectHasAttachment(error.currentProject, attachment)
    ) {
      return error.currentProject;
    }
    if (error instanceof ProjectWriteIndeterminateError) {
      console.error("Project attachment write needs reconciliation.", {
        projectId: project.id,
        objectKey: key,
        errorName: error.name,
      });
    } else {
      try {
        await bindings().FILES.delete(key);
      } catch (cleanupError) {
        console.error("Project attachment cleanup failed.", {
          projectId: project.id,
          objectKey: key,
          errorName: cleanupError instanceof Error ? cleanupError.name : "UnknownError",
        });
      }
    }
    throw error;
  }
  return updated;
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, stableValue(nested)]),
    );
  }
  return value;
}

async function exportDigest(value: unknown) {
  const bytes = new TextEncoder().encode(JSON.stringify(stableValue(value)));
  return sha256(bytes);
}

function base64FromBytes(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export async function exportProject(ownerEmail: string, projectId: string) {
  const project = await getProject(ownerEmail, projectId);
  const attachmentContent: Record<string, string> = {};
  for (const attachment of project.attachments) {
    const object = await bindings().FILES.get(attachmentKey(project.id, attachment.id));
    if (!object) throw new Error(`Attachment ${attachment.filename} is unavailable.`);
    if (
      !Number.isSafeInteger(object.size) ||
      object.size < 0 ||
      object.size > MAX_ATTACHMENT_BYTES ||
      object.size !== attachment.size_bytes
    ) {
      throw new Error(`Attachment ${attachment.filename} failed its integrity check.`);
    }
    const bytes = new Uint8Array(await object.arrayBuffer());
    if (bytes.length !== attachment.size_bytes || (await sha256(bytes)) !== attachment.sha256) {
      throw new Error(`Attachment ${attachment.filename} failed its integrity check.`);
    }
    attachmentContent[attachment.id] = base64FromBytes(bytes);
  }
  const payload = {
    schema_version: "project-workspace-export-v1" as const,
    project,
    attachment_content: attachmentContent,
  };
  return { ...payload, export_sha256: await exportDigest(payload) };
}

export async function importProject(ownerEmail: string, value: unknown) {
  if (!value || typeof value !== "object") throw new Error("Project import is invalid.");
  const input = value as Record<string, unknown>;
  if (input.schema_version !== "project-workspace-export-v1") {
    throw new Error("Project import schema is unsupported.");
  }
  if (!input.project || typeof input.project !== "object") {
    throw new Error("Project import is missing project data.");
  }
  if (!input.attachment_content || typeof input.attachment_content !== "object") {
    throw new Error("Project import is missing attachment content.");
  }
  const suppliedDigest = input.export_sha256;
  const digestPayload = {
    schema_version: input.schema_version,
    project: input.project,
    attachment_content: input.attachment_content,
  };
  if (
    typeof suppliedDigest !== "string" ||
    suppliedDigest !== (await exportDigest(digestPayload))
  ) {
    throw new Error("Project import digest is invalid.");
  }

  const importedSource = input.project as Record<string, unknown>;
  const sourceAttachments = listValue(
    importedSource.attachments ?? [],
    "Imported attachments",
    100,
  );
  const attachmentContent = input.attachment_content as Record<string, unknown>;
  const project = sanitizedProject({ ...importedSource, attachments: [] });
  const uploaded: string[] = [];
  const attachments: Attachment[] = [];
  try {
    for (const item of sourceAttachments) {
      if (!item || typeof item !== "object") throw new Error("Imported attachment is invalid.");
      const record = item as Record<string, unknown>;
      const sourceId = stringValue(record.id, "Imported attachment ID", 64);
      if (!/^attachment:[0-9a-f]{32}$/.test(sourceId)) {
        throw new Error("Imported attachment ID is invalid.");
      }
      const bytes = bytesFromBase64(attachmentContent[sourceId]);
      const expectedSize = record.size_bytes;
      const expectedSha = record.sha256;
      if (
        typeof expectedSize !== "number" ||
        expectedSize !== bytes.length ||
        typeof expectedSha !== "string" ||
        expectedSha !== (await sha256(bytes))
      ) {
        throw new Error("Imported attachment failed its integrity check.");
      }
      const attachment: Attachment = {
        id: sourceId,
        filename: portableFilename(record.filename),
        media_type:
          optionalString(record.media_type, "Imported attachment media type", 128) ||
          "application/octet-stream",
        size_bytes: bytes.length,
        sha256: expectedSha,
      };
      const key = attachmentKey(project.id, attachment.id);
      await bindings().FILES.put(key, bytes, {
        httpMetadata: { contentType: attachment.media_type },
        customMetadata: { sha256: attachment.sha256 },
      });
      uploaded.push(key);
      attachments.push(attachment);
    }
    if (Object.keys(attachmentContent).length !== attachments.length) {
      throw new Error("Project import contains undeclared attachments.");
    }
    if (
      attachments.reduce((total, item) => total + item.size_bytes, 0) >
      MAX_PROJECT_ATTACHMENT_BYTES
    ) {
      throw new Error("Imported attachment total exceeds 2 MB.");
    }
    const imported: ProjectDocument = { ...project, attachments };
    await writeProject(imported, ownerEmail, true);
    return imported;
  } catch (error) {
    await Promise.all(uploaded.map((key) => bindings().FILES.delete(key)));
    throw error;
  }
}
