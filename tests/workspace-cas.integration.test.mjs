import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { register } from "node:module";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

globalThis.__lilTweakWorkspaceTestEnv = {};
register(new URL("./workspace-test-loader.mjs", import.meta.url));

const {
  attachFile,
  createProject,
  exportProject,
  getProject,
  updateProject,
} = await import("../lib/workspace.ts");
const { POST } = await import("../app/api/workspace/route.ts");

class D1Statement {
  constructor(database, sql, owner) {
    this.database = database;
    this.sql = sql;
    this.owner = owner;
    this.values = [];
  }

  bind(...values) {
    this.values = values;
    return this;
  }

  async first() {
    return this.database.prepare(this.sql).get(...this.values) ?? null;
  }

  async all() {
    return { results: this.database.prepare(this.sql).all(...this.values) };
  }

  async run() {
    const result = this.database.prepare(this.sql).run(...this.values);
    if (
      this.owner.failProjectUpdateAfterCommit &&
      this.sql.startsWith("UPDATE workspace_projects")
    ) {
      this.owner.failProjectUpdateAfterCommit = false;
      if (this.owner.advanceProjectAfterCommit) {
        const projectId = this.values[5];
        const ownerEmail = this.values[6];
        const row = this.database.prepare(
          "SELECT record_json FROM workspace_projects WHERE id=? AND owner_email=?",
        ).get(projectId, ownerEmail);
        const project = JSON.parse(row.record_json);
        project.revision += 1;
        project.name = "Concurrent follow-up";
        project.updated_at = "2026-08-13T12:00:01.000Z";
        this.database.prepare(
          "UPDATE workspace_projects SET name=?, record_json=?, updated_at=? WHERE id=? AND owner_email=?",
        ).run(project.name, JSON.stringify(project), project.updated_at, projectId, ownerEmail);
      }
      throw new Error("Simulated lost D1 update response.");
    }
    return { meta: { changes: Number(result.changes) } };
  }
}

class LocalD1 {
  constructor(database, options = {}) {
    this.database = database;
    this.failProjectUpdateAfterCommit = options.failProjectUpdateAfterCommit ?? false;
    this.advanceProjectAfterCommit = options.advanceProjectAfterCommit ?? false;
  }

  prepare(sql) {
    return new D1Statement(this.database, sql, this);
  }
}

class MemoryR2 {
  constructor(pairProjectPuts = false, failProjectPutAfterStore = false) {
    this.objects = new Map();
    this.deleted = [];
    this.pairProjectPuts = pairProjectPuts;
    this.failProjectPutAfterStore = failProjectPutAfterStore;
    this.waitingProjectPuts = [];
    this.arrayBufferReads = 0;
  }

  async put(key, value, options = {}) {
    const bytes = value instanceof Uint8Array
      ? Uint8Array.from(value)
      : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    this.objects.set(key, { bytes, options });
    if (this.failProjectPutAfterStore && key.startsWith("projects/")) {
      throw new Error("Simulated lost R2 put response.");
    }
    if (this.pairProjectPuts && key.startsWith("projects/")) {
      await new Promise((release) => {
        this.waitingProjectPuts.push(release);
        if (this.waitingProjectPuts.length === 2) {
          const waiting = this.waitingProjectPuts.splice(0);
          queueMicrotask(() => waiting.forEach((resume) => resume()));
        }
      });
    }
    return { key };
  }

  async delete(key) {
    const keys = Array.isArray(key) ? key : [key];
    for (const item of keys) {
      this.deleted.push(item);
      this.objects.delete(item);
    }
  }

  async get(key) {
    const stored = this.objects.get(key);
    if (!stored) return null;
    return {
      size: stored.bytes.byteLength,
      arrayBuffer: async () => {
        this.arrayBufferReads += 1;
        return Uint8Array.from(stored.bytes).buffer;
      },
    };
  }
}

async function freshBindings(options = {}) {
  const database = new DatabaseSync(":memory:");
  const migration = await readFile(
    new URL("../drizzle/0000_gifted_sharon_ventura.sql", import.meta.url),
    "utf8",
  );
  database.exec(migration.replaceAll("--> statement-breakpoint", ""));
  const files = new MemoryR2(
    options.pairProjectPuts,
    options.failProjectPutAfterStore,
  );
  globalThis.__lilTweakWorkspaceTestEnv.DB = new LocalD1(
    database,
    options,
  );
  globalThis.__lilTweakWorkspaceTestEnv.FILES = files;
  return { database, files };
}

function projectInput(name = "Original") {
  return {
    name,
    description: "Initial mission.",
    status: "planned",
    requirements: [],
    milestones: [],
    board: [],
    notes: [],
  };
}

function attachmentInput(filename, content) {
  return {
    filename,
    media_type: "text/plain",
    content_base64: Buffer.from(content).toString("base64"),
  };
}

async function workspacePost(body) {
  const json = JSON.stringify(body);
  return POST(new Request("https://lil-tweak.example/api/workspace", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "content-length": String(Buffer.byteLength(json)),
      "oai-authenticated-user-id": "owner-1",
      "oai-authenticated-user-email": "islamismylifebey@gmail.com",
      origin: "https://lil-tweak.example",
      "sec-fetch-site": "same-origin",
    },
    body: json,
  }));
}

test("concurrent project updates use an explicit revision CAS", async (context) => {
  const { database } = await freshBindings();
  context.after(() => database.close());
  const owner = "beythetruth4ever@paradigmshiftingthepodcast.net";
  const created = await createProject(owner, projectInput());
  assert.equal(created.revision, 0);

  const results = await Promise.allSettled([
    updateProject(owner, created.id, { ...created, name: "First writer" }, created.revision),
    updateProject(owner, created.id, { ...created, name: "Second writer" }, created.revision),
  ]);

  const fulfilled = results.filter((result) => result.status === "fulfilled");
  const rejected = results.filter((result) => result.status === "rejected");
  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason.code, "stale_project_revision");
  assert.equal(fulfilled[0].value.revision, 1);

  const stored = await getProject(owner, created.id);
  assert.equal(stored.revision, 1);
  assert.equal(stored.name, fulfilled[0].value.name);
});

test("a losing attachment CAS deletes only its new project object", async (context) => {
  const { database, files } = await freshBindings({ pairProjectPuts: true });
  context.after(() => database.close());
  const owner = "beythetruth4ever@paradigmshiftingthepodcast.net";
  const created = await createProject(owner, projectInput());
  const engineeringSourceKey =
    "engineering/owner/jobs/job:11111111111111111111111111111111/sources/source:22222222222222222222222222222222";
  files.objects.set(engineeringSourceKey, { bytes: new Uint8Array([1]), options: {} });

  const results = await Promise.allSettled([
    attachFile(owner, created.id, attachmentInput("first.txt", "first"), created.revision),
    attachFile(owner, created.id, attachmentInput("second.txt", "second"), created.revision),
  ]);

  const fulfilled = results.filter((result) => result.status === "fulfilled");
  const rejected = results.filter((result) => result.status === "rejected");
  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason.code, "stale_project_revision");

  const stored = await getProject(owner, created.id);
  assert.equal(stored.revision, 1);
  assert.equal(stored.attachments.length, 1);
  const projectKeys = [...files.objects.keys()].filter((key) => key.startsWith("projects/"));
  assert.equal(projectKeys.length, 1);
  assert.equal(files.objects.has(engineeringSourceKey), true);
  assert.equal(files.deleted.length, 1);
  assert.match(files.deleted[0], new RegExp(`^projects/${created.id}/attachment:[0-9a-f]{32}$`));
});

test("an indeterminate attachment put is cleaned up by its exact project key", async (context) => {
  const { database, files } = await freshBindings({ failProjectPutAfterStore: true });
  context.after(() => database.close());
  const owner = "beythetruth4ever@paradigmshiftingthepodcast.net";
  const created = await createProject(owner, projectInput());
  const engineeringSourceKey =
    "engineering/owner/jobs/job:33333333333333333333333333333333/sources/source:44444444444444444444444444444444";
  files.objects.set(engineeringSourceKey, { bytes: new Uint8Array([1]), options: {} });

  await assert.rejects(
    attachFile(owner, created.id, attachmentInput("lost.txt", "lost"), created.revision),
    /lost R2 put response/,
  );
  assert.equal(
    [...files.objects.keys()].some((key) => key.startsWith("projects/")),
    false,
  );
  assert.equal(files.objects.has(engineeringSourceKey), true);
  assert.equal(files.deleted.length, 1);
  assert.match(files.deleted[0], new RegExp(`^projects/${created.id}/attachment:[0-9a-f]{32}$`));
});

test("a committed attachment survives a lost D1 update response", async (context) => {
  const { database, files } = await freshBindings({ failProjectUpdateAfterCommit: true });
  context.after(() => database.close());
  const owner = "beythetruth4ever@paradigmshiftingthepodcast.net";
  const created = await createProject(owner, projectInput());

  const attached = await attachFile(
    owner,
    created.id,
    attachmentInput("committed.txt", "committed"),
    created.revision,
  );
  assert.equal(attached.revision, 1);
  assert.equal(attached.attachments.length, 1);
  assert.equal(files.deleted.length, 0);
  assert.equal(
    files.objects.has(`projects/${created.id}/${attached.attachments[0].id}`),
    true,
  );
  assert.deepEqual(await getProject(owner, created.id), attached);
});

test("attachment reconciliation preserves a later project revision that references it", async (context) => {
  const { database, files } = await freshBindings({
    failProjectUpdateAfterCommit: true,
    advanceProjectAfterCommit: true,
  });
  context.after(() => database.close());
  const owner = "beythetruth4ever@paradigmshiftingthepodcast.net";
  const created = await createProject(owner, projectInput());

  const reconciled = await attachFile(
    owner,
    created.id,
    attachmentInput("advanced.txt", "advanced"),
    created.revision,
  );
  assert.equal(reconciled.revision, 2);
  assert.equal(reconciled.name, "Concurrent follow-up");
  assert.equal(reconciled.attachments.length, 1);
  assert.equal(files.deleted.length, 0);
  assert.equal(
    files.objects.has(`projects/${created.id}/${reconciled.attachments[0].id}`),
    true,
  );
});

test("legacy project rows start at revision zero without a schema rewrite", async (context) => {
  const { database } = await freshBindings();
  context.after(() => database.close());
  const owner = "beythetruth4ever@paradigmshiftingthepodcast.net";
  const projectId = `project:${"a".repeat(32)}`;
  const now = "2026-08-13T12:00:00.000Z";
  const legacy = {
    schema_version: "project-workspace-v1",
    id: projectId,
    ...projectInput("Legacy"),
    attachments: [],
    created_at: now,
    updated_at: now,
    model_call: "NO MODEL CALL",
    model_tokens: 0,
  };
  database.prepare(
    "INSERT INTO workspace_projects (id, owner_email, name, description, status, record_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  ).run(
    projectId,
    owner,
    legacy.name,
    legacy.description,
    legacy.status,
    JSON.stringify(legacy),
    now,
    now,
  );

  const read = await getProject(owner, projectId);
  assert.equal(read.revision, 0);
  const updated = await updateProject(owner, projectId, { ...read, name: "Migrated lazily" }, 0);
  assert.equal(updated.revision, 1);
});

test("workspace API returns the current project with 409 on a stale write", async (context) => {
  const { database } = await freshBindings();
  context.after(() => database.close());
  const owner = "beythetruth4ever@paradigmshiftingthepodcast.net";
  const created = await createProject(owner, projectInput());

  const first = await workspacePost({
    action: "update",
    id: created.id,
    expectedRevision: created.revision,
    project: { ...created, name: "Accepted" },
  });
  assert.equal(first.status, 200);

  const stale = await workspacePost({
    action: "update",
    id: created.id,
    expectedRevision: created.revision,
    project: { ...created, name: "Stale" },
  });
  assert.equal(stale.status, 409);
  assert.deepEqual(await stale.json(), {
    error: "Project changed since it was loaded.",
    code: "stale_project_revision",
    project: { ...(await getProject(owner, created.id)), name: "Accepted" },
  });
});

test("workspace API keeps safe update compatibility but rejects a blind attachment", async (context) => {
  const { database, files } = await freshBindings();
  context.after(() => database.close());
  const owner = "beythetruth4ever@paradigmshiftingthepodcast.net";
  const created = await createProject(owner, projectInput());

  const compatibleUpdate = await workspacePost({
    action: "update",
    id: created.id,
    project: { ...created, name: "Nested revision" },
  });
  assert.equal(compatibleUpdate.status, 200);
  assert.equal((await compatibleUpdate.json()).project.revision, 1);

  const blindAttachment = await workspacePost({
    action: "attach",
    id: created.id,
    attachment: attachmentInput("blind.txt", "blind"),
  });
  assert.equal(blindAttachment.status, 400);
  assert.deepEqual(await blindAttachment.json(), {
    error: "Project revision is required.",
  });
  assert.equal(
    [...files.objects.keys()].some((key) => key.startsWith("projects/")),
    false,
  );
});

test("project documents have an aggregate storage bound", async (context) => {
  const { database } = await freshBindings();
  context.after(() => database.close());
  const owner = "beythetruth4ever@paradigmshiftingthepodcast.net";
  const oversized = {
    ...projectInput(),
    notes: Array.from({ length: 20 }, () => ({ text: "x".repeat(16_000) })),
  };

  await assert.rejects(
    createProject(owner, oversized),
    /Project document exceeds the 256 KB limit/,
  );
  assert.equal(
    database.prepare("SELECT COUNT(*) AS count FROM workspace_projects").get().count,
    0,
  );
});

test("project export rejects an oversized R2 object before buffering it", async (context) => {
  const { database, files } = await freshBindings();
  context.after(() => database.close());
  const owner = "beythetruth4ever@paradigmshiftingthepodcast.net";
  const created = await createProject(owner, projectInput());
  const attached = await attachFile(
    owner,
    created.id,
    attachmentInput("bounded.txt", "bounded"),
    created.revision,
  );
  const attachment = attached.attachments[0];
  files.objects.set(`projects/${created.id}/${attachment.id}`, {
    bytes: new Uint8Array(1_000_001),
    options: {},
  });

  await assert.rejects(
    exportProject(owner, created.id),
    /failed its integrity check/,
  );
  assert.equal(files.arrayBufferReads, 0);
});
