import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("engineering D1 migration creates the owner-facing job mirror", async () => {
  const migration = await readFile(
    new URL("../drizzle/0001_lil_tweak_engineering.sql", import.meta.url),
    "utf8",
  );
  const script = String.raw`
import json, sqlite3, sys
db = sqlite3.connect(":memory:")
db.executescript(sys.stdin.read())
tables = sorted(row[0] for row in db.execute(
    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'engineering_%'"
))
jobs = [row[1:4] for row in db.execute("PRAGMA table_info(engineering_jobs)")]
sources = [row[1:4] for row in db.execute("PRAGMA table_info(engineering_sources)")]
print(json.dumps({"tables": tables, "jobs": jobs, "sources": sources}))
`;
  const result = spawnSync("python3", ["-c", script], {
    input: migration,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  const schema = JSON.parse(result.stdout);
  assert.deepEqual(schema.tables, [
    "engineering_audit_events",
    "engineering_evidence",
    "engineering_jobs",
    "engineering_sources",
  ]);
  const jobColumns = new Map(schema.jobs.map(([name, type, notNull]) => [name, { type, notNull }]));
  assert.deepEqual(jobColumns.get("id"), { type: "TEXT", notNull: 1 });
  assert.deepEqual(jobColumns.get("owner_key"), { type: "TEXT", notNull: 1 });
  assert.deepEqual(jobColumns.get("git_repository_url"), { type: "TEXT", notNull: 0 });
  assert.deepEqual(jobColumns.get("git_commit"), { type: "TEXT", notNull: 0 });
  assert.deepEqual(jobColumns.get("revision"), { type: "INTEGER", notNull: 1 });
  assert.deepEqual(jobColumns.get("core_revision"), { type: "INTEGER", notNull: 0 });
  assert.deepEqual(jobColumns.get("dispatch_reserved_at"), { type: "TEXT", notNull: 0 });
  assert.deepEqual(jobColumns.get("source_digest"), { type: "TEXT", notNull: 0 });
  assert.deepEqual(jobColumns.get("approval_proposal_json"), { type: "TEXT", notNull: 0 });
  assert.deepEqual(jobColumns.get("approval_consumed"), { type: "INTEGER", notNull: 1 });
  assert.deepEqual(jobColumns.get("create_idempotency_key"), { type: "TEXT", notNull: 1 });
  assert.deepEqual(jobColumns.get("create_request_digest"), { type: "TEXT", notNull: 1 });
  assert.deepEqual(jobColumns.get("authorized_decision"), { type: "TEXT", notNull: 0 });
  assert.deepEqual(jobColumns.get("authorized_proposal_digest"), { type: "TEXT", notNull: 0 });
  assert.deepEqual(jobColumns.get("authorized_at"), { type: "TEXT", notNull: 0 });
  assert.deepEqual(jobColumns.get("request_r2_key"), { type: "TEXT", notNull: 1 });
  const sourceColumns = new Map(schema.sources.map(([name, type, notNull]) => [name, { type, notNull }]));
  assert.deepEqual(sourceColumns.get("sha256"), { type: "TEXT", notNull: 0 });
  assert.deepEqual(sourceColumns.get("revision_applied"), { type: "INTEGER", notNull: 1 });
});

test("workspace idempotency migration preserves legacy projects with safe defaults", () => {
  const root = new URL("..", import.meta.url).pathname;
  const script = String.raw`
import json, sqlite3, sys
from pathlib import Path

root = Path(sys.argv[1])
db = sqlite3.connect(":memory:")
def migrate(name):
    sql = (root / "drizzle" / f"{name}.sql").read_text().replace("--> statement-breakpoint", "")
    db.executescript(sql)

migrate("0000_gifted_sharon_ventura")
db.executemany(
    """INSERT INTO workspace_projects
       (id, owner_email, name, description, status, record_json, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
    [
        ("project-legacy-1", "owner@example.com", "Launch plan", "Existing project", "active", '{"version":1}', "2026-08-01T12:00:00Z", "2026-08-10T15:30:00Z"),
        ("project-legacy-2", "owner@example.com", "Research", "", "planned", '{"version":2}', "2026-08-02T09:00:00Z", "2026-08-11T16:45:00Z"),
    ],
)
for migration in ("0001_lil_tweak_engineering", "0002_workspace_creation_idempotency"):
    migrate(migration)

rows = db.execute(
    """SELECT id, owner_email, name, description, status, record_json,
              create_idempotency_key, create_request_digest, create_complete,
              created_at, updated_at
       FROM workspace_projects ORDER BY id"""
).fetchall()
print(json.dumps(rows))
`;
  const result = spawnSync("python3", ["-c", script, root], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), [
    [
      "project-legacy-1",
      "owner@example.com",
      "Launch plan",
      "Existing project",
      "active",
      '{"version":1}',
      null,
      null,
      1,
      "2026-08-01T12:00:00Z",
      "2026-08-10T15:30:00Z",
    ],
    [
      "project-legacy-2",
      "owner@example.com",
      "Research",
      "",
      "planned",
      '{"version":2}',
      null,
      null,
      1,
      "2026-08-02T09:00:00Z",
      "2026-08-11T16:45:00Z",
    ],
  ]);
});

test("registers every shipped D1 migration in the Drizzle journal", async () => {
  const journal = JSON.parse(await readFile(
    new URL("../drizzle/meta/_journal.json", import.meta.url),
    "utf8",
  ));
  assert.deepEqual(
    journal.entries.map((entry) => entry.tag),
    [
      "0000_gifted_sharon_ventura",
      "0001_lil_tweak_engineering",
      "0002_workspace_creation_idempotency",
    ],
  );
  const snapshot = JSON.parse(await readFile(
    new URL("../drizzle/meta/0001_snapshot.json", import.meta.url),
    "utf8",
  ));
  const jobs = snapshot.tables.engineering_jobs;
  for (const column of ["create_idempotency_key", "create_request_digest", "dispatch_reserved_at"]) {
    assert.ok(jobs.columns[column], `Drizzle snapshot is missing ${column}`);
  }
  assert.deepEqual(jobs.indexes.idx_engineering_jobs_owner_create_key, {
    name: "idx_engineering_jobs_owner_create_key",
    columns: ["owner_key", "create_idempotency_key"],
    isUnique: true,
  });
  assert.match(
    jobs.indexes.idx_engineering_jobs_remote_id.where ?? "",
    /remote_job_id.*is not null/i,
    "Drizzle snapshot must preserve the shipped partial remote-job index",
  );
  for (const constraint of [
    "engineering_jobs_mode_check",
    "engineering_jobs_state_check",
    "engineering_jobs_approval_consumed_check",
    "engineering_jobs_authorized_decision_check",
  ]) {
    assert.ok(jobs.checkConstraints[constraint], `Drizzle snapshot is missing ${constraint}`);
  }
  assert.ok(
    snapshot.tables.engineering_sources.checkConstraints.engineering_sources_size_check,
    "Drizzle snapshot is missing the source-size constraint",
  );
  assert.ok(snapshot.tables.engineering_sources.columns.sha256, "Drizzle snapshot is missing engineering_sources.sha256");
});

test("the Drizzle source schema retains release-critical checks and partial indexes", async () => {
  const source = await readFile(new URL("../db/schema.ts", import.meta.url), "utf8");
  for (const name of [
    "engineering_jobs_mode_check",
    "engineering_jobs_state_check",
    "engineering_jobs_approval_consumed_check",
    "engineering_jobs_authorized_decision_check",
    "engineering_sources_size_check",
    "engineering_sources_sha256_check",
    "engineering_sources_revision_applied_check",
    "engineering_evidence_size_check",
    "engineering_audit_actor_check",
  ]) {
    assert.ok(source.includes(name), `Drizzle schema is missing ${name}`);
  }
  assert.match(source, /idx_engineering_jobs_remote_id[\s\S]*?\.where\(/);
});
