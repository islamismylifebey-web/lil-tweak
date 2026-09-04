import assert from "node:assert/strict";
import { register } from "node:module";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { readFile } from "node:fs/promises";

let reads = 0;
let binding;
globalThis.__lilTweakWorkspaceTestEnv = new Proxy({}, { get(_target, name) { reads += 1; if (name === "DB" && binding) return binding; throw new Error("binding touched"); } });
register(new URL("./workspace-test-loader.mjs", import.meta.url));
const { GET } = await import("../app/api/engineering/jobs/[id]/activation-evidence/route.ts");

test("forbidden owner causes zero binding fetches", async () => {
  const response = await GET(new Request("https://site.example/api/engineering/jobs/job:00000000000000000000000000000000/activation-evidence", {
    headers: { "oai-authenticated-user-id": "id", "oai-authenticated-user-email": "forbidden@example.com" },
  }), { params: Promise.resolve({ id: "job:" + "0".repeat(32) }) });
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "Owner access required." });
  assert.equal(reads, 0);
});

test("real owner route exports one D1 snapshot with exact rows and zero private fields", async () => {
  const database = new DatabaseSync(":memory:");
  database.exec((await readFile(new URL("../drizzle/0001_lil_tweak_engineering.sql", import.meta.url), "utf8")).replaceAll("--> statement-breakpoint", ""));
  binding = {
    prepare(sql) { return { bind(...values) { return { sql, values }; } }; },
    async batch(statements) {
      database.exec("BEGIN");
      try { const results = statements.map(({ sql, values }) => ({ results: database.prepare(sql).all(...values) })); database.exec("COMMIT"); return results; }
      catch (error) { database.exec("ROLLBACK"); throw error; }
    },
  };
  const scope = "a0885bc0b2c079e996629061a723c74d";
  const jobId = "job:" + "1".repeat(32);
  const remote = "00000000-0000-4000-8000-000000000000";
  const time = new Date().toISOString();
  database.prepare("INSERT INTO engineering_jobs(id,owner_key,create_idempotency_key,create_request_digest,mode,prompt_digest,prompt_preview,state,revision,remote_job_id,core_revision,git_repository_url,git_commit,source_digest,proposal_digest,request_r2_key,source_r2_prefix,evidence_r2_prefix,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").run(jobId, scope, crypto.randomUUID(), "a".repeat(64), "architect", "b".repeat(64), "private-prompt-CANARY", "completed", 3, remote, 8, "https://github.com/octocat/Hello-World.git", "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d", "c".repeat(64), "d".repeat(64), "private-key-CANARY", "private-prefix-CANARY", "private-evidence-CANARY", time, time);
  for (let index = 0; index < 5; index += 1) database.prepare("INSERT INTO engineering_evidence(id,job_id,owner_key,category,filename,media_type,size_bytes,sha256,r2_key,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)").run("evidence:" + String(index + 1).repeat(32), jobId, scope, ["plan", "patch", "tests", "manifest", "summary"][index], ["plan.md", "changes.patch", "tests.log", "manifest.json", "summary.md"][index], "text/plain", 0, "e".repeat(64), "private-object-CANARY", time);
  for (const [index, type] of ["job_created", "dispatch_reserved", "core_dispatched", "core_status_mirrored"].entries()) database.prepare("INSERT INTO engineering_audit_events(id,job_id,owner_key,actor,event_type,correlation_id,summary,detail_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)").run("audit:" + String(index + 1).repeat(32), jobId, scope, "owner", type, crypto.randomUUID(), "private-summary-CANARY", '{"secret":"CANARY"}', time);
  try {
    const response = await GET(new Request(`https://site.example/api/engineering/jobs/${jobId}/activation-evidence`, { headers: { "oai-authenticated-user-id": "id", "oai-authenticated-user-email": "islamismylifebey@gmail.com" } }), { params: Promise.resolve({ id: jobId }) });
    assert.equal(response.status, 200);
    const value = await response.json();
    assert.deepEqual(Object.keys(value).sort(), ["schema", "observedAt", "jobId", "remoteJobId", "ownerScope", "jobRevision", "coreRevision", "mode", "state", "gitSource", "sourceDigest", "proposalDigest", "approvalProposal", "approvalConsumed", "decisionCount", "exportCount", "evidence", "events"].sort());
    assert.equal(value.jobId, jobId); assert.equal(value.remoteJobId, remote); assert.equal(value.ownerScope, scope); assert.equal(value.jobRevision, 3); assert.equal(value.coreRevision, 8);
    assert.equal(value.decisionCount, 0); assert.equal(value.exportCount, 0);
    assert.deepEqual(value.evidence.map((item) => item.filename), ["changes.patch", "manifest.json", "plan.md", "summary.md", "tests.log"]);
    for (const item of value.events) assert.deepEqual(Object.keys(item).sort(), ["id", "type", "createdAt"].sort());
    for (const item of value.evidence) assert.deepEqual(Object.keys(item).sort(), ["id", "category", "filename", "mediaType", "sizeBytes", "sha256", "createdAt"].sort());
    assert.doesNotMatch(JSON.stringify(value), /CANARY|prompt|objectKey|email|environment|binding|cookie|header|origin/i);
  } finally { binding = undefined; database.close(); }
});
