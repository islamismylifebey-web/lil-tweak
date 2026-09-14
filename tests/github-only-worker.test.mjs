import assert from "node:assert/strict";
import { register } from "node:module";
import test from "node:test";

const bindingModule = `data:text/javascript,${encodeURIComponent("export const env = {};")}`;
register(`data:text/javascript,${encodeURIComponent(`
  export async function resolve(specifier, context, nextResolve) {
    if (specifier === "cloudflare:workers") return { url: ${JSON.stringify(bindingModule)}, shortCircuit: true };
    return nextResolve(specifier, context);
  }
`)}`, import.meta.url);
const { env } = await import(bindingModule);
const { default: worker } = await import("../dist/server/index.js");
const origin = "https://lil-tweak.owner.chatgpt.site";
const jobId = `job:${"a".repeat(32)}`;
const sourceId = `src:${"b".repeat(32)}`;
const headers = {
  "oai-authenticated-user-id": "owner-fixture",
  "oai-authenticated-user-email": "islamismylifebey@gmail.com",
  Origin: origin, "sec-fetch-site": "same-origin",
};

function configure(database) {
  const calls = { storage: 0, mutations: 0, sql: [] };
  const unexpected = () => { calls.storage++; throw new Error("Unexpected storage access"); };
  for (const key of Object.keys(env)) delete env[key];
  Object.assign(env, {
    ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) },
    LIL_TWEAK_ENVIRONMENT: "production", LIL_TWEAK_INGRESS_MODE: "sites_native", PUBLIC_ORIGIN: origin,
    CORE_ORIGIN: "https://core.example.invalid", CORE_ACCESS_CLIENT_ID: "fixture-id",
    CORE_ACCESS_CLIENT_SECRET: "fixture-secret", CORE_SIGNING_KEY_ID: "fixture",
    CORE_SIGNING_SECRET: "x".repeat(64),
    DB: database ? database(calls) : { prepare: unexpected, batch: unexpected },
    FILES: { get: unexpected, head: unexpected, put: unexpected, delete: unexpected },
  });
  return calls;
}

function jsonRequest(path, body, extra = {}) {
  const encoded = JSON.stringify(body);
  return new Request(origin + path, { method: "POST", headers: {
    ...headers, "Content-Type": "application/json", "Content-Length": String(Buffer.byteLength(encoded)), ...extra,
  }, body: encoded });
}
const context = { waitUntil() {}, passThroughOnException() {} };

test("built Worker rejects unsupported engineering creation before all storage", async () => {
  const uploads = [{ filename: "legacy.txt", mediaType: "text/plain", sizeBytes: 1 }];
  for (const { sources, gitSource } of [
    { sources: [], gitSource: null }, { sources: uploads, gitSource: null },
    { sources: uploads, gitSource: { repositoryUrl: "https://github.com/example/project", commit: "a".repeat(40) } },
  ]) {
    const calls = configure();
    const requestId = "01234567-89ab-4def-8abc-0123456789ab";
    const response = await worker.fetch(jsonRequest("/api/engineering/jobs", {
      mode: "build", prompt: "Build the project", projectId: null, sources, gitSource, requestId,
    }, { "idempotency-key": requestId }), env, context);
    assert.equal(response.status, 400);
    assert.match((await response.json()).error, /Git source.*required/i);
    assert.equal(calls.storage, 0);
  }
});

test("built Worker refuses engineering uploads without awaiting a stalled body or accessing storage", { timeout: 5_000 }, async () => {
  const calls = configure();
  // Vinext/Node may prefetch while wrapping a Request. Never supply a byte:
  // a route which waits for the upload body will time out instead of returning 409.
  const body = new ReadableStream({ pull() { return new Promise(() => {}); } }, { highWaterMark: 0 });
  const response = await worker.fetch(new Request(`${origin}/api/engineering/jobs/${encodeURIComponent(jobId)}/sources?sourceId=${encodeURIComponent(sourceId)}`, {
    method: "PUT", headers: { ...headers, "Content-Type": "text/plain", "Content-Length": "1" }, body, duplex: "half",
  }), env, context);
  assert.equal(response.status, 409);
  assert.match((await response.json()).error, /uploaded-project execution is unavailable/i);
  assert.equal(calls.storage, 0);
});

test("built Worker blocks legacy dispatch before recovery, mutations, R2 or Core", async (t) => {
  const previousFetch = globalThis.fetch;
  let fetches = 0;
  globalThis.fetch = async () => { fetches++; throw new Error("Core must not be contacted"); };
  t.after(() => { globalThis.fetch = previousFetch; });
  for (const { uploaded, legacyGit } of [
    { uploaded: false, legacyGit: false }, { uploaded: true, legacyGit: false },
    { uploaded: false, legacyGit: true },
  ]) {
    const calls = configure((counts) => ({
      batch() { counts.mutations++; throw new Error("Unexpected mutation"); },
      prepare(sql) {
        counts.sql.push(sql);
        return {
          bind() { return this; },
          run() { counts.mutations++; throw new Error("Unexpected mutation"); },
          async first() {
            assert.match(sql, /^SELECT id, project_id/);
            return { id: jobId, project_id: null,
              git_repository_url: legacyGit ? "https://gitlab.example/owner/repo" : null,
              git_commit: legacyGit ? "a".repeat(40) : null,
              mode: "build", prompt_preview: "Legacy job", state: "queued", revision: 7, summary: "Queued",
              proposal_digest: null, source_digest: null, approval_proposal_json: null, approval_consumed: 0,
              remote_job_id: "legacy-remote", core_revision: 0, request_r2_key: "legacy/request.json",
              source_r2_prefix: "legacy/sources", evidence_r2_prefix: "legacy/evidence",
              created_at: "2026-09-13T00:00:00Z", updated_at: "2026-09-13T00:00:00Z" };
          },
          async all() { return { results: uploaded && sql.includes("FROM engineering_sources") ? [{
            id: sourceId, job_id: jobId, filename: "legacy.txt", media_type: "text/plain", size_bytes: 1,
            sha256: "c".repeat(64), uploaded_at: "2026-09-13T00:00:00Z", r2_etag: "legacy-etag", revision_applied: 1,
          }] : [] }; },
        };
      },
    }));
    const response = await worker.fetch(jsonRequest(`/api/engineering/jobs/${encodeURIComponent(jobId)}`, {
      action: "dispatch", revision: 7,
    }), env, context);
    assert.equal(response.status, 409);
    assert.match((await response.json()).error, /Git source.*required/i);
    assert.equal(calls.sql.length, 4);
    assert.ok(calls.sql.every((sql) => !/^SELECT remote_job_id FROM/.test(sql)));
    assert.equal(calls.mutations, 0);
    assert.equal(calls.storage, 0);
    assert.equal(fetches, 0);
    if (legacyGit) {
      const readResponse = await worker.fetch(new Request(`${origin}/api/engineering/jobs/${encodeURIComponent(jobId)}`, { headers }), env, context);
      assert.equal(readResponse.status, 200);
      const detail = (await readResponse.json()).job;
      assert.equal(detail.id, jobId);
      assert.equal(detail.gitSource, null);
      assert.equal(calls.mutations, 0);
      assert.equal(calls.storage, 0);
      assert.equal(fetches, 0);
    }
  }
});
