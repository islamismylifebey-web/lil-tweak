import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { collectTueiqActivationEvidence, ACTIVATION_REPOSITORY, ACTIVATION_COMMIT, ACTIVATION_INSTRUCTION } from "../lib/engineering-activation-collector.ts";

test("loaded Site client exposes the collector in-page without starting a request", async () => {
  globalThis.window = {};
  try {
    await import("../app/engineering-client.ts?activation-install-fixture");
    assert.equal(globalThis.window.collectTueiqActivationEvidence, collectTueiqActivationEvidence);
  } finally { delete globalThis.window; }
});

test("collector rejects caller overrides and nonfresh UUID before fetch", async () => {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; throw new Error("must not fetch"); };
  Object.defineProperty(globalThis, "document", { configurable: true, value: Object.defineProperty({}, "cookie", { get() { throw new Error("cookie access"); } }) });
  try {
    for (const value of [{}, { requestId: "bad" }, { requestId: crypto.randomUUID(), repositoryUrl: "override" }]) {
      await assert.rejects(collectTueiqActivationEvidence(value));
    }
    assert.equal(calls, 0);
  } finally { globalThis.fetch = original; delete globalThis.document; }
});

test("authenticated in-page collector preserves only nine bodies and exact non-secret metadata", async () => {
  const original = globalThis.fetch;
  const requestId = crypto.randomUUID();
  const time = new Date().toISOString();
  const jobId = "job:" + createHash("sha256").update(`engineering-job-v1\0a0885bc0b2c079e996629061a723c74d\0${requestId}`).digest("hex").slice(0, 32);
  const bodies = ["plan", "", "tests", "{}", "summary"];
  const filenames = ["plan.md", "changes.patch", "tests.log", "manifest.json", "summary.md"];
  const descriptors = filenames.map((filename, index) => ({ id: "evidence:" + String(index + 1).repeat(32), jobId, filename, category: ["plan", "patch", "tests", "manifest", "summary"][index], mediaType: ["text/markdown", "text/x-diff", "text/plain", "application/json", "text/markdown"][index], sizeBytes: bodies[index].length, sha256: createHash("sha256").update(bodies[index]).digest("hex"), createdAt: time }));
  const job = { id: jobId, projectId: null, mode: "architect", promptPreview: ACTIVATION_INSTRUCTION, state: "queued", revision: 0, summary: "", proposalDigest: null, sourceDigest: null, approvalProposal: null, approvalConsumed: false, gitSource: { repositoryUrl: ACTIVATION_REPOSITORY, commit: ACTIVATION_COMMIT }, createdAt: time, updatedAt: time, sources: [], evidence: [], events: [] };
  const status = { status: { generatedAt: time, controlPlane: { storage: "configured", d1: "configured", r2: "configured" }, bridge: { origin: "core_origin", transport: "configured", signing: "configured", access: "configured", missing: [] }, runner: { owner: "tueiq", provider: "digitalocean", dropletId: "597343619", host: "galor-tweak-runner-01", role: "role-tweak-runner", route: "direct_core_to_local_podman", intermediary: "none", imagePolicy: "digest_pinned", connection: "ready", qualification: "not_reported" } } };
  const expectedBodies = [JSON.stringify(status), JSON.stringify({ job }), JSON.stringify({ job: { ...job, revision: 2 } }), JSON.stringify({ job: { ...job, revision: 3, state: "completed", evidence: descriptors } }), ...bodies];
  const calls = [];
  Object.defineProperty(globalThis, "document", { configurable: true, value: Object.defineProperty({}, "cookie", { get() { throw new Error("cookie accessed"); } }) });
  globalThis.fetch = async (path, init) => {
    const index = calls.length;
    calls.push({ path, init });
    assert.equal(init.credentials, "same-origin");
    assert.equal(init.redirect, "error");
    assert.match(path, /^\/api\/engineering\//);
    assert.doesNotMatch(path, /activation-evidence|decision|export/);
    if (index === 1) {
      assert.equal(init.method, "POST");
      assert.equal(init.headers["Idempotency-Key"], requestId);
      assert.deepEqual(JSON.parse(init.body), { requestId, mode: "architect", prompt: ACTIVATION_INSTRUCTION, projectId: null, sources: [], gitSource: { repositoryUrl: ACTIVATION_REPOSITORY, commit: ACTIVATION_COMMIT } });
    }
    if (index === 2) assert.deepEqual(JSON.parse(init.body), { action: "dispatch", revision: 0 });
    const bytes = new TextEncoder().encode(expectedBodies[index]);
    return { status: index === 1 ? 201 : 200, body: new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } }),
      headers: { get(name) {
        assert.ok(["content-type", "content-length", "x-content-sha256"].includes(name), "forbidden response metadata read");
        return name === "content-type" ? (index < 4 ? "application/json" : "text/plain; charset=utf-8") : name === "content-length" ? String(bytes.length) : index < 4 ? null : descriptors[index - 4].sha256;
      }, entries() { throw new Error("response header iteration"); }, [Symbol.iterator]() { throw new Error("response header serialization"); } },
    };
  };
  try {
    const capture = await collectTueiqActivationEvidence({ requestId });
    assert.deepEqual(Object.keys(capture).sort(), ["schema", "requestId", "startedAt", "completedAt", "responses"].sort());
    assert.equal(capture.schema, "tueiq-site-primary-capture-v1");
    assert.equal(calls.length, 9);
    for (const [index, response] of capture.responses.entries()) {
      assert.deepEqual(Object.keys(response).sort(), ["id", "status", "mediaType", "declaredLength", "contentSha256", "bodyBase64"].sort());
      assert.equal(Buffer.from(response.bodyBase64, "base64").toString(), expectedBodies[index]);
    }
    assert.doesNotMatch(JSON.stringify(capture), /cookie|authorization|set-cookie|headers|origin/i);
    await assert.rejects(collectTueiqActivationEvidence({ requestId }));
    assert.equal(calls.length, 9);
  } finally { globalThis.fetch = original; delete globalThis.document; }
});
