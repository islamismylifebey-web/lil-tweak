import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  ensureEngineeringRequestObject,
  recoverEngineeringCreateRequest,
  requireCreateRequestId,
  validateEngineeringDispatchRequest,
} from "../lib/create-request.ts";
import { engineeringCreateRequestDigest } from "../lib/engineering-store.ts";
import { sha256Hex } from "../lib/core-signing.ts";

class MemoryBucket {
  objects = new Map();

  async get(key) {
    const object = this.objects.get(key);
    if (!object) return null;
    return {
      size: new TextEncoder().encode(object.value).byteLength,
      customMetadata: object.options.customMetadata,
      checksums: { sha256: object.options.sha256 },
      async text() { return object.value; },
    };
  }

  async put(key, value, options) {
    if (this.objects.has(key)) return null;
    this.objects.set(key, { value, options });
    return { key };
  }
}

test("requires one exact canonical browser creation idempotency key", () => {
  const key = "11111111-1111-4111-8111-111111111111";
  assert.equal(requireCreateRequestId(key, key), key);
  assert.throws(() => requireCreateRequestId(null, key), /idempotency/i);
  assert.throws(() => requireCreateRequestId(key, crypto.randomUUID()), /idempotency/i);
  const lowercaseOnly = "aaaaaaaa-1111-4111-8111-111111111111";
  assert.throws(() => requireCreateRequestId(lowercaseOnly.toUpperCase(), lowercaseOnly.toUpperCase()), /idempotency/i);
});

test("revalidates the complete immutable request before dispatch", async () => {
  const bucket = new MemoryBucket();
  const job = {
    id: `job:${"1".repeat(32)}`,
    mode: "build",
    projectId: null,
    gitSource: null,
    sources: [{
      id: `src:${"2".repeat(32)}`,
      jobId: `job:${"1".repeat(32)}`,
      filename: "source.zip",
      mediaType: "application/zip",
      sizeBytes: 10,
      uploadedAt: "2026-08-13T12:00:00.000Z",
    }],
  };
  const body = JSON.stringify({
    id: job.id,
    mode: job.mode,
    prompt: "Build the exact change.",
    projectId: null,
    projectContext: null,
    gitSource: null,
  });
  const requestDigest = await engineeringCreateRequestDigest({
    mode: job.mode,
    prompt: "Build the exact change.",
    projectId: null,
    projectContext: null,
    gitSource: null,
    sources: job.sources,
  });
  const input = {
    bucket,
    key: "engineering/owner/jobs/job/request.json",
    body,
    requestDigest,
  };
  await ensureEngineeringRequestObject(input);
  const object = await bucket.get(input.key);
  assert.deepEqual(await validateEngineeringDispatchRequest({
    object,
    expectedRequestDigest: requestDigest,
    expectedPromptDigest: await sha256Hex("Build the exact change."),
    job,
  }), {
    prompt: "Build the exact change.",
    projectContext: null,
    gitSource: null,
  });
  bucket.objects.get(input.key).value = body.replace("exact", "wrong");
  await assert.rejects(
    validateEngineeringDispatchRequest({
      object: await bucket.get(input.key),
      expectedRequestDigest: requestDigest,
      expectedPromptDigest: await sha256Hex("Build the exact change."),
      job,
    }),
    /integrity/i,
  );
});

test("reuses only the exact immutable request object after a lost response", async () => {
  const bucket = new MemoryBucket();
  const input = {
    bucket,
    key: "engineering/owner/jobs/job/request.json",
    body: JSON.stringify({ mode: "build", prompt: "Add a test." }),
    requestDigest: "a".repeat(64),
  };
  assert.equal(await ensureEngineeringRequestObject(input), true);
  assert.equal(await ensureEngineeringRequestObject(input), false);
  await assert.rejects(
    ensureEngineeringRequestObject({ ...input, body: JSON.stringify({ mode: "build", prompt: "Different." }) }),
    /different request/i,
  );
});

test("freezes the complete request object before committing its D1 job", async () => {
  const route = await readFile(new URL("../app/api/engineering/jobs/route.ts", import.meta.url), "utf8");
  assert.ok(
    route.indexOf("await ensureEngineeringRequestObject") <
      route.indexOf("await jobStore.createJobWithIdempotency"),
    "R2 request freeze must happen before the D1 job becomes visible",
  );
});

test("recovers D1 creation from the already-frozen project snapshot", async () => {
  const bucket = new MemoryBucket();
  const projectId = `project:${"3".repeat(32)}`;
  const frozenContext = {
    schemaVersion: "project-context-v1",
    projectId,
    name: "Frozen name",
    description: "Original snapshot",
    status: "active",
    requirements: [],
    milestones: [],
    board: [],
    notes: [],
  };
  const request = {
    mode: "chat",
    prompt: "Review the project.",
    projectId,
    gitSource: null,
    sources: [],
  };
  const jobId = `job:${"4".repeat(32)}`;
  const body = JSON.stringify({
    id: jobId,
    mode: request.mode,
    prompt: request.prompt,
    projectId,
    projectContext: frozenContext,
    gitSource: null,
  });
  const requestDigest = await engineeringCreateRequestDigest({ ...request, projectContext: frozenContext });
  await ensureEngineeringRequestObject({
    bucket,
    key: "engineering/owner/jobs/frozen/request.json",
    body,
    requestDigest,
  });
  const recovered = await recoverEngineeringCreateRequest({
    object: await bucket.get("engineering/owner/jobs/frozen/request.json"),
    jobId,
    ownerInput: request,
  });
  assert.equal(recovered.requestDigest, requestDigest);
  assert.deepEqual(recovered.projectContext, frozenContext);
});
