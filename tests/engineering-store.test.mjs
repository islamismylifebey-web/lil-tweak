import assert from "node:assert/strict";
import test from "node:test";

import {
  MemoryEngineeringStore,
  engineeringCreateRequestDigest,
  engineeringJobIdForCreate,
} from "../lib/engineering-store.ts";

const owner = "owner:canonical";

test("creation digest is canonical for the exact normalized owner request", async () => {
  const input = {
    mode: "build",
    prompt: "Build it.",
    projectId: null,
    gitSource: null,
    sources: [
      { filename: "z.txt", mediaType: "TEXT/PLAIN", sizeBytes: 2 },
      { filename: "a.txt", mediaType: "text/plain", sizeBytes: 1 },
    ],
  };
  const left = await engineeringCreateRequestDigest(input);
  const right = await engineeringCreateRequestDigest({ ...input, sources: input.sources.slice().reverse() });
  assert.equal(left, right);
  assert.notEqual(left, await engineeringCreateRequestDigest({ ...input, prompt: "Different." }));
  assert.notEqual(left, await engineeringCreateRequestDigest({
    ...input,
    projectContext: {
      schemaVersion: "project-context-v1",
      projectId: "project:0123456789abcdef0123456789abcdef",
      name: "Changed project snapshot",
      description: "",
      status: "active",
      requirements: [],
      milestones: [],
      board: [],
      notes: [],
    },
  }));
  const requestId = "11111111-2222-4333-8444-555555555555";
  assert.equal(
    await engineeringJobIdForCreate("owner-a", requestId),
    await engineeringJobIdForCreate("owner-a", requestId),
  );
  assert.notEqual(
    await engineeringJobIdForCreate("owner-a", requestId),
    await engineeringJobIdForCreate("owner-b", requestId),
  );
});

test("creates an owner-scoped job and source manifest", async () => {
  const store = new MemoryEngineeringStore();
  const detail = await store.createJob(owner, {
    mode: "debug",
    prompt: "Find and fix the failing test.",
    projectId: null,
    gitSource: {
      repositoryUrl: "https://github.com/example/project.git",
      commit: "a".repeat(40),
    },
    sources: [{ filename: "source.zip", mediaType: "application/zip", sizeBytes: 1200 }],
  });

  assert.match(detail.id, /^job:[0-9a-f]{32}$/);
  assert.equal(detail.state, "uploading");
  assert.equal(detail.revision, 0);
  assert.equal(detail.promptPreview, "Find and fix the failing test.");
  assert.equal(detail.sources.length, 1);
  assert.match(detail.sources[0].id, /^src:[0-9a-f]{32}$/);
  assert.equal(detail.gitSource.commit, "a".repeat(40));
  assert.equal(detail.events[0].type, "job_created");
  assert.equal(await store.getJob("owner:other", detail.id), null);
  assert.deepEqual(await store.listJobs("owner:other", 20), []);
});

test("rejects duplicate source filenames before persistence", async () => {
  const store = new MemoryEngineeringStore();
  await assert.rejects(
    store.createJob(owner, {
      mode: "build",
      prompt: "Inspect both inputs.",
      projectId: null,
      sources: [
        { filename: "source.zip", mediaType: "application/zip", sizeBytes: 10 },
        { filename: "source.zip", mediaType: "application/zip", sizeBytes: 20 },
      ],
    }),
    /source filenames must be unique/i,
  );
});

test("marks an exact source uploaded once and queues only after every source", async () => {
  const store = new MemoryEngineeringStore();
  const detail = await store.createJob(owner, {
    mode: "build",
    prompt: "Build it.",
    projectId: "project:0123456789abcdef0123456789abcdef",
    sources: [
      { filename: "a.zip", mediaType: "application/zip", sizeBytes: 10 },
      { filename: "notes.txt", mediaType: "text/plain", sizeBytes: 5 },
    ],
  });
  const digestA = "a".repeat(64);
  const digestB = "b".repeat(64);
  const first = await store.markSourceUploaded(owner, detail.id, detail.sources[0].id, "etag-a", digestA);
  assert.equal(first.state, "uploading");
  assert.equal(first.revision, 1);
  assert.equal(first.sources[0].sha256, digestA);
  const retried = await store.markSourceUploaded(owner, detail.id, detail.sources[0].id, "etag-a", digestA);
  assert.equal(retried.revision, first.revision);
  await assert.rejects(
    store.markSourceUploaded(owner, detail.id, detail.sources[0].id, "etag-a", digestB),
    /does not match/i,
  );
  await assert.rejects(
    store.markSourceUploaded(owner, detail.id, detail.sources[0].id, "etag-again", digestA),
    /does not match/i,
  );
  const second = await store.markSourceUploaded(owner, detail.id, detail.sources[1].id, "etag-b", digestB);
  assert.equal(second.state, "queued");
  assert.equal(second.revision, 2);
  assert.equal(second.sources[1].sha256, digestB);
});

test("rejects stale or illegal transitions and appends real events", async () => {
  const store = new MemoryEngineeringStore();
  const detail = await store.createJob(owner, {
    mode: "test",
    prompt: "Run and improve tests.",
    projectId: null,
    sources: [],
  });
  assert.equal(detail.state, "queued");
  const ingesting = await store.transition(owner, detail.id, "ingesting", 0, "source_intake_started");
  assert.equal(ingesting.revision, 1);
  assert.equal(ingesting.events.at(-1).type, "source_intake_started");
  await assert.rejects(
    store.transition(owner, detail.id, "planning", 0, "planning_started"),
    /stale job revision/i,
  );
  await assert.rejects(
    store.transition(owner, detail.id, "completed", 1, "completed"),
    /illegal job transition/i,
  );
});
