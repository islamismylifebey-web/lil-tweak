import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  cancelEngineeringJob,
  createEngineeringJob,
  decideEngineeringJob,
  exportEngineeringPatch,
  jobCanCancel,
  jobIsPolling,
  jobNeedsApproval,
  jobStateLabel,
  uploadSourcesForJob,
} from "../app/engineering-client.ts";

const approvalTokenFixture = JSON.parse(readFileSync(
  new URL("./fixtures/approval-token-hash-v1.json", import.meta.url),
  "utf8",
));

test("creates an immutable Git-source request", async () => {
  const calls = [];
  await createEngineeringJob({
    requestId: "11111111-1111-4111-8111-111111111111",
    mode: "debug",
    prompt: "Fix it",
    projectId: null,
    files: [],
    gitSource: {
      repositoryUrl: "https://github.com/example/project.git",
      commit: "a".repeat(40),
    },
  }, async (url, init) => {
    calls.push({ url, init });
    return { ok: true, async json() { return { job: { id: "job:1" } }; } };
  });
  assert.deepEqual(JSON.parse(calls[0].init.body).gitSource, {
    repositoryUrl: "https://github.com/example/project.git",
    commit: "a".repeat(40),
  });
  assert.equal(JSON.parse(calls[0].init.body).requestId, "11111111-1111-4111-8111-111111111111");
  assert.equal(calls[0].init.headers["Idempotency-Key"], "11111111-1111-4111-8111-111111111111");
});

test("echoes the exact immutable approval proposal to the core decision route", async () => {
  const calls = [];
  const approvalProposal = {
    action: "export_patch",
    target: "owner_download",
    policyVersion: "v1",
    resourceProfile: { cpus: 1, memory: "1g" },
    sourceDigest: "b".repeat(64),
    proposalDigest: "c".repeat(64),
    expiresAt: "2026-08-13T12:05:00.000Z",
  };
  const values = new Map();
  const storage = {
    getItem(key) { return values.get(key) ?? null; },
    setItem(key, value) { values.set(key, value); },
  };
  await decideEngineeringJob({
    id: "job:11111111111111111111111111111111",
    revision: 9,
    approvalProposal,
  }, "approve", "", async (url, init) => {
    calls.push({ url, init });
    return { ok: true, async json() { return { job: { state: "applying" } }; } };
  }, {
    storage,
    randomBytes: () => Uint8Array.from(Buffer.from(approvalTokenFixture.randomBytesHex, "hex")),
    randomUUID: () => "11111111-2222-4333-8444-555555555555",
  });
  const approvalBody = JSON.parse(calls[0].init.body);
  assert.deepEqual(approvalBody, {
    decision: "approve",
    reason: "",
    revision: 9,
    approvalProposal,
    approvalTokenHash: approvalTokenFixture.approvalTokenHash,
  });
  assert.doesNotMatch(calls[0].init.body, new RegExp(approvalTokenFixture.approvalToken));

  const job = {
    id: "job:11111111111111111111111111111111",
    revision: 10,
    state: "applying",
    proposalDigest: approvalProposal.proposalDigest,
    approvalProposal,
  };
  const evidence = {
    id: `evidence:${"2".repeat(32)}`,
    category: "patch",
    filename: "changes.patch",
  };
  const exportCalls = [];
  const first = await exportEngineeringPatch(job, evidence, async (url, init) => {
    exportCalls.push({ url, init });
    return { ok: true, async blob() { return new Blob(["diff"]); } };
  }, { storage });
  const second = await exportEngineeringPatch(job, evidence, async (url, init) => {
    exportCalls.push({ url, init });
    return { ok: true, async blob() { return new Blob(["diff"]); } };
  }, { storage });
  assert.equal(await first.text(), "diff");
  assert.equal(await second.text(), "diff");
  assert.deepEqual(exportCalls.map(({ url }) => url), [
    `/api/engineering/evidence/${encodeURIComponent(evidence.id)}`,
    `/api/engineering/evidence/${encodeURIComponent(evidence.id)}`,
  ]);
  const exportBodies = exportCalls.map(({ init }) => JSON.parse(init.body));
  assert.deepEqual(exportBodies[0], exportBodies[1], "the same browser attempt must replay stably");
  assert.equal(exportBodies[0].attemptId, "11111111-2222-4333-8444-555555555555");
  assert.equal(exportBodies[0].approvalToken, approvalTokenFixture.approvalToken);
  assert.doesNotMatch(exportCalls[0].url, new RegExp(`${approvalTokenFixture.approvalToken}|approvalToken|attemptId`));
});

test("rejects a stored export attempt whose token hash no longer matches its canonical token", async () => {
  const approvalProposal = {
    action: "export_patch",
    target: "owner_download",
    policyVersion: "v1",
    resourceProfile: { cpus: 1 },
    sourceDigest: "b".repeat(64),
    proposalDigest: "c".repeat(64),
    expiresAt: "2026-08-13T12:05:00.000Z",
  };
  const values = new Map([[
    `lil-tweak:patch-export:v1:job:11111111111111111111111111111111:${approvalProposal.proposalDigest}`,
    JSON.stringify({
      version: 1,
      jobId: "job:11111111111111111111111111111111",
      proposalDigest: approvalProposal.proposalDigest,
      expiresAt: approvalProposal.expiresAt,
      approvalToken: approvalTokenFixture.approvalToken,
      approvalTokenHash: "0".repeat(64),
      attemptId: "11111111-2222-4333-8444-555555555555",
    }),
  ]]);
  const storage = {
    getItem(key) { return values.get(key) ?? null; },
    setItem(key, value) { values.set(key, value); },
  };

  await assert.rejects(
    exportEngineeringPatch(
      {
        id: "job:11111111111111111111111111111111",
        proposalDigest: approvalProposal.proposalDigest,
        approvalProposal,
      },
      { id: `evidence:${"2".repeat(32)}`, category: "patch", filename: "changes.patch" },
      async () => { throw new Error("must not fetch"); },
      { storage },
    ),
    /Approve this exact proposal/,
  );
});

test("maps execution states to truthful owner-facing labels", () => {
  assert.equal(jobStateLabel("draft"), "Draft");
  assert.equal(jobStateLabel("ingesting"), "Inspecting source");
  assert.equal(jobStateLabel("planning"), "Planning changes");
  assert.equal(jobStateLabel("awaiting_approval"), "Your approval is required");
  assert.equal(jobStateLabel("timed_out"), "Timed out");
  assert.equal(jobNeedsApproval("awaiting_approval"), true);
  assert.equal(jobNeedsApproval("executing"), false);
});

test("polls active jobs but not review pauses or terminal jobs", () => {
  for (const state of ["queued", "ingesting", "planning", "executing", "testing", "collecting", "applying"]) {
    assert.equal(jobIsPolling(state), true, state);
  }
  for (const state of ["draft", "uploading", "awaiting_approval", "completed", "rejected", "cancelled", "failed", "timed_out"]) {
    assert.equal(jobIsPolling(state), false, state);
  }
  for (const state of ["uploading", "queued", "executing", "awaiting_approval", "applying"]) {
    assert.equal(jobCanCancel(state), true, state);
  }
  for (const state of ["completed", "rejected", "cancelled", "failed", "timed_out"]) {
    assert.equal(jobCanCancel(state), false, state);
  }
});

test("cancels the exact visible job revision", async () => {
  const calls = [];
  const job = {
    id: "job:11111111111111111111111111111111",
    revision: 9,
  };
  const cancelled = { ...job, state: "cancelled" };
  const result = await cancelEngineeringJob(job, async (url, init) => {
    calls.push({ url, init });
    return {
      ok: true,
      async json() { return { job: cancelled }; },
    };
  });
  assert.equal(result.state, "cancelled");
  assert.equal(calls[0].url, `/api/engineering/jobs/${encodeURIComponent(job.id)}/cancel`);
  assert.deepEqual(JSON.parse(calls[0].init.body), { revision: 9 });
});

test("uploads each browser file to its server-issued source ID in order", async () => {
  const calls = [];
  const files = [
    new File(["alpha"], "a.txt", { type: "text/plain" }),
    new File(["PK"], "source.zip", { type: "application/zip" }),
  ];
  const sources = [
    { id: "src:00000000000000000000000000000002", filename: "source.zip", sizeBytes: 2 },
    { id: "src:00000000000000000000000000000001", filename: "a.txt", sizeBytes: 5 },
  ];
  await uploadSourcesForJob(
    "job:11111111111111111111111111111111",
    files,
    sources,
    async (url, init) => {
      calls.push({ url, init });
      return { ok: true };
    },
  );
  assert.deepEqual(calls.map((call) => call.url), [
    "/api/engineering/jobs/job%3A11111111111111111111111111111111/sources?sourceId=src%3A00000000000000000000000000000001",
    "/api/engineering/jobs/job%3A11111111111111111111111111111111/sources?sourceId=src%3A00000000000000000000000000000002",
  ]);
  assert.equal(calls[0].init.method, "PUT");
  assert.equal(calls[0].init.body, files[0]);
  assert.equal(calls[0].init.headers["Content-Type"], "text/plain");
  assert.equal(calls[1].init.headers["X-Source-Filename"], "source.zip");
});
