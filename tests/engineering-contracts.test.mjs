import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  ENGINEER_MODES,
  JOB_STATES,
  approvalProposalIsExpired,
  coreSnapshotTransitionAllowed,
  coreSnapshotAlreadyMirrored,
  decisionAuthorizesCoreState,
  engineeringObjectKey,
  parseApprovalProposal,
  parseDecision,
  parseJobCreate,
  safeSourceFilename,
  transitionAllowed,
} from "../lib/engineering.ts";
import {
  canonicalCoreRequest,
  sha256Hex,
  signCoreRequest,
} from "../lib/core-signing.ts";
import { readBoundedJson, requireExactLength } from "../lib/bounded-request.ts";

test("accepts exactly the six Lil Tweak engineering modes", () => {
  assert.deepEqual(ENGINEER_MODES, [
    "build",
    "debug",
    "refactor",
    "test",
    "architect",
    "chat",
  ]);
  assert.equal(parseJobCreate({ mode: "build", prompt: "Fix the failing test." }).mode, "build");
  assert.throws(
    () => parseJobCreate({ mode: "deploy", prompt: "ship it" }),
    /engineering mode/i,
  );
});

test("validates the exact immutable approval proposal shown to the owner", () => {
  const proposal = {
    action: "export_patch",
    target: "owner_download",
    policyVersion: "v1",
    resourceProfile: { cpus: 1, memory: "1g", pids: 256, wallSeconds: 1200 },
    sourceDigest: "a".repeat(64),
    proposalDigest: "b".repeat(64),
    expiresAt: "2026-08-13T16:05:00Z",
  };
  assert.deepEqual(parseApprovalProposal(proposal), proposal);
  assert.throws(() => parseApprovalProposal({ ...proposal, action: "deploy" }), /approval proposal/i);
  assert.throws(
    () => parseApprovalProposal({ ...proposal, resourceProfile: { nested: { unsafe: true } } }),
    /approval proposal/i,
  );
  assert.equal(approvalProposalIsExpired(proposal, Date.parse("2026-08-13T16:04:00Z")), false);
  assert.equal(approvalProposalIsExpired(proposal, Date.parse("2026-08-13T16:04:31Z")), true);
});

test("bounds job and decision input before dispatch", () => {
  assert.throws(() => parseJobCreate({ mode: "debug", prompt: "" }), /prompt is required/i);
  assert.throws(
    () => parseJobCreate({ mode: "debug", prompt: "x".repeat(16_001) }),
    /16,000 characters/i,
  );
  assert.throws(
    () => parseJobCreate({ mode: "debug", prompt: "x", projectId: "../../other" }),
    /Project ID/i,
  );
  assert.deepEqual(parseDecision({ decision: "approve", revision: 3 }), {
    decision: "approve",
    reason: "",
    revision: 3,
  });
  assert.throws(
    () => parseDecision({ decision: "reject", revision: 3, reason: "" }),
    /rejection reason/i,
  );
});

test("enforces portable source filenames and opaque object prefixes", () => {
  assert.equal(safeSourceFilename("source.zip"), "source.zip");
  for (const filename of ["../source.zip", "a/b.zip", "a\\b.zip", ".", "bad\0.zip"]) {
    assert.throws(() => safeSourceFilename(filename), /portable filename/i);
  }
  assert.equal(
    engineeringObjectKey("ownerhash", "job:0123456789abcdef0123456789abcdef", "source", "src:0123456789abcdef0123456789abcdef"),
    "engineering/ownerhash/jobs/job:0123456789abcdef0123456789abcdef/sources/src:0123456789abcdef0123456789abcdef",
  );
  assert.throws(
    () => engineeringObjectKey("../../owner", "job:bad", "source", "src:bad"),
    /invalid engineering identifier/i,
  );
});

test("allows only explicit engineering state transitions", () => {
  assert.ok(JOB_STATES.includes("awaiting_approval"));
  assert.equal(transitionAllowed("draft", "uploading"), true);
  assert.equal(transitionAllowed("uploading", "queued"), true);
  assert.equal(transitionAllowed("collecting", "awaiting_approval"), true);
  assert.equal(transitionAllowed("collecting", "completed"), true);
  assert.equal(transitionAllowed("awaiting_approval", "applying"), true);
  assert.equal(transitionAllowed("awaiting_approval", "rejected"), true);
  assert.equal(transitionAllowed("applying", "cancelled"), true);
  assert.equal(transitionAllowed("completed", "running"), false);
  assert.equal(transitionAllowed("draft", "completed"), false);
});

test("mirrors fast core progress without bypassing the approval gate", () => {
  assert.equal(coreSnapshotTransitionAllowed("queued", "testing"), true);
  assert.equal(coreSnapshotTransitionAllowed("queued", "completed"), true);
  assert.equal(coreSnapshotTransitionAllowed("queued", "applying"), false);
  assert.equal(coreSnapshotTransitionAllowed("awaiting_approval", "applying"), false);
  assert.equal(coreSnapshotTransitionAllowed("awaiting_approval", "applying", true), true);
  assert.equal(coreSnapshotTransitionAllowed("awaiting_approval", "rejected", true), true);
  assert.equal(coreSnapshotTransitionAllowed("awaiting_approval", "cancelled"), true);
  assert.equal(coreSnapshotTransitionAllowed("applying", "cancelled"), true);
  assert.equal(coreSnapshotTransitionAllowed("awaiting_approval", "failed"), true);
  assert.equal(coreSnapshotTransitionAllowed("completed", "failed"), false);
});

test("recovers only the exact durable owner decision after a lost core response", () => {
  const digest = "a".repeat(64);
  assert.equal(
    decisionAuthorizesCoreState(
      { decision: "approve", proposalDigest: digest },
      digest,
      "completed",
    ),
    true,
  );
  assert.equal(
    decisionAuthorizesCoreState(
      { decision: "reject", proposalDigest: digest },
      digest,
      "rejected",
    ),
    true,
  );
  assert.equal(
    decisionAuthorizesCoreState(
      { decision: "reject", proposalDigest: digest },
      digest,
      "completed",
    ),
    false,
  );
  assert.equal(
    decisionAuthorizesCoreState(
      { decision: "approve", proposalDigest: "b".repeat(64) },
      digest,
      "completed",
    ),
    false,
  );
});

test("does not churn D1 revisions for an identical core snapshot", () => {
  const evidence = {
    id: `evidence:${"b".repeat(32)}`,
    jobId: `job:${"1".repeat(32)}`,
    category: "patch",
    filename: "changes.patch",
    mediaType: "text/x-diff",
    sizeBytes: 0,
    sha256: "c".repeat(64),
    createdAt: "2026-08-13T12:00:00.000Z",
  };
  const job = {
    state: "completed",
    summary: "Done.",
    proposalDigest: "a".repeat(64),
    evidence: [evidence],
  };
  const snapshot = {
    state: "completed",
    summary: "Done.",
    proposalDigest: "a".repeat(64),
    coreRevision: 8,
    evidence: [{ ...evidence, corePath: "/v1/jobs/remote/evidence/changes.patch" }],
  };
  assert.equal(coreSnapshotAlreadyMirrored(job, 8, snapshot), true);
  assert.equal(coreSnapshotAlreadyMirrored(job, 7, snapshot), false);
  assert.equal(coreSnapshotAlreadyMirrored(job, 8, { ...snapshot, summary: "Changed." }), false);
  assert.equal(
    coreSnapshotAlreadyMirrored(job, 8, {
      ...snapshot,
      evidence: [{ ...snapshot.evidence[0], sha256: "d".repeat(64) }],
    }),
    false,
  );
});

test("matches the canonical request signing vector", async () => {
  const body = new TextEncoder().encode('{"mode":"build","prompt":"fix it"}');
  const bodySha256 = await sha256Hex(body);
  assert.equal(bodySha256, "797ce5f21ca436c761be4a97b0f25b4c8c59336a33a4cee574510e1cb46182d7");
  const request = {
    keyId: "primary",
    method: "POST",
    pathAndQuery: "/v1/jobs?owner=owner%3A1",
    timestamp: "1723586400",
    nonce: "00112233445566778899aabbccddeeff",
    bodySha256,
    requestId: "11111111-2222-4333-8444-555555555555",
    idempotencyKey: "job:test:create",
    ownerKey: "abcdef0123456789abcdef0123456789",
  };
  assert.equal(
    canonicalCoreRequest(request),
    [
      "v2",
      "primary",
      "POST",
      "/v1/jobs?owner=owner%3A1",
      "1723586400",
      "00112233445566778899aabbccddeeff",
      bodySha256,
      "11111111-2222-4333-8444-555555555555",
      "job:test:create",
      "abcdef0123456789abcdef0123456789",
    ].join("\n"),
  );
  assert.equal(
    await signCoreRequest("test-signing-key", request),
    "a6ed289ad346c2a5d2d0291b8b4b83ab1d877deb7f92f773c9908a3bc650e7cc",
  );
});

test("reads JSON only when the declared and actual byte lengths match", async () => {
  const valid = new Request("https://lil-tweak.example/api/engineering/jobs", {
    method: "POST",
    headers: { "content-type": "application/json", "content-length": "17" },
    body: '{"hello":"world"}',
  });
  assert.deepEqual(await readBoundedJson(valid, 32), { hello: "world" });

  await assert.rejects(
    readBoundedJson(
      new Request("https://lil-tweak.example/api/engineering/jobs", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      }),
      32,
    ),
    /content-length is required/i,
  );
  await assert.rejects(
    readBoundedJson(
      new Request("https://lil-tweak.example/api/engineering/jobs", {
        method: "POST",
        headers: { "content-type": "application/json", "content-length": "2" },
        body: "{}x",
      }),
      32,
    ),
    /body length does not match/i,
  );
  await assert.rejects(
    readBoundedJson(
      new Request("https://lil-tweak.example/api/engineering/jobs", {
        method: "POST",
        headers: { "content-type": "text/plain", "content-length": "2" },
        body: "{}",
      }),
      32,
    ),
    /application\/json/i,
  );
});

test("requires a finite exact upload length within its cap", () => {
  assert.equal(requireExactLength("25000000", 25_000_000), 25_000_000);
  for (const value of [null, "", "-1", "1.5", "25000001", "NaN"]) {
    assert.throws(() => requireExactLength(value, 25_000_000), /content-length/i);
  }
});

test("source upload streams through the actual-byte bound before R2", async () => {
  const route = await readFile(
    new URL("../app/api/engineering/jobs/[id]/sources/route.ts", import.meta.url),
    "utf8",
  );
  assert.match(route, /readBoundedBytes\(request, MAX_SOURCE_BYTES\)/);
  assert.doesNotMatch(route, /request\.arrayBuffer\(\)/);
});
