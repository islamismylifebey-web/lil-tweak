import assert from "node:assert/strict";
import test from "node:test";

import { parseCoreSnapshot, parseCoreSnapshotForJob } from "../lib/core-protocol.ts";

const validSnapshot = {
  id: "01JEXAMPLEJOB",
  state: "awaiting_approval",
  summary: "Review the exact patch and test evidence.",
  coreRevision: 7,
  proposalDigest: "a".repeat(64),
  sourceDigest: "d".repeat(64),
  approvalProposal: {
    action: "export_patch",
    target: "owner_download",
    policyVersion: "v1",
    resourceProfile: { cpus: 1, memory: "1g", network: "none" },
    sourceDigest: "d".repeat(64),
    proposalDigest: "a".repeat(64),
    expiresAt: "2026-08-13T12:05:00Z",
  },
  evidence: [
    {
      id: `evidence:${"b".repeat(32)}`,
      category: "patch",
      filename: "changes.patch",
      mediaType: "text/x-diff",
      sizeBytes: 0,
      sha256: "c".repeat(64),
      createdAt: "2026-08-13T12:00:00Z",
      corePath: "/v1/jobs/01JEXAMPLEJOB/evidence/changes.patch",
    },
  ],
};

test("parses an authoritative core revision and bounded evidence descriptor", () => {
  const parsed = parseCoreSnapshot(validSnapshot);
  assert.equal(parsed.remoteJobId, "01JEXAMPLEJOB");
  assert.equal(parsed.snapshot.coreRevision, 7);
  assert.equal(parsed.snapshot.evidence?.[0].corePath, validSnapshot.evidence[0].corePath);
  assert.deepEqual(parsed.snapshot.approvalProposal, validSnapshot.approvalProposal);
});

test("rejects malformed revisions, digests, paths, and duplicate evidence", () => {
  for (const invalid of [
    { ...validSnapshot, coreRevision: -1 },
    { ...validSnapshot, proposalDigest: "not-a-digest" },
    { ...validSnapshot, approvalProposal: { ...validSnapshot.approvalProposal, action: "push" } },
    { ...validSnapshot, approvalProposal: { ...validSnapshot.approvalProposal, sourceDigest: "e".repeat(64) } },
    { ...validSnapshot, approvalProposal: { ...validSnapshot.approvalProposal, proposalDigest: "e".repeat(64) } },
    { ...validSnapshot, approvalProposal: { ...validSnapshot.approvalProposal, resourceProfile: { nested: { too: { deeply: { nested: { value: true } } } } } } },
    { ...validSnapshot, evidence: [{ ...validSnapshot.evidence[0], corePath: "/v1/jobs/OTHER/evidence/changes.patch" }] },
    { ...validSnapshot, evidence: [{ ...validSnapshot.evidence[0], sha256: "x".repeat(64) }] },
    { ...validSnapshot, evidence: [validSnapshot.evidence[0], validSnapshot.evidence[0]] },
  ]) {
    assert.throws(() => parseCoreSnapshot(invalid), /core response/i);
  }
});

test("requires an exact approval proposal while awaiting approval", () => {
  assert.throws(
    () => parseCoreSnapshot({ ...validSnapshot, approvalProposal: undefined }),
    /core response/i,
  );
  const completed = parseCoreSnapshot({
    ...validSnapshot,
    state: "completed",
    approvalConsumed: true,
  });
  assert.equal(completed.snapshot.approvalConsumed, true);
  assert.equal(parseCoreSnapshot({ ...validSnapshot, state: "applying" }).snapshot.approvalConsumed, false);
  assert.equal(parseCoreSnapshot({ ...validSnapshot, state: "cancelled" }).snapshot.approvalConsumed, false);
  for (const invalid of [
    { ...validSnapshot, state: "applying", approvalConsumed: true },
    { ...validSnapshot, state: "completed", approvalConsumed: false },
  ]) assert.throws(() => parseCoreSnapshot(invalid), /core response/i);
});

test("binds every existing-job response to the requested remote job", () => {
  assert.equal(
    parseCoreSnapshotForJob(validSnapshot, "01JEXAMPLEJOB").remoteJobId,
    "01JEXAMPLEJOB",
  );
  assert.throws(
    () => parseCoreSnapshotForJob(validSnapshot, "OTHERJOB"),
    /core response/i,
  );
});
