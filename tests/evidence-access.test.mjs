import assert from "node:assert/strict";
import test from "node:test";

import {
  directEvidenceDownloadAllowed,
  parsePatchExportRequest,
  verifyPatchBeforeConsume,
} from "../lib/evidence-access.ts";
import { MAX_ENGINEERING_EVIDENCE_BYTES } from "../lib/engineering.ts";

test("never treats direct patch GET as an export fallback", () => {
  assert.equal(directEvidenceDownloadAllowed("patch"), false);
  for (const category of ["plan", "tests", "manifest", "summary", "log"]) {
    assert.equal(directEvidenceDownloadAllowed(category), true);
  }
});

test("requires a body-only raw token and stable browser attempt", () => {
  assert.deepEqual(parsePatchExportRequest({
    approvalToken: "A".repeat(43),
    attemptId: "11111111-2222-4333-8444-555555555555",
  }), {
    approvalToken: "A".repeat(43),
    attemptId: "11111111-2222-4333-8444-555555555555",
  });
  for (const invalid of [
    {},
    { approvalToken: "short", attemptId: "11111111-2222-4333-8444-555555555555" },
    { approvalToken: "A".repeat(43), attemptId: "not-an-attempt" },
    { approvalToken: "A".repeat(43), attemptId: "11111111-2222-4333-8444-555555555555", tokenInUrl: true },
  ]) assert.throws(() => parsePatchExportRequest(invalid), /export request/i);
});

test("bounds and digest-verifies actual private bytes before logical consume", async () => {
  const bytes = new TextEncoder().encode("diff");
  const descriptor = {
    sizeBytes: 4,
    sha256: "df087996d45b03e7eb8c133c0298fd98d35113fca26aaba58612fef3cc212cad",
  };
  let consumes = 0;
  const object = {
    size: 4,
    customMetadata: { sha256: descriptor.sha256 },
    body: new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } }),
  };
  const result = await verifyPatchBeforeConsume(object, descriptor, async () => {
    consumes += 1;
    return "completed";
  });
  assert.deepEqual(result.bytes, bytes);
  assert.equal(result.consumed, "completed");
  assert.equal(consumes, 1);

  for (const corrupted of [
    null,
    { ...object, body: new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode("bad!")); controller.close(); } }) },
    { ...object, size: 3 },
    { ...object, body: new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(MAX_ENGINEERING_EVIDENCE_BYTES + 1)); controller.close(); } }) },
  ]) {
    await assert.rejects(
      verifyPatchBeforeConsume(corrupted, descriptor, async () => { consumes += 1; }),
      /evidence/i,
    );
  }
  assert.equal(consumes, 1, "missing, corrupt, and oversized bytes must not consume approval");
});
