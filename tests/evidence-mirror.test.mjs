import assert from "node:assert/strict";
import test from "node:test";

import { mirrorCoreEvidence } from "../lib/evidence-mirror.ts";

const scope = "ownerhash";
const jobId = `job:${"1".repeat(32)}`;
const descriptor = {
  id: `evidence:${"2".repeat(32)}`,
  category: "patch",
  filename: "changes.patch",
  mediaType: "text/x-diff",
  sizeBytes: 3,
  sha256: "3".repeat(64),
  createdAt: "2026-08-13T12:00:00.000Z",
  corePath: "/v1/jobs/remote-job/evidence/changes.patch",
};

test("copies core evidence to its immutable owner/job R2 key", async () => {
  const objects = new Map();
  const bucket = {
    async head(key) { return objects.get(key) ?? null; },
    async put(key, bytes, options) {
      const object = { key, size: bytes.byteLength, etag: "etag-1", customMetadata: options.customMetadata };
      objects.set(key, object);
      return object;
    },
  };
  let fetches = 0;
  const result = await mirrorCoreEvidence({
    ownerScope: scope,
    jobId,
    remoteJobId: "remote-job",
    evidence: [descriptor],
    bucket,
    fetchEvidence: async () => {
      fetches += 1;
      return { bytes: new Uint8Array([1, 2, 3]), sizeBytes: 3, sha256: descriptor.sha256, mediaType: descriptor.mediaType };
    },
  });
  assert.equal(result[0].sizeBytes, 3);
  assert.equal(fetches, 1);
  assert.ok(objects.has(`engineering/${scope}/jobs/${jobId}/evidence/${descriptor.id}`));

  const repeated = await mirrorCoreEvidence({
    ownerScope: scope,
    jobId,
    remoteJobId: "remote-job",
    evidence: [descriptor],
    bucket,
    fetchEvidence: async () => { throw new Error("should not fetch"); },
  });
  assert.equal(repeated[0].sizeBytes, 3);
});

test("refuses to reuse an R2 object with a different digest", async () => {
  await assert.rejects(
    mirrorCoreEvidence({
      ownerScope: scope,
      jobId,
      remoteJobId: "remote-job",
      evidence: [descriptor],
      bucket: {
        async head() { return { size: 3, customMetadata: { sha256: "4".repeat(64) } }; },
        async put() { throw new Error("should not overwrite"); },
      },
      fetchEvidence: async () => { throw new Error("should not fetch"); },
    }),
    /integrity/i,
  );
});

test("preserves legitimate zero-byte evidence and enforces the declared size", async () => {
  const empty = {
    ...descriptor,
    sizeBytes: 0,
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  };
  const objects = new Map();
  const bucket = {
    async head(key) { return objects.get(key) ?? null; },
    async put(key, bytes, options) {
      const object = { size: bytes.byteLength, customMetadata: options.customMetadata };
      objects.set(key, object);
      return object;
    },
  };
  const mirrored = await mirrorCoreEvidence({
    ownerScope: scope,
    jobId,
    remoteJobId: "remote-job",
    evidence: [empty],
    bucket,
    fetchEvidence: async () => ({
      bytes: new Uint8Array(),
      sizeBytes: 0,
      sha256: empty.sha256,
      mediaType: empty.mediaType,
    }),
  });
  assert.equal(mirrored[0].sizeBytes, 0);

  await assert.rejects(
    mirrorCoreEvidence({
      ownerScope: scope,
      jobId,
      remoteJobId: "remote-job",
      evidence: [{ ...descriptor, sizeBytes: 4 }],
      bucket: {
        async head() { return { size: 3, customMetadata: { sha256: descriptor.sha256 } }; },
        async put() { throw new Error("should not overwrite"); },
      },
      fetchEvidence: async () => { throw new Error("should not fetch"); },
    }),
    /integrity/i,
  );
});

test("reuses a matching immutable object when another poll wins the write race", async () => {
  let heads = 0;
  const result = await mirrorCoreEvidence({
    ownerScope: scope,
    jobId,
    remoteJobId: "remote-job",
    evidence: [descriptor],
    bucket: {
      async head() {
        heads += 1;
        return heads === 1
          ? null
          : { size: 3, customMetadata: { sha256: descriptor.sha256 } };
      },
      async put(_key, _bytes, options) {
        assert.equal(options.onlyIf.get("if-none-match"), "*");
        return null;
      },
    },
    fetchEvidence: async () => ({
      bytes: new Uint8Array([1, 2, 3]),
      sizeBytes: 3,
      sha256: descriptor.sha256,
      mediaType: descriptor.mediaType,
    }),
  });
  assert.equal(result[0].sizeBytes, 3);
  assert.equal(heads, 2);
});
