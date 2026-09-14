import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  ImmutableObjectConflictError,
  immutableSourceMatches,
  putImmutableObject,
} from "../lib/immutable-r2.ts";

test("creates an R2 object only when its key is absent", async () => {
  let receivedOptions;
  const object = { etag: "first", size: 3 };
  const result = await putImmutableObject(
    {
      async put(_key, _value, options) {
        receivedOptions = options;
        return object;
      },
    },
    "owner/job/source",
    new Uint8Array([1, 2, 3]),
    { customMetadata: { sourceId: "src:1" } },
  );

  assert.equal(result, object);
  assert.equal(receivedOptions.onlyIf.get("if-none-match"), "*");
  assert.deepEqual(receivedOptions.customMetadata, { sourceId: "src:1" });
});

test("reports an immutable-key conflict without overwriting", async () => {
  await assert.rejects(
    putImmutableObject(
      { async put() { return null; } },
      "owner/job/source",
      new Uint8Array(),
    ),
    ImmutableObjectConflictError,
  );
});

test("accepts only the exact immutable source object described by D1", () => {
  const expected = {
    id: `src:${"a".repeat(32)}`,
    jobId: `job:${"b".repeat(32)}`,
    mediaType: "application/zip",
    sizeBytes: 42,
    sha256: "d".repeat(64),
  };
  const object = {
    size: 42,
    etag: "etag-1",
    httpMetadata: { contentType: "application/zip" },
    customMetadata: { sourceId: expected.id, jobId: expected.jobId, sha256: expected.sha256 },
  };

  assert.equal(immutableSourceMatches(object, expected), true);
  assert.equal(immutableSourceMatches({ ...object, size: 41 }, expected), false);
  assert.equal(
    immutableSourceMatches({ ...object, customMetadata: { ...object.customMetadata, sourceId: `src:${"c".repeat(32)}` } }, expected),
    false,
  );
  assert.equal(
    immutableSourceMatches({ ...object, httpMetadata: { contentType: "text/plain" } }, expected),
    false,
  );
  assert.equal(
    immutableSourceMatches({ ...object, customMetadata: { ...object.customMetadata, sha256: "e".repeat(64) } }, expected),
    false,
  );
});

test("disabled uploads retain existing immutable-source defense behind the dispatch policy", async () => {
  const [uploadRoute, dispatchRoute] = await Promise.all([
    readFile(new URL("../app/api/engineering/jobs/[id]/sources/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/engineering/jobs/[id]/route.ts", import.meta.url), "utf8"),
  ]);
  assert.match(uploadRoute, /Uploaded-project execution is unavailable/);
  assert.doesNotMatch(uploadRoute, /markSourceUploaded|putImmutableObject/);
  assert.match(dispatchRoute, /enforceModeSourcePolicy\(job.mode, job.projectId, job.sources, job.gitSource\)/);
  assert.match(dispatchRoute, /files\(\)\.head\(r2Key\)/);
  assert.match(dispatchRoute, /immutableSourceMatches\(object,[^;]+sha256/s);
  assert.match(dispatchRoute, /sources:\s*verifiedSources/);
});
