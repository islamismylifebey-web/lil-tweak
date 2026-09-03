import assert from "node:assert/strict";
import test from "node:test";

import { selectStagedSourceCandidates } from "../lib/source-staging.ts";

const item = (name, size, source = "file", type = "text/plain") => ({
  name,
  size,
  source,
  type,
});

test("applies one 100 MB source budget across files and camera captures", () => {
  const existing = [
    item("one.txt", 25_000_000),
    item("two.txt", 25_000_000),
    item("three.txt", 25_000_000),
  ];
  const first = item("photo.jpg", 25_000_000, "camera", "image/jpeg");
  const overflow = item("tiny.jpg", 1, "camera", "image/jpeg");

  const result = selectStagedSourceCandidates(existing, [first, overflow], "camera");

  assert.deepEqual(result.accepted, [first]);
  assert.equal(result.rejected, 1);
  assert.equal(result.rejectionReason, "Sources selected here must total 100 MB or less.");
});

test("rejects source filenames case-insensitively across existing and new items", () => {
  const existing = [item("Plan.TXT", 10)];
  const caseDuplicate = item("plan.txt", 11);
  const firstReadme = item("README.md", 12);
  const secondReadme = item("readme.MD", 13);

  const result = selectStagedSourceCandidates(
    existing,
    [caseDuplicate, firstReadme, secondReadme],
    "file",
  );

  assert.deepEqual(result.accepted, [firstReadme]);
  assert.equal(result.rejected, 2);
  assert.equal(result.rejectionReason, "Source filenames must be unique.");
});
