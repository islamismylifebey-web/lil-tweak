import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { canonicalCoreRequest, signCoreRequest } from "../lib/core-signing.ts";

test("TypeScript matches the shared canonical-query signing fixture", async () => {
  const fixture = JSON.parse(await readFile(new URL("./fixtures/core-signing-query-v2.json", import.meta.url), "utf8"));
  assert.equal(canonicalCoreRequest(fixture.fields), fixture.canonical);
  assert.equal(await signCoreRequest(fixture.secret, fixture.fields), fixture.signature);
  for (const [field, value] of [
    ["keyId", "secondary"],
    ["idempotencyKey", "job:public-1:poll:8"],
    ["ownerKey", "fedcba9876543210fedcba9876543210"],
  ]) {
    assert.notEqual(
      await signCoreRequest(fixture.secret, { ...fixture.fields, [field]: value }),
      fixture.signature,
      `${field} must be signature-bound`,
    );
  }
});
