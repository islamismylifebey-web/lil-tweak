import assert from "node:assert/strict";
import test from "node:test";

import { cancelRecoveryMatches, decisionRecoveryMatches, exportRecoveryMatches } from "../lib/approval-recovery.ts";

test("recovers approval only as a pending unconsumed export", () => {
  assert.equal(decisionRecoveryMatches("approve", "applying", false), true);
  assert.equal(decisionRecoveryMatches("approve", "applying", true), false);
  assert.equal(decisionRecoveryMatches("approve", "completed", true), false);
  assert.equal(decisionRecoveryMatches("reject", "rejected", false), true);
  for (const pair of [
    ["approve", "awaiting_approval"],
    ["approve", "rejected"],
    ["reject", "completed"],
    ["reject", "failed"],
  ]) assert.equal(decisionRecoveryMatches(...pair, false), false);
});

test("recovers an export only from its authoritative consumed completion", () => {
  assert.equal(exportRecoveryMatches("completed", true), true);
  for (const pair of [["applying", false], ["completed", false], ["failed", false]]) {
    assert.equal(exportRecoveryMatches(...pair), false);
  }
});

test("recovers only an already-cancelled core mutation", () => {
  assert.equal(cancelRecoveryMatches("cancelled"), true);
  for (const state of ["queued", "executing", "completed", "failed", "timed_out"]) {
    assert.equal(cancelRecoveryMatches(state), false);
  }
});
