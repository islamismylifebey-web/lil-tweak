import assert from "node:assert/strict";
import test from "node:test";

import { engineeringConnectionStatus } from "../lib/engineering-connection.ts";

function allKeys(value) {
  if (!value || typeof value !== "object") return [];
  if (Array.isArray(value)) return value.flatMap(allKeys);
  return Object.entries(value).flatMap(([key, child]) => [key, ...allKeys(child)]);
}

test("status reports only the literal direct runner identity before probing", async () => {
  const status = await engineeringConnectionStatus({
    LIL_TWEAK_ENVIRONMENT: "production",
    DB: {},
    FILES: {},
  }, "a0885bc0b2c079e996629061a723c74d", {
    now: () => new Date("2026-09-04T16:30:00.000Z"),
  });

  const expectedRunner = {
    owner: "tueiq",
    provider: "digitalocean",
    dropletId: "597343619",
    host: "galor-tweak-runner-01",
    role: "role-tweak-runner",
    route: "direct_core_to_local_podman",
    intermediary: "none",
    imagePolicy: "digest_pinned",
    connection: "pending_configuration",
    qualification: "not_reported",
  };
  assert.deepEqual(status.runner, expectedRunner);
  assert.equal("state" in status.bridge, false);
  assert.equal("health" in status.bridge, false);

  const retiredNamespace = expectedRunner.host.split("-")[0];
  const retiredBroker = ["h", "ub"].join("");
  const keys = allKeys(status).map((key) => key.toLowerCase());
  assert.equal(keys.some((key) => key.includes(retiredNamespace)), false);
  assert.equal(keys.includes(retiredBroker), false);
});
