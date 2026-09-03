import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { engineeringConnectionStatus } from "../lib/engineering-connection.ts";

const OWNER_ONLY_ROUTE = new URL("../app/api/engineering/status/route.ts", import.meta.url);

test("engineering connection status fails closed without runtime bridge configuration", async () => {
  const status = await engineeringConnectionStatus({
    LIL_TWEAK_ENVIRONMENT: "production",
    DB: {},
    FILES: {},
  }, { now: () => new Date("2026-08-21T16:30:00.000Z") });

  assert.equal(status.generatedAt, "2026-08-21T16:30:00.000Z");
  assert.equal(status.controlPlane.storage, "configured");
  assert.equal(status.bridge.state, "pending_configuration");
  assert.equal(status.bridge.transport, "missing");
  assert.equal(status.bridge.signing, "missing");
  assert.equal(status.bridge.access, "missing");
  assert.deepEqual(status.bridge.missing, [
    "CORE_ORIGIN or CUSTOMER_HTTP_LIL_TWEAK_CORE",
    "CORE_SIGNING_SECRET",
    "CORE_SIGNING_KEY_ID",
    "CORE_ACCESS_CLIENT_ID",
    "CORE_ACCESS_CLIENT_SECRET",
  ]);
});

test("engineering connection status exposes merged provenance without leaking secrets", async () => {
  const secret = "status-secret-value-that-must-not-leak";
  const calls = [];
  const status = await engineeringConnectionStatus({
    LIL_TWEAK_ENVIRONMENT: "production",
    CUSTOMER_HTTP_LIL_TWEAK_CORE: "https://core.example",
    CORE_SIGNING_KEY_ID: "primary",
    CORE_SIGNING_SECRET: secret,
    DB: {},
    FILES: {},
  }, {
    probe: true,
    fetcher: async (url, init) => {
      calls.push({ url: String(url), headers: init.headers });
      return new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: { "content-length": "15", "content-type": "application/json" },
      });
    },
  });

  assert.equal(status.bridge.state, "health_reachable");
  assert.equal(status.bridge.origin, "sites_private_tunnel");
  assert.equal(status.bridge.access, "not_required");
  assert.equal(status.github.lilTweak.head, "191189c515b9dbd8ddb82e9ad3fc86853cc815df");
  assert.equal(status.github.lilTweak.pr6Merge, "08e3705227ec428d0b6ce6bc6d58dca3657b2683");
  assert.equal(status.github.galorHub.pr28Merge, "ac15ba6cf794375339528fe7c7e5b21a81bf34f0");
  assert.equal(status.galor.version, "1.0.0");
  assert.equal(status.galor.executionHost, "galor-private-cloud-01");
  assert.deepEqual(calls, [{ url: "https://core.example/healthz", headers: { Accept: "application/json" } }]);
  assert.doesNotMatch(JSON.stringify(status), new RegExp(secret));
});

test("engineering connection status route is owner-only", async () => {
  const route = await readFile(OWNER_ONLY_ROUTE, "utf8");
  assert.match(route, /ownerFor\(request\)/);
  assert.match(route, /engineeringConnectionStatus\(env,\s*\{\s*probe:\s*true\s*\}\)/);
});
