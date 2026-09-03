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
  assert.equal(status.runner.state, "disconnected");
  assert.equal(status.runner.qualified, false);
});

test("core health never masquerades as Runner V3 connection or qualification", async () => {
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
  assert.equal(status.github.lilTweak.head, "63522fa027836b47808eeff201b84ce49a9ae1b6");
  assert.equal(status.github.lilTweak.pr6Merge, "08e3705227ec428d0b6ce6bc6d58dca3657b2683");
  assert.equal(status.github.galorHub.head, "3955152831f7b61c105c44b2faf0f5f02d1f4d07");
  assert.equal(status.github.galorHub.pr28Merge, "3955152831f7b61c105c44b2faf0f5f02d1f4d07");
  assert.equal(status.galor.version, "3.0.0");
  assert.equal(status.galor.executionHost, "galor-tweak-runner-01");
  assert.equal(status.galor.integration, "awaiting_authenticated_runner_proof");
  assert.equal(status.runner.state, "disconnected");
  assert.equal(status.runner.qualified, false);
  assert.equal(status.runner.label, "Runner V3 connection not proven");
  assert.deepEqual(calls, [{ url: "https://core.example/healthz", headers: { Accept: "application/json" } }]);
  assert.doesNotMatch(JSON.stringify(status), new RegExp(secret));
});

test("engineering connection status route is owner-only", async () => {
  const route = await readFile(OWNER_ONLY_ROUTE, "utf8");
  assert.match(route, /ownerFor\(request\)/);
  assert.match(route, /engineeringConnectionStatus\(env,\s*\{\s*probe:\s*true\s*\}\)/);
});
