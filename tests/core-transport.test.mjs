import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  coreAccessHeaders,
  publicCoreFailure,
  validateCoreSigningConfig,
  validateCoreTransportConfig,
} from "../lib/core-transport.ts";
import { enforceSiteIngress } from "../lib/ingress-boundary.ts";

test("production core transport requires a complete Access service token", () => {
  assert.throws(
    () => validateCoreTransportConfig({ coreOrigin: "https://core.example" }),
    /unavailable/i,
  );
  assert.throws(
    () => validateCoreTransportConfig({ environment: "production", coreOrigin: "https://core.example" }),
    /unavailable/i,
  );
  assert.throws(
    () => validateCoreTransportConfig({ environment: "production", coreOrigin: "https://core.example", accessClientId: "id" }),
    /unavailable/i,
  );
  assert.deepEqual(
    coreAccessHeaders(validateCoreTransportConfig({
      environment: "production",
      coreOrigin: "https://core.example",
      accessClientId: "id.access",
      accessClientSecret: "secret",
    })),
    { "CF-Access-Client-Id": "id.access", "CF-Access-Client-Secret": "secret" },
  );
});

test("production core transport accepts Sites private tunnel bindings without Access headers", () => {
  const config = validateCoreTransportConfig({
    environment: "production",
    coreOrigin: "https://core.example",
    privateBinding: true,
  });
  assert.equal(config.privateBinding, true);
  assert.equal(config.origin.toString(), "https://core.example/");
  assert.deepEqual(coreAccessHeaders(config), {});
});

test("core signing configuration matches the private core contract", () => {
  assert.deepEqual(validateCoreSigningConfig("x".repeat(32), "primary"), {
    secret: "x".repeat(32),
    keyId: "primary",
  });
  assert.throws(() => validateCoreSigningConfig("short", "primary"), /unavailable/i);
  assert.throws(() => validateCoreSigningConfig("é".repeat(15), "primary"), /unavailable/i);
  assert.throws(() => validateCoreSigningConfig("x".repeat(32), "bad key"), /unavailable/i);
  assert.throws(() => validateCoreSigningConfig("x".repeat(32), "_leading"), /unavailable/i);
});

test("maps only safe core failure semantics to the owner", () => {
  assert.deepEqual(publicCoreFailure(409), { status: 409, message: "Engineering job changed. Refresh and try again." });
  assert.deepEqual(publicCoreFailure(429), { status: 429, message: "The private engineering core is at capacity. Try again shortly." });
  assert.deepEqual(publicCoreFailure(503), { status: 503, message: "The private engineering core is unavailable." });
  assert.deepEqual(publicCoreFailure(418), { status: 503, message: "The private engineering core is unavailable." });
});

test("production Site ingress accepts only the exact configured public origin", async () => {
  const config = {
    environment: "production",
    publicOrigin: "https://lil-tweak.example",
  };
  assert.equal(
    await enforceSiteIngress(new Request("https://lil-tweak.example/"), config),
    true,
  );
  assert.equal(
    await enforceSiteIngress(new Request("https://direct.workers.dev/"), config),
    false,
  );
});

test("production Site ingress rejects noncanonical or missing public origins", async () => {
  for (const publicOrigin of [
    undefined,
    "http://lil-tweak.example",
    "https://lil-tweak.example/",
    "https://LIL-TWEAK.example",
    "https://lil-tweak.example:443",
    "https://lil-tweak.example/path",
  ]) {
    await assert.rejects(
      enforceSiteIngress(new Request("https://lil-tweak.example/"), {
        environment: "production",
        publicOrigin,
      }),
      /configuration/i,
    );
  }
  await assert.rejects(enforceSiteIngress(new Request("https://lil-tweak.example/"), {}), /configuration/i);
});

test("private core credentials never follow redirects", async () => {
  const client = await readFile(new URL("../lib/core-client.ts", import.meta.url), "utf8");
  assert.match(client, /redirect:\s*"error"/);
  assert.match(client, /CUSTOMER_HTTP_LIL_TWEAK_CORE/);
  assert.match(client, /privateBinding:\s*!coreOrigin && Boolean\(privateCoreOrigin\)/);
  assert.match(client, /keyId:\s*signing\.keyId/);
  assert.match(client, /idempotencyKey,\s*\n\s*ownerKey/);
  assert.match(client, /"X-Lil-Tweak-Owner":\s*ownerKey/);
  assert.match(client, /MAX_ENGINEERING_EVIDENCE_BYTES/);
  assert.match(client, /EVIDENCE_TIMEOUT_MS\s*=\s*30_000/);
});
