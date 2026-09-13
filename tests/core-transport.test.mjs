import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  coreAccessHeaders,
  publicCoreFailure,
  validateCoreSigningConfig,
  validateCoreTransportConfig,
} from "../lib/core-transport.ts";
import { enforceManagedIngress } from "../lib/ingress-boundary.ts";

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

test("managed assertion ingress requires a valid assertion and rejects direct hosts", async () => {
  const config = {
    environment: "production",
    ingressMode: "managed_assertion",
    publicOrigin: "https://lil-tweak.example",
    managedIngressSecret: "a-long-random-managed-ingress-secret",
  };
  assert.equal(await enforceManagedIngress(new Request("https://lil-tweak.example/", {
    headers: { "x-lil-tweak-managed-ingress": config.managedIngressSecret },
  }), config), true);
  assert.equal(await enforceManagedIngress(new Request("https://direct.workers.dev/", {
    headers: { "x-lil-tweak-managed-ingress": config.managedIngressSecret },
  }), config), false);
  assert.equal(await enforceManagedIngress(new Request("https://lil-tweak.example/"), config), false);
  const publicConfig = {
    environment: "production",
    ingressMode: "managed_assertion",
    publicOrigin: "https://lil-tweak.example",
  };
  await assert.rejects(
    enforceManagedIngress(new Request("https://lil-tweak.example/"), publicConfig),
    /configuration/i,
  );
  await assert.rejects(
    enforceManagedIngress(new Request("https://lil-tweak.example/"), {
      ...publicConfig,
      managedIngressSecret: "short",
    }),
    /configuration/i,
  );
  await assert.rejects(
    enforceManagedIngress(new Request("https://lil-tweak.example/"), { environment: "production" }),
    /configuration/i,
  );
});

const nativeOrigin = "https://lil-tweak.owner.chatgpt.site";
const nativeConfig = {
  environment: "production",
  ingressMode: "sites_native",
  publicOrigin: nativeOrigin,
};
const nativeIdentity = {
  "oai-authenticated-user-id": "site-scoped-user-fixture",
  "oai-authenticated-user-email": "owner@example.invalid",
};

test("production ingress never infers its trust mode from a missing secret", async () => {
  for (const ingressMode of [undefined, "", " ", "unknown", "SITES_NATIVE"]) {
    await assert.rejects(enforceManagedIngress(new Request(nativeOrigin, {
      headers: nativeIdentity,
    }), { ...nativeConfig, ingressMode }), /configuration/i);
  }
});

test("native Sites ingress requires both nonempty platform identity headers", async () => {
  assert.equal(await enforceManagedIngress(new Request(nativeOrigin, {
    headers: nativeIdentity,
  }), nativeConfig), true);
  for (const headers of [
    {},
    { "oai-authenticated-user-id": "id" },
    { "oai-authenticated-user-email": "owner@example.invalid" },
    { ...nativeIdentity, "oai-authenticated-user-id": " " },
    { ...nativeIdentity, "oai-authenticated-user-email": " " },
  ]) {
    assert.equal(await enforceManagedIngress(new Request(nativeOrigin, { headers }), nativeConfig), false);
  }
});

test("native Sites ingress cannot authorize an alternate or non-Sites origin", async () => {
  for (const origin of [
    "https://alternate.owner.chatgpt.site", "https://direct.workers.dev",
    "http://lil-tweak.owner.chatgpt.site", `${nativeOrigin}:8443`,
  ]) {
    assert.equal(await enforceManagedIngress(new Request(origin, {
      headers: nativeIdentity,
    }), nativeConfig), false);
  }
  for (const publicOrigin of [
    "https://not-sites.example", "https://chatgpt.site", "https://owner.chatgpt.site.evil.example",
    `${nativeOrigin}:8443`, `http://lil-tweak.owner.chatgpt.site`, `${nativeOrigin}/extra`,
  ]) {
    await assert.rejects(enforceManagedIngress(new Request(publicOrigin, {
      headers: nativeIdentity,
    }), { ...nativeConfig, publicOrigin }), /configuration/i);
  }
});

test("native Sites ingress rejects contradictory assertion configuration", async () => {
  for (const managedIngressSecret of ["", " ", "short", "x".repeat(32)]) {
    await assert.rejects(enforceManagedIngress(new Request(nativeOrigin, {
      headers: nativeIdentity,
    }), { ...nativeConfig, managedIngressSecret }), /configuration/i);
  }
});

test("managed ingress fails closed when its environment is omitted", async () => {
  await assert.rejects(
    enforceManagedIngress(new Request("https://lil-tweak.example/"), {}),
    /configuration/i,
  );
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
