import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { register } from "node:module";
import test from "node:test";

const OWNER_SCOPE = "a0885bc0b2c079e996629061a723c74d";
const SIGNING_SECRET = "literal-route-signing-secret-1234567890";
const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const READY_DOCUMENT = {
  status: "ready",
  checks: {
    database: true,
    runner: true,
    git: true,
    workspace: true,
    evidence: true,
    signing: true,
    admission: true,
  },
};

const values = {
  LIL_TWEAK_ENVIRONMENT: "production",
  CORE_ORIGIN: "https://core.example",
  CORE_SIGNING_KEY_ID: "primary",
  CORE_SIGNING_SECRET: SIGNING_SECRET,
  CORE_ACCESS_CLIENT_ID: "route-access-id",
  CORE_ACCESS_CLIENT_SECRET: "route-access-secret-canary",
  DB: {},
  FILES: {},
};
let storageReads = 0;
globalThis.__lilTweakWorkspaceTestEnv = new Proxy(values, {
  get(target, property, receiver) {
    if (property === "DB" || property === "FILES") storageReads += 1;
    return Reflect.get(target, property, receiver);
  },
});
register(new URL("./workspace-test-loader.mjs", import.meta.url));

const [{ GET }, { ownerScope }] = await Promise.all([
  import("../app/api/engineering/status/route.ts"),
  import("../lib/engineering-api.ts"),
]);

function ownerRequest(email = "islamismylifebey@gmail.com", includeId = true) {
  return new Request("https://lil-tweak.example/api/engineering/status", {
    headers: {
      ...(includeId ? { "oai-authenticated-user-id": "site-owner-id" } : {}),
      "oai-authenticated-user-email": email,
    },
  });
}

test("ordinary job owner derivation produces the exact Core partition scope", async () => {
  assert.equal(
    await ownerScope("beythetruth4ever@paradigmshiftingthepodcast.net"),
    OWNER_SCOPE,
  );
  assert.notEqual(await ownerScope("islamismylifebey@gmail.com"), OWNER_SCOPE);
  assert.notEqual(
    await ownerScope("beythetruth4ever@paradigmshiftingthepodcast.net"),
    "ab43c7488fb38a90c7bb9c4bcc0e23e5",
  );
});

test("actual authorized status route derives owner scope and signs the Core readiness probe", async () => {
  const originalFetch = globalThis.fetch;
  let fetches = 0;
  globalThis.fetch = async (url, init) => {
    fetches += 1;
    assert.equal(String(url), "https://core.example/readyz");
    assert.equal(init.redirect, "error");
    const headers = new Headers(init.headers);
    assert.equal(headers.get("x-lil-tweak-owner"), OWNER_SCOPE);
    assert.equal(headers.has("idempotency-key"), false);
    const canonical = [
      "v2",
      headers.get("x-lil-tweak-key-id"),
      "GET",
      "/readyz",
      headers.get("x-lil-tweak-timestamp"),
      headers.get("x-lil-tweak-nonce"),
      EMPTY_SHA256,
      headers.get("x-lil-tweak-request-id"),
      "",
      OWNER_SCOPE,
    ].join("\n");
    assert.equal(
      headers.get("x-lil-tweak-signature"),
      createHmac("sha256", SIGNING_SECRET).update(canonical).digest("hex"),
    );
    return Response.json(READY_DOCUMENT, {
      headers: { "content-length": String(Buffer.byteLength(JSON.stringify(READY_DOCUMENT))) },
    });
  };
  try {
    const response = await GET(ownerRequest());
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(payload.status.runner.connection, "ready");
    assert.equal(payload.status.runner.qualification, "not_reported");
    assert.equal("state" in payload.status.bridge, false);
    assert.equal(fetches, 1);
    assert.ok(storageReads > 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("actual status route rejects missing or wrong authenticated identity before Core or storage", async () => {
  const originalFetch = globalThis.fetch;
  let fetches = 0;
  globalThis.fetch = async () => {
    fetches += 1;
    throw new Error("unauthorized request reached Core");
  };
  try {
    for (const request of [
      ownerRequest("islamismylifebey@gmail.com", false),
      ownerRequest("not-the-owner@example.com"),
    ]) {
      storageReads = 0;
      const response = await GET(request);
      assert.equal(response.status, 401);
      assert.deepEqual(await response.json(), { error: "Owner access required." });
      assert.equal(fetches, 0);
      assert.equal(storageReads, 0);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});
