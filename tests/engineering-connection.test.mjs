import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";

import { engineeringConnectionStatus } from "../lib/engineering-connection.ts";
import * as engineeringClient from "../app/engineering-client.ts";

const OWNER_SCOPE = "a0885bc0b2c079e996629061a723c74d";
const LOGIN_EMAIL_HASH = "ab43c7488fb38a90c7bb9c4bcc0e23e5";
const FIXED_DATE = new Date("2026-09-04T16:30:00.000Z");
const FIXED_TIMESTAMP = "1788539400";
const FIXED_NONCE = "00112233445566778899aabbccddeeff";
const FIXED_REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000";
const SIGNING_SECRET = "literal-status-signing-secret-1234567890";
const ACCESS_SECRET_CANARY = "access-secret-canary-do-not-serialize";
const ERROR_CANARY = "caught-error-canary-do-not-serialize";
const BODY_CANARY = "raw-body-canary-do-not-serialize";
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

function configuredBindings(overrides = {}) {
  return {
    LIL_TWEAK_ENVIRONMENT: "production",
    CORE_ORIGIN: "https://core.example",
    CORE_SIGNING_KEY_ID: "primary",
    CORE_SIGNING_SECRET: SIGNING_SECRET,
    CORE_ACCESS_CLIENT_ID: "access-client-id",
    CORE_ACCESS_CLIENT_SECRET: ACCESS_SECRET_CANARY,
    DB: {},
    FILES: {},
    ...overrides,
  };
}

function fixedOptions(overrides = {}) {
  return {
    now: () => FIXED_DATE,
    nonceFactory: () => FIXED_NONCE,
    requestIdFactory: () => FIXED_REQUEST_ID,
    ...overrides,
  };
}

function responseFor(value, options = {}) {
  const body = typeof value === "string" ? value : JSON.stringify(value);
  return new Response(body, {
    status: options.status ?? 200,
    headers: {
      ...(options.contentType === null ? {} : { "content-type": options.contentType ?? "application/json" }),
      ...(options.contentLength === null ? {} : { "content-length": options.contentLength ?? String(Buffer.byteLength(body)) }),
      ...options.headers,
    },
  });
}

function expectedReadyStatus() {
  return {
    generatedAt: "2026-09-04T16:30:00.000Z",
    controlPlane: {
      storage: "configured",
      d1: "configured",
      r2: "configured",
    },
    bridge: {
      origin: "core_origin",
      transport: "configured",
      signing: "configured",
      access: "configured",
      missing: [],
    },
    runner: {
      owner: "tueiq",
      provider: "digitalocean",
      dropletId: "597343619",
      host: "galor-tweak-runner-01",
      role: "role-tweak-runner",
      route: "direct_core_to_local_podman",
      intermediary: "none",
      imagePolicy: "digest_pinned",
      connection: "ready",
      qualification: "not_reported",
    },
  };
}

function clone(value) {
  return structuredClone(value);
}

async function statusThroughBrowser(value) {
  return engineeringClient.getEngineeringConnectionStatus(
    async () => responseFor({ status: value }),
  );
}

test("signed readiness uses the exact empty-body HMAC v2 convention without an HTTP idempotency header", async () => {
  let calls = 0;
  const status = await engineeringConnectionStatus(configuredBindings(), OWNER_SCOPE, fixedOptions({
    probe: true,
    fetcher: async (url, init) => {
      calls += 1;
      assert.equal(String(url), "https://core.example/readyz");
      assert.equal(init.method, "GET");
      assert.equal(init.redirect, "error");
      assert.equal(init.body, undefined);
      assert.ok(init.signal instanceof AbortSignal);

      const headers = new Headers(init.headers);
      const canonical = [
        "v2",
        "primary",
        "GET",
        "/readyz",
        FIXED_TIMESTAMP,
        FIXED_NONCE,
        EMPTY_SHA256,
        FIXED_REQUEST_ID,
        "",
        OWNER_SCOPE,
      ].join("\n");
      const signature = createHmac("sha256", SIGNING_SECRET).update(canonical).digest("hex");
      assert.deepEqual(Object.fromEntries([...headers].sort()), {
        accept: "application/json",
        "cf-access-client-id": "access-client-id",
        "cf-access-client-secret": ACCESS_SECRET_CANARY,
        "x-lil-tweak-body-sha256": EMPTY_SHA256,
        "x-lil-tweak-key-id": "primary",
        "x-lil-tweak-nonce": FIXED_NONCE,
        "x-lil-tweak-owner": OWNER_SCOPE,
        "x-lil-tweak-request-id": FIXED_REQUEST_ID,
        "x-lil-tweak-signature": signature,
        "x-lil-tweak-timestamp": FIXED_TIMESTAMP,
      });
      assert.equal(headers.has("idempotency-key"), false);
      return responseFor(READY_DOCUMENT);
    },
  }));

  assert.equal(calls, 1);
  assert.deepEqual(status, expectedReadyStatus());
  assert.equal(status.runner.qualification, "not_reported");
  assert.equal("state" in status.bridge, false);
  assert.equal("health" in status.bridge, false);
  const serialized = JSON.stringify(status);
  assert.doesNotMatch(serialized, new RegExp(SIGNING_SECRET));
  assert.doesNotMatch(serialized, new RegExp(ACCESS_SECRET_CANARY));
  assert.doesNotMatch(serialized, /core\.example/);
});

test("configured readiness failures normalize to unreachable without leaking headers, errors, or raw bodies", async (context) => {
  const missingCheck = clone(READY_DOCUMENT);
  delete missingCheck.checks.git;
  const extraCheck = clone(READY_DOCUMENT);
  extraCheck.checks.service = true;
  const nonBoolean = clone(READY_DOCUMENT);
  nonBoolean.checks.runner = "true";
  const falseCheck = clone(READY_DOCUMENT);
  falseCheck.checks.admission = false;
  const extraTopLevel = { ...READY_DOCUMENT, raw: BODY_CANARY };

  const cases = {
    redirect: () => responseFor(READY_DOCUMENT, { status: 302, headers: { location: "/elsewhere" } }),
    "non-200": () => responseFor({ error: BODY_CANARY }, { status: 503 }),
    "missing content type": () => responseFor(READY_DOCUMENT, { contentType: null }),
    "wrong content type": () => responseFor(READY_DOCUMENT, { contentType: "text/plain" }),
    "oversized declared body": () => responseFor(READY_DOCUMENT, { contentLength: "16385" }),
    "malformed declared length": () => responseFor(READY_DOCUMENT, { contentLength: "16KiB" }),
    "malformed UTF-8": () => new Response(Uint8Array.from([0xff]), {
      status: 200,
      headers: { "content-type": "application/json", "content-length": "1" },
    }),
    "malformed JSON": () => responseFor(`{"status":"ready","raw":"${BODY_CANARY}"`),
    "extra top-level key": () => responseFor(extraTopLevel),
    "missing check": () => responseFor(missingCheck),
    "extra check": () => responseFor(extraCheck),
    "non-boolean check": () => responseFor(nonBoolean),
    "false check": () => responseFor(falseCheck),
    "fetch exception": () => { throw new Error(ERROR_CANARY); },
  };

  for (const [label, makeResponse] of Object.entries(cases)) {
    await context.test(label, async () => {
      const status = await engineeringConnectionStatus(configuredBindings(), OWNER_SCOPE, fixedOptions({
        probe: true,
        fetcher: async () => makeResponse(),
      }));
      assert.equal(status.runner.connection, "unreachable");
      assert.equal(status.runner.qualification, "not_reported");
      const serialized = JSON.stringify(status);
      for (const canary of [SIGNING_SECRET, ACCESS_SECRET_CANARY, ERROR_CANARY, BODY_CANARY]) {
        assert.doesNotMatch(serialized, new RegExp(canary));
      }
    });
  }
});

test("oversized streamed readiness stops at 16 KiB plus one byte and cancels", async () => {
  const chunks = [new Uint8Array(8192), new Uint8Array(8192), new Uint8Array(1), new Uint8Array(8192)];
  let pulls = 0;
  let cancelled = false;
  const body = new ReadableStream({
    pull(controller) {
      controller.enqueue(chunks[pulls]);
      pulls += 1;
      if (pulls === chunks.length) controller.close();
    },
    cancel() {
      cancelled = true;
    },
  }, { highWaterMark: 0 });

  const status = await engineeringConnectionStatus(configuredBindings(), OWNER_SCOPE, fixedOptions({
    probe: true,
    fetcher: async () => new Response(body, {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  }));

  assert.equal(status.runner.connection, "unreachable");
  assert.equal(pulls, 3);
  assert.equal(cancelled, true);
});

test("readiness timeout is exactly five seconds and fails closed", async () => {
  const originalSetTimeout = globalThis.setTimeout;
  const originalClearTimeout = globalThis.clearTimeout;
  let timeoutDelay = null;
  try {
    globalThis.setTimeout = (callback, delay) => {
      timeoutDelay = delay;
      queueMicrotask(callback);
      return 1;
    };
    globalThis.clearTimeout = () => {};
    const status = await engineeringConnectionStatus(configuredBindings(), OWNER_SCOPE, fixedOptions({
      probe: true,
      fetcher: async (_url, init) => new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(new Error(ERROR_CANARY)), { once: true });
      }),
    }));
    assert.equal(timeoutDelay, 5_000);
    assert.equal(status.runner.connection, "unreachable");
    assert.doesNotMatch(JSON.stringify(status), new RegExp(ERROR_CANARY));
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    globalThis.clearTimeout = originalClearTimeout;
  }
});

test("malformed or noncanonical owner scopes perform no Core fetch", async (context) => {
  for (const owner of ["", "A".repeat(32), "a".repeat(31), "g".repeat(32), LOGIN_EMAIL_HASH]) {
    await context.test(owner || "empty", async () => {
      let fetches = 0;
      const status = await engineeringConnectionStatus(configuredBindings(), owner, fixedOptions({
        probe: true,
        fetcher: async () => {
          fetches += 1;
          return responseFor(READY_DOCUMENT);
        },
      }));
      assert.equal(fetches, 0);
      assert.equal(status.runner.connection, "unreachable");
    });
  }
});

test("connection state has one truth and follows the configuration/probe matrix", async () => {
  const pending = await engineeringConnectionStatus({
    LIL_TWEAK_ENVIRONMENT: "production",
    DB: {},
    FILES: {},
  }, OWNER_SCOPE, fixedOptions());
  assert.deepEqual(pending, {
    generatedAt: "2026-09-04T16:30:00.000Z",
    controlPlane: { storage: "configured", d1: "configured", r2: "configured" },
    bridge: {
      origin: "none",
      transport: "missing",
      signing: "missing",
      access: "missing",
      missing: [
        "CORE_ORIGIN or CUSTOMER_HTTP_LIL_TWEAK_CORE",
        "CORE_SIGNING_SECRET",
        "CORE_SIGNING_KEY_ID",
        "CORE_ACCESS_CLIENT_ID",
        "CORE_ACCESS_CLIENT_SECRET",
      ],
    },
    runner: { ...expectedReadyStatus().runner, connection: "pending_configuration" },
  });

  const configured = await engineeringConnectionStatus(
    configuredBindings(),
    OWNER_SCOPE,
    fixedOptions(),
  );
  assert.equal(configured.runner.connection, "configured_pending_probe");
  assert.deepEqual(configured.bridge.missing, []);
  assert.equal("state" in configured.bridge, false);
  assert.equal("health" in configured.bridge, false);
});

test("partial optional Access configuration stays a self-consistent pending status", async () => {
  for (const bindings of [
    configuredBindings({
      LIL_TWEAK_ENVIRONMENT: "test",
      CORE_ACCESS_CLIENT_SECRET: undefined,
    }),
    configuredBindings({
      CORE_ORIGIN: undefined,
      CUSTOMER_HTTP_LIL_TWEAK_CORE: "https://private-core.example",
      CORE_ACCESS_CLIENT_SECRET: undefined,
    }),
  ]) {
    const status = await engineeringConnectionStatus(
      bindings,
      OWNER_SCOPE,
      fixedOptions(),
    );
    assert.equal(status.runner.connection, "pending_configuration");
    assert.equal(status.bridge.transport, "missing");
    assert.deepEqual(status.bridge.missing, ["CORE_ACCESS_CLIENT_SECRET"]);
    assert.deepEqual(
      engineeringClient.parseEngineeringConnectionStatus(status),
      status,
    );
  }
});

test("strict browser parser accepts only the complete literal ready status", async () => {
  const expected = expectedReadyStatus();
  assert.deepEqual(engineeringClient.parseEngineeringConnectionStatus(expected), expected);
  assert.deepEqual(await statusThroughBrowser(expected), expected);
});

test("strict browser parser rejects missing, extra, unknown, and contradictory status data", async (context) => {
  const cases = new Map();
  const add = (label, mutate) => {
    const value = expectedReadyStatus();
    mutate(value);
    cases.set(label, value);
  };

  add("missing top-level key", (value) => { delete value.controlPlane; });
  add("extra top-level key", (value) => { value.raw = BODY_CANARY; });
  add("missing bridge key", (value) => { delete value.bridge.access; });
  add("extra bridge key", (value) => { value.bridge.state = "ready"; });
  add("missing runner key", (value) => { delete value.runner.role; });
  add("extra runner key", (value) => { value.runner.health = "ok"; });
  add("malformed timestamp", (value) => { value.generatedAt = "2026-09-04T16:30:00Z"; });
  add("noncanonical timestamp", (value) => { value.generatedAt = "2026-09-04T16:30:00.000+00:00"; });
  add("storage contradiction", (value) => { value.controlPlane.storage = "missing"; });
  add("unsupported connection", (value) => { value.runner.connection = "connected"; });
  add("unsupported qualification", (value) => { value.runner.qualification = "qualified"; });
  add("ready with missing transport", (value) => { value.bridge.transport = "missing"; });
  add("ready with missing signing", (value) => { value.bridge.signing = "missing"; });
  add("ready with missing binding names", (value) => { value.bridge.missing = ["CORE_SIGNING_SECRET"]; });
  add("configured origin marked absent", (value) => { value.bridge.origin = "none"; });
  add("configured transport with missing access", (value) => { value.bridge.access = "missing"; });
  add("configured access with a missing credential", (value) => {
    value.runner.connection = "pending_configuration";
    value.bridge.transport = "missing";
    value.bridge.access = "configured";
    value.bridge.missing = ["CORE_ACCESS_CLIENT_SECRET"];
  });
  add("missing access without a missing credential", (value) => {
    value.runner.connection = "pending_configuration";
    value.bridge.transport = "missing";
    value.bridge.access = "missing";
    value.bridge.missing = ["LIL_TWEAK_ENVIRONMENT"];
  });
  add("unknown missing name", (value) => {
    value.runner.connection = "pending_configuration";
    value.bridge.transport = "missing";
    value.bridge.signing = "missing";
    value.bridge.access = "missing";
    value.bridge.missing = ["SECRET_CANARY"];
  });
  add("duplicate missing name", (value) => {
    value.runner.connection = "pending_configuration";
    value.bridge.transport = "missing";
    value.bridge.signing = "missing";
    value.bridge.access = "missing";
    value.bridge.missing = ["CORE_SIGNING_SECRET", "CORE_SIGNING_SECRET"];
  });
  add("out-of-order missing names", (value) => {
    value.runner.connection = "pending_configuration";
    value.bridge.transport = "missing";
    value.bridge.signing = "missing";
    value.bridge.access = "missing";
    value.bridge.missing = ["CORE_SIGNING_KEY_ID", "CORE_SIGNING_SECRET"];
  });
  add("pending with configured diagnostics", (value) => { value.runner.connection = "pending_configuration"; });
  add("configured pending probe with missing signing", (value) => {
    value.runner.connection = "configured_pending_probe";
    value.bridge.signing = "missing";
  });
  add("unreachable with missing list", (value) => {
    value.runner.connection = "unreachable";
    value.bridge.missing = ["CORE_ORIGIN or CUSTOMER_HTTP_LIL_TWEAK_CORE"];
  });

  for (const [field, wrong] of Object.entries({
    owner: "other",
    provider: "other",
    dropletId: "1",
    host: "other",
    role: "other",
    route: "other",
    intermediary: "broker",
    imagePolicy: "tagged",
  })) {
    add(`wrong runner ${field}`, (value) => { value.runner[field] = wrong; });
  }

  for (const [label, value] of cases) {
    await context.test(label, async () => {
      assert.throws(() => engineeringClient.parseEngineeringConnectionStatus(value));
      await assert.rejects(() => statusThroughBrowser(value));
    });
  }
});
