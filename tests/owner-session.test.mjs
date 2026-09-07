import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 100_000 },
    key,
    256,
  );
  return base64Url(new Uint8Array(bits));
}

async function loadOwnerSession() {
  const [typescript, source] = await Promise.all([
    import("typescript"),
    readFile(new URL("../lib/owner-session.ts", import.meta.url), "utf8"),
  ]);
  const transpiled = typescript.transpileModule(source, {
    compilerOptions: {
      module: typescript.ModuleKind.ESNext,
      target: typescript.ScriptTarget.ES2022,
    },
  }).outputText;
  return import(`data:text/javascript;base64,${Buffer.from(transpiled).toString("base64")}`);
}

test("owner password verification uses the configured PBKDF2 verifier", async () => {
  const salt = Uint8Array.from({ length: 16 }, (_, index) => index + 1);
  process.env.LIL_TWEAK_PASSWORD_SALT = base64Url(salt);
  process.env.LIL_TWEAK_PASSWORD_HASH = await passwordHash("correct horse battery staple", salt);
  process.env.LIL_TWEAK_SESSION_SECRET = base64Url(crypto.getRandomValues(new Uint8Array(32)));

  const session = await loadOwnerSession();
  assert.equal(await session.verifyOwnerPassword("correct horse battery staple"), true);
  assert.equal(await session.verifyOwnerPassword("wrong"), false);
  assert.equal(await session.verifyOwnerPassword("x".repeat(257)), false);
});

test("owner session tokens are signed, expiring, and tamper evident", async () => {
  process.env.LIL_TWEAK_PASSWORD_SALT = base64Url(crypto.getRandomValues(new Uint8Array(16)));
  process.env.LIL_TWEAK_PASSWORD_HASH = base64Url(crypto.getRandomValues(new Uint8Array(32)));
  process.env.LIL_TWEAK_SESSION_SECRET = base64Url(crypto.getRandomValues(new Uint8Array(32)));

  const session = await loadOwnerSession();
  const now = Date.UTC(2026, 8, 7, 12, 0, 0);
  const token = await session.createOwnerSessionToken(now);
  assert.equal(await session.verifyOwnerSessionToken(token, now + 60_000), true);
  assert.equal(await session.verifyOwnerSessionToken(`${token}x`, now + 60_000), false);
  assert.equal(await session.verifyOwnerSessionToken(token, now + session.SESSION_MAX_AGE * 1000 + 1), false);
});

test("owner session cookies are host-only, httpOnly, secure, and strict same-site", async () => {
  process.env.LIL_TWEAK_PASSWORD_SALT = base64Url(crypto.getRandomValues(new Uint8Array(16)));
  process.env.LIL_TWEAK_PASSWORD_HASH = base64Url(crypto.getRandomValues(new Uint8Array(32)));
  process.env.LIL_TWEAK_SESSION_SECRET = base64Url(crypto.getRandomValues(new Uint8Array(32)));

  const session = await loadOwnerSession();
  const cookie = session.sessionCookie("token");
  assert.match(cookie, /^__Host-lil_tweak_session=token;/);
  assert.match(cookie, /Path=\//);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /SameSite=Strict/);
  assert.doesNotMatch(cookie, /Domain=/i);

  const expired = session.expiredSessionCookie();
  assert.match(expired, /Max-Age=0/);
  assert.match(expired, /SameSite=Strict/);
});
