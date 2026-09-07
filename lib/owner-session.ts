export const SESSION_COOKIE = "__Host-lil_tweak_session";
export const SESSION_MAX_AGE = 30 * 24 * 60 * 60;
const PASSWORD_ITERATIONS = 100_000;
const encoder = new TextEncoder();

function requiredSecret(
  name: "LIL_TWEAK_PASSWORD_SALT" | "LIL_TWEAK_PASSWORD_HASH" | "LIL_TWEAK_SESSION_SECRET",
) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error("Lil Tweak owner login is not configured.");
  return value;
}

function encodeBase64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value: string) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Invalid base64url value.");
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function configuredBytes(
  name: "LIL_TWEAK_PASSWORD_SALT" | "LIL_TWEAK_PASSWORD_HASH" | "LIL_TWEAK_SESSION_SECRET",
  minimum: number,
  exact = false,
) {
  const bytes = decodeBase64Url(requiredSecret(name));
  if ((exact && bytes.length !== minimum) || (!exact && bytes.length < minimum)) {
    throw new Error("Lil Tweak owner login is not configured.");
  }
  return bytes;
}

async function passwordDigest(password: string) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: configuredBytes("LIL_TWEAK_PASSWORD_SALT", 16),
      iterations: PASSWORD_ITERATIONS,
    },
    key,
    256,
  );
  return new Uint8Array(bits);
}

export async function verifyOwnerPassword(password: string) {
  if (!password || password.length > 256) return false;
  try {
    const expected = configuredBytes("LIL_TWEAK_PASSWORD_HASH", 32, true);
    const actual = await passwordDigest(password);
    let difference = actual.length ^ expected.length;
    for (let index = 0; index < Math.min(actual.length, expected.length); index += 1) {
      difference |= actual[index] ^ expected[index];
    }
    return difference === 0;
  } catch {
    return false;
  }
}

async function signingKey() {
  return crypto.subtle.importKey(
    "raw",
    configuredBytes("LIL_TWEAK_SESSION_SECRET", 32),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export async function createOwnerSessionToken(now = Date.now()) {
  const payload = encodeBase64Url(
    encoder.encode(JSON.stringify({
      v: 1,
      sub: "owner",
      iat: Math.floor(now / 1000),
      exp: Math.floor(now / 1000) + SESSION_MAX_AGE,
    })),
  );
  const signature = await crypto.subtle.sign("HMAC", await signingKey(), encoder.encode(payload));
  return `${payload}.${encodeBase64Url(new Uint8Array(signature))}`;
}

export async function verifyOwnerSessionToken(token: string | undefined, now = Date.now()) {
  if (!token || token.length > 1024) return false;
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return false;
  try {
    const validSignature = await crypto.subtle.verify(
      "HMAC",
      await signingKey(),
      decodeBase64Url(parts[1]),
      encoder.encode(parts[0]),
    );
    if (!validSignature) return false;
    const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[0]))) as {
      v?: unknown;
      sub?: unknown;
      iat?: unknown;
      exp?: unknown;
    };
    const nowSeconds = Math.floor(now / 1000);
    return payload.v === 1 && payload.sub === "owner" &&
      typeof payload.iat === "number" && payload.iat <= nowSeconds + 60 &&
      typeof payload.exp === "number" && payload.exp > nowSeconds;
  } catch {
    return false;
  }
}

export function sessionCookie(token: string) {
  return `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${SESSION_MAX_AGE}; HttpOnly; Secure; SameSite=Strict`;
}

export function expiredSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}
