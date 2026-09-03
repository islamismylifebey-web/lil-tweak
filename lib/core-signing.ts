export interface CoreRequestFields {
  keyId: string;
  method: string;
  pathAndQuery: string;
  timestamp: string;
  nonce: string;
  bodySha256: string;
  requestId: string;
  idempotencyKey: string;
  ownerKey: string;
}

const encoder = new TextEncoder();

function safeField(value: string, label: string): string {
  if (!value || value.includes("\n") || value.includes("\r")) {
    throw new Error(`${label} is invalid.`);
  }
  return value;
}

function safeOptionalField(value: string, label: string): string {
  if (value.includes("\n") || value.includes("\r")) {
    throw new Error(`${label} is invalid.`);
  }
  return value;
}

function queryComponent(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (character) =>
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

export function canonicalCoreTarget(value: string): string {
  const target = safeField(value, "Path");
  if (!target.startsWith("/") || target.includes("#")) {
    throw new Error("Path is invalid.");
  }
  const separator = target.indexOf("?");
  const path = separator === -1 ? target : target.slice(0, separator);
  const query = separator === -1 ? "" : target.slice(separator + 1);
  const pairs = [...new URLSearchParams(query).entries()]
    .sort(([leftKey, leftValue], [rightKey, rightValue]) => {
      if (leftKey < rightKey) return -1;
      if (leftKey > rightKey) return 1;
      if (leftValue < rightValue) return -1;
      if (leftValue > rightValue) return 1;
      return 0;
    });
  const canonicalQuery = pairs
    .map(([key, item]) => `${queryComponent(key)}=${queryComponent(item)}`)
    .join("&");
  return canonicalQuery ? `${path}?${canonicalQuery}` : path;
}

function toBuffer(value: Uint8Array | ArrayBuffer | string): ArrayBuffer {
  if (typeof value === "string") return encoder.encode(value).slice().buffer;
  if (value instanceof Uint8Array) return Uint8Array.from(value).buffer;
  return value.slice(0);
}

function hex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

export async function sha256Hex(value: Uint8Array | ArrayBuffer | string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", toBuffer(value)));
}

export function canonicalCoreRequest(fields: CoreRequestFields): string {
  const method = safeField(fields.method, "Method").toUpperCase();
  const bodyDigest = safeField(fields.bodySha256, "Body digest").toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(bodyDigest)) throw new Error("Body digest is invalid.");
  return [
    "v2",
    safeField(fields.keyId, "Key ID"),
    method,
    canonicalCoreTarget(fields.pathAndQuery),
    safeField(fields.timestamp, "Timestamp"),
    safeField(fields.nonce, "Nonce"),
    bodyDigest,
    safeField(fields.requestId, "Request ID"),
    safeOptionalField(fields.idempotencyKey, "Idempotency key"),
    safeField(fields.ownerKey, "Owner"),
  ].join("\n");
}

export async function signCoreRequest(
  secret: string,
  fields: CoreRequestFields,
): Promise<string> {
  if (!secret) throw new Error("Core signing secret is unavailable.");
  const key = await crypto.subtle.importKey(
    "raw",
    toBuffer(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return hex(
    await crypto.subtle.sign("HMAC", key, toBuffer(canonicalCoreRequest(fields))),
  );
}
