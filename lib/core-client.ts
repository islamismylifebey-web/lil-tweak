import { env } from "cloudflare:workers";
import { parseCoreSnapshot, parseCoreSnapshotForJob } from "./core-protocol";
import { sha256Hex, signCoreRequest } from "./core-signing";
import { coreAccessHeaders, validateCoreSigningConfig, validateCoreTransportConfig } from "./core-transport";
import { MAX_ENGINEERING_EVIDENCE_BYTES } from "./engineering.ts";

const MAX_CORE_RESPONSE_BYTES = 256 * 1024;
const CORE_TIMEOUT_MS = 10_000;
const EVIDENCE_TIMEOUT_MS = 30_000;

interface CoreBindings {
  CORE_ORIGIN?: string;
  CUSTOMER_HTTP_LIL_TWEAK_CORE?: string;
  CORE_SIGNING_SECRET?: string;
  CORE_SIGNING_KEY_ID?: string;
  CORE_ACCESS_CLIENT_ID?: string;
  CORE_ACCESS_CLIENT_SECRET?: string;
  LIL_TWEAK_ENVIRONMENT?: string;
}

export class CoreUnavailableError extends Error {
  constructor() {
    super("The private engineering core is unavailable.");
  }
}

export class CoreRejectedError extends Error {
  readonly status: number;
  constructor(status: number) {
    super("The private engineering core rejected the request.");
    this.status = status;
  }
}

function bindings() {
  return env as unknown as CoreBindings;
}

function transportConfig() {
  try {
    const values = bindings();
    const coreOrigin = values.CORE_ORIGIN?.trim() || "";
    const privateCoreOrigin = values.CUSTOMER_HTTP_LIL_TWEAK_CORE?.trim() || "";
    return validateCoreTransportConfig({
      environment: values.LIL_TWEAK_ENVIRONMENT,
      coreOrigin: coreOrigin || privateCoreOrigin,
      accessClientId: values.CORE_ACCESS_CLIENT_ID,
      accessClientSecret: values.CORE_ACCESS_CLIENT_SECRET,
      privateBinding: !coreOrigin && Boolean(privateCoreOrigin),
    });
  } catch {
    throw new CoreUnavailableError();
  }
}

async function boundedResponse(response: Response, maxBytes = MAX_CORE_RESPONSE_BYTES) {
  const declared = response.headers.get("content-length");
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > maxBytes)) {
    throw new CoreUnavailableError();
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new CoreUnavailableError();
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function coreJson(value: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(value));
  } catch {
    throw new CoreUnavailableError();
  }
}

async function signedCoreRequest(
  method: string,
  path: string,
  body: unknown | undefined,
  idempotencyKey: string,
  ownerKey: string,
  maxResponseBytes = MAX_CORE_RESPONSE_BYTES,
  timeoutMs = CORE_TIMEOUT_MS,
) {
  const transport = transportConfig();
  let signing;
  try {
    signing = validateCoreSigningConfig(bindings().CORE_SIGNING_SECRET, bindings().CORE_SIGNING_KEY_ID);
  } catch {
    throw new CoreUnavailableError();
  }
  const payload = body === undefined ? new Uint8Array() : new TextEncoder().encode(JSON.stringify(body));
  if (!/^[a-f0-9]{32}$/.test(ownerKey)) throw new CoreUnavailableError();
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = crypto.randomUUID().replaceAll("-", "");
  const requestId = crypto.randomUUID();
  const digest = await sha256Hex(payload);
  const signature = await signCoreRequest(signing.secret, {
    keyId: signing.keyId,
    method,
    pathAndQuery: path,
    timestamp,
    nonce,
    bodySha256: digest,
    requestId,
    idempotencyKey,
    ownerKey,
  });
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(new URL(path, transport.origin), {
      method,
      redirect: "error",
      body: payload.byteLength ? payload : undefined,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(payload.byteLength ? { "Content-Type": "application/json" } : {}),
        "X-Lil-Tweak-Key-Id": signing.keyId,
        "X-Lil-Tweak-Timestamp": timestamp,
        "X-Lil-Tweak-Nonce": nonce,
        "X-Lil-Tweak-Request-Id": requestId,
        "X-Lil-Tweak-Body-Sha256": digest,
        "X-Lil-Tweak-Signature": signature,
        "X-Lil-Tweak-Owner": ownerKey,
        "Idempotency-Key": idempotencyKey,
        ...coreAccessHeaders(transport),
      },
    });
    const bytes = await boundedResponse(response, maxResponseBytes);
    if (!response.ok) throw new CoreRejectedError(response.status);
    return { response, bytes };
  } catch (error) {
    if (error instanceof CoreRejectedError || error instanceof CoreUnavailableError) throw error;
    throw new CoreUnavailableError();
  } finally {
    clearTimeout(timeout);
  }
}

async function signedCoreJson(
  method: string,
  path: string,
  body: unknown | undefined,
  idempotencyKey: string,
  ownerKey: string,
) {
  const result = await signedCoreRequest(method, path, body, idempotencyKey, ownerKey);
  if (!result.response.headers.get("content-type")?.toLowerCase().includes("application/json")) {
    throw new CoreUnavailableError();
  }
  return coreJson(result.bytes);
}

function parsedSnapshot(value: unknown) {
  try {
    return parseCoreSnapshot(value);
  } catch {
    throw new CoreUnavailableError();
  }
}

function parsedSnapshotForJob(value: unknown, expectedRemoteJobId: string) {
  try {
    return parseCoreSnapshotForJob(value, expectedRemoteJobId);
  } catch {
    throw new CoreUnavailableError();
  }
}

export async function createCoreJob(ownerKey: string, body: unknown, idempotencyKey: string) {
  return parsedSnapshot(await signedCoreJson("POST", "/v1/jobs", body, idempotencyKey, ownerKey));
}

export async function getCoreJob(ownerKey: string, remoteJobId: string, idempotencyKey: string) {
  return parsedSnapshotForJob(
    await signedCoreJson("GET", `/v1/jobs/${encodeURIComponent(remoteJobId)}`, undefined, idempotencyKey, ownerKey),
    remoteJobId,
  );
}

export async function decideCoreJob(ownerKey: string, remoteJobId: string, body: unknown, idempotencyKey: string) {
  return parsedSnapshotForJob(
    await signedCoreJson("POST", `/v1/jobs/${encodeURIComponent(remoteJobId)}/decisions`, body, idempotencyKey, ownerKey),
    remoteJobId,
  );
}

export async function exportCorePatch(ownerKey: string, remoteJobId: string, body: unknown, idempotencyKey: string) {
  return parsedSnapshotForJob(
    await signedCoreJson("POST", `/v1/jobs/${encodeURIComponent(remoteJobId)}/exports/patch`, body, idempotencyKey, ownerKey),
    remoteJobId,
  );
}

export async function cancelCoreJob(ownerKey: string, remoteJobId: string, body: unknown, idempotencyKey: string) {
  return parsedSnapshotForJob(
    await signedCoreJson("POST", `/v1/jobs/${encodeURIComponent(remoteJobId)}/cancel`, body, idempotencyKey, ownerKey),
    remoteJobId,
  );
}

export async function getCoreEvidence(
  ownerKey: string,
  remoteJobId: string,
  corePath: string,
  expectedSha256: string,
  idempotencyKey: string,
) {
  const expectedPrefix = `/v1/jobs/${encodeURIComponent(remoteJobId)}/evidence/`;
  if (!corePath.startsWith(expectedPrefix) || corePath.includes("?") || !/^[a-f0-9]{64}$/.test(expectedSha256)) {
    throw new CoreUnavailableError();
  }
  const { response, bytes } = await signedCoreRequest(
    "GET",
    corePath,
    undefined,
    idempotencyKey,
    ownerKey,
    MAX_ENGINEERING_EVIDENCE_BYTES,
    EVIDENCE_TIMEOUT_MS,
  );
  const declared = response.headers.get("content-length");
  const responseDigest = response.headers.get("x-content-sha256");
  if (
    !declared ||
    !/^\d+$/.test(declared) ||
    Number(declared) !== bytes.byteLength ||
    responseDigest !== expectedSha256 ||
    await sha256Hex(bytes) !== expectedSha256
  ) {
    throw new CoreUnavailableError();
  }
  return {
    bytes,
    sizeBytes: bytes.byteLength,
    sha256: expectedSha256,
    mediaType: response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() || "application/octet-stream",
  };
}
