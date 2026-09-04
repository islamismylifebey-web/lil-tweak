import { sha256Hex, signCoreRequest } from "./core-signing.ts";
import { coreAccessHeaders, validateCoreSigningConfig, validateCoreTransportConfig } from "./core-transport.ts";

const CORE_READY_TIMEOUT_MS = 5_000;
const CORE_READY_MAX_BYTES = 16 * 1024;
const CANONICAL_OWNER_SCOPE = "a0885bc0b2c079e996629061a723c74d";
const CHECK_NAMES = [
  "database",
  "runner",
  "git",
  "workspace",
  "evidence",
  "signing",
  "admission",
] as const;
const SIGNING_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export type EngineeringConnectionState =
  | "pending_configuration"
  | "configured_pending_probe"
  | "ready"
  | "unreachable";

export interface EngineeringConnectionBindings {
  DB?: unknown;
  FILES?: unknown;
  CORE_ORIGIN?: string;
  CUSTOMER_HTTP_LIL_TWEAK_CORE?: string;
  CORE_SIGNING_SECRET?: string;
  CORE_SIGNING_KEY_ID?: string;
  CORE_ACCESS_CLIENT_ID?: string;
  CORE_ACCESS_CLIENT_SECRET?: string;
  LIL_TWEAK_ENVIRONMENT?: string;
}

export interface EngineeringConnectionStatus {
  generatedAt: string;
  controlPlane: {
    storage: "configured" | "missing";
    d1: "configured" | "missing";
    r2: "configured" | "missing";
  };
  bridge: {
    origin: "none" | "core_origin" | "sites_private_tunnel";
    transport: "configured" | "missing";
    signing: "configured" | "missing";
    access: "configured" | "missing" | "not_required";
    missing: string[];
  };
  github: {
    lilTweak: {
      repository: "islamismylifebey-web/lil-tweak";
      branch: "main";
    };
  };
  runner: {
    owner: "lil-tweak";
    route: "direct_core_to_podman";
    intermediary: "none";
    imagePolicy: "digest_pinned";
    connection: EngineeringConnectionState;
    qualification: "not_reported";
    label: "Lil Tweak direct Podman runner";
  };
}

export interface EngineeringConnectionOptions {
  now?: () => Date;
  nonceFactory?: () => string;
  requestIdFactory?: () => string;
  probe?: boolean;
  fetcher?: typeof fetch;
}

function clean(value: string | undefined) {
  return value?.trim() ?? "";
}

function exactKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => actual.includes(key));
}

function exactReadyDocument(value: unknown): boolean {
  if (!exactKeys(value, ["status", "checks"]) || value.status !== "ready") return false;
  const checks = value.checks;
  if (!exactKeys(checks, CHECK_NAMES)) return false;
  return CHECK_NAMES.every((name) => checks[name] === true);
}

async function boundedBody(response: Response): Promise<Uint8Array | null> {
  const declared = response.headers.get("content-length");
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > CORE_READY_MAX_BYTES)) {
    await response.body?.cancel().catch(() => undefined);
    return null;
  }
  if (!response.body) return new Uint8Array();

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let overflow = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const remaining = CORE_READY_MAX_BYTES + 1 - total;
      const accepted = value.byteLength > remaining ? value.subarray(0, remaining) : value;
      chunks.push(accepted);
      total += accepted.byteLength;
      if (total > CORE_READY_MAX_BYTES) {
        overflow = true;
        await reader.cancel();
        return null;
      }
    }
  } finally {
    if (!overflow) reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

async function signedReadyProbe(
  origin: URL,
  accessHeaders: Record<string, string>,
  signing: { secret: string; keyId: string },
  ownerScope: string,
  generatedAt: Date,
  options: EngineeringConnectionOptions,
): Promise<boolean> {
  if (ownerScope !== CANONICAL_OWNER_SCOPE) return false;
  const path = "/readyz";
  const bodySha256 = await sha256Hex(new Uint8Array());
  const timestamp = Math.floor(generatedAt.getTime() / 1000).toString();
  const nonce = options.nonceFactory?.() ?? crypto.randomUUID().replaceAll("-", "");
  const requestId = options.requestIdFactory?.() ?? crypto.randomUUID();
  const signature = await signCoreRequest(signing.secret, {
    keyId: signing.keyId,
    method: "GET",
    pathAndQuery: path,
    timestamp,
    nonce,
    bodySha256,
    requestId,
    idempotencyKey: "",
    ownerKey: ownerScope,
  });
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CORE_READY_TIMEOUT_MS);
  try {
    const response = await (options.fetcher ?? fetch)(new URL(path, origin), {
      method: "GET",
      redirect: "error",
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        "X-Lil-Tweak-Key-Id": signing.keyId,
        "X-Lil-Tweak-Timestamp": timestamp,
        "X-Lil-Tweak-Nonce": nonce,
        "X-Lil-Tweak-Request-Id": requestId,
        "X-Lil-Tweak-Body-Sha256": bodySha256,
        "X-Lil-Tweak-Signature": signature,
        "X-Lil-Tweak-Owner": ownerScope,
        ...accessHeaders,
      },
    });
    if (response.status !== 200) return false;
    const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (mediaType !== "application/json") return false;
    const bytes = await boundedBody(response);
    if (bytes === null) return false;
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return exactReadyDocument(JSON.parse(text));
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

export async function engineeringConnectionStatus(
  bindings: EngineeringConnectionBindings,
  ownerScope: string,
  options: EngineeringConnectionOptions = {},
): Promise<EngineeringConnectionStatus> {
  const generatedAt = options.now?.() ?? new Date();
  const environment = clean(bindings.LIL_TWEAK_ENVIRONMENT);
  const coreOrigin = clean(bindings.CORE_ORIGIN);
  const privateOrigin = clean(bindings.CUSTOMER_HTTP_LIL_TWEAK_CORE);
  const usingPrivateBinding = !coreOrigin && Boolean(privateOrigin);
  const selectedOrigin = coreOrigin || privateOrigin;
  const accessClientId = clean(bindings.CORE_ACCESS_CLIENT_ID);
  const accessClientSecret = clean(bindings.CORE_ACCESS_CLIENT_SECRET);
  const signingSecret = clean(bindings.CORE_SIGNING_SECRET);
  const signingKeyId = clean(bindings.CORE_SIGNING_KEY_ID);
  const missing: string[] = [];

  if (!["development", "test", "production"].includes(environment)) {
    missing.push("LIL_TWEAK_ENVIRONMENT");
  }
  let originValid = false;
  try {
    const origin = new URL(selectedOrigin);
    originValid = Boolean(
      origin.protocol === "https:" && !origin.username && !origin.password &&
      origin.pathname === "/" && !origin.search && !origin.hash
    );
  } catch {
    originValid = false;
  }
  if (!originValid) missing.push("CORE_ORIGIN or CUSTOMER_HTTP_LIL_TWEAK_CORE");
  if (new TextEncoder().encode(signingSecret).byteLength < 32) {
    missing.push("CORE_SIGNING_SECRET");
  }
  if (!SIGNING_KEY_ID.test(signingKeyId)) missing.push("CORE_SIGNING_KEY_ID");
  const accessRequired = environment === "production" && !usingPrivateBinding;
  if (!accessClientId && (accessRequired || Boolean(accessClientSecret))) {
    missing.push("CORE_ACCESS_CLIENT_ID");
  }
  if (!accessClientSecret && (accessRequired || Boolean(accessClientId))) {
    missing.push("CORE_ACCESS_CLIENT_SECRET");
  }

  let transport: ReturnType<typeof validateCoreTransportConfig> | null = null;
  try {
    transport = validateCoreTransportConfig({
      environment,
      coreOrigin: selectedOrigin,
      accessClientId,
      accessClientSecret,
      privateBinding: usingPrivateBinding,
    });
  } catch {
    transport = null;
  }

  let signing: ReturnType<typeof validateCoreSigningConfig> | null = null;
  try {
    signing = validateCoreSigningConfig(signingSecret, signingKeyId);
  } catch {
    signing = null;
  }

  let ready = false;
  if (transport && signing && options.probe === true) {
    ready = await signedReadyProbe(
      transport.origin,
      coreAccessHeaders(transport),
      signing,
      ownerScope,
      generatedAt,
      options,
    );
  }
  const connection: EngineeringConnectionState = !transport || !signing
    ? "pending_configuration"
    : options.probe !== true
      ? "configured_pending_probe"
      : ready
        ? "ready"
        : "unreachable";

  const d1 = bindings.DB ? "configured" : "missing";
  const r2 = bindings.FILES ? "configured" : "missing";
  return {
    generatedAt: generatedAt.toISOString(),
    controlPlane: {
      storage: d1 === "configured" && r2 === "configured" ? "configured" : "missing",
      d1,
      r2,
    },
    bridge: {
      origin: selectedOrigin ? (usingPrivateBinding ? "sites_private_tunnel" : "core_origin") : "none",
      transport: transport ? "configured" : "missing",
      signing: signing ? "configured" : "missing",
      access: usingPrivateBinding || environment !== "production"
        ? "not_required"
        : accessClientId && accessClientSecret
          ? "configured"
          : "missing",
      missing,
    },
    github: {
      lilTweak: {
        repository: "islamismylifebey-web/lil-tweak",
        branch: "main",
      },
    },
    runner: {
      owner: "lil-tweak",
      route: "direct_core_to_podman",
      intermediary: "none",
      imagePolicy: "digest_pinned",
      connection,
      qualification: "not_reported",
      label: "Lil Tweak direct Podman runner",
    },
  };
}
