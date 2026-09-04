import { coreAccessHeaders, validateCoreSigningConfig, validateCoreTransportConfig } from "./core-transport.ts";

const CORE_HEALTH_TIMEOUT_MS = 5_000;
const CORE_HEALTH_MAX_BYTES = 16 * 1024;

export type BridgeState =
  | "pending_configuration"
  | "configured_pending_probe"
  | "health_reachable"
  | "health_unreachable";

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
    state: BridgeState;
    origin: "none" | "core_origin" | "sites_private_tunnel";
    transport: "configured" | "missing";
    signing: "configured" | "missing";
    access: "configured" | "missing" | "not_required";
    health: "not_checked" | "ok" | "failed";
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
    connection: "not_reported";
    qualification: "not_reported";
    label: "Lil Tweak direct Podman runner";
  };
}

export interface EngineeringConnectionOptions {
  now?: () => Date;
  probe?: boolean;
  fetcher?: typeof fetch;
}

function clean(value: string | undefined) {
  return value?.trim() ?? "";
}

async function boundedHealthProbe(url: URL, headers: Record<string, string>, fetcher: typeof fetch) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CORE_HEALTH_TIMEOUT_MS);
  try {
    const response = await fetcher(url, {
      method: "GET",
      redirect: "error",
      signal: controller.signal,
      headers: { Accept: "application/json", ...headers },
    });
    const declared = response.headers.get("content-length");
    if (declared && (!/^\d+$/.test(declared) || Number(declared) > CORE_HEALTH_MAX_BYTES)) {
      return false;
    }
    const body = await response.arrayBuffer();
    return response.ok && body.byteLength <= CORE_HEALTH_MAX_BYTES;
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

export async function engineeringConnectionStatus(
  bindings: EngineeringConnectionBindings,
  options: EngineeringConnectionOptions = {},
): Promise<EngineeringConnectionStatus> {
  const environment = clean(bindings.LIL_TWEAK_ENVIRONMENT);
  const coreOrigin = clean(bindings.CORE_ORIGIN);
  const privateOrigin = clean(bindings.CUSTOMER_HTTP_LIL_TWEAK_CORE);
  const usingPrivateBinding = !coreOrigin && Boolean(privateOrigin);
  const selectedOrigin = coreOrigin || privateOrigin;
  const accessClientId = clean(bindings.CORE_ACCESS_CLIENT_ID);
  const accessClientSecret = clean(bindings.CORE_ACCESS_CLIENT_SECRET);
  const signingSecret = clean(bindings.CORE_SIGNING_SECRET);
  const signingKeyId = clean(bindings.CORE_SIGNING_KEY_ID);
  const missing = new Set<string>();

  if (!environment) missing.add("LIL_TWEAK_ENVIRONMENT");
  if (!selectedOrigin) missing.add("CORE_ORIGIN or CUSTOMER_HTTP_LIL_TWEAK_CORE");
  if (!signingSecret) missing.add("CORE_SIGNING_SECRET");
  if (!signingKeyId) missing.add("CORE_SIGNING_KEY_ID");
  if (environment === "production" && !usingPrivateBinding) {
    if (!accessClientId) missing.add("CORE_ACCESS_CLIENT_ID");
    if (!accessClientSecret) missing.add("CORE_ACCESS_CLIENT_SECRET");
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

  let signing = false;
  try {
    validateCoreSigningConfig(signingSecret, signingKeyId);
    signing = true;
  } catch {
    signing = false;
  }

  let health: EngineeringConnectionStatus["bridge"]["health"] = "not_checked";
  if (transport && signing && options.probe === true) {
    health = await boundedHealthProbe(
      new URL("/healthz", transport.origin),
      coreAccessHeaders(transport),
      options.fetcher ?? fetch,
    ) ? "ok" : "failed";
  }

  let state: BridgeState = "pending_configuration";
  if (transport && signing) {
    state = health === "ok"
      ? "health_reachable"
      : health === "failed"
        ? "health_unreachable"
        : "configured_pending_probe";
  }

  const d1 = bindings.DB ? "configured" : "missing";
  const r2 = bindings.FILES ? "configured" : "missing";
  return {
    generatedAt: (options.now?.() ?? new Date()).toISOString(),
    controlPlane: {
      storage: d1 === "configured" && r2 === "configured" ? "configured" : "missing",
      d1,
      r2,
    },
    bridge: {
      state,
      origin: selectedOrigin ? (usingPrivateBinding ? "sites_private_tunnel" : "core_origin") : "none",
      transport: transport ? "configured" : "missing",
      signing: signing ? "configured" : "missing",
      access: usingPrivateBinding || environment !== "production"
        ? "not_required"
        : accessClientId && accessClientSecret
          ? "configured"
          : "missing",
      health,
      missing: Array.from(missing),
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
      connection: "not_reported",
      qualification: "not_reported",
      label: "Lil Tweak direct Podman runner",
    },
  };
}
