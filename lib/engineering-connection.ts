import { coreAccessHeaders, validateCoreSigningConfig, validateCoreTransportConfig } from "./core-transport.ts";

const LIL_TWEAK_MAIN_COMMIT = "191189c515b9dbd8ddb82e9ad3fc86853cc815df";
const LIL_TWEAK_PR6_MERGE_COMMIT = "08e3705227ec428d0b6ce6bc6d58dca3657b2683";
const GALOR_HUB_MAIN_COMMIT = "ac15ba6cf794375339528fe7c7e5b21a81bf34f0";
const GALOR_RUNNER_CONTRACT_VERSION = "1.0.0";
const GALOR_RUNNER_HOST = "galor-tweak-runner-01";
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
      head: string;
      pr6Merge: string;
    };
    galorHub: {
      repository: "islamismylifebey-web/galor-hub";
      branch: "main";
      head: string;
      pr28Merge: string;
    };
  };
  galor: {
    contract: "galor-runner";
    version: string;
    executionHost: string;
    integration: "awaiting_runtime_probe";
  };
  runner: {
    state: BridgeState;
    label: string;
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

function statusLabel(state: BridgeState) {
  if (state === "health_reachable") return "Core health reachable";
  if (state === "health_unreachable") return "Core health check failed";
  if (state === "configured_pending_probe") return "Runtime bridge configured";
  return "Runtime bridge pending";
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
        head: LIL_TWEAK_MAIN_COMMIT,
        pr6Merge: LIL_TWEAK_PR6_MERGE_COMMIT,
      },
      galorHub: {
        repository: "islamismylifebey-web/galor-hub",
        branch: "main",
        head: GALOR_HUB_MAIN_COMMIT,
        pr28Merge: GALOR_HUB_MAIN_COMMIT,
      },
    },
    galor: {
      contract: "galor-runner",
      version: GALOR_RUNNER_CONTRACT_VERSION,
      executionHost: GALOR_RUNNER_HOST,
      integration: "awaiting_runtime_probe",
    },
    runner: {
      state,
      label: statusLabel(state),
    },
  };
}
