export interface ManagedIngressConfig {
  environment?: string;
  ingressMode?: string;
  publicOrigin?: string;
  managedIngressSecret?: string;
}

function exactHttpsOrigin(value: string | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" || url.username || url.password ||
      url.pathname !== "/" || url.search || url.hash
    ) return null;
    return url.origin;
  } catch {
    return null;
  }
}

async function equalSecret(left: string, right: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [leftHash, rightHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(left)),
    crypto.subtle.digest("SHA-256", encoder.encode(right)),
  ]);
  const leftBytes = new Uint8Array(leftHash);
  const rightBytes = new Uint8Array(rightHash);
  let difference = 0;
  for (let index = 0; index < leftBytes.length; index += 1) {
    difference |= leftBytes[index] ^ rightBytes[index];
  }
  return difference === 0;
}

export async function enforceManagedIngress(
  request: Request,
  config: ManagedIngressConfig,
): Promise<boolean> {
  const environment = config.environment?.trim() || "";
  if (!["development", "test", "production"].includes(environment)) {
    throw new Error("Managed ingress configuration is invalid.");
  }
  if (environment !== "production") return true;
  const expectedOrigin = exactHttpsOrigin(config.publicOrigin);
  const mode = config.ingressMode;
  const secret = config.managedIngressSecret?.trim();
  if (!expectedOrigin || !["sites_native", "managed_assertion"].includes(mode ?? "")) {
    throw new Error("Managed ingress configuration is incomplete.");
  }
  if (mode === "sites_native") {
    const origin = new URL(expectedOrigin);
    if (
      !origin.hostname.endsWith(".chatgpt.site") || origin.port ||
      config.managedIngressSecret !== undefined
    ) {
      throw new Error("Managed ingress configuration is invalid.");
    }
    if (new URL(request.url).origin !== expectedOrigin) return false;
    // Sites dispatch authenticates the session. Identity presence does not replace
    // the independent owner allowlist and same-origin checks in application routes.
    return Boolean(
      request.headers.get("oai-authenticated-user-id")?.trim() &&
      request.headers.get("oai-authenticated-user-email")?.trim(),
    );
  }
  if (!secret || new TextEncoder().encode(secret).byteLength < 32) {
    throw new Error("Managed ingress configuration is incomplete.");
  }
  if (new URL(request.url).origin !== expectedOrigin) return false;
  const assertion = request.headers.get("x-lil-tweak-managed-ingress") ?? "";
  return equalSecret(assertion, secret);
}
