export interface ManagedIngressConfig {
  environment?: string;
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
  const secret = config.managedIngressSecret?.trim();
  if (!expectedOrigin) {
    throw new Error("Managed ingress configuration is incomplete.");
  }
  if (new URL(request.url).origin !== expectedOrigin) return false;
  if (!secret) return true;
  if (secret.length < 32) {
    throw new Error("Managed ingress configuration is incomplete.");
  }
  const assertion = request.headers.get("x-lil-tweak-managed-ingress") ?? "";
  return equalSecret(assertion, secret);
}
