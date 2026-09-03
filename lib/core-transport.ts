export interface CoreTransportInput {
  environment?: string;
  coreOrigin?: string;
  accessClientId?: string;
  accessClientSecret?: string;
  privateBinding?: boolean;
}

export interface CoreTransportConfig {
  origin: URL;
  accessClientId: string | null;
  accessClientSecret: string | null;
  privateBinding: boolean;
}

export interface CoreSigningConfig {
  secret: string;
  keyId: string;
}

const SIGNING_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function unavailable(): never {
  throw new Error("The private engineering core is unavailable.");
}

export function validateCoreTransportConfig(input: CoreTransportInput): CoreTransportConfig {
  const environment = input.environment?.trim() || "";
  if (!["development", "test", "production"].includes(environment)) unavailable();
  let origin: URL;
  try {
    origin = new URL(input.coreOrigin ?? "");
  } catch {
    unavailable();
  }
  if (
    origin.protocol !== "https:" || origin.username || origin.password ||
    origin.pathname !== "/" || origin.search || origin.hash
  ) unavailable();
  const accessClientId = input.accessClientId?.trim() || null;
  const accessClientSecret = input.accessClientSecret?.trim() || null;
  const privateBinding = input.privateBinding === true;
  if (Boolean(accessClientId) !== Boolean(accessClientSecret)) unavailable();
  if (environment === "production" && !privateBinding && (!accessClientId || !accessClientSecret)) unavailable();
  return { origin, accessClientId, accessClientSecret, privateBinding };
}

export function validateCoreSigningConfig(
  secretValue: string | undefined,
  keyIdValue: string | undefined,
): CoreSigningConfig {
  const secret = secretValue ?? "";
  const keyId = keyIdValue ?? "";
  if (new TextEncoder().encode(secret).byteLength < 32 || !SIGNING_KEY_ID.test(keyId)) unavailable();
  return { secret, keyId };
}

export function coreAccessHeaders(config: CoreTransportConfig): Record<string, string> {
  if (!config.accessClientId || !config.accessClientSecret) return {};
  return {
    "CF-Access-Client-Id": config.accessClientId,
    "CF-Access-Client-Secret": config.accessClientSecret,
  };
}

export function publicCoreFailure(status: number): { status: number; message: string } {
  if (status === 409) {
    return { status, message: "Engineering job changed. Refresh and try again." };
  }
  if (status === 429) {
    return { status, message: "The private engineering core is at capacity. Try again shortly." };
  }
  return { status: 503, message: "The private engineering core is unavailable." };
}
