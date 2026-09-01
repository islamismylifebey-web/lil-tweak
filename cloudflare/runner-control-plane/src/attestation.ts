import {
  exactRecord,
  InputError,
  integerField,
  requireMatch,
  stringField,
} from "./validation";

export const DISPATCH_ATTESTATION_SCHEMA = "lil-tweak.dispatch-attestation/v1";
export const PINNED_RUNNER_ID = "galor-tweak-runner-01";
export const PINNED_RUNNER_ROLE = "role-tweak-runner";
export const MAX_ATTESTATION_TTL_MS = 5 * 60 * 1000;
export const MAX_CLOCK_SKEW_MS = 30 * 1000;

const DIGEST_PATTERN = /^[a-f0-9]{64}$/;
const EXECUTION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const KEY_ID_PATTERN = /^[a-f0-9]{64}$/;
const BASE64_URL_PATTERN = /^[A-Za-z0-9_-]+$/;

export interface DispatchAttestationPayload {
  schema_version: typeof DISPATCH_ATTESTATION_SCHEMA;
  execution_id: string;
  runner_id: typeof PINNED_RUNNER_ID;
  runner_role: typeof PINNED_RUNNER_ROLE;
  lease_digest: string;
  contract_digest: string;
  commands_digest: string;
  approval_digest: string;
  policy_digest: string;
  attempt_nonce: string;
  issued_at_ms: number;
  expires_at_ms: number;
}

export interface SignedDispatchAttestation {
  key_id: string;
  attestation: DispatchAttestationPayload;
  signature: string;
}

export interface AttestationVerifierBindings {
  LIL_TWEAK_ATTESTATION_KEY_ID: string;
  LIL_TWEAK_ATTESTATION_PUBLIC_KEY: string;
}

export interface VerifiedDispatchAttestation {
  attestation: SignedDispatchAttestation;
  attestation_digest: string;
}

function stringifyCanonical(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new InputError("canonical JSON does not allow non-finite numbers");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stringifyCanonical(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stringifyCanonical(record[key])}`)
      .join(",")}}`;
  }
  throw new InputError("canonical JSON only supports JSON values");
}

/** Canonical signing bytes are UTF-8 recursively key-sorted JSON, without a domain prefix. */
export function canonicalJson(value: unknown): string {
  return stringifyCanonical(value);
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

export function fromBase64Url(value: string): Uint8Array {
  requireMatch(value, BASE64_URL_PATTERN, "base64url value");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(
    Math.ceil(value.length / 4) * 4,
    "=",
  );
  try {
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new InputError("base64url value has an invalid encoding");
  }
}

export function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

function parsePayload(value: unknown): DispatchAttestationPayload {
  const payload = exactRecord(
    value,
    [
      "schema_version",
      "execution_id",
      "runner_id",
      "runner_role",
      "lease_digest",
      "contract_digest",
      "commands_digest",
      "approval_digest",
      "policy_digest",
      "attempt_nonce",
      "issued_at_ms",
      "expires_at_ms",
    ],
    "attestation.payload",
  );
  const schemaVersion = stringField(payload, "schema_version", "attestation.payload");
  if (schemaVersion !== DISPATCH_ATTESTATION_SCHEMA) {
    throw new InputError("attestation payload uses an unsupported schema");
  }
  const executionId = requireMatch(
    stringField(payload, "execution_id", "attestation.payload"),
    EXECUTION_ID_PATTERN,
    "execution_id",
  );
  const runnerId = stringField(payload, "runner_id", "attestation.payload");
  const runnerRole = stringField(payload, "runner_role", "attestation.payload");
  if (runnerId !== PINNED_RUNNER_ID || runnerRole !== PINNED_RUNNER_ROLE) {
    throw new InputError("attestation is not pinned to the approved runner identity");
  }
  const digestFields = [
    "lease_digest",
    "contract_digest",
    "commands_digest",
    "approval_digest",
    "policy_digest",
  ] as const;
  const digests = Object.fromEntries(
    digestFields.map((field) => [
      field,
      requireMatch(
        stringField(payload, field, "attestation.payload"),
        DIGEST_PATTERN,
        field,
      ),
    ]),
  ) as Record<(typeof digestFields)[number], string>;
  const attemptNonce = requireMatch(
    stringField(payload, "attempt_nonce", "attestation.payload"),
    NONCE_PATTERN,
    "attempt_nonce",
  );
  if (fromBase64Url(attemptNonce).byteLength !== 32) {
    throw new InputError("attempt_nonce must encode exactly 32 bytes");
  }
  const issuedAt = integerField(payload, "issued_at_ms", "attestation.payload");
  const expiresAt = integerField(payload, "expires_at_ms", "attestation.payload");
  return {
    schema_version: DISPATCH_ATTESTATION_SCHEMA,
    execution_id: executionId,
    runner_id: PINNED_RUNNER_ID,
    runner_role: PINNED_RUNNER_ROLE,
    ...digests,
    attempt_nonce: attemptNonce,
    issued_at_ms: issuedAt,
    expires_at_ms: expiresAt,
  };
}

function parseSignedAttestation(value: unknown): SignedDispatchAttestation {
  const envelope = exactRecord(
    value,
    ["key_id", "attestation", "signature"],
    "attestation",
  );
  return {
    key_id: requireMatch(
      stringField(envelope, "key_id", "attestation"),
      KEY_ID_PATTERN,
      "attestation key_id",
    ),
    attestation: parsePayload(envelope.attestation),
    signature: requireMatch(
      stringField(envelope, "signature", "attestation"),
      BASE64_URL_PATTERN,
      "attestation signature",
    ),
  };
}

export async function verifyDispatchAttestation(
  input: unknown,
  bindings: AttestationVerifierBindings,
  nowMs: number,
): Promise<VerifiedDispatchAttestation> {
  const attestation = parseSignedAttestation(input);
  if (attestation.key_id !== bindings.LIL_TWEAK_ATTESTATION_KEY_ID) {
    throw new InputError("attestation key is not authorized");
  }
  const { issued_at_ms: issuedAt, expires_at_ms: expiresAt } =
    attestation.attestation;
  if (
    issuedAt > nowMs + MAX_CLOCK_SKEW_MS ||
    expiresAt <= nowMs ||
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > MAX_ATTESTATION_TTL_MS
  ) {
    throw new InputError("attestation has an invalid validity window");
  }
  const publicKey = fromBase64Url(bindings.LIL_TWEAK_ATTESTATION_PUBLIC_KEY);
  if (publicKey.byteLength !== 32) {
    throw new InputError("attestation public key has an invalid length");
  }
  const signature = fromBase64Url(attestation.signature);
  if (attestation.signature.length !== 86 || signature.byteLength !== 64) {
    throw new InputError("attestation signature has an invalid length");
  }
  const importedKey = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(publicKey),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const isValid = await crypto.subtle.verify(
    "Ed25519",
    importedKey,
    asArrayBuffer(signature),
    new TextEncoder().encode(canonicalJson(attestation.attestation)),
  );
  if (!isValid) {
    throw new InputError("attestation signature is invalid");
  }
  return {
    attestation,
    attestation_digest: await sha256Hex(canonicalJson(attestation)),
  };
}
