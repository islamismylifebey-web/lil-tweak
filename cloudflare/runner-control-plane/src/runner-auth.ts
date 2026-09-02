import {
  asArrayBuffer,
  canonicalJson,
  fromBase64Url,
  PINNED_RUNNER_ID,
} from "./attestation";
import {
  parseClaimRequest,
  parseEvidenceRequest,
  parseExecutionId,
  type ClaimRequest,
  type EvidenceRequest,
} from "./protocol";
import {
  exactRecord,
  InputError,
  integerField,
  requireMatch,
  stringField,
} from "./validation";

export const RUNNER_REQUEST_SCHEMA = "lil-tweak.runner-request/v1";
export const MAX_RUNNER_REQUEST_SKEW_MS = 30_000;

const NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const BASE64_URL_PATTERN = /^[A-Za-z0-9_-]+$/;

export type RunnerOperation = "poll" | "claim" | "status" | "evidence";

interface RunnerPayloads {
  poll: Record<string, never>;
  claim: ClaimRequest;
  status: { execution_id: string };
  evidence: EvidenceRequest;
}

interface RunnerRequestPayload {
  schema_version: typeof RUNNER_REQUEST_SCHEMA;
  runner_id: typeof PINNED_RUNNER_ID;
  operation: RunnerOperation;
  request_nonce: string;
  issued_at_ms: number;
  payload: unknown;
}

export interface VerifiedRunnerRequest<Operation extends RunnerOperation> {
  operation: Operation;
  request_nonce: string;
  issued_at_ms: number;
  payload: RunnerPayloads[Operation];
}

export class RunnerAuthenticationError extends Error {
  constructor() {
    super("runner authentication failed");
    this.name = "RunnerAuthenticationError";
  }
}

function parseAuthenticationEnvelope(value: unknown): {
  request: RunnerRequestPayload;
  signature: Uint8Array;
} {
  try {
    const envelope = exactRecord(value, ["request", "signature"], "runner envelope");
    const request = exactRecord(
      envelope.request,
      [
        "schema_version",
        "runner_id",
        "operation",
        "request_nonce",
        "issued_at_ms",
        "payload",
      ],
      "runner request",
    );
    if (
      stringField(request, "schema_version", "runner request") !==
        RUNNER_REQUEST_SCHEMA ||
      stringField(request, "runner_id", "runner request") !== PINNED_RUNNER_ID
    ) {
      throw new RunnerAuthenticationError();
    }
    const operation = stringField(request, "operation", "runner request");
    if (
      operation !== "poll" &&
      operation !== "claim" &&
      operation !== "status" &&
      operation !== "evidence"
    ) {
      throw new RunnerAuthenticationError();
    }
    const requestNonce = requireMatch(
      stringField(request, "request_nonce", "runner request"),
      NONCE_PATTERN,
      "runner request nonce",
    );
    if (fromBase64Url(requestNonce).byteLength !== 32) {
      throw new RunnerAuthenticationError();
    }
    const signatureText = requireMatch(
      stringField(envelope, "signature", "runner envelope"),
      BASE64_URL_PATTERN,
      "runner signature",
    );
    const signature = fromBase64Url(signatureText);
    if (signatureText.length !== 86 || signature.byteLength !== 64) {
      throw new RunnerAuthenticationError();
    }
    return {
      request: {
        schema_version: RUNNER_REQUEST_SCHEMA,
        runner_id: PINNED_RUNNER_ID,
        operation,
        request_nonce: requestNonce,
        issued_at_ms: integerField(request, "issued_at_ms", "runner request"),
        payload: request.payload,
      },
      signature,
    };
  } catch (error) {
    if (error instanceof RunnerAuthenticationError) {
      throw error;
    }
    throw new RunnerAuthenticationError();
  }
}

function parseOperationPayload<Operation extends RunnerOperation>(
  operation: Operation,
  value: unknown,
): RunnerPayloads[Operation] {
  let parsed: RunnerPayloads[RunnerOperation];
  switch (operation) {
    case "poll":
      exactRecord(value, [], "runner poll payload");
      parsed = {};
      break;
    case "claim":
      parsed = parseClaimRequest(value);
      break;
    case "status": {
      const status = exactRecord(value, ["execution_id"], "runner status payload");
      parsed = {
        execution_id: parseExecutionId(
          stringField(status, "execution_id", "runner status payload"),
        ),
      };
      break;
    }
    case "evidence":
      parsed = parseEvidenceRequest(value);
      break;
  }
  return parsed as RunnerPayloads[Operation];
}

export async function verifyRunnerRequest<Operation extends RunnerOperation>(
  value: unknown,
  expectedOperation: Operation,
  publicKeyText: string | undefined,
  nowMs: number,
): Promise<VerifiedRunnerRequest<Operation>> {
  const envelope = parseAuthenticationEnvelope(value);
  if (
    envelope.request.operation !== expectedOperation ||
    envelope.request.issued_at_ms < nowMs - MAX_RUNNER_REQUEST_SKEW_MS ||
    envelope.request.issued_at_ms > nowMs + MAX_RUNNER_REQUEST_SKEW_MS
  ) {
    throw new RunnerAuthenticationError();
  }
  let publicKey: Uint8Array;
  try {
    if (typeof publicKeyText !== "string") {
      throw new InputError("runner public key is missing");
    }
    publicKey = fromBase64Url(publicKeyText);
    if (publicKey.byteLength !== 32) {
      throw new InputError("runner public key length is invalid");
    }
  } catch {
    throw new RunnerAuthenticationError();
  }
  const key = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(publicKey),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const domain = `lil-tweak.runner-request/${expectedOperation}/v1`;
  const verified = await crypto.subtle.verify(
    "Ed25519",
    key,
    asArrayBuffer(envelope.signature),
    new TextEncoder().encode(`${domain}\n${canonicalJson(envelope.request)}`),
  );
  if (!verified) {
    throw new RunnerAuthenticationError();
  }
  return {
    operation: expectedOperation,
    request_nonce: envelope.request.request_nonce,
    issued_at_ms: envelope.request.issued_at_ms,
    payload: parseOperationPayload(expectedOperation, envelope.request.payload),
  };
}
