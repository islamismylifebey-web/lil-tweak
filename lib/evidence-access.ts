import { sha256Hex } from "./core-signing.ts";
import {
  MAX_ENGINEERING_EVIDENCE_BYTES,
  type EngineeringEvidence,
} from "./engineering.ts";

type EvidenceCategory = EngineeringEvidence["category"];

export function directEvidenceDownloadAllowed(category: EvidenceCategory): boolean {
  return category !== "patch";
}

interface PatchExportRequest {
  approvalToken: string;
  attemptId: string;
}

interface EvidenceObjectBody {
  size: number;
  body: ReadableStream<Uint8Array> | null;
  customMetadata?: Record<string, string>;
}

interface EvidenceDescriptor {
  sizeBytes: number;
  sha256: string;
}

const ATTEMPT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TOKEN = /^[A-Za-z0-9_-]{32,128}$/;

export function parsePatchExportRequest(value: unknown): PatchExportRequest {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Patch export request is invalid.");
  }
  const input = value as Record<string, unknown>;
  if (
    Object.keys(input).length !== 2 ||
    typeof input.approvalToken !== "string" ||
    !TOKEN.test(input.approvalToken) ||
    typeof input.attemptId !== "string" ||
    !ATTEMPT_ID.test(input.attemptId)
  ) {
    throw new Error("Patch export request is invalid.");
  }
  return { approvalToken: input.approvalToken, attemptId: input.attemptId };
}

async function verifiedEvidenceBytes(
  object: EvidenceObjectBody | null,
  descriptor: EvidenceDescriptor,
): Promise<Uint8Array> {
  if (
    !object ||
    !object.body ||
    !Number.isSafeInteger(descriptor.sizeBytes) ||
    descriptor.sizeBytes < 0 ||
    descriptor.sizeBytes > MAX_ENGINEERING_EVIDENCE_BYTES ||
    object.size !== descriptor.sizeBytes ||
    object.customMetadata?.sha256 !== descriptor.sha256
  ) {
    throw new Error("Engineering evidence integrity check failed.");
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = object.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_ENGINEERING_EVIDENCE_BYTES || total > descriptor.sizeBytes) {
        await reader.cancel();
        throw new Error("Engineering evidence exceeds its verified bound.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  if (total !== descriptor.sizeBytes) {
    throw new Error("Engineering evidence integrity check failed.");
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  if (await sha256Hex(bytes) !== descriptor.sha256) {
    throw new Error("Engineering evidence integrity check failed.");
  }
  return bytes;
}

export async function verifyPatchBeforeConsume<T>(
  object: EvidenceObjectBody | null,
  descriptor: EvidenceDescriptor,
  consume: () => Promise<T>,
): Promise<{ bytes: Uint8Array; consumed: T }> {
  const bytes = await verifiedEvidenceBytes(object, descriptor);
  const consumed = await consume();
  return { bytes, consumed };
}
