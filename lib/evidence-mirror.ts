import type { CoreEvidenceInput } from "./engineering-d1.ts";
import { engineeringObjectKey, MAX_ENGINEERING_EVIDENCE_BYTES } from "./engineering.ts";
import { ImmutableObjectConflictError, putImmutableObject } from "./immutable-r2.ts";

interface EvidenceObject {
  size: number;
  etag?: string;
  customMetadata?: Record<string, string>;
}

interface EvidenceBucket {
  head(key: string): Promise<EvidenceObject | null>;
  put(
    key: string,
    bytes: Uint8Array,
    options: R2PutOptions & {
      httpMetadata: { contentType: string };
      customMetadata: Record<string, string>;
    },
  ): Promise<EvidenceObject | null>;
}

interface FetchedEvidence {
  bytes: Uint8Array;
  sizeBytes: number;
  sha256: string;
  mediaType: string;
}

export function immutableEvidenceMatches(
  object: EvidenceObject | null,
  descriptor: Pick<CoreEvidenceInput, "sizeBytes" | "sha256">,
) {
  return Boolean(
    object &&
    object.size === descriptor.sizeBytes &&
    object.size >= 0 &&
    object.size <= MAX_ENGINEERING_EVIDENCE_BYTES &&
    object.customMetadata?.sha256 === descriptor.sha256,
  );
}

export async function mirrorCoreEvidence(input: {
  ownerScope: string;
  jobId: string;
  remoteJobId: string;
  evidence: CoreEvidenceInput[];
  bucket: EvidenceBucket;
  fetchEvidence: (
    remoteJobId: string,
    descriptor: CoreEvidenceInput,
  ) => Promise<FetchedEvidence>;
}): Promise<CoreEvidenceInput[]> {
  const mirrored: CoreEvidenceInput[] = [];
  for (const descriptor of input.evidence) {
    const key = engineeringObjectKey(input.ownerScope, input.jobId, "evidence", descriptor.id);
    const existing = await input.bucket.head(key);
    if (existing) {
      if (!immutableEvidenceMatches(existing, descriptor)) {
        throw new Error("Evidence integrity check failed.");
      }
      mirrored.push({ ...descriptor, sizeBytes: existing.size });
      continue;
    }
    const fetched = await input.fetchEvidence(input.remoteJobId, descriptor);
    if (
      !Number.isSafeInteger(fetched.sizeBytes) ||
      fetched.sizeBytes !== descriptor.sizeBytes ||
      fetched.sizeBytes < 0 ||
      fetched.sizeBytes > MAX_ENGINEERING_EVIDENCE_BYTES ||
      fetched.bytes.byteLength !== fetched.sizeBytes ||
      fetched.sha256 !== descriptor.sha256 ||
      fetched.mediaType !== descriptor.mediaType
    ) {
      throw new Error("Evidence integrity check failed.");
    }
    let stored: EvidenceObject;
    try {
      stored = await putImmutableObject(input.bucket, key, fetched.bytes, {
        httpMetadata: { contentType: descriptor.mediaType },
        customMetadata: {
          sha256: descriptor.sha256,
          evidenceId: descriptor.id,
          jobId: input.jobId,
        },
      });
    } catch (error) {
      if (!(error instanceof ImmutableObjectConflictError)) throw error;
      const raced = await input.bucket.head(key);
      if (!immutableEvidenceMatches(raced, descriptor)) {
        throw new Error("Evidence integrity check failed.");
      }
      stored = raced as EvidenceObject;
    }
    if (stored.size !== fetched.sizeBytes) {
      throw new Error("Evidence storage failed.");
    }
    mirrored.push({ ...descriptor, sizeBytes: fetched.sizeBytes });
  }
  return mirrored;
}
