export class ImmutableObjectConflictError extends Error {
  constructor() {
    super("The immutable object key is already in use.");
  }
}

interface ImmutableSourceObject {
  size: number;
  etag?: string;
  httpMetadata?: { contentType?: string };
  customMetadata?: Record<string, string>;
}

interface ImmutableSourceDescriptor {
  id: string;
  jobId: string;
  mediaType: string;
  sizeBytes: number;
  sha256: string;
}

export function immutableSourceMatches(
  object: ImmutableSourceObject | null,
  source: ImmutableSourceDescriptor,
) {
  return Boolean(
    object &&
    object.size === source.sizeBytes &&
    object.etag &&
    object.httpMetadata?.contentType?.toLowerCase() === source.mediaType.toLowerCase() &&
    object.customMetadata?.sourceId === source.id &&
    object.customMetadata?.jobId === source.jobId &&
    object.customMetadata?.sha256 === source.sha256,
  );
}

type R2PutValue =
  | ReadableStream
  | ArrayBuffer
  | ArrayBufferView
  | string
  | Blob
  | null;

interface ImmutableBucket<T> {
  put(key: string, value: R2PutValue, options: R2PutOptions): Promise<T | null>;
}

export async function putImmutableObject<T>(
  bucket: ImmutableBucket<T>,
  key: string,
  value: R2PutValue,
  options: Omit<R2PutOptions, "onlyIf"> = {},
): Promise<T> {
  const onlyIf = new Headers({ "If-None-Match": "*" });
  const object = await bucket.put(key, value, { ...options, onlyIf });
  if (!object) throw new ImmutableObjectConflictError();
  return object;
}
