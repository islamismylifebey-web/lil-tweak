import { readBoundedBytes, requireExactLength } from "@/lib/bounded-request";
import { sha256Hex } from "@/lib/core-signing";
import { engineeringObjectKey } from "@/lib/engineering";
import { files, json, ownerFor, ownerScope, publicError, requireJobId, requireSameOriginMutation, requireSourceId, store } from "@/lib/engineering-api";
import { ImmutableObjectConflictError, immutableSourceMatches, putImmutableObject } from "@/lib/immutable-r2";

const MAX_SOURCE_BYTES = 25_000_000;

export async function PUT(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const owner = ownerFor(request);
    requireSameOriginMutation(request);
    const jobId = requireJobId((await context.params).id);
    const sourceId = requireSourceId(new URL(request.url).searchParams.get("sourceId") ?? "");
    const length = requireExactLength(request.headers.get("content-length"), MAX_SOURCE_BYTES);
    if (!request.body || length === 0) throw new Error("Engineering source body is required.");
    const scope = await ownerScope(owner);
    const jobStore = store();
    const source = await jobStore.getSource(scope, jobId, sourceId);
    if (source.sizeBytes !== length) return json({ error: "Source body length does not match its manifest." }, 400);
    const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
    if (contentType !== source.mediaType) return json({ error: "Source content type does not match its manifest." }, 415);
    const bytes = await readBoundedBytes(request, MAX_SOURCE_BYTES);
    const sha256 = await sha256Hex(bytes);

    const key = engineeringObjectKey(scope, jobId, "source", sourceId);
    let object = await files().head(key);
    if (!object) {
      try {
        object = await putImmutableObject(files(), key, bytes, {
          httpMetadata: { contentType: source.mediaType },
          customMetadata: { sourceId, jobId, sha256 },
          sha256,
        });
      } catch (error) {
        if (!(error instanceof ImmutableObjectConflictError)) throw error;
        object = await files().head(key);
      }
    }
    if (!object || !immutableSourceMatches(object, { ...source, jobId, sha256 })) {
      throw new Error("Engineering source integrity check failed.");
    }
    const job = await jobStore.markSourceUploaded(scope, jobId, sourceId, object.etag, sha256);
    return json({ job, source: job.sources.find((item) => item.id === sourceId) ?? null });
  } catch (error) {
    return publicError(error);
  }
}
