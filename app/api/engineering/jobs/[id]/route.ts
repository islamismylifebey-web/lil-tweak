import { createCoreJob, getCoreJob } from "@/lib/core-client";
import { readBoundedJson } from "@/lib/bounded-request";
import { validateEngineeringDispatchRequest } from "@/lib/create-request";
import { engineeringObjectKey } from "@/lib/engineering";
import { files, json, mirrorCoreSnapshotEvidence, ownerFor, ownerScope, publicError, requireJobId, requireSameOriginMutation, store } from "@/lib/engineering-api";
import { immutableSourceMatches } from "@/lib/immutable-r2";

function dispatchRevision(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Engineering request must be an object.");
  const input = value as Record<string, unknown>;
  if (input.action !== "dispatch" || !Number.isSafeInteger(input.revision)) {
    throw new Error("A valid job revision is required.");
  }
  return Number(input.revision);
}

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const owner = ownerFor(request);
    const scope = await ownerScope(owner);
    const jobId = requireJobId((await context.params).id);
    const jobStore = store();
    let job = await jobStore.getJob(scope, jobId);
    if (!job) return json({ error: "Engineering job was not found." }, 404);
    const fresh = new URL(request.url).searchParams.get("fresh") === "1";
    if (fresh) {
      // The remote ID remains D1-private; it is intentionally not serialized in the public job type.
      const remote = await jobStore.getRemoteJobId(scope, jobId);
      if (remote) {
        const coreRevision = await jobStore.getCoreRevision(scope, jobId);
        const core = await getCoreJob(scope, remote, `job:${jobId}:poll:${coreRevision ?? 0}`);
        const snapshot = await mirrorCoreSnapshotEvidence(scope, jobId, remote, core.snapshot);
        job = await jobStore.applyCoreSnapshot(scope, jobId, snapshot);
      }
    }
    return json({ job });
  } catch (error) {
    return publicError(error);
  }
}

export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const owner = ownerFor(request);
    requireSameOriginMutation(request);
    const jobId = requireJobId((await context.params).id);
    const expectedRevision = dispatchRevision(await readBoundedJson(request, 8 * 1024));
    const scope = await ownerScope(owner);
    const jobStore = store();
    const job = await jobStore.getJob(scope, jobId);
    if (!job) return json({ error: "Engineering job was not found." }, 404);
    if (job.state !== "queued") {
      return json({ error: "Engineering job is not ready for dispatch." }, 409);
    }
    const existingRemoteJobId = await jobStore.getRemoteJobId(scope, jobId);
    if (existingRemoteJobId) {
      const recovered = await getCoreJob(
        scope,
        existingRemoteJobId,
        `job:${jobId}:dispatch-recovery:${job.revision}`,
      );
      const recoveredSnapshot = await mirrorCoreSnapshotEvidence(
        scope,
        jobId,
        existingRemoteJobId,
        recovered.snapshot,
      );
      return json({ job: await jobStore.applyCoreSnapshot(scope, jobId, recoveredSnapshot) });
    }
    const dispatchMetadata = await jobStore.getDispatchMetadata(scope, jobId);
    const requestPayload = await validateEngineeringDispatchRequest({
      object: await files().get(dispatchMetadata.requestR2Key),
      expectedRequestDigest: dispatchMetadata.createRequestDigest,
      expectedPromptDigest: dispatchMetadata.promptDigest,
      job,
    });
    const verifiedSources = await Promise.all(job.sources.map(async (source) => {
      if (!source.uploadedAt || !source.sha256) {
        throw new Error("Engineering source upload is incomplete.");
      }
      const r2Key = engineeringObjectKey(scope, jobId, "source", source.id);
      const object = await files().head(r2Key);
      if (!immutableSourceMatches(object, { ...source, sha256: source.sha256 })) {
        throw new Error("Engineering source integrity check failed before dispatch.");
      }
      return {
        id: source.id,
        filename: source.filename,
        mediaType: source.mediaType,
        sizeBytes: source.sizeBytes,
        sha256: source.sha256,
        r2Key,
      };
    }));
    const reservedJob = await jobStore.reserveDispatch(scope, jobId, expectedRevision);
    const core = await createCoreJob(scope, {
      id: job.id,
      ownerKey: scope,
      mode: job.mode,
      projectId: job.projectId,
      prompt: requestPayload.prompt,
      projectContext: requestPayload.projectContext ?? null,
      gitSource: job.gitSource,
      requestR2Key: dispatchMetadata.requestR2Key,
      sources: verifiedSources,
    }, `job:${jobId}:dispatch`);
    if (!core.remoteJobId) throw new Error("Core job response is invalid.");
    await jobStore.setRemoteJob(scope, jobId, reservedJob.revision, core.remoteJobId, core.snapshot.summary || "Queued in the private core.");
    const snapshot = await mirrorCoreSnapshotEvidence(scope, jobId, core.remoteJobId, core.snapshot);
    return json({ job: await jobStore.applyCoreSnapshot(scope, jobId, snapshot) });
  } catch (error) {
    return publicError(error);
  }
}
