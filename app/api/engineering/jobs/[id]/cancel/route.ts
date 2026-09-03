import { readBoundedJson } from "@/lib/bounded-request";
import { CoreRejectedError, cancelCoreJob, getCoreJob } from "@/lib/core-client";
import { cancelRecoveryMatches } from "@/lib/approval-recovery";
import { json, mirrorCoreSnapshotEvidence, ownerFor, ownerScope, publicError, requireJobId, requireSameOriginMutation, store } from "@/lib/engineering-api";

function revision(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !Number.isSafeInteger((value as Record<string, unknown>).revision)) {
    throw new Error("A valid job revision is required.");
  }
  return Number((value as Record<string, unknown>).revision);
}

export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const owner = ownerFor(request);
    requireSameOriginMutation(request);
    const expectedRevision = revision(await readBoundedJson(request, 8 * 1024));
    const jobId = requireJobId((await context.params).id);
    const scope = await ownerScope(owner);
    const jobStore = store();
    const job = await jobStore.getJob(scope, jobId);
    if (!job) return json({ error: "Engineering job was not found." }, 404);
    if (job.state === "cancelled") return json({ job });
    if (job.revision !== expectedRevision || ["completed", "rejected", "cancelled", "failed", "timed_out"].includes(job.state)) {
      return json({ error: "Engineering job cannot be cancelled." }, 409);
    }
    const remoteJobId = await jobStore.getRemoteJobId(scope, jobId);
    if (!remoteJobId) {
      if (await jobStore.dispatchIsReserved(scope, jobId)) {
        return json({ error: "Resume this reserved dispatch to reconcile it before cancellation." }, 409);
      }
      return json({ job: await jobStore.transition(scope, jobId, "cancelled", expectedRevision, "job_cancelled", "Engineering job cancelled.") });
    }
    const coreRevision = await jobStore.getCoreRevision(scope, jobId);
    if (coreRevision === null) throw new Error("Engineering job is unavailable.");
    let core;
    try {
      core = await cancelCoreJob(scope, remoteJobId, { jobId, ownerKey: scope, revision: expectedRevision, expectedCoreRevision: coreRevision }, `job:${jobId}:cancel:${expectedRevision}`);
    } catch (error) {
      if (!(error instanceof CoreRejectedError) || error.status !== 409) throw error;
      const recovered = await getCoreJob(
        scope,
        remoteJobId,
        `job:${jobId}:cancel-recovery:${expectedRevision}`,
      );
      if (!cancelRecoveryMatches(recovered.snapshot.state)) throw error;
      core = recovered;
    }
    const snapshot = await mirrorCoreSnapshotEvidence(scope, jobId, remoteJobId, core.snapshot);
    return json({ job: await jobStore.applyCoreSnapshot(scope, jobId, snapshot) });
  } catch (error) {
    return publicError(error);
  }
}
