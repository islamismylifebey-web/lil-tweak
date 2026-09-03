import { readBoundedJson } from "@/lib/bounded-request";
import { CoreRejectedError, decideCoreJob, getCoreJob } from "@/lib/core-client";
import { approvalProposalIsExpired, approvalProposalsEqual, parseApprovalProposal, parseDecision } from "@/lib/engineering";
import { json, mirrorCoreSnapshotEvidence, ownerFor, ownerScope, publicError, requireJobId, requireSameOriginMutation, store } from "@/lib/engineering-api";
import { decisionRecoveryMatches } from "@/lib/approval-recovery";

export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const owner = ownerFor(request);
    requireSameOriginMutation(request);
    const raw = await readBoundedJson(request, 8 * 1024);
    const decision = parseDecision(raw);
    const approvalTokenHash = (raw as Record<string, unknown>).approvalTokenHash;
    const proposal = parseApprovalProposal(
      (raw as Record<string, unknown>).approvalProposal,
    );
    const jobId = requireJobId((await context.params).id);
    const scope = await ownerScope(owner);
    const jobStore = store();
    const job = await jobStore.getJob(scope, jobId);
    if (!job) return json({ error: "Engineering job was not found." }, 404);
    if (!approvalProposalsEqual(job.approvalProposal, proposal)) {
      return json({ error: "Engineering approval proposal changed. Refresh and try again." }, 409);
    }
    if (
      decision.decision === "approve" &&
      (typeof approvalTokenHash !== "string" || !/^[a-f0-9]{64}$/.test(approvalTokenHash))
    ) {
      throw new Error("Engineering approval token hash is invalid.");
    }
    if (decision.decision === "reject" && approvalTokenHash !== undefined) {
      throw new Error("Engineering rejection request is invalid.");
    }
    const repeatedTerminalDecision = decision.decision === "reject" && job.state === "rejected";
    if (repeatedTerminalDecision) return json({ job });
    const repeatedApplyingApproval =
      decision.decision === "approve" && job.state === "applying" && !job.approvalConsumed;
    if (
      !repeatedApplyingApproval &&
      (job.revision !== decision.revision || job.state !== "awaiting_approval")
    ) {
      return json({ error: "Engineering job is not awaiting this decision." }, 409);
    }
    if (decision.decision === "approve" && approvalProposalIsExpired(proposal)) {
      return json({ error: "Engineering approval proposal expired. Reject or cancel this job, then request a new proposal." }, 409);
    }
    const remoteJobId = await jobStore.getRemoteJobId(scope, jobId);
    if (!remoteJobId) throw new Error("Engineering job is unavailable.");
    const coreRevision = await jobStore.getCoreRevision(scope, jobId);
    if (coreRevision === null) throw new Error("Engineering job is unavailable.");
    if (!job.proposalDigest) throw new Error("Engineering proposal is unavailable.");
    if (!repeatedApplyingApproval) {
      await jobStore.recordDecisionIntent(
        scope,
        jobId,
        decision.revision,
        decision.decision,
        job.proposalDigest,
      );
    }
    let core;
    try {
      core = await decideCoreJob(scope, remoteJobId, {
        jobId,
        ownerKey: scope,
        decision: decision.decision,
        reason: decision.reason,
        revision: decision.revision,
        expectedCoreRevision: repeatedApplyingApproval ? coreRevision - 1 : coreRevision,
        proposalDigest: job.proposalDigest,
        approvalProposal: proposal,
        ...(decision.decision === "approve" ? { approvalTokenHash } : {}),
      }, `job:${jobId}:decision:${decision.decision}:${decision.revision}`);
    } catch (error) {
      if (
        decision.decision !== "reject" ||
        !(error instanceof CoreRejectedError) ||
        error.status !== 409
      ) throw error;
      const recovered = await getCoreJob(
        scope,
        remoteJobId,
        `job:${jobId}:decision-recovery:${decision.decision}:${decision.revision}`,
      );
      if (!decisionRecoveryMatches(
        decision.decision,
        recovered.snapshot.state,
        recovered.snapshot.approvalConsumed,
      )) throw error;
      core = recovered;
    }
    const snapshot = await mirrorCoreSnapshotEvidence(scope, jobId, remoteJobId, core.snapshot);
    return json({ job: await jobStore.applyCoreSnapshot(scope, jobId, snapshot) });
  } catch (error) {
    return publicError(error);
  }
}
