import { readBoundedJson } from "@/lib/bounded-request";
import { exportCorePatch } from "@/lib/core-client";
import { engineeringObjectKey, MAX_ENGINEERING_EVIDENCE_BYTES } from "@/lib/engineering";
import { attachmentHeaders, files, mirrorCoreSnapshotEvidence, ownerFor, ownerScope, publicError, requireEvidenceId, requireSameOriginMutation, store } from "@/lib/engineering-api";
import { immutableEvidenceMatches } from "@/lib/evidence-mirror";
import { directEvidenceDownloadAllowed, parsePatchExportRequest, verifyPatchBeforeConsume } from "@/lib/evidence-access";

const MAX_PREVIEW_BYTES = MAX_ENGINEERING_EVIDENCE_BYTES;

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const owner = ownerFor(request);
    const scope = await ownerScope(owner);
    const evidence = await store().getEvidence(scope, requireEvidenceId((await context.params).id));
    const job = await store().getJob(scope, evidence.jobId);
    if (!job) return new Response(JSON.stringify({ error: "Engineering job was not found." }), {
      status: 404,
      headers: { "Content-Type": "application/json", "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" },
    });
    const preview = new URL(request.url).searchParams.get("preview") === "1";
    if (!preview && !directEvidenceDownloadAllowed(evidence.category)) {
      return new Response(JSON.stringify({ error: "Patch export requires the one-time POST flow.", code: "export_post_required" }), {
        status: 403,
        headers: { "Content-Type": "application/json", "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" },
      });
    }
    const object = await files().get(engineeringObjectKey(scope, evidence.jobId, "evidence", evidence.id));
    if (!object || !object.body) return new Response(JSON.stringify({ error: "Engineering evidence was not found." }), {
      status: 404,
      headers: { "Content-Type": "application/json", "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" },
    });
    if (!immutableEvidenceMatches(object, evidence)) {
      throw new Error("Evidence integrity check failed.");
    }
    if (preview) {
      if (evidence.sizeBytes > MAX_PREVIEW_BYTES) {
        return new Response(JSON.stringify({ error: "Evidence is too large to preview." }), {
          status: 413,
          headers: { "Content-Type": "application/json", "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" },
        });
      }
      return new Response(object.body, {
        headers: {
          "Cache-Control": "private, no-store",
          "Content-Type": "text/plain; charset=utf-8",
          "Content-Disposition": `inline; filename="${evidence.filename.replace(/["\\\r\n]/g, "_")}"`,
          "Content-Length": String(evidence.sizeBytes),
          "Content-Security-Policy": "default-src 'none'; sandbox",
          "X-Content-Type-Options": "nosniff",
          "X-Content-SHA256": evidence.sha256,
        },
      });
    }
    return new Response(object.body, { headers: attachmentHeaders(evidence.filename, evidence.mediaType, evidence.sizeBytes) });
  } catch (error) {
    return publicError(error);
  }
}

export async function POST(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const owner = ownerFor(request);
    requireSameOriginMutation(request);
    const exportRequest = parsePatchExportRequest(await readBoundedJson(request, 8 * 1024));
    const scope = await ownerScope(owner);
    const jobStore = store();
    const evidence = await jobStore.getEvidence(
      scope,
      requireEvidenceId((await context.params).id),
    );
    const job = await jobStore.getJob(scope, evidence.jobId);
    if (
      !job ||
      evidence.category !== "patch" ||
      evidence.filename !== "changes.patch" ||
      !job.approvalProposal ||
      !job.proposalDigest ||
      !job.sourceDigest ||
      !["applying", "completed"].includes(job.state) ||
      (job.state === "applying" && job.approvalConsumed) ||
      (job.state === "completed" && !job.approvalConsumed)
    ) {
      return new Response(JSON.stringify({ error: "One-time patch export is unavailable." }), {
        status: 409,
        headers: { "Content-Type": "application/json", "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" },
      });
    }
    const key = engineeringObjectKey(scope, evidence.jobId, "evidence", evidence.id);
    const object = await files().get(key);
    if (!object || !object.body) {
      return new Response(JSON.stringify({ error: "Engineering evidence was not found." }), {
        status: 404,
        headers: { "Content-Type": "application/json", "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" },
      });
    }
    const remoteJobId = await jobStore.getRemoteJobId(scope, evidence.jobId);
    const coreRevision = await jobStore.getCoreRevision(scope, evidence.jobId);
    if (!remoteJobId || coreRevision === null) throw new Error("Engineering job is unavailable.");
    const originalApplyingRevision = job.state === "completed" ? coreRevision - 1 : coreRevision;
    const verified = await verifyPatchBeforeConsume(object, evidence, async () => {
      const core = await exportCorePatch(scope, remoteJobId, {
        approvalToken: exportRequest.approvalToken,
        expectedCoreRevision: originalApplyingRevision,
        proposalDigest: job.proposalDigest,
        sourceDigest: job.sourceDigest,
        policyVersion: job.approvalProposal!.policyVersion,
        resourceProfile: job.approvalProposal!.resourceProfile,
        evidenceId: evidence.id,
        evidenceName: evidence.filename,
        evidenceSha256: evidence.sha256,
        evidenceSizeBytes: evidence.sizeBytes,
      }, exportRequest.attemptId);
      const snapshot = await mirrorCoreSnapshotEvidence(
        scope,
        evidence.jobId,
        remoteJobId,
        core.snapshot,
      );
      return jobStore.applyCoreSnapshot(scope, evidence.jobId, snapshot);
    });
    const responseBody = verified.bytes.buffer.slice(
      verified.bytes.byteOffset,
      verified.bytes.byteOffset + verified.bytes.byteLength,
    ) as ArrayBuffer;
    return new Response(responseBody, {
      headers: {
        ...attachmentHeaders(evidence.filename, evidence.mediaType, verified.bytes.byteLength),
        "X-Content-SHA256": evidence.sha256,
      },
    });
  } catch (error) {
    return publicError(error);
  }
}
