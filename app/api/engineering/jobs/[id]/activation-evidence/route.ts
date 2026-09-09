import { env } from "cloudflare:workers";
import { json, ownerFor, ownerScope, publicError, requireJobId } from "@/lib/engineering-api";

type Row = Record<string, unknown>;

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    // Authenticate before even inspecting bindings. This endpoint performs no
    // Core/R2 fetch and never reads prompt, object keys, or secret columns.
    const owner = ownerFor(request);
    const scope = await ownerScope(owner);
    const jobId = requireJobId((await context.params).id);
    const database = (env as unknown as { DB?: D1Database }).DB;
    if (!database) return json({ error: "Engineering service is unavailable." }, 503);
    const results = await database.batch([
      database.prepare("SELECT id AS jobId, remote_job_id AS remoteJobId, revision AS jobRevision, core_revision AS coreRevision, mode, state, git_repository_url AS repositoryUrl, git_commit AS gitCommit, source_digest AS sourceDigest, proposal_digest AS proposalDigest, approval_proposal_json IS NOT NULL AS hasApproval, approval_consumed AS approvalConsumed, authorized_decision IS NOT NULL AS hasDecision FROM engineering_jobs WHERE id=? AND owner_key=? LIMIT 1").bind(jobId, scope),
      database.prepare("SELECT id, category, filename, media_type AS mediaType, size_bytes AS sizeBytes, sha256, created_at AS createdAt FROM engineering_evidence WHERE job_id=? AND owner_key=? ORDER BY filename ASC LIMIT 6").bind(jobId, scope),
      database.prepare("SELECT id, event_type AS type, created_at AS createdAt FROM engineering_audit_events WHERE job_id=? AND owner_key=? ORDER BY created_at ASC, id ASC LIMIT 251").bind(jobId, scope),
    ]);
    const row = results[0].results[0] as Row | undefined;
    if (!row) return json({ error: "Engineering job was not found." }, 404);
    const evidence = results[1].results as Row[];
    const events = results[2].results as Row[];
    if (row.hasApproval !== 0 || !row.remoteJobId || !Number.isSafeInteger(row.coreRevision) || evidence.length !== 5 || events.length > 250) {
      return json({ error: "Activation evidence is unavailable." }, 409);
    }
    // Project every returned row again: a changed query/binding cannot leak a
    // newly added column. The single D1 batch supplies one transaction snapshot.
    return json({
      schema: "tueiq-d1-activation-cross-check-v1", observedAt: new Date().toISOString(),
      jobId: row.jobId, remoteJobId: row.remoteJobId, ownerScope: scope,
      jobRevision: row.jobRevision, coreRevision: row.coreRevision, mode: row.mode, state: row.state,
      gitSource: { repositoryUrl: row.repositoryUrl, commit: row.gitCommit }, sourceDigest: row.sourceDigest, proposalDigest: row.proposalDigest,
      approvalProposal: null, approvalConsumed: row.approvalConsumed === 1,
      decisionCount: Math.max(Number(row.hasDecision), events.filter((event) => event.type === "decision_authorized").length),
      exportCount: row.approvalConsumed === 1 ? 1 : 0,
      evidence: evidence.map((d) => ({ id: d.id, category: d.category, filename: d.filename, mediaType: d.mediaType, sizeBytes: d.sizeBytes, sha256: d.sha256, createdAt: d.createdAt })),
      events: events.map((event) => ({ id: event.id, type: event.type, createdAt: event.createdAt })),
    });
  } catch (error) { return publicError(error); }
}
