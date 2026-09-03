import type { CoreEvidenceInput, CoreSnapshotInput } from "./engineering-d1.ts";
import {
  JOB_STATES,
  MAX_ENGINEERING_EVIDENCE_BYTES,
  parseApprovalProposal,
  safeSourceFilename,
  type ApprovalProposal,
  type JobState,
} from "./engineering.ts";

const CORE_JOB_ID = /^[A-Za-z0-9-]{1,128}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const EVIDENCE_ID = /^evidence:[a-f0-9]{32}$/;
const MEDIA_TYPE = /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/;
const EVIDENCE_CATEGORIES = new Set<CoreEvidenceInput["category"]>([
  "plan",
  "patch",
  "tests",
  "manifest",
  "summary",
  "log",
]);

export type ParsedCoreSnapshot = CoreSnapshotInput & {
  sourceDigest: string | null;
  approvalProposal: ApprovalProposal | null;
  approvalConsumed: boolean;
};

function invalid(): never {
  throw new Error("Core response is invalid.");
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  return value as Record<string, unknown>;
}

function approvalProposal(
  value: unknown,
  proposalDigest: string | null,
  sourceDigest: string | null,
): ApprovalProposal | null {
  if (value === undefined || value === null) return null;
  const input = record(value);
  const allowed = new Set([
    "action", "target", "policyVersion", "resourceProfile",
    "sourceDigest", "proposalDigest", "expiresAt",
  ]);
  if (Object.keys(input).some((key) => !allowed.has(key))) invalid();
  try {
    const parsed = parseApprovalProposal(input);
    if (parsed.sourceDigest !== sourceDigest || parsed.proposalDigest !== proposalDigest) invalid();
    return parsed;
  } catch {
    invalid();
  }
}

function evidenceDescriptor(value: unknown, remoteJobId: string): CoreEvidenceInput {
  const item = record(value);
  const id = typeof item.id === "string" ? item.id : "";
  const category = typeof item.category === "string" ? item.category : "";
  const filename = safeSourceFilename(item.filename);
  const mediaType = typeof item.mediaType === "string" ? item.mediaType.trim().toLowerCase() : "";
  const sizeBytes = item.sizeBytes;
  const sha256 = typeof item.sha256 === "string" ? item.sha256 : "";
  const createdAt = typeof item.createdAt === "string" ? item.createdAt : "";
  const corePath = typeof item.corePath === "string" ? item.corePath : "";
  const expectedPath = `/v1/jobs/${remoteJobId}/evidence/${encodeURIComponent(filename)}`;
  if (
    !EVIDENCE_ID.test(id) ||
    !EVIDENCE_CATEGORIES.has(category as CoreEvidenceInput["category"]) ||
    !MEDIA_TYPE.test(mediaType) ||
    mediaType.length > 120 ||
    !Number.isSafeInteger(sizeBytes) ||
    Number(sizeBytes) < 0 ||
    Number(sizeBytes) > MAX_ENGINEERING_EVIDENCE_BYTES ||
    !DIGEST.test(sha256) ||
    !createdAt ||
    Number.isNaN(Date.parse(createdAt)) ||
    corePath !== expectedPath
  ) {
    invalid();
  }
  return {
    id,
    category: category as CoreEvidenceInput["category"],
    filename,
    mediaType,
    sizeBytes: Number(sizeBytes),
    sha256,
    createdAt: new Date(createdAt).toISOString(),
    corePath,
  };
}

export function parseCoreSnapshot(value: unknown): {
  remoteJobId: string | null;
  snapshot: ParsedCoreSnapshot;
} {
  const input = record(value);
  const state = input.state;
  const revision = input.coreRevision ?? input.revision;
  const summary = typeof input.summary === "string" ? input.summary.trim() : "";
  const proposalDigest = input.proposalDigest ?? input.proposal_digest ?? null;
  const sourceDigest = input.sourceDigest ?? input.source_digest ?? null;
  const approvalConsumed = input.approvalConsumed ?? input.approval_consumed ?? false;
  const remoteJobId = typeof input.id === "string"
    ? input.id
    : typeof input.remoteJobId === "string"
      ? input.remoteJobId
      : null;
  if (
    typeof state !== "string" ||
    !JOB_STATES.includes(state as JobState) ||
    !Number.isSafeInteger(revision) ||
    Number(revision) < 0 ||
    summary.length > 2_000 ||
    (remoteJobId !== null && !CORE_JOB_ID.test(remoteJobId)) ||
    (proposalDigest !== null && (typeof proposalDigest !== "string" || !DIGEST.test(proposalDigest))) ||
    (sourceDigest !== null && (typeof sourceDigest !== "string" || !DIGEST.test(sourceDigest))) ||
    typeof approvalConsumed !== "boolean"
  ) {
    invalid();
  }
  const parsedApproval = approvalProposal(input.approvalProposal, proposalDigest as string | null, sourceDigest as string | null);
  if (state === "awaiting_approval" && (!parsedApproval || approvalConsumed)) invalid();
  if (parsedApproval && state === "applying" && approvalConsumed) invalid();
  if (parsedApproval && state === "completed" && !approvalConsumed) invalid();
  if (approvalConsumed && state !== "completed") invalid();
  const values = input.evidence ?? [];
  if (!Array.isArray(values) || values.length > 10 || (values.length > 0 && !remoteJobId)) invalid();
  const evidence = values.map((item) => evidenceDescriptor(item, remoteJobId as string));
  const identities = evidence.flatMap((item) => [item.id, item.filename, item.corePath]);
  if (new Set(identities).size !== identities.length) invalid();
  return {
    remoteJobId,
    snapshot: {
      state: state as JobState,
      summary,
      coreRevision: Number(revision),
      proposalDigest: proposalDigest as string | null,
      evidence,
      sourceDigest: sourceDigest as string | null,
      approvalProposal: parsedApproval,
      approvalConsumed,
    },
  };
}

export function parseCoreSnapshotForJob(value: unknown, expectedRemoteJobId: string) {
  const parsed = parseCoreSnapshot(value);
  if (parsed.remoteJobId !== expectedRemoteJobId) invalid();
  return parsed;
}
