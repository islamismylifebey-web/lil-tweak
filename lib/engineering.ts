import type { GitSourceInput } from "./engineering-input.ts";

export const ENGINEER_MODES = [
  "build",
  "debug",
  "refactor",
  "test",
  "architect",
  "chat",
] as const;

export const MAX_ENGINEERING_EVIDENCE_BYTES = 2 * 1024 * 1024;

export const JOB_STATES = [
  "draft",
  "uploading",
  "queued",
  "ingesting",
  "planning",
  "executing",
  "testing",
  "collecting",
  "awaiting_approval",
  "applying",
  "completed",
  "rejected",
  "cancelled",
  "failed",
  "timed_out",
] as const;

export type EngineerMode = (typeof ENGINEER_MODES)[number];
export type JobState = (typeof JOB_STATES)[number];

export interface ApprovalProposal {
  action: "export_patch";
  target: "owner_download";
  policyVersion: string;
  resourceProfile: Record<string, string | number | boolean>;
  sourceDigest: string;
  proposalDigest: string;
  expiresAt: string;
}

export interface EngineeringJob {
  id: string;
  projectId: string | null;
  mode: EngineerMode;
  promptPreview: string;
  state: JobState;
  revision: number;
  summary: string;
  proposalDigest: string | null;
  sourceDigest: string | null;
  approvalProposal: ApprovalProposal | null;
  approvalConsumed: boolean;
  gitSource: GitSourceInput | null;
  createdAt: string;
  updatedAt: string;
}

export interface EngineeringSource {
  id: string;
  jobId: string;
  filename: string;
  mediaType: string;
  sizeBytes: number;
  sha256: string | null;
  uploadedAt: string | null;
}

export interface EngineeringEvidence {
  id: string;
  jobId: string;
  category: "plan" | "patch" | "tests" | "manifest" | "summary" | "log";
  filename: string;
  mediaType: string;
  sizeBytes: number;
  sha256: string;
  createdAt: string;
}

export interface EngineeringJobDetail extends EngineeringJob {
  sources: EngineeringSource[];
  evidence: EngineeringEvidence[];
  events: Array<{ id: string; type: string; summary: string; createdAt: string }>;
}

interface MirroredSnapshot {
  state: JobState;
  summary: string;
  coreRevision: number;
  proposalDigest?: string | null;
  sourceDigest?: string | null;
  approvalProposal?: ApprovalProposal | null;
  approvalConsumed?: boolean;
  evidence?: Array<Pick<EngineeringEvidence, "id" | "category" | "filename" | "mediaType" | "sizeBytes" | "sha256" | "createdAt">>;
}

export interface JobCreateInput {
  mode: EngineerMode;
  prompt: string;
  projectId: string | null;
}

export interface DecisionInput {
  decision: "approve" | "reject";
  reason: string;
  revision: number;
}

export interface DecisionIntent {
  decision: "approve" | "reject";
  proposalDigest: string;
}

const IDENTIFIER = /^(?:job|src|evidence):[0-9a-f]{32}$/;
const OWNER_HASH = /^[a-zA-Z0-9_-]{8,64}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const POLICY_VERSION = /^[A-Za-z0-9._-]{1,64}$/;
const RESOURCE_KEY = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/;

const TRANSITIONS: Readonly<Record<JobState, readonly JobState[]>> = {
  draft: ["uploading", "queued", "cancelled"],
  uploading: ["queued", "cancelled", "failed"],
  queued: ["ingesting", "cancelled", "failed"],
  ingesting: ["planning", "cancelled", "failed", "timed_out"],
  planning: ["executing", "cancelled", "failed", "timed_out"],
  executing: ["testing", "cancelled", "failed", "timed_out"],
  testing: ["collecting", "cancelled", "failed", "timed_out"],
  collecting: ["awaiting_approval", "completed", "cancelled", "failed", "timed_out"],
  awaiting_approval: ["applying", "rejected", "cancelled", "failed"],
  applying: ["completed", "cancelled", "failed", "timed_out"],
  completed: [],
  rejected: [],
  cancelled: [],
  failed: [],
  timed_out: [],
};

function recordValue(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Engineering request must be an object.");
  }
  return value as Record<string, unknown>;
}

export function parseApprovalProposal(value: unknown): ApprovalProposal {
  const input = recordValue(value);
  const profile = input.resourceProfile;
  if (
    input.action !== "export_patch" ||
    input.target !== "owner_download" ||
    typeof input.policyVersion !== "string" ||
    !POLICY_VERSION.test(input.policyVersion) ||
    typeof input.sourceDigest !== "string" ||
    !DIGEST.test(input.sourceDigest) ||
    typeof input.proposalDigest !== "string" ||
    !DIGEST.test(input.proposalDigest) ||
    typeof input.expiresAt !== "string" ||
    input.expiresAt.length > 64 ||
    Number.isNaN(Date.parse(input.expiresAt)) ||
    !profile ||
    typeof profile !== "object" ||
    Array.isArray(profile)
  ) {
    throw new Error("Core approval proposal is invalid.");
  }
  const entries = Object.entries(profile as Record<string, unknown>);
  if (
    entries.length === 0 ||
    entries.length > 16 ||
    entries.some(([key, item]) => (
      !RESOURCE_KEY.test(key) ||
      !(["string", "number", "boolean"].includes(typeof item)) ||
      (typeof item === "string" && item.length > 128) ||
      (typeof item === "number" && !Number.isFinite(item))
    ))
  ) {
    throw new Error("Core approval proposal is invalid.");
  }
  const resourceProfile = Object.fromEntries(entries) as Record<string, string | number | boolean>;
  if (JSON.stringify(resourceProfile).length > 2_048) {
    throw new Error("Core approval proposal is invalid.");
  }
  return {
    action: "export_patch",
    target: "owner_download",
    policyVersion: input.policyVersion,
    resourceProfile,
    sourceDigest: input.sourceDigest,
    proposalDigest: input.proposalDigest,
    expiresAt: input.expiresAt,
  };
}

function approvalProposalFingerprint(value: ApprovalProposal | null | undefined) {
  if (!value) return null;
  return JSON.stringify({
    ...value,
    resourceProfile: Object.fromEntries(Object.entries(value.resourceProfile).sort(([left], [right]) => left.localeCompare(right))),
  });
}

export function approvalProposalsEqual(
  left: ApprovalProposal | null | undefined,
  right: ApprovalProposal | null | undefined,
) {
  return approvalProposalFingerprint(left) === approvalProposalFingerprint(right);
}

export function approvalProposalIsExpired(
  proposal: ApprovalProposal,
  nowMs = Date.now(),
  safetyWindowMs = 30_000,
) {
  return Date.parse(proposal.expiresAt) <= nowMs + safetyWindowMs;
}

export function parseJobCreate(value: unknown): JobCreateInput {
  const input = recordValue(value);
  if (typeof input.mode !== "string" || !ENGINEER_MODES.includes(input.mode as EngineerMode)) {
    throw new Error("A valid engineering mode is required.");
  }
  if (typeof input.prompt !== "string" || !input.prompt.trim()) {
    throw new Error("Engineering prompt is required.");
  }
  const prompt = input.prompt.trim();
  if (prompt.length > 16_000) {
    throw new Error("Engineering prompt is longer than 16,000 characters.");
  }
  const projectId = input.projectId;
  if (projectId !== undefined && projectId !== null && typeof projectId !== "string") {
    throw new Error("Project ID must be text.");
  }
  const normalizedProjectId = typeof projectId === "string" ? projectId.trim() : "";
  if (normalizedProjectId && !/^project:[0-9a-f]{32}$/.test(normalizedProjectId)) {
    throw new Error("Project ID is invalid.");
  }
  return {
    mode: input.mode as EngineerMode,
    prompt,
    projectId: normalizedProjectId || null,
  };
}

export function parseDecision(value: unknown): DecisionInput {
  const input = recordValue(value);
  if (input.decision !== "approve" && input.decision !== "reject") {
    throw new Error("Decision must be approve or reject.");
  }
  if (!Number.isSafeInteger(input.revision) || Number(input.revision) < 0) {
    throw new Error("A valid job revision is required.");
  }
  const reason = typeof input.reason === "string" ? input.reason.trim() : "";
  if (reason.length > 2_000) throw new Error("Decision reason is too long.");
  if (input.decision === "reject" && !reason) {
    throw new Error("A rejection reason is required.");
  }
  return { decision: input.decision, reason, revision: Number(input.revision) };
}

export function safeSourceFilename(value: unknown): string {
  if (typeof value !== "string") throw new Error("A portable filename is required.");
  const filename = value.trim();
  if (
    !filename ||
    filename === "." ||
    filename === ".." ||
    filename.length > 255 ||
    filename.includes("/") ||
    filename.includes("\\") ||
    [...filename].some((character) => {
      const code = character.charCodeAt(0);
      return code < 32 || code === 127;
    })
  ) {
    throw new Error("A portable filename is required.");
  }
  return filename;
}

export function engineeringObjectKey(
  ownerHash: string,
  jobId: string,
  kind: "source" | "evidence",
  objectId: string,
): string {
  const expectedPrefix = kind === "source" ? "src:" : "evidence:";
  if (
    !OWNER_HASH.test(ownerHash) ||
    !IDENTIFIER.test(jobId) ||
    !IDENTIFIER.test(objectId) ||
    !objectId.startsWith(expectedPrefix)
  ) {
    throw new Error("Invalid engineering identifier.");
  }
  const collection = kind === "source" ? "sources" : "evidence";
  return `engineering/${ownerHash}/jobs/${jobId}/${collection}/${objectId}`;
}

export function transitionAllowed(from: JobState, to: JobState): boolean {
  return TRANSITIONS[from].includes(to);
}

const CORE_PROGRESS: readonly JobState[] = [
  "queued",
  "ingesting",
  "planning",
  "executing",
  "testing",
  "collecting",
  "completed",
];
const TERMINAL_STATES: readonly JobState[] = [
  "completed",
  "rejected",
  "cancelled",
  "failed",
  "timed_out",
];

export function coreSnapshotTransitionAllowed(
  from: JobState,
  to: JobState,
  authorizedDecision = false,
): boolean {
  if (TERMINAL_STATES.includes(from)) return false;
  if (from === to) return true;
  const fromProgress = CORE_PROGRESS.indexOf(from);
  const toProgress = CORE_PROGRESS.indexOf(to);
  if (fromProgress >= 0 && toProgress > fromProgress) return true;
  if (
    fromProgress >= 0 && fromProgress < CORE_PROGRESS.length - 1 &&
    ["awaiting_approval", "cancelled", "failed", "timed_out"].includes(to)
  ) {
    return true;
  }
  if (from === "awaiting_approval") {
    if (["cancelled", "failed", "timed_out"].includes(to)) return true;
    return authorizedDecision && ["applying", "completed", "rejected"].includes(to);
  }
  if (from === "applying") {
    return ["completed", "cancelled", "failed", "timed_out"].includes(to);
  }
  return false;
}

export function decisionAuthorizesCoreState(
  intent: DecisionIntent | null,
  currentProposalDigest: string | null,
  next: JobState,
): boolean {
  if (
    !intent ||
    !currentProposalDigest ||
    intent.proposalDigest !== currentProposalDigest
  ) {
    return false;
  }
  return intent.decision === "approve"
    ? next === "applying" || next === "completed"
    : next === "rejected";
}

export function coreSnapshotAlreadyMirrored(
  current: Pick<EngineeringJobDetail, "state" | "summary" | "proposalDigest" | "sourceDigest" | "approvalProposal" | "approvalConsumed" | "evidence">,
  currentCoreRevision: number | null,
  snapshot: MirroredSnapshot,
): boolean {
  if (
    currentCoreRevision !== snapshot.coreRevision ||
    current.state !== snapshot.state ||
    current.summary !== snapshot.summary.trim().slice(0, 2_000) ||
    current.proposalDigest !== (snapshot.proposalDigest ?? current.proposalDigest) ||
    current.sourceDigest !== (snapshot.sourceDigest ?? current.sourceDigest) ||
    current.approvalConsumed !== (snapshot.approvalConsumed ?? current.approvalConsumed) ||
    !approvalProposalsEqual(current.approvalProposal, snapshot.approvalProposal ?? current.approvalProposal)
  ) {
    return false;
  }
  const incoming = snapshot.evidence ?? [];
  if (current.evidence.length !== incoming.length) return false;
  const stored = new Map(current.evidence.map((item) => [item.id, item]));
  return incoming.every((item) => {
    const existing = stored.get(item.id);
    return Boolean(
      existing &&
      existing.category === item.category &&
      existing.filename === item.filename &&
      existing.mediaType === item.mediaType &&
      existing.sizeBytes === item.sizeBytes &&
      existing.sha256 === item.sha256 &&
      existing.createdAt === item.createdAt,
    );
  });
}

export function newEngineeringId(prefix: "job" | "src" | "evidence"): string {
  return `${prefix}:${crypto.randomUUID().replaceAll("-", "")}`;
}
