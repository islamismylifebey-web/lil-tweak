import {
  type EngineerMode,
  type EngineeringJob,
  type EngineeringJobDetail,
  type JobState,
  newEngineeringId,
  safeSourceFilename,
  transitionAllowed,
} from "./engineering.ts";
import { parseGitSource, type GitSourceInput, type ProjectContext } from "./engineering-input.ts";
import { sha256Hex } from "./core-signing.ts";

export interface SourceCreateInput {
  filename: string;
  mediaType: string;
  sizeBytes: number;
}

export interface EngineeringJobCreate {
  mode: EngineerMode;
  prompt: string;
  projectId: string | null;
  sources: SourceCreateInput[];
  gitSource?: GitSourceInput | null;
  projectContext?: ProjectContext | null;
}

export async function engineeringJobIdForCreate(owner: string, createKey: string) {
  return `job:${(await sha256Hex(`engineering-job-v1\0${owner}\0${createKey}`)).slice(0, 32)}`;
}

export async function engineeringCreateRequestDigest(input: EngineeringJobCreate) {
  const gitSource = parseGitSource(input.gitSource);
  const sources = validatedSources(input.sources).sort((left, right) => (
    left.filename < right.filename ? -1 : left.filename > right.filename ? 1 : 0
  ));
  return sha256Hex(JSON.stringify({
    schemaVersion: "engineering-create-v1",
    mode: input.mode,
    prompt: input.prompt,
    projectId: input.projectId,
    projectContext: input.projectContext ?? null,
    gitSource,
    sources,
  }));
}

export interface EngineeringStore {
  createJob(owner: string, input: EngineeringJobCreate): Promise<EngineeringJobDetail>;
  getJob(owner: string, jobId: string): Promise<EngineeringJobDetail | null>;
  listJobs(owner: string, limit: number): Promise<EngineeringJob[]>;
  markSourceUploaded(
    owner: string,
    jobId: string,
    sourceId: string,
    etag: string,
    sha256: string,
  ): Promise<EngineeringJobDetail>;
  transition(
    owner: string,
    jobId: string,
    next: JobState,
    expectedRevision: number,
    eventType: string,
    summary?: string,
  ): Promise<EngineeringJobDetail>;
}

interface MemoryRecord {
  owner: string;
  detail: EngineeringJobDetail;
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function event(type: string, summary: string, createdAt: string) {
  return {
    id: `event:${crypto.randomUUID().replaceAll("-", "")}`,
    type,
    summary,
    createdAt,
  };
}

function validatedSources(sources: SourceCreateInput[]) {
  if (!Array.isArray(sources) || sources.length > 10) {
    throw new Error("A job may contain up to 10 sources.");
  }
  let total = 0;
  const validated = sources.map((source) => {
    const filename = safeSourceFilename(source.filename);
    if (!Number.isSafeInteger(source.sizeBytes) || source.sizeBytes <= 0 || source.sizeBytes > 25_000_000) {
      throw new Error("Each engineering source must be between 1 byte and 25 MB.");
    }
    total += source.sizeBytes;
    if (total > 100_000_000) throw new Error("Engineering sources exceed the 100 MB job limit.");
    const mediaType = source.mediaType.trim().toLowerCase() || "application/octet-stream";
    if (mediaType.length > 120 || !/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(mediaType)) {
      throw new Error("Engineering source media type is invalid.");
    }
    return { filename, mediaType, sizeBytes: source.sizeBytes };
  });
  const filenames = validated.map((source) => source.filename.toLocaleLowerCase());
  if (new Set(filenames).size !== filenames.length) {
    throw new Error("Engineering source filenames must be unique.");
  }
  return validated;
}

export class MemoryEngineeringStore implements EngineeringStore {
  private readonly records = new Map<string, MemoryRecord>();
  private readonly sourceEtags = new Map<string, string>();

  async createJob(owner: string, input: EngineeringJobCreate): Promise<EngineeringJobDetail> {
    const now = new Date().toISOString();
    const gitSource = parseGitSource(input.gitSource);
    const sources = validatedSources(input.sources).map((source) => ({
      id: newEngineeringId("src"),
      jobId: "",
      filename: source.filename,
      mediaType: source.mediaType,
      sizeBytes: source.sizeBytes,
      sha256: null,
      uploadedAt: null,
    }));
    const id = newEngineeringId("job");
    for (const source of sources) source.jobId = id;
    const state: JobState = sources.length ? "uploading" : "queued";
    const detail: EngineeringJobDetail = {
      id,
      projectId: input.projectId,
      mode: input.mode,
      promptPreview: input.prompt.slice(0, 240),
      state,
      revision: 0,
      summary: sources.length ? "Waiting for source upload." : "Ready for secure dispatch.",
      proposalDigest: null,
      sourceDigest: null,
      approvalProposal: null,
      approvalConsumed: false,
      gitSource,
      createdAt: now,
      updatedAt: now,
      sources,
      evidence: [],
      events: [event("job_created", "Engineering job created.", now)],
    };
    this.records.set(id, { owner, detail });
    return clone(detail);
  }

  async getJob(owner: string, jobId: string): Promise<EngineeringJobDetail | null> {
    const record = this.records.get(jobId);
    return record?.owner === owner ? clone(record.detail) : null;
  }

  async listJobs(owner: string, limit: number): Promise<EngineeringJob[]> {
    const boundedLimit = Math.max(1, Math.min(50, Math.trunc(limit)));
    return [...this.records.values()]
      .filter((record) => record.owner === owner)
      .sort((left, right) => right.detail.updatedAt.localeCompare(left.detail.updatedAt))
      .slice(0, boundedLimit)
      .map((record) => clone({
        id: record.detail.id,
        projectId: record.detail.projectId,
        mode: record.detail.mode,
        promptPreview: record.detail.promptPreview,
        state: record.detail.state,
        revision: record.detail.revision,
        summary: record.detail.summary,
        proposalDigest: record.detail.proposalDigest,
        sourceDigest: record.detail.sourceDigest,
        approvalProposal: record.detail.approvalProposal,
        approvalConsumed: record.detail.approvalConsumed,
        gitSource: record.detail.gitSource,
        createdAt: record.detail.createdAt,
        updatedAt: record.detail.updatedAt,
      }));
  }

  async markSourceUploaded(
    owner: string,
    jobId: string,
    sourceId: string,
    etag: string,
    sha256: string,
  ): Promise<EngineeringJobDetail> {
    const record = this.requireRecord(owner, jobId);
    const source = record.detail.sources.find((item) => item.id === sourceId);
    if (!source) throw new Error("Engineering source was not found.");
    if (source.uploadedAt) {
      if (this.sourceEtags.get(sourceId) !== etag || source.sha256 !== sha256) {
        throw new Error("Engineering source integrity does not match the uploaded object.");
      }
      return clone(record.detail);
    }
    if (!etag.trim()) throw new Error("Source object ETag is required.");
    if (!/^[a-f0-9]{64}$/.test(sha256)) throw new Error("Source object SHA-256 is invalid.");
    const now = new Date().toISOString();
    source.uploadedAt = now;
    source.sha256 = sha256;
    this.sourceEtags.set(sourceId, etag);
    record.detail.revision += 1;
    record.detail.updatedAt = now;
    record.detail.events.push(event("source_uploaded", `${source.filename} uploaded.`, now));
    if (record.detail.sources.every((item) => item.uploadedAt)) {
      record.detail.state = "queued";
      record.detail.summary = "Ready for secure dispatch.";
      record.detail.events.push(event("sources_ready", "All sources are ready.", now));
    }
    return clone(record.detail);
  }

  async transition(
    owner: string,
    jobId: string,
    next: JobState,
    expectedRevision: number,
    eventType: string,
    summary = "",
  ): Promise<EngineeringJobDetail> {
    const record = this.requireRecord(owner, jobId);
    if (record.detail.revision !== expectedRevision) throw new Error("Stale job revision.");
    if (!transitionAllowed(record.detail.state, next)) {
      throw new Error(`Illegal job transition from ${record.detail.state} to ${next}.`);
    }
    const now = new Date().toISOString();
    record.detail.state = next;
    record.detail.revision += 1;
    record.detail.updatedAt = now;
    record.detail.summary = summary || next.replaceAll("_", " ");
    record.detail.events.push(event(eventType, summary || record.detail.summary, now));
    return clone(record.detail);
  }

  private requireRecord(owner: string, jobId: string): MemoryRecord {
    const record = this.records.get(jobId);
    if (!record || record.owner !== owner) throw new Error("Engineering job was not found.");
    return record;
  }
}
