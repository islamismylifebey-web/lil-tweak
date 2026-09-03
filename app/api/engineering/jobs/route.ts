import { readBoundedJson } from "@/lib/bounded-request";
import { json, ownerFor, ownerScope, publicError, requireSameOriginMutation, store, files } from "@/lib/engineering-api";
import { parseJobCreate, safeSourceFilename } from "@/lib/engineering";
import { engineeringCreateRequestDigest, engineeringJobIdForCreate, type SourceCreateInput } from "@/lib/engineering-store";
import { boundedProjectContext, enforceModeSourcePolicy, parseGitSource } from "@/lib/engineering-input";
import { ensureEngineeringRequestObject, recoverEngineeringCreateRequest, requireCreateRequestId } from "@/lib/create-request";
import { getProject } from "@/lib/workspace";

const MAX_JOB_JSON_BYTES = 32 * 1024;

function sourceManifest(value: unknown): SourceCreateInput[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error("Engineering sources must be a list.");
  return value.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error("Engineering source is invalid.");
    }
    const input = item as Record<string, unknown>;
    const filename = safeSourceFilename(input.filename);
    if (typeof input.mediaType !== "string") throw new Error("Engineering source media type is invalid.");
    if (!Number.isSafeInteger(input.sizeBytes)) throw new Error("Engineering source size is invalid.");
    return { filename, mediaType: input.mediaType, sizeBytes: Number(input.sizeBytes) };
  });
}

export async function GET(request: Request) {
  try {
    const owner = ownerFor(request);
    const scope = await ownerScope(owner);
    const limitValue = new URL(request.url).searchParams.get("limit") ?? "20";
    const limit = /^\d{1,2}$/.test(limitValue) ? Number(limitValue) : 20;
    return json({ jobs: await store().listJobs(scope, limit) });
  } catch (error) {
    return publicError(error);
  }
}

export async function POST(request: Request) {
  try {
    const owner = ownerFor(request);
    requireSameOriginMutation(request);
    const raw = await readBoundedJson(request, MAX_JOB_JSON_BYTES);
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("Engineering request must be an object.");
    const requestId = requireCreateRequestId(
      request.headers.get("idempotency-key"),
      (raw as Record<string, unknown>).requestId,
    );
    const input = parseJobCreate(raw);
    const sources = sourceManifest((raw as Record<string, unknown>).sources);
    const gitSource = parseGitSource((raw as Record<string, unknown>).gitSource);
    if (gitSource && sources.length) {
      throw new Error("Engineering request must use uploaded sources or one Git source, not both.");
    }
    enforceModeSourcePolicy(input.mode, input.projectId, sources, gitSource);
    const projectContext = input.projectId
      ? boundedProjectContext(await getProject(owner, input.projectId))
      : null;
    const scope = await ownerScope(owner);
    const jobStore = store();
    const ownerInput = { ...input, sources, gitSource };
    let createInput = { ...ownerInput, projectContext };
    let requestDigest = await engineeringCreateRequestDigest(createInput);
    const jobId = await engineeringJobIdForCreate(scope, requestId);
    const requestObject = JSON.stringify({
      id: jobId,
      mode: input.mode,
      prompt: input.prompt,
      projectId: input.projectId,
      projectContext,
      gitSource,
    });
    const requestKey = `engineering/${scope}/jobs/${jobId}/request.json`;
    const bucket = files();
    const recoverFrozen = async () => {
      const recovered = await recoverEngineeringCreateRequest({
        object: await bucket.get(requestKey),
        jobId,
        ownerInput,
      });
      createInput = { ...ownerInput, projectContext: recovered.projectContext };
      requestDigest = recovered.requestDigest;
    };
    if (await bucket.head(requestKey)) {
      await recoverFrozen();
    } else {
      try {
        await ensureEngineeringRequestObject({
          bucket,
          key: requestKey,
          body: requestObject,
          requestDigest,
        });
      } catch {
        await recoverFrozen();
      }
    }
    const { job: created, created: wasCreated } = await jobStore.createJobWithIdempotency(
      scope,
      createInput,
      requestId,
      requestDigest,
    );
    if (created.id !== jobId) throw new Error("Engineering creation reconciliation failed.");
    return json({ job: created }, wasCreated ? 201 : 200);
  } catch (error) {
    return publicError(error);
  }
}
