import { env } from "cloudflare:workers";
import { RequestBoundaryError } from "./bounded-request";
import { CoreRejectedError, getCoreEvidence } from "./core-client";
import { type CoreSnapshotInput, EngineeringConflictError, EngineeringNotFoundError, D1EngineeringStore } from "./engineering-d1";
import { mirrorCoreEvidence } from "./evidence-mirror";
import { sha256Hex } from "./core-signing";
import { authenticatedOwner } from "./owner-auth";
import { ImmutableObjectConflictError } from "./immutable-r2";
import { publicCoreFailure } from "./core-transport";

export const PRIVATE_JSON_HEADERS = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
  Vary: "Cookie, Origin",
};

interface EngineeringBindings {
  DB?: D1Database;
  FILES?: R2Bucket;
}

export class EngineeringAuthorizationError extends Error {
  constructor(message = "Owner access required.") {
    super(message);
  }
}

export function json(body: unknown, status = 200) {
  return Response.json(body, { status, headers: PRIVATE_JSON_HEADERS });
}

export function ownerFor(request: Request) {
  const owner = authenticatedOwner(request);
  if (!owner) throw new EngineeringAuthorizationError();
  return owner;
}

export function requireSameOriginMutation(request: Request) {
  const origin = request.headers.get("origin");
  const fetchSite = request.headers.get("sec-fetch-site");
  if (!origin || origin !== new URL(request.url).origin || (fetchSite && fetchSite !== "same-origin")) {
    throw new EngineeringAuthorizationError("Cross-site engineering request rejected.");
  }
}

export async function ownerScope(owner: string) {
  return (await sha256Hex(owner)).slice(0, 32);
}

export function store() {
  const database = (env as unknown as EngineeringBindings).DB;
  if (!database) throw new Error("Engineering storage is unavailable.");
  return new D1EngineeringStore(database);
}

export function files() {
  const bucket = (env as unknown as EngineeringBindings).FILES;
  if (!bucket) throw new Error("Engineering storage is unavailable.");
  return bucket;
}

export async function mirrorCoreSnapshotEvidence(
  owner: string,
  jobId: string,
  remoteJobId: string,
  snapshot: CoreSnapshotInput,
): Promise<CoreSnapshotInput> {
  if (!snapshot.evidence?.length) return snapshot;
  const evidence = await mirrorCoreEvidence({
    ownerScope: owner,
    jobId,
    remoteJobId,
    evidence: snapshot.evidence,
    bucket: files(),
    fetchEvidence: (remote, descriptor) => getCoreEvidence(
      owner,
      remote,
      descriptor.corePath,
      descriptor.sha256,
      `job:${jobId}:evidence:${descriptor.id}:${descriptor.sha256.slice(0, 16)}`,
    ),
  });
  return { ...snapshot, evidence };
}

export function requireJobId(value: string) {
  if (!/^job:[0-9a-f]{32}$/.test(value)) throw new EngineeringNotFoundError();
  return value;
}

export function requireSourceId(value: string) {
  if (!/^src:[0-9a-f]{32}$/.test(value)) throw new EngineeringNotFoundError();
  return value;
}

export function requireEvidenceId(value: string) {
  if (!/^evidence:[0-9a-f]{32}$/.test(value)) throw new EngineeringNotFoundError();
  return value;
}

export function publicError(error: unknown) {
  if (error instanceof RequestBoundaryError) return json({ error: error.message, code: error.code }, error.status);
  if (error instanceof EngineeringAuthorizationError) return json({ error: error.message }, error.message.startsWith("Owner") ? 401 : 403);
  if (error instanceof EngineeringNotFoundError) return json({ error: "Engineering job was not found." }, 404);
  if (error instanceof EngineeringConflictError) return json({ error: error.message }, 409);
  if (error instanceof ImmutableObjectConflictError) return json({ error: "Engineering source upload already exists." }, 409);
  if (error instanceof CoreRejectedError) {
    const failure = publicCoreFailure(error.status);
    return json({ error: failure.message }, failure.status);
  }
  const message = error instanceof Error ? error.message : "Engineering request failed.";
  if (/^(A valid|A portable|A rejection|Each engineering|Engineering creation|Engineering request|Engineering sources|Engineering prompt|Engineering source|Git source|Chat mode|Use uploaded|Decision|Project ID|Request body|Content-Type)/.test(message)) {
    return json({ error: message }, 400);
  }
  console.error("Lil Tweak engineering request failed", error);
  return json({ error: "Engineering service is unavailable." }, 503);
}

export function attachmentHeaders(filename: string, mediaType: string, sizeBytes: number) {
  const safeName = filename.replace(/["\\\r\n]/g, "_");
  return {
    "Cache-Control": "private, no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Type": mediaType || "application/octet-stream",
    "Content-Disposition": `attachment; filename="${safeName}"`,
    "Content-Length": String(sizeBytes),
  };
}
