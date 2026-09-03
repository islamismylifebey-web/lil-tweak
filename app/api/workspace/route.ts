import { authenticatedOwner, mutationRequestIsSafe } from "@/lib/owner-auth";
import { readBoundedJson, RequestBoundaryError } from "@/lib/bounded-request";
import {
  attachFile,
  createProject,
  exportProject,
  getProject,
  importProject,
  listProjects,
  ProjectConflictError,
  updateProject,
} from "@/lib/workspace";

const MAX_REQUEST_BYTES = 4_000_000;
const PRIVATE_JSON_HEADERS = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};

function jsonResponse(body: unknown, status = 200) {
  return Response.json(body, { status, headers: PRIVATE_JSON_HEADERS });
}

function errorResponse(error: unknown) {
  if (error instanceof RequestBoundaryError) {
    return jsonResponse({ error: error.message, code: error.code }, error.status);
  }
  if (error instanceof ProjectConflictError) {
    return jsonResponse(
      {
        error: error.message,
        code: error.code,
        ...(error.currentProject ? { project: error.currentProject } : {}),
      },
      409,
    );
  }
  const message = error instanceof Error ? error.message : "Unexpected workspace error.";
  const missingStorage =
    message.includes("no such table") ||
    message.includes("D1_ERROR") ||
    message.includes("binding");
  const safeValidation = /^(Attachment|Imported attachment|Milestone|Note|Project|Requirement|Task|Workspace action)/.test(message);
  if (!missingStorage && !safeValidation) {
    console.error("Lil Tweak workspace request failed", {
      errorName: error instanceof Error ? error.name : "UnknownError",
    });
  }
  return jsonResponse(
    {
      error: missingStorage
        ? "Workspace storage is not ready yet. Complete the Sites deployment, then refresh."
        : safeValidation
          ? message
          : "Workspace service is unavailable.",
    },
    missingStorage || !safeValidation ? 503 : 400,
  );
}

function expectedRevision(
  input: Record<string, unknown>,
  projectValue?: unknown,
) {
  const legacyRevision =
    projectValue && typeof projectValue === "object"
      ? (projectValue as Record<string, unknown>).revision
      : undefined;
  const revision = input.expectedRevision ?? legacyRevision;
  if (typeof revision !== "number" || !Number.isSafeInteger(revision) || revision < 0) {
    throw new Error("Project revision is required.");
  }
  return revision;
}

export async function GET(request: Request) {
  const ownerEmail = authenticatedOwner(request);
  if (!ownerEmail) return jsonResponse({ error: "Owner access required." }, 401);
  const url = new URL(request.url);
  try {
    const action = url.searchParams.get("action") ?? "list";
    const projectId = url.searchParams.get("id") ?? "";
    if (action === "get") return jsonResponse({ project: await getProject(ownerEmail, projectId) });
    if (action === "export") {
      return jsonResponse({ exported: await exportProject(ownerEmail, projectId) });
    }
    return jsonResponse({
      projects: await listProjects(
        ownerEmail,
        url.searchParams.get("query") ?? "",
        url.searchParams.get("status") ?? "",
      ),
    });
  } catch (error) {
    return errorResponse(error);
  }
}

export async function POST(request: Request) {
  const ownerEmail = authenticatedOwner(request);
  if (!ownerEmail) return jsonResponse({ error: "Owner access required." }, 401);
  if (!mutationRequestIsSafe(request)) {
    return jsonResponse({ error: "Cross-site workspace request rejected." }, 403);
  }
  try {
    const input = await readBoundedJson(request, MAX_REQUEST_BYTES) as Record<string, unknown>;
    if (input.action === "create") {
      return jsonResponse({ project: await createProject(ownerEmail, input.project) }, 201);
    }
    if (input.action === "update") {
      if (typeof input.id !== "string") throw new Error("Project ID is required.");
      return jsonResponse({
        project: await updateProject(
          ownerEmail,
          input.id,
          input.project,
          expectedRevision(input, input.project),
        ),
      });
    }
    if (input.action === "attach") {
      if (typeof input.id !== "string") throw new Error("Project ID is required.");
      return jsonResponse({
        project: await attachFile(
          ownerEmail,
          input.id,
          input.attachment,
          expectedRevision(input),
        ),
      });
    }
    if (input.action === "import") {
      return jsonResponse({ project: await importProject(ownerEmail, input.exported) }, 201);
    }
    throw new Error("Workspace action is unsupported.");
  } catch (error) {
    return errorResponse(error);
  }
}
