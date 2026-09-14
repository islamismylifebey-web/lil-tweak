import { json, ownerFor, publicError, requireJobId, requireSameOriginMutation, requireSourceId } from "@/lib/engineering-api";

export async function PUT(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    ownerFor(request);
    requireSameOriginMutation(request);
    requireJobId((await context.params).id);
    requireSourceId(new URL(request.url).searchParams.get("sourceId") ?? "");
    // Fail before reading the body or touching storage, including legacy jobs.
    return json({ error: "Uploaded-project execution is unavailable for this launch. Use a GitHub repository and exact commit." }, 409);
  } catch (error) {
    return publicError(error);
  }
}
