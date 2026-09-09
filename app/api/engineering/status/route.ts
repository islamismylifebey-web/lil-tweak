import { env } from "cloudflare:workers";
import { json, ownerFor, ownerScope, publicError } from "@/lib/engineering-api";
import { engineeringConnectionStatus } from "@/lib/engineering-connection";

export async function GET(request: Request) {
  try {
    const owner = ownerFor(request);
    const scope = await ownerScope(owner);
    return json({ status: await engineeringConnectionStatus(env, scope, { probe: true }) });
  } catch (error) {
    return publicError(error);
  }
}
