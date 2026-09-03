import { env } from "cloudflare:workers";
import { json, ownerFor, publicError } from "@/lib/engineering-api";
import { engineeringConnectionStatus } from "@/lib/engineering-connection";

export async function GET(request: Request) {
  try {
    ownerFor(request);
    return json({ status: await engineeringConnectionStatus(env, { probe: true }) });
  } catch (error) {
    return publicError(error);
  }
}
