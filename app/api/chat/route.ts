import { json, ownerFor, publicError, requireSameOriginMutation } from "@/lib/engineering-api";

/**
 * Emergency zero-token guard.
 *
 * Lil' Tweak must not make any model-provider request while this guard is
 * active. Keep the route present so the live UI fails closed instead of
 * retrying against a paid model endpoint.
 */
export async function POST(request: Request) {
  try {
    ownerFor(request);
    requireSameOriginMutation(request);

    return json(
      {
        error: "Lil' Tweak model calls are temporarily disabled to prevent token usage.",
        code: "MODEL_CALLS_DISABLED",
      },
      503,
    );
  } catch (error) {
    return publicError(error);
  }
}
